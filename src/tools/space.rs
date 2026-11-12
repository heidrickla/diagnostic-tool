//! Free space and the largest folders on a drive, plus known cleanup candidates. Reads
//! directory metadata only; no file contents are opened and nothing is deleted.
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
    GetDiskFreeSpaceExW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FIND_FIRST_EX_LARGE_FETCH, WIN32_FIND_DATAW,
};

use serde_json::{json, Value};

use super::{Args, Output, Tool};
use crate::events;

pub const TOOL: Tool = Tool {
    name: "space",
    summary: "largest folders and cleanup candidates on a drive",
    usage: "\
Usage: toolkit space [options]
  --drive LETTER    drive to look at (default the Windows drive)
  --top N           folders to list (default 15, 1 to 50)
  --depth N         folder levels to show (default 3, 1 to 6)
  --seconds N       time limit for the walk (default 60, 5 to 300)
Reads folder sizes only; nothing is deleted. Folders under a user profile are shown
as [user] and only one level deep.",
    run,
};

const SHARED_PROFILES: [&str; 4] = ["Public", "Default", "Default User", "All Users"];

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    /// A file whose size counts.
    File,
    /// A cloud-only file or folder placeholder: no local bytes, never opened.
    Cloud,
    Dir,
    /// A junction or symlink folder; never followed.
    Reparse,
}

pub(crate) fn classify(attributes: u32) -> Kind {
    const CLOUD: u32 = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_OFFLINE;
    let is_dir = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if attributes & CLOUD != 0 {
        Kind::Cloud
    } else if !is_dir {
        Kind::File
    } else if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Kind::Reparse
    } else {
        Kind::Dir
    }
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in UNITS {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

/// Replaces the account folder under `\Users` with `[user]` (shared profiles keep their names).
pub fn redact_profile(path: &str) -> String {
    let (prefix, rest) = match path.strip_prefix(r"\\?\") {
        Some(rest) => (r"\\?\", rest),
        None => ("", path),
    };
    let mut parts: Vec<&str> = rest.split('\\').collect();
    if parts.len() >= 3
        && parts[1].eq_ignore_ascii_case("Users")
        && !SHARED_PROFILES
            .iter()
            .any(|s| s.eq_ignore_ascii_case(parts[2]))
    {
        parts[2] = "[user]";
    }
    format!("{prefix}{}", parts.join("\\"))
}

/// Whether a folder at `level` gets its own line: within `depth`, and under a profile only
/// the profile itself and its first level below.
pub fn node_wanted(level: usize, depth: usize, profile_level: Option<usize>) -> bool {
    level <= depth && profile_level.is_none_or(|p| level <= p + 1)
}

#[derive(Debug)]
pub struct Node {
    pub display: String,
    pub level: usize,
    pub size: u64,
    /// False when the time limit ended the count inside this folder, so the size is a minimum.
    pub complete: bool,
    pub children: Vec<Node>,
}

#[derive(Debug)]
struct Ctx {
    deadline: Instant,
    timed_out: bool,
    unreadable: u64,
    reparse: u64,
    placeholders: u64,
    profiles: u32,
}

impl Ctx {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            timed_out: false,
            unreadable: 0,
            reparse: 0,
            placeholders: 0,
            profiles: 0,
        }
    }

    fn expired(&mut self) -> bool {
        if !self.timed_out && Instant::now() >= self.deadline {
            self.timed_out = true;
        }
        self.timed_out
    }

    fn profile_label(&mut self) -> String {
        self.profiles += 1;
        match self.profiles {
            1 => "[user]".into(),
            n => format!("[user {n}]"),
        }
    }
}

fn wide_path(path: &Path, wildcard: bool) -> Vec<u16> {
    let mut text: Vec<u16> = Vec::new();
    let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
    if !raw.starts_with(&[92, 92, 63, 92]) {
        text.extend(r"\\?\".encode_utf16());
    }
    text.extend(raw);
    if wildcard {
        while text.last() == Some(&92) {
            text.pop();
        }
        text.extend(r"\*".encode_utf16());
    }
    text.push(0);
    text
}

/// Calls `each` for every entry of a folder except `.` and `..`. Returns the Win32 error when
/// the folder cannot be opened or its listing breaks off.
pub(crate) fn list_dir(dir: &Path, mut each: impl FnMut(&WIN32_FIND_DATAW)) -> Result<(), u32> {
    let pattern = wide_path(dir, true);
    // SAFETY: WIN32_FIND_DATAW is plain data and is filled by the call.
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: pattern is NUL-terminated and data is a valid out structure.
    let handle = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FindExInfoBasic,
            &mut data as *mut _ as *mut _,
            FindExSearchNameMatch,
            std::ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads the calling thread's last error.
        return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
    }
    let mut result = Ok(());
    loop {
        let name = name_of(&data);
        if name != [46] && name != [46, 46] {
            each(&data);
        }
        // SAFETY: handle is a live search handle and data a valid out structure.
        if unsafe { FindNextFileW(handle, &mut data) } == 0 {
            // SAFETY: reads the calling thread's last error.
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                result = Err(error);
            }
            break;
        }
    }
    // SAFETY: handle came from FindFirstFileExW and is closed once.
    unsafe { FindClose(handle) };
    result
}

pub(crate) fn name_of(data: &WIN32_FIND_DATAW) -> &[u16] {
    let end = data.cFileName.iter().position(|c| *c == 0).unwrap_or(260);
    &data.cFileName[..end]
}

pub(crate) fn file_size(data: &WIN32_FIND_DATAW) -> u64 {
    (u64::from(data.nFileSizeHigh) << 32) | u64::from(data.nFileSizeLow)
}

/// Bytes of the files in a folder and the names of its sub-folders worth entering.
fn scan_dir(dir: &Path, ctx: &mut Ctx) -> Result<(u64, Vec<OsString>), u32> {
    let mut bytes = 0u64;
    let mut subdirs = Vec::new();
    let (mut reparse, mut placeholders) = (0, 0);
    list_dir(dir, |data| match classify(data.dwFileAttributes) {
        Kind::File => bytes += file_size(data),
        Kind::Cloud => placeholders += 1,
        Kind::Reparse => reparse += 1,
        Kind::Dir => subdirs.push(OsString::from_wide(name_of(data))),
    })
    .inspect_err(|_| ctx.unreadable += 1)?;
    ctx.reparse += reparse;
    ctx.placeholders += placeholders;
    Ok((bytes, subdirs))
}

/// Total bytes under a folder without building nodes; the second value is the error that
/// stopped the folder itself from opening.
fn sum_tree(root: &Path, ctx: &mut Ctx) -> (u64, Option<u32>) {
    let mut total = 0u64;
    let mut root_error = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if ctx.expired() {
            break;
        }
        match scan_dir(&dir, ctx) {
            Ok((bytes, subdirs)) => {
                total += bytes;
                stack.extend(subdirs.iter().map(|name| dir.join(name)));
            }
            Err(error) if dir == root => root_error = Some(error),
            Err(_) => {}
        }
    }
    (total, root_error)
}

/// Threads that pull folders from the shared queue.
const POOL: usize = 8;

struct Task {
    path: PathBuf,
    /// Index of the listed folder whose size this folder's files add to.
    owner: usize,
    level: usize,
    is_users: bool,
    profile_level: Option<usize>,
    /// Below the depth limit or a profile's first level: only summed, never listed.
    rolled: bool,
}

struct Slot {
    display: String,
    level: usize,
    parent: usize,
    own: u64,
    unfinished: bool,
}

struct Shared {
    queue: VecDeque<Task>,
    slots: Vec<Slot>,
    active: usize,
    ctx: Ctx,
}

/// Walks the volume breadth first with `threads` workers sharing one queue, so every
/// top-level folder progresses at once. Folders cut off by the time limit are marked.
fn walk(
    root: &Path,
    display: String,
    depth: usize,
    deadline: Instant,
    threads: usize,
) -> (Node, Ctx) {
    let shared = Mutex::new(Shared {
        queue: VecDeque::from([Task {
            path: root.to_path_buf(),
            owner: 0,
            level: 0,
            is_users: false,
            profile_level: None,
            rolled: false,
        }]),
        slots: vec![Slot {
            display,
            level: 0,
            parent: 0,
            own: 0,
            unfinished: false,
        }],
        active: 0,
        ctx: Ctx::new(deadline),
    });
    let wake = Condvar::new();
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| worker(&shared, &wake, depth, deadline));
        }
    });
    let Shared { slots, mut ctx, .. } = shared.into_inner().unwrap();
    ctx.timed_out |= slots.iter().any(|slot| slot.unfinished);
    (assemble(slots), ctx)
}

fn worker(shared: &Mutex<Shared>, wake: &Condvar, depth: usize, deadline: Instant) {
    loop {
        let task = {
            let mut guard = shared.lock().unwrap();
            loop {
                if Instant::now() >= deadline {
                    guard.ctx.timed_out = true;
                    let left: Vec<Task> = guard.queue.drain(..).collect();
                    for task in left {
                        guard.slots[task.owner].unfinished = true;
                    }
                    wake.notify_all();
                    return;
                }
                if let Some(task) = guard.queue.pop_front() {
                    guard.active += 1;
                    break task;
                }
                if guard.active == 0 {
                    wake.notify_all();
                    return;
                }
                guard = wake
                    .wait_timeout(guard, Duration::from_millis(50))
                    .unwrap()
                    .0;
            }
        };
        let mut local = Ctx::new(deadline);
        let scanned = scan_dir(&task.path, &mut local);
        let mut guard = shared.lock().unwrap();
        guard.active -= 1;
        guard.ctx.unreadable += local.unreadable;
        guard.ctx.reparse += local.reparse;
        guard.ctx.placeholders += local.placeholders;
        if let Ok((bytes, subdirs)) = scanned {
            guard.slots[task.owner].own += bytes;
            for name in subdirs {
                let child = child_task(&mut guard, &task, &name, depth);
                guard.queue.push_back(child);
            }
        }
        wake.notify_all();
    }
}

/// The queue entry for a sub-folder, adding a listed folder to the slots when it gets a line.
fn child_task(shared: &mut Shared, parent: &Task, name: &OsStr, depth: usize) -> Task {
    let path = parent.path.join(name);
    let level = parent.level + 1;
    let rolled_into_parent = Task {
        path: path.clone(),
        owner: parent.owner,
        level,
        is_users: false,
        profile_level: None,
        rolled: true,
    };
    if parent.rolled {
        return rolled_into_parent;
    }
    let lossy = name.to_string_lossy();
    let is_profile = parent.is_users
        && !SHARED_PROFILES
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&lossy));
    let profile_level = if is_profile {
        Some(level)
    } else {
        parent.profile_level
    };
    if !node_wanted(level, depth, profile_level) {
        return rolled_into_parent;
    }
    let shown = if is_profile {
        shared.ctx.profile_label()
    } else {
        lossy.into_owned()
    };
    let display = format!("{}\\{shown}", shared.slots[parent.owner].display);
    shared.slots.push(Slot {
        display,
        level,
        parent: parent.owner,
        own: 0,
        unfinished: false,
    });
    Task {
        path,
        owner: shared.slots.len() - 1,
        level,
        is_users: parent.level == 0 && lossy_eq(name, "Users"),
        profile_level,
        rolled: false,
    }
}

/// Turns the slots (children always after their parent) into the sorted node tree.
fn assemble(slots: Vec<Slot>) -> Node {
    let mut sizes: Vec<u64> = slots.iter().map(|s| s.own).collect();
    let mut unfinished: Vec<bool> = slots.iter().map(|s| s.unfinished).collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); slots.len()];
    for index in (1..slots.len()).rev() {
        let parent = slots[index].parent;
        sizes[parent] += sizes[index];
        unfinished[parent] |= unfinished[index];
        children[parent].push(index);
    }
    fn build(
        index: usize,
        slots: &[Slot],
        sizes: &[u64],
        unfinished: &[bool],
        children: &[Vec<usize>],
    ) -> Node {
        let mut kids: Vec<Node> = children[index]
            .iter()
            .map(|c| build(*c, slots, sizes, unfinished, children))
            .collect();
        kids.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.display.cmp(&b.display)));
        Node {
            display: slots[index].display.clone(),
            level: slots[index].level,
            size: sizes[index],
            complete: !unfinished[index],
            children: kids,
        }
    }
    build(0, &slots, &sizes, &unfinished, &children)
}

fn lossy_eq(name: &OsStr, other: &str) -> bool {
    name.to_string_lossy().eq_ignore_ascii_case(other)
}

/// The `n` largest folders below the root (sizes tie-broken towards the shallower folder, so
/// a parent is always chosen before its children), in tree order.
pub fn top_nodes(root: &Node, n: usize) -> Vec<&Node> {
    fn flatten<'a>(node: &'a Node, out: &mut Vec<&'a Node>) {
        for child in &node.children {
            out.push(child);
            flatten(child, out);
        }
    }
    let mut all = Vec::new();
    flatten(root, &mut all);
    let mut order: Vec<usize> = (0..all.len()).filter(|i| all[*i].size > 0).collect();
    order.sort_by(|a, b| {
        all[*b]
            .size
            .cmp(&all[*a].size)
            .then(all[*a].level.cmp(&all[*b].level))
            .then(a.cmp(b))
    });
    order.truncate(n);
    order.sort_unstable();
    order.into_iter().map(|i| all[i]).collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Measure {
    Size {
        bytes: u64,
        /// The time limit stopped the count.
        timed_out: bool,
        /// Folders inside that could not be read.
        unreadable: u64,
        items: Option<i64>,
    },
    Absent,
    Denied,
    Failed(u32),
}

/// Merges the measures of the folders that make up one candidate.
pub fn combine(parts: Vec<Measure>) -> Measure {
    let mut total = Measure::Absent;
    for part in parts {
        total = match (total, part) {
            (Measure::Absent, other) => other,
            (other, Measure::Absent) => other,
            (
                Measure::Size {
                    bytes: a,
                    timed_out: ta,
                    unreadable: ua,
                    items: ia,
                },
                Measure::Size {
                    bytes: b,
                    timed_out: tb,
                    unreadable: ub,
                    items: ib,
                },
            ) => Measure::Size {
                bytes: a + b,
                timed_out: ta || tb,
                unreadable: ua + ub,
                items: ia.zip(ib).map(|(x, y)| x + y),
            },
            (size @ Measure::Size { .. }, Measure::Denied | Measure::Failed(_)) => match size {
                Measure::Size {
                    bytes,
                    timed_out,
                    unreadable,
                    items,
                } => Measure::Size {
                    bytes,
                    timed_out,
                    unreadable: unreadable + 1,
                    items,
                },
                other => other,
            },
            (
                Measure::Denied | Measure::Failed(_),
                Measure::Size {
                    bytes,
                    timed_out,
                    unreadable,
                    items,
                },
            ) => Measure::Size {
                bytes,
                timed_out,
                unreadable: unreadable + 1,
                items,
            },
            (first, _) => first,
        };
    }
    total
}

fn measure_dir(path: &Path, deadline: Instant) -> Measure {
    let mut ctx = Ctx::new(deadline);
    let (bytes, root_error) = sum_tree(path, &mut ctx);
    match root_error {
        Some(code) if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND => {
            Measure::Absent
        }
        Some(code) if code == ERROR_ACCESS_DENIED => Measure::Denied,
        Some(code) => Measure::Failed(code),
        None => Measure::Size {
            bytes,
            timed_out: ctx.timed_out,
            unreadable: ctx.unreadable,
            items: None,
        },
    }
}

/// A single file's size from its directory entry; the file is not opened.
fn measure_file(path: &Path) -> Measure {
    let pattern = wide_path(path, false);
    // SAFETY: WIN32_FIND_DATAW is plain data and is filled by the call.
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: pattern is NUL-terminated and data is a valid out structure.
    let handle = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FindExInfoBasic,
            &mut data as *mut _ as *mut _,
            FindExSearchNameMatch,
            std::ptr::null(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads the calling thread's last error.
        return match unsafe { windows_sys::Win32::Foundation::GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Measure::Absent,
            ERROR_ACCESS_DENIED => Measure::Denied,
            other => Measure::Failed(other),
        };
    }
    // SAFETY: handle came from FindFirstFileExW and is closed once.
    unsafe { FindClose(handle) };
    Measure::Size {
        bytes: file_size(&data),
        timed_out: false,
        unreadable: 0,
        items: None,
    }
}

fn measure_recycle_bin(drive: char) -> Measure {
    use windows_sys::Win32::UI::Shell::{SHQueryRecycleBinW, SHQUERYRBINFO};
    let root: Vec<u16> = format!("{drive}:\\").encode_utf16().chain([0]).collect();
    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: root is NUL-terminated and info is a sized out structure.
    let result = unsafe { SHQueryRecycleBinW(root.as_ptr(), &mut info) };
    if result < 0 {
        return Measure::Failed(result as u32);
    }
    Measure::Size {
        bytes: info.i64Size.max(0) as u64,
        timed_out: false,
        unreadable: 0,
        items: Some(info.i64NumItems),
    }
}

enum Source {
    Dirs(Vec<PathBuf>),
    File(PathBuf),
    RecycleBin(char),
}

struct Candidate {
    label: &'static str,
    shown: String,
    source: Source,
}

/// Names of the sub-folders of `dir` that pass `keep`.
fn child_dirs(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| keep(&e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect()
}

fn candidates(drive: char, windows: &Path, local: Option<&Path>) -> Vec<Candidate> {
    let root = PathBuf::from(format!("{drive}:\\"));
    let shown = |p: &Path| redact_profile(&p.to_string_lossy());
    let dir = |label, path: PathBuf| Candidate {
        label,
        shown: shown(&path),
        source: Source::Dirs(vec![path]),
    };
    let mut list = Vec::new();
    if let Some(local) = local {
        list.push(dir("Temp folder of the current user", local.join("Temp")));
    }
    list.push(dir("Windows temp folder", windows.join("Temp")));
    list.push(dir(
        "Windows Update downloads",
        windows.join(r"SoftwareDistribution\Download"),
    ));
    list.push(dir(
        "Previous Windows installation",
        root.join("Windows.old"),
    ));
    list.push(Candidate {
        label: "Recycle Bin",
        shown: format!("{drive}:\\$Recycle.Bin"),
        source: Source::RecycleBin(drive),
    });
    for name in ["hiberfil.sys", "pagefile.sys", "swapfile.sys"] {
        list.push(Candidate {
            label: match name {
                "hiberfil.sys" => "Hibernation file",
                "pagefile.sys" => "Page file",
                _ => "Swap file",
            },
            shown: format!("{drive}:\\{name}"),
            source: Source::File(root.join(name)),
        });
    }
    list.push(Candidate {
        label: "Delivery Optimization cache",
        shown: format!(
            "{drive}:\\ProgramData\\Microsoft\\Windows\\DeliveryOptimization\\Cache and the NetworkService copy"
        ),
        source: Source::Dirs(vec![
            root.join(r"ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"),
            windows.join(
                r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
            ),
        ]),
    });
    if let Some(local) = local {
        for (label, base) in [
            ("Chrome cache", r"Google\Chrome\User Data"),
            ("Edge cache", r"Microsoft\Edge\User Data"),
        ] {
            let data = local.join(base);
            let mut paths = Vec::new();
            for profile in child_dirs(&data, |n| n == "Default" || n.starts_with("Profile ")) {
                for cache in ["Cache", "Code Cache"] {
                    paths.push(profile.join(cache));
                }
            }
            list.push(Candidate {
                label,
                shown: format!("{}\\<profile>\\Cache and Code Cache", shown(&data)),
                source: Source::Dirs(paths),
            });
        }
        let profiles = local.join(r"Mozilla\Firefox\Profiles");
        list.push(Candidate {
            label: "Firefox cache",
            shown: format!("{}\\<profile>\\cache2", shown(&profiles)),
            source: Source::Dirs(
                child_dirs(&profiles, |_| true)
                    .into_iter()
                    .map(|p| p.join("cache2"))
                    .collect(),
            ),
        });
    }
    list.push(dir("Crash mini dumps", windows.join("Minidump")));
    list.push(Candidate {
        label: "Full memory dump",
        shown: shown(&windows.join("MEMORY.DMP")),
        source: Source::File(windows.join("MEMORY.DMP")),
    });
    list.push(dir("Servicing (CBS) logs", windows.join(r"Logs\CBS")));
    list
}

fn measure(source: &Source, deadline: Instant) -> Measure {
    match source {
        Source::Dirs(paths) => combine(paths.iter().map(|p| measure_dir(p, deadline)).collect()),
        Source::File(path) => measure_file(path),
        Source::RecycleBin(drive) => measure_recycle_bin(*drive),
    }
}

fn candidate_line(label: &str, shown: &str, measure: &Measure) -> Option<String> {
    let size = match measure {
        Measure::Absent => return None,
        Measure::Denied => "unreadable (needs administrator rights)".to_string(),
        Measure::Failed(code) => format!("unreadable (error {code})"),
        Measure::Size {
            bytes,
            timed_out,
            unreadable,
            items,
        } => {
            let mut text = format_size(*bytes);
            if *timed_out || *unreadable > 0 {
                text = format!("at least {text}");
            }
            if let Some(items) = items {
                text.push_str(&format!(", {items} items"));
            }
            if *timed_out {
                text.push_str(", counting stopped at the time limit");
            }
            if *unreadable > 0 {
                text.push_str(&format!(", {unreadable} folders unreadable"));
            }
            text
        }
    };
    Some(format!("  {label}: {size}\n    {shown}"))
}

pub struct Report {
    pub drive: char,
    pub free: u64,
    pub total: u64,
    pub root: Node,
    pub top: usize,
    pub depth: usize,
    pub seconds: u64,
    pub walked: Duration,
    pub timed_out: bool,
    pub unreadable: u64,
    pub reparse: u64,
    pub placeholders: u64,
    pub candidates: Vec<(String, String, Measure)>,
}

/// Redacts account and computer names in each path part, leaving the `[user]` labels alone
/// (the shared redaction would mangle them).
pub fn redact_display(display: &str, names: &[String]) -> String {
    display
        .split('\\')
        .map(|part| {
            if part.starts_with("[user") {
                part.to_string()
            } else {
                events::redact(part, names)
            }
        })
        .collect::<Vec<_>>()
        .join("\\")
}

/// A folder size, or "at least" when the count was cut off inside the folder.
pub fn size_text(bytes: u64, complete: bool) -> String {
    if complete {
        format_size(bytes)
    } else {
        format!("at least {}, not finished", format_size(bytes))
    }
}

pub fn render(report: &Report) -> Vec<String> {
    let used = report.total.saturating_sub(report.free);
    let percent = (report.free * 100).checked_div(report.total).unwrap_or(0);
    let mut lines = vec![format!(
        "Drive {}: {} free of {} ({percent} % free).",
        report.drive,
        format_size(report.free),
        format_size(report.total)
    )];
    lines.push(format!(
        "Used {}; the walk counted {} in folders (the rest is protected folders and system files, or time ran out).",
        format_size(used),
        format_size(report.root.size)
    ));
    lines.push(format!(
        "Walk time: {:.1} s of the {} s limit.",
        report.walked.as_secs_f64(),
        report.seconds
    ));
    lines.push(format!(
        "Largest folders (top {}, down to {} levels; file sizes, hard links count each time):",
        report.top, report.depth
    ));
    let top = top_nodes(&report.root, report.top);
    if top.is_empty() {
        lines.push("  none found".into());
    }
    let sizes: Vec<String> = top.iter().map(|n| size_text(n.size, n.complete)).collect();
    let names = events::local_names();
    let width = sizes.iter().map(String::len).max().unwrap_or(0);
    for (node, size) in top.iter().zip(&sizes) {
        lines.push(format!(
            "{size:>width$}  {}{}",
            "  ".repeat(node.level - 1),
            redact_display(&node.display, &names)
        ));
    }
    lines.push(
        "Cleanup candidates (candidates only, not instructions; this tool deletes nothing):".into(),
    );
    let mut absent = Vec::new();
    let mut any = false;
    for (label, shown, measure) in &report.candidates {
        match candidate_line(label, shown, measure) {
            Some(line) => {
                any = true;
                lines.push(line);
            }
            None => absent.push(label.as_str()),
        }
    }
    if !any {
        lines.push("  none found".into());
    }
    if !absent.is_empty() {
        lines.push(format!("Not present on this drive: {}.", absent.join(", ")));
    }
    lines.push(format!(
        "Unreadable folders: {} (protected or need administrator rights). Reparse points not followed: {}. Cloud-only placeholders counted as 0 bytes: {}.",
        report.unreadable, report.reparse, report.placeholders
    ));
    if report.timed_out {
        lines.push(format!(
            "Partial result: the {} second limit ended the walk, so folders marked \"not finished\" are larger than listed. Raise --seconds for more.",
            report.seconds
        ));
    }
    lines
}

fn candidate_json(label: &str, shown: &str, measure: &Measure) -> Value {
    let (state, detail) = match measure {
        Measure::Absent => ("not_present", json!({})),
        Measure::Denied => (
            "unavailable",
            json!({ "unavailable": "needs administrator rights" }),
        ),
        Measure::Failed(code) => (
            "unavailable",
            json!({ "unavailable": format!("error {code}") }),
        ),
        Measure::Size {
            bytes,
            timed_out,
            unreadable,
            items,
        } => (
            "measured",
            json!({
                "bytes": bytes,
                "at_least": *timed_out || *unreadable > 0,
                "items": items,
                "counting_stopped_at_time_limit": timed_out,
                "folders_unreadable": unreadable,
            }),
        ),
    };
    let mut value = json!({ "label": label, "path": shown, "state": state });
    if let (Some(target), Some(extra)) = (value.as_object_mut(), detail.as_object()) {
        target.extend(extra.clone());
    }
    value
}

/// The same readings as `render`, as JSON: sizes in bytes, a folder cut off by the time
/// limit marked `complete: false`, and the limits that applied.
pub fn report_json(report: &Report) -> Value {
    let names = events::local_names();
    let top = top_nodes(&report.root, report.top);
    json!({
        "tool": "space",
        "drive": format!("{}:", report.drive),
        "free_bytes": report.free,
        "total_bytes": report.total,
        "used_bytes": report.total.saturating_sub(report.free),
        "counted_in_folders_bytes": report.root.size,
        "walk_seconds": report.walked.as_secs_f64(),
        "limits": {
            "seconds": report.seconds,
            "top": report.top,
            "depth": report.depth,
            "time_limit_ended_walk": report.timed_out,
        },
        "largest_folders": top.iter().map(|node| json!({
            "path": redact_display(&node.display, &names),
            "level": node.level,
            "bytes": node.size,
            "complete": node.complete,
        })).collect::<Vec<_>>(),
        "cleanup_candidates": report.candidates.iter()
            .map(|(label, shown, measure)| candidate_json(label, shown, measure))
            .collect::<Vec<_>>(),
        "unreadable_folders": report.unreadable,
        "reparse_points_not_followed": report.reparse,
        "cloud_placeholders_counted_as_zero": report.placeholders,
    })
}

fn parse_drive(text: &str) -> Result<char, String> {
    let letter = text.trim_end_matches([':', '\\']);
    let mut chars = letter.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() => Ok(c.to_ascii_uppercase()),
        _ => Err(format!(
            "--drive takes a drive letter such as C, not {text}"
        )),
    }
}

pub fn windows_dir() -> Option<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buffer = [0u16; 260];
    // SAFETY: buffer is writable for its stated length.
    let len =
        unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    (len > 0 && len < buffer.len()).then(|| PathBuf::from(OsString::from_wide(&buffer[..len])))
}

pub fn disk_space(drive: char) -> Result<(u64, u64), String> {
    crate::live::reading("drive space");
    let root: Vec<u16> = format!("{drive}:\\").encode_utf16().chain([0]).collect();
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: root is NUL-terminated and the three out pointers are valid.
    let ok = unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, &mut total, &mut total_free) };
    if ok == 0 {
        return Err(format!(
            "Drive {drive}: could not be read (no such drive, or no media)"
        ));
    }
    Ok((free, total))
}

fn run(args: &Args) -> Result<Output, String> {
    let started = Instant::now();
    let windows = windows_dir();
    let drive = match args.value("--drive") {
        Some(text) => parse_drive(text)?,
        None => windows
            .as_ref()
            .and_then(|w| w.to_string_lossy().chars().next())
            .map_or('C', |c| c.to_ascii_uppercase()),
    };
    let top = args.number("--top", 15, 1, 50)? as usize;
    let depth = args.number("--depth", 3, 1, 6)? as usize;
    let seconds = args.number("--seconds", 60, 5, 300)?;
    let (free, total) = disk_space(drive)?;

    let on_drive = |p: &Path| {
        p.to_string_lossy()
            .to_ascii_uppercase()
            .starts_with(&format!("{drive}:"))
    };
    let windows_here = windows
        .filter(|w| on_drive(w))
        .unwrap_or_else(|| PathBuf::from(format!("{drive}:\\Windows")));
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| on_drive(p));
    let end = started + Duration::from_secs(seconds);
    let candidate_end = started + Duration::from_secs(seconds.div_ceil(3));
    let sources = candidates(drive, &windows_here, local.as_deref());
    let count = sources.len() as u32;
    let mut measured_all = Vec::new();
    for (index, c) in sources.into_iter().enumerate() {
        // Each candidate gets an equal share of the time left, so early ones cannot starve later ones.
        let left = candidate_end.saturating_duration_since(Instant::now());
        let share = Instant::now() + left / (count - index as u32);
        let measured = measure(&c.source, share);
        measured_all.push((c.label.to_string(), c.shown, measured));
    }
    let candidates = measured_all;

    let root_path = PathBuf::from(format!("{drive}:\\"));
    let walk_started = Instant::now();
    let (root, ctx) = walk(&root_path, format!("{drive}:"), depth, end, POOL);
    let walked = walk_started.elapsed();
    let timed_out = ctx.timed_out;
    let report = Report {
        drive,
        free,
        total,
        root,
        top,
        depth,
        seconds,
        walked,
        timed_out,
        unreadable: ctx.unreadable,
        reparse: ctx.reparse,
        placeholders: ctx.placeholders,
        candidates,
    };
    Ok(Output {
        text: render(&report).join("\n"),
        data: report_json(&report),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn node(display: &str, level: usize, size: u64, children: Vec<Node>) -> Node {
        Node {
            display: display.into(),
            level,
            size,
            complete: true,
            children,
        }
    }

    /// A temporary folder tree, removed (junction first) when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("diagtool-space-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, relative: &str, size: usize) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![b'x'; size]).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir(self.0.join("link"));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scan(root: &Path, depth: usize, deadline: Instant) -> (Node, Ctx) {
        walk(root, "T:".into(), depth, deadline, POOL)
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn sizes_are_formatted_in_binary_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536 * 1024), "1.5 MiB");
        assert_eq!(format_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
        assert_eq!(format_size(3 * 1024u64.pow(4)), "3.0 TiB");
    }

    #[test]
    fn profile_names_are_redacted_but_shared_profiles_are_not() {
        assert_eq!(
            redact_profile(r"C:\Users\Bob\AppData\Local\Temp"),
            r"C:\Users\[user]\AppData\Local\Temp"
        );
        assert_eq!(redact_profile(r"c:\users\bob"), r"c:\users\[user]");
        assert_eq!(
            redact_profile(r"\\?\C:\Users\Bob\Desktop"),
            r"\\?\C:\Users\[user]\Desktop"
        );
        assert_eq!(
            redact_profile(r"C:\Users\Public\Documents"),
            r"C:\Users\Public\Documents"
        );
        assert_eq!(redact_profile(r"C:\Windows\Temp"), r"C:\Windows\Temp");
        assert_eq!(redact_profile(r"C:\Users"), r"C:\Users");
    }

    #[test]
    fn folders_under_a_profile_stop_one_level_below_it() {
        assert!(node_wanted(3, 6, Some(2)));
        assert!(!node_wanted(4, 6, Some(2)));
        assert!(node_wanted(4, 6, None));
        assert!(!node_wanted(4, 3, None));
    }

    #[test]
    fn deep_profile_folders_roll_up_into_their_first_level_folder() {
        let scratch = Scratch::new("profile");
        scratch.file(r"Users\bob\Documents\a\b\c.bin", 1000);
        scratch.file(r"Users\bob\AppData\Local\Temp\t.bin", 500);
        scratch.file(r"Users\Public\p.bin", 7);
        scratch.file(r"Windows\System32\drivers\d.bin", 200);
        let (root, ctx) = scan(&scratch.0, 6, later());
        assert!(!ctx.timed_out);
        assert_eq!(root.size, 1707);
        let users = &root
            .children
            .iter()
            .find(|n| n.display.ends_with("Users"))
            .unwrap();
        let user = users
            .children
            .iter()
            .find(|n| n.display.ends_with("[user]"))
            .unwrap();
        assert_eq!(user.size, 1500);
        let names: Vec<&str> = user.children.iter().map(|n| n.display.as_str()).collect();
        assert_eq!(
            names,
            [r"T:\Users\[user]\Documents", r"T:\Users\[user]\AppData"]
        );
        assert!(user.children.iter().all(|n| n.children.is_empty()));
        assert_eq!(user.children[1].size, 500);
        assert!(users.children.iter().any(|n| n.display.ends_with("Public")));
        let windows = root
            .children
            .iter()
            .find(|n| n.display.ends_with("Windows"))
            .unwrap();
        assert_eq!(
            windows.children[0].children[0].display,
            r"T:\Windows\System32\drivers"
        );
        assert!(!format!("{root:?}").to_lowercase().contains("bob"));
    }

    #[test]
    fn top_n_keeps_the_largest_folders_in_tree_order() {
        let root = node(
            "T:",
            0,
            100,
            vec![
                node(
                    "T:\\a",
                    1,
                    60,
                    vec![
                        node("T:\\a\\x", 2, 50, vec![]),
                        node("T:\\a\\y", 2, 10, vec![]),
                    ],
                ),
                node("T:\\b", 1, 30, vec![]),
                node("T:\\c", 1, 0, vec![]),
            ],
        );
        let names = |n| {
            top_nodes(&root, n)
                .iter()
                .map(|x| x.display.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(3), ["T:\\a", "T:\\a\\x", "T:\\b"]);
        assert_eq!(names(1), ["T:\\a"]);
        assert_eq!(names(50), ["T:\\a", "T:\\a\\x", "T:\\a\\y", "T:\\b"]);
    }

    #[test]
    fn attributes_decide_what_is_followed_or_counted() {
        assert_eq!(classify(FILE_ATTRIBUTE_DIRECTORY), Kind::Dir);
        assert_eq!(classify(0x20), Kind::File);
        assert_eq!(
            classify(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT),
            Kind::Reparse
        );
        assert_eq!(
            classify(0x20 | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
            Kind::Cloud
        );
        assert_eq!(classify(0x20 | FILE_ATTRIBUTE_OFFLINE), Kind::Cloud);
        assert_eq!(
            classify(
                FILE_ATTRIBUTE_DIRECTORY
                    | FILE_ATTRIBUTE_REPARSE_POINT
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            ),
            Kind::Cloud
        );
    }

    #[test]
    fn a_junction_is_not_followed() {
        let scratch = Scratch::new("junction");
        scratch.file(r"real\big.bin", 4000);
        scratch.file("small.bin", 10);
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(scratch.0.join("link"))
            .arg(scratch.0.join("real"))
            .output();
        if !status.is_ok_and(|o| o.status.success()) {
            eprintln!(
                "SKIPPED a_junction_is_not_followed: mklink /J failed here, nothing was checked"
            );
            return;
        }
        eprintln!("a_junction_is_not_followed: junction created, checking");
        let (root, ctx) = scan(&scratch.0, 2, later());
        assert_eq!(
            root.size, 4010,
            "the target counts once, through its real path"
        );
        assert_eq!(ctx.reparse, 1);
        assert!(root.children.iter().all(|n| !n.display.ends_with("link")));
    }

    #[test]
    fn an_expired_limit_gives_a_partial_result() {
        let scratch = Scratch::new("partial");
        scratch.file(r"a\f.bin", 10);
        let (root, ctx) = scan(&scratch.0, 2, Instant::now());
        assert!(ctx.timed_out);
        assert_eq!(root.size, 0);
        assert!(!root.complete, "the root was never counted");
        let report = Report {
            drive: 'T',
            free: 1,
            total: 2,
            root,
            top: 5,
            depth: 2,
            seconds: 5,
            walked: Duration::ZERO,
            timed_out: true,
            unreadable: 0,
            reparse: 0,
            placeholders: 0,
            candidates: vec![],
        };
        assert!(render(&report)
            .iter()
            .any(|l| l.starts_with("Partial result")));
    }

    #[test]
    fn unreadable_folders_are_counted() {
        let (root, ctx) = scan(Path::new(r"Z:\no\such\folder"), 2, later());
        assert_eq!(root.size, 0);
        assert_eq!(ctx.unreadable, 1);
    }

    #[test]
    fn candidate_measures_combine_and_print() {
        let size = |bytes| Measure::Size {
            bytes,
            timed_out: false,
            unreadable: 0,
            items: None,
        };
        assert_eq!(
            combine(vec![Measure::Absent, Measure::Absent]),
            Measure::Absent
        );
        assert_eq!(combine(vec![size(5), Measure::Absent, size(7)]), size(12));
        assert_eq!(
            combine(vec![Measure::Denied, Measure::Absent]),
            Measure::Denied
        );
        assert!(matches!(
            combine(vec![size(5), Measure::Denied]),
            Measure::Size {
                bytes: 5,
                unreadable: 1,
                ..
            }
        ));
        assert_eq!(candidate_line("Gone", "x", &Measure::Absent), None);
        let line = candidate_line("Windows temp folder", r"C:\Windows\Temp", &size(2048)).unwrap();
        assert!(line.contains("2.0 KiB") && line.contains(r"C:\Windows\Temp"));
        assert!(candidate_line("D", "p", &Measure::Denied)
            .unwrap()
            .contains("needs administrator rights"));
        let cut = Measure::Size {
            bytes: 1024,
            timed_out: true,
            unreadable: 0,
            items: None,
        };
        assert!(candidate_line("D", "p", &cut)
            .unwrap()
            .contains("at least 1.0 KiB"));
    }

    #[test]
    fn json_agrees_with_the_text_on_folders_candidates_and_limits() {
        let scratch = Scratch::new("json");
        scratch.file(r"one\a.bin", 3000);
        scratch.file(r"two\c.bin", 500);
        let (root, _) = scan(&scratch.0, 2, later());
        let size = |bytes| Measure::Size {
            bytes,
            timed_out: false,
            unreadable: 0,
            items: None,
        };
        let report = Report {
            drive: 'T',
            free: 10 * 1024,
            total: 100 * 1024,
            root,
            top: 2,
            depth: 2,
            seconds: 5,
            walked: Duration::ZERO,
            timed_out: true,
            unreadable: 3,
            reparse: 1,
            placeholders: 2,
            candidates: vec![
                (
                    "Windows temp folder".into(),
                    r"T:\Windows\Temp".into(),
                    size(2048),
                ),
                (
                    "Page file".into(),
                    r"T:\pagefile.sys".into(),
                    Measure::Absent,
                ),
                (
                    "Minidump".into(),
                    r"T:\Windows\Minidump".into(),
                    Measure::Denied,
                ),
                (
                    "Recycle Bin".into(),
                    r"T:\$Recycle.Bin".into(),
                    Measure::Size {
                        bytes: 1024,
                        timed_out: true,
                        unreadable: 0,
                        items: Some(4),
                    },
                ),
            ],
        };
        let (text, data) = (render(&report).join("\n"), report_json(&report));
        assert_eq!(data["drive"], "T:");
        assert_eq!(data["free_bytes"], 10 * 1024);
        assert!(text.contains("Drive T: 10.0 KiB free of 100.0 KiB (10 % free)."));
        assert_eq!(data["largest_folders"][0]["bytes"], 3000);
        assert!(text.contains("2.9 KiB  "));
        assert_eq!(data["counted_in_folders_bytes"], 3500);
        assert_eq!(data["limits"]["time_limit_ended_walk"], true);
        assert!(text.contains("Partial result: the 5 second limit"));
        let candidates = data["cleanup_candidates"].as_array().unwrap();
        assert_eq!(candidates[0]["bytes"], 2048);
        assert_eq!(candidates[0]["at_least"], false);
        assert_eq!(candidates[1]["state"], "not_present");
        assert!(text.contains("Not present on this drive: Page file."));
        assert_eq!(candidates[2]["unavailable"], "needs administrator rights");
        assert_eq!(candidates[3]["at_least"], true);
        assert_eq!(candidates[3]["items"], 4);
        assert!(text.contains("at least 1.0 KiB, 4 items, counting stopped"));
        assert_eq!(data["unreadable_folders"], 3);
        assert_eq!(data["reparse_points_not_followed"], 1);
        assert_eq!(data["cloud_placeholders_counted_as_zero"], 2);
    }

    #[test]
    fn a_small_tree_is_measured_and_rendered() {
        let scratch = Scratch::new("tree");
        scratch.file(r"one\a.bin", 3000);
        scratch.file(r"one\sub\b.bin", 1000);
        scratch.file(r"two\c.bin", 500);
        let (root, ctx) = scan(&scratch.0, 2, later());
        assert_eq!(root.size, 4500);
        assert_eq!(ctx.unreadable, 0);
        let report = Report {
            drive: 'T',
            free: 10 * 1024,
            total: 100 * 1024,
            root,
            top: 3,
            depth: 2,
            seconds: 5,
            walked: Duration::ZERO,
            timed_out: false,
            unreadable: 0,
            reparse: 0,
            placeholders: 0,
            candidates: vec![("Temp".into(), "T:\\Temp".into(), Measure::Absent)],
        };
        let text = render(&report).join("\n");
        assert!(text.contains("10.0 KiB free of 100.0 KiB (10 % free)"));
        assert!(text.contains("3.9 KiB  T:\\"), "{text}");
        assert!(text.contains("Not present on this drive: Temp."));
        assert!(!text.contains("Partial result"));
    }

    #[test]
    fn the_queue_drains_the_same_way_with_one_thread_or_many() {
        let scratch = Scratch::new("queue");
        let mut expected = 0u64;
        for top in 0..12 {
            for sub in 0..6 {
                for leaf in 0..4 {
                    let size = 10 + top * 7 + sub * 3 + leaf;
                    scratch.file(&format!(r"t{top}\s{sub}\l{leaf}\f.bin"), size);
                    expected += size as u64;
                }
            }
        }
        let one = walk(&scratch.0, "T:".into(), 3, later(), 1);
        for _ in 0..5 {
            let many = walk(&scratch.0, "T:".into(), 3, later(), 8);
            assert_eq!(many.0.size, expected);
            assert!(many.0.complete && !many.1.timed_out);
            assert_eq!(many.0.children.len(), 12);
            let shape = |n: &Node| -> Vec<(String, u64)> {
                n.children
                    .iter()
                    .map(|c| (c.display.clone(), c.size))
                    .collect()
            };
            assert_eq!(shape(&many.0), shape(&one.0));
            assert_eq!(shape(&many.0.children[0]), shape(&one.0.children[0]));
        }
        assert_eq!(one.0.size, expected);
        assert!(one.0.children.iter().all(|c| c.children.len() == 6));
    }

    #[test]
    fn unfinished_folders_are_marked_and_printed_as_a_minimum() {
        let mut root = node(
            "T:",
            0,
            100,
            vec![
                node("T:\\done", 1, 60, vec![]),
                node("T:\\cut", 1, 40, vec![]),
            ],
        );
        root.children[1].complete = false;
        assert_eq!(size_text(2048, true), "2.0 KiB");
        assert_eq!(size_text(2048, false), "at least 2.0 KiB, not finished");
        let report = Report {
            drive: 'T',
            free: 1,
            total: 2,
            root,
            top: 5,
            depth: 1,
            seconds: 5,
            walked: Duration::ZERO,
            timed_out: true,
            unreadable: 0,
            reparse: 0,
            placeholders: 0,
            candidates: vec![],
        };
        let text = render(&report).join("\n");
        let cut = text.lines().find(|l| l.ends_with("T:\\cut")).unwrap();
        let done = text.lines().find(|l| l.ends_with("T:\\done")).unwrap();
        assert!(cut.contains("at least 40 B, not finished"));
        assert!(!done.contains("not finished"));
    }

    #[test]
    fn a_limit_hit_with_work_queued_marks_the_unfinished_folders() {
        let scratch = Scratch::new("cut");
        for top in 0..40 {
            scratch.file(&format!(r"t{top}\a\b\f.bin"), 10);
        }
        let (root, ctx) = scan(&scratch.0, 2, Instant::now());
        assert!(ctx.timed_out && !root.complete);
        let (root, ctx) = scan(&scratch.0, 2, later());
        assert!(!ctx.timed_out && root.complete);
        assert!(root.children.iter().all(|c| c.complete));
    }

    #[test]
    fn profile_labels_survive_display_redaction() {
        let names = vec!["bob".to_string(), "pc01".to_string()];
        assert_eq!(
            redact_display(r"C:\Users\[user 2]\AppData", &names),
            r"C:\Users\[user 2]\AppData"
        );
        assert_eq!(
            redact_display(r"C:\Users\[user]", &names),
            r"C:\Users\[user]"
        );
        assert!(!redact_display(r"C:\bob", &names).contains("bob"));
    }

    #[test]
    fn drive_letters_are_validated() {
        assert_eq!(parse_drive("c"), Ok('C'));
        assert_eq!(parse_drive("d:"), Ok('D'));
        assert_eq!(parse_drive(r"E:\"), Ok('E'));
        assert!(parse_drive("CD").is_err());
        assert!(parse_drive("1").is_err());
    }

    #[test]
    fn this_pc_reports_the_windows_drive_within_the_limit() {
        let args = Args::parse(
            &["--depth", "1", "--seconds", "5", "--top", "5"].map(String::from),
            TOOL.usage,
        )
        .unwrap();
        let started = Instant::now();
        let output = run(&args).unwrap();
        let text = output.text;
        let parsed: Value = serde_json::from_str(&output.data.to_string()).unwrap();
        assert_eq!(parsed["tool"], "space");
        assert!(parsed["total_bytes"].as_u64().unwrap() > 0);
        assert!(parsed["largest_folders"].as_array().unwrap().len() <= 5);
        assert!(started.elapsed() < Duration::from_secs(12));
        assert!(text.starts_with("Drive "));
        assert!(text.contains("Cleanup candidates"));
    }
}
