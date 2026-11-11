//! Crash dump readiness: whether the next crash leaves a dump to read, and setting that up.
//!
//! Three entry points, each with typed options, typed progress events, a cancel flag and a
//! typed result, so the window and an agent drive the same engine:
//! - [`check`] reads the kernel and application crash dump settings, whether a dump of the
//!   chosen type can be written, what deletes dumps on its own and the dumps already there.
//! - [`set_up`] writes Microsoft's default kernel settings (or the technician's choices) and
//!   turns on application dumps, after saving every value it changes.
//! - [`put_back`] restores exactly what [`set_up`] found, after a restart of the app too.
//!
//! Every guard lives here: the window only builds options and shows events and results.
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};

mod hold;
mod machine;
mod places;
mod readiness;
mod setup;
mod windows;

#[cfg(test)]
mod fake;

pub use machine::{Hive, RawValue};
pub(crate) use windows::{process_identity, process_running};

/// The file holding the values set up changed, as they were before.
pub const BACKUP_FILE: &str = r"%ProgramData%\DiagnosticTool\crash-dump-settings-before.json";
pub const DEFAULT_DUMP_FILE: &str = r"%SystemRoot%\MEMORY.DMP";
pub const DEFAULT_MINIDUMP_FOLDER: &str = r"%SystemRoot%\Minidump";
pub const DEFAULT_APP_FOLDER: &str = r"%ProgramData%\DiagnosticTool\CrashDumps";
pub const MAX_APP_DUMPS: u32 = 100;
pub const MAX_FILES_LISTED: u32 = 1000;

/// The kernel dump types Windows offers, as `CrashDumpEnabled` (and `FilterPages`) set them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelDumpType {
    /// CrashDumpEnabled 3: the stop code, loaded drivers and the stopped thread's stack.
    Small,
    /// CrashDumpEnabled 2: kernel memory only.
    Kernel,
    /// CrashDumpEnabled 1: all of memory.
    Complete,
    /// CrashDumpEnabled 7: a kernel dump with a page file Windows sizes; Windows' default.
    Automatic,
    /// CrashDumpEnabled 1 with FilterPages 1: memory in use, without free and cached pages.
    Active,
}

impl KernelDumpType {
    pub const ALL: [KernelDumpType; 5] = [
        KernelDumpType::Automatic,
        KernelDumpType::Kernel,
        KernelDumpType::Small,
        KernelDumpType::Active,
        KernelDumpType::Complete,
    ];

    pub fn name(self) -> &'static str {
        match self {
            KernelDumpType::Small => "small memory dump",
            KernelDumpType::Kernel => "kernel memory dump",
            KernelDumpType::Complete => "complete memory dump",
            KernelDumpType::Automatic => "automatic memory dump",
            KernelDumpType::Active => "active memory dump",
        }
    }

    /// The name after "a" or "an", as a sentence uses it.
    pub fn with_article(self) -> String {
        let name = self.name();
        let article = if name.starts_with(['a', 'e', 'i', 'o', 'u']) {
            "an"
        } else {
            "a"
        };
        format!("{article} {name}")
    }

    pub fn crash_dump_enabled(self) -> u32 {
        match self {
            KernelDumpType::Small => 3,
            KernelDumpType::Kernel => 2,
            KernelDumpType::Complete | KernelDumpType::Active => 1,
            KernelDumpType::Automatic => 7,
        }
    }

    /// The type `CrashDumpEnabled` and `FilterPages` name: `Ok(None)` for none, `Err` for a
    /// number Windows does not document.
    pub fn from_registry(enabled: u32, filter_pages: Option<u32>) -> Result<Option<Self>, u32> {
        Ok(Some(match enabled {
            0 => return Ok(None),
            1 if filter_pages == Some(1) => KernelDumpType::Active,
            1 => KernelDumpType::Complete,
            2 => KernelDumpType::Kernel,
            3 => KernelDumpType::Small,
            7 => KernelDumpType::Automatic,
            other => return Err(other),
        }))
    }
}

/// Application dump types for `LocalDumps\DumpType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppDumpType {
    /// DumpType 1: threads, stacks and modules; a few megabytes each.
    Mini,
    /// DumpType 2: the whole process memory; as large as the program was.
    Full,
}

impl AppDumpType {
    pub fn value(self) -> u32 {
        match self {
            AppDumpType::Mini => 1,
            AppDumpType::Full => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AppDumpType::Mini => "mini dump",
            AppDumpType::Full => "full dump",
        }
    }
}

/// What [`check`] reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckOptions {
    /// Lists the dump files already present: count, newest, size. The Windows folder's
    /// dump folders need administrator rights and are said to when they cannot be read.
    pub list_dumps: bool,
    /// The most dump files counted in each place, 1 to 1,000. Default 200.
    pub max_files: u32,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            list_dumps: true,
            max_files: 200,
        }
    }
}

/// What [`set_up`] changes. `None` for a side leaves that side exactly as it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetUpOptions {
    /// The technician has seen the changes a run with `confirmed: false` listed and agreed.
    /// Without it nothing is written and the result lists what would change.
    pub confirmed: bool,
    /// Kernel crash dump settings under CrashControl.
    pub kernel: Option<KernelOptions>,
    /// Application crash dumps under Windows Error Reporting\LocalDumps.
    pub applications: Option<AppOptions>,
}

impl Default for SetUpOptions {
    fn default() -> Self {
        Self {
            confirmed: false,
            kernel: Some(KernelOptions::default()),
            applications: Some(AppOptions::default()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelOptions {
    /// Any type; none is not a set-up. Default automatic, Windows' own default.
    pub dump_type: KernelDumpType,
    /// The memory dump file: an absolute path ending in `.dmp` on a local fixed disk, at
    /// most 260 characters; `%SystemRoot%` is the only variable allowed, because Windows
    /// writes it before anyone signs in. Default `%SystemRoot%\MEMORY.DMP`.
    pub dump_file: String,
    /// The folder for small memory dumps, by the same rules. Default `%SystemRoot%\Minidump`.
    pub minidump_folder: String,
    /// Whether Windows restarts after a stop (`AutoReboot`); `None` leaves it as it is.
    pub restart_after_stop: Option<bool>,
}

impl Default for KernelOptions {
    fn default() -> Self {
        Self {
            dump_type: KernelDumpType::Automatic,
            dump_file: DEFAULT_DUMP_FILE.into(),
            minidump_folder: DEFAULT_MINIDUMP_FOLDER.into(),
            restart_after_stop: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppOptions {
    /// The folder for application dumps: an absolute path on a local fixed disk, at most
    /// 260 characters; only machine-wide variables (`%ProgramData%`, `%SystemDrive%`,
    /// `%SystemRoot%`) are allowed, since every account's crashes share it. Default
    /// `%ProgramData%\DiagnosticTool\CrashDumps`.
    pub folder: String,
    /// Mini (default) or full.
    pub dump_type: AppDumpType,
    /// How many dumps Windows keeps before replacing the oldest, 1 to 100. Default 10.
    pub count: u32,
}

impl Default for AppOptions {
    fn default() -> Self {
        Self {
            folder: DEFAULT_APP_FOLDER.into(),
            dump_type: AppDumpType::Mini,
            count: 10,
        }
    }
}

/// What [`put_back`] does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutBackOptions {
    /// The technician has seen what a run with `confirmed: false` listed and agreed.
    pub confirmed: bool,
}

/// Progress, in the order it happens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// What the engine is doing now.
    Step { text: String },
    /// One readiness item, read.
    Item { item: Item },
    /// One change made to the PC.
    Changed { change: Change },
}

/// Whether one part of crash dump readiness is in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    Ready,
    NeedsChange { reason: String },
    CouldNotRead { reason: String },
}

impl Status {
    pub fn word(&self) -> &'static str {
        match self {
            Status::Ready => "Ready",
            Status::NeedsChange { .. } => "Needs a change",
            Status::CouldNotRead { .. } => "Could not read",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Status::Ready => None,
            Status::NeedsChange { reason } | Status::CouldNotRead { reason } => Some(reason),
        }
    }
}

/// One part of readiness, in plain English for a technician.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Stable id, such as `kernel.type`.
    pub id: String,
    pub label: String,
    pub status: Status,
    /// What is there now, in one line.
    pub summary: String,
    /// The values and figures behind it.
    pub details: Vec<String>,
}

/// One registry value as read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    /// The full name, such as `HKLM\SYSTEM\...\CrashControl\CrashDumpEnabled`.
    pub name: String,
    /// The value, or `None` when it is absent.
    pub value: Option<RawValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// Everything asked for was done.
    Done,
    /// `confirmed` was false: nothing was written, and `planned` lists what would change.
    NotConfirmed,
    /// Nothing needed changing.
    NothingToDo,
    /// The engine would not do it, for these reasons; nothing was written.
    Refused { reasons: Vec<String> },
    /// The cancel flag stopped it; `changed` lists what was done before it stopped.
    Stopped,
    /// A step failed; `changed` lists what was done before it.
    Failed { reason: String },
}

/// One change, planned or made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// The registry value or folder changed.
    pub target: String,
    /// What it held before, in plain words ("absent" when it was not there).
    pub before: String,
    pub after: String,
    /// The change as a sentence.
    pub text: String,
    /// Whether it takes effect only after Windows restarts.
    pub needs_restart: bool,
}

/// What [`check`] found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub outcome: Outcome,
    pub items: Vec<Item>,
    /// Every registry value read, raw.
    pub settings: Vec<Setting>,
    /// Whether this process has administrator rights; `None` when unreadable.
    pub elevated: Option<bool>,
    /// The values set up changed are kept for Put back.
    pub put_back_available: bool,
}

/// What [`set_up`] or [`put_back`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeResult {
    pub outcome: Outcome,
    /// What this run changes, or would change.
    pub planned: Vec<Change>,
    /// What it changed.
    pub changed: Vec<Change>,
    /// Plain notes: choices made and why, what was left and why.
    pub notes: Vec<String>,
    /// A change made needs a Windows restart to take effect. The engine never restarts.
    pub restart_needed: bool,
    /// The file holding the values as they were before set up.
    pub backup: PathBuf,
}

/// Reads crash dump readiness. Read only; runs without administrator rights, with the
/// places that need them said to be unreadable.
pub fn check(
    options: &CheckOptions,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> CheckResult {
    readiness::check(&windows::Windows, options, progress, cancel)
}

/// Sets up crash dumps. Needs administrator rights and `confirmed`; kernel changes take
/// effect after the next restart, which the engine never starts.
pub fn set_up(
    options: &SetUpOptions,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> ChangeResult {
    windows::exclusive(|| {
        Ok(setup::set_up(
            &mut windows::Windows,
            options,
            progress,
            cancel,
        ))
    })
    .unwrap_or_else(|why| setup::result(Outcome::Failed { reason: why }, PathBuf::new()))
}

/// Puts back every value set up changed, exactly as it was, and removes what set up made
/// when it is still empty. Needs administrator rights and `confirmed`. This program's own
/// exclusion from application dumps stays while a recovery window relies on it.
pub fn put_back(
    options: &PutBackOptions,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> ChangeResult {
    windows::exclusive(|| {
        Ok(setup::put_back(
            &mut windows::Windows,
            options,
            progress,
            cancel,
        ))
    })
    .unwrap_or_else(|why| setup::result(Outcome::Failed { reason: why }, PathBuf::new()))
}

/// Unit tests leave this PC's crash dump settings alone unless a live test turns this on.
#[cfg(test)]
pub(crate) static TOUCH_MACHINE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn touch_machine() -> bool {
    #[cfg(test)]
    return TOUCH_MACHINE.load(std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(test))]
    true
}

/// The process's exclusion while any share of it lives.
static CURRENT: std::sync::Mutex<std::sync::Weak<Held>> =
    std::sync::Mutex::new(std::sync::Weak::new());

fn current() -> std::sync::MutexGuard<'static, std::sync::Weak<Held>> {
    CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The exclusion itself; the last share dropped lets it go.
struct Held(());

impl Drop for Held {
    fn drop(&mut self) {
        let current = current();
        // A new exclusion made while this one was ending keeps the value.
        if current.strong_count() > 0 || !touch_machine() {
            return;
        }
        let mut m = windows::Windows;
        let let_go = windows::exclusive(|| hold::let_go(&mut m));
        record_outcome(&mut m, let_go);
    }
}

/// A share of this program's exclusion from application crash dumps (see
/// `keep_out_of_dumps`). Every value that holds a recovery key, and every thread that may
/// still read one, holds a share; cloning makes another, and the exclusion is let go when
/// the last share in the process is dropped.
#[derive(Clone)]
#[must_use = "the exclusion lasts only while this value lives"]
pub struct DumpExclusion(std::sync::Arc<Held>);

impl DumpExclusion {
    /// Whether two shares are of the same exclusion.
    pub fn same(&self, other: &DumpExclusion) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for DumpExclusion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DumpExclusion")
    }
}

/// Changes to the exclusion that could not be entered in the session's change record, and
/// failures to take it away, kept for the window to show (`unrecorded`).
static UNRECORDED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Enters the exclusion's changes in the session's change record; lines that cannot be
/// entered are kept for `unrecorded`, so a change missing from the record is still said.
fn record(m: &mut windows::Windows, what: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    if let Err(why) = machine::Machine::record_changes(m, what, lines) {
        let mut kept = UNRECORDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        kept.push(format!(
            "{what}, not entered in the change record ({why}): {}",
            lines.join("; ")
        ));
    }
}

/// Records what letting go or settling did, or that it failed: the exclusion is then left
/// for the next start of the recovery window to take away.
fn record_outcome(m: &mut windows::Windows, done: Result<Vec<String>, String>) {
    match done {
        Ok(lines) => record(m, hold::LET_IN, &lines),
        Err(why) => record(
            m,
            "Could not take away this program's exclusion from crash dumps",
            &[format!(
                "{why}; it is taken away the next time the recovery window starts"
            )],
        ),
    }
}

/// Changes to this program's exclusion from crash dumps, and failures to take it away, that
/// could not be entered in the session's change record, emptied as they are read.
pub fn unrecorded() -> Vec<String> {
    std::mem::take(
        &mut *UNRECORDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Keeps this program out of dumps before a recovery key enters it. A dump of a program
/// holds its memory, and Windows keeps one of every program that crashes while application
/// crash dumps (LocalDumps) are on, as drivers and utilities often turn them on. So while
/// they are on, this writes this program's own `LocalDumps\<its file name>` `DumpCount` 0,
/// which Windows reads as keep no dump of it, records it in the session's change record and
/// reads it back, each time it is asked; the last share dropped in the last process relying
/// on it puts the value back as it was (or leaves it to crash dump set up's Put back when
/// set up keeps the same value), and one left by a process that ended is put back at the
/// next start (`settle_left_exclusion`). Err, a sentence saying why and what to do, only
/// when the value cannot be written and read back, or when AeDebug starts a debugger by
/// itself on a crash. Needs administrator rights only while application crash dumps are on.
pub fn keep_out_of_dumps() -> Result<DumpExclusion, String> {
    let mut current = current();
    if touch_machine() {
        let mut m = windows::Windows;
        let refused = match windows::exclusive(|| hold::keep_out(&mut m)) {
            Ok(lines) => {
                record(&mut m, hold::KEPT_OUT, &lines);
                setup::debugger_off(&m).err()
            }
            Err(why) => Some(why),
        };
        if let Some(why) = refused {
            if current.strong_count() == 0 {
                let let_go = windows::exclusive(|| hold::let_go(&mut m));
                record_outcome(&mut m, let_go);
            }
            return Err(why);
        }
    }
    if let Some(held) = current.upgrade() {
        return Ok(DumpExclusion(held));
    }
    let held = std::sync::Arc::new(Held(()));
    *current = std::sync::Arc::downgrade(&held);
    Ok(DumpExclusion(held))
}

/// A share of the exclusion for a value about to hold a recovery key: the process's
/// exclusion when one is held, or a new one (`keep_out_of_dumps`); `None` when it cannot be
/// made, and the caller that takes the key in refuses.
pub fn exclusion_share() -> Option<DumpExclusion> {
    if let Some(held) = current().upgrade() {
        return Some(DumpExclusion(held));
    }
    keep_out_of_dumps().ok()
}

/// Puts back an exclusion from crash dumps that a recovery window left when it ended
/// without letting go. The recovery window calls it as it starts.
pub fn settle_left_exclusion() {
    let mut m = windows::Windows;
    let settled = windows::exclusive(|| hold::settle_left(&mut m));
    record_outcome(&mut m, settled);
}

/// Whether this process has administrator rights; `None` when that cannot be read.
pub fn elevated() -> Option<bool> {
    crate::tools::crashes::elevated()
}

/// Megabytes as Windows counts them in page file settings.
const MIB: u64 = 1024 * 1024;
/// A dump's header (1 MB) and the driver data written after memory (up to 256 MB), which
/// Microsoft adds to RAM for a complete dump's page file.
const DUMP_EXTRA: u64 = 257 * MIB;

/// The page file or dedicated dump file space a dump of `dump` type needs: Microsoft's
/// figures, with the kernel memory in use now standing for kernel memory.
pub(crate) fn dump_room(dump: KernelDumpType, physical: u64, kernel: u64) -> u64 {
    match dump {
        KernelDumpType::Small => 2 * MIB,
        KernelDumpType::Kernel | KernelDumpType::Automatic => kernel + DUMP_EXTRA,
        KernelDumpType::Complete | KernelDumpType::Active => physical + DUMP_EXTRA,
    }
}

/// A path the engine may use: absolute, on a drive letter, without `..`, at most 260
/// characters once expanded. Returns the expanded path.
pub(crate) fn plain_path(expanded: &str) -> Result<PathBuf, String> {
    let bytes = expanded.as_bytes();
    let lettered =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !lettered {
        return Err(format!(
            "{expanded} is not a folder on a drive letter of this PC"
        ));
    }
    if expanded.chars().count() > 260 {
        return Err(format!("{expanded} is longer than 260 characters"));
    }
    if expanded
        .split('\\')
        .any(|part| part == ".." || part == "." || part.contains('%'))
        || expanded.contains('/')
        || expanded[2..].contains(':')
    {
        return Err(format!("{expanded} is not a plain path"));
    }
    Ok(PathBuf::from(expanded.trim_end_matches('\\')))
}

/// The first part of `path`, from its drive down, that is a junction, symbolic link or
/// other reparse point: a folder under one is somewhere else.
pub(crate) fn link_on_path<M: machine::Machine>(
    m: &M,
    path: &Path,
) -> Result<Option<PathBuf>, String> {
    let mut parts: Vec<&Path> = path.ancestors().collect();
    parts.reverse();
    for part in parts {
        if m.folder(part)? == machine::PathKind::Link {
            return Ok(Some(part.to_path_buf()));
        }
    }
    Ok(None)
}

/// Whether two paths name the same place, as Windows compares them.
pub(crate) fn same_place(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().trim_end_matches('\\').to_lowercase();
    norm(a) == norm(b)
}
