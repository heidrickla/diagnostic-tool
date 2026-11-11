//! The readiness check: reads settings through a `Machine` and says, item by item, whether
//! the next crash leaves a dump. Read only.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::machine::{
    Key, Machine, RawValue, VolumeKind, AEDEBUG, CLEANUP_MEMORY_DUMPS, CLEANUP_MINIDUMPS,
    CRASH_CONTROL, ERROR_REPORTING, ERROR_REPORTING_POLICY, ERROR_REPORTING_SERVICE, LOCAL_DUMPS,
    MEMORY_MANAGEMENT, STORAGE_SENSE, STORAGE_SENSE_POLICY,
};
use super::{
    dump_room, AppDumpType, CheckOptions, CheckResult, Event, Item, KernelDumpType, Outcome,
    Setting, Status, BACKUP_FILE, MAX_FILES_LISTED, MIB,
};
use crate::clock;
use crate::tools::drives::bytes_text;

/// Windows deletes MEMORY.DMP after a stop when its drive has less than this free, unless
/// AlwaysKeepMemoryDump is 1 (Microsoft's WER team, "Kernel dump storage and clean up
/// behavior in Windows 7"; servers and domain members are exempt).
pub(crate) const KEEP_THRESHOLD: u64 = 25_000_000_000;
/// Room kept for small memory dumps: a few hundred of them.
pub(crate) const MINIDUMP_ROOM: u64 = 64 * MIB;
/// Room one application mini dump takes, counted per dump kept.
pub(crate) const APP_MINI_ROOM: u64 = 8 * MIB;
/// Room for full application dumps: one large program's memory.
pub(crate) const APP_FULL_ROOM: u64 = 2048 * MIB;
/// What a system-managed page file leaves free on its volume (Microsoft: it "can grow to
/// within 1 GB of free space on the volume if necessary for crash dump settings").
const MANAGED_RESERVE: u64 = 1024 * MIB;

pub(crate) fn check<M: Machine>(
    m: &M,
    options: &CheckOptions,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> CheckResult {
    let mut result = CheckResult {
        outcome: Outcome::Done,
        items: Vec::new(),
        settings: Vec::new(),
        elevated: m.elevated(),
        put_back_available: false,
    };
    if !(1..=MAX_FILES_LISTED).contains(&options.max_files) {
        result.outcome = Outcome::Refused {
            reasons: vec![format!(
                "max_files must be 1 to {MAX_FILES_LISTED}, not {}",
                options.max_files
            )],
        };
        return result;
    }
    let mut reader = Reader {
        m,
        settings: Vec::new(),
        stop: Some(cancel),
    };
    let steps: [(&str, Step<M>); 5] = [
        ("Reading the kernel crash dump settings", kernel_items),
        ("Reading the application crash dump settings", app_items),
        ("Reading what deletes dumps on its own", |r, _, items| {
            cleanup_items(r, items)
        }),
        ("Looking for dumps already here", dump_items),
        ("Reading the saved settings for Put back", |r, _, items| {
            backup_item(r, items)
        }),
    ];
    for (text, step) in steps {
        if cancel.load(Ordering::Relaxed) {
            result.outcome = Outcome::Stopped;
            break;
        }
        progress(Event::Step { text: text.into() });
        let mut items = Vec::new();
        step(&mut reader, options, &mut items);
        for item in items {
            progress(Event::Item { item: item.clone() });
            result.items.push(item);
        }
    }
    result.put_back_available = matches!(saved_settings(m), Ok(Some(_)));
    result.settings = reader.settings;
    result
}

type Step<M> = fn(&mut Reader<'_, M>, &CheckOptions, &mut Vec<Item>);

/// The saved settings Put back works from: their text, `None` when there are none.
fn saved_settings<M: Machine>(m: &M) -> Result<Option<String>, String> {
    let path = m.expand(BACKUP_FILE)?;
    m.read_state(Path::new(&path))
        .map_err(|why| format!("{path} could not be read: {why}"))
}

/// An item only when the saved settings exist but cannot be read: Put back is then not
/// offered, and this says why.
fn backup_item<M: Machine>(r: &mut Reader<'_, M>, items: &mut Vec<Item>) {
    if let Err(why) = saved_settings(r.m) {
        items.push(unread("putback.saved", "Saved settings for Put back", why));
    }
}

/// Reads values and keeps each one read for the result.
pub(crate) struct Reader<'a, M: Machine> {
    pub(crate) m: &'a M,
    pub(crate) settings: Vec<Setting>,
    /// The check's cancel flag, which also ends a dump listing part way.
    pub(crate) stop: Option<&'a AtomicBool>,
}

impl<M: Machine> Reader<'_, M> {
    pub(crate) fn get(&mut self, key: Key, name: &str) -> Result<Option<RawValue>, String> {
        let value = self.m.read_value(key.hive, key.path, name)?;
        let full = key.named(name);
        if !self.settings.iter().any(|s| s.name == full) {
            self.settings.push(Setting {
                name: full,
                value: value.clone(),
            });
        }
        Ok(value)
    }

    fn dword(&mut self, key: Key, name: &str) -> Result<Option<u32>, String> {
        match self.get(key, name)? {
            None => Ok(None),
            Some(value) => value
                .as_dword()
                .map(Some)
                .ok_or_else(|| format!("{name} holds {}, not a number", value.describe())),
        }
    }

    fn text(&mut self, key: Key, name: &str) -> Result<Option<String>, String> {
        match self.get(key, name)? {
            None => Ok(None),
            Some(value) => value
                .as_text()
                .map(Some)
                .ok_or_else(|| format!("{name} holds {}, not a text", value.describe())),
        }
    }
}

fn item(id: &str, label: &str, status: Status, summary: String, details: Vec<String>) -> Item {
    Item {
        id: id.into(),
        label: label.into(),
        status,
        summary,
        details,
    }
}

fn unread(id: &str, label: &str, reason: String) -> Item {
    item(
        id,
        label,
        Status::CouldNotRead {
            reason: reason.clone(),
        },
        format!("Could not read: {reason}"),
        Vec::new(),
    )
}

fn needs(reason: impl Into<String>) -> Status {
    Status::NeedsChange {
        reason: reason.into(),
    }
}

/// The kernel dump type now set: `Ok(None)` for none.
pub(crate) fn kernel_type<M: Machine>(
    r: &mut Reader<'_, M>,
) -> Result<Result<Option<KernelDumpType>, String>, String> {
    let enabled = r.dword(CRASH_CONTROL, "CrashDumpEnabled")?;
    let filter = r.dword(CRASH_CONTROL, "FilterPages")?;
    Ok(match enabled {
        None => Err("CrashDumpEnabled is not set".into()),
        Some(value) => KernelDumpType::from_registry(value, filter)
            .map_err(|n| format!("CrashDumpEnabled is {n}, which is not a type Windows documents")),
    })
}

/// A page file entry from `PagingFiles`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PageFile {
    /// The drive letter, or `None` for `?:`, Windows managing every drive's page file.
    pub(crate) drive: Option<char>,
    /// `None` when Windows manages its size.
    pub(crate) fixed_mb: Option<(u64, u64)>,
    pub(crate) path: String,
}

/// `PagingFiles` entries: "C:\pagefile.sys 2048 4096" is a fixed size in MB, "C:\pagefile.sys
/// 0 0" or a path alone is system managed, and "?:\pagefile.sys" manages every drive.
pub(crate) fn parse_paging_files(entries: &[String]) -> Vec<PageFile> {
    entries
        .iter()
        .filter_map(|entry| {
            let mut parts = entry.split_whitespace();
            let path = parts.next()?.to_string();
            let numbers: Vec<u64> = parts.filter_map(|p| p.parse().ok()).collect();
            let letter = path.chars().next()?.to_ascii_uppercase();
            let drive = (letter != '?').then_some(letter);
            let fixed_mb = match numbers[..] {
                [initial, max, ..] if initial > 0 => Some((initial, max.max(initial))),
                _ => None,
            };
            Some(PageFile {
                drive,
                fixed_mb,
                path,
            })
        })
        .collect()
}

/// Where a crash dump is first written: the page file on the Windows volume or a
/// dedicated dump file, and the room around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Backing {
    pub(crate) windows_drive: char,
    pub(crate) windows_free: u64,
    pub(crate) pages: Vec<PageFile>,
    /// The page file's current size on the Windows volume.
    pub(crate) page_now: Option<u64>,
    /// A dedicated dump file: its path, its set size in MB (0 or absent: Windows sizes
    /// it) and the room for it: the free space on its volume plus the file's present size,
    /// since Windows makes the file at its set size when it starts.
    pub(crate) dedicated: Option<(String, Option<u64>, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fit {
    Fits(String),
    TooSmall { needed: u64, why: String },
}

/// Whether a dump needing `needed` bytes can be written.
pub(crate) fn fits(needed: u64, b: &Backing) -> Fit {
    if let Some((path, size_mb, room)) = &b.dedicated {
        return match size_mb {
            Some(mb) if mb * MIB >= needed && *room >= mb * MIB => Fit::Fits(format!(
                "the dedicated dump file {path} is set to {}, and its drive has room for it",
                bytes_text(mb * MIB)
            )),
            Some(mb) if mb * MIB >= needed => Fit::TooSmall {
                needed,
                why: format!(
                    "the dedicated dump file {path} is set to {}, but it and the free space on its drive come to only {}, so Windows cannot make it",
                    bytes_text(mb * MIB),
                    bytes_text(*room)
                ),
            },
            Some(mb) => Fit::TooSmall {
                needed,
                why: format!(
                    "the dedicated dump file {path} is set to {}",
                    bytes_text(mb * MIB)
                ),
            },
            None if *room >= needed => Fit::Fits(format!(
                "Windows sizes the dedicated dump file {path}, and its drive has room"
            )),
            None => Fit::TooSmall {
                needed,
                why: format!(
                    "Windows sizes the dedicated dump file {path}, but its drive has only {} free",
                    bytes_text(*room)
                ),
            },
        };
    }
    let drive = b.windows_drive;
    let page = b.pages.iter().find(|p| p.drive.is_none_or(|d| d == drive));
    match page.map(|p| p.fixed_mb) {
        None => Fit::TooSmall {
            needed,
            why: format!("there is no page file on {drive}: and no dedicated dump file"),
        },
        Some(None) => {
            let room = (b.page_now.unwrap_or(0) + b.windows_free).saturating_sub(MANAGED_RESERVE);
            if room >= needed {
                Fit::Fits(format!(
                    "Windows manages the page file on {drive}: and sizes it for the dump setting; {drive}: has {} free",
                    bytes_text(b.windows_free)
                ))
            } else {
                Fit::TooSmall {
                    needed,
                    why: format!(
                        "Windows manages the page file on {drive}:, but {drive}: has only {} free",
                        bytes_text(b.windows_free)
                    ),
                }
            }
        }
        Some(Some((initial, _)))
            if initial * MIB >= needed
                && b.page_now.unwrap_or(0) + b.windows_free >= initial * MIB =>
        {
            Fit::Fits(format!(
                "the page file on {drive}: starts at {}",
                bytes_text(initial * MIB)
            ))
        }
        Some(Some((initial, _))) if initial * MIB >= needed => Fit::TooSmall {
            needed,
            why: format!(
                "the page file on {drive}: is set to start at {}, but it and the free space on {drive}: come to only {}, so Windows cannot make it that size",
                bytes_text(initial * MIB),
                bytes_text(b.page_now.unwrap_or(0) + b.windows_free)
            ),
        },
        Some(Some((initial, _))) => Fit::TooSmall {
            needed,
            why: format!(
                "the page file on {drive}: is set to start at {}",
                bytes_text(initial * MIB)
            ),
        },
    }
}

/// `text` with its first letter capitalised.
pub(crate) fn sentence_start(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

pub(crate) fn too_small_text(dump: KernelDumpType, needed: u64, why: &str, drive: char) -> String {
    format!(
        "{} needs a page file of at least {} on {drive}: (or a dedicated dump file that size); {why}",
        sentence_start(&dump.with_article()),
        bytes_text(needed)
    )
}

/// Reads where a dump is first written.
pub(crate) fn backing<M: Machine>(r: &mut Reader<'_, M>) -> Result<Backing, String> {
    let windows = r.m.expand("%SystemRoot%")?;
    let windows_drive = windows
        .chars()
        .next()
        .filter(char::is_ascii_alphabetic)
        .ok_or("the Windows folder has no drive letter")?
        .to_ascii_uppercase();
    let windows_free = r.m.volume(Path::new(&windows))?.free;
    let pages = match r.get(MEMORY_MANAGEMENT, "PagingFiles")? {
        None => Vec::new(),
        Some(value) => parse_paging_files(&value.as_strings().ok_or_else(|| {
            format!(
                "PagingFiles holds {}, not a list of page files",
                value.describe()
            )
        })?),
    };
    let page_now =
        r.m.file_size(&PathBuf::from(format!("{windows_drive}:\\pagefile.sys")))?;
    let dedicated = match r.text(CRASH_CONTROL, "DedicatedDumpFile")? {
        Some(path) if !path.trim().is_empty() => {
            let size = r.dword(CRASH_CONTROL, "DumpFileSize")?.filter(|mb| *mb > 0);
            let expanded = r.m.expand(&path)?;
            let file = PathBuf::from(&expanded);
            let room = r.m.volume(&file)?.free + r.m.file_size(&file)?.unwrap_or(0);
            Some((expanded, size.map(u64::from), room))
        }
        _ => None,
    };
    Ok(Backing {
        windows_drive,
        windows_free,
        pages,
        page_now,
        dedicated,
    })
}

fn yes_no(value: Option<u32>, yes: &str, no: &str, absent: &str) -> String {
    match value {
        Some(0) => no.into(),
        Some(_) => yes.into(),
        None => absent.into(),
    }
}

fn kernel_items<M: Machine>(r: &mut Reader<'_, M>, _: &CheckOptions, items: &mut Vec<Item>) {
    let dump = match kernel_type(r) {
        Err(why) => {
            items.push(unread("kernel.type", "Kernel dump type", why));
            None
        }
        Ok(Err(why)) => {
            items.push(item(
                "kernel.type",
                "Kernel dump type",
                needs(format!("{why}, so a stop may leave no dump")),
                why,
                Vec::new(),
            ));
            None
        }
        Ok(Ok(None)) => {
            items.push(item(
                "kernel.type",
                "Kernel dump type",
                needs("set to none, so a stop leaves no dump"),
                "None".into(),
                Vec::new(),
            ));
            None
        }
        Ok(Ok(Some(dump))) => {
            let mut name = dump.name().to_string();
            name[..1].make_ascii_uppercase();
            items.push(item(
                "kernel.type",
                "Kernel dump type",
                Status::Ready,
                name,
                Vec::new(),
            ));
            Some(dump)
        }
    };
    let memory = r.m.memory();
    match (dump, memory.as_ref(), backing(r).as_ref()) {
        (_, Err(why), _) | (_, _, Err(why)) => {
            items.push(unread("kernel.space", "Room to write a dump", why.clone()))
        }
        (None, Ok(_), Ok(_)) => items.push(item(
            "kernel.space",
            "Room to write a dump",
            needs("no dump type is set"),
            "Nothing is set to be written".into(),
            Vec::new(),
        )),
        (Some(dump), Ok(memory), Ok(b)) => {
            let b = b.clone();
            let needed = dump_room(dump, memory.physical, memory.kernel);
            let mut details = vec![
                format!("Memory: {}", bytes_text(memory.physical)),
                format!("Kernel memory in use now: {}", bytes_text(memory.kernel)),
            ];
            details.extend(b.pages.iter().map(|p| match p.fixed_mb {
                None => format!("Page file {}: managed by Windows", p.path),
                Some((initial, max)) => format!(
                    "Page file {}: {} to {}",
                    p.path,
                    bytes_text(initial * MIB),
                    bytes_text(max * MIB)
                ),
            }));
            if let Some(now) = b.page_now {
                details.push(format!(
                    "Page file on {}: now {}",
                    b.windows_drive,
                    bytes_text(now)
                ));
            }
            items.push(match fits(needed, &b) {
                Fit::Fits(how) => item(
                    "kernel.space",
                    "Room to write a dump",
                    Status::Ready,
                    format!("{} fits: {how}", sentence_start(&dump.with_article())),
                    details,
                ),
                Fit::TooSmall { needed, why } => {
                    let text = too_small_text(dump, needed, &why, b.windows_drive);
                    item(
                        "kernel.space",
                        "Room to write a dump",
                        needs(text.clone()),
                        text,
                        details,
                    )
                }
            });
        }
    }
    dump_file_item(r, dump, memory.ok(), items);
    minidump_item(r, items);
    switch_item(
        r,
        items,
        ("kernel.event", "Stop written to the System log", "LogEvent"),
        "a stop is not written to the System log",
        (
            "Each stop is written to the System log",
            "Stops are not written to the System log",
        ),
    );
    if dump != Some(KernelDumpType::Small) {
        switch_item(
            r,
            items,
            (
                "kernel.overwrite",
                "New memory dump replaces the old",
                "Overwrite",
            ),
            "a new memory dump is not written over MEMORY.DMP while one is there",
            (
                "A new memory dump replaces the last one",
                "A new memory dump does not replace the last one",
            ),
        );
    }
    match r.dword(CRASH_CONTROL, "AutoReboot") {
        Err(why) => items.push(unread("kernel.restart", "Restart after a stop", why)),
        Ok(value) => items.push(item(
            "kernel.restart",
            "Restart after a stop",
            Status::Ready,
            yes_no(
                value,
                "Windows restarts by itself after a stop",
                "Windows stays on the stop screen until it is restarted",
                "Not set; Windows restarts by itself after a stop",
            ),
            Vec::new(),
        )),
    }
}

/// An on/off CrashControl value whose wanted state is 1.
fn switch_item<M: Machine>(
    r: &mut Reader<'_, M>,
    items: &mut Vec<Item>,
    (id, label, name): (&str, &str, &str),
    off_reason: &str,
    (on, off): (&str, &str),
) {
    items.push(match r.dword(CRASH_CONTROL, name) {
        Err(why) => unread(id, label, why),
        Ok(Some(value)) if value != 0 => item(id, label, Status::Ready, on.into(), Vec::new()),
        Ok(Some(_)) => item(id, label, needs(off_reason), off.into(), Vec::new()),
        Ok(None) => item(
            id,
            label,
            needs(format!("{name} is not set; Windows' own setting is 1")),
            format!("{name} is not set"),
            Vec::new(),
        ),
    });
}

/// Checks a place a dump is written: on a local fixed disk, with `room` free.
fn place_status<M: Machine>(
    m: &M,
    path: &Path,
    room: u64,
    extra: u64,
) -> Result<(Status, String), String> {
    let volume = m.volume(path)?;
    let free = format!(
        "{} has {} free",
        volume.root.display(),
        bytes_text(volume.free)
    );
    Ok(match volume.kind {
        VolumeKind::Fixed if volume.free + extra >= room => (Status::Ready, free),
        VolumeKind::Fixed => (
            needs(format!(
                "{free}; a dump here needs about {}",
                bytes_text(room)
            )),
            free,
        ),
        other => (
            needs(format!(
                "{} is on a {} drive; dumps need a local fixed disk",
                path.display(),
                kind_name(other)
            )),
            free,
        ),
    })
}

pub(crate) fn kind_name(kind: VolumeKind) -> &'static str {
    match kind {
        VolumeKind::Fixed => "local fixed",
        VolumeKind::Removable => "removable",
        VolumeKind::Network => "network",
        VolumeKind::CdRom => "CD or DVD",
        VolumeKind::RamDisk => "RAM disk",
        VolumeKind::Unknown => "unknown",
    }
}

fn dump_file_item<M: Machine>(
    r: &mut Reader<'_, M>,
    dump: Option<KernelDumpType>,
    memory: Option<super::machine::Memory>,
    items: &mut Vec<Item>,
) {
    let (id, label) = ("kernel.dump_file", "Memory dump file");
    let text = match r.text(CRASH_CONTROL, "DumpFile") {
        Err(why) => return items.push(unread(id, label, why)),
        Ok(None) => {
            return items.push(item(
                id,
                label,
                needs("DumpFile is not set"),
                "Not set".into(),
                Vec::new(),
            ))
        }
        Ok(Some(text)) => text,
    };
    let path = match r.m.expand(&text) {
        Ok(path) => PathBuf::from(path),
        Err(why) => return items.push(unread(id, label, why)),
    };
    let keep = r.dword(CRASH_CONTROL, "AlwaysKeepMemoryDump");
    let (Some(dump), Some(memory)) = (dump, memory) else {
        return items.push(item(
            id,
            label,
            Status::Ready,
            path.display().to_string(),
            Vec::new(),
        ));
    };
    if dump == KernelDumpType::Small {
        items.push(item(
            id,
            label,
            Status::Ready,
            format!("{} (a small memory dump does not use it)", path.display()),
            Vec::new(),
        ));
    } else {
        let room = dump_room(dump, memory.physical, memory.kernel);
        let existing = match r.m.file_size(&path) {
            Ok(size) => size.unwrap_or(0),
            Err(why) => {
                items.push(unread(
                    id,
                    label,
                    format!("the size of {} could not be read: {why}", path.display()),
                ));
                return;
            }
        };
        items.push(match place_status(r.m, &path, room, existing) {
            Err(why) => unread(id, label, why),
            Ok((status, free)) => item(
                id,
                label,
                status,
                format!("{} ({free})", path.display()),
                vec![format!(
                    "{} may need about {}",
                    sentence_start(&dump.with_article()),
                    bytes_text(room)
                )],
            ),
        });
    }
    let (id, label) = ("kernel.keep", "Memory dump kept when space is low");
    let free = r.m.volume(&path).map(|v| v.free);
    items.push(match (keep, free) {
        (Err(why), _) | (_, Err(why)) => unread(id, label, why),
        (Ok(Some(value)), Ok(_)) if value != 0 => item(
            id,
            label,
            Status::Ready,
            "Windows keeps MEMORY.DMP however little space is left".into(),
            Vec::new(),
        ),
        (Ok(_), Ok(free)) => item(
            id,
            label,
            needs(format!(
                "Windows deletes MEMORY.DMP after a stop when its drive has less than {} free, unless AlwaysKeepMemoryDump is 1; the drive has {} free now",
                bytes_text(KEEP_THRESHOLD),
                bytes_text(free)
            )),
            "AlwaysKeepMemoryDump is not 1".into(),
            Vec::new(),
        ),
    });
}

fn minidump_item<M: Machine>(r: &mut Reader<'_, M>, items: &mut Vec<Item>) {
    let (id, label) = ("kernel.minidump", "Small memory dump folder");
    let text = match r.text(CRASH_CONTROL, "MinidumpDir") {
        Err(why) => return items.push(unread(id, label, why)),
        Ok(None) => {
            return items.push(item(
                id,
                label,
                needs("MinidumpDir is not set"),
                "Not set".into(),
                Vec::new(),
            ))
        }
        Ok(Some(text)) => text,
    };
    let path = match r.m.expand(&text) {
        Ok(path) => PathBuf::from(path),
        Err(why) => return items.push(unread(id, label, why)),
    };
    items.push(match place_status(r.m, &path, MINIDUMP_ROOM, 0) {
        Err(why) => unread(id, label, why),
        Ok((status, free)) => item(
            id,
            label,
            status,
            format!("{} ({free})", path.display()),
            Vec::new(),
        ),
    });
}

/// The application dump folder as Windows would use it, expanded for this account.
pub(crate) fn app_folder_text(folder: Option<String>) -> String {
    folder
        .filter(|f| !f.trim().is_empty())
        .unwrap_or_else(|| r"%LOCALAPPDATA%\CrashDumps".into())
}

fn app_items<M: Machine>(r: &mut Reader<'_, M>, _: &CheckOptions, items: &mut Vec<Item>) {
    let (id, label) = ("apps.local_dumps", "Application crash dumps");
    let exists = match r.m.key_exists(LOCAL_DUMPS.hive, LOCAL_DUMPS.path) {
        Ok(exists) => exists,
        Err(why) => return items.push(unread(id, label, why)),
    };
    if !exists {
        items.push(item(
            id,
            label,
            needs("LocalDumps is not set up, so Windows keeps no dump when a program crashes"),
            "Off".into(),
            Vec::new(),
        ));
    } else {
        let read = (|| -> Result<_, String> {
            Ok((
                r.text(LOCAL_DUMPS, "DumpFolder")?,
                r.dword(LOCAL_DUMPS, "DumpType")?,
                r.dword(LOCAL_DUMPS, "DumpCount")?,
            ))
        })();
        match read {
            Err(why) => items.push(unread(id, label, why)),
            Ok((folder, kind, count)) => {
                let kind_text = match kind.unwrap_or(1) {
                    0 => "custom dump".to_string(),
                    1 => AppDumpType::Mini.name().into(),
                    2 => AppDumpType::Full.name().into(),
                    other => format!("dump type {other}"),
                };
                let count = count.unwrap_or(10);
                let mut details = Vec::new();
                if let Ok(apps) = r.m.subkeys(LOCAL_DUMPS.hive, LOCAL_DUMPS.path) {
                    if !apps.is_empty() {
                        details.push(format!("Settings for single programs: {}", apps.join(", ")));
                    }
                }
                let status = if count == 0 {
                    needs("DumpCount is 0, so no dump is kept")
                } else if kind.is_some_and(|k| k > 2) {
                    needs(format!("{kind_text} is not a type Windows documents"))
                } else {
                    Status::Ready
                };
                items.push(item(
                    id,
                    label,
                    status,
                    format!("On: {kind_text}, up to {count} kept"),
                    details,
                ));
                let text = app_folder_text(folder);
                let (id, label) = ("apps.folder", "Application dump folder");
                let room = if kind == Some(2) {
                    APP_FULL_ROOM
                } else {
                    APP_MINI_ROOM * u64::from(count.max(1))
                };
                let per_user = text.to_ascii_uppercase().contains("%LOCALAPPDATA%")
                    || text.to_ascii_uppercase().contains("%USERPROFILE%");
                items.push(match r.m.expand(&text).map(PathBuf::from) {
                    Err(why) => unread(id, label, why),
                    Ok(path) => match (place_status(r.m, &path, room, 0), r.m.folder(&path)) {
                        (Err(why), _) | (_, Err(why)) => unread(id, label, why),
                        (Ok((status, free)), Ok(state)) => {
                            let mut details = Vec::new();
                            if per_user {
                                details.push(format!(
                                    "{text} is each account's own folder; this is the one for the account running this tool"
                                ));
                            }
                            let link = match super::link_on_path(r.m, &path) {
                                Ok(link) => link,
                                Err(why) => {
                                    items.push(unread(
                                        id,
                                        label,
                                        format!("whether {} is reached through a link could not be read: {why}", path.display()),
                                    ));
                                    return;
                                }
                            };
                            let status = match state {
                                super::machine::PathKind::Link => needs(format!(
                                    "{} is a link to another place",
                                    path.display()
                                )),
                                _ if link.is_some() => needs(format!(
                                    "{} is reached through {}, a link to another place",
                                    path.display(),
                                    link.unwrap_or_default().display()
                                )),
                                super::machine::PathKind::File => {
                                    needs(format!("{} is a file, not a folder", path.display()))
                                }
                                _ => status,
                            };
                            item(id, label, status, format!("{} ({free})", path.display()), details)
                        }
                    },
                });
            }
        }
    }
    items.push(reporting_item(r));
}

fn reporting_item<M: Machine>(r: &mut Reader<'_, M>) -> Item {
    let (id, label) = ("apps.reporting", "Windows Error Reporting");
    let read = (|| -> Result<_, String> {
        Ok((
            r.dword(ERROR_REPORTING_POLICY, "Disabled")?,
            r.dword(ERROR_REPORTING, "Disabled")?,
            r.dword(ERROR_REPORTING_SERVICE, "Start")?,
            r.text(AEDEBUG, "Auto")?,
            r.text(AEDEBUG, "Debugger")?,
        ))
    })();
    let (policy, disabled, start, auto, debugger) = match read {
        Ok(read) => read,
        Err(why) => return unread(id, label, why),
    };
    let mut details = Vec::new();
    if policy == Some(1) || disabled == Some(1) {
        details.push("Reporting to Microsoft is turned off; Microsoft documents that local dumps are still written".into());
    }
    let mut problems = Vec::new();
    if start == Some(4) {
        problems.push("the Windows Error Reporting service is disabled, and it starts the program that writes application dumps");
    }
    let debugger_set = auto.as_deref().map(str::trim) == Some("1")
        && debugger.as_deref().is_some_and(|d| !d.trim().is_empty());
    if debugger_set {
        problems.push("a debugger is set to start by itself on every program crash (AeDebug Auto is 1), and then Windows writes no local dump");
        details.push(format!("Debugger: {}", debugger.unwrap_or_default()));
    }
    let service = match start {
        Some(2) => "starts with Windows",
        Some(3) | None => "starts when needed",
        Some(4) => "disabled",
        Some(_) => "set to start another way",
    };
    let summary = format!("Service {service}");
    if problems.is_empty() {
        item(id, label, Status::Ready, summary, details)
    } else {
        let mut reason = problems.join("; ");
        reason[..1].make_ascii_uppercase();
        item(id, label, needs(reason), summary, details)
    }
}

fn cleanup_items<M: Machine>(r: &mut Reader<'_, M>, items: &mut Vec<Item>) {
    let (id, label) = ("cleanup.storage_sense", "Storage Sense");
    let read = (|| -> Result<_, String> {
        Ok((
            r.dword(STORAGE_SENSE_POLICY, "AllowStorageSenseGlobal")?,
            r.dword(
                STORAGE_SENSE_POLICY,
                "AllowStorageSenseTemporaryFilesCleanup",
            )?,
            r.dword(STORAGE_SENSE, "01")?,
            r.dword(STORAGE_SENSE, "04")?,
        ))
    })();
    items.push(match read {
        Err(why) => unread(id, label, why),
        Ok((global, temp_policy, on, temp)) => {
            let running = match global {
                Some(value) => value != 0,
                None => on == Some(1),
            };
            let cleans_temp = match temp_policy {
                Some(value) => value != 0,
                None => temp == Some(1),
            };
            if running && cleans_temp {
                item(
                    id,
                    label,
                    needs("Storage Sense is on and removes temporary system files, which can include system error memory dumps; turn off its temporary file cleanup in Settings, System, Storage, to keep dumps"),
                    "On, removing temporary files".into(),
                    vec!["Read for the account running this tool".into()],
                )
            } else {
                item(
                    id,
                    label,
                    Status::Ready,
                    if running {
                        "On, not removing temporary files".into()
                    } else {
                        "Off".into()
                    },
                    vec!["Read for the account running this tool".into()],
                )
            }
        }
    });
    let (id, label) = ("cleanup.disk_cleanup", "Saved Disk Cleanup sets");
    let mut sets = Vec::new();
    for key in [CLEANUP_MEMORY_DUMPS, CLEANUP_MINIDUMPS] {
        let names = match r.m.value_names(key.hive, key.path) {
            Ok(names) => names,
            Err(why) => return items.push(unread(id, label, why)),
        };
        for name in names {
            let Some(number) = name.strip_prefix("StateFlags") else {
                continue;
            };
            if number.len() != 4 || !number.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            match r.dword(key, &name) {
                Ok(Some(2)) if !sets.contains(&number.to_string()) => sets.push(number.to_string()),
                Ok(_) => {}
                Err(why) => return items.push(unread(id, label, why)),
            }
        }
    }
    sets.sort();
    items.push(if sets.is_empty() {
        item(
            id,
            label,
            Status::Ready,
            "No saved set removes crash dumps".into(),
            Vec::new(),
        )
    } else {
        item(
            id,
            label,
            needs(format!(
                "saved Disk Cleanup set {} removes system error memory dumps whenever something runs cleanmgr /sagerun with it; clear that choice with cleanmgr /sageset",
                sets.join(", ")
            )),
            format!("Set {} removes crash dumps", sets.join(", ")),
            Vec::new(),
        )
    });
}

fn dump_items<M: Machine>(r: &mut Reader<'_, M>, options: &CheckOptions, items: &mut Vec<Item>) {
    if !options.list_dumps {
        return;
    }
    let (id, label) = ("dumps.present", "Dumps already here");
    let mut places = Vec::new();
    let mut details = Vec::new();
    let mut unreadable = Vec::new();
    // A place that cannot be worked out is said, never replaced by the default one.
    let mut not_read = |what: String, why: String| {
        details.push(format!("{what}: could not be read: {why}"));
        unreadable.push(why);
    };
    let kernel = [
        ("DumpFile", r"%SystemRoot%\MEMORY.DMP"),
        ("MinidumpDir", r"%SystemRoot%\Minidump"),
    ];
    for (name, default) in kernel {
        match r.text(CRASH_CONTROL, name) {
            Ok(text) => places.push(text.unwrap_or_else(|| default.into())),
            Err(why) => not_read(format!("Where {name} points"), why),
        }
    }
    places.push(r"%SystemRoot%\LiveKernelReports".into());
    match r.m.key_exists(LOCAL_DUMPS.hive, LOCAL_DUMPS.path) {
        Ok(true) => match r.text(LOCAL_DUMPS, "DumpFolder") {
            Ok(folder) => places.push(app_folder_text(folder)),
            Err(why) => not_read("The application dump folder".into(), why),
        },
        Ok(false) => {}
        Err(why) => not_read("Whether application dumps are on".into(), why),
    }
    let mut count = 0;
    let mut bytes = 0;
    let mut newest: Option<(PathBuf, std::time::SystemTime, u64)> = None;
    let mut seen: Vec<PathBuf> = Vec::new();
    for place in places {
        let path = match r.m.expand(&place) {
            Ok(path) => PathBuf::from(path),
            Err(why) => {
                details.push(format!("{place}: could not be read: {why}"));
                unreadable.push(why);
                continue;
            }
        };
        if seen.iter().any(|s| super::same_place(s, &path)) {
            continue;
        }
        if r.stop.is_some_and(|stop| stop.load(Ordering::Relaxed)) {
            details.push(format!(
                "{}: not read, the check was stopped",
                path.display()
            ));
            continue;
        }
        seen.push(path.clone());
        match r.m.dumps(&path, options.max_files as usize, r.stop) {
            Ok(None) => details.push(format!("{}: nothing there", path.display())),
            Ok(Some(found)) => {
                count += found.count;
                bytes += found.bytes;
                details.push(format!(
                    "{}: {} {}, {}{}",
                    path.display(),
                    found.count,
                    if found.count == 1 { "dump" } else { "dumps" },
                    bytes_text(found.bytes),
                    if found.cut {
                        ", listing stopped at its limit"
                    } else {
                        ""
                    }
                ));
                if let Some(file) = found.newest {
                    if newest.as_ref().is_none_or(|n| file.1 > n.1) {
                        newest = Some(file);
                    }
                }
            }
            Err(why) => {
                details.push(format!("{}: could not read: {why}", path.display()));
                unreadable.push(why);
            }
        }
    }
    let summary = match &newest {
        None if count == 0 => "None found".to_string(),
        None => format!("{count} found, {}", bytes_text(bytes)),
        Some((path, time, size)) => format!(
            "{count} found, {}; newest {}, {}, {}",
            bytes_text(bytes),
            clock::local(*time).long(),
            bytes_text(*size),
            path.display()
        ),
    };
    let status = if unreadable.is_empty() {
        Status::Ready
    } else {
        Status::CouldNotRead {
            reason: format!(
                "{} of the places could not be read: {}",
                unreadable.len(),
                unreadable.join("; ")
            ),
        }
    };
    items.push(item(id, label, status, summary, details));
}

#[cfg(test)]
mod tests {
    use super::super::fake::Fake;
    use super::*;

    fn run(m: &Fake) -> CheckResult {
        check(
            m,
            &CheckOptions::default(),
            &mut |_| {},
            &AtomicBool::new(false),
        )
    }

    fn status<'a>(result: &'a CheckResult, id: &str) -> &'a Status {
        &result
            .items
            .iter()
            .find(|i| i.id == id)
            .unwrap_or_else(|| panic!("no item {id} in {:?}", result.items))
            .status
    }

    #[test]
    fn windows_defaults_with_local_dumps_are_ready() {
        let mut m = Fake::windows_default();
        m.set_up_app_dumps();
        let result = run(&m);
        assert_eq!(result.outcome, Outcome::Done);
        for item in &result.items {
            assert_eq!(item.status, Status::Ready, "{item:?}");
        }
        let kinds = result.items.iter().find(|i| i.id == "kernel.type").unwrap();
        assert_eq!(kinds.summary, "Automatic memory dump");
    }

    #[test]
    fn a_stock_pc_needs_application_dumps_and_keeping_the_memory_dump() {
        let result = run(&Fake::windows_default_without_keep());
        assert!(
            matches!(status(&result, "apps.local_dumps"), Status::NeedsChange { reason } if reason.contains("keeps no dump"))
        );
        assert!(
            matches!(status(&result, "kernel.keep"), Status::NeedsChange { reason } if reason.contains("25.0 GB"))
        );
        assert_eq!(*status(&result, "kernel.type"), Status::Ready);
    }

    #[test]
    fn every_dump_type_number_reads_as_its_name() {
        for (value, filter, want) in [
            (0, None, Ok(None)),
            (1, None, Ok(Some(KernelDumpType::Complete))),
            (1, Some(1), Ok(Some(KernelDumpType::Active))),
            (2, None, Ok(Some(KernelDumpType::Kernel))),
            (3, None, Ok(Some(KernelDumpType::Small))),
            (7, None, Ok(Some(KernelDumpType::Automatic))),
            (5, None, Err(5)),
        ] {
            assert_eq!(
                KernelDumpType::from_registry(value, filter),
                want,
                "{value}"
            );
        }
        for dump in KernelDumpType::ALL {
            let filter = (dump == KernelDumpType::Active).then_some(1);
            assert_eq!(
                KernelDumpType::from_registry(dump.crash_dump_enabled(), filter),
                Ok(Some(dump))
            );
        }
    }

    #[test]
    fn no_dump_type_and_an_unknown_one_need_a_change() {
        let mut m = Fake::windows_default();
        m.dword(CRASH_CONTROL, "CrashDumpEnabled", 0);
        let result = run(&m);
        assert!(
            matches!(status(&result, "kernel.type"), Status::NeedsChange { reason } if reason.contains("none"))
        );
        m.dword(CRASH_CONTROL, "CrashDumpEnabled", 5);
        let result = run(&m);
        assert!(
            matches!(status(&result, "kernel.type"), Status::NeedsChange { reason } if reason.contains("5"))
        );
    }

    #[test]
    fn a_fixed_page_file_too_small_for_a_complete_dump_says_the_size_needed() {
        let mut m = Fake::windows_default();
        m.dword(CRASH_CONTROL, "CrashDumpEnabled", 1);
        m.multi(
            MEMORY_MANAGEMENT,
            "PagingFiles",
            &[r"C:\pagefile.sys 4096 4096"],
        );
        let result = run(&m);
        let Status::NeedsChange { reason } = status(&result, "kernel.space") else {
            panic!("{result:?}")
        };
        // 16 GiB of memory plus 257 MiB, in decimal units.
        assert!(reason.contains("17.4 GB on C:"), "{reason}");
        assert!(reason.contains("set to start at 4.3 GB"), "{reason}");
    }

    #[test]
    fn a_dedicated_dump_file_stands_in_for_the_page_file() {
        let mut m = Fake::windows_default();
        m.multi(MEMORY_MANAGEMENT, "PagingFiles", &[]);
        let result = run(&m);
        assert!(
            matches!(status(&result, "kernel.space"), Status::NeedsChange { reason } if reason.contains("no page file"))
        );
        m.text(CRASH_CONTROL, "DedicatedDumpFile", r"D:\dedicated.sys");
        let result = run(&m);
        assert_eq!(
            *status(&result, "kernel.space"),
            Status::Ready,
            "{result:?}"
        );
    }

    /// The guard: the runner VM showed "A automatic memory dump fits".
    #[test]
    fn dump_names_take_the_article_that_fits() {
        let result = run(&Fake::windows_default());
        let space = result
            .items
            .iter()
            .find(|i| i.id == "kernel.space")
            .unwrap();
        assert!(
            space.summary.starts_with("An automatic memory dump fits"),
            "{}",
            space.summary
        );
        let text = too_small_text(KernelDumpType::Small, 2 * MIB, "x", 'C');
        assert!(text.starts_with("A small memory dump needs"), "{text}");
        let text = too_small_text(KernelDumpType::Active, 2 * MIB, "x", 'C');
        assert!(text.starts_with("An active memory dump needs"), "{text}");
    }

    #[test]
    fn page_file_entries_parse_as_windows_writes_them() {
        let parsed = parse_paging_files(&[
            r"?:\pagefile.sys".into(),
            r"c:\pagefile.sys 0 0".into(),
            r"D:\pagefile.sys 2048 8192".into(),
        ]);
        assert_eq!(parsed[0].drive, None);
        assert_eq!(parsed[0].fixed_mb, None);
        assert_eq!(parsed[1].drive, Some('C'));
        assert_eq!(parsed[1].fixed_mb, None);
        assert_eq!(parsed[2].fixed_mb, Some((2048, 8192)));
    }

    /// The guard: a dedicated dump file set large enough fits only when the file as it is
    /// and the free space on its drive can hold it at that size.
    #[test]
    fn a_dedicated_dump_file_needs_room_for_its_set_size() {
        let b = |size_mb: Option<u64>, room: u64| Backing {
            windows_drive: 'C',
            windows_free: 0,
            pages: Vec::new(),
            page_now: None,
            dedicated: Some((r"D:\dedicated.sys".into(), size_mb, room)),
        };
        let needed = 16_000_000_000;
        // Set to 32 GB, absent, 2 GB free.
        let Fit::TooSmall { why, .. } = fits(needed, &b(Some(32 * 1024), 2_000_000_000)) else {
            panic!("a 32 GB file on a drive with 2 GB free fits")
        };
        assert!(why.contains("Windows cannot make it"), "{why}");
        // Present at its size, or room enough to make it.
        assert!(matches!(
            fits(needed, &b(Some(32 * 1024), 34_359_738_368)),
            Fit::Fits(_)
        ));
        // Set too small, whatever the room.
        assert!(matches!(
            fits(needed, &b(Some(8 * 1024), 100_000_000_000)),
            Fit::TooSmall { .. }
        ));
        assert!(matches!(
            fits(needed, &b(None, 2_000_000_000)),
            Fit::TooSmall { .. }
        ));
        assert!(matches!(
            fits(needed, &b(None, 20_000_000_000)),
            Fit::Fits(_)
        ));
        // The same for a page file set to a fixed start size.
        let page = |now: Option<u64>, free: u64| Backing {
            windows_drive: 'C',
            windows_free: free,
            pages: parse_paging_files(&[r"C:\pagefile.sys 32768 32768".into()]),
            page_now: now,
            dedicated: None,
        };
        assert!(matches!(
            fits(needed, &page(None, 2_000_000_000)),
            Fit::TooSmall { .. }
        ));
        assert!(matches!(
            fits(needed, &page(Some(34_359_738_368), 0)),
            Fit::Fits(_)
        ));
    }

    #[test]
    fn a_managed_page_file_without_room_on_its_drive_is_too_small() {
        let b = Backing {
            windows_drive: 'C',
            windows_free: 2_000_000_000,
            pages: parse_paging_files(&[r"?:\pagefile.sys".into()]),
            page_now: Some(1_000_000_000),
            dedicated: None,
        };
        assert!(matches!(fits(1_500_000_000, &b), Fit::Fits(_)));
        // 3 GB on hand less the 1 GiB Windows leaves free.
        assert!(matches!(fits(2_000_000_000, &b), Fit::TooSmall { .. }));
    }

    #[test]
    fn dumps_on_a_network_or_removable_drive_need_a_change() {
        let mut m = Fake::windows_default();
        m.set_up_app_dumps();
        m.expand_string(LOCAL_DUMPS, "DumpFolder", r"N:\dumps");
        m.expand_string(CRASH_CONTROL, "MinidumpDir", r"E:\mini");
        let result = run(&m);
        assert!(
            matches!(status(&result, "apps.folder"), Status::NeedsChange { reason } if reason.contains("network"))
        );
        assert!(
            matches!(status(&result, "kernel.minidump"), Status::NeedsChange { reason } if reason.contains("removable"))
        );
    }

    #[test]
    fn what_deletes_dumps_is_named() {
        let mut m = Fake::windows_default();
        m.dword(STORAGE_SENSE, "01", 1);
        m.dword(STORAGE_SENSE, "04", 1);
        m.dword(CLEANUP_MEMORY_DUMPS, "StateFlags0042", 2);
        m.dword(CLEANUP_MINIDUMPS, "StateFlags0007", 0);
        let result = run(&m);
        assert!(matches!(
            status(&result, "cleanup.storage_sense"),
            Status::NeedsChange { .. }
        ));
        let Status::NeedsChange { reason } = status(&result, "cleanup.disk_cleanup") else {
            panic!()
        };
        assert!(reason.contains("set 0042"), "{reason}");
        assert!(!reason.contains("0007"), "{reason}");
        m.dword(STORAGE_SENSE_POLICY, "AllowStorageSenseGlobal", 0);
        assert_eq!(*status(&run(&m), "cleanup.storage_sense"), Status::Ready);
    }

    #[test]
    fn a_disabled_service_and_an_automatic_debugger_stop_application_dumps() {
        let mut m = Fake::windows_default();
        m.dword(ERROR_REPORTING_SERVICE, "Start", 4);
        m.text(AEDEBUG, "Auto", "1");
        m.text(AEDEBUG, "Debugger", r"C:\dbg\x.exe -p %ld");
        let Status::NeedsChange { reason } = status(&run(&m), "apps.reporting").clone() else {
            panic!()
        };
        assert!(reason.contains("service is disabled"), "{reason}");
        assert!(reason.contains("AeDebug Auto is 1"), "{reason}");
        m.dword(ERROR_REPORTING_POLICY, "Disabled", 1);
        m.dword(ERROR_REPORTING_SERVICE, "Start", 3);
        m.text(AEDEBUG, "Auto", "0");
        assert_eq!(*status(&run(&m), "apps.reporting"), Status::Ready);
    }

    #[test]
    fn dumps_present_give_count_newest_and_unreadable_places() {
        let mut m = Fake::windows_default();
        m.dump_place(r"C:\Windows\Minidump", 3, 3_000_000);
        m.dump_place(r"C:\Windows\MEMORY.DMP", 1, 900_000_000);
        m.denied(r"C:\Windows\LiveKernelReports");
        let result = run(&m);
        let item = result
            .items
            .iter()
            .find(|i| i.id == "dumps.present")
            .unwrap();
        assert!(
            item.summary.starts_with("4 found, 903.0 MB; newest"),
            "{}",
            item.summary
        );
        assert!(
            matches!(&item.status, Status::CouldNotRead { reason } if reason.contains("administrator"))
        );
    }

    /// The guard: what cannot be read is said as Could not read with its reason, never
    /// read as a default: saved settings that exist but cannot be read, a page file list of
    /// the wrong type, and dump places that cannot be worked out.
    #[test]
    fn what_cannot_be_read_is_said_with_its_reason() {
        let mut m = Fake::windows_default();
        m.state_unreadable = true;
        let result = run(&m);
        assert!(!result.put_back_available);
        assert!(
            matches!(status(&result, "putback.saved"), Status::CouldNotRead { reason } if reason.contains("access denied")),
            "{:?}",
            result.items
        );

        let mut m = Fake::windows_default();
        m.dword(MEMORY_MANAGEMENT, "PagingFiles", 1);
        let result = run(&m);
        assert!(
            matches!(status(&result, "kernel.space"), Status::CouldNotRead { reason } if reason.contains("not a list of page files")),
            "{:?}",
            result.items
        );

        let mut m = Fake::windows_default();
        m.fail_reads(CRASH_CONTROL, "DumpFile");
        let result = run(&m);
        let dumps = result
            .items
            .iter()
            .find(|i| i.id == "dumps.present")
            .unwrap();
        assert!(
            matches!(&dumps.status, Status::CouldNotRead { .. }),
            "{dumps:?}"
        );
        assert!(
            dumps
                .details
                .iter()
                .any(|d| d.contains("Where DumpFile points")),
            "{dumps:?}"
        );
    }

    #[test]
    fn an_unreadable_value_is_said_never_passed() {
        let mut m = Fake::windows_default();
        m.fail_reads(CRASH_CONTROL, "CrashDumpEnabled");
        let result = run(&m);
        assert!(matches!(
            status(&result, "kernel.type"),
            Status::CouldNotRead { .. }
        ));
        assert!(!matches!(status(&result, "kernel.space"), Status::Ready));
    }

    #[test]
    fn cancel_stops_before_the_next_step_and_bounds_are_checked() {
        let m = Fake::windows_default();
        let result = check(
            &m,
            &CheckOptions::default(),
            &mut |_| {},
            &AtomicBool::new(true),
        );
        assert_eq!(result.outcome, Outcome::Stopped);
        assert!(result.items.is_empty());
        let options = CheckOptions {
            max_files: 0,
            ..CheckOptions::default()
        };
        let result = check(&m, &options, &mut |_| {}, &AtomicBool::new(false));
        assert!(matches!(result.outcome, Outcome::Refused { .. }));
    }

    #[test]
    fn every_item_is_sent_as_an_event_and_every_value_read_is_kept() {
        let m = Fake::windows_default();
        let mut events = Vec::new();
        let result = check(
            &m,
            &CheckOptions::default(),
            &mut |e| events.push(e),
            &AtomicBool::new(false),
        );
        let sent = events
            .iter()
            .filter(|e| matches!(e, Event::Item { .. }))
            .count();
        assert_eq!(sent, result.items.len());
        assert!(result
            .settings
            .iter()
            .any(|s| s.name.ends_with(r"CrashControl\CrashDumpEnabled")
                && s.value == Some(RawValue::dword(7))));
    }
}
