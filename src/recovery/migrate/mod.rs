//! Copy the customer's files: from an old Windows drive or a rescue image, find the Windows
//! volumes, then for each person's profile copy their own folders, OneDrive files that are
//! on the drive, browser profiles without their caches, Outlook data files and Sticky Notes,
//! and write a report a technician can hand over, with the Windows product key and the
//! saved Wi-Fi networks. Files are read through the app's own NTFS reader and copied by the
//! rescue copy, so the drive is only read and failed reads follow the copy's rules.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use super::copy::{self, Entry, Job, Tree};
use super::dest::Guard;
use super::fs::parts::{self, Search};
use super::fs::{ntfs, FsKind, Origin, Progress as FsProgress, Vol};
use super::ledger::files;
use super::reader::Reader;
use super::{timed, BlockSource, ReadError, SourceChoice};
use crate::budget::{Budget, Limits};
use crate::tools::drives::bytes_text;

pub mod hive;
pub mod tree;

use tree::{NtfsTree, Shared, SharedSource};

/// The report's file name, in the folder the copy makes.
pub const REPORT: &str = "Customer files report.txt";
/// Each person's copy log, in their folder.
pub const LOG: &str = "Copy log.txt";
/// The report's last line, with no line break after it.
pub const END: &str = "End of report.";

/// The folders copied from each profile, by their names on the drive.
pub const FOLDERS: [&str; 8] = [
    "Desktop",
    "Documents",
    "Pictures",
    "Music",
    "Videos",
    "Downloads",
    "Favorites",
    "Contacts",
];

/// Cache folders left out of browser profiles: the browser rebuilds them.
pub const BROWSER_CACHES: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "CacheStorage",
    "ScriptCache",
    "ShaderCache",
    "GrShaderCache",
    "GraphiteDawnCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Media Cache",
    "cache2",
    "startupCache",
    "jumpListCache",
    "OfflineCache",
    "thumbnails",
    "Crashpad",
    "Crash Reports",
];

/// Where each browser keeps its profiles in a user's folder, and the name it gets.
const BROWSERS: [(&str, &str); 3] = [
    ("Chrome", r"AppData\Local\Google\Chrome\User Data"),
    ("Edge", r"AppData\Local\Microsoft\Edge\User Data"),
    ("Firefox", r"AppData\Roaming\Mozilla\Firefox"),
];

const STICKY_NEW: &str =
    r"AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState";
const STICKY_OLD: &str = r"AppData\Roaming\Microsoft\Sticky Notes";
const SOFTWARE: &str = r"\Windows\System32\config\SOFTWARE";
const WLAN: &str = r"\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces";
/// The most of one file read into memory: the registry hive and Wi-Fi profiles.
const MAX_READ: u64 = 1 << 30;
/// What reading one file into memory may hold: the file, rounded up to whole sectors,
/// charged before its buffer is made.
const READ: Limits = Limits {
    what: "the read of a file into memory",
    unit: "files",
    count: 1,
    bytes: u64::MAX,
    memory: MAX_READ + (1 << 20),
    depth: 0,
    nested: "parts",
    time: None,
};

/// What the engine is asked to do: plain data, so a technician's window or an agent can
/// build it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    /// The old drive, by disk number (needs administrator rights), or a rescue image file.
    /// It is only read.
    pub source: SourceChoice,
    /// The folder to copy into. It must be on another disk than the source (refused
    /// otherwise, checked through its handle); a new folder "Customer files <date>" is made
    /// in it. None finds Windows and plans the copy, and copies nothing.
    pub destination: Option<PathBuf>,
    /// The profiles to copy, by their folder names in Users as the plan gives them; None
    /// copies every person's. A name the plan does not hold is refused before anything is
    /// copied.
    pub people: Option<Vec<String>>,
    /// Leave out files with unreadable parts instead of copying them with zeros where the
    /// drive could not be read.
    pub skip_damaged: bool,
}

/// What the engine is doing, as it happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Opening,
    ReadingPartitions,
    ReadingFileTable,
    ReadingRegistry,
    Copying,
    WritingReport,
}

/// One progress event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A new phase begins; `about` says of what, for people ("Partition 3, NTFS, 499 GB").
    Phase { phase: Phase, about: String },
    /// Records of the file table read so far, out of all.
    Reading { done: u64, total: u64 },
    /// The copy so far, over every person: files and bytes written, out of those planned.
    Copying {
        person: String,
        /// 1 while copying what reads easily, 2 while reading failed parts again.
        pass: u64,
        files: u64,
        bytes: u64,
        planned_files: u64,
        planned_bytes: u64,
        damaged: u64,
        skipped: u64,
        current: String,
    },
    /// A damaged or skipped file, as the copy finds it.
    Warning { text: String },
}

/// Where events go: a callback that may be called from the engine's own threads.
pub type Events<'a> = &'a (dyn Fn(Event) + Sync);

/// Runs `work`, calling `tick` about four times a second meanwhile and once at the end.
fn ticking<T>(work: impl FnOnce() -> T, tick: &(dyn Fn() + Sync)) -> T {
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                tick();
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        let out = work();
        done.store(true, Ordering::Relaxed);
        out
    })
}

/// What will be copied for one part of a profile, as measured before the copy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub label: String,
    pub files: u64,
    pub bytes: u64,
}

/// One person's profile and what is copied from it.
#[derive(Debug)]
pub struct User {
    /// The profile folder's name on the drive.
    pub name: String,
    pub profile: PathBuf,
    /// The folder it is copied into, in the copy's folder.
    pub into: String,
    pub jobs: Vec<Job>,
    pub parts: Vec<Part>,
    /// Outlook data files: where each is and its size; .pst files are copied.
    pub pst: Vec<(PathBuf, u64)>,
    pub ost: Vec<(PathBuf, u64)>,
    pub browsers: Vec<&'static str>,
    pub sticky: bool,
}

impl User {
    pub fn files(&self) -> u64 {
        self.parts.iter().map(|p| p.files).sum()
    }

    pub fn bytes(&self) -> u64 {
        self.parts.iter().map(|p| p.bytes).sum()
    }
}

/// A saved Wi-Fi network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub name: String,
    pub security: String,
}

/// One Windows installation found on the source.
pub struct Install {
    /// "Partition 3, NTFS, 499 GB at 1.05 GB".
    pub volume: String,
    pub partition: Option<usize>,
    pub tree: NtfsTree,
    pub windows: Result<hive::Windows, String>,
    pub wifi: Result<Vec<Network>, String>,
    pub users: Vec<User>,
    /// Folders in Users that are not a person's, with why.
    pub skipped: Vec<(String, String)>,
    /// What could not be read of the volume, for people.
    pub notes: Vec<String>,
}

/// What the search found.
pub struct Found {
    pub source: String,
    pub source_disk: crate::recovery::dest::Protected,
    pub installs: Vec<Install>,
    /// About the source as a whole: partitions with nothing readable, tables that failed.
    pub notes: Vec<String>,
}

/// Opens the source named in `options`, within the time limit for opening a drive, finds
/// the Windows installations on it and plans each person's copy. Only reads.
pub fn find(options: &Options, events: Events, cancel: &AtomicBool) -> Result<Found, String> {
    events(Event::Phase {
        phase: Phase::Opening,
        about: options.source.label(),
    });
    let source = timed::open_source_within(options.source.clone(), timed::OPEN_LIMIT)?;
    find_in(source, events, cancel)
}

/// What the walks of the people's folders in an installation's file table may spend:
/// 2^24 entries looked at, twice the file table records a scan reads, since each folder is
/// walked once to plan and once to measure; folders `copy::MAX_DEPTH` deep, as deep as the
/// copy goes. The table is already in memory, within its scan's own budget. No clock
/// limit: the technician starts the search and watches it with a Stop button, checked at
/// every entry.
pub const WALK: Limits = Limits {
    what: "the walk of the people's folders",
    unit: "folder entries",
    count: 1 << 24,
    bytes: u64::MAX,
    memory: u64::MAX,
    depth: copy::MAX_DEPTH as u32,
    nested: "folders",
    time: None,
};

/// `find`, on a source already open.
pub fn find_in(
    source: Box<dyn BlockSource>,
    events: Events,
    cancel: &AtomicBool,
) -> Result<Found, String> {
    let description = source.describe();
    let source_disk = source.protected();
    let shared: SharedSource = Arc::new(Mutex::new(source));
    let mut reader = Reader::new(Box::new(Shared(shared.clone())));
    let progress = FsProgress::default();
    let tick = || {
        events(Event::Reading {
            done: progress.done.load(Ordering::Relaxed),
            total: progress.total.load(Ordering::Relaxed),
        })
    };
    events(Event::Phase {
        phase: Phase::ReadingPartitions,
        about: description.clone(),
    });
    let finds = parts::find(&mut reader, Search::Tables, cancel, &progress);
    let mut notes = finds.notes.clone();
    for unread in &finds.unread {
        notes.push(format!(
            "{}; if it is encrypted with BitLocker, unlock it first.",
            unread.describe()
        ));
    }
    let mut installs = Vec::new();
    for volume in finds
        .volumes
        .iter()
        .filter(|v| v.kind == FsKind::Ntfs && !v.is_lost())
    {
        if cancel.load(Ordering::Relaxed) {
            return Err("The search was stopped.".into());
        }
        if let Some(why) = reader.gone() {
            return Err(why.to_string());
        }
        let label = volume.describe();
        events(Event::Phase {
            phase: Phase::ReadingFileTable,
            about: label.clone(),
        });
        progress.set(0, 0);
        let mut vol = Vol::new(&mut reader, volume.start, volume.len);
        let mut budget = Budget::new(ntfs::LIMITS, Some(cancel));
        let live = ticking(|| ntfs::live(&mut vol, &mut budget, &progress), &tick);
        let (records, mut scan_notes) = match live {
            Ok(found) => found,
            Err(why) => {
                notes.push(format!("{label}: {why}."));
                continue;
            }
        };
        if let Some(said) = budget.said() {
            scan_notes.push(match budget.hit() {
                Some(_) => format!(
                    "{said} Files the file table describes after that point are not copied."
                ),
                None => said,
            });
        }
        if cancel.load(Ordering::Relaxed) {
            return Err("The search was stopped.".into());
        }
        let mut tree = NtfsTree::new(shared.clone(), records);
        if !(tree.is_folder(Path::new(r"\Users")) && tree.is_folder(Path::new(r"\Windows"))) {
            continue;
        }
        let mut install_notes = scan_notes;
        if tree.unplaced > 0 {
            install_notes.push(format!(
                "{} on this volume could not be placed in a folder, since a folder record on the way could not be read; they are not copied. Recover deleted or lost files lists them.",
                files(tree.unplaced)
            ));
        }
        tree.keep(&[Path::new(r"\Users"), Path::new(WLAN), Path::new(SOFTWARE)]);
        events(Event::Phase {
            phase: Phase::ReadingRegistry,
            about: label.clone(),
        });
        let windows = read_file(&mut tree, Path::new(SOFTWARE)).and_then(|(bytes, unread)| {
            let mut budget = Budget::new(hive::LIMITS, Some(cancel));
            let mut found = hive::windows(&bytes, &mut budget)?;
            if unread > 0 {
                found.dirty = true;
            }
            Ok(found)
        });
        let wifi = networks(&mut tree, &mut install_notes);
        let mut walking = Budget::new(WALK, Some(cancel));
        let (users, skipped) = profiles(&mut tree, &mut walking, &mut install_notes);
        if let Some(said) = walking.said() {
            install_notes.push(match walking.hit() {
                Some(_) => format!("{said} What is planned for the people past that point may be short of what they hold."),
                None => format!("{said} Those folders are not copied either."),
            });
        }
        let partition = match volume.origin {
            Origin::Mbr(n) | Origin::Gpt(n) => Some(n),
            _ => None,
        };
        installs.push(Install {
            volume: label,
            partition,
            tree,
            windows,
            wifi,
            users,
            skipped,
            notes: install_notes,
        });
    }
    // With more than one Windows, each person's folder names its partition.
    if installs.len() > 1 {
        for install in &mut installs {
            let tag = install
                .partition
                .map_or_else(|| "whole drive".to_string(), |n| format!("partition {n}"));
            for user in &mut install.users {
                user.into = format!("{} ({tag})", user.name);
            }
        }
    }
    if installs.is_empty() {
        let mut why = "No Windows installation was found: no NTFS volume holds both a Windows and a Users folder.".to_string();
        for note in &notes {
            why.push(' ');
            why.push_str(note);
        }
        return Err(why);
    }
    Ok(Found {
        source: description,
        source_disk,
        installs,
        notes,
    })
}

/// Reads a whole file into memory, reading a failed chunk again a sector at a time; returns
/// it with the count of bytes that could not be read (zeros in it).
fn read_file(tree: &mut NtfsTree, path: &Path) -> Result<(Vec<u8>, u64), String> {
    let len = tree
        .file_len(path)
        .ok_or_else(|| format!("{} is not on the drive", path.display()))?;
    if len > MAX_READ {
        return Err(format!("{} is too large to read", path.display()));
    }
    let mut file = tree
        .open(path, len)
        .map_err(|e| format!("{} could not be opened: {e:?}", path.display()))?;
    let sector = u64::from(file.sector_size().max(1));
    let chunk = (1u64 << 20) / sector * sector;
    let mut budget = Budget::new(READ, None);
    let mut out = budget
        .buffer(len.div_ceil(sector) as usize * sector as usize)
        .map_err(|_| format!("{} is too large to read", path.display()))?;
    let mut unread = 0u64;
    let mut pos = 0u64;
    while pos < len {
        let n = chunk.min(len.div_ceil(sector) * sector - pos);
        let buf = &mut out[pos as usize..(pos + n) as usize];
        match file.read_at(pos, buf) {
            Ok(()) => {}
            Err(ReadError::Gone(code)) => {
                return Err(format!("the drive stopped answering (error {code})"))
            }
            Err(_) => {
                let mut at = 0u64;
                while at < n {
                    let piece = &mut buf[at as usize..(at + sector) as usize];
                    match file.read_at(pos + at, piece) {
                        Ok(()) => {}
                        Err(ReadError::Gone(code)) => {
                            return Err(format!("the drive stopped answering (error {code})"))
                        }
                        Err(_) => {
                            piece.fill(0);
                            unread += sector;
                        }
                    }
                    at += sector;
                }
            }
        }
        pos += n;
    }
    out.truncate(len as usize);
    Ok((out, unread))
}

/// The text between `<tag>` and `</tag>` after `from`, with XML's five entities undone.
fn element(xml: &str, tag: &str, from: usize) -> Option<(String, usize)> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.get(from..)?.find(&open)? + from + open.len();
    let end = xml.get(start..)?.find(&close)? + start;
    let text = xml.get(start..end)?;
    Some((
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
        end,
    ))
}

/// A Wi-Fi profile's name and security, from its XML; never its key.
pub fn network(bytes: &[u8]) -> Option<Network> {
    let xml = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    let profile = xml.find("<WLANProfile")?;
    let (name, _) = element(&xml, "name", profile)?;
    let auth = element(&xml, "authentication", profile).map(|(a, _)| a);
    let security = match auth.as_deref() {
        Some("open") => "Open, no password",
        Some("shared") => "WEP",
        Some("WPA") => "WPA-Enterprise",
        Some("WPAPSK") => "WPA-Personal",
        Some("WPA2") => "WPA2-Enterprise",
        Some("WPA2PSK") => "WPA2-Personal",
        Some("WPA3") | Some("WPA3ENT") => "WPA3-Enterprise",
        Some("WPA3ENT192") => "WPA3-Enterprise 192-bit",
        Some("WPA3SAE") => "WPA3-Personal",
        Some("OWE") => "Enhanced Open",
        Some(other) => {
            return Some(Network {
                name,
                security: other.to_string(),
            })
        }
        None => "not stated",
    };
    Some(Network {
        name,
        security: security.to_string(),
    })
}

/// The saved Wi-Fi networks, from the profile files of every wireless adapter. A profile
/// that cannot be read or made sense of is said in `notes`, not dropped.
fn networks(tree: &mut NtfsTree, notes: &mut Vec<String>) -> Result<Vec<Network>, String> {
    let root = Path::new(WLAN);
    if !tree.is_folder(root) {
        return Ok(Vec::new());
    }
    let mut out: Vec<Network> = Vec::new();
    for adapter in tree.list(root)? {
        let Entry::Folder { name, .. } = adapter else {
            continue;
        };
        let folder = root.join(&name);
        let entries = match tree.list(&folder) {
            Ok(entries) => entries,
            Err(why) => {
                notes.push(format!(
                    "The Wi-Fi profiles in {} could not be listed ({why}); their networks are not listed.",
                    folder.display()
                ));
                continue;
            }
        };
        for entry in entries {
            let Entry::File { name, len, .. } = entry else {
                continue;
            };
            if !name.to_string_lossy().to_lowercase().ends_with(".xml") {
                continue;
            }
            let path = folder.join(&name);
            if len > 1 << 20 {
                notes.push(format!(
                    "{} is too large to be a Wi-Fi profile and was not read.",
                    path.display()
                ));
                continue;
            }
            match read_file(tree, &path) {
                Ok((bytes, unread)) => match network(&bytes) {
                    Some(found) => {
                        if !out.contains(&found) {
                            out.push(found);
                        }
                    }
                    None => notes.push(format!(
                        "The Wi-Fi profile {} could not be made sense of{}; its network is not listed.",
                        path.display(),
                        if unread > 0 { ", and part of it could not be read" } else { "" }
                    )),
                },
                Err(why) => notes.push(format!(
                    "The Wi-Fi profile {} could not be read ({why}); its network is not listed.",
                    path.display()
                )),
            }
        }
    }
    out.sort_by_key(|n| n.name.to_lowercase());
    Ok(out)
}

/// Why a folder in Users is not a person's, by its name; None for one that may be.
pub fn not_a_person(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "default" | "default user" => Some("the template Windows copies for new accounts"),
        "public" => Some("shared by every account, not one person's"),
        "all users" => Some("a link Windows keeps for older programs"),
        "wdagutilityaccount" => Some("the account of Windows Defender Application Guard"),
        _ if lower.starts_with("defaultuser") => {
            Some("an account Windows makes while it is being set up")
        }
        _ => None,
    }
}

/// Walks a folder of the tree as the copy would, calling `f` for every entry with its
/// path, within `budget` (made from `WALK`): each entry counted, a folder deeper than the
/// copy goes left out as the copy leaves it, and the walk ended when the budget is spent.
/// A folder that cannot be listed is said in `notes`.
fn walk(
    tree: &mut NtfsTree,
    root: &Path,
    leave_out: &[&str],
    budget: &mut Budget,
    notes: &mut Vec<String>,
    f: &mut dyn FnMut(&Path, &Entry),
) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((folder, depth)) = stack.pop() {
        let entries = match tree.list(&folder) {
            Ok(entries) => entries,
            Err(why) => {
                notes.push(format!(
                    "{} could not be listed ({why}); what it holds is not counted.",
                    folder.display()
                ));
                continue;
            }
        };
        for entry in entries {
            if budget.item().is_err() {
                return;
            }
            let path = match &entry {
                Entry::Folder { name, .. }
                | Entry::File { name, .. }
                | Entry::Link { name, .. } => folder.join(name),
            };
            if let Entry::Folder { name, .. } = &entry {
                if leave_out
                    .iter()
                    .any(|out| name.eq_ignore_ascii_case(std::ffi::OsStr::new(out)))
                {
                    continue;
                }
                if budget.within_depth(depth + 1) {
                    stack.push((path.clone(), depth + 1));
                }
            }
            f(&path, &entry);
        }
    }
}

/// Files and bytes a job copies, as the tree stands.
fn measure(
    tree: &mut NtfsTree,
    job: &Job,
    budget: &mut Budget,
    notes: &mut Vec<String>,
) -> (u64, u64) {
    if let Some(len) = job.file {
        return (1, len);
    }
    let (mut n, mut bytes) = (0u64, 0u64);
    walk(
        tree,
        &job.source,
        job.leave_out,
        budget,
        notes,
        &mut |_, entry| {
            if let Entry::File { len, .. } = entry {
                n += 1;
                bytes += len;
            }
        },
    );
    (n, bytes)
}

/// "Outlook.pst", or "Outlook (2).pst" when the name is taken (ignoring case).
fn unique(name: &str, taken: &mut Vec<String>) -> String {
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    let mut candidate = name.to_string();
    let mut n = 2;
    while taken.iter().any(|t| t.eq_ignore_ascii_case(&candidate)) {
        candidate = format!("{stem} ({n}){ext}");
        n += 1;
    }
    taken.push(candidate.clone());
    candidate
}

/// The people's profiles in Users with what each copy holds, and the folders skipped,
/// walked within `budget`; what could not be listed is said in `notes`.
fn profiles(
    tree: &mut NtfsTree,
    budget: &mut Budget,
    notes: &mut Vec<String>,
) -> (Vec<User>, Vec<(String, String)>) {
    let users_root = Path::new(r"\Users");
    let mut users = Vec::new();
    let mut skipped = Vec::new();
    let entries = match tree.list(users_root) {
        Ok(entries) => entries,
        Err(why) => {
            // Not zero people: their folder could not be listed.
            notes.push(format!(
                "The Users folder could not be listed ({why}), so no person's files are planned; Recover deleted or lost files may still reach them."
            ));
            Vec::new()
        }
    };
    for entry in entries {
        let name = match &entry {
            Entry::Folder { name, .. } => name.to_string_lossy().into_owned(),
            Entry::Link { name, what } => {
                let name = name.to_string_lossy().into_owned();
                let why = not_a_person(&name).unwrap_or(what).to_string();
                skipped.push((name, why));
                continue;
            }
            Entry::File { .. } => continue,
        };
        if let Some(why) = not_a_person(&name) {
            skipped.push((name, why.to_string()));
            continue;
        }
        let profile = users_root.join(&name);
        let looks_like_one = tree.file_len(&profile.join("NTUSER.DAT")).is_some()
            || tree.is_folder(&profile.join("Desktop"))
            || tree.is_folder(&profile.join("Documents"));
        if !looks_like_one {
            skipped.push((
                name,
                "no user registry file (NTUSER.DAT) and no Desktop or Documents, so not a person's profile".into(),
            ));
            continue;
        }
        users.push(plan(tree, &name, &profile, budget, notes));
    }
    (users, skipped)
}

/// What is copied from one profile.
fn plan(
    tree: &mut NtfsTree,
    name: &str,
    profile: &Path,
    budget: &mut Budget,
    notes: &mut Vec<String>,
) -> User {
    let mut jobs: Vec<(String, Job)> = Vec::new();
    for folder in FOLDERS {
        let source = profile.join(folder);
        if tree.is_folder(&source) {
            jobs.push((folder.into(), Job::folder(source, vec![folder.into()])));
        }
    }
    let top = tree.list(profile).unwrap_or_else(|why| {
        notes.push(format!(
            "{} could not be listed ({why}); a OneDrive folder in it may not be planned.",
            profile.display()
        ));
        Vec::new()
    });
    for entry in top {
        if let Entry::Folder { name, .. } = entry {
            let text = name.to_string_lossy().into_owned();
            if text.eq_ignore_ascii_case("OneDrive") || text.starts_with("OneDrive - ") {
                jobs.push((text.clone(), Job::folder(profile.join(&name), vec![name])));
            }
        }
    }
    let mut browsers = Vec::new();
    for (browser, rel) in BROWSERS {
        let source = profile.join(rel);
        if tree.is_folder(&source) {
            browsers.push(browser);
            jobs.push((
                format!("Browser data ({browser})"),
                Job {
                    source,
                    into: vec!["Browser data".into(), browser.into()],
                    file: None,
                    leave_out: BROWSER_CACHES,
                },
            ));
        }
    }
    let mut sticky = false;
    let mut sticky_names = Vec::new();
    for (folder, files) in [
        (
            STICKY_NEW,
            &["plum.sqlite", "plum.sqlite-wal", "plum.sqlite-shm"][..],
        ),
        (STICKY_OLD, &["StickyNotes.snt"][..]),
    ] {
        for file in files {
            let source = profile.join(folder).join(file);
            if let Some(len) = tree.file_len(&source) {
                sticky = true;
                let into = unique(file, &mut sticky_names);
                jobs.push((
                    "Sticky Notes".into(),
                    Job {
                        source,
                        into: vec!["Sticky Notes".into(), into.into()],
                        file: Some(len),
                        leave_out: &[],
                    },
                ));
            }
        }
    }
    // Outlook data files anywhere in the profile; those in a folder copied already go
    // with it.
    let (mut pst, mut ost) = (Vec::new(), Vec::new());
    walk(tree, profile, &[], budget, notes, &mut |path, entry| {
        if let Entry::File { name, len, .. } = entry {
            let lower = name.to_string_lossy().to_lowercase();
            if lower.ends_with(".pst") {
                pst.push((path.to_path_buf(), *len));
            } else if lower.ends_with(".ost") {
                ost.push((path.to_path_buf(), *len));
            }
        }
    });
    pst.sort();
    ost.sort();
    let mut pst_names = Vec::new();
    for (path, len) in &pst {
        let covered = jobs
            .iter()
            .any(|(_, job)| job.file.is_none() && path.starts_with(&job.source));
        if covered {
            continue;
        }
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let into = unique(&file, &mut pst_names);
        jobs.push((
            "Outlook data files".into(),
            Job {
                source: path.clone(),
                into: vec!["Outlook data files".into(), OsString::from(into)],
                file: Some(*len),
                leave_out: &[],
            },
        ));
    }
    let mut parts: Vec<Part> = Vec::new();
    for (label, job) in &jobs {
        let (n, bytes) = measure(tree, job, budget, notes);
        match parts.iter_mut().find(|p| &p.label == label) {
            Some(part) => {
                part.files += n;
                part.bytes += bytes;
            }
            None => parts.push(Part {
                label: label.clone(),
                files: n,
                bytes,
            }),
        }
    }
    User {
        name: name.to_string(),
        profile: profile.to_path_buf(),
        into: name.to_string(),
        jobs: jobs.into_iter().map(|(_, job)| job).collect(),
        parts,
        pst,
        ost,
        browsers,
        sticky,
    }
}

/// How one person's copy went.
struct UserResult {
    name: String,
    /// The person's folder name in the copy, which tells two Windows' people apart.
    key: String,
    into: PathBuf,
    /// None when the copy ended before this person's turn.
    report: Option<copy::Report>,
    /// The damaged and skipped notes the copy gave for this person.
    notes: Vec<String>,
}

/// How a whole copy went, before it becomes the result.
#[derive(Default)]
struct Outcome {
    folder: Option<PathBuf>,
    users: Vec<UserResult>,
    report: Option<PathBuf>,
    report_error: Option<String>,
    report_ended: Option<String>,
    failed: Option<String>,
    complete: bool,
}

impl Outcome {
    fn copied(&self) -> usize {
        self.reports().map(copy::Report::copied).sum()
    }
    fn bytes(&self) -> u64 {
        self.reports().map(copy::Report::bytes).sum()
    }
    fn damaged(&self) -> usize {
        self.reports().map(copy::Report::damaged).sum()
    }
    fn partial(&self) -> usize {
        self.reports().map(copy::Report::partial).sum()
    }
    fn skipped(&self) -> usize {
        self.reports().map(|r| r.skipped.len()).sum()
    }
    fn reports(&self) -> impl Iterator<Item = &copy::Report> {
        self.users.iter().filter_map(|u| u.report.as_ref())
    }
    /// How the copy as a whole ended.
    fn ended(&self) -> copy::Outcome {
        for report in self.reports() {
            if report.outcome != copy::Outcome::Finished {
                return report.outcome.clone();
            }
        }
        copy::Outcome::Finished
    }
}

/// Copies the chosen people's files from `found` into a new folder in `destination`, then
/// writes the report. The destination is refused on the source's disk; every output is
/// made through a checked folder handle.
fn copy_found(
    found: &mut Found,
    destination: &Path,
    skip_damaged: bool,
    chosen: &dyn Fn(&User) -> bool,
    stop: &AtomicBool,
    progress: &copy::Progress,
    current: &Mutex<String>,
) -> Outcome {
    let mut outcome = Outcome::default();
    let guard = Guard::of(&found.source_disk);
    if let Err(why) = guard.check_folder(destination) {
        outcome.failed = Some(why);
        return outcome;
    }
    let stamp = crate::clock::local(SystemTime::now()).file();
    let name = format!("Customer files {stamp}");
    let top = match guard
        .base(destination)
        .and_then(|base| guard.folder(&base, std::ffi::OsStr::new(&name)))
    {
        Ok(top) => top,
        Err(e) => {
            outcome.failed = Some(format!(
                "{} could not be made: {e}",
                destination.join(&name).display()
            ));
            return outcome;
        }
    };
    outcome.folder = Some(top.path().to_path_buf());
    let settings = copy::Settings {
        skip_damaged,
        log_name: LOG,
        log_title: "Copy of the customer's files by Diagnostic Tool",
        ..copy::Settings::default()
    };
    let mut ended = false;
    for install in &mut found.installs {
        for user in install.users.iter().filter(|u| chosen(u)) {
            let into = top.path().join(&user.into);
            if let Ok(mut current) = current.lock() {
                current.clone_from(&user.name);
            }
            if ended {
                outcome.users.push(UserResult {
                    name: user.name.clone(),
                    key: user.into.clone(),
                    into,
                    report: None,
                    notes: Vec::new(),
                });
                continue;
            }
            let folder = match guard.folder(&top, std::ffi::OsStr::new(&user.into)) {
                Ok(folder) => folder,
                Err(e) => {
                    let why = format!("{} could not be made: {e}", into.display());
                    outcome.users.push(UserResult {
                        name: user.name.clone(),
                        key: user.into.clone(),
                        into,
                        report: None,
                        notes: vec![why.clone()],
                    });
                    outcome.failed.get_or_insert(why);
                    ended = true;
                    continue;
                }
            };
            let before = progress.notes.lock().map(|n| n.len()).unwrap_or(0);
            let report = copy::run_jobs(
                &mut install.tree,
                &user.jobs,
                &folder,
                &guard,
                &settings,
                stop,
                progress,
            );
            let notes = progress
                .notes
                .lock()
                .map(|n| n.get(before..).unwrap_or_default().to_vec())
                .unwrap_or_default();
            if report.outcome != copy::Outcome::Finished {
                ended = true;
            }
            outcome.users.push(UserResult {
                name: user.name.clone(),
                key: user.into.clone(),
                into,
                report: Some(report),
                notes,
            });
        }
    }
    let every_write = outcome.failed.is_none()
        && outcome.users.iter().all(|u| {
            u.report.as_ref().is_none_or(|r| {
                r.log_error.is_none()
                    && r.unlisted == 0
                    && !matches!(r.outcome, copy::Outcome::Failed(_))
            })
        });
    let text = report_text(found, &outcome, top.path());
    if let Ok(mut current) = current.lock() {
        current.clear();
    }
    // No line break after "End of report.": a report cut short of its last byte lacks it.
    let mut bytes = text.into_bytes();
    if every_write {
        bytes.extend_from_slice(END.as_bytes());
    }
    let (made, ended) = super::writer::write_lone_report(&guard, &top, REPORT, &bytes);
    outcome.complete = every_write && made.path.is_some() && made.error.is_none();
    outcome.report = made.path;
    outcome.report_error = made.error;
    outcome.report_ended = ended;
    outcome
}

/// A file the plan names, with its size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileItem {
    pub path: PathBuf,
    pub bytes: u64,
}

/// A folder in Users that is not a person's, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub name: String,
    pub why: String,
}

/// What will be copied from one person's profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonPlan {
    /// The profile folder's name in Users: what `Options::people` names.
    pub name: String,
    /// The folder the copy goes into, in "Customer files <date>".
    pub into: String,
    pub parts: Vec<Part>,
    pub files: u64,
    pub bytes: u64,
    /// Outlook data files, copied; offline files, listed and not copied.
    pub pst: Vec<FileItem>,
    pub ost: Vec<FileItem>,
    pub browsers: Vec<String>,
    pub sticky_notes: bool,
}

/// One Windows installation found, and what will be copied from it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPlan {
    /// "Partition 3, NTFS, 499 GB at 1.0 GB".
    pub volume: String,
    /// What the SOFTWARE hive says: product, version and product key; None with
    /// `registry_error` when it could not be read.
    pub windows: Option<hive::Windows>,
    pub registry_error: Option<String>,
    /// The report's lines on the product and its key, saying what kind of key it is.
    pub key_lines: Vec<String>,
    /// Saved Wi-Fi networks, names and security only.
    pub wifi: Vec<Network>,
    pub wifi_error: Option<String>,
    pub people: Vec<PersonPlan>,
    pub skipped: Vec<Skipped>,
    /// What could not be read of the volume.
    pub notes: Vec<String>,
}

/// What was found on the source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub source: String,
    pub windows: Vec<WindowsPlan>,
    pub notes: Vec<String>,
}

impl Found {
    /// What was found and will be copied, as plain data.
    pub fn plan(&self) -> Plan {
        let items = |list: &[(PathBuf, u64)]| {
            list.iter()
                .map(|(path, bytes)| FileItem {
                    path: path.clone(),
                    bytes: *bytes,
                })
                .collect()
        };
        Plan {
            source: self.source.clone(),
            notes: self.notes.clone(),
            windows: self
                .installs
                .iter()
                .map(|i| WindowsPlan {
                    volume: i.volume.clone(),
                    windows: i.windows.as_ref().ok().cloned(),
                    registry_error: i.windows.as_ref().err().cloned(),
                    key_lines: i.windows.as_ref().map(key_lines).unwrap_or_default(),
                    wifi: i.wifi.as_ref().cloned().unwrap_or_default(),
                    wifi_error: i.wifi.as_ref().err().cloned(),
                    people: i
                        .users
                        .iter()
                        .map(|u| PersonPlan {
                            name: u.name.clone(),
                            into: u.into.clone(),
                            parts: u.parts.clone(),
                            files: u.files(),
                            bytes: u.bytes(),
                            pst: items(&u.pst),
                            ost: items(&u.ost),
                            browsers: u.browsers.iter().map(|b| b.to_string()).collect(),
                            sticky_notes: u.sticky,
                        })
                        .collect(),
                    skipped: i
                        .skipped
                        .iter()
                        .map(|(name, why)| Skipped {
                            name: name.clone(),
                            why: why.clone(),
                        })
                        .collect(),
                    notes: i.notes.clone(),
                })
                .collect(),
        }
    }
}

/// Why the engine stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ended", content = "why", rename_all = "snake_case")]
pub enum Ended {
    /// Found and planned; no destination was given, so nothing was copied.
    Planned,
    Finished,
    /// Cancelled before the end; what was copied so far is kept and reported.
    Stopped,
    /// The source stopped answering.
    DriveGone(String),
    /// A write to the destination failed.
    WriteFailed(String),
    /// Nothing was copied: the source could not be read, no Windows was found, or the
    /// options were refused.
    NotStarted(String),
}

/// A file not copied, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotCopied {
    pub path: PathBuf,
    pub why: String,
}

/// How one person's copy went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonResult {
    pub name: String,
    /// Their folder in the copy; their log, listing every file, is in it.
    pub folder: PathBuf,
    pub log: Option<PathBuf>,
    /// False when the copy ended before this person's turn.
    pub started: bool,
    /// Files copied with every part read, and their bytes.
    pub copied: usize,
    pub bytes: u64,
    /// Files copied with zeros where the drive could not be read, as the copy noted them.
    pub damaged: Vec<String>,
    /// Files holding only part of their content.
    pub incomplete: usize,
    /// Links not followed, OneDrive files only in the cloud, unreadable folders.
    pub not_copied: Vec<NotCopied>,
}

/// What the engine did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateResult {
    pub ended: Ended,
    /// What was found; None when nothing could be.
    pub plan: Option<Plan>,
    /// "Customer files <date>", when it was made.
    pub folder: Option<PathBuf>,
    pub report: Option<PathBuf>,
    /// The report ends with "End of report.": it and every other write succeeded.
    pub report_complete: bool,
    pub report_error: Option<String>,
    /// How the report file ended, from its ledger entry: "read in full", or "PARTIAL: why".
    #[serde(default)]
    pub report_ended: Option<String>,
    pub people: Vec<PersonResult>,
    pub copied: usize,
    pub bytes: u64,
    pub damaged: usize,
    pub incomplete: usize,
    pub not_copied: usize,
}

impl MigrateResult {
    fn not_started(plan: Option<Plan>, why: String) -> Self {
        MigrateResult {
            ended: Ended::NotStarted(why),
            plan,
            folder: None,
            report: None,
            report_complete: false,
            report_error: None,
            report_ended: None,
            people: Vec::new(),
            copied: 0,
            bytes: 0,
            damaged: 0,
            incomplete: 0,
            not_copied: 0,
        }
    }
}

/// The engine: finds Windows on the source and plans each person's copy, then, when
/// `options.destination` is given, copies and writes the report. Only the destination is
/// written. `cancel` stops it at the next file or chunk.
pub fn run(options: &Options, events: Events, cancel: &AtomicBool) -> MigrateResult {
    match find(options, events, cancel) {
        Ok(mut found) if options.destination.is_some() => copy(&mut found, options, events, cancel),
        Ok(found) => MigrateResult {
            ended: Ended::Planned,
            ..MigrateResult::not_started(Some(found.plan()), String::new())
        },
        Err(why) => MigrateResult::not_started(None, why),
    }
}

/// The copy half of the engine, on what `find` found: checks the options, copies the chosen
/// people's files into a new folder in `options.destination` and writes the report.
pub fn copy(
    found: &mut Found,
    options: &Options,
    events: Events,
    cancel: &AtomicBool,
) -> MigrateResult {
    let plan = found.plan();
    let Some(destination) = &options.destination else {
        return MigrateResult::not_started(Some(plan), "no destination was given".into());
    };
    let names: Vec<String> = found
        .installs
        .iter()
        .flat_map(|i| i.users.iter().map(|u| u.name.clone()))
        .collect();
    if let Some(people) = &options.people {
        if let Some(unknown) = people
            .iter()
            .find(|p| !names.iter().any(|n| n.eq_ignore_ascii_case(p)))
        {
            return MigrateResult::not_started(
                Some(plan),
                format!(
                    "there is no profile named {unknown:?}; the profiles are {}",
                    names.join(", ")
                ),
            );
        }
    }
    let chosen = |u: &User| {
        options
            .people
            .as_ref()
            .is_none_or(|p| p.iter().any(|n| n.eq_ignore_ascii_case(&u.name)))
    };
    let (planned_files, planned_bytes) = found
        .installs
        .iter()
        .flat_map(|i| i.users.iter())
        .filter(|u| chosen(u))
        .fold((0, 0), |(f, b), u| (f + u.files(), b + u.bytes()));
    events(Event::Phase {
        phase: Phase::Copying,
        about: destination.display().to_string(),
    });
    let progress = copy::Progress::default();
    let person = Mutex::new(String::new());
    let sent = Mutex::new(0usize);
    let tick = || {
        let notes = progress.notes.lock().map(|n| n.clone()).unwrap_or_default();
        if let Ok(mut sent) = sent.lock() {
            for text in notes.iter().skip(*sent) {
                events(Event::Warning { text: text.clone() });
            }
            *sent = notes.len();
        }
        events(Event::Copying {
            person: person.lock().map(|p| p.clone()).unwrap_or_default(),
            pass: progress.pass.load(Ordering::Relaxed),
            files: progress.files.load(Ordering::Relaxed),
            bytes: progress.bytes.load(Ordering::Relaxed),
            planned_files,
            planned_bytes,
            damaged: progress.damaged.load(Ordering::Relaxed),
            skipped: progress.skipped.load(Ordering::Relaxed),
            current: progress
                .current
                .lock()
                .map(|c| c.clone())
                .unwrap_or_default(),
        });
    };
    let outcome = ticking(
        || {
            copy_found(
                found,
                destination,
                options.skip_damaged,
                &chosen,
                cancel,
                &progress,
                &person,
            )
        },
        &tick,
    );
    tick();
    let ended = match (&outcome.failed, outcome.ended()) {
        (Some(why), _) if outcome.users.iter().all(|u| u.report.is_none()) => {
            Ended::NotStarted(why.clone())
        }
        (Some(why), copy::Outcome::Finished) => Ended::WriteFailed(why.clone()),
        (_, copy::Outcome::Finished) => Ended::Finished,
        (_, copy::Outcome::Stopped) => Ended::Stopped,
        (_, copy::Outcome::Gone(why)) => Ended::DriveGone(why),
        (_, copy::Outcome::Failed(why)) => Ended::WriteFailed(why),
    };
    let people = outcome
        .users
        .iter()
        .map(|u| PersonResult {
            name: u.name.clone(),
            folder: u.into.clone(),
            log: u.report.as_ref().map(|r| r.log.clone()),
            started: u.report.is_some(),
            copied: u.report.as_ref().map_or(0, copy::Report::copied),
            bytes: u.report.as_ref().map_or(0, copy::Report::bytes),
            damaged: u
                .notes
                .iter()
                .filter_map(|n| n.strip_prefix("Damaged: "))
                .map(str::to_string)
                .collect(),
            incomplete: u.report.as_ref().map_or(0, copy::Report::partial),
            not_copied: u
                .report
                .iter()
                .flat_map(|r| r.skipped.iter())
                .map(|(path, why)| NotCopied {
                    path: path.clone(),
                    why: why.clone(),
                })
                .collect(),
        })
        .collect();
    MigrateResult {
        ended,
        plan: Some(plan),
        folder: outcome.folder.clone(),
        report: outcome.report.clone(),
        report_complete: outcome.complete,
        report_error: outcome.report_error.clone(),
        report_ended: outcome.report_ended.clone(),
        people,
        copied: outcome.copied(),
        bytes: outcome.bytes(),
        damaged: outcome.damaged(),
        incomplete: outcome.partial(),
        not_copied: outcome.skipped(),
    }
}

/// What Windows the installation is, and its product key with what kind it is.
pub fn key_lines(windows: &hive::Windows) -> Vec<String> {
    let mut lines = Vec::new();
    let mut what = windows
        .product
        .clone()
        .unwrap_or_else(|| "Windows (edition not recorded)".into());
    if let Some(version) = &windows.version {
        what.push_str(&format!(", version {version}"));
    }
    if let Some(build) = &windows.build {
        what.push_str(&format!(" (build {build})"));
    }
    lines.push(what);
    let oem = windows.product_id.as_deref().is_some_and(hive::oem);
    match &windows.key {
        None => lines.push(match &windows.key_unread {
            Some(why) => format!("Product key: recorded, but it could not be read: {why}."),
            None => "Product key: none recorded in the registry.".into(),
        }),
        Some(key) => {
            lines.push(format!("Product key: {key}"));
            lines.push(match hive::key_kind(key) {
                hive::KeyKind::Blank => "No key is kept on this drive: Windows was activated by a digital license or by a key in the old PC's firmware. Neither moves to a new PC with the files.".into(),
                hive::KeyKind::Generic(edition) => format!("This is the generic key Windows installs for {edition} when the license is digital. It is not the customer's own key and does not activate another PC; the license is tied to the old PC's hardware, and to the customer's Microsoft account if one was linked."),
                hive::KeyKind::Volume(edition) => format!("This is the generic key for {edition} activated by an organization's own activation server (KMS); the license belongs to that organization."),
                hive::KeyKind::Own if oem => "This key came with the PC: the maker put it in the old PC's firmware. It belongs to that PC and does not activate a new one.".into(),
                hive::KeyKind::Own => "This is the key Windows was installed with. A retail key can be moved to the new PC (used on one PC at a time); a key that came with the old PC stays with it.".into(),
            });
        }
    }
    if oem
        && !matches!(
            windows.key.as_deref().map(hive::key_kind),
            Some(hive::KeyKind::Own)
        )
    {
        lines.push(
            "The license channel is OEM: the key lives in the old PC's firmware, not on the drive."
                .into(),
        );
    }
    if windows.dirty {
        lines.push("The registry file was not saved cleanly when Windows last ran, or parts of it could not be read; what it says may be out of date.".into());
    }
    lines
}

/// The handover report, all but its last line.
fn report_text(found: &Found, outcome: &Outcome, folder: &Path) -> String {
    let mut r = String::new();
    let mut line = |text: &str| {
        r.push_str(text);
        r.push_str("\r\n");
    };
    line("Customer files report");
    line("This report is complete only if its last line reads \"End of report\" with a full stop.");
    line("");
    line(&format!("From: {}", found.source));
    line(&format!("Into: {}", folder.display()));
    line(&format!(
        "Written: {}",
        crate::clock::local(SystemTime::now()).long()
    ));
    for note in &found.notes {
        line(&format!("Note: {note}"));
    }
    for install in &found.installs {
        line("");
        line(&format!("Windows on {}", install.volume));
        match &install.windows {
            Ok(windows) => {
                for text in key_lines(windows) {
                    line(&format!("  {text}"));
                }
            }
            Err(why) => line(&format!("  The product key could not be read: {why}.")),
        }
        for note in &install.notes {
            line(&format!("  Note: {note}"));
        }
        line("");
        line("  Saved Wi-Fi networks (names and security only; the passwords are not copied):");
        match &install.wifi {
            Ok(list) if list.is_empty() => line("    none"),
            Ok(list) => {
                for n in list {
                    line(&format!("    {}  ({})", n.name, n.security));
                }
            }
            Err(why) => line(&format!("    could not be read: {why}")),
        }
        for user in &install.users {
            line("");
            line(&format!(
                "Person: {}  (copied into \"{}\")",
                user.name, user.into
            ));
            for part in &user.parts {
                line(&format!(
                    "  {}: {} ({}) found",
                    part.label,
                    files(part.files as usize),
                    bytes_text(part.bytes)
                ));
            }
            if user.parts.is_empty() {
                line("  Nothing to copy was found in this profile.");
            }
            let Some(result) = outcome.users.iter().find(|u| u.key == user.into) else {
                line("  Not copied: not chosen for this copy.");
                continue;
            };
            let Some(report) = &result.report else {
                line("  Not copied: the copy ended before this person's turn.");
                for note in &result.notes {
                    line(&format!("  {note}"));
                }
                continue;
            };
            line(&format!(
                "  Result: {}",
                copy::summary(report, &report.outcome)
            ));
            let damaged: Vec<&String> = result
                .notes
                .iter()
                .filter(|n| n.starts_with("Damaged"))
                .collect();
            if !damaged.is_empty() {
                line("  Damaged files, copied with zeros where the drive could not be read:");
                for note in damaged {
                    line(&format!("    {}", note.trim_start_matches("Damaged: ")));
                }
            }
            if report.partial() > 0 {
                line(&format!(
                    "  {} hold only part of their content; \"{}\" in this person's folder lists them as PARTIAL.",
                    files(report.partial()),
                    LOG
                ));
            }
            let online: Vec<&PathBuf> = report
                .skipped
                .iter()
                .filter(|(_, why)| why == tree::ONLINE_ONLY || why == tree::PARTLY_ONLINE)
                .map(|(p, _)| p)
                .collect();
            if !online.is_empty() {
                line("  OneDrive files kept only in the cloud (placeholders), not on this drive and not copied; they come back when the customer signs in to OneDrive on the new PC:");
                for path in online {
                    line(&format!("    {}", path.display()));
                }
            }
            let links = report
                .skipped
                .iter()
                .filter(|(_, why)| why == tree::LINK)
                .count();
            if links > 0 {
                line(&format!(
                    "  {links} {} not followed; Windows makes them for older programs and they point at folders copied by their own names.",
                    if links == 1 { "junction or link was" } else { "junctions and links were" }
                ));
            }
            let other: Vec<&(PathBuf, String)> = report
                .skipped
                .iter()
                .filter(|(_, why)| {
                    why != tree::ONLINE_ONLY && why != tree::PARTLY_ONLINE && why != tree::LINK
                })
                .collect();
            if !other.is_empty() {
                line("  Not copied:");
                for (path, why) in other {
                    line(&format!("    {}  ({why})", path.display()));
                }
            }
            if !user.pst.is_empty() {
                line("  Outlook data files (.pst), copied; open them in Outlook on the new PC:");
                for (path, len) in &user.pst {
                    line(&format!("    {}  ({})", path.display(), bytes_text(*len)));
                }
            }
            if !user.ost.is_empty() {
                line("  Outlook offline files (.ost), not copied: they are copies of a mailbox kept on the mail server, and Outlook makes them again on the new PC:");
                for (path, len) in &user.ost {
                    line(&format!("    {}  ({})", path.display(), bytes_text(*len)));
                }
            }
            if !user.browsers.is_empty() {
                line(&format!(
                    "  Browser data copied for {}, without caches: bookmarks, history and settings carry over. Saved passwords do not: they are encrypted to the old Windows account. The customer gets them back by signing in to the browser's sync, or by exporting them from the browser on the old PC while it still runs.",
                    user.browsers.join(", ")
                ));
            }
            line(if user.sticky {
                "  Sticky Notes copied (in \"Sticky Notes\"): to use them, close Sticky Notes on the new PC and put plum.sqlite in its LocalState folder."
            } else {
                "  No Sticky Notes found."
            });
            line(&format!(
                "  Every file copied, damaged or not copied is listed in \"{}\\{}\".",
                user.into, LOG
            ));
        }
        if !install.skipped.is_empty() {
            line("");
            line("Folders in Users that are not a person's, not copied:");
            for (name, why) in &install.skipped {
                line(&format!("  {name}: {why}"));
            }
        }
    }
    line("");
    line("What does not carry over");
    line("  Saved passwords in browsers and Windows, and Wi-Fi passwords: they are encrypted to the old Windows account.");
    line("  Programs: they are installed again on the new PC.");
    line("  OneDrive files kept only in the cloud: they are in the customer's OneDrive account, not on this drive.");
    line("  Outlook .ost files: Outlook makes them again from the mail server.");
    line("");
    let how = match outcome.ended() {
        copy::Outcome::Finished => "Finished".to_string(),
        copy::Outcome::Stopped => "Stopped before the end".to_string(),
        copy::Outcome::Gone(why) | copy::Outcome::Failed(why) => format!("Ended early: {why}"),
    };
    line(&format!(
        "{how}. In all: {} copied ({}), {} damaged, {} incomplete, {} not copied.",
        files(outcome.copied()),
        bytes_text(outcome.bytes()),
        outcome.damaged(),
        outcome.partial(),
        outcome.skipped()
    ));
    if let Some(why) = &outcome.failed {
        line(&format!("This report has no last line: {why}."));
    }
    for result in &outcome.users {
        if let Some(report) = &result.report {
            if let Some(why) = &report.log_error {
                line(&format!(
                    "This report has no last line: the log in \"{}\" could not be written in full ({why}).",
                    result.into.display()
                ));
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recovery::fs::ntfs::Live;
    use crate::recovery::fs::{Data, Place, Run};
    use crate::recovery::MemDisk;

    /// A tree over `disk` of `(record, parent, name, is_dir, len, at)` records below the
    /// root (record 5); a file's content is `len` bytes at byte `at`.
    fn tree_of(disk: MemDisk, records: &[(u64, u64, &str, bool, u64, u64)]) -> NtfsTree {
        let live = |no, parent, name: &str, is_dir, len, at| Live {
            no,
            seq: 1,
            name: name.into(),
            parent,
            parent_seq: 0,
            is_dir,
            size: len,
            data: Data::Runs(if len == 0 {
                Vec::new()
            } else {
                vec![Run {
                    place: Place::At(at),
                    len: len.next_multiple_of(512),
                }]
            }),
            created: None,
            modified: None,
            accessed: None,
            attributes: 0,
            reparse: None,
            compressed: false,
            encrypted: false,
            damaged: false,
        };
        let mut all = vec![live(5, 5, "", true, 0, 0)];
        for &(no, parent, name, is_dir, len, at) in records {
            all.push(live(no, parent, name, is_dir, len, at));
        }
        let source: SharedSource = Arc::new(Mutex::new(Box::new(disk) as Box<dyn BlockSource>));
        NtfsTree::new(source, all)
    }

    /// The guard: a Wi-Fi profile on unreadable sectors, one too large to be a profile, and
    /// an adapter folder of them are each said, never silently dropped; a readable one is
    /// listed.
    #[test]
    fn a_wifi_profile_that_cannot_be_read_is_said() {
        let good =
            br"<WLANProfile><name>Cafe</name><authentication>open</authentication></WLANProfile>";
        let mut data = vec![0u8; 8192];
        data[..good.len()].copy_from_slice(good);
        let mut disk = MemDisk::new(data);
        disk.bad.push(4096..4608);
        let mut tree = tree_of(
            disk,
            &[
                (30, 5, "ProgramData", true, 0, 0),
                (31, 30, "Microsoft", true, 0, 0),
                (32, 31, "Wlansvc", true, 0, 0),
                (33, 32, "Profiles", true, 0, 0),
                (34, 33, "Interfaces", true, 0, 0),
                (35, 34, "{adapter}", true, 0, 0),
                (36, 35, "cafe.xml", false, good.len() as u64, 0),
                (37, 35, "lost.xml", false, 300, 4096),
                (38, 35, "huge.xml", false, 2 << 20, 0),
            ],
        );
        let mut notes = Vec::new();
        let found = networks(&mut tree, &mut notes).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Cafe");
        let said = notes.join(" ");
        assert!(
            said.contains("lost.xml") && said.contains("could not be read"),
            "{said}"
        );
        assert!(
            said.contains("huge.xml") && said.contains("too large"),
            "{said}"
        );
    }

    /// The guard: a Users entry that cannot be listed is said, not shown as no people.
    #[test]
    fn a_users_folder_that_cannot_be_listed_is_said() {
        let mut tree = tree_of(MemDisk::new(vec![0; 512]), &[(30, 5, "Users", false, 0, 0)]);
        let mut budget = Budget::new(WALK, None);
        let mut notes = Vec::new();
        let (users, _) = profiles(&mut tree, &mut budget, &mut notes);
        assert!(users.is_empty());
        assert!(
            notes
                .join(" ")
                .contains("The Users folder could not be listed"),
            "{notes:?}"
        );
    }

    /// The guard: folders nested past the copy's depth are not walked, as the copy does not
    /// copy them, and that is said; a walk past its count ends there and says so.
    #[test]
    fn the_walk_of_a_profile_is_bounded_by_its_budget() {
        let mut records = vec![(30, 5, "Users", true, 0, 0), (31, 30, "Ann", true, 0, 0)];
        for k in 0..400u64 {
            records.push((32 + k, 31 + k, "d", true, 0, 0));
        }
        let mut tree = tree_of(MemDisk::new(vec![0; 512]), &records);
        let started = std::time::Instant::now();
        let mut budget = Budget::new(WALK, None);
        let mut notes = Vec::new();
        let mut seen = 0;
        walk(
            &mut tree,
            Path::new(r"\Users\Ann"),
            &[],
            &mut budget,
            &mut notes,
            &mut |_, _| seen += 1,
        );
        // The folders down to 255 deep are listed; the one at 256 is seen but not entered.
        assert_eq!(seen, copy::MAX_DEPTH + 1);
        assert_eq!(budget.spent().too_deep, 1);
        assert!(budget
            .said()
            .unwrap()
            .contains("1 of its folders lay more than 255 deep"));
        let mut budget = Budget::new(Limits { count: 100, ..WALK }, None);
        seen = 0;
        walk(
            &mut tree,
            Path::new(r"\Users\Ann"),
            &[],
            &mut budget,
            &mut notes,
            &mut |_, _| seen += 1,
        );
        assert_eq!(
            (seen, budget.hit()),
            (100, Some(crate::budget::Limit::Count))
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn wifi_profiles_give_name_and_security_and_never_the_key() {
        let xml = br#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>Home &amp; Garden</name>
	<SSIDConfig><SSID><hex>486F6D65</hex><name>Home &amp; Garden</name></SSID></SSIDConfig>
	<MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption>
	<sharedKey><keyType>passPhrase</keyType><protected>true</protected><keyMaterial>01000000D08C9DDF</keyMaterial></sharedKey></security></MSM>
</WLANProfile>"#;
        let n = network(xml).unwrap();
        assert_eq!(n.name, "Home & Garden");
        assert_eq!(n.security, "WPA2-Personal");
        assert!(!format!("{n:?}").contains("01000000"));
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                String::from_utf8_lossy(xml)
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes()),
            )
            .collect();
        assert_eq!(network(&utf16).unwrap(), n);
        assert_eq!(network(b"<nothing/>"), None);
        let open =
            br"<WLANProfile><name>Cafe</name><authentication>open</authentication></WLANProfile>";
        assert_eq!(network(open).unwrap().security, "Open, no password");
    }

    #[test]
    fn system_folders_in_users_are_not_people() {
        for name in [
            "Default",
            "Public",
            "All Users",
            "defaultuser0",
            "Default User",
        ] {
            assert!(not_a_person(name).is_some(), "{name}");
        }
        for name in ["Ann", "Administrator", "TEMP", "bob.CONTOSO"] {
            assert!(not_a_person(name).is_none(), "{name}");
        }
    }

    #[test]
    fn copied_outlook_files_get_distinct_names() {
        let mut taken = Vec::new();
        assert_eq!(unique("Outlook.pst", &mut taken), "Outlook.pst");
        assert_eq!(unique("outlook.PST", &mut taken), "outlook (2).PST");
        assert_eq!(unique("Outlook.pst", &mut taken), "Outlook (3).pst");
        assert_eq!(unique("archive", &mut taken), "archive");
    }

    #[test]
    fn the_key_lines_say_what_kind_of_key_it_is() {
        let mut w = hive::Windows {
            product: Some("Windows 11 Pro".into()),
            key: Some("BBBBB-BBBBB-BBBBB-BBBBB-BBBBB".into()),
            ..Default::default()
        };
        assert!(key_lines(&w)
            .join(" ")
            .contains("digital license or by a key in the old PC's firmware"));
        w.key = Some("VK7JG-NPHTM-C97JM-9MPGT-3V66T".into());
        assert!(key_lines(&w)
            .join(" ")
            .contains("generic key Windows installs for Pro"));
        w.product_id = Some("00330-80000-00000-AAOEM".into());
        assert!(key_lines(&w).join(" ").contains("old PC's firmware"));
        w.key = Some(
            "ABCDE-FGHJK-MNPQR-TVWXY-23467".replace(['A', 'E', 'I', 'L', 'O', 'S', 'U', 'Z'], "B"),
        );
        assert!(key_lines(&w).join(" ").contains("came with the PC"));
    }
}
