//! Rescue copy: copies chosen folders from a failing drive's volume to a folder on another
//! disk. Easy first: every file is read once in large chunks with no retries, then only the
//! chunks that failed are read again sector by sector. What stays unreadable becomes zeros
//! and the file is listed as damaged, or damaged files are left out if the user chose so.
//! Folder structure and timestamps are kept; junctions and links are never followed; the
//! source is only read; a plain-text log goes into the destination.
use std::ffi::{OsStr, OsString};
use std::fs::{File, FileTimes};
use std::io::Write;
use std::os::windows::fs::{FileTimesExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

use super::dest::{self, Folder, Guard, Made};
use super::disk::TimedFile;
use super::ledger::{files, Ledger};
use super::{write_all_at, BlockSource, ReadError, Sink};
use crate::tools::drives::bytes_text;

/// A file or folder's three times; None where the file system did not give one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Times {
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
}

/// One entry of a folder on the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Folder {
        name: OsString,
        times: Times,
    },
    File {
        name: OsString,
        len: u64,
        times: Times,
    },
    /// A junction, symbolic link or other reparse point, an online-only cloud file, or an
    /// entry that could not be read; never followed or copied.
    Link {
        name: OsString,
        what: &'static str,
    },
}

/// The source side of a copy: folder listings and files to read.
pub trait Tree {
    fn list(&mut self, folder: &Path) -> Result<Vec<Entry>, String>;
    fn open(&mut self, file: &Path, len: u64) -> Result<Box<dyn BlockSource>, ReadError>;
    fn times(&mut self, path: &Path) -> Times;
    /// Whether the source's own records of the file at `path` are damaged, so its copy
    /// ends damaged however much of it is read: a file system read directly can say so.
    fn damaged(&mut self, _path: &Path) -> bool {
        false
    }
}

/// The deepest folder a copy goes below the folder it copies: 255 levels, past any real
/// profile's, where a damaged or forged file table can nest folders millions deep and each
/// level's path is longer than the last. A deeper folder is skipped and said.
pub const MAX_DEPTH: usize = 255;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x4_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

fn times_of(meta: &std::fs::Metadata) -> Times {
    Times {
        created: meta.created().ok(),
        modified: meta.modified().ok(),
        accessed: meta.accessed().ok(),
    }
}

/// Folders and files on a mounted volume, read through `TimedFile`.
pub struct Volume {
    sector: u32,
}

impl Volume {
    /// `root` is any path on the volume; its sector size sets the read alignment.
    pub fn new(root: &Path) -> Self {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceW;
        let top = root.ancestors().last().unwrap_or(root);
        let name = super::disk::wide(&top.to_string_lossy());
        let (mut per_cluster, mut sector, mut free, mut total) = (0u32, 0u32, 0u32, 0u32);
        // SAFETY: name is NUL-terminated and the out pointers are valid.
        let ok = unsafe {
            GetDiskFreeSpaceW(
                name.as_ptr(),
                &mut per_cluster,
                &mut sector,
                &mut free,
                &mut total,
            )
        };
        let sector = if ok != 0 && sector >= 512 && sector.is_power_of_two() {
            sector
        } else {
            4096
        };
        Self { sector }
    }
}

impl Tree for Volume {
    fn list(&mut self, folder: &Path) -> Result<Vec<Entry>, String> {
        let reader = std::fs::read_dir(folder).map_err(|e| e.to_string())?;
        let mut entries = Vec::new();
        for item in reader {
            let item = item.map_err(|e| e.to_string())?;
            let name = item.file_name();
            // From the folder listing itself, so a link is seen as a link, not followed.
            let Ok(meta) = item.metadata() else {
                entries.push(Entry::Link {
                    name,
                    what: "its details could not be read",
                });
                continue;
            };
            let attributes = meta.file_attributes();
            entries.push(if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                Entry::Link {
                    name,
                    what: "a junction or link, not followed",
                }
            } else if attributes
                & (FILE_ATTRIBUTE_OFFLINE
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                != 0
            {
                Entry::Link {
                    name,
                    what: "an online-only file, not on this drive",
                }
            } else if meta.is_dir() {
                Entry::Folder {
                    name,
                    times: times_of(&meta),
                }
            } else {
                Entry::File {
                    name,
                    len: meta.len(),
                    times: times_of(&meta),
                }
            });
        }
        Ok(entries)
    }

    fn open(&mut self, file: &Path, len: u64) -> Result<Box<dyn BlockSource>, ReadError> {
        TimedFile::open(file, len, self.sector).map(|f| Box::new(f) as Box<dyn BlockSource>)
    }

    fn times(&mut self, path: &Path) -> Times {
        std::fs::symlink_metadata(path)
            .map(|m| times_of(&m))
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    /// Bytes per read in the first pass; rounded to the sector size.
    pub chunk: u64,
    /// Leave out files with unreadable parts instead of copying them with zeros.
    pub skip_damaged: bool,
    /// The log's file name in the copy's folder, and its first line.
    pub log_name: &'static str,
    pub log_title: &'static str,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            chunk: 1 << 20,
            skip_damaged: false,
            log_name: "Rescue copy log.txt",
            log_title: "Rescue copy by Diagnostic Tool",
        }
    }
}

/// One thing to copy: a folder with all it holds, or one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub source: PathBuf,
    /// Where it goes below the copy's folder: the folders it goes in, made as needed, then
    /// its own name.
    pub into: Vec<OsString>,
    /// A file of this many bytes; None for a folder.
    pub file: Option<u64>,
    /// Folders left out wherever they are met inside it, by name, ignoring case: caches
    /// that are rebuilt by themselves.
    pub leave_out: &'static [&'static str],
}

impl Job {
    /// All of folder `source`, into `into` below the copy's folder.
    pub fn folder(source: PathBuf, into: Vec<OsString>) -> Job {
        Job {
            source,
            into,
            file: None,
            leave_out: &[],
        }
    }
}

/// What the window shows while a copy runs.
#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    pub damaged: AtomicU64,
    pub skipped: AtomicU64,
    /// 1 for the first pass, 2 for the second.
    pub pass: AtomicU64,
    pub current: Mutex<String>,
    /// Damaged and skipped items as they are found, for the window's list.
    pub notes: Mutex<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Finished,
    Stopped,
    Gone(String),
    Failed(String),
}

#[derive(Debug)]
pub struct Report {
    pub outcome: Outcome,
    /// Every file made, entered as it was made, each with how it ended.
    pub ledger: Ledger,
    pub skipped: Vec<(PathBuf, String)>,
    pub log: PathBuf,
    /// Why the log could not be written to its end, if so.
    pub log_error: Option<String>,
    /// Files made that have no row in the log, since writing it failed.
    pub unlisted: usize,
}

impl Report {
    /// Files copied in full with every part read.
    pub fn copied(&self) -> usize {
        self.ledger.complete()
    }

    pub fn bytes(&self) -> u64 {
        self.ledger.complete_bytes()
    }

    /// Files copied with zeros in place of unreadable parts.
    pub fn damaged(&self) -> usize {
        self.ledger.damaged()
    }

    /// Files that hold less than they should: stopped, or a write failed.
    pub fn partial(&self) -> usize {
        self.ledger.incomplete()
    }
}

/// Refuses a destination on `disk` or any disk the sources lie on, then makes the folder the
/// copy goes into, "Rescued files <date-time>" inside `destination`, and returns it, held
/// open, with the guard every output of the copy is checked by.
pub fn prepare(
    sources: &[PathBuf],
    destination: &Path,
    disk: Option<u32>,
) -> Result<(Folder, Guard), String> {
    if sources.is_empty() {
        return Err("choose at least one folder to copy".into());
    }
    let mut disks: Vec<u32> = disk.into_iter().collect();
    for source in sources {
        disks.extend(crate::tools::drives::device::disks_of_path(source)?);
    }
    let guard = Guard::new(disks);
    guard.check_folder(destination)?;
    let stamp = crate::clock::local(SystemTime::now()).file();
    let name = format!("Rescued files {stamp}");
    let folder = destination.join(&name);
    if folder.exists() {
        return Err(format!("{} is already there", folder.display()));
    }
    let made = guard
        .base(destination)
        .and_then(|base| guard.folder(&base, OsStr::new(&name)))
        .map_err(|e| format!("{} could not be made: {e}", folder.display()))?;
    Ok((made, guard))
}

enum Halt {
    Stop,
    Gone(String),
    Write(String),
}

/// A file whose first pass left failed chunks, which are its ledger entry's zeroed ranges.
/// It is closed; the second pass opens it again by its file ID or walk, so it writes to the
/// file the first one made. Its source, size and zeroed ranges are its open entry's.
struct Pending {
    made: Made,
    /// Its entry in the ledger.
    output: usize,
    times: Times,
}

/// What every output file's writes go through: the file itself, or in tests a writer that
/// fails as told.
type Wrap<'a> = &'a mut dyn FnMut(File) -> Box<dyn Sink>;
type LogWrap<'a> = &'a mut dyn FnMut(File) -> Box<dyn Write + Send>;

/// The log's last line, with no line break after it; a log that does not end with it was
/// cut short.
pub const LOG_END: &str = "End of log.";

struct Copier<'a> {
    tree: &'a mut dyn Tree,
    guard: &'a Guard,
    /// The folder the copy goes into, held for the whole copy. Other folders are held only
    /// while being filled, and opened again by their IDs when needed.
    base: &'a Folder,
    settings: &'a Settings,
    stop: &'a AtomicBool,
    progress: &'a Progress,
    wrap: Wrap<'a>,
    buffer: Vec<u8>,
    pending: Vec<Pending>,
    /// Every folder made, with the times it gets when the copy ends.
    folders: Vec<(Made, Times)>,
    report: Report,
}

/// The ranges of `failed` chunks, as zeroed ranges.
fn ranges(failed: &[(u64, u64)]) -> Vec<std::ops::Range<u64>> {
    failed.iter().map(|&(at, n)| at..at + n).collect()
}

fn file_times(times: &Times) -> FileTimes {
    let mut set = FileTimes::new();
    if let Some(time) = times.modified {
        set = set.set_modified(time);
    }
    if let Some(time) = times.accessed {
        set = set.set_accessed(time);
    }
    if let Some(time) = times.created {
        set = set.set_created(time);
    }
    set
}

/// The name a source folder gets in the rescue folder: its own name, or "Drive F" for a
/// drive's root, with " (2)" and so on when two are alike.
fn target_name(source: &Path, taken: &[OsString]) -> OsString {
    let base = match source.file_name() {
        Some(name) => name.to_os_string(),
        None => {
            let letter = source
                .to_string_lossy()
                .chars()
                .next()
                .filter(char::is_ascii_alphabetic)
                .unwrap_or('X');
            OsString::from(format!("Drive {letter}"))
        }
    };
    let mut name = base.clone();
    let mut n = 2;
    while taken.contains(&name) {
        let mut next = base.clone();
        next.push(format!(" ({n})"));
        name = next;
        n += 1;
    }
    name
}

fn gone(code: u32) -> Halt {
    Halt::Gone(format!(
        "The drive stopped answering (error {code}): it was unplugged or has failed. What was copied so far is kept."
    ))
}

impl Copier<'_> {
    /// A log that cannot be written must not stop the rescue; the ledger keeps the failure,
    /// and the log is never ended as if it were whole.
    fn line(&mut self, text: &str) {
        self.report.ledger.line(text);
    }

    fn note(&self, text: String) {
        if let Ok(mut notes) = self.progress.notes.lock() {
            notes.push(text);
        }
    }

    fn skip(&mut self, path: &Path, why: &str) {
        let text = format!("Skipped: {}  ({why})", path.display());
        self.line(&text);
        self.note(text);
        self.progress.skipped.fetch_add(1, Ordering::Relaxed);
        self.report
            .skipped
            .push((path.to_path_buf(), why.to_string()));
    }

    fn check_stop(&self) -> Result<(), Halt> {
        if self.stop.load(Ordering::Relaxed) {
            Err(Halt::Stop)
        } else {
            Ok(())
        }
    }

    fn set_current(&self, path: &Path) {
        if let Ok(mut current) = self.progress.current.lock() {
            *current = path.display().to_string();
        }
    }

    /// Walks one source folder into folder `name` of the base, copying each file's easy
    /// parts. Each folder is made in its parent, opened again by ID, and held only while
    /// its own files are made.
    fn first_pass(
        &mut self,
        source: &Path,
        parent: Option<usize>,
        name: &OsStr,
        times: Times,
        leave_out: &[&str],
    ) -> Result<(), Halt> {
        let mut stack: Vec<(PathBuf, Option<usize>, OsString, Times, usize)> =
            vec![(source.to_path_buf(), parent, name.to_os_string(), times, 0)];
        while let Some((folder, parent, name, times, depth)) = stack.pop() {
            self.check_stop()?;
            if depth > MAX_DEPTH {
                self.skip(
                    &folder,
                    &format!("more than {MAX_DEPTH} folders deep; not copied"),
                );
                continue;
            }
            let into = self.make_folder(parent, &name)?;
            self.folders.push((
                self.guard.record_folder(self.base, &into).map_err(|e| {
                    Halt::Write(format!("{} could not be noted: {e}", into.path().display()))
                })?,
                times,
            ));
            let index = self.folders.len() - 1;
            let entries = match self.tree.list(&folder) {
                Ok(entries) => entries,
                Err(why) => {
                    self.skip(&folder, &format!("folder could not be read: {why}"));
                    continue;
                }
            };
            for entry in entries {
                match entry {
                    Entry::Folder { name, .. }
                        if leave_out
                            .iter()
                            .any(|out| name.eq_ignore_ascii_case(OsStr::new(out))) =>
                    {
                        let text = format!(
                            "Left out: {}  (a cache, rebuilt by itself)",
                            folder.join(&name).display()
                        );
                        self.line(&text);
                    }
                    Entry::Folder { name, times } => {
                        stack.push((folder.join(&name), Some(index), name, times, depth + 1));
                    }
                    Entry::Link { name, what } => self.skip(&folder.join(&name), what),
                    Entry::File { name, len, times } => {
                        self.copy_file(&folder.join(&name), &into, &name, len, times)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Makes the folders `parts` below the base, each in the one before, or takes those made
    /// already; returns the last one's index in `self.folders`, None for the base itself.
    fn job_folder(
        &mut self,
        made: &mut Vec<(Vec<OsString>, usize)>,
        parts: &[OsString],
    ) -> Result<Option<usize>, Halt> {
        let mut parent = None;
        for depth in 1..=parts.len() {
            let path = &parts[..depth];
            if let Some((_, index)) = made.iter().find(|(p, _)| p.as_slice() == path) {
                parent = Some(*index);
                continue;
            }
            let folder = self.make_folder(parent, &parts[depth - 1])?;
            let record = self.guard.record_folder(self.base, &folder).map_err(|e| {
                Halt::Write(format!(
                    "{} could not be noted: {e}",
                    folder.path().display()
                ))
            })?;
            self.folders.push((record, Times::default()));
            let index = self.folders.len() - 1;
            made.push((path.to_vec(), index));
            parent = Some(index);
        }
        Ok(parent)
    }

    /// Copies one job: its folders are made, then the file, or the folder walked.
    fn job(&mut self, job: &Job, made: &mut Vec<(Vec<OsString>, usize)>) -> Result<(), Halt> {
        let Some((name, parts)) = job.into.split_last() else {
            return Ok(());
        };
        let parent = self.job_folder(made, parts)?;
        let times = self.tree.times(&job.source);
        match job.file {
            None => self.first_pass(&job.source, parent, name, times, job.leave_out),
            Some(len) => {
                let reopened;
                let into = match parent {
                    None => self.base,
                    Some(index) => {
                        let record = &self.folders[index].0;
                        reopened = self.guard.reopen_folder(self.base, record).map_err(|e| {
                            Halt::Write(format!(
                                "{} could not be opened: {e}",
                                record.path().display()
                            ))
                        })?;
                        &reopened
                    }
                };
                self.copy_file(&job.source, into, name, len, times)
            }
        }
    }

    /// Makes folder `name` in folder `parent` of `self.folders`, or in the base.
    fn make_folder(&mut self, parent: Option<usize>, name: &OsStr) -> Result<Folder, Halt> {
        let reopened;
        let parent = match parent {
            None => self.base,
            Some(index) => {
                let made = &self.folders[index].0;
                reopened = self.guard.reopen_folder(self.base, made).map_err(|e| {
                    Halt::Write(format!(
                        "{} could not be opened: {e}",
                        made.path().display()
                    ))
                })?;
                &reopened
            }
        };
        self.guard.folder(parent, name).map_err(|e| {
            Halt::Write(format!(
                "{} could not be made: {e}",
                parent.path().join(name).display()
            ))
        })
    }

    /// Copies one file into `name` in folder `into`. It is entered in the ledger as it is
    /// made; every way it ends is entered there too.
    fn copy_file(
        &mut self,
        source: &Path,
        into: &Folder,
        name: &OsStr,
        len: u64,
        times: Times,
    ) -> Result<(), Halt> {
        self.check_stop()?;
        self.set_current(source);
        let mut reader = match self.tree.open(source, len) {
            Ok(reader) => reader,
            Err(ReadError::Gone(code)) => return Err(gone(code)),
            Err(ReadError::Bad(code)) => {
                self.skip(source, &format!("could not be opened, error {code}"));
                return Ok(());
            }
            Err(ReadError::TimedOut) => {
                self.skip(source, "could not be opened in time");
                return Ok(());
            }
        };
        let target = into.path().join(name);
        let entry = super::writer::Entry {
            tag: 0,
            source: source.to_path_buf(),
            note: String::new(),
            size: len,
        };
        let super::writer::Made { file: out, id, .. } =
            super::writer::create_exact(self.guard, into, name, &mut self.report.ledger, entry)
                .map_err(|e| Halt::Write(format!("{} could not be made: {e}", target.display())))?;
        if self.tree.damaged(source) {
            self.report.ledger.flawed(id, super::output::FLAW);
        }
        let mut sink = match out.try_clone() {
            Ok(file) => (self.wrap)(file),
            Err(e) => {
                let why = format!("{} could not be written: {e}", target.display());
                self.report.ledger.partial(id, why.clone());
                return Err(Halt::Write(why));
            }
        };
        let sector = u64::from(reader.sector_size().max(1));
        let chunk = (self.settings.chunk / sector).max(1) * sector;
        let mut failed = Vec::new();
        let mut pos = 0;
        while pos < len {
            if let Err(halt) = self.check_stop() {
                self.cut_short(id, &failed, "the copy was stopped");
                return Err(halt);
            }
            let want = chunk.min(len - pos);
            let read = (want.div_ceil(sector) * sector) as usize;
            if self.buffer.len() < read {
                self.buffer.resize(read, 0);
            }
            match reader.read_at(pos, &mut self.buffer[..read]) {
                Ok(()) => {
                    if let Err(e) = write_all_at(sink.as_mut(), &self.buffer[..want as usize], pos)
                    {
                        let why = format!("writing failed at byte {pos}: {e}");
                        self.cut_short(id, &failed, &why);
                        return Err(Halt::Write(format!(
                            "{} could not be written: {e}",
                            target.display()
                        )));
                    }
                    self.progress.bytes.fetch_add(want, Ordering::Relaxed);
                }
                Err(ReadError::Gone(code)) => {
                    self.cut_short(id, &failed, "the drive stopped answering");
                    return Err(gone(code));
                }
                Err(_) if self.settings.skip_damaged => {
                    drop(sink);
                    match dest::remove(out) {
                        Ok(()) => {
                            self.report
                                .ledger
                                .removed(id, "damaged, left out as chosen");
                            self.skip(source, "damaged, left out as chosen");
                        }
                        Err(e) => {
                            let why = format!("damaged, and it could not be removed ({e})");
                            self.cut_short(id, &failed, &why);
                        }
                    }
                    return Ok(());
                }
                Err(_) => failed.push((pos, want)),
            }
            pos += want;
            // Read or not, all before `pos` is written: a failed chunk stays zeros.
            self.report.ledger.wrote(id, pos);
        }
        drop(sink);
        if let Err(e) = out.set_len(len) {
            let why = format!("it could not be sized: {e}");
            self.cut_short(id, &failed, &why);
            return Err(Halt::Write(format!(
                "{} could not be sized: {e}",
                target.display()
            )));
        }
        self.report.ledger.wrote(id, len);
        if failed.is_empty() {
            self.finish_file(id, &out, &times, Vec::new());
            return Ok(());
        }
        match self.guard.record(self.base, &out, &target) {
            Ok(made) => {
                // Its entry stays open, holding the failed chunks, until the second pass.
                self.report.ledger.zeroed(id, ranges(&failed));
                self.pending.push(Pending {
                    made,
                    output: id,
                    times,
                });
            }
            // It cannot be found again, so the first pass's copy is what it holds.
            Err(_) => self.finish_file(id, &out, &times, ranges(&failed)),
        }
        Ok(())
    }

    /// Enters a file cut short in the ledger, which writes its row to the log.
    fn cut_short(&mut self, id: usize, failed: &[(u64, u64)], why: &str) {
        self.report.ledger.zeroed(id, ranges(failed));
        self.report.ledger.partial(id, why);
    }

    /// Ends one file written in full, through a handle to it that was made or reopened
    /// where it was made: its times go on, and it is entered in the ledger as whole, with
    /// any zeroed ranges. A file that cannot be reached is never ended here.
    fn finish_file(
        &mut self,
        id: usize,
        out: &File,
        times: &Times,
        zeroed: Vec<std::ops::Range<u64>>,
    ) {
        let output = self.report.ledger.get(id);
        let (source, target, len) = (output.source.clone(), output.path.clone(), output.size);
        if let Err(e) = out.set_times(file_times(times)) {
            self.line(&format!("Times not kept: {}  ({e})", target.display()));
        }
        self.report.ledger.zeroed(id, zeroed);
        // Read before it ends: an ended entry leaves memory, its row going to the log.
        let damaged = self.report.ledger.get(id).zeroed_bytes();
        let flaw = self.report.ledger.get(id).flaw.clone();
        self.report.ledger.whole(id);
        self.progress.files.fetch_add(1, Ordering::Relaxed);
        if damaged != 0 {
            self.progress.damaged.fetch_add(1, Ordering::Relaxed);
            self.note(format!(
                "Damaged: {}  ({} of {} unreadable, written as zeros)",
                source.display(),
                bytes_text(damaged),
                bytes_text(len)
            ));
        } else if let Some(flaw) = flaw {
            self.progress.damaged.fetch_add(1, Ordering::Relaxed);
            self.note(format!("Damaged: {}  ({flaw})", source.display()));
        }
    }

    /// Reads the failed chunks of each damaged file again, one sector at a time, once.
    fn second_pass(&mut self) -> Result<(), Halt> {
        self.progress.pass.store(2, Ordering::Relaxed);
        while !self.pending.is_empty() {
            self.check_stop()?;
            let file = self.pending.remove(0);
            let entry = self.report.ledger.get(file.output);
            let (source, len, failed) = (entry.source.clone(), entry.size, entry.zeroed.clone());
            self.set_current(&source);
            let mut reader = match self.tree.open(&source, len) {
                Ok(reader) => reader,
                Err(ReadError::Gone(code)) => {
                    self.pending.insert(0, file);
                    return Err(gone(code));
                }
                Err(_) => {
                    self.finish_pending(&file);
                    continue;
                }
            };
            let out = match self.guard.reopen(self.base, &file.made) {
                Ok(out) => out,
                Err(e) => {
                    let why = format!(
                        "it could not be opened again for the second pass ({e}); it holds the first pass's copy, with zeros where that failed"
                    );
                    self.report.ledger.partial(file.output, why);
                    continue;
                }
            };
            let mut sink = match out.try_clone() {
                Ok(clone) => (self.wrap)(clone),
                Err(e) => {
                    let why = format!("it could not be written again ({e})");
                    self.report.ledger.partial(file.output, why);
                    continue;
                }
            };
            let sector = u64::from(reader.sector_size().max(1));
            let mut zeroed = Vec::new();
            let mut piece = vec![0u8; sector as usize];
            let mut halt = None;
            'chunks: for chunk in &failed {
                let (start, size) = (chunk.start, chunk.end - chunk.start);
                let mut pos = start;
                while pos < start + size {
                    if halt.is_some() || self.stop.load(Ordering::Relaxed) {
                        // Not read again, so it stays zeros.
                        zeroed.push(pos..start + size);
                        halt.get_or_insert(Halt::Stop);
                        continue 'chunks;
                    }
                    let want = sector.min(start + size - pos);
                    match reader.read_at(pos, &mut piece) {
                        Ok(()) => {
                            if let Err(e) =
                                write_all_at(sink.as_mut(), &piece[..want as usize], pos)
                            {
                                zeroed.push(pos..start + size);
                                halt = Some(Halt::Write(format!(
                                    "{} could not be written: {e}",
                                    file.made.path().display()
                                )));
                                continue 'chunks;
                            }
                            self.progress.bytes.fetch_add(want, Ordering::Relaxed);
                        }
                        Err(ReadError::Gone(code)) => {
                            zeroed.push(pos..start + size);
                            halt = Some(gone(code));
                            continue 'chunks;
                        }
                        Err(_) => zeroed.push(pos..pos + want),
                    }
                    pos += want;
                }
            }
            drop(sink);
            if let Some(Halt::Write(why)) = &halt {
                let why = format!("writing failed during the second pass: {why}");
                self.report.ledger.zeroed(file.output, zeroed);
                self.report.ledger.partial(file.output, why);
            } else {
                self.finish_file(file.output, &out, &file.times, zeroed);
            }
            if let Some(halt) = halt {
                return Err(halt);
            }
        }
        Ok(())
    }

    /// Files whose second pass never ran keep what the first pass wrote.
    fn flush_pending(&mut self) {
        for file in std::mem::take(&mut self.pending) {
            self.finish_pending(&file);
        }
    }

    /// A file that cannot be opened again where it was made is not known to hold what the
    /// first pass wrote, so it is entered as incomplete.
    fn finish_pending(&mut self, file: &Pending) {
        match self.guard.reopen(self.base, &file.made) {
            Ok(out) => {
                let zeroed = self.report.ledger.get(file.output).zeroed.clone();
                self.finish_file(file.output, &out, &file.times, zeroed);
            }
            Err(e) => {
                let why = format!(
                    "it could not be opened again ({e}); it holds the first pass's copy, with zeros where that failed"
                );
                self.report.ledger.partial(file.output, why);
            }
        }
    }
}

/// Copies `sources` into `folder`, made by `prepare`; every output is checked by `guard`.
pub fn run(
    tree: &mut dyn Tree,
    sources: &[PathBuf],
    folder: &Folder,
    guard: &Guard,
    settings: &Settings,
    stop: &AtomicBool,
    progress: &Progress,
) -> Report {
    let mut taken = Vec::new();
    let jobs: Vec<Job> = sources
        .iter()
        .map(|source| {
            let name = target_name(source, &taken);
            taken.push(name.clone());
            Job::folder(source.clone(), vec![name])
        })
        .collect();
    run_jobs(tree, &jobs, folder, guard, settings, stop, progress)
}

/// Copies `jobs` into `folder`, made by the caller and held open; every output is checked
/// by `guard`. Two jobs never name the same file.
pub fn run_jobs(
    tree: &mut dyn Tree,
    jobs: &[Job],
    folder: &Folder,
    guard: &Guard,
    settings: &Settings,
    stop: &AtomicBool,
    progress: &Progress,
) -> Report {
    let mut plain = |file: File| -> Box<dyn Sink> { Box::new(file) };
    let mut plain_log = |file: File| -> Box<dyn Write + Send> { Box::new(file) };
    run_with(
        tree,
        jobs,
        folder,
        guard,
        settings,
        stop,
        progress,
        &mut plain,
        &mut plain_log,
    )
}

/// `run`, with every output file's writes going through `wrap` and the log's through
/// `log_wrap`, so tests can fail them.
#[allow(clippy::too_many_arguments)]
fn run_with(
    tree: &mut dyn Tree,
    jobs: &[Job],
    folder: &Folder,
    guard: &Guard,
    settings: &Settings,
    stop: &AtomicBool,
    progress: &Progress,
    wrap: Wrap<'_>,
    log_wrap: LogWrap<'_>,
) -> Report {
    let log_path = folder.path().join(settings.log_name);
    let empty = |outcome| Report {
        outcome,
        ledger: Ledger::default(),
        skipped: Vec::new(),
        log: log_path.clone(),
        log_error: None,
        unlisted: 0,
    };
    let log = match super::writer::create_log(guard, folder, OsStr::new(settings.log_name)) {
        Ok(log) => log,
        Err(e) => {
            return empty(Outcome::Failed(format!(
                "{} could not be made: {e}",
                log_path.display()
            )))
        }
    };
    let mut copier = Copier {
        tree,
        guard,
        base: folder,
        settings,
        stop,
        progress,
        wrap,
        buffer: Vec::new(),
        pending: Vec::new(),
        folders: Vec::new(),
        // The log is the ledger: each file's row goes into it as the file ends.
        report: Report {
            ledger: Ledger::to_log(log_wrap(log), folder.path().to_path_buf()),
            ..empty(Outcome::Finished)
        },
    };
    copier.line(settings.log_title);
    // The last line is named without its full stop: a log cut just after a quote of it
    // must not end with it.
    copier.line(&format!(
        "This log is complete only if its last line reads \"{}\" with a full stop.",
        LOG_END.trim_end_matches('.')
    ));
    copier.line(
        "Each file made has a row as it ends: its path in this folder, its size, its condition and the file it was copied from, separated by tabs.",
    );
    copier.line(&format!(
        "Started: {}",
        crate::clock::local(SystemTime::now()).long()
    ));
    copier.line(&format!("Into: {}", folder.path().display()));
    copier.line(if settings.skip_damaged {
        "Damaged files: left out"
    } else {
        "Damaged files: copied, with zeros where the drive could not be read"
    });
    copier.line("");
    progress.pass.store(1, Ordering::Relaxed);
    let mut made = Vec::new();
    let mut result = Ok(());
    for job in jobs {
        let into: PathBuf = job.into.iter().collect();
        copier.line(&format!(
            "From: {}  to  {}",
            job.source.display(),
            folder.path().join(into).display()
        ));
        result = copier.job(job, &mut made);
        if result.is_err() {
            break;
        }
    }
    if result.is_ok() && !copier.pending.is_empty() {
        copier.line("");
        copier.line("Second pass: reading the failed parts again, one sector at a time.");
        result = copier.second_pass();
    }
    copier.flush_pending();
    // Folder times last, deepest first, since writing into a folder changes them.
    for (made, times) in std::mem::take(&mut copier.folders).iter().rev() {
        let kept = copier
            .guard
            .reopen_folder(folder, made)
            .and_then(|again| again.set_times(file_times(times)));
        if let Err(e) = kept {
            copier.line(&format!("Times not kept: {}  ({e})", made.path().display()));
        }
    }
    copier
        .report
        .ledger
        .close("the copy ended before it was finished");
    let outcome = match result {
        Ok(()) => Outcome::Finished,
        Err(Halt::Stop) => Outcome::Stopped,
        Err(Halt::Gone(why)) => Outcome::Gone(why),
        Err(Halt::Write(why)) => Outcome::Failed(why),
    };
    copier.line("");
    // A log with a gap gets no summary and no last line, so it never reads as whole; the
    // check after the summary keeps a failed summary from being followed by the last line.
    match copier.report.ledger.log_error().map(str::to_string) {
        Some(why) => {
            copier.line(&format!(
                "This log is incomplete: a write to it failed ({why})."
            ));
            copier
                .report
                .ledger
                .write_unwritten("Files made whose rows could not be written above:");
        }
        None => {
            let text = summary(&copier.report, &outcome);
            copier.line(&text);
            if copier.report.ledger.log_error().is_none() {
                copier.report.ledger.last_line(LOG_END);
            }
        }
    }
    copier.report.log_error = copier.report.ledger.close_log();
    copier.report.unlisted = copier.report.ledger.unlisted();
    copier.report.outcome = outcome;
    copier.report
}

/// One line on how a copy went.
pub fn summary(report: &Report, outcome: &Outcome) -> String {
    let how = match outcome {
        Outcome::Finished => "Finished".to_string(),
        Outcome::Stopped => "Stopped before the end".to_string(),
        Outcome::Gone(why) | Outcome::Failed(why) => format!("Ended early: {why}"),
    };
    format!(
        "{how}. Copied {} ({}), {} damaged, {} incomplete, {} skipped.",
        files(report.copied()),
        bytes_text(report.bytes()),
        report.damaged(),
        report.partial(),
        report.skipped.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::MemDisk;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    type Log = Arc<Mutex<Vec<(PathBuf, u64, usize)>>>;

    /// A file of the test tree; reads are logged in one list for the whole tree.
    struct Shared {
        path: PathBuf,
        disk: Arc<Mutex<MemDisk>>,
        len: u64,
        log: Log,
    }

    impl BlockSource for Shared {
        fn len(&self) -> u64 {
            self.len
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.log
                .lock()
                .unwrap()
                .push((self.path.clone(), offset, buf.len()));
            self.disk.lock().unwrap().read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.path.display().to_string()
        }
    }

    enum Node {
        Folder,
        File(u64, Arc<Mutex<MemDisk>>),
        Link,
    }

    struct MemTree {
        nodes: BTreeMap<PathBuf, Node>,
        log: Log,
        /// Files whose records the tree says are damaged.
        flawed: Vec<PathBuf>,
    }

    fn when(seconds: u64) -> Times {
        Times {
            created: Some(UNIX_EPOCH + Duration::from_secs(seconds)),
            modified: Some(UNIX_EPOCH + Duration::from_secs(seconds + 100)),
            accessed: Some(UNIX_EPOCH + Duration::from_secs(seconds + 200)),
        }
    }

    impl Tree for MemTree {
        fn list(&mut self, folder: &Path) -> Result<Vec<Entry>, String> {
            Ok(self
                .nodes
                .iter()
                .filter(|(path, _)| path.parent() == Some(folder))
                .map(|(path, node)| {
                    let name = path.file_name().unwrap().to_os_string();
                    match node {
                        Node::Folder => Entry::Folder {
                            name,
                            times: when(1_500_000_000),
                        },
                        Node::File(len, _) => Entry::File {
                            name,
                            len: *len,
                            times: when(1_600_000_000),
                        },
                        Node::Link => Entry::Link {
                            name,
                            what: "a junction or link, not followed",
                        },
                    }
                })
                .collect())
        }

        fn open(&mut self, file: &Path, len: u64) -> Result<Box<dyn BlockSource>, ReadError> {
            match self.nodes.get(file) {
                Some(Node::File(_, disk)) => Ok(Box::new(Shared {
                    path: file.to_path_buf(),
                    disk: disk.clone(),
                    len,
                    log: self.log.clone(),
                })),
                _ => Err(ReadError::Bad(2)),
            }
        }

        fn times(&mut self, _path: &Path) -> Times {
            when(1_400_000_000)
        }

        fn damaged(&mut self, path: &Path) -> bool {
            self.flawed.iter().any(|f| f == path)
        }
    }

    fn content(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    type Range = Option<std::ops::Range<u64>>;

    fn file(data: &[u8], bad: Range, slow: Range, dies_after: Option<usize>) -> Node {
        let mut padded = data.to_vec();
        padded.resize(data.len().div_ceil(512) * 512, 0);
        let mut disk = MemDisk::new(padded);
        disk.bad.extend(bad);
        disk.slow.extend(slow);
        disk.dies_after = dies_after;
        Node::File(data.len() as u64, Arc::new(Mutex::new(disk)))
    }

    /// src: a.txt (good), sub/b.bin (two bad sectors), sub/c.bin (a slow sector), link.
    fn tree(dies_after: Option<usize>) -> (MemTree, Vec<u8>, Vec<u8>, Vec<u8>) {
        let (a, b, c) = (content(3000, 1), content(300_000, 2), content(150_000, 3));
        let mut nodes = BTreeMap::new();
        nodes.insert(PathBuf::from(r"X:\src"), Node::Folder);
        nodes.insert(
            PathBuf::from(r"X:\src\a.txt"),
            file(&a, None, None, dies_after),
        );
        nodes.insert(PathBuf::from(r"X:\src\sub"), Node::Folder);
        nodes.insert(
            PathBuf::from(r"X:\src\sub\b.bin"),
            file(&b, Some(100_352..101_376), None, dies_after),
        );
        nodes.insert(
            PathBuf::from(r"X:\src\sub\c.bin"),
            file(&c, None, Some(140_288..140_800), dies_after),
        );
        nodes.insert(PathBuf::from(r"X:\src\link"), Node::Link);
        let tree = MemTree {
            nodes,
            log: Arc::new(Mutex::new(Vec::new())),
            flawed: Vec::new(),
        };
        (tree, a, b, c)
    }

    fn folder(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("diagtool-copy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn settings(skip_damaged: bool) -> Settings {
        Settings {
            chunk: 64 << 10,
            skip_damaged,
            ..Settings::default()
        }
    }

    /// The destination folder held open, as `prepare` hands it over.
    fn held(path: &Path) -> Folder {
        Guard::default().base(path).unwrap()
    }

    fn copy(tree: &mut MemTree, dir: &Path, skip_damaged: bool) -> Report {
        run(
            tree,
            &[PathBuf::from(r"X:\src")],
            &held(dir),
            &Guard::new([9999]),
            &settings(skip_damaged),
            &AtomicBool::new(false),
            &Progress::default(),
        )
    }

    /// The guard: a file whose records the source says are damaged is copied, read in full,
    /// and still listed damaged, never copied whole.
    #[test]
    fn a_file_with_a_damaged_record_is_listed_damaged() {
        let dir = folder("flawed");
        let (mut tree, a, _, _) = tree(None);
        tree.flawed.push(PathBuf::from(r"X:\src\a.txt"));
        let report = copy(&mut tree, &dir, false);
        assert_eq!(report.outcome, Outcome::Finished);
        assert_eq!(std::fs::read(dir.join(r"src\a.txt")).unwrap(), a);
        assert_eq!((report.copied(), report.damaged()), (0, 3));
        let a_row = table(&report)
            .into_iter()
            .find(|(path, _, _)| path.ends_with("a.txt"))
            .unwrap();
        assert!(
            a_row.2.starts_with("DAMAGED: the volume's record"),
            "{a_row:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_files_are_copied_with_zeros_and_listed() {
        let dir = folder("damaged");
        let (mut tree, a, b, c) = tree(None);
        let report = copy(&mut tree, &dir, false);
        assert_eq!(report.outcome, Outcome::Finished);
        assert_eq!(report.copied(), 1);
        let out = dir.join("src");
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), a);
        let mut want_b = b.clone();
        want_b[100_352..101_376].fill(0);
        assert_eq!(std::fs::read(out.join(r"sub\b.bin")).unwrap(), want_b);
        let mut want_c = c.clone();
        want_c[140_288..140_800].fill(0);
        assert_eq!(std::fs::read(out.join(r"sub\c.bin")).unwrap(), want_c);
        assert_eq!(report.damaged(), 2);
        let mut damaged: Vec<(String, String)> = table(&report)
            .into_iter()
            .filter(|(_, _, condition)| condition.starts_with("DAMAGED"))
            .map(|(path, _, condition)| (path, condition))
            .collect();
        damaged.sort();
        assert_eq!(damaged.len(), 2, "{damaged:?}");
        assert_eq!(damaged[0].0, r"src\sub\b.bin");
        assert!(
            damaged[0].1.starts_with("DAMAGED: 1024 bytes"),
            "{damaged:?}"
        );
        assert_eq!(damaged[1].0, r"src\sub\c.bin");
        assert!(
            damaged[1].1.starts_with("DAMAGED: 512 bytes"),
            "{damaged:?}"
        );
        assert_eq!(report.skipped.len(), 1);
        assert!(!out.join("link").exists(), "a link was followed");
        // Times are kept on files and folders.
        let meta = std::fs::metadata(out.join(r"sub\b.bin")).unwrap();
        assert_eq!(
            meta.modified().unwrap(),
            when(1_600_000_000).modified.unwrap()
        );
        assert_eq!(
            meta.created().unwrap(),
            when(1_600_000_000).created.unwrap()
        );
        let meta = std::fs::metadata(out.join("sub")).unwrap();
        assert_eq!(
            meta.modified().unwrap(),
            when(1_500_000_000).modified.unwrap()
        );
        let meta = std::fs::metadata(&out).unwrap();
        assert_eq!(
            meta.modified().unwrap(),
            when(1_400_000_000).modified.unwrap()
        );
        // Easy first: every chunk of every file is read before any failed chunk again.
        let reads = tree.log.lock().unwrap().clone();
        let first_small = reads.iter().position(|(_, _, len)| *len == 512).unwrap();
        assert!(reads[..first_small].iter().all(|(_, _, len)| *len > 512));
        assert!(reads[first_small..].iter().all(|(_, _, len)| *len == 512));
        let chunked: u64 = reads[..first_small]
            .iter()
            .map(|(_, _, len)| *len as u64)
            .sum();
        let sectors = |n: u64| n.div_ceil(512) * 512;
        assert_eq!(chunked, sectors(3000) + sectors(300_000) + sectors(150_000));
        // The second pass reads only the failed chunks, by sector: b's 64 KiB chunk and
        // the 18,928-byte tail chunk of c.
        assert_eq!(reads.len() - first_small, 128 + 37);
        let log = std::fs::read_to_string(&report.log).unwrap();
        assert!(
            log.contains("src\\a.txt\t3000 bytes\tread in full\tX:\\src\\a.txt\r\n"),
            "{log}"
        );
        assert!(
            log.contains("src\\sub\\b.bin\t300000 bytes\tDAMAGED: 1024 bytes unreadable"),
            "{log}"
        );
        assert!(
            log.contains(r"Skipped: X:\src\link  (a junction or link, not followed)"),
            "{log}"
        );
        assert!(log.contains("Finished. Copied 1 file"), "{log}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_files_can_be_left_out() {
        let dir = folder("leftout");
        let (mut tree, a, _, _) = tree(None);
        let report = copy(&mut tree, &dir, true);
        assert_eq!(report.outcome, Outcome::Finished);
        assert_eq!(report.damaged(), 0);
        assert_eq!(report.skipped.len(), 3);
        let out = dir.join("src");
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), a);
        assert!(!out.join(r"sub\b.bin").exists());
        assert!(!out.join(r"sub\c.bin").exists());
        assert!(tree
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, len)| *len > 512));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_drive_that_goes_away_ends_the_copy_with_the_log_written() {
        let dir = folder("gone");
        let (mut tree, _, _, _) = tree(Some(2));
        let report = copy(&mut tree, &dir, false);
        assert!(
            matches!(report.outcome, Outcome::Gone(_)),
            "{:?}",
            report.outcome
        );
        let log = std::fs::read_to_string(&report.log).unwrap();
        assert!(
            log.contains("Ended early: The drive stopped answering"),
            "{log}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn source_folders_get_distinct_names() {
        let taken = vec![OsString::from("Documents")];
        assert_eq!(
            target_name(Path::new(r"F:\Users\Bob\Documents"), &taken),
            "Documents (2)"
        );
        assert_eq!(target_name(Path::new(r"F:\"), &[]), "Drive F");
    }

    /// The guard: a destination on a disk being copied from is refused before anything.
    #[test]
    fn a_destination_on_the_source_disk_is_refused() {
        let source = folder("samesrc");
        let destination = folder("samedst");
        let err = prepare(std::slice::from_ref(&source), &destination, None).unwrap_err();
        assert!(err.contains("the disk being recovered"), "{err}");
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
        assert!(prepare(&[], &destination, None).is_err());
        std::fs::remove_dir_all(&source).unwrap();
        std::fs::remove_dir_all(&destination).unwrap();
    }

    /// The file rows of a copy's log, written as each file ended: path, size and condition.
    fn table(report: &Report) -> Vec<(String, String, String)> {
        let log = std::fs::read_to_string(&report.log).unwrap();
        log.lines()
            .filter(|l| l.contains('\t'))
            .map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                assert_eq!(f.len(), 4, "{l}");
                (f[0].to_string(), f[1].to_string(), f[2].to_string())
            })
            .collect()
    }

    /// A tree that runs `swap` when a file is opened a second time, between the passes.
    struct SwapBetweenPasses<F: FnMut()> {
        tree: MemTree,
        opened: Vec<PathBuf>,
        swap: Option<F>,
        /// After the swap, the source file cannot be opened for the second pass either.
        then_fail: bool,
    }

    impl<F: FnMut()> Tree for SwapBetweenPasses<F> {
        fn list(&mut self, folder: &Path) -> Result<Vec<Entry>, String> {
            self.tree.list(folder)
        }
        fn open(&mut self, file: &Path, len: u64) -> Result<Box<dyn BlockSource>, ReadError> {
            if self.opened.iter().any(|p| p == file) {
                if let Some(mut swap) = self.swap.take() {
                    swap();
                }
                if self.then_fail {
                    return Err(ReadError::Bad(1117));
                }
            }
            self.opened.push(file.to_path_buf());
            self.tree.open(file, len)
        }
        fn times(&mut self, path: &Path) -> Times {
            self.tree.times(path)
        }
    }

    fn junction(link: &Path, target: &Path) {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed: {made:?}");
    }

    /// What the second pass wrote into b.bin: the good sectors of its failed 64 KiB chunk.
    fn second_pass_part(b: &[u8]) -> (std::ops::Range<usize>, &[u8]) {
        (65_536..100_352, &b[65_536..100_352])
    }

    /// Swaps `sub` for `with` between the passes, as a person or program might: the folder
    /// is renamed aside and a junction put in its place. Returns whether the swap happened.
    fn swap_sub(sub: &Path, moved: &Path, with: &Path) -> bool {
        if std::fs::rename(sub, moved).is_err() {
            return false;
        }
        junction(sub, with);
        true
    }

    /// The guard: the second pass writes only the file the first pass made, opened again by
    /// its ID. Left alone, it gets the second pass's data; moved after it was made, with a
    /// folder on the same disk holding another file of that name put in its place, neither
    /// is written, and the ledger says the file holds the first pass's copy.
    #[test]
    fn the_second_pass_writes_only_the_file_the_first_pass_made() {
        for swap in [false, true] {
            let into = folder(&format!("swap-same-{swap}"));
            let elsewhere = folder(&format!("swap-same-other-{swap}"));
            std::fs::write(elsewhere.join("b.bin"), b"someone else's file").unwrap();
            let sub = into.join(r"src\sub");
            let moved = into.join(r"src\sub-moved");
            let (tree, _, b, _) = tree(None);
            let mut swapped = false;
            let mut unheld = false;
            let mut swapping = SwapBetweenPasses {
                tree,
                opened: Vec::new(),
                then_fail: false,
                swap: Some(|| {
                    // Between the passes no handle to a damaged file is held: it opens
                    // with no sharing at all.
                    use std::os::windows::fs::OpenOptionsExt;
                    unheld = ["b.bin", "c.bin"].iter().all(|name| {
                        std::fs::OpenOptions::new()
                            .read(true)
                            .share_mode(0)
                            .open(sub.join(name))
                            .is_ok()
                    });
                    swapped = swap && swap_sub(&sub, &moved, &elsewhere);
                }),
            };
            let report = run(
                &mut swapping,
                &[PathBuf::from(r"X:\src")],
                &held(&into),
                &Guard::new([9999]),
                &settings(false),
                &AtomicBool::new(false),
                &Progress::default(),
            );
            assert!(swapping.swap.is_none(), "the second pass never ran");
            assert!(
                unheld,
                "a damaged file's handle was held between the passes"
            );
            assert_eq!(swapped, swap, "the folder could not be swapped");
            assert_eq!(report.outcome, Outcome::Finished);
            assert_eq!(
                std::fs::read(elsewhere.join("b.bin")).unwrap(),
                b"someone else's file"
            );
            let b_out = table(&report)
                .into_iter()
                .find(|row| row.0.ends_with("b.bin"))
                .unwrap()
                .2;
            let (range, part) = second_pass_part(&b);
            if swap {
                std::fs::remove_dir(&sub).unwrap();
                let held = std::fs::read(moved.join("b.bin")).unwrap();
                assert!(
                    held[range].iter().all(|byte| *byte == 0),
                    "the moved file was written"
                );
                assert!(
                    b_out.starts_with("PARTIAL: ") && b_out.contains("could not be opened again"),
                    "{b_out}"
                );
            } else {
                assert_eq!(&std::fs::read(sub.join("b.bin")).unwrap()[range], part);
                assert!(b_out.starts_with("DAMAGED: "), "{b_out}");
            }
            std::fs::remove_dir_all(&into).unwrap();
            std::fs::remove_dir_all(&elsewhere).unwrap();
        }
    }

    /// The guard: a damaged file whose second pass cannot run, and which cannot be opened
    /// again where it was made, is entered as incomplete, never as whole.
    #[test]
    fn a_file_that_cannot_be_opened_again_is_never_reported_whole() {
        let into = folder("unreachable");
        let elsewhere = folder("unreachable-other");
        let (sub, moved) = (into.join(r"src\sub"), into.join(r"src\sub-moved"));
        let (tree, _, _, _) = tree(None);
        let mut swapped = false;
        let mut swapping = SwapBetweenPasses {
            tree,
            opened: Vec::new(),
            then_fail: true,
            swap: Some(|| swapped = swap_sub(&sub, &moved, &elsewhere)),
        };
        let report = run(
            &mut swapping,
            &[PathBuf::from(r"X:\src")],
            &held(&into),
            &Guard::new([9999]),
            &settings(false),
            &AtomicBool::new(false),
            &Progress::default(),
        );
        assert!(swapped, "the folder could not be swapped");
        let rows = table(&report);
        let b_out = &rows.iter().find(|row| row.0.ends_with("b.bin")).unwrap().2;
        assert!(
            b_out.starts_with("PARTIAL: ") && b_out.contains("could not be opened again"),
            "{b_out}"
        );
        // c.bin, damaged too and in the same folder, ends the same way.
        let mut partial: Vec<&str> = rows
            .iter()
            .filter(|row| row.2.starts_with("PARTIAL"))
            .map(|row| row.0.as_str())
            .collect();
        partial.sort_unstable();
        assert_eq!(partial, [r"src\sub\b.bin", r"src\sub\c.bin"], "{rows:?}");
        assert_eq!(report.partial(), 2);
        std::fs::remove_dir(&sub).unwrap();
        std::fs::remove_dir_all(&into).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();
    }

    /// The guard: the same swap to a folder on the disk being recovered writes nothing there.
    #[test]
    fn a_second_pass_never_writes_through_a_swapped_folder() {
        use crate::tools::drives::device::disks_of_path;
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"target\tmp");
        std::fs::create_dir_all(&base).unwrap();
        let into = base.join(format!("diagtool-copy-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&into);
        std::fs::create_dir_all(&into).unwrap();
        let source_side = folder("swaptarget");
        let disk = disks_of_path(&source_side).unwrap()[0];
        assert!(
            !disks_of_path(&into).unwrap().contains(&disk),
            "the temporary folder and the target folder share disk {disk}; this test needs two disks"
        );
        std::fs::write(source_side.join("b.bin"), b"customer data").unwrap();
        let sub = into.join(r"src\sub");
        let moved = into.join(r"src\sub-moved");
        let (tree, _, _, _) = tree(None);
        let mut swapped = None;
        let mut swapping = SwapBetweenPasses {
            tree,
            opened: Vec::new(),
            then_fail: false,
            swap: Some(|| swapped = Some(swap_sub(&sub, &moved, &source_side))),
        };
        run(
            &mut swapping,
            &[PathBuf::from(r"X:\src")],
            &held(&into),
            &Guard::new([disk]),
            &settings(false),
            &AtomicBool::new(false),
            &Progress::default(),
        );
        assert!(swapping.swap.is_none(), "the second pass never ran");
        if swapped == Some(true) {
            std::fs::remove_dir(&sub).unwrap();
        }
        assert_eq!(
            std::fs::read(source_side.join("b.bin")).unwrap(),
            b"customer data"
        );
        assert_eq!(std::fs::read_dir(&source_side).unwrap().count(), 1);
        std::fs::remove_dir_all(&into).unwrap();
        std::fs::remove_dir_all(&source_side).unwrap();
    }

    #[test]
    fn a_real_folder_is_copied_without_following_links() {
        let source = folder("realsrc");
        std::fs::create_dir_all(source.join("inner")).unwrap();
        std::fs::write(source.join("inner").join("one.txt"), b"hello rescue").unwrap();
        std::fs::write(source.join("two.bin"), vec![9u8; 70_000]).unwrap();
        // A junction back to the folder itself would loop forever if followed.
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(source.join("loop"))
            .arg(&source)
            .output()
            .unwrap();
        assert!(made.status.success());
        let into = folder("realdst");
        let mut volume = Volume::new(&source);
        let report = run(
            &mut volume,
            std::slice::from_ref(&source),
            &held(&into),
            &Guard::new([9999]),
            &Settings::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        );
        assert_eq!(report.outcome, Outcome::Finished);
        assert_eq!(report.copied(), 2);
        let name = source.file_name().unwrap();
        assert_eq!(
            std::fs::read(into.join(name).join("inner").join("one.txt")).unwrap(),
            b"hello rescue"
        );
        assert_eq!(
            std::fs::read(into.join(name).join("two.bin")).unwrap(),
            vec![9u8; 70_000]
        );
        assert!(!into.join(name).join("loop").exists());
        assert_eq!(report.skipped.len(), 1);
        std::fs::remove_dir(source.join("loop")).unwrap();
        std::fs::remove_dir_all(&source).unwrap();
        std::fs::remove_dir_all(&into).unwrap();
    }

    /// An output writer that takes `left` more bytes and then fails, as a full or failing
    /// destination does.
    struct FailingSink {
        file: File,
        left: u64,
    }

    impl Sink for FailingSink {
        fn write_at(&mut self, data: &[u8], pos: u64) -> std::io::Result<usize> {
            use std::os::windows::fs::FileExt;
            if self.left == 0 {
                return Err(std::io::Error::other("the destination is full"));
            }
            let n = (data.len() as u64).min(self.left) as usize;
            self.left -= n as u64;
            self.file.seek_write(&data[..n], pos)
        }
        fn flush_data(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Every file under `dir` but the log, as its path inside `dir`.
    fn files_in(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(folder) = stack.pop() {
            for entry in std::fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().unwrap() != "Rescue copy log.txt" {
                    found.push(path.strip_prefix(dir).unwrap().display().to_string());
                }
            }
        }
        found.sort();
        found
    }

    /// A log writer that takes `left` more bytes and then fails: every write after that
    /// too, as a full destination does, or, when `once`, only that one.
    struct CutLog {
        file: File,
        left: usize,
        once: bool,
        failed: bool,
    }

    impl Write for CutLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.failed {
                return if self.once {
                    self.file.write(buf)
                } else {
                    Err(std::io::Error::other("the destination is full"))
                };
            }
            if buf.len() <= self.left {
                self.left -= buf.len();
                return self.file.write(buf);
            }
            if self.left > 0 {
                let n = self.file.write(&buf[..self.left])?;
                self.left -= n;
                return Ok(n);
            }
            self.failed = true;
            Err(std::io::Error::other("the destination is full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    /// Copies a small tree into `dir` with the log written through `log_wrap`: src holds
    /// a.txt (good), sub/b.bin (2 KiB, a bad sector, so a second pass) and a link.
    fn copy_logged(dir: &Path, log_wrap: LogWrap<'_>) -> (Report, String) {
        let mut nodes = BTreeMap::new();
        nodes.insert(PathBuf::from(r"X:\src"), Node::Folder);
        let a = file(&content(3000, 1), None, None, None);
        nodes.insert(PathBuf::from(r"X:\src\a.txt"), a);
        nodes.insert(PathBuf::from(r"X:\src\sub"), Node::Folder);
        let b = file(&content(2048, 2), Some(512..1024), None, None);
        nodes.insert(PathBuf::from(r"X:\src\sub\b.bin"), b);
        nodes.insert(PathBuf::from(r"X:\src\link"), Node::Link);
        let mut tree = MemTree {
            nodes,
            log: Arc::new(Mutex::new(Vec::new())),
            flawed: Vec::new(),
        };
        let mut plain = |file: File| -> Box<dyn Sink> { Box::new(file) };
        let report = run_with(
            &mut tree,
            &[Job::folder(PathBuf::from(r"X:\src"), vec!["src".into()])],
            &held(dir),
            &Guard::new([9999]),
            &settings(false),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut plain,
            log_wrap,
        );
        let log = std::fs::read_to_string(&report.log).unwrap();
        (report, log)
    }

    /// The guard: a log cut at any byte, with every write after the cut failing or only the
    /// one across it, never has the last line unless it was written whole; the report says
    /// why, and a whole log ends with the summary and the last line.
    #[test]
    fn a_log_cut_at_any_byte_never_reads_as_complete_unless_whole() {
        for once in [false, true] {
            let mut whole = None;
            for cut in 0.. {
                let dir = folder(&format!("cutlog-{once}-{cut:05}"));
                let mut log_wrap = |file: File| -> Box<dyn Write + Send> {
                    Box::new(CutLog {
                        file,
                        left: cut,
                        once,
                        failed: false,
                    })
                };
                let (report, log) = copy_logged(&dir, &mut log_wrap);
                drop(report.ledger);
                std::fs::remove_dir_all(&dir).unwrap();
                let Some(why) = report.log_error else {
                    whole = Some((cut, log));
                    break;
                };
                assert_eq!(why, "the destination is full");
                assert!(
                    !log.ends_with(LOG_END) && !log.lines().any(|l| l == LOG_END),
                    "cut at byte {cut}, once {once}:\n{log}"
                );
            }
            let (cut, log) = whole.unwrap();
            assert!(cut > 500, "the log is {cut} bytes");
            assert!(
                log.ends_with(&format!("\r\nFinished. Copied 1 file (3.0 kB), 1 damaged, 0 incomplete, 1 skipped.\r\n{LOG_END}")),
                "{log}"
            );
        }
    }

    /// The guard: a failed summary write, with the write after it working, leaves no last
    /// line, and the report says the log could not be written.
    #[test]
    fn a_failed_summary_is_never_followed_by_the_last_line() {
        struct FailSummary(File);
        impl Write for FailSummary {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if buf.starts_with(b"Finished.") {
                    return Err(std::io::Error::other("the destination is full"));
                }
                self.0.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }
        let dir = folder("failsummary");
        let mut log_wrap = |file: File| -> Box<dyn Write + Send> { Box::new(FailSummary(file)) };
        let (report, log) = copy_logged(&dir, &mut log_wrap);
        assert!(!log.contains("Finished."), "{log}");
        assert!(
            !log.ends_with(LOG_END) && !log.lines().any(|l| l == LOG_END),
            "{log}"
        );
        assert_eq!(report.log_error.as_deref(), Some("the destination is full"));
        drop(report);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a row whose write fails once is written after the log says it is
    /// incomplete, so the log names every file in the destination, and none is unlisted.
    #[test]
    fn a_row_whose_write_failed_is_written_at_the_end() {
        struct FailRow {
            file: File,
            failed: bool,
        }
        impl Write for FailRow {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.failed && buf.starts_with(b"src\\a.txt\t") {
                    self.failed = true;
                    return Err(std::io::Error::other("the destination is busy"));
                }
                self.file.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.file.flush()
            }
        }
        let dir = folder("failrow");
        let mut log_wrap = |file: File| -> Box<dyn Write + Send> {
            Box::new(FailRow {
                file,
                failed: false,
            })
        };
        let (report, log) = copy_logged(&dir, &mut log_wrap);
        assert_eq!(report.log_error.as_deref(), Some("the destination is busy"));
        assert_eq!(report.unlisted, 0);
        let present = files_in(&dir);
        assert_eq!(present.len(), 2, "{present:?}");
        for file in &present {
            assert!(
                log.lines().any(|l| l.starts_with(&format!("{file}\t"))),
                "{file} has no row:\n{log}"
            );
        }
        assert!(
            log.ends_with("Files made whose rows could not be written above:\r\nsrc\\a.txt\t3000 bytes\tread in full\tX:\\src\\a.txt\r\n"),
            "{log}"
        );
        drop(report);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a copy leaves nothing in the destination but the files it made, each with
    /// a row in the log, and the log itself, however it ends.
    #[test]
    fn nothing_but_the_copied_files_and_the_log_is_left() {
        for (name, skip_damaged, dies_after) in [
            ("left-finished", false, None),
            ("left-skipped", true, None),
            ("left-gone", false, Some(2)),
        ] {
            let dir = folder(name);
            let (mut tree, _, _, _) = tree(dies_after);
            let report = copy(&mut tree, &dir, skip_damaged);
            let mut rows: Vec<String> = table(&report)
                .into_iter()
                .filter(|(_, _, condition)| !condition.starts_with("REMOVED"))
                .map(|(path, _, _)| path)
                .collect();
            rows.sort();
            let mut present = files_in(&dir);
            assert!(dir.join("Rescue copy log.txt").is_file());
            assert_eq!(present, rows, "{name}");
            present.push("Rescue copy log.txt".into());
            let all = std::fs::read_dir(&dir).unwrap().count();
            assert_eq!(all, 2, "{name}: the copy's folder and the log only");
            drop(report);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn every_file_left_by_a_failed_write_is_in_the_log() {
        // Writers are made in this order: a.txt, b.bin, c.bin, then b.bin and c.bin again.
        for (fails, left, rows) in [(2, 70_000, 2), (4, 0, 3)] {
            let dir = folder(&format!("failwrite-{fails}"));
            let (mut tree, _, _, _) = tree(None);
            let mut made = 0;
            let mut wrap = |file: File| -> Box<dyn Sink> {
                made += 1;
                if made == fails {
                    Box::new(FailingSink { file, left })
                } else {
                    Box::new(file)
                }
            };
            let report = run_with(
                &mut tree,
                &[Job::folder(PathBuf::from(r"X:\src"), vec!["src".into()])],
                &held(&dir),
                &Guard::new([9999]),
                &settings(false),
                &AtomicBool::new(false),
                &Progress::default(),
                &mut wrap,
                &mut |file: File| -> Box<dyn Write + Send> { Box::new(file) },
            );
            assert!(
                matches!(&report.outcome, Outcome::Failed(why) if why.contains("the destination is full")),
                "{:?}",
                report.outcome
            );
            let log = std::fs::read_to_string(&report.log).unwrap();
            let present = files_in(&dir);
            assert_eq!(present.len(), rows, "{present:?}");
            for file in &present {
                assert!(
                    log.contains(&format!("{file}\t")),
                    "{file} has no row:\n{log}"
                );
            }
            assert_eq!(table(&report).len(), rows);
            assert_eq!(report.copied(), 1, "{log}");
            assert_eq!(report.partial(), 1, "{log}");
            let b_row = log
                .lines()
                .find(|l| l.starts_with("src\\sub\\b.bin\t"))
                .unwrap();
            assert!(b_row.contains("PARTIAL: writing failed"), "{b_row}");
            assert!(log.contains("Copied 1 file ("), "{log}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
