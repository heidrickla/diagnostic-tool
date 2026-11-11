//! Copying found files to a destination folder: the destination is checked against the
//! source disk first, names are made safe and never overwrite anything, unreadable parts
//! are written as zeros with the file marked damaged, and a plain-text report of what was
//! recovered is written beside the files.
//!
//! Each file's row goes to a log in the folder as the file ends, so a run cut short leaves a
//! list of what it finished. A later run into the folder keeps a file an earlier one left
//! only when it is byte for byte what this run writes, where this run puts it, and finishes
//! one the log names as cut short. Files are read in order of their place on the source, and
//! made durable on the destination many at a time.
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::dest::Protected;
use super::dest::{Folder, Guard};
use super::fs::{Data, Found, Place, Progress, Run};
use super::ledger::{files, Ledger, Output};
use super::pace::Rate;
use super::reader::{Reader, CHUNK};
use super::writer::{self, Entry, Flusher, Made, Wrap};
use super::BlockSource;
use super::SourceChoice;

/// The damage a volume's own records show in a file, for its report row.
pub const FLAW: &str =
    "the volume's record of this file is damaged, so it may hold less than the file did";

/// The name a top-level `$RECYCLE.BIN` of the source is given in the destination, where
/// Windows would take it for the destination's own recycle bin and hide it.
pub const RECYCLE_BIN: &str = "Recycle Bin (from the drive)";

/// The top-level source folder Windows keeps for itself; a destination refuses its files.
pub const SYSTEM_FOLDER: &str = "System Volume Information";

/// The log in the destination that gets each file's row as the file ends.
pub const LOG_NAME: &str = "Recovery log.txt";

/// What a built-in preview's entry says of it, before where in the picture it was found.
pub const PREVIEW_NOTE: &str = "built-in preview of a damaged picture";

/// One file to recover, from a volume listing or a carving.
#[derive(Clone, Debug)]
pub struct Item {
    pub name: String,
    /// Folder names on the source, outermost first.
    pub folder: Vec<String>,
    pub size: u64,
    pub data: Data,
    /// The state shown in the list, for the report: "intact", "deleted, overwritten".
    pub state: String,
    /// Whether the file is deleted on the source.
    pub deleted: bool,
    /// What the volume's own records say is wrong with it; the file it is copied to ends
    /// damaged however much of it is read.
    pub flaw: Option<String>,
}

impl Item {
    pub fn from_found(f: &Found) -> Item {
        let mut state = f.state_text();
        if f.deleted {
            state = format!("deleted, {state}");
        }
        if let Some(note) = &f.note {
            state = format!("{state}; {note}");
        }
        Item {
            name: f.name.clone(),
            folder: f.folder.iter().map(|p| p.name.clone()).collect(),
            size: f.size,
            data: f.data.clone(),
            state,
            deleted: f.deleted,
            flaw: f.damaged.then(|| FLAW.to_string()),
        }
    }

    pub fn from_carved(c: &super::carve::Carved) -> Item {
        Item {
            name: c.name(),
            folder: Vec::new(),
            size: c.len,
            data: Data::Runs(vec![Run {
                place: Place::At(c.offset),
                len: c.len,
            }]),
            state: format!("found by type at byte {}", c.offset),
            deleted: false,
            flaw: None,
        }
    }

    /// Where its content starts on the source: the place of its first run that has one;
    /// None for content held in its record or in no place on the source.
    pub fn first_place(&self) -> Option<u64> {
        match &self.data {
            Data::Resident(_) => None,
            Data::Runs(runs) => runs.iter().find_map(|r| match r.place {
                Place::At(at) => Some(at),
                _ => None,
            }),
        }
    }

    /// Whether it lies under the source's top-level System Volume Information.
    pub fn is_system(&self) -> bool {
        self.folder
            .first()
            .is_some_and(|f| f.eq_ignore_ascii_case(SYSTEM_FOLDER))
    }

    /// What it is copied from, as its rows name it.
    fn source(&self) -> PathBuf {
        self.folder.iter().chain([&self.name]).collect()
    }
}

/// How recovered files are laid out in the destination.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Layout {
    /// The folders they were in on the source.
    #[default]
    Folders,
    /// One folder per kind of file: Pictures, Documents and so on.
    ByType,
}

/// How a recovery lays out and writes its files. The default is the layout by folders, with
/// deleted and damaged files among the rest.
#[derive(Clone, Debug, Default)]
pub struct RecoverOptions {
    pub layout: Layout,
    /// A folder of the destination that deleted files go under, laid out as the rest.
    pub deleted_folder: Option<String>,
    /// A folder of the destination that files ending damaged go under, laid out as the
    /// rest, with the built-in previews of damaged pictures; without one a damaged picture
    /// is named "(partial)" beside the whole files.
    pub damaged_folder: Option<String>,
    pub flush: FlushEvery,
}

/// How often files written are made durable on the destination: when the first of these is
/// reached since the last time, and at the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushEvery {
    pub time: Duration,
    pub bytes: u64,
    /// Files, which bounds the handles held until then.
    pub files: usize,
}

impl Default for FlushEvery {
    fn default() -> Self {
        Self {
            time: Duration::from_secs(2),
            bytes: 256 << 20,
            files: 1024,
        }
    }
}

/// A kind of file by its extension, for grouping and filtering.
pub fn group_of(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" | "jpe" | "jfif" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff"
        | "heic" | "heif" | "raw" | "cr2" | "cr3" | "nef" | "nrw" | "arw" | "dng" | "orf"
        | "raf" | "rw2" | "pef" | "srw" | "ico" | "svg" => "Pictures",
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp"
        | "rtf" | "txt" | "csv" | "md" | "epub" | "pages" | "numbers" | "key" | "one" => {
            "Documents"
        }
        "mp4" | "mov" | "avi" | "mkv" | "wmv" | "m4v" | "3gp" | "mpg" | "mpeg" | "webm" => "Video",
        "mp3" | "wav" | "m4a" | "flac" | "aac" | "ogg" | "wma" | "opus" => "Audio",
        "zip" | "7z" | "rar" | "gz" | "tar" | "bz2" | "xz" | "cab" | "iso" => "Archives",
        "sqlite" | "db" | "sqlite3" | "mdb" | "accdb" | "pst" | "ost" => "Databases",
        _ => "Other",
    }
}

/// A file name Windows accepts: no reserved characters or names, no trailing dot or space.
pub fn safe_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c < ' ' || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    while out.ends_with('.') || out.ends_with(' ') {
        out.pop();
    }
    if out.is_empty() {
        out = "unnamed".into();
    }
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        out.insert(0, '_');
    }
    // Keep within the usual 255-character limit, extension included.
    if out.chars().count() > 200 {
        let ext: String = out
            .rsplit_once('.')
            .map(|(_, e)| format!(".{}", e.chars().take(16).collect::<String>()))
            .unwrap_or_default();
        out = out
            .chars()
            .take(200 - ext.chars().count())
            .collect::<String>()
            + &ext;
    }
    out
}

/// Whether a file is a picture, by its extension: one whose damaged copy is named partial
/// and whose built-in preview is looked for.
pub fn is_picture(name: &str) -> bool {
    group_of(name) == "Pictures"
}

/// "IMG_0001 (partial).jpg" for "IMG_0001.jpg": a name that says, and sorts beside the
/// original, that parts of the picture are missing.
pub fn partial_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} (partial).{ext}"),
        _ => format!("{name} (partial)"),
    }
}

/// The folders, below the destination, an item is written in: the damaged folder when it
/// ended damaged and there is one, the deleted folder when it is deleted and there is one,
/// then its folders on the source or its kind.
fn folder_parts(item: &Item, options: &RecoverOptions, damaged: bool) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(folder) = options.damaged_folder.as_ref().filter(|_| damaged) {
        parts.push(safe_name(folder));
    }
    if let Some(folder) = options.deleted_folder.as_ref().filter(|_| item.deleted) {
        parts.push(safe_name(folder));
    }
    match options.layout {
        Layout::Folders => parts.extend(item.folder.iter().enumerate().map(|(i, f)| {
            if i == 0 && f.eq_ignore_ascii_case("$RECYCLE.BIN") {
                RECYCLE_BIN.to_string()
            } else {
                safe_name(f)
            }
        })),
        Layout::ByType => parts.push(group_of(&safe_name(&item.name)).to_string()),
    }
    parts
}

/// A picture recovered with parts missing: its output, by ledger entry number, and its
/// built-in preview.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Salvaged {
    pub output: usize,
    pub preview: Preview,
}

/// A damaged picture's built-in preview, as the recovery left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Preview {
    /// None was found whole in the parts read.
    None,
    /// Written beside it, by ledger entry number, and where in the picture it was found.
    Saved(usize, super::preview::Source),
    /// Found, and not written, for the reason given.
    NotSaved(super::preview::Source, String),
}

#[derive(Debug, Default)]
pub struct Outcome {
    /// Every file made, entered as it was made, each with how it ended; an output's tag is
    /// the position of its item in the items given to `recover`.
    pub ledger: Ledger,
    /// Items for which no file could be made, and why, in the order of the items.
    pub failed: Vec<(String, String)>,
    pub report: Option<PathBuf>,
    /// The report's own ledger entry, tagged `REPORT_TAG`, once it was made.
    pub report_entry: Option<usize>,
    /// Why the report could not be made or written to its end, if so.
    pub report_error: Option<String>,
    pub stopped: bool,
    /// Why the source stopped answering, if it did.
    pub gone: Option<String>,
    /// Pictures with missing parts, named "(partial)" or in the damaged folder, and their
    /// previews.
    pub pictures: Vec<Salvaged>,
    /// Files an earlier run into the folder left whole, kept as they were.
    pub kept: usize,
    /// Files an earlier run left cut short, finished from where it stopped.
    pub resumed: usize,
    /// Items under the source's System Volume Information, left out.
    pub left_out: usize,
    /// The folder files that ended damaged were put under, when one was asked for.
    pub damaged_folder: Option<PathBuf>,
    /// The log each file's row went to as it ended.
    pub log: Option<PathBuf>,
    /// Why the log could not be written to its end, if so.
    pub log_error: Option<String>,
}

impl Outcome {
    /// Files written in full with every part read, not counting built-in previews or the
    /// report.
    pub fn complete(&self) -> usize {
        self.ledger.complete() - self.previews() - self.report_is(Output::complete)
    }

    /// 1 when the report's entry is as `state` asks, else 0.
    fn report_is(&self, state: fn(&Output) -> bool) -> usize {
        self.report_entry
            .is_some_and(|id| state(&self.ledger.outputs()[id]))
            .into()
    }

    /// Built-in previews written in full, or kept from an earlier run.
    pub fn previews(&self) -> usize {
        self.ledger
            .outputs()
            .iter()
            .filter(|o| o.complete() && o.note.starts_with(PREVIEW_NOTE))
            .count()
    }

    /// Where the pictures with missing parts were put, worded for the report and the window.
    pub fn pictures_placed(&self) -> String {
        match &self.damaged_folder {
            Some(folder) => format!("under {}", folder.display()),
            None => "named \"(partial)\"".to_string(),
        }
    }

    /// Pictures with missing parts that could not be moved or renamed so; each one's row
    /// says where it is.
    pub fn pictures_stayed(&self) -> usize {
        self.pictures
            .iter()
            .filter(|p| self.ledger.outputs()[p.output].remark.is_some())
            .count()
    }

    /// Files written in full with zeros where the source could not be read.
    pub fn damaged(&self) -> usize {
        self.ledger.damaged()
    }

    /// Files that hold less than their size: stopped, or a write failed; not the report.
    pub fn partial(&self) -> usize {
        self.ledger.incomplete() - self.report_is(Output::partial)
    }
}

pub use super::writer::{write_report_file, ReportFile, REPORT_TAG};

/// The disks the destination check guards: the failing disk itself; for an image, the
/// drive its map says it was made from, wherever it is connected now (an image file is in
/// use, which new files cannot overwrite, so output may share its own drive). A volume's
/// disk is the one its own extents name, whatever number came with it; opening it refuses
/// a number that disagrees (`disk::volume_disk`).
/// An image that cannot be opened, or whose map cannot be read, protects by refusing every
/// output: what it was made from is not known.
pub fn source_disk(choice: &SourceChoice) -> Protected {
    match choice {
        SourceChoice::Disk(n) => drive_of(*n),
        SourceChoice::Image(path) => match super::ImageFile::open(path) {
            Ok(image) => image.protected(),
            Err(e) => Protected::unknown(format!(
                "the drive {} was made from is not known ({e})",
                path.display()
            )),
        },
        SourceChoice::Volume { path, disk, .. } => {
            match crate::tools::drives::device::disks_of_volume(path).as_deref() {
                Ok([on, ..]) => drive_of(*on),
                _ => drive_of(*disk),
            }
        }
    }
}

/// Disk `number` by its number and, when it can be read now, its identity, so it is still
/// refused after a replug under another number.
fn drive_of(number: u32) -> Protected {
    let drives = super::target::identity_of(number)
        .map(|d| {
            let id = super::SourceId {
                model: d.model,
                serial: d.serial,
                size: d.size,
                drive: d.drive,
                sector: Some(d.sector),
                scope: Some(super::Scope::Disk),
                disk_size: Some(d.size),
            };
            super::dest::Guarded::new(id, Some(d.disk_id))
        })
        .into_iter()
        .collect();
    Protected {
        drives,
        ..Protected::disk(number)
    }
}

/// Copies `items` into `dest`, laid out as `options` say. Refuses before reading or writing
/// anything when `dest` is on `source_disk`. Items under the source's System Volume
/// Information are left out; the rest are read in order of their place on the source.
pub fn recover(
    reader: &mut Reader,
    items: &[Item],
    dest: &Path,
    options: &RecoverOptions,
    source_disk: &Protected,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Result<Outcome, String> {
    let mut plain = writer::plain;
    let mut plain_log = |file: File| -> Box<dyn Write + Send> { Box::new(file) };
    let hooks = Hooks {
        wrap: &mut plain,
        log: &mut plain_log,
        flusher: None,
    };
    recover_with(
        reader,
        items,
        dest,
        options,
        source_disk,
        cancel,
        progress,
        hooks,
    )
}

/// Where a recovery's writes and flushes go, so tests can fail or count them.
struct Hooks<'a> {
    /// Every output file's writes.
    wrap: &'a mut Wrap<'a>,
    /// The log's writes.
    log: &'a mut dyn FnMut(File) -> Box<dyn Write + Send>,
    /// The flushes; None for the destination's own (`writer::ToDisk`).
    flusher: Option<&'a mut dyn Flusher>,
}

/// `recover`, with its writes and flushes going through `hooks`.
#[allow(clippy::too_many_arguments)]
fn recover_with(
    reader: &mut Reader,
    items: &[Item],
    dest: &Path,
    options: &RecoverOptions,
    source_disk: &Protected,
    cancel: &AtomicBool,
    progress: &Progress,
    hooks: Hooks<'_>,
) -> Result<Outcome, String> {
    // What the source being read says, with what the caller gave: a protection worked out from
    // another open of the source cannot stand for this one.
    let guard = Guard::of(&source_disk.clone().join(reader.protected()));
    guard.check_folder(dest)?;
    // Held for the whole recovery: everything is made through it, never by path.
    let base = guard
        .base(dest)
        .map_err(|e| format!("{} could not be opened: {e}", dest.display()))?;
    let mut to_disk;
    let flusher: &mut dyn Flusher = match hooks.flusher {
        Some(flusher) => flusher,
        None => {
            to_disk = writer::ToDisk::new(&base);
            &mut to_disk
        }
    };
    let log_path = dest.join(LOG_NAME);
    let (log, held) = writer::open_log(&guard, &base, OsStr::new(LOG_NAME))
        .map_err(|e| format!("{} could not be made: {e}", log_path.display()))?;
    let mut outcome = Outcome {
        ledger: Ledger::kept_with_log((hooks.log)(log), dest.to_path_buf()),
        log: Some(log_path),
        damaged_folder: options
            .damaged_folder
            .as_ref()
            .map(|f| dest.join(safe_name(f))),
        ..Outcome::default()
    };
    start_log(&mut outcome.ledger, &held, dest, options);
    let (left_out, mut order): (Vec<usize>, Vec<usize>) =
        (0..items.len()).partition(|&i| items[i].is_system());
    outcome.left_out = left_out.len();
    // By place on the source, so its reads run forwards; content with no place first.
    order.sort_by_key(|&i| items[i].first_place());
    let total = order
        .iter()
        .fold(0u64, |t, &i| t.saturating_add(items[i].size));
    progress.set(0, total);
    progress
        .pace
        .files_total
        .store(order.len() as u64, Ordering::Relaxed);
    let mut run = Recovery {
        guard: &guard,
        base: &base,
        options,
        reader,
        cancel,
        progress,
        wrap: hooks.wrap,
        batch: Batch {
            every: options.flush,
            flusher,
            pending: Vec::new(),
            bytes: 0,
            since: Instant::now(),
        },
        earlier: Earlier::read(&held),
        claimed: HashSet::new(),
        done: 0,
    };
    let mut rate = Rate::default();
    let mut last = Instant::now();
    let mut failed = Vec::new();
    for (n, &index) in order.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            outcome.stopped = true;
            break;
        }
        if let Some(why) = run.reader.gone() {
            outcome.gone = Some(why.to_string());
            break;
        }
        let item = &items[index];
        match run.item(index, item, &mut outcome) {
            Ok(Ended::Stopped) => {
                outcome.stopped = true;
                break;
            }
            Ok(Ended::Kept) => {}
            Ok(Ended::Written(bytes)) => rate.file(last.elapsed().as_secs_f64(), bytes),
            Err(why) => failed.push((index, item.name.clone(), why)),
        }
        last = Instant::now();
        run.done = run.done.saturating_add(item.size);
        progress.set(run.done, total);
        progress
            .found
            .store(outcome.ledger.outputs().len() as u64, Ordering::Relaxed);
        progress
            .pace
            .files_done
            .store(n as u64 + 1, Ordering::Relaxed);
        progress.pace.set(
            &rate,
            (order.len() - n - 1) as u64,
            total.saturating_sub(run.done),
        );
        if run.batch.due() {
            run.batch.flush(&mut outcome.ledger);
        }
    }
    run.batch.flush(&mut outcome.ledger);
    failed.sort_by_key(|(index, _, _)| *index);
    outcome.failed = failed
        .into_iter()
        .map(|(_, name, why)| (name, why))
        .collect();
    if outcome.gone.is_none() {
        outcome.gone = run.reader.gone().map(str::to_string);
    }
    outcome
        .ledger
        .close("the recovery ended before it was finished");
    // The log's last line says every row of the run is in it.
    outcome.ledger.line("");
    if outcome.ledger.log_error().is_none() {
        outcome.ledger.last_line(super::copy::LOG_END);
    }
    outcome.log_error = outcome.ledger.close_log();
    let source = run.reader.describe();
    // Rendered first, from the ledger as the run left it; then entered and written.
    let mut text = Vec::new();
    write_report(&mut text, &source, dest, &outcome)
        .map_err(|e| format!("the report could not be put together: {e}"))?;
    let made = write_report_file(
        &guard,
        &base,
        "Recovery report.txt",
        &text,
        &mut outcome.ledger,
        &mut *run.wrap,
        &mut *run.batch.flusher,
    );
    outcome.report = made.path;
    outcome.report_entry = made.entry;
    outcome.report_error = made.error;
    Ok(outcome)
}

/// Writes the log's opening lines for this run, after what an earlier run into the folder
/// left in it, `held`.
fn start_log(ledger: &mut Ledger, held: &[u8], dest: &Path, options: &RecoverOptions) {
    if !held.is_empty() {
        // An earlier run cut short may have stopped part way through a line.
        if !held.ends_with(b"\n") {
            ledger.line("");
        }
        ledger.line("");
    }
    ledger.line("Recovery log by Diagnostic Tool");
    // The last line is named without its full stop: a log cut just after a quote of it
    // must not end with it.
    ledger.line(&format!(
        "This run's part of the log is complete only if the log's last line reads \"{}\" with a full stop.",
        super::copy::LOG_END.trim_end_matches('.')
    ));
    ledger.line(
        "Each file has a row as it ends: its path in this folder, its size, what the source said of it, its condition and the file it was copied from, separated by tabs. A file is entered whole only once it is on the destination's disk.",
    );
    ledger.line(&format!(
        "Started: {}",
        crate::clock::local(std::time::SystemTime::now()).long()
    ));
    ledger.line(&format!("Into: {}", dest.display()));
    if let Some(folder) = &options.deleted_folder {
        ledger.line(&format!("Deleted files: under {}", safe_name(folder)));
    }
    if let Some(folder) = &options.damaged_folder {
        ledger.line(&format!("Damaged files: under {}", safe_name(folder)));
    }
    ledger.line("");
}

/// How an item's copy ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// Written, in full or ended by a failed write, with the bytes written this run; the
    /// ledger says which.
    Written(u64),
    /// Already there whole from an earlier run.
    Kept,
    /// Stop cut it short.
    Stopped,
}

/// An item's file as `Recovery::open` made or took it.
struct Opened {
    made: Made,
    /// The folder it is in.
    folder: Folder,
    /// The length of the file an earlier run left, when that was taken.
    earlier: Option<u64>,
    /// The parts of what it held that the source could not be read now.
    zeroed: Vec<Range<u64>>,
    /// Already where this run moves or renames a damaged file to, so neither is done again.
    placed: bool,
}

/// A recovery under way: what every item's copy needs.
struct Recovery<'a, 'r> {
    guard: &'a Guard,
    base: &'a Folder,
    options: &'a RecoverOptions,
    reader: &'a mut Reader<'r>,
    cancel: &'a AtomicBool,
    progress: &'a Progress,
    wrap: &'a mut Wrap<'a>,
    batch: Batch<'a>,
    earlier: Earlier,
    /// The paths this run has given a file, by `claim_key`.
    claimed: HashSet<String>,
    /// The bytes of the items done before this one.
    done: u64,
}

/// A path as the destination tells names apart: without regard to case.
fn claim_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

impl Recovery<'_, '_> {
    /// Copies one item, keeps an earlier run's whole copy of it, or finishes an earlier
    /// run's copy cut short. Err when no file could be made.
    fn item(&mut self, index: usize, item: &Item, outcome: &mut Outcome) -> Result<Ended, String> {
        // Entered as it is made, before a byte is written, so however the copy ends it is
        // listed.
        let entry = Entry {
            tag: index,
            source: item.source(),
            note: item.state.clone(),
            size: item.size,
        };
        let Some(Opened {
            made,
            folder,
            earlier,
            zeroed,
            placed,
        }) = self.open(item, entry, &mut outcome.ledger)?
        else {
            return Ok(Ended::Stopped);
        };
        let from = earlier.unwrap_or(0);
        let id = made.id;
        self.claimed.insert(claim_key(&made.path));
        if let Some(flaw) = &item.flaw {
            outcome.ledger.flawed(id, flaw.clone());
        }
        // Written through its own handle, the one moved, read back and flushed below.
        let ended = copy(
            self.reader,
            item,
            from,
            (self.wrap)(&made.file),
            &mut outcome.ledger,
            id,
            zeroed,
            self.cancel,
            self.progress,
            self.done,
        );
        match ended {
            Copied::Whole => {}
            Copied::Failed => return Ok(Ended::Written(item.size - from)),
            Copied::Stopped => return Ok(Ended::Stopped),
        }
        let whole_before = earlier == Some(item.size);
        if whole_before {
            outcome.kept += 1;
        } else if earlier.is_some() {
            outcome.resumed += 1;
        }
        let o = outcome.ledger.get(id);
        let damaged = !o.zeroed.is_empty() || o.flaw.is_some();
        let mut folder = folder;
        if !placed && damaged && self.options.damaged_folder.is_some() {
            folder = self.move_damaged(item, &made.file, id, folder, &mut outcome.ledger);
        }
        if is_picture(&item.name) {
            self.salvage(&folder, &made.file, item, index, id, !placed, outcome);
        }
        self.batch.add(id, made.file, item.size - from);
        Ok(if whole_before {
            Ended::Kept
        } else {
            Ended::Written(item.size - from)
        })
    }

    /// Makes `item`'s file, or takes one an earlier run left that is what this copy writes
    /// now, at a place this run puts it (`placed`): first a whole or cut short copy the
    /// earlier run's log names, then a whole file under its name in its folder, or the first
    /// of "name (2)" and so on not taken, made new when none is there. A file the log does not
    /// name is never written on: holding only the start of the item, it may be anyone's. None
    /// when Stop came while an earlier file was compared.
    fn open(
        &mut self,
        item: &Item,
        entry: Entry,
        ledger: &mut Ledger,
    ) -> Result<Option<Opened>, String> {
        let source = entry.source.display().to_string();
        for row in self.earlier.rows(&source, item.size) {
            let path = self.base.path().join(&row.path);
            // Read only where some ending of the copy would put it.
            if self.claimed.contains(&claim_key(&path))
                || placed(item, self.options, &row.path, true).is_none()
            {
                continue;
            }
            let Ok((folder, name)) = self.reach(&row.path) else {
                continue;
            };
            match self.compare(&folder, &name, item, row.whole) {
                Compared::Same(file, len, zeroed) => {
                    // A file cut short is where it was made: its damage is known at its end.
                    let unread = len == item.size && !zeroed.is_empty();
                    let Some(placed) = placed(item, self.options, &row.path, unread) else {
                        continue;
                    };
                    return Ok(Some(Opened {
                        made: writer::take_earlier(file, path, ledger, entry),
                        folder,
                        earlier: Some(len),
                        zeroed,
                        placed,
                    }));
                }
                Compared::Stopped => return Ok(None),
                Compared::Differs => {}
            }
        }
        let folder = self
            .guard
            .folders(self.base, folder_parts(item, self.options, false))
            .map_err(|e| e.to_string())?;
        for candidate in names_for(&safe_name(&item.name), false) {
            let path = folder.path().join(&candidate);
            if self.claimed.contains(&claim_key(&path)) {
                continue;
            }
            let name = OsStr::new(&candidate);
            match writer::create_exact(self.guard, &folder, name, ledger, entry.clone()) {
                Ok(made) => {
                    return Ok(Some(Opened {
                        made,
                        folder,
                        earlier: None,
                        zeroed: Vec::new(),
                        placed: false,
                    }))
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.to_string()),
            }
            match self.compare(&folder, name, item, true) {
                Compared::Same(file, len, zeroed) => {
                    return Ok(Some(Opened {
                        made: writer::take_earlier(file, path, ledger, entry),
                        folder,
                        earlier: Some(len),
                        zeroed,
                        placed: false,
                    }))
                }
                Compared::Stopped => return Ok(None),
                Compared::Differs => {}
            }
        }
        Err("too many files with this name".into())
    }

    /// The folder and name of `path`, a path below the destination, reached one folder at a
    /// time through the held handles, making nothing and following no link.
    fn reach(&self, path: &Path) -> std::io::Result<(Folder, OsString)> {
        let mut parts: Vec<&OsStr> = path.components().map(|c| c.as_os_str()).collect();
        let name = parts
            .pop()
            .ok_or_else(|| std::io::Error::other("no name"))?;
        let mut folder = self.base.try_clone()?;
        for part in parts {
            folder = self.guard.existing_folder(&folder, part)?;
        }
        Ok((folder, name.to_os_string()))
    }

    /// Checks the file `name` in `folder` an earlier run left against what `item`'s copy
    /// writes now: exactly the item's size when `whole`, else no longer, and the same at
    /// every byte, zeros where the source cannot be read now. The same file comes back with
    /// its length and the parts of it this run could not read.
    fn compare(&mut self, folder: &Folder, name: &OsStr, item: &Item, whole: bool) -> Compared {
        let Ok(file) = writer::open_earlier(self.guard, folder, name) else {
            return Compared::Differs;
        };
        let len = file.metadata().map_or(u64::MAX, |m| m.len());
        if len > item.size || (whole && len != item.size) {
            return Compared::Differs;
        }
        let mut zeroed = Vec::new();
        let mut same = Same {
            file: &file,
            held: Vec::new(),
        };
        let compared = fill(
            self.reader,
            item,
            0..len,
            &mut same,
            &mut zeroed,
            self.cancel,
            self.progress,
            self.done,
        );
        match compared {
            Ok(None) => Compared::Same(file, len, zeroed),
            Ok(Some(_)) => Compared::Stopped,
            Err(_) => Compared::Differs,
        }
    }

    /// Moves a file that ended damaged into the damaged folder, under the folders it was in;
    /// returns the folder it is in now. One that cannot be moved stays where it is, and its
    /// entry says so and why.
    fn move_damaged(
        &mut self,
        item: &Item,
        file: &File,
        id: usize,
        folder: Folder,
        ledger: &mut Ledger,
    ) -> Folder {
        let moved = self
            .guard
            .folders(self.base, folder_parts(item, self.options, true))
            .map_err(|e| e.to_string())
            .and_then(|target| {
                self.rename(file, &target, &safe_name(&item.name), false, id, ledger)?;
                Ok(target)
            });
        match moved {
            Ok(target) => target,
            Err(why) => {
                let damaged = self
                    .options
                    .damaged_folder
                    .as_deref()
                    .map(safe_name)
                    .unwrap_or_default();
                ledger.remark(
                    id,
                    format!("it could not be moved under {damaged}, so it is here: {why}"),
                );
                folder
            }
        }
    }

    /// Renames `file`, entry `id`, by its handle into `folder` as the first of
    /// `names_for(base, partial)` not taken; why not, if it was not.
    fn rename(
        &mut self,
        file: &File,
        folder: &Folder,
        base: &str,
        partial: bool,
        id: usize,
        ledger: &mut Ledger,
    ) -> Result<(), String> {
        for candidate in names_for(base, partial) {
            let path = folder.path().join(&candidate);
            if self.claimed.contains(&claim_key(&path)) {
                continue;
            }
            match super::dest::rename_new(file, folder, OsStr::new(&candidate)) {
                Ok(()) => {
                    self.claimed.remove(&claim_key(&ledger.get(id).path));
                    self.claimed.insert(claim_key(&path));
                    ledger.moved(id, path);
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("too many files with this name".into())
    }

    /// For a picture written in full with parts missing: writes its built-in preview beside
    /// it, entered in the ledger, and, when `rename` is set and there is no damaged folder,
    /// renames it "(partial)" so it sorts as such. The preview is read back from the file
    /// just written, never from the source again, and only from parts that were read.
    #[allow(clippy::too_many_arguments)]
    fn salvage(
        &mut self,
        folder: &Folder,
        file: &File,
        item: &Item,
        tag: usize,
        id: usize,
        rename: bool,
        outcome: &mut Outcome,
    ) {
        let o = outcome.ledger.get(id);
        if o.zeroed.is_empty() || o.size == 0 {
            return;
        }
        let (size, source) = (o.size, o.source.clone());
        let unreadable = o.zeroed.clone();
        let name = o
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut picture = super::preview::FileBytes {
            file,
            len: size,
            unreadable: &unreadable,
        };
        let mut preview = Preview::None;
        let mut budget = crate::budget::Budget::new(super::preview::LIMITS, None);
        if let Some((found, bytes)) = super::preview::best(&mut picture, &mut budget) {
            let entry = Entry {
                tag,
                source,
                note: format!("{PREVIEW_NOTE} ({})", found.source.label()),
                size: bytes.len() as u64,
            };
            let preview_name = super::preview::preview_name(&name);
            preview =
                match self.write_preview(folder, &preview_name, &bytes, entry, &mut outcome.ledger)
                {
                    Ok(made) => Preview::Saved(made, found.source),
                    Err(why) => Preview::NotSaved(found.source, why),
                };
        }
        if rename && self.options.damaged_folder.is_none() {
            let base = safe_name(&item.name);
            let partial = partial_name(&base);
            if let Err(why) = self.rename(file, folder, &base, true, id, &mut outcome.ledger) {
                outcome.ledger.remark(
                    id,
                    format!("it could not be renamed \"{partial}\", so it is here: {why}"),
                );
            }
        }
        outcome.pictures.push(Salvaged {
            output: id,
            preview,
        });
    }

    /// Writes a built-in preview `bytes` into `folder` as `name`, or the first of "name (2)"
    /// and so on not taken; one an earlier run left there with the same bytes is taken as it
    /// is. Returns its entry, or why it could not be written.
    fn write_preview(
        &mut self,
        folder: &Folder,
        name: &str,
        bytes: &[u8],
        entry: Entry,
        ledger: &mut Ledger,
    ) -> Result<usize, String> {
        for candidate in writer::names(name) {
            let path = folder.path().join(&candidate);
            if self.claimed.contains(&claim_key(&path)) {
                continue;
            }
            let name = OsStr::new(&candidate);
            let mut made =
                match writer::create_exact(self.guard, folder, name, ledger, entry.clone()) {
                    Ok(made) => made,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let Ok(mut file) = writer::open_earlier(self.guard, folder, name) else {
                            continue;
                        };
                        let mut held = Vec::new();
                        if file.read_to_end(&mut held).is_err() || held != bytes {
                            continue;
                        }
                        let made = writer::take_earlier(file, path, ledger, entry);
                        ledger.wrote(made.id, held.len() as u64);
                        self.claimed.insert(claim_key(&made.path));
                        self.batch.add(made.id, made.file, 0);
                        return Ok(made.id);
                    }
                    Err(e) => return Err(format!("it could not be made: {e}")),
                };
            self.claimed.insert(claim_key(&made.path));
            return match writer::write_pending(&mut made, bytes, ledger) {
                Ok(()) => {
                    let id = made.id;
                    self.batch.add(id, made.file, bytes.len() as u64);
                    Ok(id)
                }
                Err(why) => {
                    writer::discard(made, ledger, &why);
                    Err(why)
                }
            };
        }
        Err("too many files with this name".into())
    }
}

/// What `Recovery::compare` found of a file an earlier run left.
enum Compared {
    /// It holds nothing the copy will not: its handle, its length and the parts of it that
    /// are zeros for want of a read.
    Same(File, u64, Vec<Range<u64>>),
    Differs,
    /// Stop came while it was compared.
    Stopped,
}

/// Where an earlier run into the destination put each whole or cut short file, from its log,
/// by the file each was copied from: only where to look, since what a file holds now and
/// where it is decide whether it is taken.
#[derive(Debug, Default)]
struct Earlier {
    rows: HashMap<String, Vec<Logged>>,
}

/// A file an earlier run's log names.
#[derive(Clone, Debug)]
struct Logged {
    /// Its path below the destination.
    path: PathBuf,
    size: u64,
    /// Whether it ended whole; else it was cut short.
    whole: bool,
}

impl Earlier {
    /// From the log's text, `held`; rows that name a path outside the folder, and those of
    /// built-in previews, which are made again from their pictures, are left out.
    fn read(held: &[u8]) -> Self {
        let mut rows: HashMap<String, Vec<Logged>> = HashMap::new();
        for row in super::ledger::logged_rows(&String::from_utf8_lossy(held)) {
            if row.note.starts_with(PREVIEW_NOTE)
                || !row
                    .path
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
            {
                continue;
            }
            rows.entry(row.source).or_default().push(Logged {
                path: row.path,
                size: row.size,
                whole: row.whole,
            });
        }
        Self { rows }
    }

    /// The rows of copies made from `source`, `size` bytes long, the latest first.
    fn rows(&self, source: &str, size: u64) -> Vec<Logged> {
        self.rows.get(source).map_or_else(Vec::new, |rows| {
            rows.iter()
                .rev()
                .filter(|r| r.size == size)
                .cloned()
                .collect()
        })
    }
}

/// The names this run gives an item's file whose safe name is `base`: `base`, then
/// "name (2)" and so on, each with " (partial)" before its extension when `partial`.
fn names_for(base: &str, partial: bool) -> impl Iterator<Item = String> + '_ {
    writer::names(base).map(move |name| if partial { partial_name(&name) } else { name })
}

/// Whether `name` is one of `names_for(base, partial)`, without regard to case: the stem,
/// then " (n)" for n from 2, then " (partial)" when `partial`, then the extension.
fn is_named(name: &str, base: &str, partial: bool) -> bool {
    let (name, base) = (name.to_lowercase(), base.to_lowercase());
    // Split as `writer::names` splits.
    let stem = match base.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => base.as_str(),
    };
    let ext = &base[stem.len()..];
    let Some(middle) = name
        .strip_prefix(stem)
        .and_then(|rest| rest.strip_suffix(ext))
    else {
        return false;
    };
    let middle = match (partial, middle.strip_suffix(" (partial)")) {
        (false, _) => middle,
        (true, Some(middle)) => middle,
        (true, None) => return false,
    };
    middle.is_empty()
        || middle
            .strip_prefix(" (")
            .and_then(|n| n.strip_suffix(')'))
            .and_then(|n| n.parse::<u32>().ok().filter(|v| v.to_string() == n))
            .is_some_and(|n| (2..10_000).contains(&n))
}

/// What `path`, below the destination, is to `item`'s copy in this run, when the copy holds
/// whole with parts `unread`: Some(false) where its file is made, to be moved or renamed as
/// a new one is; Some(true) where a damaged file is moved or renamed to; None elsewhere.
fn placed(item: &Item, options: &RecoverOptions, path: &Path, unread: bool) -> Option<bool> {
    let name = path.file_name()?.to_string_lossy();
    let folder: Vec<String> = path
        .parent()?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    let base = safe_name(&item.name);
    let at = |moved: bool, partial: bool| {
        folder_parts(item, options, moved)
            .iter()
            .map(|p| p.to_lowercase())
            .eq(folder.iter().cloned())
            && is_named(&name, &base, partial)
    };
    let moved = options.damaged_folder.is_some() && (unread || item.flaw.is_some());
    let partial = options.damaged_folder.is_none() && unread && is_picture(&item.name);
    if at(false, false) {
        Some(false)
    } else if (moved || partial) && at(moved, partial) {
        Some(true)
    } else {
        None
    }
}

/// Where `fill` puts an item's bytes, in order: every byte of the span, zeros where the
/// source could not be read.
trait Sink {
    fn put(&mut self, data: &[u8]) -> std::io::Result<()>;
}

/// Takes what a copy would write and checks it against a file an earlier run left, read in
/// step: the same at every byte, zeros where the source cannot be read now included.
struct Same<'a> {
    file: &'a File,
    held: Vec<u8>,
}

impl Sink for Same<'_> {
    fn put(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.held.resize(data.len(), 0);
        let mut file = self.file;
        file.read_exact(&mut self.held)?;
        if data != self.held {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the earlier file differs from this one",
            ));
        }
        Ok(())
    }
}

/// Files written since the last flush, made durable together.
struct Batch<'a> {
    every: FlushEvery,
    flusher: &'a mut dyn Flusher,
    /// Their entries, still open, each with the handle it was written through.
    pending: Vec<(usize, File)>,
    bytes: u64,
    since: Instant,
}

impl Batch<'_> {
    fn add(&mut self, id: usize, file: File, bytes: u64) {
        self.pending.push((id, file));
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn due(&self) -> bool {
        !self.pending.is_empty()
            && (self.bytes >= self.every.bytes
                || self.pending.len() >= self.every.files
                || self.since.elapsed() >= self.every.time)
    }

    /// Makes every file written since the last flush durable, then ends each entry: a
    /// ledger, and so the log, never says whole for bytes a crash could still take, nor for
    /// a file that holds less than its size (`writer::end_flushed`).
    fn flush(&mut self, ledger: &mut Ledger) {
        if self.pending.is_empty() {
            return;
        }
        let paths: Vec<PathBuf> = self
            .pending
            .iter()
            .map(|(id, _)| ledger.get(*id).path.clone())
            .collect();
        let files: Vec<(&Path, &File)> = paths
            .iter()
            .zip(&self.pending)
            .map(|(path, (_, file))| (path.as_path(), file))
            .collect();
        let flushed = self.flusher.flush(&files);
        for (id, _) in self.pending.drain(..) {
            writer::end_flushed(ledger, id, &flushed);
        }
        self.bytes = 0;
        self.since = Instant::now();
    }
}

/// How `copy` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Copied {
    /// Written to its size; entered whole once a flush covers it.
    Whole,
    /// A write failed; entered partial.
    Failed,
    /// Stop cut it short; entered partial.
    Stopped,
}

/// Writes one item into `out` from byte `from`, an earlier run's copy having the bytes before
/// it with `zeroed` the parts of them the source could not be read; enters what the file
/// holds and, when it ends short, partial where Stop or a failed write cut it.
#[allow(clippy::too_many_arguments)]
fn copy(
    reader: &mut Reader,
    item: &Item,
    from: u64,
    mut out: Box<dyn Write + '_>,
    ledger: &mut Ledger,
    id: usize,
    mut zeroed: Vec<Range<u64>>,
    cancel: &AtomicBool,
    progress: &Progress,
    base: u64,
) -> Copied {
    let mut counted = Counted {
        inner: &mut out,
        bytes: 0,
    };
    let result = fill(
        reader,
        item,
        from..item.size,
        &mut counted,
        &mut zeroed,
        cancel,
        progress,
        base,
    )
    .and_then(|ended| counted.flush().map(|()| ended));
    // What the file holds is what its writer took, however the copy ended.
    let at = from + counted.bytes;
    ledger.wrote(id, at);
    ledger.zeroed(id, zeroed);
    match result {
        Ok(None) => Copied::Whole,
        Ok(Some(_)) => {
            ledger.partial(id, "the recovery was stopped; the rest was not copied");
            Copied::Stopped
        }
        Err(e) => {
            ledger.partial(id, format!("writing failed after {at} bytes: {e}"));
            Copied::Failed
        }
    }
}

/// A writer that counts the bytes its inner writer took.
struct Counted<'a> {
    inner: &'a mut dyn Write,
    bytes: u64,
}

impl Write for Counted<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Sink for Counted<'_> {
    fn put(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.write_all(data)
    }
}

/// The bytes of `span` of `item`, put into `out` in order: the source is read for those
/// alone, and every byte of the span is put, as zeros where nothing can be read. Returns
/// where Stop cut it short, if it did.
#[allow(clippy::too_many_arguments)]
fn fill(
    reader: &mut Reader,
    item: &Item,
    span: Range<u64>,
    out: &mut dyn Sink,
    zeroed: &mut Vec<Range<u64>>,
    cancel: &AtomicBool,
    progress: &Progress,
    base: u64,
) -> std::io::Result<Option<u64>> {
    let zeros = vec![0u8; CHUNK as usize];
    // How far the item's data reaches; nothing is known of it past there.
    let reached = match &item.data {
        Data::Resident(bytes) => {
            let held = (bytes.len() as u64).min(item.size);
            let piece = span.start.min(held)..span.end.min(held);
            out.put(&bytes[piece.start as usize..piece.end as usize])?;
            held
        }
        Data::Runs(runs) => {
            let mut pos = 0u64;
            for run in runs {
                if pos >= span.end {
                    break;
                }
                let len = run.len.min(item.size - pos);
                let mut at = span.start.max(pos);
                let end = span.end.min(pos + len);
                while at < end {
                    if cancel.load(Ordering::Relaxed) {
                        return Ok(Some(at));
                    }
                    let n = CHUNK.min(end - at);
                    // A run placed past where any source can reach, as only a damaged
                    // record gives, is read nowhere: it is unreadable.
                    let place = match run.place {
                        Place::At(place) => place
                            .checked_add(at - pos)
                            .filter(|from| from.checked_add(n).is_some())
                            .map_or(Place::Missing, Place::At),
                        other => other,
                    };
                    match place {
                        Place::At(from) => {
                            let lossy = reader.read_lossy(from, n as usize);
                            zeroed.extend(
                                lossy
                                    .unreadable
                                    .iter()
                                    .map(|r| at + r.start as u64..at + r.end as u64),
                            );
                            out.put(&lossy.data)?;
                        }
                        Place::Zeros => out.put(&zeros[..n as usize])?,
                        Place::Missing => {
                            zeroed.push(at..at + n);
                            out.put(&zeros[..n as usize])?;
                        }
                    }
                    at += n;
                    progress.done.store(base + at, Ordering::Relaxed);
                }
                pos += len;
            }
            pos
        }
    };
    // Data that ends short of the size leaves the rest unknown: zeros, entered unreadable.
    let mut at = span.start.max(reached);
    if at < span.end {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Some(at));
        }
        zeroed.push(at..span.end);
        while at < span.end {
            let n = (span.end - at).min(CHUNK);
            out.put(&zeros[..n as usize])?;
            at += n;
        }
    }
    Ok(None)
}

/// Writes the plain-text report into `out`, from the ledger alone, a row at a time as the
/// ledger is walked.
pub fn write_report(
    out: &mut dyn Write,
    source: &str,
    dest: &Path,
    outcome: &Outcome,
) -> std::io::Result<()> {
    let stamp = crate::clock::local(std::time::SystemTime::now()).long();
    write!(
        out,
        "Recovery report\r\n{COMPLETE_IF}\r\n\r\nSource: {source}\r\nDestination: {}\r\nWritten: {stamp}\r\n\r\nFiles\r\n",
        dest.display()
    )?;
    outcome.ledger.write_rows(out, dest, true)?;
    if !outcome.pictures.is_empty() {
        write!(out, "\r\nPictures with missing parts\r\n")?;
        for p in &outcome.pictures {
            write!(out, "{}\r\n", picture_line(outcome, p, dest))?;
        }
    }
    if !outcome.failed.is_empty() {
        write!(out, "\r\nNot made\r\n")?;
        for (name, why) in &outcome.failed {
            write!(out, "{name}\t{why}\r\n")?;
        }
    }
    // The summary comes after the table, so a report cut short never shows one.
    write!(
        out,
        "\r\n{} recovered in full, {} damaged (unreadable parts written as zeros, or a damaged record on the volume), {} incomplete; {} could not be made.\r\n",
        files(outcome.complete()),
        outcome.damaged(),
        outcome.partial(),
        outcome.failed.len()
    )?;
    if !outcome.pictures.is_empty() {
        write!(
            out,
            "{} with missing parts {}; {} built-in previews saved beside them.\r\n",
            if outcome.pictures.len() == 1 {
                "1 picture".to_string()
            } else {
                format!("{} pictures", outcome.pictures.len())
            },
            outcome.pictures_placed(),
            outcome.previews()
        )?;
        let stayed = outcome.pictures_stayed();
        if stayed > 0 {
            write!(
                out,
                "{stayed} of them could not be put so; the rows above say where each is and why.\r\n"
            )?;
        }
    }
    if outcome.kept > 0 {
        write!(
            out,
            "Kept as an earlier run into this folder left them, whole: {}.\r\n",
            files(outcome.kept)
        )?;
    }
    if outcome.resumed > 0 {
        write!(
            out,
            "Finished from where an earlier run cut them short: {}.\r\n",
            files(outcome.resumed)
        )?;
    }
    if outcome.left_out > 0 {
        write!(
            out,
            "Left out, under {SYSTEM_FOLDER}, which Windows keeps for itself: {}.\r\n",
            files(outcome.left_out)
        )?;
    }
    if outcome.stopped {
        write!(
            out,
            "The recovery was stopped before every file was copied.\r\n"
        )?;
    }
    if let Some(why) = &outcome.log_error {
        write!(
            out,
            "The log of this run could not be written to its end: {why}.\r\n"
        )?;
    }
    if outcome.partial() > 0 {
        write!(
            out,
            "Incomplete files hold only their first part; they are marked PARTIAL above.\r\n"
        )?;
    }
    if let Some(why) = &outcome.gone {
        write!(out, "The recovery ended early: {why}.\r\n")?;
    }
    // No line break after it: a report cut anywhere short of its last byte does not end
    // with it.
    write!(out, "{END}")?;
    out.flush()
}

/// A report line for a picture with missing parts: how much is missing and where, how much of
/// its start is whole, and its preview.
fn picture_line(outcome: &Outcome, p: &Salvaged, base: &Path) -> String {
    let o = &outcome.ledger.outputs()[p.output];
    let rel = |path: &Path| {
        path.strip_prefix(base)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let mut missing = o.zeroed.clone();
    if o.at < o.size {
        missing.push(o.at..o.size);
    }
    let missing = super::reader::merge(missing);
    let lost: u64 = missing.iter().map(|r| r.end - r.start).sum();
    let first = missing.first().map_or(o.size, |r| r.start);
    let percent = |n: u64| n.saturating_mul(100) / o.size.max(1);
    let places: Vec<String> = missing
        .iter()
        .take(8)
        .map(|r| format!("{}-{}", r.start, r.end))
        .collect();
    let more = if missing.len() > 8 { ", ..." } else { "" };
    let preview = match &p.preview {
        Preview::Saved(id, source) => format!(
            "its {} is saved as {}",
            source.label(),
            rel(&outcome.ledger.outputs()[*id].path)
        ),
        Preview::NotSaved(source, why) => {
            format!("its {} could not be saved: {why}", source.label())
        }
        Preview::None => "no whole built-in preview was found in the parts read".into(),
    };
    let whole = if first == 0 {
        "its first byte is missing".to_string()
    } else {
        format!(
            "it is whole from its start to byte {first} ({}%)",
            percent(first)
        )
    };
    format!(
        "{}\t{lost} of {} bytes missing ({}%), at bytes {}{more}; {whole}; {preview}",
        rel(&o.path),
        o.size,
        percent(lost).max(u64::from(lost > 0)),
        places.join(", ")
    )
}

/// The report's last line, with no line break after it; a report that does not end with it
/// was cut short.
pub const END: &str = "End of report.";
/// Names the last line without its full stop: a report cut just after a quote of it must
/// not end with it.
pub(crate) const COMPLETE_IF: &str =
    "This report is complete only if its last line reads \"End of report\" with a full stop.";

#[cfg(test)]
mod tests {
    /// Recovers every file of the first NTFS volume of a virtual disk made for the test:
    /// DIAGTOOL_LIVE_DISK names the disk (a Msft Virtual Disk, never disk 0, 3 or 4) and
    /// DIAGTOOL_LIVE_FOLDER a new folder on another disk; DIAGTOOL_LIVE_COMPARE, when set,
    /// is a folder holding the same files as Windows reads them. Needs administrator rights.
    /// Prints every ledger row and the report, then deletes its folder.
    #[test]
    #[ignore = "reads a virtual disk made for it; needs administrator rights and two environment variables"]
    fn live_recover_files_of_a_virtual_disk() {
        use crate::recovery::fs::parts::{self, Search};
        let number: u32 = std::env::var("DIAGTOOL_LIVE_DISK")
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            ![0, 3, 4].contains(&number),
            "disk {number} is not to be read"
        );
        let folder = PathBuf::from(std::env::var("DIAGTOOL_LIVE_FOLDER").unwrap());
        assert!(!folder.exists(), "{} must be new", folder.display());
        let source = crate::recovery::open_source(&SourceChoice::Disk(number)).unwrap();
        let id = source.identity().expect("the disk says what it is");
        assert!(
            id.model.contains("Virtual Disk"),
            "disk {number} is {}",
            id.model
        );
        eprintln!("source: {}", source.describe());
        let never = AtomicBool::new(false);
        let mut reader = Reader::new(source);
        let volumes = parts::find(&mut reader, Search::Tables, &never, &Progress::default());
        let volume = volumes.volumes.first().expect("a volume").clone();
        eprintln!("volume: {}", volume.describe());
        let listing =
            super::super::fs::scan(&mut reader, &volume, &never, &Progress::default()).unwrap();
        let found: Vec<&Found> = listing
            .files
            .iter()
            .filter(|f| {
                !f.name.starts_with('$')
                    && !f
                        .folder
                        .iter()
                        .any(|p| p.name.starts_with('$') || p.name == "System Volume Information")
            })
            .collect();
        let items: Vec<Item> = found.iter().map(|f| Item::from_found(f)).collect();
        std::fs::create_dir(&folder).unwrap();
        let outcome = recover(
            &mut reader,
            &items,
            &folder,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::disk(number),
            &never,
            &Progress::default(),
        )
        .unwrap();
        for o in outcome.ledger.outputs() {
            eprintln!(
                "  {}\t{}\t{}",
                o.path.display(),
                o.size_text(),
                o.condition()
            );
        }
        let report = outcome.ledger.get(outcome.report_entry.unwrap());
        assert!(report.complete(), "{report:?}");
        assert_eq!(outcome.complete(), items.len(), "every file read in full");
        if let Ok(compare) = std::env::var("DIAGTOOL_LIVE_COMPARE") {
            for o in &outcome.ledger.outputs()[..items.len()] {
                let rel = o.path.strip_prefix(&folder).unwrap();
                let want = std::fs::read(Path::new(&compare).join(rel)).unwrap();
                assert!(
                    std::fs::read(&o.path).unwrap() == want,
                    "{} differs",
                    rel.display()
                );
                eprintln!(
                    "  {} matches what Windows reads ({} bytes)",
                    rel.display(),
                    want.len()
                );
            }
        }
        let text = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        eprintln!("{text}");
        assert!(text.ends_with("End of report."));
        std::fs::remove_dir_all(&folder).unwrap();
    }

    use super::*;

    /// The guard (review F2, C5, round 11): output from an image is refused on the drive its
    /// map says it was made from, found by identity when each output is opened, so a drive
    /// that comes back under another number is still refused; a disk that cannot be told
    /// apart from it is refused; an image whose map cannot be read refuses every output. The
    /// image's own drive is not guarded (its file is in use). Before rc.8 an image guarded
    /// nothing, and a test said so; in rc.8's first cut it guarded disk numbers taken once.
    #[test]
    fn an_image_source_guards_the_drive_it_was_made_from() {
        use crate::recovery::dest::{Guard, Protected};
        use crate::recovery::{check_destination, Scope, SourceId};
        assert_eq!(
            source_disk(&SourceChoice::Disk(9999)),
            Protected::disk(9999)
        );
        let dir = std::env::temp_dir().join(format!("diagtool-origin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The drive the temporary folder is on plays the drive the image was made from.
        let on = crate::tools::drives::device::disks_of_path(&dir).unwrap()[0];
        let disk = crate::recovery::target::list_disks()
            .unwrap()
            .into_iter()
            .find(|d| d.number == on && !d.serial.trim().is_empty())
            .expect("the temporary folder's disk, with a serial number");
        let id = SourceId {
            model: disk.model.clone(),
            serial: disk.serial.clone(),
            size: disk.size,
            drive: disk.drive.clone(),
            sector: Some(disk.sector),
            scope: Some(Scope::Disk),
            disk_size: Some(disk.size),
        };
        let image = dir.join("customer.img");
        std::fs::write(&image, vec![0u8; 4096]).unwrap();
        let map = |id: Option<&SourceId>| {
            let mut text: String = id
                .map(crate::recovery::image::identity_lines)
                .unwrap_or_default()
                .iter()
                .map(|l| format!("# {l}\n"))
                .collect();
            text.push_str("0x00000000     +               1\n0x00000000  0x00001000  +\n");
            text
        };
        // Under its appended name, as GNU ddrescue users name it.
        let beside = dir.join("customer.img.map");
        std::fs::write(&beside, map(Some(&id))).unwrap();
        let guarded = source_disk(&SourceChoice::Image(image.clone()));
        assert!(
            guarded.disks.is_empty(),
            "no number is taken once: {guarded:?}"
        );
        assert_eq!(guarded.drives.len(), 1);
        let guard = Guard::of(&guarded);
        assert!(guard.refuses_disk(disk.number).is_some_and(|r| r.firm));
        let unknown = guard.refuses_disk(9999).unwrap();
        assert!(
            unknown.reason.contains("could not be told apart"),
            "{unknown:?}"
        );
        assert!(
            !unknown.firm,
            "a disk that cannot be read is a doubt: {unknown:?}"
        );
        let why = check_destination(&dir, &guarded).unwrap_err();
        assert!(why.contains("made from"), "{why}");
        assert!(guard.base(&dir).is_err(), "the held folder is refused too");
        // The writer guards by the source it reads through, whatever protection it is given
        // (round 12: a page's protection came from another open of the image).
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::ImageFile::open(&image).unwrap(),
        ));
        let Err(refused) = recover(
            &mut reader,
            &[],
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &std::sync::atomic::AtomicBool::new(false),
            &Progress::default(),
        ) else {
            panic!("output on the drive the image was made from");
        };
        assert!(refused.contains("made from"), "{refused}");
        drop(reader);
        // A map that names no drive, or no map: nothing to guard by.
        std::fs::write(&beside, map(None)).unwrap();
        let none = source_disk(&SourceChoice::Image(image.clone()));
        assert_eq!(none, Protected::default());
        assert!(check_destination(&dir, &none).is_ok());
        std::fs::remove_file(&beside).unwrap();
        assert_eq!(
            source_disk(&SourceChoice::Image(image.clone())),
            Protected::default()
        );
        // A map there that cannot be read: what it was made from is not known, so nothing is
        // written anywhere.
        std::fs::create_dir(dir.join("customer.map")).unwrap();
        let unread = source_disk(&SourceChoice::Image(image));
        assert!(unread.unknown.is_some(), "{unread:?}");
        let elsewhere = std::env::temp_dir();
        assert!(check_destination(&elsewhere, &unread).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        // The guard: a volume's disk is read from the volume, not taken from its number.
        let path = crate::recovery::disk::temp_volume();
        let real = crate::tools::drives::device::disks_of_volume(&path).unwrap()[0];
        let volume = SourceChoice::Volume {
            path,
            disk: real + 1,
            name: "a volume".into(),
        };
        let by_volume = source_disk(&volume);
        assert_eq!(by_volume.disks, [real]);
        // A disk chosen by its number is guarded by its identity too (round 13), so the
        // check window refuses it under another number.
        assert_eq!(by_volume.drives.len(), 1, "{by_volume:?}");
        let chosen = source_disk(&SourceChoice::Disk(real));
        assert_eq!(chosen.drives, by_volume.drives);
    }

    /// What a real image's map protects, asked of a real destination folder: RESCUE_MAP names
    /// the map, RESCUE_DEST the folder. Prints the drive the map names and the answer; fails
    /// only when the answer differs from RESCUE_DEST_REFUSED ("yes" or "no", default "no").
    #[test]
    #[ignore = "reads a real rescue map named by RESCUE_MAP and a folder named by RESCUE_DEST"]
    fn a_real_image_s_protection_against_a_real_destination() {
        use crate::recovery::dest::Protected;
        let map = std::env::var("RESCUE_MAP").expect("RESCUE_MAP");
        let dest = std::env::var("RESCUE_DEST").expect("RESCUE_DEST");
        let refused = std::env::var("RESCUE_DEST_REFUSED").unwrap_or_else(|_| "no".into()) == "yes";
        let text = std::fs::read_to_string(&map).unwrap();
        let id = crate::recovery::image::map_identity(&text).expect("a map that names its drive");
        eprintln!("the map names {}", id.text());
        // RESCUE_IMAGE, when given, adds the partition table read from the image itself.
        let protected = match std::env::var("RESCUE_IMAGE") {
            Ok(image) => {
                let image = crate::recovery::ImageFile::open(std::path::Path::new(&image)).unwrap();
                crate::recovery::BlockSource::protected(&image)
            }
            Err(_) => Protected {
                drives: vec![crate::recovery::dest::Guarded::new(id, None)],
                ..Protected::default()
            },
        };
        for drive in &protected.drives {
            let places: Vec<u64> = drive.samples.iter().map(|s| s.pos).collect();
            eprintln!("guarded: table {:?}, samples at {places:?}", drive.table);
        }
        let answer = crate::recovery::check_destination(std::path::Path::new(&dest), &protected);
        eprintln!("{dest}: {answer:?}");
        assert_eq!(answer.is_err(), refused, "{answer:?}");
    }

    /// A source that presses Stop once a read reaches `from`, as a person does mid-file.
    struct StopsAt {
        disk: crate::recovery::MemDisk,
        from: u64,
        stop: std::sync::Arc<AtomicBool>,
    }

    impl crate::recovery::BlockSource for StopsAt {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            self.disk.sector_size()
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), crate::recovery::ReadError> {
            if offset >= self.from {
                self.stop.store(true, Ordering::Relaxed);
            }
            self.disk.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            "test disk".into()
        }
    }

    /// The guard: the last file, cut short by Stop, is marked partial in the outcome and the
    /// report, and the report says the recovery was stopped.
    #[test]
    fn each_written_file_names_its_own_item_after_a_failed_one() {
        let dir = std::env::temp_dir().join(format!("diagtool-item-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A file where the first item's folder must go makes that item fail.
        std::fs::write(dir.join("clash"), b"x").unwrap();
        let mut reader = Reader::new(Box::new(crate::recovery::MemDisk::new(vec![7u8; 8192])));
        let item = |name: &str, folder: &[&str]| Item {
            name: name.into(),
            folder: folder.iter().map(|f| f.to_string()).collect(),
            size: 512,
            data: Data::Runs(vec![Run {
                place: Place::At(0),
                len: 512,
            }]),
            state: "intact".into(),
            deleted: false,
            flaw: None,
        };
        let items = [item("a.bin", &["clash"]), item("b.bin", &[])];
        let outcome = recover(
            &mut reader,
            &items,
            &dir,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        assert_eq!(outcome.failed.len(), 1, "{:?}", outcome.failed);
        assert_eq!(outcome.ledger.outputs().len(), 2, "the file and the report");
        assert_eq!(
            outcome.ledger.outputs()[0].tag,
            1,
            "the written file names the wrong item"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a file the volume's records show damaged is never reported read in full,
    /// even when every byte its runs name was read; one whose runs hold less than its size
    /// keeps that size, the rest written as zeros.
    #[test]
    fn a_file_with_a_damaged_record_is_never_read_in_full() {
        use crate::recovery::fs::{Found, State as FsState};
        let dir = std::env::temp_dir().join(format!("diagtool-flaw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut reader = Reader::new(Box::new(crate::recovery::MemDisk::new(vec![7u8; 8192])));
        let found = |name: &str, size: u64, runs: Vec<Run>| Found {
            name: name.into(),
            folder: Vec::new(),
            size,
            modified: None,
            deleted: false,
            state: FsState::Intact,
            data: Data::Runs(runs),
            damaged: true,
            note: None,
            why: None,
        };
        let read = Run {
            place: Place::At(0),
            len: 4096,
        };
        let missing = Run {
            place: Place::Missing,
            len: 4096,
        };
        let items = [
            Item::from_found(&found("record.bin", 4096, vec![read.clone()])),
            Item::from_found(&found("short.bin", 8192, vec![read, missing])),
        ];
        assert!(
            items.iter().all(|i| i.flaw.is_some()),
            "the flag was dropped"
        );
        let outcome = recover(
            &mut reader,
            &items,
            &dir,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        let ledger = &outcome.ledger.outputs()[..2];
        assert!(
            ledger.iter().all(|o| o.damaged() && !o.complete()),
            "{ledger:?}"
        );
        assert_eq!((outcome.complete(), outcome.damaged()), (0, 2));
        assert_eq!(std::fs::metadata(&ledger[1].path).unwrap().len(), 8192);
        assert_eq!(ledger[1].zeroed, vec![4096..8192]);
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        assert!(!report.contains("read in full"), "{report}");
        assert!(
            report.contains("record.bin\t4096 bytes\tintact\tDAMAGED: the volume's record"),
            "{report}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_cut_short_by_stop_is_never_reported_whole() {
        let dir = std::env::temp_dir().join(format!("diagtool-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let source = StopsAt {
            disk: crate::recovery::MemDisk::new(vec![5u8; 4 * CHUNK as usize]),
            from: CHUNK,
            stop: stop.clone(),
        };
        let mut reader = Reader::new(Box::new(source));
        let item = |name: &str, at: u64, len: u64| Item {
            name: name.into(),
            folder: Vec::new(),
            size: len,
            data: Data::Runs(vec![Run {
                place: Place::At(at),
                len,
            }]),
            state: "intact".into(),
            deleted: false,
            flaw: None,
        };
        let items = [item("a.bin", 0, 4096), item("b.bin", CHUNK, 3 * CHUNK)];
        let outcome = recover(
            &mut reader,
            &items,
            &dir,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::default(),
            &stop,
            &Progress::default(),
        )
        .unwrap();
        assert!(outcome.stopped, "the outcome does not say it was stopped");
        assert_eq!(
            outcome.ledger.outputs().len(),
            3,
            "two files and the report"
        );
        assert!(outcome.ledger.outputs()[0].complete());
        let b = &outcome.ledger.outputs()[1];
        assert!(b.partial() && b.at == CHUNK, "{b:?}");
        assert_eq!(std::fs::metadata(&b.path).unwrap().len(), CHUNK);
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        assert!(report.contains("The recovery was stopped"), "{report}");
        assert!(
            report.contains("b.bin\t1.0 MB of 3.1 MB (1048576 of 3145728 bytes)\tintact\tPARTIAL"),
            "{report}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A writer that takes `left` more bytes and then fails, and can fail its flush, as a
    /// full or failing destination does.
    struct Failing<'f> {
        file: &'f File,
        left: usize,
        flush_fails: bool,
    }

    impl Write for Failing<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other("the destination is full"));
            }
            let n = buf.len().min(self.left);
            self.left -= n;
            self.file.write(&buf[..n])
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flush_fails {
                return Err(std::io::Error::other("the flush failed"));
            }
            self.file.flush()
        }
    }

    /// The log's writer of `recover`.
    fn plain_log(file: File) -> Box<dyn Write + Send> {
        Box::new(file)
    }

    /// Every file under `dir` but the report and the log, as its path inside `dir`.
    fn files_in(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(folder) = stack.pop() {
            for entry in std::fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("Recovery "))
                {
                    found.push(path.strip_prefix(dir).unwrap().display().to_string());
                }
            }
        }
        found
    }

    /// A test disk holding `files` one after another from 4 KiB, each on a sector boundary,
    /// with `bad` unreadable; the items for them, named as the carver names its finds.
    fn picture_disk(files: &[&[u8]], bad: &[Range<u64>]) -> (Reader<'static>, Vec<Item>) {
        let (disk, items) = laid_out(files, bad);
        (Reader::new(Box::new(disk)), items)
    }

    /// `picture_disk`'s disk itself.
    fn laid_out(files: &[&[u8]], bad: &[Range<u64>]) -> (crate::recovery::MemDisk, Vec<Item>) {
        let mut data = vec![0u8; 4096];
        let mut items = Vec::new();
        for bytes in files {
            let at = data.len() as u64;
            data.extend(*bytes);
            data.resize(data.len().div_ceil(512) * 512, 0);
            items.push(Item {
                name: format!("f{:08}.jpg", at / 512),
                folder: Vec::new(),
                size: bytes.len() as u64,
                data: Data::Runs(vec![Run {
                    place: Place::At(at),
                    len: bytes.len() as u64,
                }]),
                state: format!("found by type at byte {at}"),
                deleted: false,
                flaw: None,
            });
        }
        data.resize(data.len() + 4096, 0);
        let mut disk = crate::recovery::MemDisk::new(data);
        disk.bad.extend(bad.iter().cloned());
        (disk, items)
    }

    /// A picture with missing parts is written with zeros in them, named "(partial)", and
    /// its built-in preview is written beside it; the report says how much is missing, where,
    /// and names the preview. A whole picture and a damaged file that is not a picture keep
    /// their names.
    #[test]
    fn a_damaged_photo_is_named_partial_and_its_preview_is_saved_beside_it() {
        use crate::recovery::preview::tests::{camera_jpeg, HOLIDAY, PHOTO};
        let camera = camera_jpeg(HOLIDAY, PHOTO, None);
        let first = 4096u64;
        // One bad sector in the main picture; the reader gives up the 4 KiB piece around it.
        let gap = first + 8192..first + 8704;
        // The third copy's start is unreadable, so it has no preview to give.
        let third = picture_disk(&[&camera, HOLIDAY, &camera], &[]).1[2].clone();
        let Data::Runs(runs) = &third.data else {
            unreachable!()
        };
        let Place::At(third) = runs[0].place else {
            unreachable!()
        };
        let (mut reader, items) = picture_disk(
            &[&camera, HOLIDAY, &camera],
            &[gap.clone(), third..third + 512],
        );
        let mut notes = items.clone();
        notes.push(Item {
            name: "notes.txt".into(),
            ..items[0].clone()
        });
        let dir =
            std::env::temp_dir().join(format!("diagtool-picture-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = recover(
            &mut reader,
            &notes,
            &dir,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        let mut names = files_in(&dir);
        names.sort();
        assert_eq!(
            names,
            vec![
                "f00000008 (partial).jpg",
                "f00000008 (preview).jpg",
                "f00000040.jpg",
                format!("f{:08} (partial).jpg", third / 512).as_str(),
                "notes.txt",
            ]
        );
        let partial = std::fs::read(dir.join("f00000008 (partial).jpg")).unwrap();
        assert_eq!(partial.len(), camera.len());
        assert!(partial[8192..12288].iter().all(|b| *b == 0));
        assert_eq!(partial[..8192], camera[..8192]);
        assert_eq!(partial[12288..], camera[12288..]);
        assert_eq!(
            std::fs::read(dir.join("f00000008 (preview).jpg")).unwrap(),
            PHOTO
        );
        assert_eq!(outcome.pictures.len(), 2);
        assert_eq!(outcome.previews(), 1);
        assert_eq!(outcome.complete(), 1);
        assert_eq!(outcome.damaged(), 3);
        let ledger = outcome.ledger.outputs();
        assert_eq!(ledger[0].path, dir.join("f00000008 (partial).jpg"));
        assert!(ledger[1].complete() && ledger[1].note.contains("EXIF thumbnail"));
        let report = std::fs::read_to_string(outcome.report.unwrap()).unwrap();
        assert!(report.contains("Pictures with missing parts"), "{report}");
        assert!(
            report.contains(&format!(
                "f00000008 (partial).jpg\t4096 of {} bytes missing ({}%), at bytes 8192-12288; it is whole from its start to byte 8192 ({}%); its EXIF thumbnail is saved as f00000008 (preview).jpg",
                camera.len(),
                4096 * 100 / camera.len(),
                8192 * 100 / camera.len()
            )),
            "{report}"
        );
        assert!(report.contains("its first byte is missing"), "{report}");
        assert!(
            report.contains(
                "2 pictures with missing parts named \"(partial)\"; 1 built-in previews saved"
            ),
            "{report}"
        );
        assert!(report.ends_with(END));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Takes `left` bytes, then fails every write.
    struct Cut {
        taken: Vec<u8>,
        left: usize,
    }

    impl Write for Cut {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other("the destination is full"));
            }
            let n = buf.len().min(self.left);
            self.left -= n;
            self.taken.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The guard: a report cut short anywhere fails, never shows its summary before every
    /// row, and never ends on its last line; only a report written whole does.
    #[test]
    fn a_report_cut_short_never_reads_as_complete() {
        let mut outcome = Outcome::default();
        for i in 0..40 {
            let id = outcome.ledger.made(
                i,
                PathBuf::from(format!(r"E:\Recovered\file{i}.jpg")),
                format!("file{i}.jpg").into(),
                "deleted, intact".into(),
                1000,
            );
            outcome.ledger.whole(id);
        }
        let dest = Path::new(r"E:\Recovered");
        let mut whole = Vec::new();
        write_report(&mut whole, "disk 4", dest, &outcome).unwrap();
        let whole = String::from_utf8(whole).unwrap();
        assert!(whole.ends_with(&format!("\r\n{END}")), "{whole}");
        let summary = whole.find("recovered in full").unwrap();
        assert!(summary > whole.find("file39.jpg").unwrap(), "{whole}");
        for left in 0..whole.len() {
            let mut cut = Cut {
                taken: Vec::new(),
                left,
            };
            assert!(write_report(&mut cut, "disk 4", dest, &outcome).is_err());
            let taken = String::from_utf8_lossy(&cut.taken);
            assert!(
                !taken.ends_with(END) && !taken.lines().any(|l| l == END),
                "cut at {left}"
            );
            assert!(
                !taken.contains("recovered in full") || taken.contains("file39.jpg"),
                "cut at {left}: a summary before the last row"
            );
        }
    }

    /// The guard: the report is entered in the ledger when it is made and ends whole, or
    /// partial at what was written when a write fails; it is never counted as a recovered
    /// file.
    #[test]
    fn the_report_is_in_the_ledger_and_ends_whole_or_partial() {
        let dir = std::env::temp_dir().join(format!("diagtool-report-{}", std::process::id()));
        let mut reader = Reader::new(Box::new(crate::recovery::MemDisk::new(vec![3u8; 8192])));
        let items = [Item {
            name: "a.bin".into(),
            folder: Vec::new(),
            size: 512,
            data: Data::Runs(vec![Run {
                place: Place::At(0),
                len: 512,
            }]),
            state: "intact".into(),
            deleted: false,
            flaw: None,
        }];
        for report_fails in [false, true] {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let mut made = 0;
            let outcome = recover_with(
                &mut reader,
                &items,
                &dir,
                &RecoverOptions::default(),
                &crate::recovery::dest::Protected::default(),
                &AtomicBool::new(false),
                &Progress::default(),
                Hooks {
                    wrap: &mut |file| {
                        made += 1;
                        if made == 2 && report_fails {
                            Box::new(Failing {
                                file,
                                left: 100,
                                flush_fails: false,
                            })
                        } else {
                            Box::new(file)
                        }
                    },
                    log: &mut plain_log,
                    flusher: None,
                },
            )
            .unwrap();
            let id = outcome
                .report_entry
                .expect("the report has no ledger entry");
            let report = &outcome.ledger.outputs()[id];
            assert_eq!(report.tag, REPORT_TAG);
            assert_eq!(Some(&report.path), outcome.report.as_ref());
            assert_eq!((outcome.complete(), outcome.partial()), (1, 0));
            let on_disk = std::fs::metadata(&report.path).unwrap().len();
            if report_fails {
                assert!(report.partial() && report.at == 100, "{report:?}");
                assert_eq!(on_disk, 100);
                assert!(outcome.report_error.is_some());
            } else {
                assert!(report.complete() && report.size == on_disk, "{report:?}");
                assert!(outcome.report_error.is_none());
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a file whose write or flush fails after it was made is listed with what
    /// it holds, never as not written, and every file left in the destination has a row.
    #[test]
    fn every_file_left_in_the_destination_is_in_the_report() {
        let dir = std::env::temp_dir().join(format!("diagtool-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut reader = Reader::new(Box::new(crate::recovery::MemDisk::new(vec![3u8; 1 << 16])));
        let item = |name: &str| Item {
            name: name.into(),
            folder: vec!["docs".into()],
            size: 5000,
            data: Data::Runs(vec![Run {
                place: Place::At(0),
                len: 5000,
            }]),
            state: "intact".into(),
            deleted: false,
            flaw: None,
        };
        let items = [item("a.bin"), item("b.bin"), item("c.bin")];
        let mut made = 0;
        let outcome = recover_with(
            &mut reader,
            &items,
            &dir,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
            Hooks {
                wrap: &mut |file| {
                    made += 1;
                    match made {
                        2 => Box::new(Failing {
                            file,
                            left: 1000,
                            flush_fails: false,
                        }),
                        3 => Box::new(Failing {
                            file,
                            left: usize::MAX,
                            flush_fails: true,
                        }),
                        _ => Box::new(file),
                    }
                },
                log: &mut plain_log,
                flusher: None,
            },
        )
        .unwrap();
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        let present = files_in(&dir);
        assert_eq!(present.len(), 3, "{present:?}");
        for file in &present {
            assert!(
                report.contains(&format!("{file}\t")),
                "{file} has no row:\n{report}"
            );
        }
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert_eq!((outcome.complete(), outcome.partial()), (1, 2));
        assert!(
            report.contains("b.bin\t1.0 kB of 5.0 kB (1000 of 5000 bytes)\tintact\tPARTIAL: writing failed after 1000 bytes: the destination is full"),
            "{report}"
        );
        assert!(
            report.contains("PARTIAL: writing failed after 5000 bytes: the flush failed"),
            "{report}"
        );
        assert!(report.contains("1 file recovered in full"), "{report}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The bytes an item's copy should hold, read from `disk` with zeros in the 4 KiB
    /// pieces the reader gives up around a bad area.
    fn expected(disk: &crate::recovery::MemDisk, item: &Item) -> Vec<u8> {
        let Data::Runs(runs) = &item.data else {
            unreachable!()
        };
        let Place::At(at) = runs[0].place else {
            unreachable!()
        };
        let mut bytes = disk.data[at as usize..(at + item.size) as usize].to_vec();
        for bad in &disk.bad {
            let piece = bad.start & !4095..bad.end.div_ceil(4096) * 4096;
            for (i, b) in bytes.iter_mut().enumerate() {
                if piece.contains(&(at + i as u64)) {
                    *b = 0;
                }
            }
        }
        bytes
    }

    /// Distinct bytes, so one file's copy is never another's.
    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) | 1)
            .collect()
    }

    /// A damaged picture, two large files and a small one, in order of place, the last
    /// deleted and the second in a folder; the picture has a bad sector.
    fn resume_disk() -> (crate::recovery::MemDisk, Vec<Item>) {
        use crate::recovery::preview::tests::{camera_jpeg, HOLIDAY, PHOTO};
        let camera = camera_jpeg(HOLIDAY, PHOTO, None);
        let big = pattern(3, 3 * CHUNK as usize + 700);
        let small = pattern(5, 5000);
        let last = pattern(7, 2 * CHUNK as usize + 100);
        let gap = 4096 + 8192..4096 + 8704;
        let (disk, mut items) = laid_out(&[&camera, &big, &small, &last], &[gap]);
        items[1].name = "big.bin".into();
        items[1].folder = vec!["docs".into()];
        items[2].name = "small.bin".into();
        items[3].name = "last.bin".into();
        items[3].deleted = true;
        (disk, items)
    }

    /// Every file under `dir` but the reports and the log, sorted.
    fn sorted_files(dir: &Path) -> Vec<String> {
        let mut names = files_in(dir);
        names.sort();
        names
    }

    /// The guard (manual step 30): a recovery stopped part way and run again into the same
    /// folder ends with every file once, whole, and no " (2)" name. What the earlier run left
    /// whole is kept, by its log's rows or, for a file the log does not name, by its bytes;
    /// what its log names as cut short is written on from where it ends. The damaged picture
    /// keeps its "(partial)" name and its one preview. A run killed before the row of the file
    /// it was copying reached the log leaves that file as it is and copies the item again.
    #[test]
    fn a_recovery_run_again_finishes_what_an_earlier_run_left() {
        for log_rows_lost in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "diagtool-resume-{log_rows_lost}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let (disk, items) = resume_disk();
            let Data::Runs(runs) = &items[3].data else {
                unreachable!()
            };
            let Place::At(last_at) = runs[0].place else {
                unreachable!()
            };
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let source = StopsAt {
                disk: crate::recovery::MemDisk {
                    data: disk.data.clone(),
                    bad: disk.bad.clone(),
                    ..crate::recovery::MemDisk::new(Vec::new())
                },
                from: last_at,
                stop: stop.clone(),
            };
            let mut reader = Reader::new(Box::new(source));
            let first = recover(
                &mut reader,
                &items,
                &dir,
                &RecoverOptions::default(),
                &Protected::default(),
                &stop,
                &Progress::default(),
            )
            .unwrap();
            assert!(first.stopped);
            assert_eq!(
                (first.complete(), first.damaged(), first.partial()),
                (2, 1, 1)
            );
            let partial = first.ledger.outputs().iter().find(|o| o.tag == 3).unwrap();
            assert_eq!(std::fs::metadata(&partial.path).unwrap().len(), CHUNK);
            let log = dir.join(LOG_NAME);
            if log_rows_lost {
                // As a run killed while it copied leaves it: no row for the file cut short,
                // and none for a file whose row did not reach the disk.
                let text = std::fs::read_to_string(&log).unwrap();
                let kept: Vec<&str> = text
                    .split("\r\n")
                    .filter(|l| !l.contains("big.bin") && !l.contains("last.bin"))
                    .collect();
                std::fs::write(&log, kept.join("\r\n")).unwrap();
            }
            drop(reader);
            let mut reader = Reader::new(Box::new(disk));
            let disk_again = resume_disk().0;
            let again = recover(
                &mut reader,
                &items,
                &dir,
                &RecoverOptions::default(),
                &Protected::default(),
                &AtomicBool::new(false),
                &Progress::default(),
            )
            .unwrap();
            assert!(!again.stopped && again.failed.is_empty());
            assert_eq!(
                (again.kept, again.resumed),
                (3, usize::from(!log_rows_lost)),
                "rows lost: {log_rows_lost}"
            );
            assert_eq!(
                (again.complete(), again.damaged(), again.partial()),
                (3, 1, 0)
            );
            let mut want = vec![
                "docs\\big.bin",
                "f00000008 (partial).jpg",
                "f00000008 (preview).jpg",
                "last.bin",
                "small.bin",
            ];
            if log_rows_lost {
                want.insert(3, "last (2).bin");
                assert_eq!(
                    std::fs::metadata(dir.join("last.bin")).unwrap().len(),
                    CHUNK
                );
            }
            assert_eq!(sorted_files(&dir), want, "rows lost: {log_rows_lost}");
            for (index, item) in items.iter().enumerate() {
                let o = again
                    .ledger
                    .outputs()
                    .iter()
                    .find(|o| o.tag == index && !o.note.starts_with(PREVIEW_NOTE))
                    .unwrap();
                assert_eq!(
                    std::fs::read(&o.path).unwrap(),
                    expected(&disk_again, item),
                    "{}",
                    item.name
                );
            }
            let report = std::fs::read_to_string(again.report.as_ref().unwrap()).unwrap();
            assert!(report.ends_with(END), "{report}");
            assert!(
                report
                    .contains("Kept as an earlier run into this folder left them, whole: 3 files."),
                "{report}"
            );
            assert_eq!(
                report.contains("Finished from where an earlier run cut them short: 1 file."),
                !log_rows_lost,
                "{report}"
            );
            // The log holds both runs, the second ended.
            let log = std::fs::read_to_string(&log).unwrap();
            assert_eq!(
                log.matches("Recovery log by Diagnostic Tool").count(),
                2,
                "{log}"
            );
            assert!(log.ends_with(crate::recovery::copy::LOG_END), "{log}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A file at a name the recovery would give that holds what the item does not is never
    /// written on: the copy takes the next name.
    #[test]
    fn a_file_the_recovery_did_not_leave_is_never_written_over() {
        let dir = std::env::temp_dir().join(format!("diagtool-other-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (disk, mut items) = laid_out(&[&pattern(1, 3000), &pattern(2, 3000)], &[]);
        items[0].name = "a.bin".into();
        items[1].name = "b.bin".into();
        // Shorter and different; longer and the same at first.
        std::fs::write(dir.join("a.bin"), b"someone else's").unwrap();
        let mut longer = expected(&disk, &items[1]);
        longer.extend(b"more");
        std::fs::write(dir.join("b.bin"), &longer).unwrap();
        let outcome = recover(
            &mut Reader::new(Box::new(disk)),
            &items,
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        assert_eq!(
            (outcome.complete(), outcome.kept, outcome.resumed),
            (2, 0, 0)
        );
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), b"someone else's");
        assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), longer);
        assert_eq!(
            sorted_files(&dir),
            ["a (2).bin", "a.bin", "b (2).bin", "b.bin"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What the guard of manual step 31 sees: the flushes, with the paths each covered, and
    /// the log's rows, in the order they came.
    #[derive(Clone, Default)]
    struct Seen(std::sync::Arc<std::sync::Mutex<Vec<(bool, String)>>>);

    impl writer::Flusher for Seen {
        fn flush(&mut self, files: &[(&Path, &File)]) -> std::io::Result<()> {
            let mut seen = self.0.lock().unwrap();
            for (path, _) in files {
                seen.push((true, path.display().to_string()));
            }
            seen.push((true, String::new()));
            Ok(())
        }
    }

    impl Write for Seen {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let text = String::from_utf8_lossy(buf).into_owned();
            self.0.lock().unwrap().push((false, text));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The guard (manual step 31): files are made durable many at a time, not each on its
    /// own, and none is entered whole, in the ledger or its log, before a flush covered it.
    #[test]
    fn files_are_flushed_in_batches_and_entered_whole_only_after() {
        let dir = std::env::temp_dir().join(format!("diagtool-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files: Vec<Vec<u8>> = (0..200).map(|i| pattern(i as u8, 600)).collect();
        let slices: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
        let (disk, mut items) = laid_out(&slices, &[]);
        for (i, item) in items.iter_mut().enumerate() {
            item.name = format!("file{i}.bin");
        }
        let seen = Seen::default();
        let mut flusher = seen.clone();
        let mut wrap = writer::plain;
        let log_seen = seen.clone();
        let mut log = move |_file: File| -> Box<dyn Write + Send> { Box::new(log_seen.clone()) };
        let options = RecoverOptions {
            flush: FlushEvery {
                files: 50,
                ..FlushEvery::default()
            },
            ..RecoverOptions::default()
        };
        let outcome = recover_with(
            &mut Reader::new(Box::new(disk)),
            &items,
            &dir,
            &options,
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
            Hooks {
                wrap: &mut wrap,
                log: &mut log,
                flusher: Some(&mut flusher),
            },
        )
        .unwrap();
        let seen = seen.0.lock().unwrap().clone();
        let flushes = seen.iter().filter(|(f, p)| *f && p.is_empty()).count();
        assert!(
            (1..=200 / 10).contains(&flushes),
            "{flushes} flushes for 200 files"
        );
        let mut flushed = HashSet::new();
        let mut rows = 0;
        for (flush, text) in &seen {
            if *flush {
                flushed.insert(text.clone());
            } else if let Some((path, _)) = text
                .split_once('\t')
                .filter(|_| text.contains("read in full"))
            {
                rows += 1;
                assert!(
                    flushed.contains(&dir.join(path).display().to_string()),
                    "{path} was entered whole before a flush covered it"
                );
            }
        }
        assert_eq!(rows, 200);
        assert_eq!(outcome.complete(), 200);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (manual step 37): files under the source's System Volume Information are
    /// left out of the copy, neither failures nor rows, and the report says how many.
    #[test]
    fn system_volume_information_is_left_out() {
        let dir = std::env::temp_dir().join(format!("diagtool-svi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (disk, mut items) =
            laid_out(&[&pattern(1, 900), &pattern(2, 900), &pattern(3, 900)], &[]);
        items[0].name = "tracking.log".into();
        items[0].folder = vec!["System Volume Information".into()];
        items[1].name = "IndexerVolumeGuid".into();
        items[1].folder = vec!["system volume information".into(), "sub".into()];
        items[2].name = "kept.txt".into();
        items[2].folder = vec!["Users".into(), "System Volume Information".into()];
        let outcome = recover(
            &mut Reader::new(Box::new(disk)),
            &items,
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert_eq!((outcome.left_out, outcome.complete()), (2, 1));
        assert_eq!(
            sorted_files(&dir),
            ["Users\\System Volume Information\\kept.txt"]
        );
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        assert!(!report.contains("tracking.log") && !report.contains("IndexerVolumeGuid"));
        assert!(report.contains("Left out, under System Volume Information, which Windows keeps for itself: 2 files."), "{report}");
        assert!(!report.contains("Not made"), "{report}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A source that notes where each read starts.
    struct Noted {
        disk: crate::recovery::MemDisk,
        reads: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
    }

    impl crate::recovery::BlockSource for Noted {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            self.disk.sector_size()
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), crate::recovery::ReadError> {
            self.reads.lock().unwrap().push(offset);
            self.disk.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            "test disk".into()
        }
    }

    /// The guard (manual step 39): items are read in order of their first byte on the
    /// source, content held in a record first, whatever order they were chosen in; the
    /// report lists them in the order chosen. The pace says every file is done.
    #[test]
    fn files_are_read_in_order_of_their_place_on_the_source() {
        let dir = std::env::temp_dir().join(format!("diagtool-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files: Vec<Vec<u8>> = (0..6).map(|i| pattern(i, 3000)).collect();
        let slices: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
        let (disk, laid) = laid_out(&slices, &[]);
        // Chosen in another order: 3, 0, 5, 1, 4, 2, with a file held in its record.
        let mut items: Vec<Item> = [3, 0, 5, 1, 4, 2]
            .iter()
            .map(|&i| laid[i].clone())
            .collect();
        for (i, item) in items.iter_mut().enumerate() {
            item.name = format!("chosen{i}.bin");
        }
        items.push(Item {
            name: "resident.txt".into(),
            data: Data::Resident(b"held in the record".to_vec()),
            size: 18,
            ..items[0].clone()
        });
        let reads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut reader = Reader::new(Box::new(Noted {
            disk,
            reads: reads.clone(),
        }));
        let progress = Progress::default();
        let outcome = recover(
            &mut reader,
            &items,
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &progress,
        )
        .unwrap();
        assert_eq!(outcome.complete(), 7);
        let reads = reads.lock().unwrap().clone();
        assert_eq!(reads.len(), 6, "{reads:?}");
        assert!(
            reads.windows(2).all(|w| w[0] < w[1]),
            "read out of order: {reads:?}"
        );
        let made: Vec<usize> = outcome.ledger.outputs().iter().map(|o| o.tag).collect();
        assert_eq!(made[0], 6, "content in its record first: {made:?}");
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        let at: Vec<usize> = (0..6)
            .map(|i| report.find(&format!("chosen{i}.bin\t")).unwrap())
            .chain([report.find("resident.txt\t").unwrap()])
            .collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{report}");
        assert_eq!(progress.pace.files_done.load(Ordering::Relaxed), 7);
        assert_eq!(progress.pace.files_total.load(Ordering::Relaxed), 7);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Manual steps 33, 35 and 36: with the folders asked for, deleted files go under the
    /// deleted folder and files that end damaged under the damaged folder, each in its
    /// folders, a damaged picture with its preview and without "(partial)"; the source's
    /// recycle bin is named so Windows does not take it for the destination's own.
    #[test]
    fn deleted_damaged_and_recycled_files_go_where_asked() {
        use crate::recovery::preview::tests::{camera_jpeg, HOLIDAY, PHOTO};
        let camera = camera_jpeg(HOLIDAY, PHOTO, None);
        let gap = 4096 + 8192..4096 + 8704;
        let files = [
            camera.clone(),
            pattern(1, 700),
            pattern(2, 700),
            pattern(3, 700),
            pattern(4, 700),
        ];
        let slices: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
        let (disk, mut items) = laid_out(&slices, &[gap]);
        items[0].name = "IMG_1.jpg".into();
        items[0].folder = vec!["Photos".into()];
        items[1].name = "old.txt".into();
        items[1].folder = vec!["Photos".into()];
        items[1].deleted = true;
        items[2].name = "$R1X.txt".into();
        items[2].folder = vec!["$Recycle.Bin".into(), "S-1-5-21".into()];
        items[2].deleted = true;
        items[3].name = "record.doc".into();
        items[3].folder = vec!["Docs".into()];
        items[3].flaw = Some(FLAW.into());
        items[4].name = "plain.txt".into();
        items[4].folder = vec!["Docs".into()];
        let options = RecoverOptions {
            deleted_folder: Some("deleted".into()),
            damaged_folder: Some("repair_needed".into()),
            ..RecoverOptions::default()
        };
        let dir = std::env::temp_dir().join(format!("diagtool-folders-{}", std::process::id()));
        for options in [options, RecoverOptions::default()] {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let outcome = recover(
                &mut Reader::new(Box::new(crate::recovery::MemDisk {
                    data: disk.data.clone(),
                    bad: disk.bad.clone(),
                    ..crate::recovery::MemDisk::new(Vec::new())
                })),
                &items,
                &dir,
                &options,
                &Protected::default(),
                &AtomicBool::new(false),
                &Progress::default(),
            )
            .unwrap();
            assert_eq!((outcome.complete(), outcome.damaged()), (3, 2));
            let want: &[&str] = if options.damaged_folder.is_some() {
                &[
                    "Docs\\plain.txt",
                    "deleted\\Photos\\old.txt",
                    "deleted\\Recycle Bin (from the drive)\\S-1-5-21\\$R1X.txt",
                    "repair_needed\\Docs\\record.doc",
                    "repair_needed\\Photos\\IMG_1 (preview).jpg",
                    "repair_needed\\Photos\\IMG_1.jpg",
                ]
            } else {
                &[
                    "Docs\\plain.txt",
                    "Docs\\record.doc",
                    "Photos\\IMG_1 (partial).jpg",
                    "Photos\\IMG_1 (preview).jpg",
                    "Photos\\old.txt",
                    "Recycle Bin (from the drive)\\S-1-5-21\\$R1X.txt",
                ]
            };
            assert_eq!(sorted_files(&dir), want);
            let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
            if options.damaged_folder.is_some() {
                assert!(
                    report.contains(&format!(
                        "1 picture with missing parts under {}",
                        dir.join("repair_needed").display()
                    )),
                    "{report}"
                );
            }
            assert!(report.ends_with(END));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A fresh reader over a copy of `disk`.
    fn reader_of(disk: &crate::recovery::MemDisk) -> Reader<'static> {
        Reader::new(Box::new(crate::recovery::MemDisk {
            data: disk.data.clone(),
            bad: disk.bad.clone(),
            ..crate::recovery::MemDisk::new(Vec::new())
        }))
    }

    /// A new empty folder for a test.
    fn new_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("diagtool-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The guard (review F1): a file an earlier run left is kept only for the item whose
    /// bytes it holds, whatever its log row says. Two deleted items alike in path, state and
    /// size each keep their own copy, and a copy changed since at its size is left as it is
    /// while the item is copied again.
    #[test]
    fn an_earlier_file_is_kept_only_for_the_item_whose_bytes_it_holds() {
        let dir = new_dir("kept-own");
        let (disk, mut items) = laid_out(
            &[&pattern(1, 3000), &pattern(2, 3000), &pattern(3, 3000)],
            &[],
        );
        for item in &mut items[..2] {
            item.name = "twin.bin".into();
            item.deleted = true;
            item.state = "deleted, intact".into();
        }
        items[2].name = "changed.bin".into();
        items[2].state = "intact".into();
        let run = || {
            recover(
                &mut reader_of(&disk),
                &items,
                &dir,
                &RecoverOptions::default(),
                &Protected::default(),
                &AtomicBool::new(false),
                &Progress::default(),
            )
            .unwrap()
        };
        assert_eq!(run().complete(), 3);
        let mut changed = std::fs::read(dir.join("changed.bin")).unwrap();
        changed[100] ^= 0xff;
        std::fs::write(dir.join("changed.bin"), &changed).unwrap();
        let again = run();
        for (index, item) in items.iter().enumerate() {
            let o = again
                .ledger
                .outputs()
                .iter()
                .find(|o| o.tag == index)
                .unwrap();
            assert!(o.complete(), "{o:?}");
            assert!(
                std::fs::read(&o.path).unwrap() == expected(&disk, item),
                "{} took {}",
                item.name,
                o.path.display()
            );
        }
        assert_eq!(again.kept, 2);
        assert_eq!(std::fs::read(dir.join("changed.bin")).unwrap(), changed);
        assert_eq!(
            sorted_files(&dir),
            ["changed (2).bin", "changed.bin", "twin (2).bin", "twin.bin"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F2): a zero the source reads is data, so an earlier file that holds
    /// another byte there is neither kept nor written on from where it ends.
    #[test]
    fn a_zero_the_source_reads_is_compared_like_any_other_byte() {
        let dir = new_dir("zero-byte");
        let mut whole = pattern(1, 3000);
        whole[1000..1100].fill(0);
        let mut half = pattern(2, 3000);
        half[200..300].fill(0);
        let (disk, mut items) = laid_out(&[&whole, &half], &[]);
        items[0].name = "whole.bin".into();
        items[1].name = "half.bin".into();
        // At its size and at half of it, each differing only where the source reads zeros.
        let mut other = whole.clone();
        other[1050] = 0x55;
        std::fs::write(dir.join("whole.bin"), &other).unwrap();
        let mut short = half[..1500].to_vec();
        short[250] = 0x55;
        std::fs::write(dir.join("half.bin"), &short).unwrap();
        let outcome = recover(
            &mut reader_of(&disk),
            &items,
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        assert_eq!(
            (outcome.complete(), outcome.kept, outcome.resumed),
            (2, 0, 0)
        );
        assert_eq!(std::fs::read(dir.join("whole.bin")).unwrap(), other);
        assert_eq!(std::fs::read(dir.join("half.bin")).unwrap(), short);
        assert_eq!(std::fs::read(dir.join("whole (2).bin")).unwrap(), whole);
        assert_eq!(std::fs::read(dir.join("half (2).bin")).unwrap(), half);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A recovery with `options` of `items` from a copy of `disk` into `dir`.
    fn recover_into(
        dir: &Path,
        disk: &crate::recovery::MemDisk,
        items: &[Item],
        options: &RecoverOptions,
    ) -> Outcome {
        recover(
            &mut reader_of(disk),
            items,
            dir,
            options,
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap()
    }

    /// The entry this run made for item `index`.
    fn output_of(outcome: &Outcome, index: usize) -> &Output {
        outcome
            .ledger
            .outputs()
            .iter()
            .find(|o| o.tag == index && !o.note.starts_with(PREVIEW_NOTE))
            .unwrap()
    }

    /// The guard (review F1): a part an earlier run could not read, which the source reads
    /// now, is compared like any other, whatever the log says of it: the earlier file, zeros
    /// there, is left as it is and the item copied again whole.
    #[test]
    fn a_part_an_earlier_run_could_not_read_is_compared_once_it_reads() {
        let dir = new_dir("once-failed");
        let gap = 4096 + 1024..4096 + 1536;
        let (failing, mut items) = laid_out(&[&pattern(1, 6000)], std::slice::from_ref(&gap));
        items[0].name = "x.bin".into();
        let options = RecoverOptions::default();
        assert_eq!(recover_into(&dir, &failing, &items, &options).damaged(), 1);
        let earlier = std::fs::read(dir.join("x.bin")).unwrap();
        let mended = crate::recovery::MemDisk::new(failing.data.clone());
        let again = recover_into(&dir, &mended, &items, &options);
        assert_eq!((again.kept, again.complete(), again.damaged()), (0, 1, 0));
        assert_eq!(std::fs::read(dir.join("x.bin")).unwrap(), earlier);
        assert_eq!(
            std::fs::read(dir.join("x (2).bin")).unwrap(),
            expected(&mended, &items[0])
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F2): where the source cannot be read now the copy writes zeros, so
    /// an earlier file that holds anything else there is left as it is and the item copied
    /// again, whether the log names the file or not; the copy's unread parts are this run's.
    #[test]
    fn bytes_where_the_source_cannot_be_read_now_are_compared_with_zeros() {
        let dir = new_dir("unread-now");
        let gap = |at: u64| at + 1024..at + 1536;
        let (disk, mut items) = laid_out(
            &[&pattern(1, 8192), &pattern(2, 8192)],
            &[gap(4096), gap(4096 + 8192)],
        );
        items[0].name = "logged.bin".into();
        items[1].name = "unlogged.bin".into();
        let options = RecoverOptions::default();
        assert_eq!(recover_into(&dir, &disk, &items, &options).damaged(), 2);
        let mut earlier = Vec::new();
        for name in ["logged.bin", "unlogged.bin"] {
            let mut bytes = std::fs::read(dir.join(name)).unwrap();
            bytes[1200] = 0x55;
            std::fs::write(dir.join(name), &bytes).unwrap();
            earlier.push(bytes);
        }
        let log = std::fs::read_to_string(dir.join(LOG_NAME)).unwrap();
        let kept: Vec<&str> = log
            .split("\r\n")
            .filter(|l| !l.contains("unlogged.bin"))
            .collect();
        std::fs::write(dir.join(LOG_NAME), kept.join("\r\n")).unwrap();
        let again = recover_into(&dir, &disk, &items, &options);
        assert_eq!((again.kept, again.damaged()), (0, 2));
        for (index, name) in ["logged", "unlogged"].iter().enumerate() {
            assert_eq!(
                std::fs::read(dir.join(format!("{name}.bin"))).unwrap(),
                earlier[index]
            );
            let o = output_of(&again, index);
            assert_eq!(o.path, dir.join(format!("{name} (2).bin")));
            assert_eq!(o.zeroed, std::iter::once(0..4096).collect::<Vec<_>>());
            assert_eq!(
                std::fs::read(&o.path).unwrap(),
                expected(&disk, &items[index])
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F1): a file at the item's name that holds only the start of the
    /// item, an empty one too, and that no earlier run's log names as cut short, may be
    /// anyone's: it is never written on, and the item is copied whole under the next name.
    #[test]
    fn a_file_holding_the_start_of_an_item_is_finished_only_when_the_log_names_it() {
        let dir = new_dir("start-only");
        let (disk, mut items) = laid_out(&[&pattern(1, 3000), &pattern(2, 3000)], &[]);
        items[0].name = "a.bin".into();
        items[1].name = "b.bin".into();
        let start = expected(&disk, &items[0])[..1500].to_vec();
        std::fs::write(dir.join("a.bin"), &start).unwrap();
        std::fs::write(dir.join("b.bin"), b"").unwrap();
        let outcome = recover_into(&dir, &disk, &items, &RecoverOptions::default());
        assert_eq!(
            (outcome.complete(), outcome.kept, outcome.resumed),
            (2, 0, 0)
        );
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), start);
        assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b"");
        for (index, item) in items.iter().enumerate() {
            assert_eq!(
                std::fs::read(&output_of(&outcome, index).path).unwrap(),
                expected(&disk, item)
            );
        }
        assert_eq!(
            sorted_files(&dir),
            ["a (2).bin", "a.bin", "b (2).bin", "b.bin"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F1): an earlier file is kept only where this run puts the item. A
    /// copy under the deleted folder, the damaged folder or a kind's folder, the same byte
    /// for byte, is left as it is when this run lays the item out otherwise or the item is
    /// no longer deleted, and the item copied again; laid out as before, each is kept.
    #[test]
    fn an_earlier_file_is_kept_only_where_this_run_puts_the_item() {
        let dir = new_dir("routed");
        let (disk, mut items) = laid_out(
            &[&pattern(1, 6000), &pattern(2, 6000), &pattern(3, 6000)],
            std::slice::from_ref(&(4096 + 8192 + 1024..4096 + 8192 + 1536)),
        );
        items[0].name = "gone.bin".into();
        items[0].deleted = true;
        items[1].name = "torn.bin".into();
        items[2].name = "plain.txt".into();
        let sorted = RecoverOptions {
            layout: Layout::ByType,
            deleted_folder: Some("deleted".into()),
            damaged_folder: Some("repair".into()),
            ..RecoverOptions::default()
        };
        let first = recover_into(&dir, &disk, &items, &sorted);
        assert_eq!((first.complete(), first.damaged()), (2, 1));
        let earlier = [
            "deleted\\Other\\gone.bin",
            "repair\\Other\\torn.bin",
            "Documents\\plain.txt",
        ];
        assert_eq!(sorted_files(&dir), {
            let mut want = earlier.to_vec();
            want.sort();
            want
        });
        let held: Vec<Vec<u8>> = earlier
            .iter()
            .map(|p| std::fs::read(dir.join(p)).unwrap())
            .collect();
        let again = recover_into(&dir, &disk, &items, &RecoverOptions::default());
        assert_eq!((again.kept, again.complete(), again.damaged()), (0, 2, 1));
        for (index, path) in ["gone.bin", "torn.bin", "plain.txt"].iter().enumerate() {
            assert_eq!(output_of(&again, index).path, dir.join(path));
        }
        for (path, bytes) in earlier.iter().zip(&held) {
            assert_eq!(&std::fs::read(dir.join(path)).unwrap(), bytes, "{path}");
        }
        // Laid out as the first run was, each of its files is kept where it is.
        let third = recover_into(&dir, &disk, &items, &sorted);
        assert_eq!(third.kept, 3);
        for (index, path) in earlier.iter().enumerate() {
            assert_eq!(output_of(&third, index).path, dir.join(path));
        }
        // The deleted file found live now goes under its kind, not the deleted folder.
        items[0].deleted = false;
        let live = recover_into(&dir, &disk, &items, &sorted);
        assert_eq!(live.kept, 2);
        assert_eq!(output_of(&live, 0).path, dir.join("Other\\gone.bin"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F1): an older log's row that names only the first eight of a
    /// file's unread parts, ending ", ...", needs nothing of its own. The file is kept only
    /// when it holds zeros at every part the source cannot be read now, and with this run's
    /// parts, all nine; one holding another byte in its ninth is left as it is.
    #[test]
    fn a_log_row_naming_only_some_unread_parts_needs_nothing_of_its_own() {
        let dir = new_dir("nine-parts");
        let size = 9 * 8192u64;
        let bad = |at: u64| (0..9).map(move |i| at + i * 8192..at + i * 8192 + 512);
        let (disk, mut items) = laid_out(
            &[&pattern(1, size as usize), &pattern(2, size as usize)],
            &bad(4096).chain(bad(4096 + size)).collect::<Vec<_>>(),
        );
        items[0].name = "kept.bin".into();
        items[1].name = "changed.bin".into();
        let options = RecoverOptions::default();
        assert_eq!(recover_into(&dir, &disk, &items, &options).damaged(), 2);
        let log = std::fs::read_to_string(dir.join(LOG_NAME)).unwrap();
        assert_eq!(log.matches(", ...)").count(), 2, "{log}");
        let mut changed = std::fs::read(dir.join("changed.bin")).unwrap();
        changed[8 * 8192 + 100] = 0x55;
        std::fs::write(dir.join("changed.bin"), &changed).unwrap();
        let again = recover_into(&dir, &disk, &items, &options);
        assert_eq!((again.kept, again.damaged()), (1, 2));
        let parts: Vec<Range<u64>> = (0..9).map(|i| i * 8192..i * 8192 + 4096).collect();
        let kept = output_of(&again, 0);
        assert_eq!(
            (kept.path.clone(), kept.zeroed.clone()),
            (dir.join("kept.bin"), parts.clone())
        );
        let copied = output_of(&again, 1);
        assert_eq!(
            (copied.path.clone(), copied.zeroed.clone()),
            (dir.join("changed (2).bin"), parts)
        );
        assert_eq!(std::fs::read(dir.join("changed.bin")).unwrap(), changed);
        assert_eq!(
            std::fs::read(&copied.path).unwrap(),
            expected(&disk, &items[1])
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The names a resume takes a file at are exactly those this run gives: the item's,
    /// numbered from 2, with " (partial)" for a damaged picture, in any case; no other.
    #[test]
    fn a_name_is_the_item_s_only_as_this_run_names_it() {
        for base in ["IMG_1.jpg", "notes", ".bashrc", "v1.2.tar"] {
            for partial in [false, true] {
                for name in names_for(base, partial).take(12) {
                    assert!(is_named(&name, base, partial), "{name}");
                    assert!(is_named(&name.to_uppercase(), base, partial), "{name}");
                    assert!(!is_named(&name, base, !partial), "{name}");
                }
            }
        }
        for name in [
            "IMG_10.jpg",
            "IMG_1 (1).jpg",
            "IMG_1 (02).jpg",
            "IMG_1 (+2).jpg",
            "IMG_1 (2) (2).jpg",
            "IMG_1 (10000).jpg",
            "IMG_1.jpg.jpg",
            "IMG_1 (partial) (2).jpg",
        ] {
            assert!(!is_named(name, "IMG_1.jpg", false), "{name}");
            assert!(!is_named(name, "IMG_1.jpg", true), "{name}");
        }
    }

    /// What a recovery's flushes were given, by raw handle.
    #[derive(Clone, Default)]
    struct Handles(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);

    impl writer::Flusher for Handles {
        fn flush(&mut self, files: &[(&Path, &File)]) -> std::io::Result<()> {
            use std::os::windows::io::AsRawHandle;
            let mut flushed = self.0.lock().unwrap();
            flushed.extend(files.iter().map(|(_, f)| f.as_raw_handle() as usize));
            Ok(())
        }
    }

    /// The guard (review F3): every file, the report included, is flushed through the handle
    /// it was written through, so no file can be entered whole for want of a second handle;
    /// and output is entered whole by `writer::end_flushed` alone, after a flush.
    #[test]
    fn each_file_is_flushed_through_the_handle_it_was_written_through() {
        use std::os::windows::io::AsRawHandle;
        let dir = new_dir("handles");
        let (disk, items) = laid_out(&[&pattern(1, 900), &pattern(2, 900), &pattern(3, 900)], &[]);
        let flushed = Handles::default();
        let mut flusher = flushed.clone();
        let mut written = Vec::new();
        let outcome = recover_with(
            &mut reader_of(&disk),
            &items,
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
            Hooks {
                wrap: &mut |file| {
                    written.push(file.as_raw_handle() as usize);
                    Box::new(file)
                },
                log: &mut plain_log,
                flusher: Some(&mut flusher),
            },
        )
        .unwrap();
        assert_eq!(outcome.complete(), 3);
        assert!(outcome.report_error.is_none());
        let flushed = flushed.0.lock().unwrap().clone();
        assert_eq!(written.len(), 4, "three files and the report");
        assert!(
            written.iter().all(|h| flushed.contains(h)),
            "written through {written:?}, flushed {flushed:?}"
        );
        for (name, code, calls) in [
            ("output.rs", include_str!("output.rs"), 0),
            ("writer.rs", include_str!("writer.rs"), 1),
        ] {
            let code = &code[..code.find("#[cfg(test)]").unwrap()];
            assert_eq!(code.matches(".whole(").count(), calls, "{name}");
        }
        let writer = include_str!("writer.rs");
        let end = &writer[writer.find("pub fn end_flushed(").unwrap()..];
        assert!(end[..end.find("\n}\n").unwrap()].contains("ledger.whole(id)"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F4): a damaged file that cannot be moved into the damaged folder
    /// stays where it is, and its rows in the report and the log name that place and say the
    /// move failed; the report does not count it as under the folder.
    #[test]
    fn a_damaged_file_that_cannot_be_moved_is_reported_where_it_is() {
        use crate::recovery::preview::tests::{camera_jpeg, HOLIDAY, PHOTO};
        let dir = new_dir("unmoved");
        let camera = camera_jpeg(HOLIDAY, PHOTO, None);
        let gap = 4096 + 8192..4096 + 8704;
        let (disk, mut items) = laid_out(&[&camera, &pattern(1, 700)], &[gap]);
        items[0].name = "IMG_1.jpg".into();
        items[0].folder = vec!["Photos".into()];
        items[1].name = "record.doc".into();
        items[1].folder = vec!["Docs".into()];
        items[1].flaw = Some(FLAW.into());
        // A file where the damaged folder must go, so it cannot be made.
        std::fs::write(dir.join("repair_needed"), b"x").unwrap();
        let options = RecoverOptions {
            damaged_folder: Some("repair_needed".into()),
            ..RecoverOptions::default()
        };
        let outcome = recover(
            &mut reader_of(&disk),
            &items,
            &dir,
            &options,
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        assert_eq!(outcome.damaged(), 2);
        assert_eq!(
            sorted_files(&dir),
            [
                "Docs\\record.doc",
                "Photos\\IMG_1 (preview).jpg",
                "Photos\\IMG_1.jpg",
                "repair_needed"
            ]
        );
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        let log = std::fs::read_to_string(dir.join(LOG_NAME)).unwrap();
        for row in ["Photos\\IMG_1.jpg\t", "Docs\\record.doc\t"] {
            for text in [&report, &log] {
                let line = text.lines().find(|l| l.starts_with(row)).unwrap();
                assert!(
                    line.contains("DAMAGED: ")
                        && line.contains(
                            "; it could not be moved under repair_needed, so it is here: "
                        ),
                    "{line}"
                );
            }
        }
        assert!(
            report.contains(
                "1 of them could not be put so; the rows above say where each is and why."
            ),
            "{report}"
        );
        // A preview found and not written says why, not that none was found.
        let mut shown = Outcome::default();
        let id = shown
            .ledger
            .made(0, dir.join("a.jpg"), "a.jpg".into(), String::new(), 100);
        shown.ledger.zeroed(id, std::iter::once(10..20).collect());
        shown.ledger.whole(id);
        shown.pictures.push(Salvaged {
            output: id,
            preview: Preview::NotSaved(
                crate::recovery::preview::Source::ExifThumbnail,
                "it could not be made: access denied".into(),
            ),
        });
        let line = picture_line(&shown, &shown.pictures[0], &dir);
        assert!(
            line.ends_with(
                "its EXIF thumbnail could not be saved: it could not be made: access denied"
            ),
            "{line}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F5): a record whose data is shorter than the file's size is written
    /// to its size, the rest as zeros and the file damaged, never short and whole; and a
    /// flushed entry that holds less than its size ends partial.
    #[test]
    fn a_short_record_is_written_to_its_size_and_never_entered_whole_short() {
        let dir = new_dir("short-record");
        let item = Item {
            name: "short.txt".into(),
            folder: Vec::new(),
            size: 20,
            data: Data::Resident(b"held".to_vec()),
            state: "intact".into(),
            deleted: false,
            flaw: None,
        };
        let outcome = recover(
            &mut Reader::new(Box::new(crate::recovery::MemDisk::new(vec![0u8; 4096]))),
            std::slice::from_ref(&item),
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        let o = &outcome.ledger.outputs()[0];
        assert!(
            o.damaged() && o.zeroed == std::slice::from_ref(&(4..20)),
            "{o:?}"
        );
        let mut want = b"held".to_vec();
        want.resize(20, 0);
        assert_eq!(std::fs::read(&o.path).unwrap(), want);
        // At the boundary itself: a flush does not make a file short of its size whole.
        let mut ledger = Ledger::default();
        let id = ledger.made(0, dir.join("cut.bin"), "cut.bin".into(), String::new(), 10);
        ledger.wrote(id, 4);
        let mut flusher = Seen::default();
        let mut batch = Batch {
            every: FlushEvery::default(),
            flusher: &mut flusher,
            pending: Vec::new(),
            bytes: 0,
            since: Instant::now(),
        };
        batch.add(id, File::create(dir.join("cut.bin")).unwrap(), 4);
        batch.flush(&mut ledger);
        assert_eq!(
            ledger.get(id).condition(),
            "PARTIAL: it holds 4 of its 10 bytes"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A flusher that fails any flush that covers the report.
    #[derive(Clone, Default)]
    struct ReportUnflushed(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl writer::Flusher for ReportUnflushed {
        fn flush(&mut self, files: &[(&Path, &File)]) -> std::io::Result<()> {
            let mut seen = self.0.lock().unwrap();
            seen.extend(files.iter().map(|(p, _)| p.display().to_string()));
            if files
                .iter()
                .any(|(p, _)| p.ends_with("Recovery report.txt"))
            {
                return Err(std::io::Error::other("the report's flush failed"));
            }
            Ok(())
        }
    }

    /// The guard (review F6): the report is entered whole only once a flush of the
    /// destination covers it, and a failed one leaves it partial with the reason, which the
    /// outcome gives.
    #[test]
    fn the_report_is_entered_whole_only_once_a_flush_covers_it() {
        let dir = new_dir("report-flush");
        let (disk, items) = laid_out(&[&pattern(1, 900)], &[]);
        let seen = ReportUnflushed::default();
        let mut flusher = seen.clone();
        let outcome = recover_with(
            &mut reader_of(&disk),
            &items,
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
            Hooks {
                wrap: &mut writer::plain,
                log: &mut plain_log,
                flusher: Some(&mut flusher),
            },
        )
        .unwrap();
        assert_eq!(outcome.complete(), 1);
        let report = &outcome.ledger.outputs()[outcome.report_entry.unwrap()];
        assert!(report.partial(), "{report:?}");
        assert!(
            outcome
                .report_error
                .as_deref()
                .is_some_and(|e| e.contains("the report's flush failed")),
            "{:?}",
            outcome.report_error
        );
        let path = outcome.report.as_ref().unwrap().display().to_string();
        assert!(seen.0.lock().unwrap().contains(&path));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F9): a run a damaged record places past where any source reaches is
    /// unreadable, written as zeros with the file damaged, never a read at a wrapped offset.
    #[test]
    fn a_run_past_any_source_is_unreadable_and_never_wraps() {
        let dir = new_dir("wrapping-run");
        let size = 2 * CHUNK + 5;
        let item = Item {
            name: "far.bin".into(),
            folder: Vec::new(),
            size,
            data: Data::Runs(vec![Run {
                place: Place::At(u64::MAX - 100),
                len: size,
            }]),
            state: "intact".into(),
            deleted: false,
            flaw: None,
        };
        let outcome = recover(
            &mut Reader::new(Box::new(crate::recovery::MemDisk::new(vec![9u8; 8192]))),
            std::slice::from_ref(&item),
            &dir,
            &RecoverOptions::default(),
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        let o = &outcome.ledger.outputs()[0];
        assert!(
            o.damaged() && o.zeroed == std::slice::from_ref(&(0..size)),
            "{o:?}"
        );
        let held = std::fs::read(&o.path).unwrap();
        assert!(held.len() as u64 == size && held.iter().all(|b| *b == 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
