//! The one writer of recovery output. Every file a recovery tool makes is made here,
//! through the destination guard (`dest.rs`) relative to a checked folder handle, and
//! entered in a ledger before a byte is written; bytes written from memory go through
//! `ledger::write_counted`, so a write that fails part way leaves the ledger saying what the
//! file holds, and each entry ends whole, damaged, partial or removed.
//!
//! Three files are made here but kept outside a ledger entry, each because something finer
//! already says what it holds: a rescue image, whose map records every byte as rescued,
//! unreadable or untried (`open_image`); the map itself, written whole to a scratch file and
//! renamed over the old one, so a failed save leaves the last good map (`save_map`); and a
//! rescue copy's or a recovery's log, which is the ledger's own output (`create_log`,
//! `open_log`). A health log beside an image keeps its own ledger (`open_beside`,
//! `health_log.rs`).
//!
//! One kind of file is opened again for writing: a recovery's output that an earlier run
//! into the same folder left cut short, taken once the caller has checked that it holds
//! nothing the new copy will not (`open_earlier`, `take_earlier`).
//!
//! The guard below fails if any other recovery file makes a file itself.
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::dest::{self, Folder, Guard};
use super::ledger::{write_counted, Ledger};

/// The tag of a report's own ledger entry: it names no item.
pub const REPORT_TAG: usize = usize::MAX;

/// What a new file is entered in the ledger as.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The caller's own index for it, such as the item it was copied from.
    pub tag: usize,
    /// What it was copied from, for people.
    pub source: PathBuf,
    /// What the source said of it, such as "deleted, intact".
    pub note: String,
    /// The size it should reach.
    pub size: u64,
}

/// A file made and entered: its handle, where it is, and its ledger entry.
#[derive(Debug)]
pub struct Made {
    pub file: File,
    pub path: PathBuf,
    pub id: usize,
}

/// Makes a new file `name` in `folder`, or "name (2).ext" and so on when it is taken, and
/// enters it in `ledger` at once. Nothing that exists is ever opened for writing.
pub fn create(
    guard: &Guard,
    folder: &Folder,
    name: &str,
    ledger: &mut Ledger,
    entry: Entry,
) -> io::Result<Made> {
    let (file, path) = create_unique(guard, folder, name)?;
    let id = ledger.made(
        entry.tag,
        path.clone(),
        entry.source,
        entry.note,
        entry.size,
    );
    Ok(Made { file, path, id })
}

/// Opens `name` in `folder`, a file an earlier run left, for reading and writing, without
/// entering it: the caller checks it first and enters it with `take_earlier` or leaves it.
pub fn open_earlier(guard: &Guard, folder: &Folder, name: &OsStr) -> io::Result<File> {
    guard.open_earlier(folder, name)
}

/// Enters a file opened by `open_earlier` in `ledger` as made, to be written from where its
/// handle stands.
pub fn take_earlier(file: File, path: PathBuf, ledger: &mut Ledger, entry: Entry) -> Made {
    let id = ledger.made(
        entry.tag,
        path.clone(),
        entry.source,
        entry.note,
        entry.size,
    );
    Made { file, path, id }
}

/// Makes a new file named exactly `name` in `folder` and enters it in `ledger` at once; a
/// name already taken is an error, never opened.
pub fn create_exact(
    guard: &Guard,
    folder: &Folder,
    name: &OsStr,
    ledger: &mut Ledger,
    entry: Entry,
) -> io::Result<Made> {
    let file = guard.create_new(folder, name)?;
    let path = folder.path().join(name);
    let id = ledger.made(
        entry.tag,
        path.clone(),
        entry.source,
        entry.note,
        entry.size,
    );
    Ok(Made { file, path, id })
}

/// Writes all of `data` into the file `made`, counted into its entry, then makes it durable;
/// the entry ends whole, or partial at what was written. Returns why it ended short.
pub fn write_whole(made: &mut Made, data: &[u8], ledger: &mut Ledger) -> Result<(), String> {
    let id = made.id;
    let mut at = 0u64;
    let written = write_counted(&mut made.file, data, &mut |n| {
        at = n;
        ledger.wrote(id, n);
    });
    if let Err(e) = written.and_then(|()| made.file.flush()) {
        let why = format!("writing it failed after {at} bytes: {e}");
        ledger.partial(id, why.clone());
        return Err(why);
    }
    end_flushed(ledger, id, &made.file.sync_data()).map_or(Ok(()), Err)
}

/// Ends entry `id` once `flushed`, a flush that covered its file after its last write, has
/// ended: whole only when the flush succeeded and the entry holds every byte of its size,
/// else partial. Returns why it is not whole. This writer and a recovery of listed items
/// end an entry whole here and nowhere else.
pub fn end_flushed(ledger: &mut Ledger, id: usize, flushed: &io::Result<()>) -> Option<String> {
    let o = ledger.get(id);
    let why = match flushed {
        Err(e) => format!("it could not be made durable on the destination: {e}"),
        Ok(()) if o.at != o.size => format!("it holds {} of its {} bytes", o.at, o.size),
        Ok(()) => {
            ledger.whole(id);
            return None;
        }
    };
    ledger.partial(id, why.clone());
    Some(why)
}

/// Writes all of `data` into the file `made`, counted into its entry, which stays open: a
/// flush that covers it ends it whole (`Flusher`), and on a failed write, whose reason is
/// returned, the caller ends it, partial or removed.
pub fn write_pending(made: &mut Made, data: &[u8], ledger: &mut Ledger) -> Result<(), String> {
    let id = made.id;
    let mut at = 0u64;
    let written = write_counted(&mut made.file, data, &mut |n| {
        at = n;
        ledger.wrote(id, n);
    });
    written.map_err(|e| format!("writing it failed after {at} bytes: {e}"))
}

/// Makes files written so far durable on the destination, many at a time.
pub trait Flusher {
    /// Makes `files`, by path and handle, durable.
    fn flush(&mut self, files: &[(&Path, &File)]) -> io::Result<()>;
}

/// The destination's flusher: one flush of its volume's cache when the volume can be opened
/// for it (administrator rights), else a flush of each file's.
pub struct ToDisk {
    volume: Option<File>,
}

impl ToDisk {
    /// For files made below `base`.
    pub fn new(base: &Folder) -> Self {
        Self {
            volume: dest::volume_to_flush(base).ok(),
        }
    }

    /// A flush of each file's alone, for a run that makes one or two files.
    pub fn per_file() -> Self {
        Self { volume: None }
    }
}

impl Flusher for ToDisk {
    fn flush(&mut self, files: &[(&Path, &File)]) -> io::Result<()> {
        if let Some(volume) = &self.volume {
            if volume.sync_all().is_ok() {
                return Ok(());
            }
            self.volume = None;
        }
        files.iter().try_for_each(|(_, file)| file.sync_data())
    }
}

/// Removes a file `made` that is not to be kept, and ends its entry removed for `why`;
/// a file that cannot be removed ends partial, saying so.
pub fn discard(made: Made, ledger: &mut Ledger, why: &str) {
    let id = made.id;
    match dest::remove(made.file) {
        Ok(()) => ledger.removed(id, why.to_string()),
        Err(e) => ledger.partial(id, format!("{why}, and it could not be removed: {e}")),
    }
}

/// A report file as `write_report_file` left it.
#[derive(Debug, Default)]
pub struct ReportFile {
    pub path: Option<PathBuf>,
    /// Its ledger entry, once it was made.
    pub entry: Option<usize>,
    /// Why it could not be made or written to its end.
    pub error: Option<String>,
}

/// Writes `text`, a report already rendered, into a new file `name` in `folder` through
/// `out`, a writer over the file made, then makes it durable through `flusher`. The file is
/// entered in `ledger` before a byte is written, tagged `REPORT_TAG`, and ends whole, or
/// partial at what was written.
pub fn write_report_file(
    guard: &Guard,
    folder: &Folder,
    name: &str,
    text: &[u8],
    ledger: &mut Ledger,
    out: &mut Wrap<'_>,
    flusher: &mut dyn Flusher,
) -> ReportFile {
    let entry = Entry {
        tag: REPORT_TAG,
        source: PathBuf::new(),
        note: "the report of this run".into(),
        size: text.len() as u64,
    };
    let made = match create(guard, folder, name, ledger, entry) {
        Ok(made) => made,
        Err(e) => {
            return ReportFile {
                error: Some(format!("it could not be made: {e}")),
                ..ReportFile::default()
            }
        }
    };
    let id = made.id;
    let mut at = 0u64;
    let written = {
        let mut out = out(&made.file);
        write_counted(out.as_mut(), text, &mut |n| {
            at = n;
            ledger.wrote(id, n);
        })
        .and_then(|()| out.flush())
    };
    let error = match written {
        Ok(()) => {
            let flushed = flusher.flush(&[(&made.path, &made.file)]);
            end_flushed(ledger, id, &flushed)
        }
        Err(e) => {
            let why = format!("writing it failed after {at} bytes: {e}");
            ledger.partial(id, why.clone());
            Some(why)
        }
    };
    ReportFile {
        path: Some(made.path),
        entry: Some(id),
        error,
    }
}

/// What every write to an output file goes through: a writer over the file's own handle, so
/// the handle a flush is given is the one written through.
pub type Wrap<'a> = dyn for<'f> FnMut(&'f File) -> Box<dyn Write + 'f> + 'a;

/// A writer straight to the file.
pub fn plain(file: &File) -> Box<dyn Write + '_> {
    Box::new(file)
}

/// Writes a report that is a run's only output into a new file `name` in `folder`, with a
/// ledger of its own: where it is, and how it ended, "read in full" or "PARTIAL: why".
pub fn write_lone_report(
    guard: &Guard,
    folder: &Folder,
    name: &str,
    text: &[u8],
) -> (ReportFile, Option<String>) {
    let mut ledger = Ledger::default();
    let made = write_report_file(
        guard,
        folder,
        name,
        text,
        &mut ledger,
        &mut plain,
        &mut ToDisk::per_file(),
    );
    let ended = made.entry.map(|id| ledger.get(id).condition());
    (made, ended)
}

/// Checks a file Windows itself made in `folder` (a differencing disk), entered in `ledger`
/// first, so however the check ends it is listed: its id and volume serial and file id.
pub fn adopt(
    guard: &Guard,
    folder: &Folder,
    name: &OsStr,
    ledger: &mut Ledger,
    entry: Entry,
) -> (usize, io::Result<(u64, [u8; 16])>) {
    let id = ledger.made(
        entry.tag,
        folder.path().join(name),
        entry.source,
        entry.note,
        entry.size,
    );
    (id, guard.adopt(folder, name))
}

/// Makes a rescue image `name` in `folder`, or, when resuming, opens the one a stopped run
/// left. Its map, not a ledger entry, says what it holds.
pub fn open_image(guard: &Guard, folder: &Folder, name: &OsStr, resumed: bool) -> io::Result<File> {
    if resumed {
        guard.open_existing(folder, name)
    } else {
        guard.create_new(folder, name)
    }
}

/// Saves a rescue map: `text` counted into a scratch file "name.new", made durable, then
/// renamed over `name`, so a save that fails leaves the last good map.
pub fn save_map(
    guard: &Guard,
    folder: &Folder,
    name: &OsStr,
    text: &[u8],
    patient: bool,
) -> Result<(), MapNotSaved> {
    let mut temp = name.to_os_string();
    temp.push(".new");
    let mut file = guard.create_scratch(folder, &temp)?;
    write_counted(&mut file, text, &mut |_| {})?;
    file.sync_all()?;
    // Another program reading the map without sharing delete (a virus scanner, an indexer,
    // a watcher) refuses the rename for as long as it holds it. A `patient` save (the first
    // and the last of a run) waits for it; a timed save tries once, and its caller carries
    // on (`Rescue::save_timed`). The 2026-11-09 rescue ended so at 600 GB.
    let mut tries = 0;
    loop {
        match dest::rename_over(&file, folder, name) {
            Err(e) if patient && refused(&e) && tries < SAVE_TRIES => {
                tries += 1;
                std::thread::sleep(SAVE_WAIT);
            }
            Err(e) => {
                return Err(MapNotSaved {
                    held: refused(&e),
                    error: e,
                })
            }
            Ok(()) => return Ok(()),
        }
    }
}

/// Why a map was not saved. `held` only when the rename over the map was refused because
/// another program holds it, which passes; a failure to make, write or sync the scratch
/// file is never that, whatever its code.
#[derive(Debug)]
pub struct MapNotSaved {
    pub error: io::Error,
    pub held: bool,
}

impl From<io::Error> for MapNotSaved {
    fn from(error: io::Error) -> Self {
        Self { error, held: false }
    }
}

impl std::fmt::Display for MapNotSaved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

/// How often, and how far apart, a refused map save is tried again: 10 s in all.
const SAVE_TRIES: u32 = 20;
const SAVE_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// Whether a rename was refused because another program holds the file: access denied or
/// a sharing violation.
fn refused(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(5 | 32))
}

/// Opens a file beside a rescue image through the same checks: made new, or, when a stopped
/// run left one, opened to be added to. A health log, which keeps its own ledger.
pub fn open_beside(guard: &Guard, folder: &Folder, name: &OsStr) -> io::Result<File> {
    match guard.create_new(folder, name) {
        // The creating handle holds DELETE access (to remove a file the guard refuses). Held
        // for the run, it would refuse every reader that does not share delete, such as a
        // watcher tailing the events log, so it is swapped for one without it.
        Ok(created) => {
            drop(created);
            guard.open_existing(folder, name)
        }
        Err(_) => guard.open_existing(folder, name),
    }
}

/// Makes a rescue copy's log, the file its ledger writes each row to as a file ends.
pub fn create_log(guard: &Guard, folder: &Folder, name: &OsStr) -> io::Result<File> {
    guard.create_new(folder, name)
}

/// Makes a recovery's log, or opens the one an earlier run into the folder left to be added
/// to; returns it, positioned at its end, with what it held.
pub fn open_log(guard: &Guard, folder: &Folder, name: &OsStr) -> io::Result<(File, Vec<u8>)> {
    match guard.create_new(folder, name) {
        Ok(file) => Ok((file, Vec::new())),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let mut file = guard.open_existing(folder, name)?;
            let mut held = Vec::new();
            file.read_to_end(&mut held)?;
            Ok((file, held))
        }
        Err(e) => Err(e),
    }
}

/// The names a file `name` is given in turn when one is taken: "name.ext", "name (2).ext"
/// and so on.
pub fn names(name: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    (1..10_000).map(move |n| {
        if n == 1 {
            name.to_string()
        } else {
            format!("{stem} ({n}){ext}")
        }
    })
}

/// Creates a new file `name` in `folder`, or "name (2).ext" and so on when it is taken,
/// made through the folder's handle and checked by `guard`.
fn create_unique(guard: &Guard, folder: &Folder, name: &str) -> io::Result<(File, PathBuf)> {
    for candidate in names(name) {
        match guard.create_new(folder, OsStr::new(&candidate)) {
            Ok(file) => return Ok((file, folder.path().join(candidate))),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("too many files with this name"))
}

#[cfg(test)]
mod tests;
