//! Windows Explorer's thumbnail caches: `thumbcache_*.db` in each user's
//! `AppData\Local\Microsoft\Windows\Explorer`, which hold small copies of pictures that were
//! viewed in Explorer, sometimes the only copy left. Each cache (Windows Vista's format 20,
//! Windows 7's 21, and Windows 8 to 11's 30 to 32) is a "CMMM" header and entries, each with
//! a hash, sizes and a JPEG, PNG or BMP. The caches are read through the file system readers
//! from the source, deleted ones included, or from a copy; every image in them is written to
//! `Thumbnails <date>\<cache>\<hash>.<type>`, entered in the ledger, with a report.
//!
//! The engine is `run`; the recovery window only builds its options and shows its events.
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use super::dest::{Folder, Guard};
use super::fs::{self, parts, Data, Found, Place};
use super::ledger::{files, Ledger};
use super::output::{safe_name, COMPLETE_IF, END};
use super::reader::{merge, Reader, CHUNK};
use crate::budget::{Budget, Limit, Limits};

/// The largest image taken from an entry.
const DATA_MAX: u64 = 64 << 20;
/// The largest cache read.
const CACHE_MAX: u64 = 16 << 30;

/// What a walk of one thumbnail cache may spend: 250,000 entries, each an image written as
/// a file, where Explorer's largest caches hold tens of thousands; twice `CACHE_MAX` read,
/// for the entries and the search past damage for the next one, each byte at most twice;
/// one entry's image held while it is written (up to `DATA_MAX`, charged before it is made)
/// and 64 MiB for the record of unreadable parts. No clock limit: the technician starts
/// the run and watches it with a Stop button, checked at every entry and every piece of a
/// search.
pub const LIMITS: Limits = Limits {
    what: "the read of the thumbnail cache",
    unit: "entries",
    count: 250_000,
    bytes: 2 * CACHE_MAX,
    memory: DATA_MAX + (64 << 20),
    depth: 0,
    nested: "parts",
    time: None::<std::time::Duration>,
};

/// What `run` does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    /// The folder the "Thumbnails <date>" folder is made in; never on `source_disk`.
    pub destination: PathBuf,
    /// The volumes searched for caches, by their start in bytes on the source; empty for
    /// every volume in the source's partition tables.
    pub volumes: Vec<u64>,
    /// Deleted cache files are read too.
    pub include_deleted: bool,
    /// Cache files already on a readable drive (copies), read as they are, besides any on
    /// the source.
    pub files: Vec<PathBuf>,
    /// The disk being recovered, when the source is one: nothing is written on it.
    pub source_disk: crate::recovery::dest::Protected,
}

/// What `run` reports as it goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// What it is doing, for people: "Reading the volume's files".
    Phase(String),
    /// Cache `index` (from 0) of `of` is being read.
    Cache {
        index: usize,
        of: usize,
        name: String,
    },
    /// Bytes of all caches read so far, of their total, and images written.
    Progress { done: u64, total: u64, images: u64 },
    /// Something a person should know.
    Warning(String),
}

/// What one cache gave.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheResult {
    /// "thumbcache_256.db".
    pub name: String,
    /// Where it was: "\Users\Ann\AppData\...\thumbcache_256.db" on the source, or a path.
    pub from: String,
    pub deleted: bool,
    /// The user folder it was in, when known.
    pub user: Option<String>,
    pub size: u64,
    /// The cache's format version (20 Vista, 21 Windows 7, 30 to 32 Windows 8 to 11), when
    /// its header was read.
    pub version: Option<u32>,
    /// The folder its images went to.
    pub folder: Option<PathBuf>,
    /// Entries found, and of them: images written whole, images written with unreadable
    /// parts as zeros, entries with no image, entries whose data is not an image, entries
    /// whose image could not be read at all.
    pub entries: u64,
    pub images: u64,
    pub partial: u64,
    pub empty: u64,
    pub invalid: u64,
    pub unreadable: u64,
    /// Bytes of the cache that could not be read.
    pub unread_bytes: u64,
    /// Entries whose image is larger than this tool takes (64 MiB): skipped and counted.
    #[serde(default)]
    pub too_large: u64,
    /// The limit of its budget the read reached, in words, when it reached one.
    #[serde(default)]
    pub limit: Option<String>,
    /// Why it gave nothing, if so.
    pub note: Option<String>,
}

/// What `run` did.
#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    /// The "Thumbnails <date>" folder, once made.
    pub folder: Option<PathBuf>,
    pub caches: Vec<CacheResult>,
    /// Every file made, in order; not serialized, its rows are in the report.
    #[serde(skip)]
    pub ledger: Ledger,
    /// Images that could not be written, and why.
    pub failed: Vec<(String, String)>,
    pub report: Option<PathBuf>,
    pub report_error: Option<String>,
    pub stopped: bool,
    /// Why the source stopped answering, if it did.
    pub gone: Option<String>,
    /// Notes on the search: volumes that could not be read, no cache found.
    pub notes: Vec<String>,
}

impl Outcome {
    /// Images written whole.
    pub fn images(&self) -> u64 {
        self.caches.iter().map(|c| c.images).sum()
    }

    /// Images written with unreadable parts as zeros.
    pub fn partial(&self) -> u64 {
        self.caches.iter().map(|c| c.partial).sum()
    }
}

/// Whether a file found on a volume is an Explorer thumbnail cache: `thumbcache_*.db`, not
/// the index, which holds no images.
pub fn is_cache(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("thumbcache_") && lower.ends_with(".db") && lower != "thumbcache_idx.db"
}

/// The user a cache belongs to: the folder after "Users".
fn user_of(found: &Found) -> Option<String> {
    let at = found
        .folder
        .iter()
        .position(|p| p.name.eq_ignore_ascii_case("Users"))?;
    found.folder.get(at + 1).map(|p| p.name.clone())
}

// ---- reading a cache -------------------------------------------------------------------

/// A cache's bytes by offset, read into a zeroed buffer the walk made within its budget,
/// with the ranges that could not be read (left as zeros).
pub trait Source {
    fn len(&self) -> u64;
    fn fill(&mut self, at: u64, out: &mut [u8]) -> Vec<Range<u64>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A cache file on a volume, read through its runs.
struct OnVolume<'a, 's> {
    reader: &'a mut Reader<'s>,
    data: &'a Data,
    size: u64,
}

impl Source for OnVolume<'_, '_> {
    fn len(&self) -> u64 {
        self.size
    }

    fn fill(&mut self, at: u64, out: &mut [u8]) -> Vec<Range<u64>> {
        let n = out.len();
        let end = at.saturating_add(n as u64).min(self.size);
        let mut bad = Vec::new();
        if at.saturating_add(n as u64) > end {
            bad.push(end.max(at)..at + n as u64);
        }
        let runs = match self.data {
            Data::Resident(bytes) => {
                let (s, e) = (at.min(bytes.len() as u64), end.min(bytes.len() as u64));
                out[..(e - s) as usize].copy_from_slice(&bytes[s as usize..e as usize]);
                return merge(bad);
            }
            Data::Runs(runs) => runs,
        };
        let mut pos = 0u64;
        for run in runs {
            let (from, to) = (at.max(pos), end.min(pos.saturating_add(run.len)));
            if from < to {
                let into = (from - at) as usize..(to - at) as usize;
                match run.place {
                    Place::At(on) => {
                        // A piece at a time, so a long run is never held twice over.
                        for (k, piece) in out[into].chunks_mut(CHUNK as usize).enumerate() {
                            let offset = on + (from - pos) + k as u64 * CHUNK;
                            let lossy = self.reader.read_lossy(offset, piece.len());
                            piece.copy_from_slice(&lossy.data);
                            let base = from + k as u64 * CHUNK;
                            bad.extend(
                                lossy
                                    .unreadable
                                    .iter()
                                    .map(|r| base + r.start as u64..base + r.end as u64),
                            );
                        }
                    }
                    Place::Zeros => {}
                    Place::Missing => bad.push(from..to),
                }
            }
            pos = pos.saturating_add(run.len);
            if pos >= end {
                break;
            }
        }
        if pos < end {
            bad.push(pos.max(at)..end);
        }
        merge(bad)
    }
}

/// A cache file on a readable drive.
pub struct OnDisk {
    pub file: File,
    pub len: u64,
}

impl Source for OnDisk {
    fn len(&self) -> u64 {
        self.len
    }

    fn fill(&mut self, at: u64, out: &mut [u8]) -> Vec<Range<u64>> {
        let n = out.len();
        let mut done = 0usize;
        while done < n {
            match self.file.seek_read(&mut out[done..], at + done as u64) {
                Ok(0) | Err(_) => break,
                Ok(k) => done += k,
            }
        }
        if done < n {
            out[done..].fill(0);
            vec![Range {
                start: at + done as u64,
                end: at + n as u64,
            }]
        } else {
            Vec::new()
        }
    }
}

/// An image in a cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Where the entry starts in the cache.
    pub at: u64,
    pub hash: u64,
    /// Where its image is in the cache, and its length.
    pub data: Range<u64>,
}

/// The entry header layouts: header size, and where the identifier size, padding size and
/// data size are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    header: u64,
    id: usize,
    pad: usize,
    data: usize,
}

/// Windows Vista (20): an 8-byte extension before the sizes.
const VISTA: Layout = Layout {
    header: 56,
    id: 24,
    pad: 28,
    data: 32,
};
/// Windows 7 (21).
const SEVEN: Layout = Layout {
    header: 48,
    id: 16,
    pad: 20,
    data: 24,
};
/// Windows 8 to 11 (30 to 32): width and height after the data size.
const EIGHT: Layout = Layout {
    header: 56,
    id: 16,
    pad: 20,
    data: 24,
};

fn le32(b: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

/// The entry whose 56 header bytes are `b` at `at`, with `room` bytes of the cache left
/// from it, under the layouts the version allows: one whose sizes add up exactly first.
fn entry_at(b: &[u8], at: u64, room: u64, version: Option<u32>) -> Option<(Entry, u64)> {
    if b.len() < 56 || &b[..4] != b"CMMM" {
        return None;
    }
    let size = le32(b, 4);
    let hash = u64::from_le_bytes(b[8..16].try_into().expect("eight bytes"));
    let layouts: &[Layout] = match version {
        Some(20) => &[VISTA],
        Some(21) => &[SEVEN],
        Some(v) if v >= 30 => &[EIGHT],
        _ => &[EIGHT, SEVEN, VISTA],
    };
    let fits = |l: &Layout| {
        let (id, pad, data) = (le32(b, l.id), le32(b, l.pad), le32(b, l.data));
        let used = l.header + id + pad + data;
        (size >= l.header && size <= room && used <= size).then_some((
            used == size,
            at + l.header + id + pad,
            data,
        ))
    };
    let chosen = layouts
        .iter()
        .filter_map(fits)
        .max_by_key(|(exact, _, _)| *exact)?;
    let (_, start, len) = chosen;
    Some((
        Entry {
            at,
            hash,
            data: start..start + len,
        },
        size,
    ))
}

/// How a walk of a cache went.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Walk {
    pub version: Option<u32>,
    pub entries: u64,
    /// Bytes skipped looking for the next entry after one that could not be read.
    pub skipped: u64,
    pub unread_bytes: u64,
    /// Entries whose image is larger than `DATA_MAX`, skipped.
    pub too_large: u64,
    /// The limit of its budget the walk reached, if one.
    pub limit: Option<Limit>,
}

/// Unreadable parts kept before they are merged, so a cache of many small bad areas holds
/// a bounded record of them.
const UNREAD_MERGE: usize = 1 << 16;

/// What a walk calls with each entry: the source, the walk's budget, the entry and where
/// it lies; a refusal of the budget ends the walk.
pub type EachEntry<'e> =
    dyn FnMut(&mut dyn Source, &mut Budget, &Entry, u64) -> Result<(), Limit> + 'e;

/// `n` bytes at `at` with the ranges not read: the buffer's memory charged to `budget`
/// before it is made, and left charged, so the caller frees `n` when it lets them go.
pub fn read(
    src: &mut dyn Source,
    budget: &mut Budget,
    at: u64,
    n: usize,
) -> Result<(Vec<u8>, Vec<Range<u64>>), Limit> {
    let mut out = budget.buffer(n)?;
    let bad = src.fill(at, &mut out);
    Ok((out, bad))
}

/// Walks a cache's entries in order within `budget` (made from `LIMITS`), calling `each`
/// with each; after an entry that cannot be read or makes no sense, looks for the next
/// "CMMM" and carries on, so a damaged or deleted cache gives what it still holds. An
/// entry whose image is larger than `DATA_MAX` is counted and skipped.
pub fn walk(src: &mut dyn Source, budget: &mut Budget, each: &mut EachEntry) -> Walk {
    let len = src.len().min(CACHE_MAX);
    let mut w = Walk::default();
    let mut head = [0u8; 24];
    let head_bad = src.fill(0, &mut head);
    let mut pos = 24u64;
    if head_bad.is_empty() && &head[..4] == b"CMMM" {
        let version = le32(&head, 4) as u32;
        w.version = Some(version);
        let first = if version >= 30 {
            le32(&head, 16)
        } else {
            le32(&head, 12)
        };
        if (24..len).contains(&first) {
            pos = first;
        }
    }
    let mut unread: Vec<Range<u64>> = Vec::new();
    let walked: Result<(), Limit> = (|| {
        budget.read(24)?;
        // The file's own header unreadable is counted with the rest.
        keep_unread(&mut unread, head_bad, budget)?;
        while pos + 56 <= len {
            budget.read(56)?;
            let mut b = [0u8; 56];
            let bad = src.fill(pos, &mut b);
            let entry = bad
                .is_empty()
                .then(|| entry_at(&b, pos, len - pos, w.version))
                .flatten();
            match entry {
                Some((entry, size)) if entry.data.end - entry.data.start > DATA_MAX => {
                    w.too_large += 1;
                    pos += size.max(56);
                }
                Some((entry, size)) => {
                    budget.item()?;
                    budget.read(entry.data.end - entry.data.start)?;
                    w.entries += 1;
                    each(src, budget, &entry, pos)?;
                    pos += size.max(56);
                }
                None => {
                    keep_unread(&mut unread, bad, budget)?;
                    // Look for the next entry's signature, a piece at a time.
                    let from = pos + 1;
                    match find_signature(src, from, len, &mut unread, budget)? {
                        Some(next) => {
                            w.skipped += next - pos;
                            pos = next;
                        }
                        None => {
                            w.skipped += len - pos;
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    })();
    w.limit = walked.err();
    w.unread_bytes = merge(unread).iter().map(|r| r.end - r.start).sum();
    w
}

/// Adds unreadable parts to the record, merging it when it grows past `UNREAD_MERGE`, its
/// memory charged to `budget`.
fn keep_unread(
    unread: &mut Vec<Range<u64>>,
    bad: Vec<Range<u64>>,
    budget: &mut Budget,
) -> Result<(), Limit> {
    if bad.is_empty() {
        return Ok(());
    }
    let size = std::mem::size_of::<Range<u64>>() as u64;
    if unread.len() + bad.len() > UNREAD_MERGE {
        let before = unread.len() as u64;
        *unread = merge(std::mem::take(unread));
        budget.free(before.saturating_sub(unread.len() as u64) * size);
    }
    budget.hold(bad.len() as u64 * size)?;
    unread.extend(bad);
    Ok(())
}

/// The next "CMMM" at or after `from`, each piece read charged to `budget`.
fn find_signature(
    src: &mut dyn Source,
    mut from: u64,
    len: u64,
    unread: &mut Vec<Range<u64>>,
    budget: &mut Budget,
) -> Result<Option<u64>, Limit> {
    while from + 4 <= len {
        let n = (len - from).min(CHUNK) as usize;
        budget.read(n as u64)?;
        let (piece, bad) = read(src, budget, from, n)?;
        let found = piece.windows(4).position(|w| w == b"CMMM");
        budget.free(n as u64);
        drop(piece);
        keep_unread(unread, bad, budget)?;
        if let Some(i) = found {
            return Ok(Some(from + i as u64));
        }
        if n < 4 {
            return Ok(None);
        }
        from += (n - 3) as u64;
    }
    Ok(None)
}

/// The image type and whole length of `b`, when it is a JPEG, PNG or BMP whose structure is
/// whole: JPEG start to end marker, PNG chunks to IEND, a BMP its stated size.
pub fn image_kind(b: &[u8]) -> Option<(&'static str, usize)> {
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return super::preview::jpeg_len(b).map(|n| ("jpg", n));
    }
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut pos = 8usize;
        let mut first = true;
        loop {
            let len = u32::from_be_bytes(b.get(pos..pos + 4)?.try_into().ok()?) as usize;
            let kind = b.get(pos + 4..pos + 8)?;
            if first && kind != b"IHDR" {
                return None;
            }
            first = false;
            let end = pos.checked_add(12)?.checked_add(len)?;
            if end > b.len() {
                return None;
            }
            if kind == b"IEND" {
                return Some(("png", end));
            }
            pos = end;
        }
    }
    if b.starts_with(b"BM") && b.len() >= 30 {
        let size = le32(b, 2) as usize;
        let pixels = le32(b, 10) as usize;
        let dib = le32(b, 14);
        if matches!(dib, 12 | 40 | 52 | 56 | 108 | 124) && size <= b.len() && pixels < size {
            return Some(("bmp", size));
        }
    }
    None
}

/// The type an image's first bytes say, read or not.
fn magic(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpg")
    } else if b.starts_with(b"\x89PNG") {
        Some("png")
    } else if b.starts_with(b"BM") {
        Some("bmp")
    } else {
        None
    }
}

// ---- the engine ------------------------------------------------------------------------

/// A cache to read: on the source, or a file on a readable drive.
enum Where<'a> {
    Volume(&'a Found),
    Disk(&'a Path),
}

/// Finds the thumbnail caches on the source (the volumes `options` names, or every volume in
/// the partition tables), and in the files it names, and writes every image in them to
/// `Thumbnails <date>\<cache>\` in the destination, with "Thumbnail report.txt" there.
/// `scanned` holds volumes already read, by their start, so they are not read again; the
/// files given for one need only be its caches. Refuses before reading or writing anything
/// when the destination is on the source disk.
pub fn run(
    mut reader: Option<&mut Reader>,
    options: &Options,
    scanned: &[(u64, Vec<Found>)],
    events: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> Result<Outcome, String> {
    let protected = match reader.as_deref() {
        Some(reader) => options.source_disk.clone().join(reader.protected()),
        None => options.source_disk.clone(),
    };
    let guard = Guard::of(&protected);
    guard.check_folder(&options.destination)?;
    let mut outcome = Outcome::default();

    // The caches on the source.
    let mut found: Vec<Found> = Vec::new();
    if let Some(reader) = reader.as_deref_mut() {
        let wanted: Vec<u64> = if options.volumes.is_empty() {
            events(Event::Phase("Reading the partition tables".into()));
            let progress = fs::Progress::default();
            let finds = parts::find(reader, parts::Search::Tables, cancel, &progress);
            outcome.notes.extend(finds.notes);
            let mut starts: Vec<u64> = finds.volumes.iter().map(|v| v.start).collect();
            starts.extend(scanned.iter().map(|s| s.0));
            starts.sort_unstable();
            starts.dedup();
            starts
        } else {
            options.volumes.clone()
        };
        let mut volumes = None;
        for start in wanted {
            if cancel.load(Ordering::Relaxed) {
                outcome.stopped = true;
                break;
            }
            if let Some((_, files)) = scanned.iter().find(|s| s.0 == start) {
                found.extend(files.iter().filter(|f| is_cache(&f.name)).cloned());
                continue;
            }
            let all = volumes.get_or_insert_with(|| {
                let progress = fs::Progress::default();
                parts::find(reader, parts::Search::Tables, cancel, &progress).volumes
            });
            let Some(volume) = all.iter().find(|v| v.start == start).cloned() else {
                outcome.notes.push(format!(
                    "No volume starts at byte {start} in the partition tables."
                ));
                continue;
            };
            events(Event::Phase(format!(
                "Reading the files of {}",
                volume.describe()
            )));
            let progress = fs::Progress::default();
            match fs::scan(reader, &volume, cancel, &progress) {
                Ok(listing) => {
                    found.extend(listing.files.into_iter().filter(|f| is_cache(&f.name)))
                }
                Err(why) => outcome
                    .notes
                    .push(format!("{} could not be read: {why}.", volume.describe())),
            }
        }
    }
    found.retain(|f| options.include_deleted || !f.deleted);
    let mut caches: Vec<Where> = found.iter().map(Where::Volume).collect();
    caches.extend(options.files.iter().map(|p| Where::Disk(p)));
    if caches.is_empty() {
        outcome
            .notes
            .push("No Explorer thumbnail cache (thumbcache_*.db) was found.".into());
        return Ok(outcome);
    }

    let base = guard
        .base(&options.destination)
        .map_err(|e| format!("{} could not be opened: {e}", options.destination.display()))?;
    let stamp = crate::clock::local(std::time::SystemTime::now());
    let top_name = format!(
        "Thumbnails {:04}-{:02}-{:02}",
        stamp.year, stamp.month, stamp.day
    );
    let top = guard
        .folders(&base, [top_name.as_str()])
        .map_err(|e| format!("the folder {top_name} could not be made: {e}"))?;
    outcome.folder = Some(top.path().to_path_buf());
    let total: u64 = caches
        .iter()
        .map(|c| match c {
            Where::Volume(f) => f.size,
            // Only the progress total: a length that cannot be read adds nothing here, and
            // is said when the cache is opened.
            Where::Disk(p) => std::fs::metadata(p).map_or(0, |m| m.len()),
        })
        .sum();
    let mut done = 0u64;
    let mut used: HashSet<String> = HashSet::new();
    let of = caches.len();
    for (index, cache) in caches.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            outcome.stopped = true;
            break;
        }
        if let Some(why) = reader.as_deref().and_then(Reader::gone) {
            outcome.gone = Some(why.to_string());
            break;
        }
        let mut result = match cache {
            Where::Volume(f) => CacheResult {
                name: f.name.clone(),
                from: format!("{}\\{}", f.folder_text().trim_end_matches('\\'), f.name),
                deleted: f.deleted,
                user: user_of(f),
                size: f.size,
                ..CacheResult::default()
            },
            Where::Disk(p) => CacheResult {
                name: p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                from: p.display().to_string(),
                ..CacheResult::default()
            },
        };
        events(Event::Cache {
            index,
            of,
            name: result.from.clone(),
        });
        // "thumbcache_256.db (Ann, deleted)", unique within this run.
        let mut tags: Vec<String> = result.user.iter().cloned().collect();
        if result.deleted {
            tags.push("deleted".into());
        }
        let mut folder_name = if tags.is_empty() {
            result.name.clone()
        } else {
            format!("{} ({})", result.name, tags.join(", "))
        };
        folder_name = safe_name(&folder_name);
        let stem = folder_name.clone();
        let mut n = 2;
        while !used.insert(folder_name.to_ascii_lowercase()) {
            folder_name = format!("{stem} {n}");
            n += 1;
        }
        let folder = match guard.folder(&top, OsStr::new(&folder_name)) {
            Ok(folder) => folder,
            Err(e) => {
                result.note = Some(format!("its folder could not be made: {e}"));
                outcome.caches.push(result);
                continue;
            }
        };
        result.folder = Some(folder.path().to_path_buf());
        let source_path = PathBuf::from(&result.from);
        let images_before = outcome.images() + outcome.partial();
        let mut on_volume;
        let mut on_disk;
        let src: &mut dyn Source = match cache {
            Where::Volume(f) => {
                let Some(reader) = reader.as_deref_mut() else {
                    continue;
                };
                on_volume = OnVolume {
                    reader,
                    data: &f.data,
                    size: f.size,
                };
                &mut on_volume
            }
            Where::Disk(p) => match File::open(p).and_then(|f| Ok((f.metadata()?.len(), f))) {
                Ok((len, file)) => {
                    result.size = len;
                    on_disk = OnDisk { file, len };
                    &mut on_disk
                }
                // A length that cannot be read is said, not taken for an empty cache.
                Err(e) => {
                    result.note = Some(format!("it could not be opened: {e}"));
                    outcome.caches.push(result);
                    continue;
                }
            },
        };
        let mut written = Writer {
            guard: &guard,
            folder: &folder,
            ledger: &mut outcome.ledger,
            failed: &mut outcome.failed,
            result: &mut result,
            tag: index,
            source: &source_path,
        };
        let mut budget = Budget::new(LIMITS, Some(cancel));
        let walked = walk(src, &mut budget, &mut |src, budget, entry, pos| {
            written.entry(src, budget, entry)?;
            if written.result.entries.is_multiple_of(64) {
                events(Event::Progress {
                    done: done + pos,
                    total,
                    images: images_before + written.result.images + written.result.partial,
                });
            }
            Ok(())
        });
        result.version = walked.version;
        result.unread_bytes = walked.unread_bytes;
        result.too_large = walked.too_large;
        result.limit = walked.limit.and(budget.said());
        if walked.version.is_none() && result.entries == 0 {
            result.note = Some(if walked.unread_bytes > 0 {
                "its start could not be read and no entry was found in the rest".into()
            } else {
                "it is not a thumbnail cache, or nothing of one is left".into()
            });
        }
        if walked.limit == Some(Limit::Stopped) {
            outcome.stopped = true;
        }
        done += result.size;
        events(Event::Progress {
            done,
            total,
            images: images_before + result.images + result.partial,
        });
        outcome.caches.push(result);
        if outcome.stopped {
            break;
        }
    }
    if outcome.gone.is_none() {
        outcome.gone = reader.as_deref().and_then(Reader::gone).map(str::to_string);
    }
    outcome
        .ledger
        .close("the recovery ended before it was finished");
    let source = reader
        .as_deref()
        .map_or_else(|| "files on a readable drive".to_string(), Reader::describe);
    // Rendered first, from the ledger as the run left it; then entered and written.
    let mut text = Vec::new();
    write_report(&mut text, &source, top.path(), &outcome)
        .map_err(|e| format!("the report could not be put together: {e}"))?;
    let made = super::output::write_report_file(
        &guard,
        &top,
        "Thumbnail report.txt",
        &text,
        &mut outcome.ledger,
        &mut super::writer::plain,
        &mut super::writer::ToDisk::per_file(),
    );
    outcome.report = made.path;
    outcome.report_error = made.error;
    Ok(outcome)
}

/// Writes one cache's images.
struct Writer<'a> {
    guard: &'a Guard,
    folder: &'a Folder,
    ledger: &'a mut Ledger,
    failed: &'a mut Vec<(String, String)>,
    result: &'a mut CacheResult,
    tag: usize,
    source: &'a Path,
}

impl Writer<'_> {
    /// Reads one entry's image, its memory charged to `budget` before it is made and freed
    /// once it is written; refused past the budget's memory.
    fn entry(
        &mut self,
        src: &mut dyn Source,
        budget: &mut Budget,
        entry: &Entry,
    ) -> Result<(), Limit> {
        self.result.entries += 1;
        let len = entry.data.end - entry.data.start;
        if len == 0 {
            self.result.empty += 1;
            return Ok(());
        }
        let (bytes, bad) = read(src, budget, entry.data.start, len as usize)?;
        self.keep(entry, &bytes, &bad);
        budget.free(len);
        Ok(())
    }

    /// Writes one entry's image from its bytes, as much of it as was read.
    fn keep(&mut self, entry: &Entry, bytes: &[u8], bad: &[Range<u64>]) {
        let head_read = !bad.iter().any(|r| r.start < entry.data.start + 8);
        let (ext, keep, zeroed) = if bad.is_empty() {
            match image_kind(bytes) {
                Some((ext, n)) => (ext, n, Vec::new()),
                None => {
                    self.result.invalid += 1;
                    return;
                }
            }
        } else {
            match magic(bytes).filter(|_| head_read) {
                Some(ext) => {
                    let zeroed: Vec<Range<u64>> = bad
                        .iter()
                        .map(|r| r.start - entry.data.start..r.end - entry.data.start)
                        .collect();
                    (ext, bytes.len(), zeroed)
                }
                None => {
                    self.result.unreadable += 1;
                    return;
                }
            }
        };
        let name = if zeroed.is_empty() {
            format!("{:016x}.{ext}", entry.hash)
        } else {
            format!("{:016x} (partial).{ext}", entry.hash)
        };
        let entry = super::writer::Entry {
            tag: self.tag,
            source: self.source.join(format!("{:016x}", entry.hash)),
            note: format!("thumbnail at byte {} of the cache", entry.at),
            size: keep as u64,
        };
        match super::writer::create(self.guard, self.folder, &name, self.ledger, entry) {
            Ok(mut made) => {
                let partial = !zeroed.is_empty();
                if partial {
                    self.ledger.zeroed(made.id, zeroed);
                }
                match super::writer::write_whole(&mut made, &bytes[..keep], self.ledger) {
                    Ok(()) if partial => self.result.partial += 1,
                    Ok(()) => self.result.images += 1,
                    Err(why) => self.failed.push((name, why)),
                }
            }
            Err(e) => self.failed.push((name, e.to_string())),
        }
    }
}

/// The report: each cache and what it gave, then each file made, from the ledger.
pub fn write_report(
    out: &mut dyn Write,
    source: &str,
    dest: &Path,
    outcome: &Outcome,
) -> std::io::Result<()> {
    let stamp = crate::clock::local(std::time::SystemTime::now()).long();
    write!(
        out,
        "Thumbnail report\r\n{COMPLETE_IF}\r\n\r\nThese are the small copies of pictures that Windows Explorer kept in its thumbnail caches. Each is named by the cache's hash of the picture it was made from.\r\n\r\nSource: {source}\r\nDestination: {}\r\nWritten: {stamp}\r\n\r\nCaches\r\n",
        dest.display()
    )?;
    for c in &outcome.caches {
        let mut line = format!(
            "{}{}\t{} bytes\t{} entries: {} images written, {} with unreadable parts, {} empty, {} not images, {} unreadable",
            c.from,
            if c.deleted { " (deleted)" } else { "" },
            c.size,
            c.entries,
            c.images,
            c.partial,
            c.empty,
            c.invalid,
            c.unreadable
        );
        if c.unread_bytes > 0 {
            line.push_str(&format!(
                "; {} bytes of the cache could not be read",
                c.unread_bytes
            ));
        }
        if c.too_large > 0 {
            line.push_str(&format!(
                "; {} entries hold an image larger than this tool takes ({}) and were skipped",
                c.too_large,
                crate::tools::drives::bytes_text(DATA_MAX)
            ));
        }
        if let Some(limit) = c.limit.as_ref().filter(|_| !outcome.stopped) {
            line.push_str(&format!("; {limit}"));
        }
        if let Some(note) = &c.note {
            line.push_str(&format!("; {note}"));
        }
        write!(out, "{line}\r\n")?;
    }
    for note in &outcome.notes {
        write!(out, "{note}\r\n")?;
    }
    write!(out, "\r\nFiles\r\n")?;
    outcome.ledger.write_rows(out, dest, false)?;
    if !outcome.failed.is_empty() {
        write!(out, "\r\nNot made\r\n")?;
        for (name, why) in &outcome.failed {
            write!(out, "{name}\t{why}\r\n")?;
        }
    }
    write!(
        out,
        "\r\n{} read; {} written whole, {} with unreadable parts written as zeros; {} could not be made.\r\n",
        if outcome.caches.len() == 1 {
            "1 cache".to_string()
        } else {
            format!("{} caches", outcome.caches.len())
        },
        files(outcome.images() as usize),
        outcome.partial(),
        outcome.failed.len()
    )?;
    if outcome.stopped {
        write!(out, "It was stopped before every cache was read.\r\n")?;
    }
    if let Some(why) = &outcome.gone {
        write!(out, "It ended early: {why}.\r\n")?;
    }
    write!(out, "{END}")?;
    out.flush()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::recovery::preview::tests::{HOLIDAY, PHOTO};

    /// A thumbnail cache in the format of `version` holding `images` (empty ones give
    /// entries with no data).
    pub fn cache(version: u32, images: &[&[u8]]) -> Vec<u8> {
        let mut out = b"CMMM".to_vec();
        out.extend(version.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        if version >= 30 {
            out.extend(0u32.to_le_bytes());
            out.extend(24u32.to_le_bytes());
            out.extend(0u32.to_le_bytes());
        } else {
            out.extend(24u32.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend((images.len() as u32).to_le_bytes());
        }
        for (i, image) in images.iter().enumerate() {
            let id: Vec<u8> = format!("{:016x}", 0x1000 + i)
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let header = if version == 21 { 48 } else { 56 };
            let used = header + id.len() + image.len();
            let pad = (8 - used % 8) % 8;
            let size = used + pad;
            let mut e = b"CMMM".to_vec();
            e.extend((size as u32).to_le_bytes());
            e.extend((0xABCD_0000_u64 + i as u64).to_le_bytes());
            if version == 20 {
                e.extend("jpg\0".encode_utf16().flat_map(u16::to_le_bytes));
            }
            e.extend((id.len() as u32).to_le_bytes());
            e.extend((pad as u32).to_le_bytes());
            e.extend((image.len() as u32).to_le_bytes());
            if version >= 30 {
                e.extend(96u32.to_le_bytes());
                e.extend(64u32.to_le_bytes());
            }
            e.extend(0u32.to_le_bytes());
            e.extend([0x11; 16]);
            if version == 20 {
                e.truncate(56);
            }
            assert_eq!(e.len(), header, "version {version}");
            e.extend(&id);
            e.extend(vec![0u8; pad]);
            e.extend(*image);
            out.extend(e);
        }
        out
    }

    struct Mem(Vec<u8>, Vec<Range<u64>>);

    impl Source for Mem {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn fill(&mut self, at: u64, out: &mut [u8]) -> Vec<Range<u64>> {
            let n = out.len();
            out.fill(0);
            let end = (at + n as u64).min(self.len());
            if at < end {
                out[..(end - at) as usize].copy_from_slice(&self.0[at as usize..end as usize]);
            }
            let mut bad: Vec<Range<u64>> = self
                .1
                .iter()
                .filter(|r| r.start < at + n as u64 && at < r.end)
                .map(|r| r.start.max(at)..r.end.min(at + n as u64))
                .collect();
            if end < at + n as u64 {
                bad.push(end.max(at)..at + n as u64);
            }
            for r in &bad {
                out[(r.start - at) as usize..(r.end - at) as usize].fill(0);
            }
            merge(bad)
        }
    }

    fn images_in(bytes: Vec<u8>, bad: Vec<Range<u64>>) -> (Walk, Vec<(u64, Vec<u8>, bool)>) {
        let mut got = Vec::new();
        let walked = walk(
            &mut Mem(bytes, bad),
            &mut Budget::new(LIMITS, None),
            &mut |src, budget, e, _| {
                let n = e.data.end - e.data.start;
                let (b, bad) = read(src, budget, e.data.start, n as usize)?;
                budget.free(n);
                got.push((e.hash, b, bad.is_empty()));
                Ok(())
            },
        );
        (walked, got)
    }

    const PNG: &[u8] = include_bytes!("../../tests/fixtures/recovery/samples/image.png");
    const BMP: &[u8] = include_bytes!("../../tests/fixtures/recovery/samples/picture.bmp");

    #[test]
    fn every_version_of_the_cache_gives_its_images() {
        for version in [20, 21, 30, 31, 32] {
            let (walked, got) = images_in(cache(version, &[PHOTO, b"", PNG, BMP]), Vec::new());
            assert_eq!(walked.version, Some(version));
            assert_eq!(walked.entries, 4, "version {version}");
            assert_eq!(got[0].1, PHOTO);
            assert!(got[1].1.is_empty());
            assert_eq!(got[2].1, PNG);
            assert_eq!(got[3].1, BMP);
            assert_eq!(got[3].0, 0xABCD_0003);
        }
        assert_eq!(image_kind(PHOTO), Some(("jpg", PHOTO.len())));
        assert_eq!(image_kind(PNG), Some(("png", PNG.len())));
        assert_eq!(image_kind(BMP), Some(("bmp", BMP.len())));
        assert_eq!(image_kind(&PNG[..PNG.len() - 1]), None);
    }

    #[test]
    fn a_cache_with_an_unreadable_or_broken_entry_gives_the_rest() {
        let bytes = cache(32, &[PHOTO, HOLIDAY, PNG]);
        let second = 24 + (56 + 32 + PHOTO.len()).div_ceil(8) * 8;
        // The second entry's header unreadable: the first and third are still found.
        let (walked, got) = images_in(
            bytes.clone(),
            vec![Range {
                start: second as u64,
                end: second as u64 + 512,
            }],
        );
        let hashes: Vec<u64> = got.iter().map(|g| g.0).collect();
        assert_eq!(hashes, vec![0xABCD_0000, 0xABCD_0002]);
        assert!(walked.unread_bytes >= 512);
        // A header with the file's own header gone (a deleted cache's first cluster reused).
        let mut headless = bytes.clone();
        headless[..24].fill(0x55);
        let (walked, got) = images_in(headless, Vec::new());
        assert_eq!(walked.version, None);
        assert_eq!(got.len(), 3);
        // An entry claiming more than the cache holds is skipped, not trusted.
        let mut lying = bytes;
        lying[24 + 24..24 + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        let (_, got) = images_in(lying, Vec::new());
        assert_eq!(
            got.iter().map(|g| g.0).collect::<Vec<_>>(),
            vec![0xABCD_0001, 0xABCD_0002]
        );
    }

    /// A cache of `len` bytes, `head` at its start and zeros after it.
    struct Sparse(Vec<u8>, u64);

    impl Source for Sparse {
        fn len(&self) -> u64 {
            self.1
        }
        fn fill(&mut self, at: u64, out: &mut [u8]) -> Vec<Range<u64>> {
            out.fill(0);
            let head = self.0.len() as u64;
            if at < head {
                let end = head.min(at + out.len() as u64);
                out[..(end - at) as usize].copy_from_slice(&self.0[at as usize..end as usize]);
            }
            Vec::new()
        }
    }

    #[test]
    fn a_hostile_cache_stops_within_its_budget() {
        // The most entries the budget takes and more: each an empty 56-byte entry.
        let started = std::time::Instant::now();
        let n = LIMITS.count as usize + 10_000;
        let bytes = cache(32, &vec![&b""[..]; n]);
        let mut budget = Budget::new(LIMITS, None);
        let mut seen = 0u64;
        let walked = walk(
            &mut Mem(bytes, Vec::new()),
            &mut budget,
            &mut |_, _, _, _| {
                seen += 1;
                Ok(())
            },
        );
        assert_eq!((walked.entries, seen), (LIMITS.count, LIMITS.count));
        assert_eq!(walked.limit, Some(Limit::Count));
        assert_eq!(
            budget.said().unwrap(),
            "The read of the thumbnail cache stopped at its limit of 250,000 entries."
        );
        assert!(budget.spent().bytes < LIMITS.bytes);
        assert!(started.elapsed() < std::time::Duration::from_secs(60));

        // An entry whose image is larger than the tool takes is counted, not dropped
        // silently, and the walk goes on past it.
        let mut head = cache(32, &[]);
        let big = DATA_MAX + 1;
        let mut e = b"CMMM".to_vec();
        e.extend(((56 + big) as u32).to_le_bytes());
        e.extend(7u64.to_le_bytes());
        e.extend(
            [0u32, 0, big as u32, 96, 64, 0]
                .iter()
                .flat_map(|v| v.to_le_bytes()),
        );
        e.extend([0x11; 16]);
        head.extend(e);
        let len = head.len() as u64 + big + (1 << 20);
        let mut budget = Budget::new(LIMITS, None);
        let walked = walk(
            &mut Sparse(head, len),
            &mut budget,
            &mut |_, _, _, _| Ok(()),
        );
        assert_eq!(
            (walked.too_large, walked.entries, walked.limit),
            (1, 0, None)
        );

        // Unreadable parts everywhere: the record of them is merged and charged, and a
        // small memory limit stops the walk and is said.
        let bad: Vec<Range<u64>> = (0..20_000u64).map(|i| i * 64..i * 64 + 1).collect();
        let small = Limits {
            memory: 1024,
            ..LIMITS
        };
        let mut budget = Budget::new(small, None);
        let walked = walk(
            &mut Mem(vec![0u8; 20_000 * 64], bad.clone()),
            &mut budget,
            &mut |_, _, _, _| Ok(()),
        );
        assert_eq!(walked.limit, Some(Limit::Memory));
        assert!(budget.spent().peak <= 1024);
        assert!(budget.said().unwrap().contains("memory limit of 1.0 kB"));
        // Within the real limit the record stays bounded by its merging.
        let mut budget = Budget::new(LIMITS, None);
        let walked = walk(
            &mut Mem(vec![0u8; 20_000 * 64], bad),
            &mut budget,
            &mut |_, _, _, _| Ok(()),
        );
        assert_eq!(walked.limit, None);
        assert_eq!(walked.unread_bytes, 20_000);

        // Stopped by the person.
        let stop = AtomicBool::new(true);
        let mut budget = Budget::new(LIMITS, Some(&stop));
        let walked = walk(
            &mut Mem(cache(32, &[PHOTO]), Vec::new()),
            &mut budget,
            &mut |_, _, _, _| Ok(()),
        );
        assert_eq!((walked.entries, walked.limit), (0, Some(Limit::Stopped)));
    }

    #[test]
    fn hostile_caches_never_panic() {
        let seed = cache(32, &[PHOTO, PNG, BMP]);
        let mut state = 99u64;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };
        for _ in 0..2000 {
            let mut bytes = seed.clone();
            for _ in 0..1 + next() % 6 {
                let at = next() as usize % bytes.len();
                match next() % 3 {
                    0 => bytes[at] = next() as u8,
                    1 => {
                        for (i, b) in (next() as u32).to_le_bytes().iter().enumerate() {
                            if at + i < bytes.len() {
                                bytes[at + i] = *b;
                            }
                        }
                    }
                    _ => bytes.truncate(at.max(1)),
                }
            }
            let (_, got) = images_in(bytes, Vec::new());
            for (_, b, _) in got {
                let _ = image_kind(&b);
            }
        }
    }

    #[test]
    fn caches_are_told_by_name() {
        assert!(is_cache("thumbcache_256.db"));
        assert!(is_cache("THUMBCACHE_1920.DB"));
        assert!(!is_cache("thumbcache_idx.db"));
        assert!(!is_cache("iconcache_16.db"));
    }

    /// The engine, on cache files given as copies: each image is written once under the
    /// cache's folder by its hash, a broken one is counted and not written, and the report
    /// ends whole.
    #[test]
    fn the_engine_writes_each_image_and_a_report() {
        let dir = std::env::temp_dir().join(format!("diagtool-thumbs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let mut broken = HOLIDAY.to_vec();
        broken.truncate(4000);
        std::fs::write(
            dir.join("thumbcache_256.db"),
            cache(32, &[PHOTO, b"", &broken, PNG]),
        )
        .unwrap();
        std::fs::write(dir.join("thumbcache_96.db"), cache(21, &[BMP])).unwrap();
        let options = Options {
            destination: dir.join("out"),
            files: vec![dir.join("thumbcache_256.db"), dir.join("thumbcache_96.db")],
            source_disk: crate::recovery::dest::Protected::disk(9999),
            ..Options::default()
        };
        let mut events = Vec::new();
        let outcome = run(
            None,
            &options,
            &[],
            &mut |e| events.push(e),
            &AtomicBool::new(false),
        )
        .unwrap();
        let top = outcome.folder.clone().unwrap();
        assert!(top
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("Thumbnails 20"));
        let c = &outcome.caches[0];
        assert_eq!((c.entries, c.images, c.empty, c.invalid), (4, 2, 1, 1));
        assert_eq!(c.version, Some(32));
        assert_eq!(
            std::fs::read(top.join("thumbcache_256.db").join("00000000abcd0000.jpg")).unwrap(),
            PHOTO
        );
        assert_eq!(
            std::fs::read(top.join("thumbcache_256.db").join("00000000abcd0003.png")).unwrap(),
            PNG
        );
        assert_eq!(
            std::fs::read(top.join("thumbcache_96.db").join("00000000abcd0000.bmp")).unwrap(),
            BMP
        );
        assert_eq!(outcome.images(), 3);
        assert_eq!(outcome.ledger.complete(), 4, "three images and the report");
        let report = outcome.ledger.outputs().last().unwrap();
        assert_eq!(report.tag, crate::recovery::output::REPORT_TAG);
        assert_eq!(Some(&report.path), outcome.report.as_ref());
        let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
        assert!(
            report.contains(
                "4 entries: 2 images written, 0 with unreadable parts, 1 empty, 1 not images"
            ),
            "{report}"
        );
        assert!(report.ends_with(END), "{report}");
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Cache {
                index: 1,
                of: 2,
                ..
            }
        )));
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["caches"][0]["images"], 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nothing_is_made_when_no_cache_is_found() {
        let dir = std::env::temp_dir().join(format!("diagtool-nothumbs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let options = Options {
            destination: dir.clone(),
            source_disk: crate::recovery::dest::Protected::disk(9999),
            ..Options::default()
        };
        let outcome = run(None, &options, &[], &mut |_| {}, &AtomicBool::new(false)).unwrap();
        assert!(outcome.folder.is_none());
        assert!(outcome.notes[0].contains("No Explorer thumbnail cache"));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
