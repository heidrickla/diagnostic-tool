//! File system readers for deleted and lost file recovery: NTFS, FAT12/16/32 and exFAT,
//! and the search for volumes in partition tables and on the bare disk. Everything is read
//! through a `Reader`, so unreadable areas are recorded and skipped.
#![deny(clippy::arithmetic_side_effects)]
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::reader::Reader;
use crate::budget::{Budget, Limit};
use crate::recovery::carve::{Missing, Start};

pub(crate) mod count;
pub mod exfat;
pub mod fat;
pub mod ntfs;
pub mod parts;

/// The most one table of a file system (allocation table, cluster bitmap) is read into
/// memory. Sizes come from the volume's own, possibly damaged, records, so each is bounded
/// by what the volume's geometry allows and then by this.
pub const MAX_TABLE: u64 = 256 << 20;

/// The most pieces one file's content is taken in; a chain with more is a loop or damage.
pub const MAX_FRAGMENTS: usize = 1 << 20;

/// A file system this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsKind {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

impl FsKind {
    pub fn label(self) -> &'static str {
        match self {
            FsKind::Ntfs => "NTFS",
            FsKind::Fat12 => "FAT12",
            FsKind::Fat16 => "FAT16",
            FsKind::Fat32 => "FAT32",
            FsKind::ExFat => "exFAT",
        }
    }
}

/// How much of a deleted file's space is now another file's, from the volume's own record
/// of used space. Files in use are Intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Intact,
    /// Clusters now used by other files, out of the file's clusters.
    Partly {
        used: u64,
        of: u64,
    },
    Overwritten,
    /// The volume's record of used space could not be read, or the file has no clusters
    /// recorded (a FAT entry whose first cluster is gone).
    Unknown,
}

impl State {
    pub fn from_counts(used: u64, of: u64) -> State {
        match (used, of) {
            (_, 0) => State::Intact,
            (0, _) => State::Intact,
            (u, o) if u >= o => State::Overwritten,
            (used, of) => State::Partly { used, of },
        }
    }

    pub fn label(self) -> String {
        match self {
            State::Intact => "intact".into(),
            State::Partly { used, of } => format!("partly overwritten ({}%)", percent(used, of)),
            State::Overwritten => "overwritten".into(),
            State::Unknown => "unknown".into(),
        }
    }
}

/// `used` of `of` as a whole percent, rounded up and below 100 while any is left. A u64
/// times 100 always fits a u128.
fn percent(used: u64, of: u64) -> u128 {
    u128::from(used)
        .checked_mul(100)
        .map_or(99, |p| p.div_ceil(u128::from(of.max(1))).min(99))
}

/// Where one stretch of a file's content is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// At this byte offset on the source.
    At(u64),
    /// Reads as zeros by design: sparse, or past what the file system ever wrote.
    Zeros,
    /// Should hold data but cannot be read: outside the volume or a damaged map. Written
    /// as zeros and the file is marked damaged.
    Missing,
}

/// One stretch of a file's content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub place: Place,
    pub len: u64,
}

/// Where a file's content is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    /// Held inside the file system's own record (small NTFS files).
    Resident(Vec<u8>),
    /// Stretches on the source, in file order, adding up to at least the file's size.
    Runs(Vec<Run>),
}

/// A modification time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modified {
    /// Seconds since 1970 UTC (NTFS).
    Utc(i64),
    /// Local wall-clock time as the volume stored it (FAT and exFAT).
    Local {
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
    },
}

impl Modified {
    /// From an NTFS time: 100 ns ticks since 1601 UTC.
    pub fn from_filetime(ticks: u64) -> Option<Modified> {
        const EPOCH_DIFF: i64 = 11_644_473_600;
        // Ticks over 10^7 are at most 1.8 * 10^12 seconds, which an i64 holds.
        let secs = (ticks != 0).then_some((ticks / 10_000_000) as i64)?;
        secs.checked_sub(EPOCH_DIFF).map(Modified::Utc)
    }

    /// From a DOS date and time, as FAT and exFAT store them.
    pub fn from_dos(date: u16, time: u16) -> Option<Modified> {
        let (day, month) = ((date & 0x1F) as u8, ((date >> 5) & 0x0F) as u8);
        if date == 0 || day == 0 || !(1..=12).contains(&month) {
            return None;
        }
        Some(Modified::Local {
            year: 1980u16.checked_add(date >> 9)?,
            month,
            day,
            hour: ((time >> 11) & 0x1F) as u8,
            minute: ((time >> 5) & 0x3F) as u8,
        })
    }

    /// "2026-11-06 14:03", in local time.
    pub fn text(self) -> String {
        match self {
            Modified::Utc(secs) => {
                // A damaged record can hold any time; one before 1970 or past year 9999 is
                // said to be unreadable, never shown as a date it is not.
                let Some(time) = u64::try_from(secs)
                    .ok()
                    .filter(|s| *s < 253_402_300_800)
                    .and_then(|s| {
                        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(s))
                    })
                else {
                    return UNREADABLE_TIME.into();
                };
                let s = crate::clock::local(time);
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}",
                    s.year, s.month, s.day, s.hour, s.minute
                )
            }
            Modified::Local {
                year,
                month,
                day,
                hour,
                minute,
            } => format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}"),
        }
    }
}

/// What a file's time says when its record holds one that cannot be a date.
pub const UNREADABLE_TIME: &str = "time not readable";

/// One folder on a file's path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub name: String,
    /// The folder itself was deleted, or its record is gone ("lost").
    pub deleted: bool,
}

/// A file found on a volume.
#[derive(Clone, Debug)]
pub struct Found {
    pub name: String,
    pub folder: Vec<Part>,
    pub size: u64,
    pub modified: Option<Modified>,
    pub deleted: bool,
    pub state: State,
    pub data: Data,
    /// Its record or content could not be read in full.
    pub damaged: bool,
    /// Anything else a person should know, such as "compressed by NTFS".
    pub note: Option<String>,
    /// What shows it overwritten beyond its volume's own record of used space.
    pub why: Option<Why>,
}

/// What is known of a file's content beyond its volume's own record of used space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    /// Its first bytes are not what a file of its type starts with: overwritten. Names the
    /// current partitions over its area, if any.
    Mismatch(Option<String>),
    /// Its first bytes lack the marker most files of its type show there, though a valid
    /// one may have a longer lead: it may be overwritten. Names its type, "a zip document".
    Unlike(&'static str),
    /// Its start could not be read, so it is not judged by it.
    Unread,
    /// Current partitions ("partition 1") hold `used` of its `of` bytes on the source. A
    /// partition entry is a risk, not proof: `start` says what its start showed, None when
    /// its type has no known start or it was never written.
    Claimed {
        names: String,
        used: u64,
        of: u64,
        start: Option<Start>,
    },
}

impl Found {
    /// Its state for people, from the evidence: the volume's record, the partitions now
    /// over its area and its first bytes.
    pub fn state_text(&self) -> String {
        // The volume's own record is evidence too, and is said first.
        let own = match self.state {
            State::Partly { .. } | State::Overwritten => format!("{}; ", self.state.label()),
            State::Intact | State::Unknown => String::new(),
        };
        match &self.why {
            None => self.state.label(),
            Some(Why::Mismatch(None)) => "overwritten: contents do not match its type".into(),
            Some(Why::Mismatch(Some(names))) => {
                format!("overwritten: contents do not match its type; {names} now holds this area")
            }
            Some(Why::Unlike(what)) => {
                format!("{own}may be overwritten: its start does not look like {what}")
            }
            Some(Why::Unread) => format!("{own}not judged: its start could not be read"),
            Some(Why::Claimed {
                names,
                used,
                of,
                start,
            }) => {
                let held = if used < of {
                    format!("{names} now holds {}% of this area", percent(*used, *of))
                } else {
                    format!("{names} now holds this area")
                };
                match start {
                    Some(Start::Fits) => {
                        format!("{own}at risk: {held}; it starts as its type should")
                    }
                    Some(Start::Unlike(what)) => format!(
                        "{own}may be overwritten: {held}; its start does not look like {what}"
                    ),
                    Some(Start::Unread) => {
                        format!("{own}may be overwritten: {held}; its start could not be read")
                    }
                    Some(Start::Mismatch) | None => format!("{own}may be overwritten: {held}"),
                }
            }
        }
    }

    /// "\Users\Ann\Documents", with deleted folders marked.
    pub fn folder_text(&self) -> String {
        if self.folder.is_empty() {
            return "\\".into();
        }
        self.folder
            .iter()
            .map(|p| {
                if p.deleted {
                    format!("\\{} (deleted)", p.name)
                } else {
                    format!("\\{}", p.name)
                }
            })
            .collect()
    }
}

impl Found {
    /// About what it holds in memory, for a scan's budget: the struct, its name, its folder
    /// path (each file holds its own copy) and its content's map.
    pub(crate) fn held(&self) -> u64 {
        let parts = count::sum(
            0,
            self.folder
                .iter()
                .map(|p| count::add(std::mem::size_of::<Part>(), p.name.len())),
        );
        let data = match &self.data {
            Data::Resident(v) => v.len(),
            Data::Runs(r) => count::mul(r.len(), std::mem::size_of::<Run>()),
        };
        count::sum(
            0,
            [
                std::mem::size_of::<Found>(),
                self.name.len(),
                parts,
                data,
                self.note.as_ref().map_or(0, String::len),
            ],
        ) as u64
    }
}

/// What a volume scan found.
#[derive(Debug, Default)]
pub struct Listing {
    pub files: Vec<Found>,
    /// What could not be read or made sense of, for people, with the limit the scan reached
    /// in words when it reached one.
    pub notes: Vec<String>,
    /// The limit of its budget the scan reached, if it reached one: the files are those it
    /// found before then.
    pub limit: Option<Limit>,
}

/// Where a volume is and what is on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    pub kind: FsKind,
    /// Byte offset of the volume on the source, and its size.
    pub start: u64,
    pub len: u64,
    pub origin: Origin,
    /// For a lost volume, the current partitions that lie over part of it.
    pub claims: Vec<Claim>,
}

/// An area of the source a current partition table entry holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// "partition 1".
    pub name: String,
    pub range: Range<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The source holds one volume with no partition table.
    Whole,
    /// A partition table entry, numbered from 1.
    Mbr(usize),
    Gpt(usize),
    /// Found by its boot sector with no partition entry pointing at it.
    Found,
    /// Found by NTFS's backup boot sector at the volume's end; the first one is unreadable
    /// or gone.
    Backup,
}

impl Volume {
    pub fn describe(&self) -> String {
        let at = crate::tools::drives::bytes_text(self.start);
        let size = crate::tools::drives::bytes_text(self.len);
        let kind = self.kind.label();
        let text = match self.origin {
            Origin::Whole => format!("{kind} volume, {size}"),
            Origin::Mbr(n) | Origin::Gpt(n) => format!("Partition {n}, {kind}, {size} at {at}"),
            Origin::Found => format!("Lost {kind} volume, {size} at {at}, no partition entry"),
            Origin::Backup => {
                format!("Lost {kind} volume, {size} at {at}, found by its backup boot sector")
            }
        };
        match self.claims_text() {
            Some(names) if self.claims.len() == 1 => {
                format!("{text}; {names} now lies over part of it")
            }
            Some(names) => format!("{text}; {names} now lie over part of it"),
            None => text,
        }
    }

    /// "partition 1 and partition 2", or None when no current partition lies over it.
    fn claims_text(&self) -> Option<String> {
        let names: Vec<&str> = self.claims.iter().map(|c| c.name.as_str()).collect();
        match names.as_slice() {
            [] => None,
            [one] => Some((*one).to_string()),
            [rest @ .., last] => Some(format!("{} and {last}", rest.join(", "))),
        }
    }

    /// A lost volume, found by a boot sector with no partition entry pointing at it.
    pub fn is_lost(&self) -> bool {
        matches!(self.origin, Origin::Found | Origin::Backup)
    }
}

/// Progress of a long read, shared with the window.
#[derive(Debug, Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
    pub found: AtomicU64,
    /// A copy's pace and the time it has left, where the copy measures them.
    pub pace: super::pace::Pace,
}

impl Progress {
    pub fn set(&self, done: u64, total: u64) {
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    /// Done out of total in thousandths.
    pub fn permille(&self) -> u32 {
        let total = self.total.load(Ordering::Relaxed);
        let done = self.done.load(Ordering::Relaxed).min(total);
        // A u64 times 1000 always fits a u128; no total is no progress.
        u128::from(done)
            .checked_mul(1000)
            .and_then(|p| p.checked_div(u128::from(total)))
            .map_or(0, |p| p as u32)
    }
}

/// Reads one volume's files, deleted and in use, within the budget its file system's
/// reader states (`ntfs::LIMITS`, `fat::LIMITS`, `exfat::LIMITS`), stopped by `cancel`.
pub fn scan(
    reader: &mut Reader,
    volume: &Volume,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Result<Listing, String> {
    let limits = match volume.kind {
        FsKind::Ntfs => ntfs::LIMITS,
        FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 => fat::LIMITS,
        FsKind::ExFat => exfat::LIMITS,
    };
    let mut budget = Budget::new(limits, Some(cancel));
    let mut vol = Vol::new(reader, volume.start, volume.len);
    let mut listing = match volume.kind {
        FsKind::Ntfs => ntfs::scan(&mut vol, &mut budget, progress),
        FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 => fat::scan(&mut vol, &mut budget, progress),
        FsKind::ExFat => exfat::scan(&mut vol, &mut budget, progress),
    }?;
    listing.limit = budget.hit();
    if let Some(said) = budget.said() {
        let rest = if budget.hit().is_some() {
            " The files found before then are listed; the rest are not."
        } else {
            ""
        };
        listing.notes.push(format!("{said}{rest}"));
    }
    // Content the volume's map puts outside the volume, or cannot place, is damage.
    for f in &mut listing.files {
        if let Data::Runs(runs) = &f.data {
            f.damaged |= runs.iter().any(|r| r.place == Place::Missing);
        }
    }
    assess(reader, volume, &mut listing, cancel);
    Ok(listing)
}

/// Marks what the volume's own record cannot show: space a current partition now holds,
/// and a start that is not what the file's type begins with. On a lost volume every file
/// is checked; on a current one, the deleted ones.
fn assess(reader: &mut Reader, volume: &Volume, listing: &mut Listing, cancel: &AtomicBool) {
    for f in &mut listing.files {
        if cancel.load(Ordering::Relaxed) || reader.gone().is_some() {
            return;
        }
        if !f.deleted && !volume.is_lost() {
            continue;
        }
        let claim = claimed(&f.data, f.size, &volume.claims);
        // What its start says: at most its first 4 KiB, in one read and never again.
        let start = crate::recovery::carve::Expect::of(&f.name).and_then(|expect| {
            let (data, size) = (&f.data, f.size);
            expect.check(size, &mut |at, n| bytes_at(reader, data, size, at, n))
        });
        f.why = match (start, claim) {
            (Some(Start::Mismatch), claim) => {
                f.state = State::Overwritten;
                Some(Why::Mismatch(claim.map(|c| c.2)))
            }
            (start, Some((used, of, names))) => Some(Why::Claimed {
                names,
                used,
                of,
                start,
            }),
            (Some(Start::Unlike(what)), None) => Some(Why::Unlike(what)),
            (Some(Start::Unread), None) => Some(Why::Unread),
            (Some(Start::Fits) | None, None) => None,
        };
    }
}

/// Bytes of a file's first `size` bytes on the source that lie in current partitions, out
/// of those on the source, with the partitions' names.
fn claimed(data: &Data, size: u64, claims: &[Claim]) -> Option<(u64, u64, String)> {
    let Data::Runs(runs) = data else {
        return None;
    };
    let (mut used, mut of, mut left) = (0u64, 0u64, size);
    let mut names: Vec<&str> = Vec::new();
    // The counts are of bytes within `size`, so no sum of them overflows; a run that would end
    // past the address space is on no source, so in no partition.
    for r in runs {
        let (len, rest) = match left.checked_sub(r.len) {
            Some(rest) => (r.len, rest),
            None => (left, 0),
        };
        left = rest;
        let Place::At(at) = r.place else { continue };
        let Some(end) = at.checked_add(len) else {
            continue;
        };
        of = of.checked_add(len)?;
        // Partition entries can overlap each other; a byte counts once.
        let mut hits: Vec<Range<u64>> = Vec::new();
        for c in claims {
            let (s, e) = (at.max(c.range.start), end.min(c.range.end));
            if s < e {
                hits.push(s..e);
                if !names.contains(&c.name.as_str()) {
                    names.push(&c.name);
                }
            }
        }
        for h in crate::recovery::reader::merge(hits) {
            used = used.checked_add(h.end.checked_sub(h.start)?)?;
        }
    }
    let names = match names.as_slice() {
        [] => return None,
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    Some((used, of, names))
}

/// `n` bytes of a file from byte `at`, each part read once with no retry, since the source
/// may be failing. Unwritten when any lie past its size or were never written (not evidence
/// of anything written over them), Unreadable when any could not be read.
fn bytes_at(
    reader: &mut Reader,
    data: &Data,
    size: u64,
    at: u64,
    n: usize,
) -> Result<Vec<u8>, Missing> {
    let end = at
        .checked_add(n as u64)
        .filter(|end| *end <= size)
        .ok_or(Missing::Unwritten)?;
    let runs = match data {
        Data::Resident(bytes) => {
            return bytes
                .get(at as usize..end as usize)
                .map(<[u8]>::to_vec)
                .ok_or(Missing::Unwritten)
        }
        Data::Runs(runs) => runs,
    };
    // Not sized ahead: it grows with what is read, at most `n`, which the start checks keep
    // to the first 4 KiB of a file.
    let mut out = Vec::new();
    let mut pos = 0u64;
    for r in runs {
        // Runs whose lengths overflow hold no place in the file: what is not read is Unwritten.
        let Some(next) = pos.checked_add(r.len) else {
            break;
        };
        let (from, to) = (at.max(pos), end.min(next));
        if from < to {
            match r.place {
                Place::At(on) => {
                    // A run whose place and length overflow is damage: unreadable.
                    let on = from
                        .checked_sub(pos)
                        .and_then(|skip| on.checked_add(skip))
                        .ok_or(Missing::Unreadable)?;
                    let n = to.checked_sub(from).ok_or(Missing::Unreadable)? as usize;
                    out.extend(reader.read_once(on, n).ok_or(Missing::Unreadable)?);
                }
                Place::Zeros | Place::Missing => return Err(Missing::Unwritten),
            }
        }
        pos = next;
        if pos >= end {
            break;
        }
    }
    if out.len() == n {
        Ok(out)
    } else {
        Err(Missing::Unwritten)
    }
}

/// What file system a boot sector belongs to, and the volume size it states. A boot sector
/// whose size does not fit in a u64 is no volume: its size is never taken for a smaller one.
pub fn identify(boot: &[u8]) -> Option<(FsKind, u64)> {
    let ntfs = || ntfs::Boot::parse(boot).and_then(|b| Some((FsKind::Ntfs, b.volume_len()?)));
    let exfat = || exfat::Boot::parse(boot).and_then(|b| Some((FsKind::ExFat, b.volume_len()?)));
    let fat = || fat::Boot::parse(boot).and_then(|b| Some((b.kind, b.volume_len()?)));
    ntfs().or_else(exfat).or_else(fat)
}

/// A volume's window onto the source: offsets are relative to the volume's start, and
/// nothing outside the volume is ever read.
pub struct Vol<'a, 's> {
    pub reader: &'a mut Reader<'s>,
    pub start: u64,
    pub len: u64,
    /// Unreadable areas met while reading the volume's own structures, in volume offsets.
    pub unreadable: Vec<Range<u64>>,
}

impl<'a, 's> Vol<'a, 's> {
    pub fn new(reader: &'a mut Reader<'s>, start: u64, len: u64) -> Self {
        // A volume that starts past the source's end holds none of it.
        let len = reader
            .len()
            .checked_sub(start)
            .map_or(0, |room| len.min(room));
        Self {
            reader,
            start,
            len,
            unreadable: Vec::new(),
        }
    }

    /// Reads within the volume, or None if any byte is outside it or unreadable. The `len`
    /// bytes are charged to `budget` before they are read, refused past its memory limit,
    /// and stay charged: the caller frees them (`Budget::free`) when it lets them go, also
    /// when the read gives None.
    pub fn read(
        &mut self,
        budget: &mut Budget,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>, Limit> {
        let lossy = self.read_lossy(budget, offset, len)?;
        Ok(lossy.1.then_some(lossy.0))
    }

    /// Reads within the volume with zeros for what is outside it or unreadable; the flag
    /// says whether every byte was read. Charged as `read` is.
    pub fn read_lossy(
        &mut self,
        budget: &mut Budget,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, bool), Limit> {
        let (data, unread) = self.read_marked(budget, offset, len)?;
        Ok((data, unread.is_empty()))
    }

    /// Reads within the volume with zeros for what is outside it or unreadable, with the
    /// ranges of the bytes returned that were not read. Charged as `read` is.
    fn read_marked(
        &mut self,
        budget: &mut Budget,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, Vec<Range<usize>>), Limit> {
        // The bytes the volume holds from `offset` on; the rest of `len` lies outside it.
        let (held, _) = self.split(offset, len as u64);
        let unread_from = |from: usize| (from < len).then_some(from..len);
        let Some(at) = self.place(offset).filter(|_| held > 0) else {
            return Ok((budget.buffer(len)?, unread_from(0).into_iter().collect()));
        };
        // What the reader makes is charged before it makes it; the rest as it grows.
        budget.hold(held)?;
        let lossy = self.reader.read_lossy(at, held as usize);
        let mut data = lossy.data;
        if let Err(limit) = budget.grow(&mut data, len) {
            budget.free(held);
            return Err(limit);
        }
        // Each range lies within the `held` bytes from `offset`, inside the volume.
        for r in &lossy.unreadable {
            if let (Some(s), Some(e)) = (
                offset.checked_add(r.start as u64),
                offset.checked_add(r.end as u64),
            ) {
                self.unreadable.push(s..e);
            }
        }
        let mut unread = lossy.unreadable;
        unread.extend(unread_from(held as usize));
        Ok((data, unread))
    }

    /// How many of `len` bytes from volume byte `offset` the volume holds, and how many lie
    /// past its end, counted without forming an end that could overflow; a place past the
    /// end holds none.
    fn split(&self, offset: u64, len: u64) -> (u64, u64) {
        let Some(room) = self.len.checked_sub(offset) else {
            return (0, len);
        };
        match len.checked_sub(room) {
            Some(outside) => (room, outside),
            None => (len, 0),
        }
    }

    /// A stretch in volume bytes as runs on the source: the one place the NTFS, FAT and exFAT
    /// listings make a `Place::At`. Only bytes inside the volume, which `new` keeps inside the
    /// source, are placed; the rest of `len`, however far it reaches or if it overflows, is
    /// Missing, so no run of a listing names a byte past the source and the runs add up to `len`.
    pub fn runs(&self, offset: u64, len: u64) -> Vec<Run> {
        let (inside, outside) = self.split(offset, len);
        let mut runs = Vec::new();
        let missing = match self.place(offset) {
            Some(at) if inside > 0 => {
                runs.push(Run {
                    place: Place::At(at),
                    len: inside,
                });
                outside
            }
            _ => len,
        };
        if missing > 0 {
            runs.push(Run {
                place: Place::Missing,
                len: missing,
            });
        }
        runs
    }

    /// Where volume byte `offset` lies on the source; None past the address space, which no
    /// byte inside the volume is, since `new` keeps the volume inside the source.
    fn place(&self, offset: u64) -> Option<u64> {
        self.start.checked_add(offset)
    }

    /// The volume offset of a run's place; None for a place before the volume, which no run
    /// `runs` made is.
    pub fn offset(&self, at: u64) -> Option<u64> {
        at.checked_sub(self.start)
    }
}

/// The `N` bytes at `at`, None past the end of `b`.
fn bytes_of<const N: usize>(b: &[u8], at: usize) -> Option<&[u8; N]> {
    b.get(at..)?.first_chunk::<N>()
}

/// How the walk of a chain of clusters or of a runlist ended, as only the walk that read it
/// can say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// On the chain's end-of-chain marker, or the runlist's zero header.
    Marker,
    /// At the most the walk takes, with the chain or runlist going on.
    Limit,
    /// On an entry that is no valid next cluster (unreadable, free, bad or out of range), a
    /// malformed or cut runlist entry, or more pieces than a file may have.
    Broken,
}

/// A chain's clusters as (first cluster, count) pieces, the clusters taken, and how the walk
/// ended.
pub(crate) type Chain = (Vec<(u64, u64)>, u64, End);

/// What ends a structure, and so what makes it whole once read.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Ending {
    /// A place and size its records state, with no chain to walk: a fixed root, or a folder
    /// marked or taken as contiguous.
    Stated,
    /// A chain or runlist, ended as its walk found: whole only on its `End::Marker`.
    Walked(End),
    /// No stated size and no chain, as a deleted folder: it ends at the first stretch read
    /// whose entries hold their end marker, which this finds.
    Entries(fn(&[u8]) -> bool),
}

/// A structure of the volume's own (a folder, an attribute list) as its records lay it out.
pub(crate) struct Layout {
    /// Where its bytes are, in order.
    pub runs: Vec<Run>,
    /// The bytes it declares: its stated size, or its chain's clusters.
    pub extent: u64,
    pub ending: Ending,
}

/// A structure as read: its bytes, zeros where they could not be read, and the ranges of them
/// that were not.
pub(crate) struct Structure {
    pub bytes: Vec<u8>,
    pub unread: Vec<Range<usize>>,
    /// It met its ending (`read_structure` says how) and every byte it holds was read.
    pub whole: bool,
}

impl Structure {
    /// The entries of the stretches that were read, in order, each parsed by `parse`, which
    /// says whether it met the entries' end marker. The entries end at a marker that was
    /// read, never at the zeros of a part that could not be.
    pub(crate) fn entries<T>(&self, mut parse: impl FnMut(&[u8]) -> (Vec<T>, bool)) -> Vec<T> {
        let mut out = Vec::new();
        for part in stretches(&self.bytes, &self.unread) {
            let (found, ended) = parse(part);
            out.extend(found);
            if ended {
                break;
            }
        }
        out
    }
}

/// The stretches of `bytes` between the sorted ranges `gaps`, in order.
fn stretches<'b>(bytes: &'b [u8], gaps: &'b [Range<usize>]) -> impl Iterator<Item = &'b [u8]> {
    let end = bytes.len();
    let mut from = 0;
    gaps.iter()
        .cloned()
        .chain(std::iter::once(end..end))
        .filter_map(move |gap| {
            let part = bytes.get(from..gap.start);
            from = from.max(gap.end);
            part
        })
}

/// Reads a structure, at most `most` bytes, each `unit` bytes of a run (a cluster) its own
/// read, so one that fails costs no neighbor: a drive's failed read is tried again only in
/// 4 KiB pieces. A run the volume's map puts outside the volume or never wrote, or whose
/// place cannot be formed, is a gap of zeros where it lies, and the runs after it are still
/// read. Charged to `budget` as read and as held, as `Vol::read` is; on a refusal nothing
/// stays charged. It is whole only when every byte it holds was read and its ending was met:
/// its stated extent, its walk's end marker with the extent, or its entries' end marker.
pub(crate) fn read_structure(
    vol: &mut Vol,
    budget: &mut Budget,
    layout: &Layout,
    most: u64,
    unit: u64,
) -> Result<Structure, Limit> {
    let want = layout.extent.min(most);
    let unit = if unit == 0 { u64::MAX } else { unit };
    let mut bytes = Vec::new();
    let mut unread: Vec<Range<usize>> = Vec::new();
    let mut marker = false;
    'runs: for r in &layout.runs {
        let start = match r.place {
            Place::At(at) => vol.offset(at),
            Place::Zeros | Place::Missing => None,
        };
        let mut done = 0u64;
        while let Some(rest) = r.len.checked_sub(done).filter(|n| *n > 0) {
            // Once `want` bytes are held, the read ends.
            let Some(room) = want.checked_sub(bytes.len() as u64).filter(|n| *n > 0) else {
                break 'runs;
            };
            let piece = rest.min(room).min(unit);
            let got = match start.and_then(|s| s.checked_add(done)) {
                Some(offset) => budget
                    .read(piece)
                    .and_then(|()| vol.read_marked(budget, offset, piece as usize)),
                None => budget
                    .buffer(piece as usize)
                    .map(|b| (b, std::iter::once(0..piece as usize).collect())),
            };
            let (b, gaps) = match got {
                Ok(got) => got,
                Err(limit) => {
                    budget.free(bytes.len() as u64);
                    return Err(limit);
                }
            };
            // Only bytes that were read can hold the entries' end marker.
            if let Ending::Entries(ends) = layout.ending {
                marker = stretches(&b, &gaps).any(ends);
            }
            // Places in the bytes held in memory.
            let base = bytes.len();
            unread.extend(
                gaps.into_iter()
                    .map(|g| count::add(base, g.start)..count::add(base, g.end)),
            );
            bytes.extend(b);
            if marker {
                break 'runs;
            }
            // `piece` is at most `rest`, so this is at most `r.len`.
            done = done.checked_add(piece).unwrap_or(r.len);
        }
    }
    let held = bytes.len() as u64;
    let met = match layout.ending {
        Ending::Stated => held == layout.extent,
        Ending::Walked(end) => end == End::Marker && held == layout.extent,
        Ending::Entries(_) => marker,
    };
    let whole = met && unread.is_empty();
    Ok(Structure {
        bytes,
        unread: crate::recovery::reader::merge(unread),
        whole,
    })
}

/// The listing's note for `n` folders a walk could not read in full, if any.
pub(crate) fn incomplete_folders(n: u64) -> Option<String> {
    (n > 0).then(|| {
        format!("{n} folders could not be read in full; files listed there may be missing.")
    })
}

pub(crate) fn le16(b: &[u8], at: usize) -> u16 {
    bytes_of(b, at).map_or(0, |s| u16::from_le_bytes(*s))
}

pub(crate) fn le32(b: &[u8], at: usize) -> u32 {
    bytes_of(b, at).map_or(0, |s| u32::from_le_bytes(*s))
}

pub(crate) fn le64(b: &[u8], at: usize) -> u64 {
    bytes_of(b, at).map_or(0, |s| u64::from_le_bytes(*s))
}

/// UTF-16LE to a string, stopping at a NUL.
pub(crate) fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Joins adjacent runs and adds up their length.
pub(crate) fn tidy(runs: Vec<Run>) -> Vec<Run> {
    // Not sized ahead: it holds at most the runs given, already held.
    let mut out: Vec<Run> = Vec::new();
    for r in runs.into_iter().filter(|r| r.len > 0) {
        if let Some(last) = out.last_mut() {
            let joins = match (last.place, r.place) {
                (Place::At(a), Place::At(b)) => a.checked_add(last.len) == Some(b),
                (Place::Zeros, Place::Zeros) | (Place::Missing, Place::Missing) => true,
                _ => false,
            };
            // Two runs whose lengths together overflow stay apart.
            if let Some(len) = last.len.checked_add(r.len).filter(|_| joins) {
                last.len = len;
                continue;
            }
        }
        out.push(r);
    }
    out
}

/// Adds cluster `n` to the last of a chain's (first cluster, count) `pieces` when it is the
/// next one; false when it is not.
pub(crate) fn join(pieces: &mut [(u64, u64)], n: u64) -> bool {
    match pieces.last_mut() {
        Some((start, len)) if start.checked_add(*len) == Some(n) => match len.checked_add(1) {
            Some(grown) => {
                *len = grown;
                true
            }
            None => false,
        },
        _ => false,
    }
}

/// Total length of runs; None when it does not fit in a u64, more than any source holds.
pub fn runs_len(runs: &[Run]) -> Option<u64> {
    runs.iter().try_fold(0u64, |sum, r| sum.checked_add(r.len))
}

/// Cuts runs to `size` bytes; a shortfall is Missing.
pub(crate) fn cut(runs: Vec<Run>, size: u64) -> Vec<Run> {
    let mut out = Vec::new();
    let mut left = size;
    for r in runs {
        if left == 0 {
            break;
        }
        let (len, rest) = match left.checked_sub(r.len) {
            Some(rest) => (r.len, rest),
            None => (left, 0),
        };
        out.push(Run {
            place: r.place,
            len,
        });
        left = rest;
    }
    if left > 0 {
        out.push(Run {
            place: Place::Missing,
            len: left,
        });
    }
    tidy(out)
}

/// A volume's record of which clusters are used, counted by ranges: a bit per cluster with
/// a running count every `RANK` clusters, so the used clusters of a run are counted in a
/// few steps however long the run is, never one cluster at a time.
pub(crate) struct Used {
    bits: Vec<u8>,
    /// The cluster number of bit 0.
    first: u64,
    /// Cluster ranges whose state could not be read, sorted.
    unknown: Vec<Range<u64>>,
    /// What a cluster outside the bits is: used (FAT and exFAT give a cluster past the
    /// volume's end to nothing else) or unknown (NTFS).
    outside: Option<bool>,
    /// Used clusters before each block of `RANK`, and in all.
    rank: Vec<u64>,
    total: u64,
}

fn ones(bytes: &[u8]) -> u64 {
    bytes.iter().map(|b| u64::from(b.count_ones())).sum()
}

const RANK: u64 = 4096;

impl Used {
    pub(crate) fn new(
        bits: Vec<u8>,
        first: u64,
        mut unknown: Vec<Range<u64>>,
        outside: Option<bool>,
    ) -> Used {
        // Not sized ahead: one count for every 512 bytes of `bits`, which its caller charged
        // before it read them; the whole is charged with `held` once made.
        let mut rank = Vec::new();
        let mut total = 0u64;
        for block in bits.chunks((RANK / 8) as usize) {
            rank.push(total);
            total = count::add(total, ones(block));
        }
        unknown.sort_by_key(|r| r.start);
        Used {
            bits,
            first,
            unknown,
            outside,
            rank,
            total,
        }
    }

    /// The bytes of its bits, as read and charged before it was made.
    pub(crate) fn bits_len(&self) -> u64 {
        self.bits.len() as u64
    }

    /// What it holds in memory, for a scan's budget.
    pub(crate) fn held(&self) -> u64 {
        count::sum(
            0,
            [
                self.bits.len(),
                count::mul(self.rank.len(), 8),
                count::mul(self.unknown.len(), std::mem::size_of::<Range<u64>>()),
            ],
        ) as u64
    }

    /// Used clusters among bits `0..n`, which lie in the bits: counts of the bits held.
    fn before(&self, n: u64) -> u64 {
        let block = (n / RANK) as usize;
        let Some(&base) = self.rank.get(block) else {
            return self.total;
        };
        let from = count::mul(block, (RANK / 8) as usize);
        let whole = (n / 8) as usize;
        let mut used = count::add(base, ones(&self.bits[from..whole]));
        if !n.is_multiple_of(8) {
            // The bits below `n` in its byte.
            let low = !(u8::MAX << (n % 8));
            used = count::add(used, u64::from((self.bits[whole] & low).count_ones()));
        }
        used
    }

    /// Used clusters in `from..to`, or None when any of them is unknown.
    pub(crate) fn count(&self, from: u64, to: u64) -> Option<u64> {
        if from >= to {
            return Some(0);
        }
        let i = self.unknown.partition_point(|r| r.end <= from);
        if self.unknown.get(i).is_some_and(|r| r.start < to) {
            return None;
        }
        // The bits held span `lo..hi`, a count of what is in memory from cluster 0 or 2.
        // `from..to` holds `a..b`, which lies within `lo..hi`, so no difference below fails.
        let (lo, hi) = (
            self.first,
            count::add(self.first, count::mul(self.bits.len() as u64, 8)),
        );
        let (a, b) = (from.clamp(lo, hi), to.clamp(lo, hi));
        let outside = to.checked_sub(from)?.checked_sub(b.checked_sub(a)?)?;
        let mut used = self
            .before(b.checked_sub(lo)?)
            .checked_sub(self.before(a.checked_sub(lo)?))?;
        if outside > 0 {
            used = used.checked_add(match self.outside? {
                true => outside,
                false => 0,
            })?;
        }
        Some(used)
    }
}

/// Counts a file's clusters that the volume now records as used (volume-relative cluster
/// numbers from `first_cluster_no`), by ranges. Unknown wins.
pub(crate) fn overwritten(
    runs: &[Run],
    vol_start: u64,
    heap: u64,
    cluster: u64,
    first_cluster_no: u64,
    used: &Used,
) -> State {
    let (mut hit, mut of) = (0u64, 0u64);
    for r in runs {
        let Place::At(at) = r.place else { continue };
        // A run before the heap, or a heap past the address space, holds no cluster.
        let Some(rel) = vol_start.checked_add(heap).and_then(|h| at.checked_sub(h)) else {
            continue;
        };
        // A run that would end past the address space, or cluster numbers past it, are no
        // clusters the record holds: what the file's space holds is unknown.
        let counted = rel.checked_div(cluster).and_then(|first| {
            let last = rel.checked_add(r.len)?.div_ceil(cluster);
            let n = used.count(
                first.checked_add(first_cluster_no)?,
                last.checked_add(first_cluster_no)?,
            )?;
            Some((last.checked_sub(first)?, n))
        });
        let Some((clusters, n)) = counted else {
            return State::Unknown;
        };
        let (Some(o), Some(h)) = (of.checked_add(clusters), hit.checked_add(n)) else {
            return State::Unknown;
        };
        (of, hit) = (o, h);
    }
    State::from_counts(hit, of)
}

/// A source of `len` bytes that holds `head` at its start and zeros after it, counting the
/// bytes read, for tests of what a damaged boot sector makes the readers ask for.
#[cfg(test)]
pub(crate) fn test_source(head: Vec<u8>, len: u64) -> (Reader<'static>, std::sync::Arc<AtomicU64>) {
    struct Sparse {
        head: Vec<u8>,
        len: u64,
        read: std::sync::Arc<AtomicU64>,
    }
    impl super::BlockSource for Sparse {
        fn len(&self) -> u64 {
            self.len
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), super::ReadError> {
            self.read.fetch_add(buf.len() as u64, Ordering::Relaxed);
            buf.fill(0);
            let start = (offset as usize).min(self.head.len());
            let end = (offset as usize)
                .saturating_add(buf.len())
                .min(self.head.len());
            buf[..end.saturating_sub(start)].copy_from_slice(&self.head[start..end]);
            Ok(())
        }
        fn describe(&self) -> String {
            "sparse test source".into()
        }
    }
    let read = std::sync::Arc::new(AtomicU64::new(0));
    let source = Sparse {
        head,
        len,
        read: read.clone(),
    };
    (Reader::new(Box::new(source)), read)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// The guard: the used clusters of a range are counted by ranges and agree with a count
    /// one cluster at a time, unknown clusters and those past the bits included; and a run
    /// of a quarter of a billion clusters is counted at once.
    #[test]
    fn used_clusters_are_counted_by_ranges() {
        let mut state = 7u64;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };
        let bits: Vec<u8> = (0..3000).map(|_| next() as u8).collect();
        let first = 2u64;
        let unknown = vec![9000..9100, 15_000..15_001];
        for outside in [Some(true), Some(false), None] {
            let used = Used::new(bits.clone(), first, unknown.clone(), outside);
            let naive = |from: u64, to: u64| -> Option<u64> {
                let mut n = 0;
                for c in from..to {
                    if unknown.iter().any(|r| r.contains(&c)) {
                        return None;
                    }
                    let bit = c.checked_sub(first).filter(|b| *b < 24_000);
                    n += match bit {
                        Some(b) => u64::from(bits[(b / 8) as usize] >> (b % 8) & 1),
                        None => u64::from(outside?),
                    };
                }
                Some(n)
            };
            for _ in 0..2000 {
                let from = next() % 26_000;
                let to = from + next() % 5000;
                assert_eq!(
                    used.count(from, to),
                    naive(from, to),
                    "{from}..{to} {outside:?}"
                );
            }
        }
        let used = Used::new(vec![0xFF; 1 << 20], 0, Vec::new(), Some(true));
        let started = std::time::Instant::now();
        let runs = [Run {
            place: Place::At(1 << 20),
            len: 1 << 40,
        }];
        assert_eq!(
            overwritten(&runs, 0, 1 << 20, 4096, 0, &used),
            State::from_counts(1 << 28, 1 << 28)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// The guard (review F9, round 5): saturated arithmetic is not terminal, since later steps
    /// can bring a saturated place back into range, so the file system readers and the reader
    /// combine what they read only with checked arithmetic. Saturation is left only for what
    /// the program holds or spends, through `count`, where it can be seen.
    #[test]
    fn saturating_arithmetic_is_only_in_the_count_helper() {
        let reader = include_str!("../reader.rs");
        let reader = reader.split("#[cfg(test)]").next().unwrap();
        let files = [
            "fs/ntfs.rs",
            "fs/fat.rs",
            "fs/exfat.rs",
            "fs/parts.rs",
            "fs/mod.rs",
        ]
        .map(|f| (f, crate::budget::parser_code(f)));
        for (file, code) in files.into_iter().chain([("reader.rs", reader)]) {
            let found: Vec<(usize, &str)> = code
                .lines()
                .enumerate()
                .filter(|(_, l)| l.contains("saturating_"))
                .map(|(n, l)| (n + 1, l.trim()))
                .collect();
            assert!(
                found.is_empty(),
                "{file} saturates outside `count`: {found:?}"
            );
        }
        assert!(include_str!("count.rs").contains("saturating_add"));
    }

    /// The guard (review F9, round 5): a boot sector whose volume size overflows a u64 is no
    /// volume, never one whose size saturates and is then cut to the whole source.
    #[test]
    fn a_volume_size_past_the_address_space_is_no_volume() {
        let mut boot = vec![0u8; 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        boot[0x0D] = 8;
        // Sectors whose bytes fit in a u64, but not with the backup boot sector after them.
        boot[0x28..0x30].copy_from_slice(&(u64::MAX / 512).to_le_bytes());
        boot[0x30..0x38].copy_from_slice(&4u64.to_le_bytes());
        boot[0x38..0x40].copy_from_slice(&8u64.to_le_bytes());
        boot[0x40] = 0xF6;
        assert!(ntfs::Boot::parse(&boot).is_none());
        assert_eq!(identify(&boot), None);
        let (mut reader, _) = test_source(boot, 1 << 20);
        let finds = parts::find(
            &mut reader,
            parts::Search::Tables,
            &AtomicBool::new(false),
            &Progress::default(),
        );
        assert!(finds.volumes.is_empty(), "{:?}", finds.volumes);
    }

    /// The guard (review F9): every listing makes its `Place::At` runs in `Vol::runs`, which
    /// places only bytes inside the volume and makes the rest of the stretch Missing, so a
    /// run that reaches past the source, or whose length overflows, is unreadable there and
    /// nothing downstream sees a position outside the source.
    #[test]
    fn a_listing_never_places_a_byte_past_the_source_and_its_runs_add_up() {
        let mut reader = Reader::new(Box::new(MemDisk::new(vec![0u8; 1 << 20])));
        let vol = Vol::new(&mut reader, 4096, 1 << 19);
        let (start, end) = (vol.start, vol.start + vol.len);
        for (offset, len) in [
            (0, 10),
            (0, 0),
            (100, u64::MAX),
            (vol.len - 1, 5),
            (vol.len, 5),
            (u64::MAX, u64::MAX),
            (10, u64::MAX - 5),
        ] {
            let runs = vol.runs(offset, len);
            assert_eq!(runs_len(&runs), Some(len), "{offset} {len}: {runs:?}");
            for run in &runs {
                if let Place::At(at) = run.place {
                    assert!(
                        start <= at && at + run.len <= end,
                        "{offset} {len}: {runs:?}"
                    );
                }
            }
        }
        assert_eq!(
            vol.runs(vol.len - 1, 5),
            vec![
                Run {
                    place: Place::At(end - 1),
                    len: 1
                },
                Run {
                    place: Place::Missing,
                    len: 4
                }
            ]
        );
        for code in [
            include_str!("ntfs.rs"),
            include_str!("fat.rs"),
            include_str!("exfat.rs"),
        ] {
            let code = code.split("#[cfg(test)]").next().unwrap();
            assert!(
                !code.contains("place: Place::At("),
                "a listing places a run outside Vol::runs"
            );
        }
    }

    /// The guard (review F9): a read that runs past the end of a volume as long as the
    /// address space is not whole: the bytes past it are zeros, never counted as read.
    #[test]
    fn a_read_past_the_end_of_the_largest_volume_is_not_whole() {
        let (mut reader, _) = test_source(Vec::new(), u64::MAX);
        let mut vol = Vol::new(&mut reader, 0, u64::MAX);
        let mut budget = Budget::new(ntfs::LIMITS, None);
        let (data, whole) = vol.read_lossy(&mut budget, u64::MAX - 4, 8).unwrap();
        assert_eq!(data, vec![0; 8]);
        assert!(!whole, "8 bytes from u64::MAX - 4 read whole");
        budget.free(8);
        assert_eq!(vol.read(&mut budget, u64::MAX - 4, 8), Ok(None));
        budget.free(8);
        let (_, whole) = vol.read_lossy(&mut budget, u64::MAX - 4, 4).unwrap();
        assert!(whole);
        budget.free(4);
    }

    /// The guard: a time a record could not hold is said to be unreadable, never shown as
    /// 1970.
    #[test]
    fn an_impossible_time_is_said_to_be_unreadable() {
        for secs in [-1, i64::MIN, 253_402_300_800, i64::MAX] {
            assert_eq!(Modified::Utc(secs).text(), UNREADABLE_TIME, "{secs}");
        }
        assert!(Modified::Utc(1_700_000_000).text().starts_with("2023-11-1"));
    }

    use crate::recovery::{BlockSource, MemDisk, ReadError};
    use std::sync::{Arc, Mutex};

    /// A test disk the test keeps a hold of, to see the reads asked of it.
    struct Shared(Arc<Mutex<MemDisk>>);

    impl BlockSource for Shared {
        fn len(&self) -> u64 {
            self.0.lock().unwrap().len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.0.lock().unwrap().read_at(offset, buf)
        }
        fn describe(&self) -> String {
            "shared test disk".into()
        }
    }

    /// The guard: a file whose start cannot be read costs one read of at most 4 KiB, never
    /// a retry in pieces, and is not judged by it, with or without a partition over it.
    #[test]
    fn an_unreadable_start_is_read_once_and_not_judged() {
        const AREA: u64 = 64 << 10;
        let names = ["a.docx", "a.jpg", "b.docx"];
        let mut disk = MemDisk::new(vec![0x5A; names.len() * AREA as usize]);
        disk.bad = names
            .iter()
            .enumerate()
            .map(|(i, _)| i as u64 * AREA..i as u64 * AREA + 512)
            .collect();
        let disk = Arc::new(Mutex::new(disk));
        let mut reader = Reader::new(Box::new(Shared(disk.clone())));
        let volume = Volume {
            kind: FsKind::Ntfs,
            start: 0,
            len: names.len() as u64 * AREA,
            origin: Origin::Backup,
            claims: vec![Claim {
                name: "partition 1".into(),
                range: 2 * AREA..3 * AREA,
            }],
        };
        let mut listing = Listing {
            files: names
                .iter()
                .enumerate()
                .map(|(i, name)| Found {
                    size: AREA,
                    data: Data::Runs(vec![Run {
                        place: Place::At(i as u64 * AREA),
                        len: AREA,
                    }]),
                    ..file(name, i as u64 * AREA)
                })
                .collect(),
            notes: Vec::new(),
            limit: None,
        };
        assess(&mut reader, &volume, &mut listing, &AtomicBool::new(false));
        let reads = disk.lock().unwrap().reads.clone();
        assert_eq!(reads, [(0, 4096), (AREA, 512), (2 * AREA, 4096)]);
        let texts: Vec<(String, State)> = listing
            .files
            .iter()
            .map(|f| (f.state_text(), f.state))
            .collect();
        assert_eq!(
            texts,
            [
                (
                    "not judged: its start could not be read".to_string(),
                    State::Intact
                ),
                (
                    "not judged: its start could not be read".to_string(),
                    State::Intact
                ),
                (
                    "may be overwritten: partition 1 now holds this area; its start could not be read"
                        .to_string(),
                    State::Intact
                ),
            ]
        );
    }

    fn file(name: &str, at: u64) -> Found {
        Found {
            name: name.into(),
            folder: Vec::new(),
            size: 1000,
            modified: None,
            deleted: true,
            state: State::Intact,
            data: Data::Runs(vec![Run {
                place: Place::At(at),
                len: 1000,
            }]),
            damaged: false,
            note: None,
            why: None,
        }
    }

    /// The guard: what a partition over a file's area means depends on what its start can
    /// show. A type with no known start may be overwritten; one that starts as it should is
    /// at risk; one that does not is overwritten. Without a partition, only the last counts.
    #[test]
    fn a_claimed_area_is_judged_by_the_files_start() {
        let mut head = vec![0x5A; 8192];
        head[4096..4104].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        let (mut reader, _) = test_source(head, 1 << 20);
        let volume = Volume {
            kind: FsKind::Ntfs,
            start: 0,
            len: 1 << 20,
            origin: Origin::Backup,
            claims: vec![Claim {
                name: "partition 1".into(),
                range: 0..1 << 19,
            }],
        };
        let mut listing = Listing {
            files: vec![
                file("data.bin", 0),
                file("picture.png", 4096),
                file("picture.png", 0),
                file("far.bin", 1 << 19),
            ],
            notes: Vec::new(),
            limit: None,
        };
        assess(&mut reader, &volume, &mut listing, &AtomicBool::new(false));
        let texts: Vec<(String, State)> = listing
            .files
            .iter()
            .map(|f| (f.state_text(), f.state))
            .collect();
        assert_eq!(
            texts,
            vec![
                (
                    "may be overwritten: partition 1 now holds this area".into(),
                    State::Intact
                ),
                (
                    "at risk: partition 1 now holds this area; it starts as its type should".into(),
                    State::Intact
                ),
                (
                    "overwritten: contents do not match its type; partition 1 now holds this area"
                        .into(),
                    State::Overwritten
                ),
                ("intact".into(), State::Intact),
            ]
        );
    }

    /// The guard: assessment reads at most a file's first 4 KiB, in one read through its
    /// runs, and never its end, whatever its type; an ISO's one read is its 2 KiB volume
    /// descriptor at 32 KiB instead. On a failing source every read counts.
    #[test]
    fn assessment_reads_only_the_first_4_kib_of_each_file() {
        // Each file has its first 1 KiB in one run and the rest 8 KiB further on, with an
        // end record and a box at its end for a check that would look there.
        const AREA: u64 = 512 << 10;
        const SIZE: u64 = 256 << 10;
        let names = [
            "a.jpg", "a.png", "a.gif", "a.bmp", "a.pdf", "a.docx", "a.xlsx", "a.mp4", "a.wav",
            "a.avi", "a.webp", "a.7z", "a.rar", "a.iso", "a.bin",
        ];
        let mut bytes = vec![0x5A; names.len() * AREA as usize];
        let runs = |base: u64| {
            vec![
                Run {
                    place: Place::At(base),
                    len: 1024,
                },
                Run {
                    place: Place::At(base + 8192),
                    len: SIZE - 1024,
                },
            ]
        };
        let end = |base: u64| (base + 8192 + SIZE - 1024 - 22) as usize;
        let mut files = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let base = i as u64 * AREA;
            bytes[end(base)..end(base) + 4].copy_from_slice(b"PK\x05\x06");
            files.push(Found {
                size: SIZE,
                data: Data::Runs(runs(base)),
                ..file(name, base)
            });
        }
        let disk = Arc::new(Mutex::new(MemDisk::new(bytes)));
        let mut reader = Reader::new(Box::new(Shared(disk.clone())));
        let volume = Volume {
            kind: FsKind::Ntfs,
            start: 0,
            len: names.len() as u64 * AREA,
            origin: Origin::Backup,
            claims: Vec::new(),
        };
        let mut listing = Listing {
            files,
            notes: Vec::new(),
            limit: None,
        };
        assess(&mut reader, &volume, &mut listing, &AtomicBool::new(false));
        let reads = disk.lock().unwrap().reads.clone();
        for (i, name) in names.iter().enumerate() {
            let base = i as u64 * AREA;
            // File bytes from 1024 on lie at base + 8192 - 1024 + offset.
            let first = if *name == "a.iso" {
                let at = base + 8192 - 1024 + 0x8000;
                std::iter::once(at..at + 2048).collect::<Vec<_>>()
            } else {
                vec![base..base + 1024, base + 8192..base + 8192 + 3072]
            };
            let mine: Vec<&(u64, usize)> = reads
                .iter()
                .filter(|(at, _)| (base..base + AREA).contains(at))
                .collect();
            let read: usize = mine.iter().map(|(_, n)| n).sum();
            let most = if *name == "a.iso" { 2048 } else { 4096 };
            assert!(read <= most, "{name}: {read} bytes read, {mine:?}");
            for &&(at, n) in &mine {
                let range = at..at + n as u64;
                assert!(
                    first
                        .iter()
                        .any(|f| f.start <= range.start && range.end <= f.end),
                    "{name} read {range:?} outside its first 4 KiB"
                );
            }
        }
        let texts: Vec<(&str, String, State)> = listing
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.state_text(), f.state))
            .collect();
        let unlike =
            |what: &str| format!("may be overwritten: its start does not look like {what}");
        for (name, text, state) in texts {
            let want = match name {
                "a.pdf" => (unlike("a PDF document"), State::Intact),
                "a.docx" | "a.xlsx" => (unlike("a zip document"), State::Intact),
                "a.bin" => ("intact".into(), State::Intact),
                _ => (
                    "overwritten: contents do not match its type".into(),
                    State::Overwritten,
                ),
            };
            assert_eq!((text, state), want, "{name}");
        }
    }
}
