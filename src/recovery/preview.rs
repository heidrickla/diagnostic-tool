//! Built-in previews: the small JPEGs cameras and raw formats carry inside a photo (the EXIF
//! thumbnail, a Multi-Picture preview, a raw file's preview images), found from a photo whose
//! own picture is damaged but whose start reads. Every parse is bounded and checked: a
//! preview is taken only when every byte of it was read and it is a whole JPEG, from its
//! start marker through its end marker with every segment inside it.
//!
//! The engine, `run`, writes the largest preview of each picture beside it as
//! "name (preview).jpg"; the recovery of deleted and lost files calls `best` and writes it the
//! same way for each damaged photo it recovers.
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::ops::Range;
use std::os::windows::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use super::dest::{Folder, Guard};
use crate::budget::{Budget, Limit, Limits};

/// The largest preview taken, and so the most any one read asks for.
pub const PREVIEW_MAX: u64 = 64 << 20;

/// What the search of one picture may spend. Its parts are the IFDs and their entries, the
/// boxes, the JPEG segments and the Multi-Picture index entries it reads: a camera's file
/// has tens to a few hundred, so 16,384 leaves room for any real one. It reads at most
/// four whole previews' worth (256 MiB), since each possible preview found is read whole to
/// be checked; it holds the one preview it is checking (up to `PREVIEW_MAX`), charged before
/// it is made, and at most 4 MiB of offsets still to visit and previews still to check
/// (24 bytes each), and follows boxes four deep (CR3 needs three). 30 seconds a picture:
/// the engine reads a folder of pictures, and one that reads slowly or is built to waste
/// time is given up with its reason so the rest are read.
pub const LIMITS: Limits = Limits {
    what: "the search of the picture for previews",
    unit: "parts of the picture",
    count: 16_384,
    bytes: 4 * PREVIEW_MAX,
    memory: PREVIEW_MAX + (4 << 20),
    depth: 4,
    nested: "boxes",
    time: Some(std::time::Duration::from_secs(30)),
};

/// Held for one offset queued or one possible preview kept.
const QUEUED: u64 = 8;
const CANDIDATE: u64 = 24;

/// Bytes of a picture by offset, into a buffer the search made within its budget; false when
/// any byte asked for is outside it or was not read.
pub trait Bytes {
    fn len(&self) -> u64;
    fn fill(&mut self, at: u64, buf: &mut [u8]) -> bool;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A picture in memory, with the ranges that were not read.
pub struct Slice<'a> {
    pub bytes: &'a [u8],
    pub unreadable: &'a [Range<u64>],
}

impl Bytes for Slice<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn fill(&mut self, at: u64, buf: &mut [u8]) -> bool {
        let n = buf.len();
        let Some(end) = at.checked_add(n as u64) else {
            return false;
        };
        if end > self.len() || n as u64 > PREVIEW_MAX || overlaps(self.unreadable, at, end) {
            return false;
        }
        buf.copy_from_slice(&self.bytes[at as usize..end as usize]);
        true
    }
}

/// A picture file on disk, of `len` bytes, with the ranges that were not read.
pub struct FileBytes<'a> {
    pub file: &'a File,
    pub len: u64,
    pub unreadable: &'a [Range<u64>],
}

impl Bytes for FileBytes<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn fill(&mut self, at: u64, buf: &mut [u8]) -> bool {
        let n = buf.len();
        let Some(end) = at.checked_add(n as u64) else {
            return false;
        };
        if end > self.len || n as u64 > PREVIEW_MAX || overlaps(self.unreadable, at, end) {
            return false;
        }
        let mut done = 0;
        while done < n {
            match self.file.seek_read(&mut buf[done..], at + done as u64) {
                Ok(0) | Err(_) => return false,
                Ok(k) => done += k,
            }
        }
        true
    }
}

fn overlaps(ranges: &[Range<u64>], start: u64, end: u64) -> bool {
    ranges.iter().any(|r| r.start < end && start < r.end)
}

/// Where in a picture a preview was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Source {
    /// The thumbnail in the EXIF block's second IFD.
    ExifThumbnail,
    /// A preview image named by the Multi-Picture Format index (most cameras' large preview).
    MultiPicture,
    /// A JPEG named by a TIFF-based raw file's IFDs (CR2, NEF, ARW, DNG, ORF, RW2, PEF).
    RawIfd,
    /// The preview JPEG in a Fujifilm RAF header.
    Raf,
    /// The preview or thumbnail box of a Canon CR3.
    Cr3,
}

impl Source {
    /// For people.
    pub fn label(self) -> &'static str {
        match self {
            Source::ExifThumbnail => "EXIF thumbnail",
            Source::MultiPicture => "camera preview (Multi-Picture)",
            Source::RawIfd => "raw file preview",
            Source::Raf => "Fujifilm preview",
            Source::Cr3 => "Canon CR3 preview",
        }
    }
}

/// A preview found and checked: a whole JPEG at `at` of `len` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview {
    pub at: u64,
    pub len: u64,
    pub source: Source,
}

/// The length of the whole JPEG at the start of `b`, through its end marker, when it is one a
/// viewer shows: a start marker, a baseline, extended or progressive frame with a size and one
/// to four components, a scan after it, every segment inside `b`, and an end marker.
pub fn jpeg_len(b: &[u8]) -> Option<usize> {
    if b.len() < 4 || b[..3] != [0xFF, 0xD8, 0xFF] {
        return None;
    }
    let (mut pos, mut frame, mut scan) = (2usize, false, false);
    loop {
        if *b.get(pos)? != 0xFF {
            return None;
        }
        let mut marker = *b.get(pos + 1)?;
        while marker == 0xFF {
            pos += 1;
            marker = *b.get(pos + 1)?;
        }
        pos += 2;
        match marker {
            0xD9 => return (frame && scan).then_some(pos),
            0xD0..=0xD7 | 0x01 => {}
            0xD8 | 0x00 => return None,
            _ => {
                let len = usize::from(u16::from_be_bytes([*b.get(pos)?, *b.get(pos + 1)?]));
                let segment = b.get(pos + 2..pos.checked_add(len)?)?;
                if len < 2 {
                    return None;
                }
                match marker {
                    0xC0..=0xC2 => {
                        let n = usize::from(*segment.get(5)?);
                        let (h, w) = (
                            u16::from_be_bytes([segment[1], segment[2]]),
                            u16::from_be_bytes([segment[3], segment[4]]),
                        );
                        if frame || segment[0] != 8 || h == 0 || w == 0 {
                            return None;
                        }
                        if !(1..=4).contains(&n) || segment.len() != 6 + 3 * n {
                            return None;
                        }
                        frame = true;
                    }
                    // Lossless, hierarchical and arithmetic-coded frames: not a preview a
                    // viewer shows, and the main data of some raw formats.
                    0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => return None,
                    0xDA => {
                        if !frame {
                            return None;
                        }
                        scan = true;
                    }
                    _ => {}
                }
                pos += len;
                if marker == 0xDA {
                    // Entropy-coded data runs to the next marker that is not a stuffed zero
                    // or a restart.
                    loop {
                        pos += b.get(pos..)?.iter().position(|c| *c == 0xFF)?;
                        match *b.get(pos + 1)? {
                            0x00 | 0xD0..=0xD7 => pos += 2,
                            0xFF => pos += 1,
                            _ => break,
                        }
                    }
                }
            }
        }
    }
}

/// `n` bytes at `at`: the bytes read charged to `budget` first, and the buffer's memory
/// charged before it is made. The memory stays charged; the caller frees `n` when it lets
/// the bytes go. None, with nothing left charged, when they could not all be read.
fn get(
    src: &mut dyn Bytes,
    budget: &mut Budget,
    at: u64,
    n: usize,
) -> Result<Option<Vec<u8>>, Limit> {
    budget.read(n as u64)?;
    let mut buf = budget.buffer(n)?;
    if src.fill(at, &mut buf) {
        Ok(Some(buf))
    } else {
        budget.free(n as u64);
        Ok(None)
    }
}

/// The most bytes `small` reads.
const HEADER: usize = 64;

/// A header of at most `HEADER` bytes at `at`, charged as `get` is and let go of by the
/// budget as it is handed back: its size is fixed in the code, and a search holds a few.
fn small(
    src: &mut dyn Bytes,
    budget: &mut Budget,
    at: u64,
    n: usize,
) -> Result<Option<Vec<u8>>, Limit> {
    debug_assert!(n <= HEADER);
    let read = get(src, budget, at, n.min(HEADER))?;
    if read.is_some() {
        budget.free(n.min(HEADER) as u64);
    }
    Ok(read)
}

/// The possible previews a search found, held within its budget.
struct Candidates(Vec<(u64, u64, Source)>);

impl Candidates {
    fn push(&mut self, budget: &mut Budget, found: (u64, u64, Source)) -> Result<(), Limit> {
        budget.hold(CANDIDATE)?;
        self.0.push(found);
        Ok(())
    }
}

/// Every whole preview in the picture, largest first, each read and checked, within
/// `budget` (made from `LIMITS`). When the search reaches a limit of its budget it still
/// checks what it found before then; `budget.said()` names the limit.
pub fn find(src: &mut dyn Bytes, budget: &mut Budget) -> Vec<Preview> {
    let mut candidates = Candidates(Vec::new());
    let searched: Result<(), Limit> = (|| {
        let first = 16.min(src.len() as usize);
        let Some(head) = small(src, budget, 0, first)? else {
            return Ok(());
        };
        if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
            jpeg_candidates(src, budget, &mut candidates)
        } else if head.starts_with(b"FUJIFILMCCD-RAW") {
            raf_candidates(src, budget, &mut candidates)
        } else if head.len() >= 8 && &head[4..8] == b"ftyp" {
            bmff_candidates(src, budget, &mut candidates)
        } else if tiff_order(&head).is_some() {
            Tiff::new(0).collect(src, budget, Source::RawIfd, &mut candidates)
        } else {
            Ok(())
        }
    })();
    debug_assert!(searched.is_ok() || budget.hit().is_some());
    let mut seen = HashSet::new();
    let mut found: Vec<Preview> = Vec::new();
    for (at, len, source) in candidates.0 {
        if !(4..=PREVIEW_MAX).contains(&len) || !seen.insert(at) {
            continue;
        }
        let Ok(read) = get(src, budget, at, len as usize) else {
            break;
        };
        let Some(bytes) = read else {
            continue;
        };
        let whole = jpeg_len(&bytes);
        budget.free(len);
        drop(bytes);
        if let Some(n) = whole {
            found.push(Preview {
                at,
                len: n as u64,
                source,
            });
        }
    }
    found.sort_by_key(|p| std::cmp::Reverse(p.len));
    found
}

/// The largest whole preview and its bytes, within `budget` (made from `LIMITS`). The
/// largest one was read whole when it was checked, so its second read is not charged as
/// read; its memory is charged before it is made and freed as it is handed back.
pub fn best(src: &mut dyn Bytes, budget: &mut Budget) -> Option<(Preview, Vec<u8>)> {
    let preview = *find(src, budget).first()?;
    let mut bytes = budget.buffer(preview.len as usize).ok()?;
    let read = src.fill(preview.at, &mut bytes);
    budget.free(preview.len);
    read.then_some((preview, bytes))
}

/// The header segments of a JPEG up to its first scan: EXIF and Multi-Picture blocks.
fn jpeg_candidates(
    src: &mut dyn Bytes,
    budget: &mut Budget,
    out: &mut Candidates,
) -> Result<(), Limit> {
    let mut pos = 2u64;
    loop {
        budget.item()?;
        let Some(head) = small(src, budget, pos, 4)? else {
            return Ok(());
        };
        if head[0] != 0xFF {
            return Ok(());
        }
        if head[1] == 0xFF {
            pos += 1;
            continue;
        }
        let marker = head[1];
        if matches!(marker, 0xD9 | 0xDA) || (0xD0..=0xD8).contains(&marker) {
            return Ok(());
        }
        let len = u64::from(u16::from_be_bytes([head[2], head[3]]));
        if len < 2 {
            return Ok(());
        }
        let data = pos + 4;
        let body = len - 2;
        match marker {
            0xE1 if body > 14
                && small(src, budget, data, 6)?.as_deref() == Some(&b"Exif\0\0"[..]) =>
            {
                let mut walk = Tiff::new(data + 6);
                walk.limit = Some(data + body);
                walk.collect(src, budget, Source::ExifThumbnail, out)?;
            }
            0xE2 if body > 12 && small(src, budget, data, 4)?.as_deref() == Some(&b"MPF\0"[..]) => {
                mpf_candidates(src, budget, data + 4, out)?;
            }
            _ => {}
        }
        pos = data + body;
    }
}

/// The Multi-Picture index at `base` (its TIFF header): each image after the first, at an
/// offset from `base`.
fn mpf_candidates(
    src: &mut dyn Bytes,
    budget: &mut Budget,
    base: u64,
    out: &mut Candidates,
) -> Result<(), Limit> {
    let Some(head) = small(src, budget, base, 8)? else {
        return Ok(());
    };
    let Some(le) = tiff_order(&head) else {
        return Ok(());
    };
    let first = u64::from(u32_at(&head, 4, le));
    let Some(count) = small(src, budget, base + first, 2)?.map(|b| u64::from(u16_at(&b, 0, le)))
    else {
        return Ok(());
    };
    for i in 0..count {
        budget.item()?;
        let Some(entry) = small(src, budget, base + first + 2 + i * 12, 12)? else {
            return Ok(());
        };
        if u16_at(&entry, 0, le) != 0xB002 {
            continue;
        }
        let n = u64::from(u32_at(&entry, 4, le)) / 16;
        let at = base + u64::from(u32_at(&entry, 8, le));
        for k in 0..n {
            budget.item()?;
            let Some(e) = small(src, budget, at + k * 16, 16)? else {
                return Ok(());
            };
            let (size, offset) = (u32_at(&e, 4, le), u32_at(&e, 8, le));
            if offset != 0 {
                out.push(
                    budget,
                    (
                        base + u64::from(offset),
                        u64::from(size),
                        Source::MultiPicture,
                    ),
                )?;
            }
        }
    }
    Ok(())
}

/// A Fujifilm RAF: the preview JPEG's offset and length at bytes 84 and 88, big-endian.
fn raf_candidates(
    src: &mut dyn Bytes,
    budget: &mut Budget,
    out: &mut Candidates,
) -> Result<(), Limit> {
    if let Some(b) = small(src, budget, 84, 8)? {
        let at = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        let len = u64::from(u32::from_be_bytes([b[4], b[5], b[6], b[7]]));
        out.push(budget, (at, len, Source::Raf))?;
    }
    Ok(())
}

/// An ISO base media file (CR3): the boxes, into `moov` and `uuid` boxes, and in each `PRVW`
/// or `THMB` box the JPEG that follows its small header.
fn bmff_candidates(
    src: &mut dyn Bytes,
    budget: &mut Budget,
    out: &mut Candidates,
) -> Result<(), Limit> {
    budget.hold(QUEUED)?;
    let mut stack: Vec<(u64, u64, usize)> = vec![(0, src.len(), 0)];
    while let Some((mut pos, end, depth)) = stack.pop() {
        budget.free(QUEUED);
        while pos + 8 <= end {
            budget.item()?;
            let Some(head) = small(src, budget, pos, 8)? else {
                break;
            };
            let mut size = u64::from(u32::from_be_bytes([head[0], head[1], head[2], head[3]]));
            let kind = [head[4], head[5], head[6], head[7]];
            let mut header = 8;
            if size == 1 {
                let Some(large) = small(src, budget, pos + 8, 8)? else {
                    break;
                };
                size = u64::from_be_bytes(large.try_into().expect("eight bytes"));
                header = 16;
            } else if size == 0 {
                size = end - pos;
            }
            let Some(box_end) = pos
                .checked_add(size)
                .filter(|e| *e <= end && size >= header)
            else {
                break;
            };
            let opens =
                matches!(&kind, b"moov" | b"trak") || (&kind == b"uuid" && size >= header + 16);
            match &kind {
                _ if opens && !budget.within_depth(depth + 1) => {}
                b"moov" | b"trak" => {
                    budget.hold(QUEUED)?;
                    stack.push((pos + header, box_end, depth + 1));
                }
                b"uuid" if opens => {
                    // Canon's boxes hold their children after the UUID; the preview box's
                    // parent holds eight more bytes first.
                    budget.hold(2 * QUEUED)?;
                    stack.push((pos + header + 16, box_end, depth + 1));
                    stack.push((pos + header + 24, box_end, depth + 1));
                }
                b"PRVW" | b"THMB" => {
                    let look = (box_end - pos).min(64) as usize;
                    if let Some(b) = small(src, budget, pos, look)? {
                        if let Some(i) = b.windows(3).position(|w| w == [0xFF, 0xD8, 0xFF]) {
                            let at = pos + i as u64;
                            out.push(budget, (at, box_end - at, Source::Cr3))?;
                        }
                    }
                }
                _ => {}
            }
            pos = box_end;
        }
    }
    Ok(())
}

/// The byte order a TIFF header names, little-endian as true: "II" or "MM" and a magic of 42,
/// or Olympus's and Panasonic's own.
pub(super) fn tiff_order(head: &[u8]) -> Option<bool> {
    if head.len() < 8 {
        return None;
    }
    let le = match &head[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    matches!(u16_at(head, 2, le), 42 | 0x4F52 | 0x5352 | 0x55).then_some(le)
}

fn u16_at(b: &[u8], at: usize, le: bool) -> u16 {
    let v = [b[at], b[at + 1]];
    if le {
        u16::from_le_bytes(v)
    } else {
        u16::from_be_bytes(v)
    }
}

fn u32_at(b: &[u8], at: usize, le: bool) -> u32 {
    let v = [b[at], b[at + 1], b[at + 2], b[at + 3]];
    if le {
        u32::from_le_bytes(v)
    } else {
        u32::from_be_bytes(v)
    }
}

/// A walk of a TIFF structure's IFDs from the header at `base`, offsets taken from `base`.
struct Tiff {
    base: u64,
    /// Offsets must stay below this (the EXIF block's end), when set.
    limit: Option<u64>,
    seen: HashSet<u64>,
}

impl Tiff {
    fn new(base: u64) -> Self {
        Self {
            base,
            limit: None,
            seen: HashSet::new(),
        }
    }

    /// Collects every JPEG the IFDs name, following the IFD chain, SubIFDs and the EXIF IFD.
    /// Each IFD visited and each of its entries is a part; each offset queued and each IFD
    /// seen is held.
    fn collect(
        &mut self,
        src: &mut dyn Bytes,
        budget: &mut Budget,
        source: Source,
        out: &mut Candidates,
    ) -> Result<(), Limit> {
        let Some(head) = small(src, budget, self.base, 8)? else {
            return Ok(());
        };
        let Some(le) = tiff_order(&head) else {
            return Ok(());
        };
        budget.hold(QUEUED)?;
        let mut queue = vec![u64::from(u32_at(&head, 4, le))];
        while let Some(offset) = queue.pop() {
            budget.free(QUEUED);
            if offset < 8 || self.seen.contains(&offset) {
                continue;
            }
            budget.item()?;
            budget.hold(2 * QUEUED)?;
            self.seen.insert(offset);
            let at = self.base + offset;
            if self.limit.is_some_and(|l| at >= l) {
                continue;
            }
            let Some(count) = small(src, budget, at, 2)?.map(|b| u64::from(u16_at(&b, 0, le)))
            else {
                continue;
            };
            budget.count(count)?;
            // The entries are charged as they are read, before they are made.
            let held = count * 12 + 4;
            let Some(entries) = get(src, budget, at + 2, held as usize)? else {
                continue;
            };
            let mut tags: Vec<(u16, u16, u32, u32)> = Vec::new();
            for i in 0..count as usize {
                let e = &entries[i * 12..i * 12 + 12];
                tags.push((
                    u16_at(e, 0, le),
                    u16_at(e, 2, le),
                    u32_at(e, 4, le),
                    u32_at(e, 8, le),
                ));
            }
            let value = |tag: u16| {
                tags.iter().find(|t| t.0 == tag).map(|&(_, kind, _, raw)| {
                    // A count-one SHORT sits in the field's first two bytes.
                    if kind == 3 {
                        if le {
                            raw & 0xFFFF
                        } else {
                            raw >> 16
                        }
                    } else {
                        raw
                    }
                })
            };
            if let (Some(o), Some(n)) = (value(0x0201), value(0x0202)) {
                out.push(budget, (self.base + u64::from(o), u64::from(n), source))?;
            }
            if matches!(value(0x0103), Some(6 | 7)) {
                let strip = |tag| tags.iter().find(|t| t.0 == tag && t.2 == 1).copied();
                if let (Some(_), Some(_)) = (strip(0x0111), strip(0x0117)) {
                    if let (Some(o), Some(n)) = (value(0x0111), value(0x0117)) {
                        out.push(budget, (self.base + u64::from(o), u64::from(n), source))?;
                    }
                }
            }
            // Panasonic's JpgFromRaw: the JPEG's bytes are the tag's value.
            if let Some(&(_, 7, n, o)) = tags.iter().find(|t| t.0 == 0x002E) {
                out.push(budget, (self.base + u64::from(o), u64::from(n), source))?;
            }
            let queued = |queue: &mut Vec<u64>, offset: u64, budget: &mut Budget| {
                budget.hold(QUEUED)?;
                queue.push(offset);
                Ok::<(), Limit>(())
            };
            for &(tag, kind, n, raw) in &tags {
                match tag {
                    0x8769 => queued(&mut queue, u64::from(raw), budget)?,
                    0x014A if n == 1 => queued(&mut queue, u64::from(raw), budget)?,
                    0x014A if matches!(kind, 4 | 13) => {
                        // Each SubIFD listed is a part; a list longer than the budget
                        // allows stops the search with its limit named.
                        let n = u64::from(n);
                        budget.count(n)?;
                        let list = get(src, budget, self.base + u64::from(raw), (n * 4) as usize)?;
                        if let Some(list) = list {
                            for k in 0..n as usize {
                                queued(&mut queue, u64::from(u32_at(&list, k * 4, le)), budget)?;
                            }
                            budget.free(n * 4);
                        }
                    }
                    _ => {}
                }
            }
            let next = u32_at(&entries, count as usize * 12, le);
            budget.free(held);
            if next != 0 {
                queued(&mut queue, u64::from(next), budget)?;
            }
        }
        Ok(())
    }
}

// ---- the engine ------------------------------------------------------------------------

/// A picture to take a preview from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Picture {
    /// The picture file, recovered earlier; its folder takes the preview.
    pub path: PathBuf,
    /// Byte ranges of it that were never read (zeros), from the recovery report; no preview
    /// is taken over them. Empty when every byte was read.
    pub unreadable: Vec<Range<u64>>,
}

/// What `run` does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    /// The pictures, in order. Any number; each is read up to `PREVIEW_MAX` per preview.
    pub pictures: Vec<Picture>,
    /// The disk being recovered, when there is one: no preview is written on it.
    pub source_disk: crate::recovery::dest::Protected,
}

/// What `run` reports as it goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// Picture `index` (from 0) of `of` is being read.
    Picture {
        index: usize,
        of: usize,
        path: PathBuf,
    },
    /// A preview was written.
    Written { path: PathBuf, bytes: u64 },
    /// Something a person should know, such as a picture that could not be opened.
    Warning(String),
}

/// One preview written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Written {
    pub picture: PathBuf,
    pub path: PathBuf,
    pub bytes: u64,
    pub source: Source,
}

/// What `run` did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub written: Vec<Written>,
    /// Pictures with no whole preview in the parts that were read.
    pub none: Vec<PathBuf>,
    /// Pictures that could not be read, or whose preview could not be written, and why.
    pub failed: Vec<(PathBuf, String)>,
    /// Stopped before every picture was read.
    pub stopped: bool,
    /// Pictures whose search reached a limit of its budget, and the limit in words: the
    /// previews found before then were still checked.
    #[serde(default)]
    pub limited: Vec<(PathBuf, String)>,
}

/// "IMG_0001 (preview).jpg" for "IMG_0001.CR2" or "IMG_0001 (partial).jpg".
pub fn preview_name(picture: &str) -> String {
    let stem = picture
        .rsplit_once('.')
        .map_or(picture, |(s, _)| if s.is_empty() { picture } else { s });
    let stem = stem.strip_suffix(" (partial)").unwrap_or(stem);
    format!("{stem} (preview).jpg")
}

/// Writes `bytes` as a new file named for `picture`'s preview in `folder`, never over
/// anything, entered in `ledger` as it is made; the path it was given. A write that fails
/// removes the file again, and its entry says so.
pub fn write_preview(
    guard: &Guard,
    folder: &Folder,
    picture: &str,
    bytes: &[u8],
    ledger: &mut super::ledger::Ledger,
) -> std::io::Result<PathBuf> {
    let entry = super::writer::Entry {
        tag: 0,
        source: PathBuf::from(picture),
        note: "built-in preview".into(),
        size: bytes.len() as u64,
    };
    let mut made = super::writer::create(guard, folder, &preview_name(picture), ledger, entry)?;
    match super::writer::write_whole(&mut made, bytes, ledger) {
        Ok(()) => Ok(made.path),
        Err(why) => {
            super::writer::discard(made, ledger, &why);
            Err(std::io::Error::other(why))
        }
    }
}

/// Takes the largest whole preview of each picture and writes it beside the picture as
/// "name (preview).jpg". Reads only the pictures; writes only new files.
pub fn run(options: &Options, events: &mut dyn FnMut(Event), cancel: &AtomicBool) -> Outcome {
    let guard = Guard::of(&options.source_disk);
    let mut outcome = Outcome::default();
    // Every preview made, entered as it is made; the outcome lists them from it.
    let mut ledger = super::ledger::Ledger::default();
    let of = options.pictures.len();
    for (index, picture) in options.pictures.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            outcome.stopped = true;
            break;
        }
        events(Event::Picture {
            index,
            of,
            path: picture.path.clone(),
        });
        let failed = |why: String, outcome: &mut Outcome, events: &mut dyn FnMut(Event)| {
            events(Event::Warning(format!("{}: {why}", picture.path.display())));
            outcome.failed.push((picture.path.clone(), why));
        };
        let (Some(folder), Some(name)) = (
            picture.path.parent(),
            picture.path.file_name().and_then(OsStr::to_str),
        ) else {
            failed("it is not a file path".into(), &mut outcome, events);
            continue;
        };
        let file = match File::open(&picture.path) {
            Ok(file) => file,
            Err(e) => {
                failed(format!("it could not be opened: {e}"), &mut outcome, events);
                continue;
            }
        };
        // A length that cannot be read is said, not taken for an empty picture.
        let len = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                failed(
                    format!("its length could not be read: {e}"),
                    &mut outcome,
                    events,
                );
                continue;
            }
        };
        let mut src = FileBytes {
            file: &file,
            len,
            unreadable: &picture.unreadable,
        };
        let mut budget = Budget::new(LIMITS, Some(cancel));
        let found = best(&mut src, &mut budget);
        if budget.hit() == Some(Limit::Stopped) {
            outcome.stopped = true;
            break;
        }
        if let Some(said) = budget.said() {
            events(Event::Warning(format!(
                "{}: {said}",
                picture.path.display()
            )));
            outcome.limited.push((picture.path.clone(), said));
        }
        let Some((preview, bytes)) = found else {
            outcome.none.push(picture.path.clone());
            continue;
        };
        let written = guard
            .check_folder(folder)
            .map_err(std::io::Error::other)
            .and_then(|()| guard.base(folder))
            .and_then(|base| write_preview(&guard, &base, name, &bytes, &mut ledger));
        match written {
            Ok(path) => {
                events(Event::Written {
                    path: path.clone(),
                    bytes: bytes.len() as u64,
                });
                outcome.written.push(Written {
                    picture: picture.path.clone(),
                    path,
                    bytes: bytes.len() as u64,
                    source: preview.source,
                });
            }
            Err(e) => failed(
                format!("its preview could not be written: {e}"),
                &mut outcome,
                events,
            ),
        }
    }
    outcome
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const PHOTO: &[u8] = include_bytes!("../../tests/fixtures/recovery/samples/photo.jpg");
    pub const HOLIDAY: &[u8] = include_bytes!("../../tests/fixtures/recovery/samples/holiday.jpg");

    /// A little-endian TIFF block whose IFD0 has `ifd0` entries and whose IFD1 names a
    /// JPEG thumbnail, the thumbnail following the IFDs.
    pub fn exif_tiff(thumbnail: &[u8]) -> Vec<u8> {
        let mut t = b"II*\0\x08\0\0\0".to_vec();
        // IFD0: one entry (Orientation), then the offset of IFD1.
        t.extend(1u16.to_le_bytes());
        t.extend(entry(0x0112, 3, 1, 1));
        let ifd1 = 8 + 2 + 12 + 4;
        t.extend((ifd1 as u32).to_le_bytes());
        // IFD1: Compression (6, JPEG), JPEGInterchangeFormat and its length.
        let data = ifd1 + 2 + 3 * 12 + 4;
        t.extend(3u16.to_le_bytes());
        t.extend(entry(0x0103, 3, 1, 6));
        t.extend(entry(0x0201, 4, 1, data as u32));
        t.extend(entry(0x0202, 4, 1, thumbnail.len() as u32));
        t.extend(0u32.to_le_bytes());
        t.extend(thumbnail);
        t
    }

    pub fn entry(tag: u16, kind: u16, count: u32, value: u32) -> Vec<u8> {
        let mut e = tag.to_le_bytes().to_vec();
        e.extend(kind.to_le_bytes());
        e.extend(count.to_le_bytes());
        e.extend(value.to_le_bytes());
        e
    }

    /// A camera-style JPEG: `main` with an EXIF block holding `thumbnail` after its start
    /// marker, and when `large` is given a Multi-Picture block naming it as a second image
    /// after the main one, as cameras store their large preview.
    pub fn camera_jpeg(main: &[u8], thumbnail: &[u8], large: Option<&[u8]>) -> Vec<u8> {
        let tiff = exif_tiff(thumbnail);
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend(&tiff);
        let mut out = vec![0xFF, 0xD8];
        out.extend([0xFF, 0xE1]);
        out.extend(((app1.len() + 2) as u16).to_be_bytes());
        out.extend(&app1);
        let mpf_at = out.len() + 4 + 4;
        let mut mpf_len = 0;
        if large.is_some() {
            // The index: one entry, MPEntry, two images; the offsets are fixed below.
            mpf_len = 8 + 2 + 12 + 4 + 32;
            out.extend([0xFF, 0xE2]);
            out.extend(((mpf_len + 4 + 2) as u16).to_be_bytes());
            out.extend(b"MPF\0");
            out.extend(vec![0u8; mpf_len]);
        }
        out.extend(&main[2..]);
        if let Some(large) = large {
            let offset = (out.len() - mpf_at) as u32;
            out.extend(large);
            let mut index = b"II*\0\x08\0\0\0".to_vec();
            index.extend(1u16.to_le_bytes());
            index.extend(entry(0xB002, 7, 32, 8 + 2 + 12 + 4));
            index.extend(0u32.to_le_bytes());
            index.extend([0u8; 4]);
            index.extend((main.len() as u32).to_le_bytes());
            index.extend(0u32.to_le_bytes());
            index.extend([0u8; 4]);
            index.extend([0u8; 4]);
            index.extend((large.len() as u32).to_le_bytes());
            index.extend(offset.to_le_bytes());
            index.extend([0u8; 4]);
            assert_eq!(index.len(), mpf_len);
            out[mpf_at..mpf_at + mpf_len].copy_from_slice(&index);
        }
        out
    }

    fn slice(bytes: &[u8]) -> Slice<'_> {
        Slice {
            bytes,
            unreadable: &[],
        }
    }

    #[test]
    fn real_jpegs_are_whole_and_cut_or_altered_ones_are_not() {
        assert_eq!(jpeg_len(PHOTO), Some(PHOTO.len()));
        assert_eq!(jpeg_len(HOLIDAY), Some(HOLIDAY.len()));
        let mut padded = PHOTO.to_vec();
        padded.extend([0u8; 100]);
        assert_eq!(jpeg_len(&padded), Some(PHOTO.len()));
        for cut in [3, 20, 200, PHOTO.len() / 2, PHOTO.len() - 1] {
            assert_eq!(jpeg_len(&PHOTO[..cut]), None, "cut at {cut}");
        }
        // A lossless frame (the main data of a CR2 or DNG) is not taken as a preview.
        let sof = PHOTO.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
        let mut lossless = PHOTO.to_vec();
        lossless[sof + 1] = 0xC3;
        assert_eq!(jpeg_len(&lossless), None);
        assert_eq!(jpeg_len(&[0xFF, 0xD8, 0xFF, 0xD9]), None);
    }

    #[test]
    fn a_camera_jpeg_gives_its_exif_thumbnail_and_its_large_preview() {
        let picture = camera_jpeg(HOLIDAY, PHOTO, None);
        assert_eq!(jpeg_len(&picture), Some(picture.len()));
        let found = find(&mut slice(&picture), &mut Budget::new(LIMITS, None));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source, Source::ExifThumbnail);
        let (_, bytes) = best(&mut slice(&picture), &mut Budget::new(LIMITS, None)).unwrap();
        assert_eq!(bytes, PHOTO);

        let picture = camera_jpeg(PHOTO, PHOTO, Some(HOLIDAY));
        let found = find(&mut slice(&picture), &mut Budget::new(LIMITS, None));
        let sources: Vec<Source> = found.iter().map(|p| p.source).collect();
        assert_eq!(sources, vec![Source::MultiPicture, Source::ExifThumbnail]);
        assert_eq!(
            best(&mut slice(&picture), &mut Budget::new(LIMITS, None))
                .unwrap()
                .1,
            HOLIDAY
        );
    }

    #[test]
    fn a_preview_over_an_unread_range_is_not_taken() {
        let picture = camera_jpeg(PHOTO, PHOTO, Some(HOLIDAY));
        let large = find(&mut slice(&picture), &mut Budget::new(LIMITS, None))[0];
        let gap = [Range {
            start: large.at + 1000,
            end: large.at + 1512,
        }];
        let mut src = Slice {
            bytes: &picture,
            unreadable: &gap,
        };
        let found = find(&mut src, &mut Budget::new(LIMITS, None));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source, Source::ExifThumbnail);
        // An unread start leaves nothing.
        let mut src = Slice {
            bytes: &picture,
            unreadable: &[Range { start: 0, end: 512 }],
        };
        assert!(find(&mut src, &mut Budget::new(LIMITS, None)).is_empty());
    }

    /// A TIFF raw file in the style of a CR2 or ARW: IFD0 names a large preview by its
    /// strip with JPEG compression, IFD1 a thumbnail, and a SubIFD a lossless raw frame.
    fn raw_tiff(big_endian: bool) -> Vec<u8> {
        let mut lossless = PHOTO.to_vec();
        let sof = lossless.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
        lossless[sof + 1] = 0xC3;
        let ifd0 = 8u32;
        let ifd1 = ifd0 + 2 + 5 * 12 + 4;
        let sub = ifd1 + 2 + 2 * 12 + 4;
        let data = sub + 2 + 3 * 12 + 4;
        let (big, thumb, raw) = (
            data,
            data + HOLIDAY.len() as u32,
            data + (HOLIDAY.len() + PHOTO.len()) as u32,
        );
        let ifds: Vec<Vec<(u16, u16, u32, u32)>> = vec![
            vec![
                (0x0103, 3, 1, 6),
                (0x0111, 4, 1, big),
                (0x0117, 4, 1, HOLIDAY.len() as u32),
                (0x014A, 4, 1, sub),
                (0x0112, 3, 1, 1),
            ],
            vec![(0x0201, 4, 1, thumb), (0x0202, 4, 1, PHOTO.len() as u32)],
            vec![
                (0x0103, 3, 1, 7),
                (0x0111, 4, 1, raw),
                (0x0117, 4, 1, lossless.len() as u32),
            ],
        ];
        let w16 = |v: u16| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let w32 = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut t = if big_endian {
            b"MM\0*".to_vec()
        } else {
            b"II*\0".to_vec()
        };
        t.extend(w32(ifd0));
        let nexts = [ifd1, 0, 0];
        for (ifd, next) in ifds.iter().zip(nexts) {
            t.extend(w16(ifd.len() as u16));
            for &(tag, kind, count, value) in ifd {
                t.extend(w16(tag));
                t.extend(w16(kind));
                t.extend(w32(count));
                if kind == 3 {
                    t.extend(w16(value as u16));
                    t.extend([0, 0]);
                } else {
                    t.extend(w32(value));
                }
            }
            t.extend(w32(next));
        }
        assert_eq!(t.len() as u32, data);
        t.extend(HOLIDAY);
        t.extend(PHOTO);
        t.extend(&lossless);
        t
    }

    #[test]
    fn raw_files_give_their_previews_and_never_their_raw_data() {
        for big_endian in [false, true] {
            let raw = raw_tiff(big_endian);
            let found = find(&mut slice(&raw), &mut Budget::new(LIMITS, None));
            assert_eq!(found.len(), 2, "{found:?}");
            assert!(found.iter().all(|p| p.source == Source::RawIfd));
            assert_eq!(found[0].len, HOLIDAY.len() as u64);
            assert_eq!(found[1].len, PHOTO.len() as u64);
        }
        // Fujifilm: the header names the preview.
        let mut raf = b"FUJIFILMCCD-RAW 0201FF383501".to_vec();
        raf.resize(100, 0);
        raf[84..88].copy_from_slice(&100u32.to_be_bytes());
        raf[88..92].copy_from_slice(&(HOLIDAY.len() as u32).to_be_bytes());
        raf.extend(HOLIDAY);
        assert_eq!(
            best(&mut slice(&raf), &mut Budget::new(LIMITS, None))
                .unwrap()
                .1,
            HOLIDAY
        );
        // Canon CR3: a PRVW box inside the preview UUID box.
        let mut prvw = (8 + 16 + HOLIDAY.len() as u32).to_be_bytes().to_vec();
        prvw.extend(b"PRVW");
        prvw.extend([0, 0, 0, 0, 0, 1, 6, 0x54, 4, 0x38, 0, 1]);
        prvw.extend((HOLIDAY.len() as u32).to_be_bytes());
        prvw.extend(HOLIDAY);
        let mut uuid = ((8 + 16 + 8 + prvw.len()) as u32).to_be_bytes().to_vec();
        uuid.extend(b"uuid");
        uuid.extend([0xEA; 16]);
        uuid.extend([0, 0, 0, 0, 0, 0, 0, 1]);
        uuid.extend(&prvw);
        let mut cr3 = 24u32.to_be_bytes().to_vec();
        cr3.extend(b"ftypcrx \0\0\0\x01crx isom");
        cr3.extend(&uuid);
        let found = find(&mut slice(&cr3), &mut Budget::new(LIMITS, None));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source, Source::Cr3);
        assert_eq!(
            best(&mut slice(&cr3), &mut Budget::new(LIMITS, None))
                .unwrap()
                .1,
            HOLIDAY
        );
    }

    /// Pseudo-random numbers for the fuzz-style tests.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    /// Mutated and cut pictures never panic, and every preview taken from one is whole.
    #[test]
    fn hostile_bytes_never_panic_and_give_only_whole_previews() {
        let seeds: Vec<Vec<u8>> = vec![
            camera_jpeg(HOLIDAY, PHOTO, Some(PHOTO)),
            raw_tiff(false),
            raw_tiff(true),
            {
                let mut raf = b"FUJIFILMCCD-RAW 0201".to_vec();
                raf.resize(100, 0);
                raf[84..88].copy_from_slice(&100u32.to_be_bytes());
                raf[88..92].copy_from_slice(&(PHOTO.len() as u32).to_be_bytes());
                raf.extend(PHOTO);
                raf
            },
        ];
        let mut rng = Lcg(7);
        for round in 0..3000 {
            let mut bytes = seeds[round % seeds.len()].clone();
            let edits = 1 + rng.next() % 8;
            for _ in 0..edits {
                let at = (rng.next() as usize) % bytes.len();
                match rng.next() % 4 {
                    0 => bytes[at] = rng.next() as u8,
                    1 => bytes[at] = 0xFF,
                    2 => {
                        // A field set to a large or pointing value.
                        let v = (rng.next() as u32).to_le_bytes();
                        for (i, b) in v.iter().enumerate() {
                            if at + i < bytes.len() {
                                bytes[at + i] = *b;
                            }
                        }
                    }
                    _ => bytes.truncate(at.max(1)),
                }
            }
            for p in find(&mut slice(&bytes), &mut Budget::new(LIMITS, None)) {
                let whole = &bytes[p.at as usize..(p.at + p.len) as usize];
                assert_eq!(jpeg_len(whole), Some(p.len as usize), "round {round}");
            }
            let _ = jpeg_len(&bytes);
        }
        // Pure noise, too.
        for _ in 0..500 {
            let n = (rng.next() % 4096) as usize;
            let mut bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            if n > 3 {
                bytes[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
            }
            let _ = find(&mut slice(&bytes), &mut Budget::new(LIMITS, None));
        }
    }

    /// A picture of `len` bytes, `head` at its start and zeros after it.
    struct Sparse(Vec<u8>, u64);

    impl Bytes for Sparse {
        fn len(&self) -> u64 {
            self.1
        }
        fn fill(&mut self, at: u64, out: &mut [u8]) -> bool {
            let Some(end) = at.checked_add(out.len() as u64).filter(|e| *e <= self.1) else {
                return false;
            };
            out.fill(0);
            let head = self.0.len() as u64;
            if at < head {
                let stop = head.min(end);
                out[..(stop - at) as usize].copy_from_slice(&self.0[at as usize..stop as usize]);
            }
            true
        }
    }

    /// A TIFF whose IFDs follow one another, each holding `entries(i)`.
    fn ifd_chain(n: usize, entries: impl Fn(usize) -> Vec<Vec<u8>>) -> Vec<u8> {
        let mut t = b"II*\0\x08\0\0\0".to_vec();
        for i in 0..n {
            let e = entries(i);
            t.extend((e.len() as u16).to_le_bytes());
            let next = t.len() + e.len() * 12 + 4;
            e.iter().for_each(|e| t.extend(e));
            let next = if i + 1 == n { 0 } else { next as u32 };
            t.extend(next.to_le_bytes());
        }
        t
    }

    #[test]
    fn a_hostile_picture_stops_within_its_budget() {
        let started = std::time::Instant::now();
        // More IFDs than the budget takes: the count stops it and is said.
        let t = ifd_chain(20_000, |_| vec![entry(0x0100, 3, 1, 1)]);
        let mut budget = Budget::new(LIMITS, None);
        assert!(find(&mut slice(&t), &mut budget).is_empty());
        assert_eq!(budget.hit(), Some(Limit::Count));
        assert_eq!(budget.spent().count, LIMITS.count);
        assert!(budget.spent().peak <= LIMITS.memory);
        assert_eq!(
            budget.said().unwrap(),
            "The search of the picture for previews stopped at its limit of 16,384 parts of the picture."
        );

        // Possible previews of 60 MB each in a 2 GB picture: four are read whole to be
        // checked, the fifth would pass the bytes it reads.
        let big = 60 << 20;
        let t = ifd_chain(10, |i| {
            vec![
                entry(0x0201, 4, 1, (1 << 20) + i as u32 * big),
                entry(0x0202, 4, 1, big),
            ]
        });
        let mut budget = Budget::new(LIMITS, None);
        assert!(find(&mut Sparse(t, 2 << 30), &mut budget).is_empty());
        assert_eq!(budget.hit(), Some(Limit::Bytes));
        assert!(budget.spent().bytes <= LIMITS.bytes);
        assert!(budget.spent().bytes >= 4 * u64::from(big));
        assert!(budget.said().unwrap().contains("limit of 268.4 MB read"));

        // SubIFD lists that fan out: what is queued is held, and a small memory limit stops
        // it; within the real limits the count bounds the queue first.
        let fan = |_: usize| {
            (0..1000)
                .map(|k| entry(0x014A, 4, 16, 64 + k * 4))
                .collect::<Vec<_>>()
        };
        let t = ifd_chain(1, fan);
        let small = Limits {
            memory: 16 << 10,
            ..LIMITS
        };
        let mut budget = Budget::new(small, None);
        find(&mut slice(&t), &mut budget);
        assert_eq!(budget.hit(), Some(Limit::Memory));
        assert!(budget.spent().peak <= 16 << 10);
        assert!(budget.said().unwrap().contains("memory limit of 16.4 kB"));
        let mut budget = Budget::new(LIMITS, None);
        find(&mut slice(&t), &mut budget);
        assert_eq!(budget.hit(), Some(Limit::Count));
        assert!(budget.spent().peak <= LIMITS.memory);

        // Boxes nested deeper than a CR3's are counted and left out, and the search goes on.
        let mut cr3 = b"\0\0\0\x10ftypcrx \0\0\0\x01".to_vec();
        let depth = 6u32;
        for d in 0..depth {
            cr3.extend((8 * (depth - d)).to_be_bytes());
            cr3.extend(b"moov");
        }
        let mut budget = Budget::new(LIMITS, None);
        assert!(find(&mut slice(&cr3), &mut budget).is_empty());
        assert_eq!(budget.hit(), None);
        assert_eq!(
            budget.said().unwrap(),
            "1 of its boxes lay more than 4 deep and was not followed."
        );

        // Stopped by the person.
        let stop = AtomicBool::new(true);
        let mut budget = Budget::new(LIMITS, Some(&stop));
        let picture = camera_jpeg(PHOTO, HOLIDAY, None);
        assert!(find(&mut slice(&picture), &mut budget).is_empty());
        assert_eq!(budget.hit(), Some(Limit::Stopped));
        assert!(started.elapsed() < LIMITS.time.unwrap());
    }

    #[test]
    fn a_loop_of_ifds_ends() {
        let mut t = b"II*\0\x08\0\0\0".to_vec();
        t.extend(1u16.to_le_bytes());
        t.extend(entry(0x8769, 4, 1, 8));
        t.extend(8u32.to_le_bytes());
        assert!(find(&mut slice(&t), &mut Budget::new(LIMITS, None)).is_empty());
    }

    /// Makes camera-style JPEGs for the live tests: each `salvage_N.jpg` under
    /// D:\\diagtool-qa\\salvage\\photos (made by Windows' own JPEG encoder) with `thumb_N.jpg` as
    /// its EXIF thumbnail and `preview_N.jpg` as its Multi-Picture preview, written to
    /// D:\\diagtool-qa\\salvage\\camera. Needs those files.
    #[test]
    #[ignore]
    fn make_camera_jpegs() {
        let base = std::path::Path::new(r"D:\diagtool-qa\salvage");
        let out = base.join("camera");
        std::fs::create_dir_all(&out).unwrap();
        for n in 1..=6 {
            let read = |name: &str| {
                std::fs::read(base.join("photos").join(format!("{name}_{n}.jpg"))).unwrap()
            };
            let (main, thumb, large) = (read("salvage"), read("thumb"), read("preview"));
            let camera = camera_jpeg(&main, &thumb, Some(&large));
            // The main picture ends at its end marker; the preview follows it, as in a camera's.
            assert_eq!(jpeg_len(&camera), Some(camera.len() - large.len()));
            let found = find(&mut slice(&camera), &mut Budget::new(LIMITS, None));
            assert_eq!(found.len(), 2);
            std::fs::write(out.join(format!("DSC_000{n}.jpg")), &camera).unwrap();
            println!(
                "DSC_000{n}.jpg {} bytes, previews {:?}",
                camera.len(),
                found
            );
        }
    }

    #[test]
    fn preview_names_follow_the_picture() {
        assert_eq!(preview_name("IMG_0001.CR2"), "IMG_0001 (preview).jpg");
        assert_eq!(preview_name("Beach (partial).jpg"), "Beach (preview).jpg");
        assert_eq!(preview_name("noext"), "noext (preview).jpg");
        assert_eq!(preview_name(".jpg"), ".jpg (preview).jpg");
    }

    #[test]
    fn the_engine_writes_each_preview_beside_its_picture() {
        let dir = std::env::temp_dir().join(format!("diagtool-preview-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let camera = camera_jpeg(PHOTO, PHOTO, Some(HOLIDAY));
        std::fs::write(dir.join("DSC_0001 (partial).jpg"), &camera).unwrap();
        std::fs::write(dir.join("plain.jpg"), HOLIDAY).unwrap();
        let options = Options {
            pictures: vec![
                Picture {
                    path: dir.join("DSC_0001 (partial).jpg"),
                    unreadable: vec![Range {
                        start: 600,
                        end: 1100,
                    }],
                },
                Picture {
                    path: dir.join("plain.jpg"),
                    unreadable: Vec::new(),
                },
                Picture {
                    path: dir.join("missing.jpg"),
                    unreadable: Vec::new(),
                },
            ],
            source_disk: crate::recovery::dest::Protected::disk(9999),
        };
        let mut events = Vec::new();
        let outcome = run(&options, &mut |e| events.push(e), &AtomicBool::new(false));
        assert_eq!(outcome.written.len(), 1);
        assert_eq!(outcome.written[0].path, dir.join("DSC_0001 (preview).jpg"));
        assert_eq!(
            std::fs::read(dir.join("DSC_0001 (preview).jpg")).unwrap(),
            HOLIDAY
        );
        assert_eq!(outcome.none, vec![dir.join("plain.jpg")]);
        assert_eq!(outcome.failed.len(), 1);
        assert!(events.iter().any(|e| matches!(e, Event::Written { .. })));
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("MultiPicture"), "{json}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
