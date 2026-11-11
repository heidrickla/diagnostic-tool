//! Good versions of damaged pictures: for each picture in use with bytes the rescue did not
//! read, the other files on the volume that hold it whole (a copy, renamed or not) or as
//! another version taken at the same moment (an edit, a Google Photos copy). A rescue done by hand
//! on one drive found 24 copies and 10 such versions (manual step 34).
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use super::fs::{Data, Found, Listing, Place, Progress, State};
use super::image::{Map, Status};
use super::reader::{merge, Reader, CHUNK};

/// How much of a file's start is read for its format and capture time.
pub const HEAD: u64 = 64 << 10;
/// A near copy differs from the damaged file only this close to a part never read, where a
/// rescue's edges are least sure.
pub const NEAR: u64 = 512;
/// The list written beside the versions, saying where each came from.
pub const LIST_NAME: &str = "Where these came from.txt";

/// A picture's real format, from its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    Jpeg,
    Png,
    Heic,
}

impl Format {
    /// From a file's first bytes: FF D8 FF, 89 'PNG', or an ISO box `ftyp` of a HEIF brand.
    pub fn of_bytes(head: &[u8]) -> Option<Format> {
        if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
            Some(Format::Jpeg)
        } else if head.starts_with(&[0x89, b'P', b'N', b'G']) {
            Some(Format::Png)
        } else if head.len() >= 12 && &head[4..8] == b"ftyp" && HEIF_BRANDS.contains(&&head[8..12])
        {
            Some(Format::Heic)
        } else {
            None
        }
    }

    /// From a file name's ending, for a file whose start was not read.
    pub fn of_name(name: &str) -> Option<Format> {
        match ending(name)?.to_ascii_lowercase().as_str() {
            "jpg" | "jpeg" | "jpe" => Some(Format::Jpeg),
            "png" => Some(Format::Png),
            "heic" | "heif" => Some(Format::Heic),
            _ => None,
        }
    }

    /// The ending a file of this format is named with.
    pub fn ending(self) -> &'static str {
        match self {
            Format::Jpeg => "jpg",
            Format::Png => "png",
            Format::Heic => "heic",
        }
    }
}

const HEIF_BRANDS: &[&[u8]] = &[
    b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"hevm", b"hevs", b"mif1", b"msf1",
];

/// What a good version is to the damaged picture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The same size and the same on every byte the damaged picture has.
    Whole,
    /// The same size and the same except within `NEAR` bytes of a part never read.
    Near,
    /// Another picture taken at the same moment, by its EXIF capture time: an edit, or a copy
    /// made smaller by a photo service.
    Lesser,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Whole => "whole copy",
            Kind::Near => "near copy, differs only next to unreadable parts",
            Kind::Lesser => "other version, same capture time",
        }
    }
}

/// One good version of a damaged picture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// Its index in the listing's files.
    pub file: usize,
    /// "\DCIM\Camera\BQOE9443.JPG", deleted folders marked.
    pub path: String,
    pub size: u64,
    pub deleted: bool,
    pub kind: Kind,
    /// From its first bytes; None when they are none of the formats known here.
    pub format: Option<Format>,
}

/// A picture in use with bytes the rescue did not read, and its good versions: whole copies
/// (a same-named one first), then near copies, then other versions (largest first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Damaged {
    /// Its index in the listing's files.
    pub file: usize,
    pub name: String,
    /// The names of the folders it is in, from the volume's root.
    pub folder: Vec<String>,
    pub path: String,
    pub size: u64,
    /// Bytes of it the rescue did not read.
    pub missing: u64,
    /// From its first bytes, or its name's ending when they were not read.
    pub format: Option<Format>,
    /// Its EXIF capture time, when its readable start holds one.
    pub captured: Option<Capture>,
    pub versions: Vec<Version>,
}

/// What `search` found: every damaged picture, with or without versions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Search {
    pub damaged: Vec<Damaged>,
    /// It was stopped before the end: the versions are those found before then.
    pub stopped: bool,
}

/// A picture's capture time from EXIF: "2023:05:01 14:03:22", and its fraction of a second
/// when the camera wrote one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Capture {
    pub when: String,
    pub subsec: Option<String>,
}

impl Capture {
    /// The same moment: the same second, and the same fraction when both name one, so two
    /// shots of a burst are told apart while an edit that dropped the fraction still matches.
    pub fn same(&self, other: &Capture) -> bool {
        self.when == other.when
            && match (&self.subsec, &other.subsec) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

/// Finds the damaged pictures of `listing` and their good versions, reading through
/// `reader` (the source the listing was read from) only bytes `map` shows rescued. Each
/// whole picture's first `HEAD` bytes are read once, in the order they lie on the source.
pub fn search(
    reader: &mut Reader,
    map: &Map,
    listing: &Listing,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Search {
    let files = &listing.files;
    let mut found = Search::default();
    let mut whole: Vec<usize> = Vec::new();
    let mut gaps: HashMap<usize, Vec<Range<u64>>> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        let unread = unrescued(f, map);
        if unread.is_empty() {
            if usable(f) {
                whole.push(i);
            }
        } else if !f.deleted && is_picture(&f.name) {
            gaps.insert(i, unread);
        }
    }
    let mut damaged: Vec<usize> = gaps.keys().copied().collect();
    damaged.sort_unstable();
    if damaged.is_empty() {
        return found;
    }
    let pictures: Vec<usize> = whole
        .iter()
        .copied()
        .filter(|&i| is_picture(&files[i].name))
        .collect();
    let total = (damaged.len() * 2 + pictures.len()) as u64;
    let mut done = 0u64;
    let stop = |reader: &Reader| cancel.load(Ordering::Relaxed) || reader.gone().is_some();

    // The damaged pictures' own starts first: what they are, and when they were taken.
    for &i in &damaged {
        if stop(reader) {
            found.stopped = true;
            return found;
        }
        let f = &files[i];
        let readable = gaps[&i].first().map_or(f.size, |g| g.start);
        let head = read_range(reader, f, 0..readable.min(HEAD).min(f.size)).unwrap_or_default();
        found.damaged.push(Damaged {
            file: i,
            name: f.name.clone(),
            folder: f.folder.iter().map(|p| p.name.clone()).collect(),
            path: path_text(f),
            size: f.size,
            missing: gaps[&i].iter().map(|g| g.end - g.start).sum(),
            format: Format::of_bytes(&head).or_else(|| Format::of_name(&f.name)),
            captured: capture(&head),
            versions: Vec::new(),
        });
        done += 1;
        progress.set(done, total);
    }

    // One pass over the whole pictures, in source order, for those taken at a wanted moment.
    let wanted: HashSet<&str> = found
        .damaged
        .iter()
        .filter_map(|d| d.captured.as_ref().map(|c| c.when.as_str()))
        .collect();
    let mut taken: HashMap<String, Vec<(usize, Capture, Option<Format>)>> = HashMap::new();
    if !wanted.is_empty() {
        let mut order = pictures.clone();
        order.sort_by_key(|&i| first_byte(&files[i]));
        for i in order {
            if stop(reader) {
                found.stopped = true;
                return found;
            }
            let f = &files[i];
            if let Some(head) = read_range(reader, f, 0..f.size.min(HEAD)) {
                if let Some(c) = capture(&head).filter(|c| wanted.contains(c.when.as_str())) {
                    taken
                        .entry(c.when.clone())
                        .or_default()
                        .push((i, c, Format::of_bytes(&head)));
                }
            }
            done += 1;
            progress.set(done, total);
        }
    } else {
        done += pictures.len() as u64;
    }

    // Each damaged picture against the whole files of its size, then by capture time.
    let mut by_size: HashMap<u64, Vec<usize>> = HashMap::new();
    for &i in &whole {
        by_size.entry(files[i].size).or_default().push(i);
    }
    for d in &mut found.damaged {
        let f = &files[d.file];
        let mut same: Vec<usize> = by_size.get(&f.size).cloned().unwrap_or_default();
        // A same-named copy is checked, and listed, first.
        same.sort_by_key(|&i| {
            (
                !files[i].name.eq_ignore_ascii_case(&f.name),
                files[i].deleted,
            )
        });
        let gaps = &gaps[&d.file];
        for i in same {
            if stop(reader) {
                found.stopped = true;
                return found;
            }
            if let Some(kind) = copy_kind(reader, f, &files[i], gaps) {
                let head = read_range(reader, &files[i], 0..16.min(f.size)).unwrap_or_default();
                d.versions
                    .push(version(&files[i], i, kind, Format::of_bytes(&head)));
            }
        }
        d.versions.sort_by_key(|v| v.kind == Kind::Near);
        if let Some(c) = &d.captured {
            let mut lesser: Vec<Version> = taken
                .get(&c.when)
                .into_iter()
                .flatten()
                .filter(|(i, other, _)| {
                    *i != d.file && c.same(other) && !d.versions.iter().any(|v| v.file == *i)
                })
                .map(|&(i, _, format)| version(&files[i], i, Kind::Lesser, format))
                .collect();
            lesser.sort_by_key(|v| std::cmp::Reverse(v.size));
            d.versions.extend(lesser);
        }
        if !d.versions.is_empty() {
            progress.found.fetch_add(1, Ordering::Relaxed);
        }
        done += 1;
        progress.set(done, total);
    }
    found
}

fn version(f: &Found, file: usize, kind: Kind, format: Option<Format>) -> Version {
    Version {
        file,
        path: path_text(f),
        size: f.size,
        deleted: f.deleted,
        kind,
        format,
    }
}

/// Whether `copy` (wholly rescued, the damaged file's size) holds `damaged`: Whole when they
/// agree on every byte `damaged` has, Near when they differ only within `NEAR` bytes of its
/// unread parts `gaps`, None otherwise or when a byte could not be read to tell.
fn copy_kind(
    reader: &mut Reader,
    damaged: &Found,
    copy: &Found,
    gaps: &[Range<u64>],
) -> Option<Kind> {
    let all = 0..damaged.size;
    let edges = merge(
        gaps.iter()
            .map(|g| g.start.saturating_sub(NEAR)..(g.end + NEAR).min(damaged.size))
            .collect(),
    );
    // The bytes far from any unread part must agree; those near one may differ.
    let far = subtract(std::slice::from_ref(&all), &edges);
    let near = subtract(&edges, gaps);
    if !agree(reader, damaged, copy, &far)? {
        return None;
    }
    Some(if agree(reader, damaged, copy, &near)? {
        Kind::Whole
    } else {
        Kind::Near
    })
}

/// Whether two files agree over `ranges`, read in chunks; None when a chunk cannot be read.
fn agree(reader: &mut Reader, a: &Found, b: &Found, ranges: &[Range<u64>]) -> Option<bool> {
    for r in ranges {
        let mut at = r.start;
        while at < r.end {
            let end = at.saturating_add(CHUNK).min(r.end);
            if read_range(reader, a, at..end)? != read_range(reader, b, at..end)? {
                return Some(false);
            }
            at = end;
        }
    }
    Some(true)
}

/// `from` less `cut`, both sorted and merged.
fn subtract(from: &[Range<u64>], cut: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut out = Vec::new();
    for r in from {
        let mut at = r.start;
        for c in cut.iter().filter(|c| c.start < r.end && r.start < c.end) {
            if c.start > at {
                out.push(at..c.start);
            }
            at = at.max(c.end);
        }
        if at < r.end {
            out.push(at..r.end);
        }
    }
    out
}

/// A whole file that may stand for a damaged one: in use, or deleted with its space its own
/// and its start as its type should be.
fn usable(f: &Found) -> bool {
    !f.damaged && (!f.deleted || (f.state == State::Intact && f.why.is_none()))
}

/// A picture, by its name's ending: the photo endings less video.
fn is_picture(name: &str) -> bool {
    super::photos::is_photo(name)
        && !ending(name)
            .is_some_and(|e| e.eq_ignore_ascii_case("mp4") || e.eq_ignore_ascii_case("mov"))
}

fn ending(name: &str) -> Option<&str> {
    name.rsplit_once('.').map(|(_, e)| e)
}

fn path_text(f: &Found) -> String {
    if f.folder.is_empty() {
        format!("\\{}", f.name)
    } else {
        format!("{}\\{}", f.folder_text(), f.name)
    }
}

/// Where a file's content starts on the source, to read files in the order they lie.
fn first_byte(f: &Found) -> u64 {
    match &f.data {
        Data::Resident(_) => 0,
        Data::Runs(runs) => runs
            .iter()
            .find_map(|r| match r.place {
                Place::At(at) => Some(at),
                _ => None,
            })
            .unwrap_or(0),
    }
}

/// The parts of a file, as offsets in it, that the rescue did not read: on the source in
/// blocks not rescued, or nowhere the volume can place.
pub fn unrescued(f: &Found, map: &Map) -> Vec<Range<u64>> {
    let Data::Runs(runs) = &f.data else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut pos = 0u64;
    for r in runs {
        if pos >= f.size {
            break;
        }
        let len = r.len.min(f.size - pos);
        match r.place {
            Place::Zeros => {}
            Place::Missing => out.push(pos..pos + len),
            // A run that ends past u64::MAX lies on no source: nothing of it was read.
            Place::At(on) => match on.checked_add(len) {
                None => out.push(pos..pos + len),
                Some(end) => {
                    let first = map.blocks.partition_point(|b| b.end() <= on);
                    let mut at = on;
                    for b in map.blocks[first..].iter().take_while(|b| b.pos < end) {
                        if b.status != Status::Rescued {
                            let (s, e) = (b.pos.max(on), b.end().min(end));
                            out.push(pos + (s - on)..pos + (e - on));
                        }
                        at = b.end();
                    }
                    // Past the map's end nothing was read.
                    if at < end {
                        out.push(pos + (at.max(on) - on)..pos + len);
                    }
                }
            },
        }
        pos += len;
    }
    if pos < f.size {
        out.push(pos..f.size);
    }
    merge(out)
}

/// Bytes `range` of a file, through its runs; None when any could not be read or the
/// volume cannot place them.
fn read_range(reader: &mut Reader, f: &Found, range: Range<u64>) -> Option<Vec<u8>> {
    let runs = match &f.data {
        Data::Resident(bytes) => {
            return bytes
                .get(range.start as usize..range.end as usize)
                .map(<[u8]>::to_vec)
        }
        Data::Runs(runs) => runs,
    };
    let mut out = Vec::with_capacity((range.end - range.start) as usize);
    let mut pos = 0u64;
    for r in runs {
        let (from, to) = (
            range.start.max(pos),
            range.end.min(pos.saturating_add(r.len)),
        );
        if from < to {
            match r.place {
                Place::At(on) => {
                    out.extend(reader.read(on.checked_add(from - pos)?, (to - from) as usize)?)
                }
                Place::Zeros => out.resize(out.len() + (to - from) as usize, 0),
                Place::Missing => return None,
            }
        }
        pos = pos.saturating_add(r.len);
        if pos >= range.end {
            break;
        }
    }
    (out.len() as u64 == range.end - range.start).then_some(out)
}

// ---- capture time ----------------------------------------------------------------------

/// The capture time in a picture's first bytes: EXIF DateTimeOriginal (0x9003), or DateTime
/// (0x0132) when there is no original, from a JPEG's APP1, a PNG's eXIf chunk or a HEIF's
/// Exif item. None when the EXIF block lies past `head` or holds no valid time.
pub fn capture(head: &[u8]) -> Option<Capture> {
    let tiff = match Format::of_bytes(head)? {
        Format::Jpeg => jpeg_exif(head)?,
        Format::Png => png_exif(head)?,
        Format::Heic => heif_exif(head)?,
    };
    tiff_capture(tiff)
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A big-endian unsigned number `size` bytes long (0, 4 or 8), as ISO boxes store them.
fn be_n(b: &[u8], at: usize, size: usize) -> Option<u64> {
    let bytes = b.get(at..at + size)?;
    Some(bytes.iter().fold(0u64, |n, &x| n << 8 | u64::from(x)))
}

/// The TIFF block of a JPEG's EXIF segment, from its header segments.
fn jpeg_exif(b: &[u8]) -> Option<&[u8]> {
    let mut pos = 2usize;
    loop {
        if *b.get(pos)? != 0xFF {
            return None;
        }
        let marker = *b.get(pos + 1)?;
        if marker == 0xFF {
            pos += 1;
            continue;
        }
        if matches!(marker, 0xD9 | 0xDA) || (0xD0..=0xD8).contains(&marker) {
            return None;
        }
        let len = usize::from(be16(b, pos + 2)?);
        let body = b.get(pos + 4..(pos + 2 + len).min(b.len()))?;
        if marker == 0xE1 && body.starts_with(b"Exif\0\0") {
            return Some(&body[6..]);
        }
        pos += 2 + len.max(2);
    }
}

/// The TIFF block of a PNG's eXIf chunk, from the chunks before its image data.
fn png_exif(b: &[u8]) -> Option<&[u8]> {
    let mut pos = 8usize;
    loop {
        let len = be32(b, pos)? as usize;
        let kind = b.get(pos + 4..pos + 8)?;
        if kind == b"IDAT" || kind == b"IEND" {
            return None;
        }
        if kind == b"eXIf" {
            return b.get(pos + 8..pos + 8 + len);
        }
        pos = pos.checked_add(12 + len)?;
    }
}

/// The TIFF block of a HEIF's Exif item: its id from `iinf`, its place from `iloc`, both in
/// the top-level `meta` box. The item starts with the offset of the TIFF header after it.
fn heif_exif(b: &[u8]) -> Option<&[u8]> {
    let meta = boxes(b).find(|(kind, _)| kind == b"meta")?.1;
    let children = meta.get(4..)?;
    let iinf = boxes(children).find(|(k, _)| k == b"iinf")?.1;
    let iloc = boxes(children).find(|(k, _)| k == b"iloc")?.1;
    let item = exif_item(iinf)?;
    let (at, len) = item_extent(iloc, item)?;
    let data = b.get(at..at.checked_add(len)?.min(b.len()))?;
    let skip = be32(data, 0)? as usize;
    data.get(4 + skip..)
}

/// The boxes laid one after another in `b`, as (type, body).
fn boxes(b: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let size = be32(b, pos)? as usize;
        let kind: [u8; 4] = b.get(pos + 4..pos + 8)?.try_into().ok()?;
        let (head, size) = match size {
            1 => (16, usize::try_from(be_n(b, pos + 8, 8)?).ok()?),
            0 => (8, b.len() - pos),
            n => (8, n),
        };
        if size < head {
            return None;
        }
        let body = b.get(pos + head..(pos + size).min(b.len()))?;
        pos += size;
        Some((kind, body))
    })
}

/// The id of the item of type "Exif" an `iinf` box's body lists.
fn exif_item(iinf: &[u8]) -> Option<u32> {
    let version = *iinf.first()?;
    let entries = iinf.get(if version == 0 { 6 } else { 8 }..)?;
    boxes(entries).find_map(|(kind, infe)| {
        if &kind != b"infe" {
            return None;
        }
        let (id, at) = match *infe.first()? {
            2 => (u32::from(be16(infe, 4)?), 8),
            3 => (be32(infe, 4)?, 10),
            _ => return None,
        };
        (infe.get(at..at + 4)? == b"Exif").then_some(id)
    })
}

/// Where item `id`'s first extent is in the file, from an `iloc` box's body; only items
/// stored in the file itself (construction method 0).
fn item_extent(iloc: &[u8], id: u32) -> Option<(usize, usize)> {
    let version = *iloc.first()?;
    let sizes = be16(iloc, 4)?;
    let (offset_size, length_size) = (usize::from(sizes >> 12), usize::from(sizes >> 8 & 0xF));
    let base_size = usize::from(sizes >> 4 & 0xF);
    let index_size = if version >= 1 {
        usize::from(sizes & 0xF)
    } else {
        0
    };
    let (count, mut pos) = if version < 2 {
        (u32::from(be16(iloc, 6)?), 8)
    } else {
        (be32(iloc, 6)?, 10)
    };
    for _ in 0..count {
        let item = if version < 2 {
            pos += 2;
            u32::from(be16(iloc, pos - 2)?)
        } else {
            pos += 4;
            be32(iloc, pos - 4)?
        };
        let method = if version >= 1 {
            pos += 2;
            be16(iloc, pos - 2)? & 0xF
        } else {
            0
        };
        pos += 2; // data reference index
        let base = be_n(iloc, pos, base_size)?;
        pos += base_size;
        let extents = be16(iloc, pos)?;
        pos += 2;
        let mut first = None;
        for _ in 0..extents {
            pos += index_size;
            let offset = be_n(iloc, pos, offset_size)?;
            let length = be_n(iloc, pos + offset_size, length_size)?;
            pos += offset_size + length_size;
            first.get_or_insert((offset, length));
        }
        if item == id {
            let (offset, length) = first?;
            return (method == 0)
                .then(|| {
                    Some((
                        usize::try_from(base + offset).ok()?,
                        usize::try_from(length).ok()?,
                    ))
                })
                .flatten();
        }
    }
    None
}

/// The capture time a TIFF block's IFD0 and EXIF IFD hold.
fn tiff_capture(t: &[u8]) -> Option<Capture> {
    let le = super::preview::tiff_order(t)?;
    let ifd0 = ifd(t, le, u32_at(t, 4, le)?)?;
    let exif = find(&ifd0, 0x8769)
        .and_then(|e| ifd(t, le, e.raw))
        .unwrap_or_default();
    let original = find(&exif, 0x9003)
        .and_then(|e| ascii(t, le, e))
        .filter(|s| valid_time(s));
    if let Some(when) = original {
        let subsec = find(&exif, 0x9291).and_then(|e| ascii(t, le, e));
        return Some(Capture { when, subsec });
    }
    let when = find(&ifd0, 0x0132)
        .and_then(|e| ascii(t, le, e))
        .filter(|s| valid_time(s))?;
    let subsec = find(&exif, 0x9290).and_then(|e| ascii(t, le, e));
    Some(Capture { when, subsec })
}

#[derive(Clone, Copy)]
struct Entry {
    tag: u16,
    kind: u16,
    count: u32,
    raw: u32,
    /// Where its value field is in the TIFF block, for values of four bytes or fewer.
    field: usize,
}

fn u16_at(b: &[u8], at: usize, le: bool) -> Option<u16> {
    let v: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(v)
    } else {
        u16::from_be_bytes(v)
    })
}

fn u32_at(b: &[u8], at: usize, le: bool) -> Option<u32> {
    let v: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(v)
    } else {
        u32::from_be_bytes(v)
    })
}

/// The entries of the IFD at `offset`; None when it lies past the block.
fn ifd(t: &[u8], le: bool, offset: u32) -> Option<Vec<Entry>> {
    let at = offset as usize;
    let count = usize::from(u16_at(t, at, le)?);
    (0..count)
        .map(|i| {
            let e = at + 2 + i * 12;
            Some(Entry {
                tag: u16_at(t, e, le)?,
                kind: u16_at(t, e + 2, le)?,
                count: u32_at(t, e + 4, le)?,
                raw: u32_at(t, e + 8, le)?,
                field: e + 8,
            })
        })
        .collect()
}

fn find(entries: &[Entry], tag: u16) -> Option<Entry> {
    entries.iter().find(|e| e.tag == tag).copied()
}

/// An ASCII value, without its ending NULs and spaces.
fn ascii(t: &[u8], le: bool, e: Entry) -> Option<String> {
    if e.kind != 2 {
        return None;
    }
    let n = e.count as usize;
    let at = if n <= 4 {
        e.field
    } else {
        u32_at(t, e.field, le)? as usize
    };
    let bytes = t.get(at..at.checked_add(n)?)?;
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.trim_end_matches(['\0', ' ']);
    (!text.is_empty()).then(|| text.to_string())
}

/// "YYYY:MM:DD HH:MM:SS", not the blank "0000:00:00 00:00:00" some cameras write.
fn valid_time(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 19
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b':',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
        && &s[..4] != "0000"
}

// ---- writing them out ------------------------------------------------------------------

/// One version to write, and the name it takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    /// Indexes into the search's damaged pictures and that picture's versions.
    pub damaged: usize,
    pub version: usize,
    /// The damaged picture's folders, from the volume's root, under the output folder.
    pub folder: Vec<String>,
    pub name: String,
}

/// The names to write the versions under, and the list for each folder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub files: Vec<Named>,
    /// For each folder written to, the text of its `LIST_NAME`.
    pub lists: Vec<(Vec<String>, String)>,
}

/// Names each version after its damaged picture, in that picture's folder path: the first
/// takes its name, a second " (2)" and so on, a version of another real format takes that
/// format's ending, and a name already taken in the folder moves on to the next number.
pub fn plan(damaged: &[Damaged]) -> Plan {
    let mut plan = Plan::default();
    let mut taken: HashMap<Vec<String>, HashSet<String>> = HashMap::new();
    for (di, d) in damaged.iter().enumerate() {
        let (stem, own) = match d.name.rsplit_once('.') {
            Some((stem, ext)) => (stem, Some(ext)),
            None => (d.name.as_str(), None),
        };
        let used = taken
            .entry(d.folder.clone())
            .or_insert_with(|| HashSet::from([LIST_NAME.to_lowercase()]));
        for (vi, v) in d.versions.iter().enumerate() {
            let ext = match (v.format, own) {
                (Some(f), own) if Some(f) != d.format => Some(cased(f.ending(), own)),
                (_, own) => own.map(str::to_string),
            };
            let mut n = vi + 1;
            let name = loop {
                let numbered = if n == 1 {
                    stem.to_string()
                } else {
                    format!("{stem} ({n})")
                };
                let name = match &ext {
                    Some(ext) => format!("{numbered}.{ext}"),
                    None => numbered,
                };
                if used.insert(name.to_lowercase()) {
                    break name;
                }
                n += 1;
            };
            let line = format!("{name}\t{}\t{}\r\n", v.kind.label(), v.path);
            match plan.lists.iter_mut().find(|(f, _)| *f == d.folder) {
                Some((_, text)) => text.push_str(&line),
                None => plan.lists.push((
                    d.folder.clone(),
                    format!("Name here\tKind\tCopied from\r\n{line}"),
                )),
            }
            plan.files.push(Named {
                damaged: di,
                version: vi,
                folder: d.folder.clone(),
                name,
            });
        }
    }
    plan
}

/// `ending` in the case of the damaged file's own ending: "JPG" beside "PNG".
fn cased(ending: &str, own: Option<&str>) -> String {
    match own {
        Some(own)
            if own.chars().any(|c| c.is_ascii_uppercase())
                && !own.chars().any(|c| c.is_ascii_lowercase()) =>
        {
            ending.to_ascii_uppercase()
        }
        _ => ending.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::fs::{Part, Run};
    use crate::recovery::MemDisk;

    /// A TIFF block holding IFD0 (with DateTime when `datetime`) and an EXIF IFD with
    /// DateTimeOriginal and SubSecTimeOriginal when given.
    fn tiff(
        le: bool,
        original: Option<&str>,
        subsec: Option<&str>,
        datetime: Option<&str>,
    ) -> Vec<u8> {
        let w16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let w32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let ascii = |s: &str| {
            let mut b = s.as_bytes().to_vec();
            b.push(0);
            b
        };
        let mut ifd0: Vec<(u16, u16, Vec<u8>)> = vec![(0x8769, 4, Vec::new())];
        if let Some(d) = datetime {
            ifd0.push((0x0132, 2, ascii(d)));
        }
        let mut exif: Vec<(u16, u16, Vec<u8>)> = Vec::new();
        if let Some(d) = original {
            exif.push((0x9003, 2, ascii(d)));
        }
        if let Some(s) = subsec {
            exif.push((0x9291, 2, ascii(s)));
        }
        // Layout: header, IFD0, its values, the EXIF IFD, its values.
        let size = |n: usize| 2 + n * 12 + 4;
        let values = |e: &[(u16, u16, Vec<u8>)]| -> usize {
            e.iter()
                .map(|x| if x.2.len() > 4 { x.2.len() } else { 0 })
                .sum()
        };
        let exif_at = 8 + size(ifd0.len()) + values(&ifd0);
        let mut out = Vec::new();
        out.extend_from_slice(if le { b"II" } else { b"MM" });
        out.extend_from_slice(&w16(42));
        out.extend_from_slice(&w32(8));
        let write = |out: &mut Vec<u8>, at: usize, entries: &[(u16, u16, Vec<u8>)], ptr: u32| {
            let mut value_at = at + size(entries.len());
            let mut tail = Vec::new();
            out.extend_from_slice(&w16(entries.len() as u16));
            for (tag, kind, v) in entries {
                out.extend_from_slice(&w16(*tag));
                out.extend_from_slice(&w16(*kind));
                if *tag == 0x8769 {
                    out.extend_from_slice(&w32(1));
                    out.extend_from_slice(&w32(ptr));
                } else if v.len() <= 4 {
                    out.extend_from_slice(&w32(v.len() as u32));
                    let mut f = v.clone();
                    f.resize(4, 0);
                    out.extend_from_slice(&f);
                } else {
                    out.extend_from_slice(&w32(v.len() as u32));
                    out.extend_from_slice(&w32(value_at as u32));
                    value_at += v.len();
                    tail.extend_from_slice(v);
                }
            }
            out.extend_from_slice(&w32(0));
            out.extend_from_slice(&tail);
        };
        write(&mut out, 8, &ifd0, exif_at as u32);
        write(&mut out, exif_at, &exif, 0);
        out
    }

    /// A JPEG of `size` bytes taken at `when`, its body filled from `seed`.
    fn jpeg(when: &str, seed: u8, size: usize) -> Vec<u8> {
        let t = tiff(true, Some(when), None, None);
        let mut b = vec![0xFF, 0xD8, 0xFF, 0xE1];
        b.extend_from_slice(&((t.len() + 8) as u16).to_be_bytes());
        b.extend_from_slice(b"Exif\0\0");
        b.extend_from_slice(&t);
        b.extend_from_slice(&[0xFF, 0xDA]);
        fill(b, seed, size)
    }

    /// A PNG of `size` bytes taken at `when`, from its eXIf chunk.
    fn png(when: &str, seed: u8, size: usize) -> Vec<u8> {
        let t = tiff(false, Some(when), None, None);
        let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
        b.extend_from_slice(&13u32.to_be_bytes());
        b.extend_from_slice(b"IHDR");
        b.extend_from_slice(&[0; 17]);
        b.extend_from_slice(&(t.len() as u32).to_be_bytes());
        b.extend_from_slice(b"eXIf");
        b.extend_from_slice(&t);
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(b"IDAT");
        fill(b, seed, size)
    }

    fn fill(mut b: Vec<u8>, seed: u8, size: usize) -> Vec<u8> {
        let mut x = u32::from(seed).wrapping_mul(2_654_435_761) | 1;
        while b.len() < size {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            b.push((x >> 16) as u8);
        }
        b
    }

    /// A volume of files, an image of it and its map: each file laid at the next 64 KiB,
    /// with `gaps` (offsets in the file) not rescued and read as zeros, as in an image.
    struct Volume {
        listing: Listing,
        data: Vec<u8>,
        map: Map,
    }

    impl Volume {
        fn new() -> Self {
            Self {
                listing: Listing::default(),
                data: Vec::new(),
                map: Map::new(0),
            }
        }

        fn add(&mut self, folder: &str, name: &str, bytes: &[u8], gaps: &[Range<u64>]) -> usize {
            let at = self.data.len() as u64;
            let mut bytes = bytes.to_vec();
            for g in gaps {
                bytes[g.start as usize..g.end as usize].fill(0);
            }
            self.data.extend_from_slice(&bytes);
            self.data
                .resize((at as usize + bytes.len()).div_ceil(65536) * 65536, 0);
            self.listing.files.push(Found {
                name: name.into(),
                folder: folder
                    .split('\\')
                    .filter(|p| !p.is_empty())
                    .map(|p| Part {
                        name: p.into(),
                        deleted: false,
                    })
                    .collect(),
                size: bytes.len() as u64,
                modified: None,
                deleted: false,
                state: State::Intact,
                data: Data::Runs(vec![Run {
                    place: Place::At(at),
                    len: bytes.len() as u64,
                }]),
                damaged: false,
                note: None,
                why: None,
            });
            let mut map = Map::new(self.data.len() as u64);
            map.set(0, self.data.len() as u64, Status::Rescued);
            for b in &self.map.blocks {
                if b.status != Status::Rescued {
                    map.set(b.pos, b.size, b.status);
                }
            }
            for g in gaps {
                map.set(at + g.start, g.end - g.start, Status::Bad);
            }
            self.map = map;
            self.listing.files.len() - 1
        }

        fn search(&self) -> Search {
            let mut reader = Reader::new(Box::new(MemDisk::new(self.data.clone())));
            search(
                &mut reader,
                &self.map,
                &self.listing,
                &AtomicBool::new(false),
                &Progress::default(),
            )
        }
    }

    const SIZE: usize = 20_000;
    const GAP: Range<u64> = 8192..8704;
    const START: Range<u64> = 0..512;

    fn kinds(d: &Damaged) -> Vec<(&str, Kind)> {
        d.versions
            .iter()
            .map(|v| (v.path.as_str(), v.kind))
            .collect()
    }

    /// The guard: a copy is compared only over the bytes the damaged picture has; the bytes
    /// it lacks read as zeros in the image and differ from the copy's, and a renamed copy is
    /// found after a same-named one.
    #[test]
    fn a_renamed_whole_copy_is_found_by_its_readable_bytes() {
        let photo = jpeg("2019:11:24 08:07:36", 1, SIZE);
        let mut vol = Volume::new();
        vol.add("\\DCIM", "20191124_080736.jpg", &photo, &[GAP]);
        vol.add("\\Backup\\Phone", "BQOE9443.JPG", &photo, &[]);
        vol.add("\\Backup", "20191124_080736.JPG", &photo, &[]);
        let found = vol.search();
        assert_eq!(found.damaged.len(), 1);
        let d = &found.damaged[0];
        assert_eq!(d.path, "\\DCIM\\20191124_080736.jpg");
        assert_eq!(d.missing, 512);
        assert_eq!(
            kinds(d),
            [
                ("\\Backup\\20191124_080736.JPG", Kind::Whole),
                ("\\Backup\\Phone\\BQOE9443.JPG", Kind::Whole),
            ]
        );
        assert!(d
            .versions
            .iter()
            .all(|v| v.format == Some(Format::Jpeg) && v.size == SIZE as u64));
    }

    /// The guard: a copy whose run is laid at the top of the address space, as a damaged
    /// file-system record can lay it, is not read from a low offset where the sum wrapped:
    /// it is counted as a damaged picture, with all of its bytes missing, and is no copy.
    #[test]
    fn a_run_laid_past_the_top_of_the_source_is_not_read_as_a_copy() {
        let photo = jpeg("2019:11:24 08:07:36", 1, SIZE);
        let mut vol = Volume::new();
        vol.add("\\DCIM", "a.jpg", &photo, &[GAP]);
        let bogus = vol.add("\\Other", "b.jpg", &photo, &[]);
        vol.listing.files[bogus].data = Data::Runs(vec![Run {
            place: Place::At(u64::MAX),
            len: SIZE as u64,
        }]);
        let found = vol.search();
        assert_eq!(found.damaged.len(), 2);
        let (real, laid) = (&found.damaged[0], &found.damaged[1]);
        assert!(real.versions.is_empty(), "{:?}", real.versions);
        assert_eq!(
            (laid.path.as_str(), laid.missing),
            ("\\Other\\b.jpg", SIZE as u64)
        );
    }

    /// A same-sized file that differs on a byte the damaged picture has is not a copy, nor is
    /// one that differs just past the near margin.
    #[test]
    fn a_copy_differing_in_a_readable_byte_is_rejected() {
        let photo = jpeg("2019:11:24 08:07:36", 1, SIZE);
        let mut vol = Volume::new();
        vol.add("\\DCIM", "a.jpg", &photo, &[GAP]);
        for at in [100, GAP.end + NEAR, GAP.start - NEAR - 1] {
            let mut other = photo.clone();
            other[at as usize] ^= 0x40;
            vol.add("\\Other", &format!("a{at}.jpg"), &other, &[]);
        }
        let found = vol.search();
        // Same capture time, so each is still an other version; none is a copy.
        let versions = &found.damaged[0].versions;
        assert_eq!(versions.len(), 3);
        assert!(versions.iter().all(|v| v.kind == Kind::Lesser));
    }

    /// A copy that differs only within `NEAR` bytes of an unread part is a near copy, listed
    /// after the whole ones.
    #[test]
    fn a_copy_differing_next_to_an_unread_part_is_near() {
        let photo = jpeg("2019:11:24 08:07:36", 1, SIZE);
        let mut vol = Volume::new();
        vol.add("\\DCIM", "a.jpg", &photo, &[GAP]);
        let mut near = photo.clone();
        near[(GAP.end + NEAR - 1) as usize] ^= 1;
        near[(GAP.start - NEAR) as usize] ^= 1;
        vol.add("\\Near", "a.jpg", &near, &[]);
        vol.add("\\Whole", "b.jpg", &photo, &[]);
        let found = vol.search();
        assert_eq!(
            kinds(&found.damaged[0]),
            [
                ("\\Whole\\b.jpg", Kind::Whole),
                ("\\Near\\a.jpg", Kind::Near)
            ]
        );
    }

    /// The guard: another version is matched by its capture time alone, whatever its name and
    /// size, and a picture taken at another time or in another frame of a burst is not.
    #[test]
    fn a_lesser_version_is_found_by_capture_time() {
        let mut vol = Volume::new();
        vol.add(
            "\\DCIM",
            "IMG_2767.JPG",
            &jpeg("2023:05:01 14:03:22", 1, SIZE),
            &[GAP],
        );
        vol.add(
            "\\DCIM",
            "IMG_E2767.JPG",
            &jpeg("2023:05:01 14:03:22", 2, 15_000),
            &[],
        );
        vol.add(
            "\\DCIM",
            "IMG_2768.JPG",
            &jpeg("2023:05:01 14:03:23", 3, SIZE),
            &[],
        );
        vol.add(
            "\\DCIM",
            "IMG_2766.JPG",
            &jpeg("2023:05:01 14:03:21", 4, 15_000),
            &[],
        );
        vol.add(
            "\\Takeout\\Photos from 2023",
            "IMG_2767.JPG",
            &jpeg("2023:05:01 14:03:22", 5, 9_000),
            &[],
        );
        let found = vol.search();
        let d = &found.damaged[0];
        assert_eq!(
            d.captured.as_ref().map(|c| c.when.as_str()),
            Some("2023:05:01 14:03:22")
        );
        assert_eq!(
            kinds(d),
            [
                ("\\DCIM\\IMG_E2767.JPG", Kind::Lesser),
                ("\\Takeout\\Photos from 2023\\IMG_2767.JPG", Kind::Lesser),
            ]
        );
        let burst = |subsec: Option<&str>| {
            let t = tiff(true, Some("2023:05:01 14:03:22"), subsec, None);
            tiff_capture(&t).unwrap()
        };
        assert!(burst(Some("10")).same(&burst(None)));
        assert!(!burst(Some("10")).same(&burst(Some("55"))));
    }

    /// A damaged picture whose start was not read has no capture time, so no other version.
    #[test]
    fn a_damaged_picture_with_an_unread_start_has_no_date() {
        let mut vol = Volume::new();
        vol.add(
            "\\DCIM",
            "a.jpg",
            &jpeg("2023:05:01 14:03:22", 1, SIZE),
            &[START],
        );
        vol.add(
            "\\DCIM",
            "b.jpg",
            &jpeg("2023:05:01 14:03:22", 2, 9_000),
            &[],
        );
        let found = vol.search();
        assert_eq!(found.damaged[0].captured, None);
        assert!(found.damaged[0].versions.is_empty());
        assert_eq!(found.damaged[0].format, Some(Format::Jpeg));
    }

    /// A PNG's JPEG version takes the JPEG ending, in the PNG's case, beside the PNG's name.
    #[test]
    fn a_png_damaged_files_jpeg_version_is_named_jpg() {
        let mut vol = Volume::new();
        vol.add(
            "\\Pictures",
            "IMG_3236.PNG",
            &png("2022:08:14 09:30:00", 1, SIZE),
            &[GAP],
        );
        vol.add(
            "\\Photos from 2022",
            "IMG_3236.jpg",
            &jpeg("2022:08:14 09:30:00", 2, 7_000),
            &[],
        );
        let found = vol.search();
        let d = &found.damaged[0];
        assert_eq!(d.format, Some(Format::Png));
        assert_eq!(d.versions[0].format, Some(Format::Jpeg));
        let plan = plan(&found.damaged);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].folder, ["Pictures"]);
        assert_eq!(plan.files[0].name, "IMG_3236.JPG");
    }

    fn version_at(file: usize, path: &str, kind: Kind, format: Option<Format>) -> Version {
        Version {
            file,
            path: path.into(),
            size: 1,
            deleted: false,
            kind,
            format,
        }
    }

    /// The first version takes the damaged name, the next " (2)" and on, a name already
    /// taken in the folder moves on, and the list says where each came from.
    #[test]
    fn versions_after_the_first_are_numbered() {
        let damaged = |file: usize, name: &str, versions: Vec<Version>| Damaged {
            file,
            name: name.into(),
            folder: vec!["DCIM".into()],
            path: format!("\\DCIM\\{name}"),
            size: 1,
            missing: 1,
            format: Format::of_name(name),
            captured: None,
            versions,
        };
        let jpg = Some(Format::Jpeg);
        let list = [
            damaged(
                0,
                "a.jpg",
                vec![
                    version_at(1, "\\x\\a.jpg", Kind::Whole, jpg),
                    version_at(2, "\\y\\b.jpg", Kind::Near, jpg),
                    version_at(3, "\\z\\c.jpg", Kind::Lesser, jpg),
                ],
            ),
            damaged(
                4,
                "a.png",
                vec![version_at(5, "\\w\\a.jpeg", Kind::Lesser, jpg)],
            ),
        ];
        let plan = plan(&list);
        let names: Vec<&str> = plan.files.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["a.jpg", "a (2).jpg", "a (3).jpg", "a (4).jpg"]);
        assert_eq!(
            plan.lists,
            [(
                vec!["DCIM".to_string()],
                "Name here\tKind\tCopied from\r\n\
                 a.jpg\twhole copy\t\\x\\a.jpg\r\n\
                 a (2).jpg\tnear copy, differs only next to unreadable parts\t\\y\\b.jpg\r\n\
                 a (3).jpg\tother version, same capture time\t\\z\\c.jpg\r\n\
                 a (4).jpg\tother version, same capture time\t\\w\\a.jpeg\r\n"
                    .to_string()
            )]
        );
    }

    /// A test disk the test keeps a hold of, to see the reads asked of it.
    struct Shared(std::sync::Arc<std::sync::Mutex<MemDisk>>);

    impl crate::recovery::BlockSource for Shared {
        fn len(&self) -> u64 {
            self.0.lock().unwrap().len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), crate::recovery::ReadError> {
            self.0.lock().unwrap().read_at(offset, buf)
        }
        fn describe(&self) -> String {
            "shared test disk".into()
        }
    }

    /// The whole pictures' starts are read once each, in the order they lie on the source
    /// whatever the listing's order; progress ends at its total, and a stop is said.
    #[test]
    fn starts_are_read_in_source_order_and_a_stop_is_said() {
        let mut vol = Volume::new();
        vol.add(
            "\\DCIM",
            "a.jpg",
            &jpeg("2023:05:01 14:03:22", 1, SIZE),
            &[GAP],
        );
        for seed in 2..6 {
            let photo = jpeg("2023:05:01 14:03:22", seed, 9_000 + usize::from(seed));
            vol.add("\\DCIM", &format!("{seed}.jpg"), &photo, &[]);
        }
        vol.listing.files.reverse();
        let disk = std::sync::Arc::new(std::sync::Mutex::new(MemDisk::new(vol.data.clone())));
        let mut reader = Reader::new(Box::new(Shared(disk.clone())));
        let progress = Progress::default();
        let found = search(
            &mut reader,
            &vol.map,
            &vol.listing,
            &AtomicBool::new(false),
            &progress,
        );
        assert_eq!(found.damaged[0].versions.len(), 4);
        assert!(!found.stopped);
        let reads: Vec<u64> = disk.lock().unwrap().reads.iter().map(|r| r.0).collect();
        let starts: Vec<u64> = reads.into_iter().filter(|at| *at >= 65536).collect();
        assert_eq!(starts, [65536, 131072, 196608, 262144]);
        assert_eq!(progress.permille(), 1000);
        assert_eq!(progress.found.load(Ordering::Relaxed), 1);

        let mut reader = Reader::new(Box::new(MemDisk::new(vol.data.clone())));
        let stopped = search(
            &mut reader,
            &vol.map,
            &vol.listing,
            &AtomicBool::new(true),
            &Progress::default(),
        );
        assert!(stopped.stopped);
    }

    /// DateTime stands in when there is no original, in either byte order; a blank time is
    /// none.
    #[test]
    fn exif_times_are_read_in_either_byte_order() {
        for le in [true, false] {
            let t = tiff(le, None, None, Some("2020:01:02 03:04:05"));
            assert_eq!(tiff_capture(&t).unwrap().when, "2020:01:02 03:04:05");
            let t = tiff(
                le,
                Some("2021:01:02 03:04:05"),
                Some("123"),
                Some("2020:01:02 03:04:05"),
            );
            let c = tiff_capture(&t).unwrap();
            assert_eq!(
                (c.when.as_str(), c.subsec.as_deref()),
                ("2021:01:02 03:04:05", Some("123"))
            );
            let t = tiff(le, Some("0000:00:00 00:00:00"), None, None);
            assert_eq!(tiff_capture(&t), None);
        }
        // A JPEG whose EXIF block runs past the bytes read has no time.
        let j = jpeg("2020:01:02 03:04:05", 1, 4096);
        assert!(capture(&j).is_some());
        assert_eq!(capture(&j[..40]), None);
    }

    /// A HEIF's time comes from its Exif item, placed by `iloc`.
    #[test]
    fn a_heif_time_comes_from_its_exif_item() {
        let t = tiff(true, Some("2024:02:03 04:05:06"), None, None);
        let boxed = |kind: &[u8], body: &[u8]| {
            let mut b = ((body.len() + 8) as u32).to_be_bytes().to_vec();
            b.extend_from_slice(kind);
            b.extend_from_slice(body);
            b
        };
        let mut ftyp = b"heic".to_vec();
        ftyp.extend_from_slice(&[0, 0, 0, 0]);
        ftyp.extend_from_slice(b"mif1heic");
        let ftyp = boxed(b"ftyp", &ftyp);
        let mut infe1 = vec![2, 0, 0, 0, 0, 1, 0, 0];
        infe1.extend_from_slice(b"hvc1\0");
        let mut infe2 = vec![2, 0, 0, 0, 0, 7, 0, 0];
        infe2.extend_from_slice(b"Exif\0");
        let mut iinf = vec![0, 0, 0, 0, 0, 2];
        iinf.extend(boxed(b"infe", &infe1));
        iinf.extend(boxed(b"infe", &infe2));
        let iinf = boxed(b"iinf", &iinf);
        // Version 1, 4-byte offsets and lengths, no base offset: items 1 and 7.
        let iloc_len = 8 + 8 + 2 * 16;
        let meta_len = 8 + 4 + iinf.len() + iloc_len;
        let exif_at = (ftyp.len() + meta_len + 8) as u32;
        let mut iloc = vec![1, 0, 0, 0, 0x44, 0x00, 0, 2];
        for (id, at, len) in [(1u16, 0u32, 0u32), (7, exif_at, (t.len() + 10) as u32)] {
            iloc.extend_from_slice(&id.to_be_bytes());
            iloc.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
            iloc.extend_from_slice(&at.to_be_bytes());
            iloc.extend_from_slice(&len.to_be_bytes());
        }
        let iloc = boxed(b"iloc", &iloc);
        let mut meta = vec![0, 0, 0, 0];
        meta.extend(iinf);
        meta.extend(iloc);
        let mut file = ftyp;
        file.extend(boxed(b"meta", &meta));
        let mut item = 6u32.to_be_bytes().to_vec();
        item.extend_from_slice(b"Exif\0\0");
        item.extend_from_slice(&t);
        file.extend(boxed(b"mdat", &item));
        assert_eq!(Format::of_bytes(&file), Some(Format::Heic));
        assert_eq!(capture(&file).unwrap().when, "2024:02:03 04:05:06");
    }
}
