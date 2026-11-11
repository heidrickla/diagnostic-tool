//! Finding files by type: a read of the whole source in large chunks, looking at the start
//! of every sector for a known file header, and each find's real end from its own structure
//! (JPEG markers, PNG chunks, ISO boxes, size fields and archive ends) within a cap per type.
//! Unreadable chunks are skipped by the reader and recorded there.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::reader::{Reader, CHUNK};
use crate::budget::{Budget, Limit, Limits};

/// What a search of a source may spend: 4,194,304 files found (each a row the person
/// chooses from); its bytes, the source read for headers and each find read to its end,
/// are set for each source by `bytes_for`; nothing held past the chunk it reads; no clock
/// limit, since the person watches it with a Stop button, checked at every chunk and every
/// piece a find's end is looked for in.
pub const LIMITS: Limits = Limits {
    what: "the search for files by type",
    unit: "files found",
    count: 1 << 22,
    bytes: u64::MAX,
    memory: u64::MAX,
    depth: 0,
    nested: "parts",
    time: None,
};

/// The bytes a search of a `len`-byte source may read: the source once for its headers,
/// twice more for finding the ends of what starts there (a real file's end is read once,
/// and its bytes are then skipped), and one more of the largest cap, so the last find of a
/// small source is still measured. Starts forged in every sector, each sending the search
/// to read up to its cap, end the search at this limit instead of reading for days.
pub fn bytes_for(len: u64) -> u64 {
    len.saturating_mul(3).saturating_add(Kind::Mp4.cap())
}

/// A file type the carver finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Jpeg,
    Png,
    Gif,
    Bmp,
    Pdf,
    Zip,
    Mp4,
    Riff,
    Sqlite,
    SevenZip,
    Rar,
}

impl Kind {
    pub const ALL: [Kind; 11] = [
        Kind::Jpeg,
        Kind::Png,
        Kind::Gif,
        Kind::Bmp,
        Kind::Pdf,
        Kind::Zip,
        Kind::Mp4,
        Kind::Riff,
        Kind::Sqlite,
        Kind::SevenZip,
        Kind::Rar,
    ];

    pub fn index(self) -> usize {
        Kind::ALL.iter().position(|k| *k == self).unwrap_or(0)
    }

    /// For people.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Jpeg => "JPEG",
            Kind::Png => "PNG",
            Kind::Gif => "GIF",
            Kind::Bmp => "BMP",
            Kind::Pdf => "PDF",
            Kind::Zip => "ZIP and Office",
            Kind::Mp4 => "MP4 and MOV",
            Kind::Riff => "AVI, WAV, WebP",
            Kind::Sqlite => "SQLite",
            Kind::SevenZip => "7z",
            Kind::Rar => "RAR",
        }
    }

    /// The largest file of the type the carver takes; a longer one is cut here.
    pub fn cap(self) -> u64 {
        const MIB: u64 = 1 << 20;
        match self {
            Kind::Jpeg | Kind::Png => 128 * MIB,
            Kind::Gif => 64 * MIB,
            Kind::Bmp | Kind::Pdf => 512 * MIB,
            Kind::Zip | Kind::Riff | Kind::Sqlite => 4096 * MIB,
            Kind::Mp4 | Kind::SevenZip | Kind::Rar => 8192 * MIB,
        }
    }
}

/// One file found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carved {
    pub kind: Kind,
    pub ext: &'static str,
    pub offset: u64,
    pub len: u64,
    /// Part of it could not be read.
    pub damaged: bool,
}

impl Carved {
    /// A name from where it was found: "f0002048.jpg" for sector 2048.
    pub fn name(&self) -> String {
        format!("f{:08}.{}", self.offset / 512, self.ext)
    }
}

#[derive(Debug, Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
    pub counts: [AtomicU64; 11],
    /// Starts of each kind whose end lies past the kind's cap: skipped, and counted here.
    pub too_long: [AtomicU64; 11],
}

/// How a search ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Carving {
    /// Starts of each kind (by `Kind::index`) whose end lies past the kind's cap, skipped.
    pub too_long: [u64; 11],
    /// The limit of its budget it reached, in words, when it reached one.
    pub limit: Option<String>,
}

impl Carving {
    /// What was skipped and why, for people, one line per kind; empty when nothing was.
    pub fn notes(&self) -> Vec<String> {
        let mut out: Vec<String> = Kind::ALL
            .iter()
            .filter(|k| self.too_long[k.index()] > 0)
            .map(|k| {
                let n = self.too_long[k.index()];
                format!(
                    "{n} {} {} whose end lies past the {} this search takes {} skipped.",
                    k.label(),
                    if n == 1 { "start" } else { "starts" },
                    crate::tools::drives::bytes_text(k.cap()),
                    if n == 1 { "was" } else { "were" },
                )
            })
            .collect();
        out.extend(self.limit.clone());
        out
    }
}

/// The type whose header starts `b`, if any.
pub fn header(b: &[u8]) -> Option<Kind> {
    if b.len() < 32 {
        return None;
    }
    let be32 = |at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let le32 = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let le16 = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    if b[..3] == [0xFF, 0xD8, 0xFF]
        && (b[3] & 0xF0 == 0xE0 || matches!(b[3], 0xDB | 0xC0 | 0xC2 | 0xC4 | 0xFE))
    {
        return Some(Kind::Jpeg);
    }
    if b[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(Kind::Png);
    }
    if &b[..6] == b"GIF87a" || &b[..6] == b"GIF89a" {
        return Some(Kind::Gif);
    }
    if &b[..2] == b"BM"
        && le32(2) >= 26
        && le32(6) == 0
        && [12, 40, 52, 56, 64, 108, 124].contains(&le32(14))
        && le32(10) < le32(2)
    {
        return Some(Kind::Bmp);
    }
    if &b[..5] == b"%PDF-" {
        return Some(Kind::Pdf);
    }
    if &b[..4] == b"PK\x03\x04" && le16(4) <= 63 && (1..=1024).contains(&le16(26)) {
        return Some(Kind::Zip);
    }
    if &b[4..8] == b"ftyp"
        && (8..=1024).contains(&be32(0))
        && b[8..12].iter().all(|c| c.is_ascii_graphic() || *c == b' ')
    {
        return Some(Kind::Mp4);
    }
    if &b[..4] == b"RIFF" && matches!(&b[8..12], b"AVI " | b"WAVE" | b"WEBP") {
        return Some(Kind::Riff);
    }
    if &b[..16] == b"SQLite format 3\0" {
        return Some(Kind::Sqlite);
    }
    if b[..6] == [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(Kind::SevenZip);
    }
    if &b[..7] == b"Rar!\x1A\x07\x00" || &b[..8] == b"Rar!\x1A\x07\x01\x00" {
        return Some(Kind::Rar);
    }
    None
}

/// The most of a file's start the check reads, in one read through its runs. It never reads
/// a file's end, since the source may be failing.
pub const HEAD: usize = 4096;

/// The signatures of a zip's records: local file header, central directory header, end of
/// central directory, the zip64 end record and its locator, and the spanning marker.
const ZIP_MARKERS: [&[u8; 4]; 6] = [
    b"PK\x03\x04",
    b"PK\x01\x02",
    b"PK\x05\x06",
    b"PK\x06\x06",
    b"PK\x06\x07",
    b"PK\x07\x08",
];

/// The top-level box types MP4 and QuickTime files are seen to start with.
const BOXES_FIRST: [&[u8; 4]; 12] = [
    b"ftyp", b"styp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot", b"uuid", b"junk",
    b"pdin", b"sidx",
];

/// What a file's start says of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// It starts as its type should.
    Fits,
    /// Every file of its type starts this way at byte 0, and it does not: overwritten.
    Mismatch,
    /// Most files of its type show a marker near their start, and it does not, though a
    /// valid one may have a longer lead: "a zip document" names the type.
    Unlike(&'static str),
    /// Its start could not be read, so it is not judged by it.
    Unread,
}

/// Why bytes asked of a file were not given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    /// They lie past its end or were never written: nothing to judge.
    Unwritten,
    /// The source could not read them.
    Unreadable,
}

/// What a file's start must hold to be what its extension says, for the check of files
/// whose space may now hold something else. Only types with a marker in the first 4 KiB,
/// or at a fixed offset, are here: a plain zip may carry a self-extractor of any size, and
/// an encrypted SQLite database starts with random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// FF D8 FF: the start-of-image marker and the next marker's FF.
    Jpeg,
    Png,
    /// GIF87a or GIF89a.
    Gif,
    /// "BM", or an OS/2 bitmap's "BA", "CI", "CP", "IC" or "PT".
    Bmp,
    /// "%PDF-" within the first 1 KiB, where readers look for it; one without it may still
    /// be a PDF, so it is never called overwritten.
    Pdf,
    /// Office Open XML, OpenDocument and EPUB: a zip, which may have bytes before its first
    /// entry, so a zip record's signature within the first 4 KiB; one without it may still
    /// be a document, so it is never called overwritten.
    Office,
    /// MP4, MOV and their kin: a top-level box type seen first in such files (ftyp, moov,
    /// mdat, free, skip, wide and the rest) with a size that fits the file.
    Bmff,
    /// RIFF, RIFX, RF64 or BW64, with WAVE at byte 8.
    Wav,
    /// RIFF with "AVI " at byte 8.
    Avi,
    /// RIFF with WEBP at byte 8.
    Webp,
    SevenZip,
    /// RAR 1.5 to 4, RAR 5 or RAR 1.4.
    Rar,
    /// An ISO 9660 or UDF volume descriptor at 32 KiB + 1: CD001, BEA01 and the rest. Its
    /// first 32 KiB may hold anything, so its one read is the 2 KiB descriptor at 32 KiB.
    Iso,
}

/// Where an ISO's first volume descriptor starts, and its size.
const ISO_DESCRIPTOR: (u64, usize) = (0x8000, 2048);

impl Expect {
    /// What a file named `name` must start with, or None for a type with no known start.
    pub fn of(name: &str) -> Option<Expect> {
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match ext.as_str() {
            "jpg" | "jpeg" | "jpe" => Expect::Jpeg,
            "png" => Expect::Png,
            "gif" => Expect::Gif,
            "bmp" => Expect::Bmp,
            "pdf" => Expect::Pdf,
            "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" => Expect::Office,
            "mp4" | "m4v" | "m4a" | "mov" | "3gp" => Expect::Bmff,
            "wav" => Expect::Wav,
            "avi" => Expect::Avi,
            "webp" => Expect::Webp,
            "7z" => Expect::SevenZip,
            "rar" => Expect::Rar,
            "iso" => Expect::Iso,
            _ => return None,
        })
    }

    /// The fewest bytes a file must have for its start to be judged: the smallest zip, an
    /// empty one, is its 22-byte end record.
    pub fn need(self) -> usize {
        match self {
            Expect::Pdf | Expect::Office => 22,
            Expect::Iso => ISO_DESCRIPTOR.0 as usize + ISO_DESCRIPTOR.1,
            _ => 16,
        }
    }

    /// Where its one read starts and how long it is at most: no more than `HEAD`, from
    /// byte 0 for every type but an ISO, whose read is its first volume descriptor.
    fn window(self) -> (u64, usize) {
        match self {
            Expect::Pdf => (0, 1024),
            Expect::Office => (0, HEAD),
            Expect::Iso => ISO_DESCRIPTOR,
            _ => (0, 16),
        }
    }

    /// What the start of a file of `size` bytes says of it, read in one call to
    /// `read(offset, len)` at its window. None when there is too little to tell or the
    /// bytes were never written.
    pub fn check(
        self,
        size: u64,
        read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, Missing>,
    ) -> Option<Start> {
        if size < self.need() as u64 {
            return None;
        }
        let (from, len) = self.window();
        let head = match read(from, (size - from).min(len as u64) as usize) {
            Ok(head) => head,
            Err(Missing::Unwritten) => return None,
            Err(Missing::Unreadable) => return Some(Start::Unread),
        };
        Some(match self {
            _ if self.fits(&head, size) => Start::Fits,
            Expect::Pdf => Start::Unlike("a PDF document"),
            Expect::Office => Start::Unlike("a zip document"),
            _ => Start::Mismatch,
        })
    }

    /// Whether `head`, the bytes `check` reads at its window, are as its type's are, in a
    /// file of `size` bytes.
    fn fits(self, head: &[u8], size: u64) -> bool {
        let at = |n: usize, s: &[u8]| head.get(n..n + s.len()) == Some(s);
        let riff = |form: &[u8]| at(0, b"RIFF") && at(8, form);
        match self {
            Expect::Jpeg => at(0, &[0xFF, 0xD8, 0xFF]),
            Expect::Png => at(0, &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
            Expect::Gif => at(0, b"GIF87a") || at(0, b"GIF89a"),
            Expect::Bmp => [b"BM", b"BA", b"CI", b"CP", b"IC", b"PT"]
                .iter()
                .any(|m| at(0, *m)),
            Expect::Pdf => head.windows(5).any(|w| w == b"%PDF-"),
            Expect::Office => head.windows(4).any(|w| ZIP_MARKERS.iter().any(|m| w == *m)),
            Expect::Bmff => {
                if head.len() < 16 {
                    return false;
                }
                let first = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
                let large = u64::from_be_bytes(head[8..16].try_into().unwrap_or([0; 8]));
                // A size of 0 runs to the end of the file; 1 means a 64-bit size follows.
                let size_ok = match first {
                    0 => true,
                    1 => (16..=size).contains(&large),
                    n => (8..=size).contains(&u64::from(n)),
                };
                size_ok && BOXES_FIRST.iter().any(|b| at(4, *b))
            }
            Expect::Wav => {
                [b"RIFF", b"RIFX", b"RF64", b"BW64"]
                    .iter()
                    .any(|m| at(0, *m))
                    && at(8, b"WAVE")
            }
            Expect::Avi => riff(b"AVI "),
            Expect::Webp => riff(b"WEBP"),
            Expect::SevenZip => at(0, &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]),
            Expect::Rar => {
                at(0, b"Rar!\x1A\x07\x00") || at(0, b"Rar!\x1A\x07\x01\x00") || at(0, b"RE~^")
            }
            // Read from 0x8000, so the identifier at 0x8001 is at 1.
            Expect::Iso => [
                b"CD001", b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2", b"CDW02",
            ]
            .iter()
            .any(|id| at(1, *id)),
        }
    }
}

/// Reads forward from a find, with a buffer, never past a limit, each read charged to the
/// search's budget.
struct Stream<'r, 's, 'b, 'c> {
    reader: &'r mut Reader<'s>,
    budget: &'b mut Budget<'c>,
    start: u64,
    /// Bytes from `start` that may be read.
    limit: u64,
    /// The limit is the kind's cap, not the end of the source.
    capped: bool,
    /// Something past the limit was asked for.
    past: bool,
    /// The furthest byte from `start` the measure looked at: what it is charged for, so a
    /// find is charged its own length and not the whole piece read around it.
    reached: u64,
    buf: Vec<u8>,
    buf_at: u64,
}

impl<'r, 's, 'b, 'c> Stream<'r, 's, 'b, 'c> {
    fn new(reader: &'r mut Reader<'s>, budget: &'b mut Budget<'c>, start: u64, cap: u64) -> Self {
        let room = reader.len().saturating_sub(start);
        Self {
            reader,
            budget,
            start,
            limit: cap.min(room),
            capped: cap < room,
            past: false,
            reached: 0,
            buf: Vec::new(),
            buf_at: 0,
        }
    }

    /// Whether the find's end lies past its kind's cap.
    fn too_long(&self) -> bool {
        self.capped && self.past
    }

    fn get(&mut self, pos: u64, n: usize) -> Option<&[u8]> {
        let end = pos.checked_add(n as u64)?;
        if end > self.limit {
            self.past = true;
            return None;
        }
        if n as u64 > CHUNK {
            return None;
        }
        let have = pos >= self.buf_at && end <= self.buf_at + self.buf.len() as u64;
        if !have {
            // Stopped by the person: the measure ends and the search sees why.
            self.budget.tick().ok()?;
            let len = CHUNK.min(self.limit - pos).max(n as u64);
            self.buf = self.reader.read_lossy(self.start + pos, len as usize).data;
            self.buf_at = pos;
        }
        self.reached = self.reached.max(end);
        let at = (pos - self.buf_at) as usize;
        Some(&self.buf[at..at + n])
    }

    fn byte(&mut self, pos: u64) -> Option<u8> {
        self.get(pos, 1).map(|b| b[0])
    }

    fn be16(&mut self, pos: u64) -> Option<u64> {
        self.get(pos, 2)
            .map(|b| u64::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn be32(&mut self, pos: u64) -> Option<u64> {
        self.get(pos, 4)
            .map(|b| u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }

    fn le16(&mut self, pos: u64) -> Option<u64> {
        self.get(pos, 2)
            .map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])))
    }

    fn le32(&mut self, pos: u64) -> Option<u64> {
        self.get(pos, 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    fn le64(&mut self, pos: u64) -> Option<u64> {
        self.get(pos, 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")))
    }

    /// The next position at or after `from` holding `pattern`, scanning a piece at a time.
    fn find(&mut self, pattern: &[u8], from: u64) -> Option<u64> {
        let mut pos = from;
        loop {
            let n = (self.limit.checked_sub(pos)?).min(1 << 16) as usize;
            if n < pattern.len() {
                self.past = true;
                return None;
            }
            let piece = self.get(pos, n)?;
            if let Some(i) = piece.windows(pattern.len()).position(|w| w == pattern) {
                return Some(pos + i as u64);
            }
            pos += (n - pattern.len() + 1) as u64;
        }
    }
}

fn jpeg_end(s: &mut Stream) -> Option<u64> {
    let mut pos = 2u64;
    loop {
        if s.byte(pos)? != 0xFF {
            return None;
        }
        let mut marker = s.byte(pos + 1)?;
        while marker == 0xFF {
            pos += 1;
            marker = s.byte(pos + 1)?;
        }
        pos += 2;
        match marker {
            0xD9 => return Some(pos),
            0xD0..=0xD7 | 0x01 => {}
            0xD8 | 0x00 => return None,
            _ => {
                let len = s.be16(pos)?;
                if len < 2 {
                    return None;
                }
                pos += len;
                if marker == 0xDA {
                    // Entropy-coded data runs to the next marker that is not a stuffed
                    // zero or a restart.
                    loop {
                        pos = s.find(&[0xFF], pos)?;
                        match s.byte(pos + 1)? {
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

fn png_end(s: &mut Stream) -> Option<u64> {
    let mut pos = 8u64;
    loop {
        let len = s.be32(pos)?;
        let kind = s.get(pos + 4, 4)?.to_vec();
        if !kind.iter().all(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        pos += 12 + len;
        if kind == b"IEND" {
            return (pos <= s.limit).then_some(pos);
        }
    }
}

fn skip_sub_blocks(s: &mut Stream, mut pos: u64) -> Option<u64> {
    loop {
        let n = u64::from(s.byte(pos)?);
        pos += 1;
        if n == 0 {
            return Some(pos);
        }
        pos += n;
    }
}

fn gif_end(s: &mut Stream) -> Option<u64> {
    let flags = s.byte(10)?;
    let mut pos = 13u64;
    if flags & 0x80 != 0 {
        pos += 3 << ((flags & 7) + 1);
    }
    loop {
        match s.byte(pos)? {
            0x21 => pos = skip_sub_blocks(s, pos + 2)?,
            0x2C => {
                let flags = s.byte(pos + 9)?;
                pos += 10;
                if flags & 0x80 != 0 {
                    pos += 3 << ((flags & 7) + 1);
                }
                pos = skip_sub_blocks(s, pos + 1)?;
            }
            0x3B => return Some(pos + 1),
            _ => return None,
        }
    }
}

/// The last "%%EOF" before the cap or the next sector that starts another file.
fn pdf_end(s: &mut Stream, sector: u64) -> Option<u64> {
    let mut last = None;
    let mut pos = 5u64;
    while let Some(hit) = s.find(b"%%EOF", pos) {
        // Stop at a sector boundary between pos and hit that starts another file.
        let mut boundary = pos.div_ceil(sector) * sector;
        while boundary < hit {
            if s.get(boundary, 32).is_some_and(|b| header(b).is_some()) {
                return last;
            }
            boundary += sector;
        }
        let mut end = hit + 5;
        for _ in 0..2 {
            if matches!(s.byte(end), Some(b'\r' | b'\n')) {
                end += 1;
            }
        }
        last = Some(end);
        pos = hit + 5;
    }
    last
}

/// The end of central directory record whose directory sits just before it: the archive's
/// length and where that record is.
fn zip_end(s: &mut Stream) -> Option<(u64, u64)> {
    let mut pos = 30u64;
    loop {
        let p = s.find(b"PK\x05\x06", pos)?;
        let (cd_size, cd_off, comment) = (s.le32(p + 12)?, s.le32(p + 16)?, s.le16(p + 20)?);
        let zip64 = cd_off == 0xFFFF_FFFF && p >= 20 && s.get(p - 20, 4)? == b"PK\x06\x07";
        if cd_off + cd_size == p || zip64 {
            return Some((p + 22 + comment, p));
        }
        pos = p + 4;
    }
}

/// docx, xlsx, pptx, odt and the rest by the names inside.
fn zip_ext(s: &mut Stream, eocd: u64) -> &'static str {
    let (Some(cd_size), Some(cd_off)) = (s.le32(eocd + 12), s.le32(eocd + 16)) else {
        return "zip";
    };
    let mut names = Vec::new();
    let (mut pos, end) = (cd_off, (cd_off + cd_size).min(cd_off + (4 << 20)));
    while pos + 46 <= end && names.len() < 4096 {
        if s.get(pos, 4) != Some(b"PK\x01\x02") {
            break;
        }
        let (Some(n), Some(x), Some(c)) = (s.le16(pos + 28), s.le16(pos + 30), s.le16(pos + 32))
        else {
            break;
        };
        if let Some(name) = s.get(pos + 46, n as usize) {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
        pos += 46 + n + x + c;
    }
    let has = |prefix: &str| names.iter().any(|n| n.starts_with(prefix));
    if has("word/") {
        return "docx";
    }
    if has("xl/") {
        return "xlsx";
    }
    if has("ppt/") {
        return "pptx";
    }
    if names.first().is_some_and(|n| n == "mimetype") {
        let n = s.le16(26).unwrap_or(0);
        let x = s.le16(28).unwrap_or(0);
        let mime = s
            .get(30 + n + x, 46)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        for (key, ext) in [
            ("opendocument.text", "odt"),
            ("opendocument.spreadsheet", "ods"),
            ("opendocument.presentation", "odp"),
            ("epub+zip", "epub"),
        ] {
            if mime.contains(key) {
                return ext;
            }
        }
    }
    "zip"
}

/// ISO base media boxes, as far as they are boxes a file of this kind has at its top level.
fn mp4_end(s: &mut Stream) -> Option<u64> {
    const TOP: [&[u8; 4]; 16] = [
        b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"pdin", b"moof",
        b"mfra", b"styp", b"sidx", b"ssix", b"prft", b"emsg",
    ];
    let mut pos = 0u64;
    let mut media = false;
    while let Some(head) = s.get(pos, 8).map(|b| b.to_vec()) {
        let kind: [u8; 4] = head[4..8].try_into().expect("four bytes");
        if !TOP.contains(&&kind) {
            break;
        }
        let mut size = u64::from(u32::from_be_bytes(head[..4].try_into().expect("four")));
        if size == 1 {
            size = s
                .get(pos + 8, 8)
                .map(|b| u64::from_be_bytes(b.try_into().expect("eight")))?;
        }
        if size < 8 || pos.checked_add(size)? > s.limit {
            break;
        }
        media |= &kind == b"moov" || &kind == b"mdat" || &kind == b"moof";
        pos += size;
    }
    (media && pos > 0).then_some(pos)
}

fn mp4_ext(s: &mut Stream) -> &'static str {
    match s.get(8, 4) {
        Some(b"qt  ") => "mov",
        Some(b"M4A ") => "m4a",
        Some(b) if b.starts_with(b"3g") => "3gp",
        _ => "mp4",
    }
}

fn sqlite_end(s: &mut Stream) -> Option<u64> {
    let page = match s.be16(16)? {
        1 => 65536,
        n if n >= 512 && n.is_power_of_two() => n,
        _ => return None,
    };
    let (count, change, valid_for) = (s.be32(28)?, s.be32(24)?, s.be32(92)?);
    (count > 0 && change == valid_for).then_some(page * count)
}

fn vint(s: &mut Stream, pos: &mut u64) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = s.byte(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// RAR blocks up to the end-of-archive block, or as far as valid blocks go.
fn rar_end(s: &mut Stream) -> Option<u64> {
    if s.get(6, 2)? == [0x01, 0x00] {
        let mut pos = 8u64;
        loop {
            let mut at = pos + 4;
            let Some(size) = vint(s, &mut at) else {
                return Some(pos).filter(|p| *p > 8);
            };
            let body = at;
            let kind = vint(s, &mut at)?;
            let flags = vint(s, &mut at)?;
            if flags & 1 != 0 {
                vint(s, &mut at)?;
            }
            let data = if flags & 2 != 0 { vint(s, &mut at)? } else { 0 };
            if !(1..=5).contains(&kind) || size == 0 || size > 2 << 20 {
                return Some(pos).filter(|p| *p > 8);
            }
            pos = body.checked_add(size)?.checked_add(data)?;
            if kind == 5 {
                return Some(pos);
            }
        }
    }
    let mut pos = 7u64;
    loop {
        let (Some(kind), Some(flags), Some(size)) =
            (s.byte(pos + 2), s.le16(pos + 3), s.le16(pos + 5))
        else {
            return Some(pos).filter(|p| *p > 7);
        };
        if !(0x72..=0x7B).contains(&kind) || size < 7 {
            return Some(pos).filter(|p| *p > 7);
        }
        let add = if flags & 0x8000 != 0 {
            s.le32(pos + 7)?
        } else {
            0
        };
        pos += size + add;
        if kind == 0x7B {
            return Some(pos);
        }
    }
}

/// The length and file extension of a find of `kind` at the stream's start.
fn measure(s: &mut Stream, kind: Kind, sector: u64) -> Option<(u64, &'static str)> {
    match kind {
        Kind::Jpeg => jpeg_end(s).map(|n| (n, "jpg")),
        Kind::Png => png_end(s).map(|n| (n, "png")),
        Kind::Gif => gif_end(s).map(|n| (n, "gif")),
        Kind::Bmp => s.le32(2).map(|n| (n, "bmp")),
        Kind::Pdf => pdf_end(s, sector).map(|n| (n, "pdf")),
        Kind::Zip => {
            let (n, eocd) = zip_end(s)?;
            Some((n, zip_ext(s, eocd)))
        }
        Kind::Mp4 => {
            let n = mp4_end(s)?;
            Some((n, mp4_ext(s)))
        }
        Kind::Riff => {
            let n = s.le32(4)? + 8;
            let ext = match s.get(8, 4)? {
                b"AVI " => "avi",
                b"WAVE" => "wav",
                _ => "webp",
            };
            Some((n + n % 2, ext))
        }
        Kind::Sqlite => sqlite_end(s).map(|n| (n, "sqlite")),
        Kind::SevenZip => {
            let (off, size) = (s.le64(12)?, s.le64(20)?);
            Some((32u64.checked_add(off)?.checked_add(size)?, "7z"))
        }
        Kind::Rar => rar_end(s).map(|n| (n, "rar")),
    }
    .filter(|(n, _)| {
        s.past |= *n > s.limit;
        *n > 0 && *n <= s.limit
    })
}

/// Searches the whole source for files of the chosen kinds, calling `found` for each, within
/// a budget made from `LIMITS` with `bytes_for` the source; what was skipped and why is in
/// the result.
pub fn carve(
    reader: &mut Reader,
    kinds: &[Kind],
    cancel: &AtomicBool,
    progress: &Progress,
    found: &mut dyn FnMut(Carved),
) -> Carving {
    let limits = Limits {
        bytes: bytes_for(reader.len()),
        ..LIMITS
    };
    let mut budget = Budget::new(limits, Some(cancel));
    let mut carving = carve_within(reader, kinds, &mut budget, progress, found);
    carving.limit = budget
        .hit()
        .filter(|l| *l != Limit::Stopped)
        .and(budget.said());
    carving
}

/// The search itself, within `budget`: it ends at the first limit the budget reaches.
pub fn carve_within(
    reader: &mut Reader,
    kinds: &[Kind],
    budget: &mut Budget,
    progress: &Progress,
    found: &mut dyn FnMut(Carved),
) -> Carving {
    let mut carving = Carving::default();
    let len = reader.len();
    let sector = reader.sector().max(512);
    let step = 4 * CHUNK;
    progress.total.store(len, Ordering::Relaxed);
    let mut at = 0u64;
    'chunks: while at < len {
        if reader.gone().is_some() {
            break;
        }
        // A little extra so a header at the chunk's last sector can be checked whole.
        let n = (step + sector).min(len - at);
        if budget.read(n).is_err() {
            break;
        }
        let data = reader.read_lossy(at, n as usize).data;
        let body = step.min(len - at);
        let mut i = 0u64;
        while i < body {
            let slice = &data[i as usize..];
            if let Some(kind) = header(slice).filter(|k| kinds.contains(k)) {
                let start = at + i;
                let mut stream = Stream::new(reader, budget, start, kind.cap());
                let measured = measure(&mut stream, kind, sector);
                let (too_long, reached) = (stream.too_long(), stream.reached);
                if budget.hit().is_some() || budget.read(reached).is_err() {
                    break 'chunks;
                }
                if measured.is_none() && too_long {
                    carving.too_long[kind.index()] += 1;
                    progress.too_long[kind.index()].fetch_add(1, Ordering::Relaxed);
                }
                if let Some((size, ext)) = measured {
                    if budget.item().is_err() {
                        break 'chunks;
                    }
                    // The bad areas are sorted and merged: the first ending past the start.
                    let bad = reader.bad_areas();
                    let first = bad.partition_point(|b| b.end <= start);
                    let damaged = bad.get(first).is_some_and(|b| b.start < start + size);
                    found(Carved {
                        kind,
                        ext,
                        offset: start,
                        len: size,
                        damaged,
                    });
                    progress.counts[kind.index()].fetch_add(1, Ordering::Relaxed);
                    // Carry on after the file, at the next sector.
                    let next = (start + size).div_ceil(sector) * sector;
                    if next >= at + body {
                        at = next;
                        progress.done.store(at.min(len), Ordering::Relaxed);
                        continue 'chunks;
                    }
                    i = next - at;
                    continue;
                }
            }
            i += sector;
        }
        at += body;
        progress.done.store(at, Ordering::Relaxed);
    }
    carving
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{BlockSource, MemDisk, ReadError};

    /// A source of `len` zero bytes after `head`.
    struct Sparse(Vec<u8>, u64);

    impl BlockSource for Sparse {
        fn len(&self) -> u64 {
            self.1
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            buf.fill(0);
            let head = self.0.len() as u64;
            if offset < head {
                let end = head.min(offset + buf.len() as u64);
                buf[..(end - offset) as usize]
                    .copy_from_slice(&self.0[offset as usize..end as usize]);
            }
            Ok(())
        }
        fn describe(&self) -> String {
            "sparse test source".into()
        }
    }

    fn bmp(size: u32) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..2].copy_from_slice(b"BM");
        b[2..6].copy_from_slice(&size.to_le_bytes());
        b[10..14].copy_from_slice(&54u32.to_le_bytes());
        b[14..18].copy_from_slice(&40u32.to_le_bytes());
        b
    }

    fn search(source: Box<dyn BlockSource>, limits: Limits) -> (Carving, u64, Budget<'static>) {
        let mut reader = Reader::new(source);
        let mut budget = Budget::new(limits, None);
        let mut found = 0u64;
        let carving = carve_within(
            &mut reader,
            &Kind::ALL,
            &mut budget,
            &Progress::default(),
            &mut |_| found += 1,
        );
        (carving, found, budget)
    }

    #[test]
    fn a_hostile_source_stops_within_its_budget() {
        let started = std::time::Instant::now();
        // A PDF start in every sector and no end anywhere: each start sends the measure to
        // the end of the source, so without a limit the search reads the source once per
        // sector.
        let len = 8 << 20;
        let disk: Vec<u8> = (0..len / 512)
            .flat_map(|_| start(512, &[(0, b"%PDF-1.4\n")]))
            .collect();
        let limits = Limits {
            bytes: 3 * len as u64,
            ..LIMITS
        };
        let (carving, found, budget) = search(Box::new(MemDisk::new(disk)), limits);
        assert_eq!((found, budget.hit()), (0, Some(Limit::Bytes)));
        assert!(budget.spent().bytes <= 3 * len as u64);
        assert_eq!(
            budget.said().unwrap(),
            "The search for files by type stopped at its limit of 25.2 MB read."
        );
        assert_eq!(carving.too_long, [0; 11]);
        assert_eq!(bytes_for(len as u64), 3 * len as u64 + (8 << 30));

        // A file in every sector: the count of files found stops it.
        let disk: Vec<u8> = (0..2048).flat_map(|_| bmp(512)).collect();
        let few = Limits {
            count: 100,
            ..LIMITS
        };
        let (_, found, budget) = search(Box::new(MemDisk::new(disk)), few);
        assert_eq!((found, budget.hit()), (100, Some(Limit::Count)));
        assert_eq!(
            budget.said().unwrap(),
            "The search for files by type stopped at its limit of 100 files found."
        );

        // A start whose end lies past its kind's cap is counted and said, not skipped
        // silently.
        let cap = Kind::Bmp.cap();
        let source = Sparse(bmp(cap as u32 + 1), cap + (8 << 20));
        let (carving, found, budget) = search(Box::new(source), LIMITS);
        assert_eq!((found, budget.hit()), (0, None));
        assert_eq!(carving.too_long[Kind::Bmp.index()], 1);
        assert_eq!(
            carving.notes(),
            vec!["1 BMP start whose end lies past the 536.9 MB this search takes was skipped."]
        );

        // Stopped by the person: nothing read, and no limit said.
        let stop = AtomicBool::new(true);
        let mut reader = Reader::new(Box::new(MemDisk::new(bmp(512))));
        let carving = carve(
            &mut reader,
            &Kind::ALL,
            &stop,
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(carving, Carving::default());
        assert!(started.elapsed() < std::time::Duration::from_secs(60));
    }

    /// A file of `len` bytes holding `parts` at their offsets and 0x5A elsewhere.
    fn start(len: usize, parts: &[(usize, &[u8])]) -> Vec<u8> {
        let mut b = vec![0x5A; len];
        for (at, bytes) in parts {
            b[*at..*at + bytes.len()].copy_from_slice(bytes);
        }
        b
    }

    /// What the check says of `bytes` as a file named `name`, after checking it asked for
    /// at most one read, no longer than `HEAD`: from byte 0, or for an ISO its 2 KiB
    /// descriptor at 32 KiB.
    fn judge(name: &str, bytes: &[u8]) -> Option<Start> {
        let expect = Expect::of(name).unwrap_or_else(|| panic!("{name} has no check"));
        let mut reads = Vec::new();
        let start = expect.check(bytes.len() as u64, &mut |at, n| {
            reads.push((at, n));
            bytes
                .get(at as usize..at as usize + n)
                .map(<[u8]>::to_vec)
                .ok_or(Missing::Unwritten)
        });
        let allowed = |&(at, n): &(u64, usize)| match expect {
            Expect::Iso => (at, n) == ISO_DESCRIPTOR,
            _ => at == 0 && n <= HEAD,
        };
        assert!(
            reads.len() <= 1 && reads.iter().all(allowed),
            "{name} read {reads:?}"
        );
        start
    }

    fn box_at(size: u32, kind: &[u8; 4]) -> Vec<u8> {
        let mut b = size.to_be_bytes().to_vec();
        b.extend_from_slice(kind);
        b
    }

    /// The guard: every legitimate start of each type passes, so a sound file is never
    /// called overwritten; junk where the start should be fails, and only a type with a
    /// fixed start at byte 0 is called overwritten for it.
    #[test]
    fn every_valid_start_of_each_type_passes_its_check() {
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("a.jpg", start(16, &[(0, &[0xFF, 0xD8, 0xFF, 0xE0])])),
            ("a.jpeg", start(16, &[(0, &[0xFF, 0xD8, 0xFF, 0xE1])])),
            ("a.jpe", start(16, &[(0, &[0xFF, 0xD8, 0xFF, 0xDB])])),
            ("a.jpg", start(16, &[(0, &[0xFF, 0xD8, 0xFF, 0xFF, 0xC0])])),
            ("a.jpg", start(16, &[(0, &[0xFF, 0xD8, 0xFF, 0xDD])])),
            ("a.png", start(16, &[(0, b"\x89PNG\r\n\x1a\n")])),
            ("a.gif", start(16, &[(0, b"GIF87a")])),
            ("a.gif", start(16, &[(0, b"GIF89a")])),
            ("a.bmp", start(16, &[(0, b"BM")])),
            ("a.bmp", start(16, &[(0, b"BA")])),
            ("a.pdf", start(1024, &[(0, b"%PDF-1.7")])),
            ("a.pdf", start(1024, &[(0, b"\xEF\xBB\xBF%PDF-1.4")])),
            ("a.pdf", start(1024, &[(1000, b"%PDF-1.4")])),
            ("a.wav", start(16, &[(0, b"RIFF"), (8, b"WAVE")])),
            (
                "a.wav",
                start(16, &[(0, b"RF64"), (4, &[0xFF; 4]), (8, b"WAVE")]),
            ),
            ("a.wav", start(16, &[(0, b"BW64"), (8, b"WAVE")])),
            ("a.wav", start(16, &[(0, b"RIFX"), (8, b"WAVE")])),
            ("a.avi", start(16, &[(0, b"RIFF"), (8, b"AVI ")])),
            ("a.webp", start(16, &[(0, b"RIFF"), (8, b"WEBP")])),
            (
                "a.7z",
                start(16, &[(0, &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C])]),
            ),
            ("a.rar", start(16, &[(0, b"Rar!\x1A\x07\x00")])),
            ("a.rar", start(16, &[(0, b"Rar!\x1A\x07\x01\x00")])),
            ("a.rar", start(16, &[(0, b"RE~^")])),
            ("VMware.x86_64.ISO", start(0x8800, &[(0x8001, b"CD001")])),
            ("a.iso", start(0x8800, &[(0x8001, b"BEA01")])),
            // Zip documents: an entry at the start or after leading bytes, a spanning
            // marker, a central directory or end record within the first 4 KiB, and an
            // empty archive.
            ("a.docx", start(64 << 10, &[(0, b"PK\x03\x04")])),
            ("a.xlsx", start(64 << 10, &[(0, b"PK\x07\x08PK\x03\x04")])),
            ("a.pptx", start(64 << 10, &[(1000, b"PK\x03\x04")])),
            ("a.odt", start(64 << 10, &[(HEAD - 4, b"PK\x01\x02")])),
            ("a.ods", start(3000, &[(2978, b"PK\x05\x06")])),
            ("a.epub", start(22, &[(0, b"PK\x05\x06")])),
        ];
        // MP4 and QuickTime: each first box type seen, with sizes that fit the file.
        for kind in BOXES_FIRST {
            cases.push(("a.mp4", start(8192, &[(0, &box_at(4096, kind))])));
        }
        cases.push(("a.mov", start(8192, &[(0, &box_at(0, b"mdat"))])));
        let mut large = box_at(1, b"mdat");
        large.extend_from_slice(&4096u64.to_be_bytes());
        cases.push(("a.3gp", start(8192, &[(0, &large)])));
        for name in ["a.m4v", "a.m4a"] {
            cases.push((name, start(8192, &[(0, &box_at(32, b"ftyp"))])));
        }
        for (name, bytes) in &cases {
            assert_eq!(
                judge(name, bytes),
                Some(Start::Fits),
                "{name}: {:02x?}",
                &bytes[..8]
            );
            let junk = vec![0xA5; bytes.len()];
            let want = match Expect::of(name).unwrap() {
                Expect::Pdf => Start::Unlike("a PDF document"),
                Expect::Office => Start::Unlike("a zip document"),
                _ => Start::Mismatch,
            };
            assert_eq!(judge(name, &junk), Some(want), "{name} passes junk");
            let need = Expect::of(name).unwrap().need();
            assert_eq!(judge(name, &bytes[..need - 1]), None, "{name} short");
        }
        // Types whose start can legitimately be anything are never judged by it.
        for name in [
            "bundle.zip",
            "app.jar",
            "contacts.sqlite",
            "notes.txt",
            "README",
        ] {
            assert_eq!(Expect::of(name), None, "{name}");
        }
        // Box headers that cannot be a first box: an unknown type, a size under 8, a box
        // larger than the file.
        for bytes in [
            start(8192, &[(0, &[0, 0, 0x10, 0, b'A', b'B', b'C', b'D'])]),
            start(8192, &[(0, &box_at(5, b"ftyp"))]),
            start(8192, &[(0, &box_at(9000, b"moov"))]),
        ] {
            assert_eq!(
                judge("a.mp4", &bytes),
                Some(Start::Mismatch),
                "{:02x?}",
                &bytes[..8]
            );
        }
        // A zip document whose first entry lies past 4 KiB only may be overwritten: its
        // end is never read. One whose start cannot be read is not judged by it.
        let late = start(200 << 10, &[(70 << 10, b"PK\x03\x04")]);
        assert_eq!(
            judge("a.docx", &late),
            Some(Start::Unlike("a zip document"))
        );
        assert_eq!(
            Expect::Office.check(200 << 10, &mut |_, _| Err(Missing::Unreadable)),
            Some(Start::Unread)
        );
        assert_eq!(
            Expect::Office.check(200 << 10, &mut |_, _| Err(Missing::Unwritten)),
            None
        );
    }
}
