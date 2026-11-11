//! Checking recovered files: a folder of recovered or copied files is walked and every file
//! is sorted into good, damaged or not checked, with a one-line reason, by its contents (its
//! first bytes), never by its name alone. Each format's structure is walked from start to
//! end with every length kept in bounds, and checksums are checked where the format has
//! them. Pictures are not decoded.
//!
//! Every byte read is treated as hostile: no panics, no allocation sized by a field in the
//! file, and each file's check runs within a budget (`LIMITS`, with the time and the bytes
//! it may unpack set by the options) whose limit, when reached, is the file's reason for
//! being not checked. Files are
//! read through ordinary handles, shared, and never written; the one thing written is the
//! report, through `dest::Guard` into the folder checked.
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::dest::Guard;
use super::ledger::{files, Ledger};
use crate::budget::{Budget, Limit, Limits};
use crate::tools::drives::bytes_text;

mod media;
mod pdf;
mod say;
mod zip;

/// How a file came out of the check. Ordered damaged first, the order the list shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Verdict {
    Damaged,
    NotChecked,
    Good,
}

impl Verdict {
    /// For people.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Damaged => "Damaged",
            Verdict::NotChecked => "Not checked",
            Verdict::Good => "Good",
        }
    }
}

/// One file's result: its verdict, what its contents are, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Checked {
    pub verdict: Verdict,
    /// What the contents are, for people: "JPEG image", "Word document", "unknown".
    pub kind: &'static str,
    pub reason: String,
}

/// What one file's check may spend, by default; `Options::limits` sets its time and bytes.
/// Its parts are the segments, chunks, blocks, boxes, image directories and their values,
/// archive entries and PDF objects it reads: 16,777,216 covers the largest real files with
/// room. Its bytes are what it takes out of the file to check: the data it unpacks (ZIP
/// entries, PDF streams) and the stored ZIP entries it reads for their checksums, 2 GB by
/// default. It holds at most 512 MiB for what it keeps (an archive's entries and names, a
/// PDF's index, offsets still to visit), follows boxes 16 deep, and takes 60 seconds a file
/// by default. A limit reached makes the file "not checked", saying which.
pub const LIMITS: Limits = Limits {
    what: "the check of the file",
    unit: "parts",
    count: 1 << 24,
    bytes: 2_000_000_000,
    memory: 512 << 20,
    depth: 16,
    nested: "boxes",
    time: Some(Duration::from_secs(60)),
};

/// Something read by offset: a file, or bytes in memory in tests.
pub trait Source {
    fn len(&self) -> u64;
    /// Fills `buf` from `pos`; the range is inside `len`.
    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A file opened to be checked, with the length read when it was opened: a length that
/// cannot be read makes the file "not checked", never an empty file.
pub struct OpenFile {
    file: File,
    len: u64,
}

impl OpenFile {
    pub fn new(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl Source for OpenFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            match self.file.seek_read(&mut buf[done..], pos + done as u64)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => done += n,
            }
        }
        Ok(())
    }
}

/// Bytes in memory as a source.
pub struct Mem<'b>(pub &'b [u8]);

impl Source for Mem<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(pos).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let piece = at
            .checked_add(buf.len())
            .and_then(|end| self.0.get(at..end))
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(piece);
        Ok(())
    }
}

/// Why a check ended without a verdict of good.
#[derive(Debug)]
enum Fault {
    /// The file is damaged, and this says how.
    Damaged(String),
    /// The check reached a limit of its budget.
    Limit(Limit),
    /// Something this check does not read, or more of it than it reads: why.
    Unsupported(String),
}

impl From<Limit> for Fault {
    fn from(limit: Limit) -> Self {
        Fault::Limit(limit)
    }
}

type Res<T> = Result<T, Fault>;

fn damaged<T>(why: impl Into<String>) -> Res<T> {
    Err(Fault::Damaged(why.into()))
}

fn unsupported<T>(why: impl Into<String>) -> Res<T> {
    Err(Fault::Unsupported(why.into()))
}

/// A sound file: what it is and anything worth saying about it.
struct Good {
    kind: &'static str,
    note: String,
}

fn good(kind: &'static str, note: impl Into<String>) -> Res<Good> {
    Ok(Good {
        kind,
        note: note.into(),
    })
}

/// The most read at once, and the largest piece a check asks for.
const WINDOW: usize = 1 << 20;
/// A run of zero bytes at least this long, from a 512-byte boundary, inside compressed data
/// is taken for an unreadable part written as zeros, as the recovery tools write them.
const ZERO_RUN: u64 = 4096;

/// Reads a file by offset through a window, within the check's budget.
struct Data<'a, 'c> {
    src: &'a mut dyn Source,
    len: u64,
    buf: Vec<u8>,
    buf_at: u64,
    budget: &'a mut Budget<'c>,
    /// The furthest byte read, for a check stopped by its limits.
    reached: u64,
}

/// The window goes with the reader, and its charge with it.
impl Drop for Data<'_, '_> {
    fn drop(&mut self) {
        self.budget.free(self.buf.len() as u64);
    }
}

impl<'a, 'c> Data<'a, 'c> {
    fn new(src: &'a mut dyn Source, budget: &'a mut Budget<'c>) -> Self {
        let len = src.len();
        Self {
            src,
            len,
            buf: Vec::new(),
            buf_at: 0,
            budget,
            reached: 0,
        }
    }

    /// Ends the check when it is stopped or out of time.
    fn tick(&mut self) -> Res<()> {
        Ok(self.budget.tick()?)
    }

    /// Counts one part of the file read.
    fn item(&mut self) -> Res<()> {
        Ok(self.budget.item()?)
    }

    /// Counts `n` bytes more held for the check.
    fn hold(&mut self, n: u64) -> Res<()> {
        Ok(self.budget.hold(n)?)
    }

    fn free(&mut self, n: u64) {
        self.budget.free(n);
    }

    /// Counts `n` bytes taken out of the file to check: unpacked, or read for a checksum.
    fn taken(&mut self, n: u64) -> Res<()> {
        Ok(self.budget.read(n)?)
    }

    /// Whether `n` bytes from `pos` are inside the file.
    fn has(&self, pos: u64, n: u64) -> bool {
        pos.checked_add(n).is_some_and(|end| end <= self.len)
    }

    /// `n` bytes from `pos`; a range past the end says the file is cut short inside `what`.
    fn get(&mut self, pos: u64, n: usize, what: &str) -> Res<&[u8]> {
        let Some(end) = pos.checked_add(n as u64).filter(|end| *end <= self.len) else {
            return damaged(format!("cut short: the file ends inside {what}"));
        };
        if n > WINDOW {
            return unsupported(format!("{what} is larger than this check reads"));
        }
        let held = pos >= self.buf_at && end <= self.buf_at + self.buf.len() as u64;
        if !held {
            self.tick()?;
            let want = (WINDOW as u64).min(self.len - pos).max(n as u64) as usize;
            // The window is charged to the check's memory before it grows, and freed with
            // the check's reader.
            self.budget.grow(&mut self.buf, want)?;
            if let Err(e) = self.src.read_at(pos, &mut self.buf) {
                self.budget.free(self.buf.len() as u64);
                self.buf.clear();
                return damaged(format!("it could not be read at byte {pos} ({e})"));
            }
            self.buf_at = pos;
        }
        self.reached = self.reached.max(end);
        let at = (pos - self.buf_at) as usize;
        Ok(&self.buf[at..at + n])
    }

    fn byte(&mut self, pos: u64, what: &str) -> Res<u8> {
        Ok(self.get(pos, 1, what)?[0])
    }

    fn be16(&mut self, pos: u64, what: &str) -> Res<u64> {
        let b = self.get(pos, 2, what)?;
        Ok(u64::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn be32(&mut self, pos: u64, what: &str) -> Res<u64> {
        let b = self.get(pos, 4, what)?;
        Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }

    fn be64(&mut self, pos: u64, what: &str) -> Res<u64> {
        let b = self.get(pos, 8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn le16(&mut self, pos: u64, what: &str) -> Res<u64> {
        let b = self.get(pos, 2, what)?;
        Ok(u64::from(u16::from_le_bytes([b[0], b[1]])))
    }

    fn le32(&mut self, pos: u64, what: &str) -> Res<u64> {
        let b = self.get(pos, 4, what)?;
        Ok(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    fn le64(&mut self, pos: u64, what: &str) -> Res<u64> {
        let b = self.get(pos, 8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    /// Up to `n` bytes from `pos`, fewer at the end of the file, copied.
    fn upto(&mut self, pos: u64, n: usize) -> Res<Vec<u8>> {
        if pos >= self.len {
            return Ok(Vec::new());
        }
        let n = (n as u64).min(self.len.saturating_sub(pos)) as usize;
        Ok(self.get(pos, n, "")?.to_vec())
    }

    /// As `upto`, for a size the file gives: the copy is charged to the check's memory
    /// before it is made, and left charged, so the caller frees its length.
    fn upto_held(&mut self, pos: u64, n: usize) -> Res<Vec<u8>> {
        let n = if pos >= self.len {
            0
        } else {
            (n as u64).min(self.len - pos) as usize
        };
        self.hold(n as u64)?;
        match self.upto(pos, n) {
            Ok(v) => Ok(v),
            Err(f) => {
                self.free(n as u64);
                Err(f)
            }
        }
    }

    /// An empty list with room for `n` items, made once its memory is charged; the caller
    /// frees it.
    fn room<T>(&mut self, n: usize) -> Res<Vec<T>> {
        Ok(self.budget.room(n)?)
    }

    /// The first `pattern` at or after `from` and before `to`.
    fn find(&mut self, pattern: &[u8], from: u64, to: u64) -> Res<Option<u64>> {
        let to = to.min(self.len);
        let mut pos = from;
        while pos < to {
            let n = (to - pos).min(WINDOW as u64) as usize;
            if n < pattern.len() {
                return Ok(None);
            }
            let piece = self.get(pos, n, "")?;
            if let Some(i) = piece.windows(pattern.len()).position(|w| w == pattern) {
                return Ok(Some(pos + i as u64));
            }
            pos += (n - pattern.len() + 1) as u64;
        }
        Ok(None)
    }

    /// Where a run of `ZERO_RUN` zero bytes from a 512-byte boundary starts between `from`
    /// and `to`, if one does.
    fn zero_run(&mut self, from: u64, to: u64) -> Res<Option<u64>> {
        let to = to.min(self.len);
        let mut run: Option<u64> = None;
        let mut pos = from;
        while pos < to {
            let n = (to - pos).min(WINDOW as u64) as usize;
            let piece = self.get(pos, n, "")?;
            for (i, &b) in piece.iter().enumerate() {
                if b != 0 {
                    run = None;
                    continue;
                }
                let at = pos + i as u64;
                let start = *run.get_or_insert(at);
                let aligned = start.div_ceil(512) * 512;
                if at + 1 >= aligned + ZERO_RUN {
                    return Ok(Some(aligned));
                }
            }
            pos += n as u64;
        }
        Ok(None)
    }

    /// Decompresses `len` bytes of deflate data (zlib-wrapped when `zlib`) from `start`,
    /// to its proper end, never more than `max_out` bytes out. Keeps up to `keep.1` bytes
    /// of the output in `keep.0` when asked.
    fn inflate(
        &mut self,
        start: u64,
        len: u64,
        zlib: bool,
        max_out: u64,
        mut keep: Option<(&mut Vec<u8>, usize)>,
    ) -> Res<Inflated> {
        let end = start.saturating_add(len).min(self.len);
        let mut z = flate2::Decompress::new(zlib);
        let mut out = vec![0u8; 1 << 16];
        let mut hasher = crc32fast::Hasher::new();
        let mut pos = start;
        let mut total = 0u64;
        let ended = loop {
            self.tick()?;
            let n = (end.saturating_sub(pos)).min(1 << 16) as usize;
            let (before_in, before_out) = (z.total_in(), z.total_out());
            let status = {
                let input: &[u8] = if n == 0 {
                    &[]
                } else {
                    self.get(pos, n, "its compressed data")?
                };
                z.decompress(input, &mut out, flate2::FlushDecompress::None)
            };
            let used = z.total_in() - before_in;
            let made = (z.total_out() - before_out) as usize;
            pos += used;
            total += made as u64;
            if total > max_out {
                return damaged("it decompresses to more than its stated size");
            }
            self.taken(made as u64)?;
            hasher.update(&out[..made]);
            if let Some((kept, cap)) = keep.as_mut() {
                // What is kept is charged before it grows, and left charged.
                let room = cap.saturating_sub(kept.len()).min(made);
                self.budget.hold(room as u64)?;
                kept.extend_from_slice(&out[..room]);
            }
            match status {
                Ok(flate2::Status::StreamEnd) => break true,
                Ok(_) if used == 0 && made == 0 => break false,
                Ok(_) => {}
                Err(e) => {
                    return damaged(format!("its compressed data is corrupt ({e})"));
                }
            }
        };
        if !ended {
            return damaged("its compressed data stops before its end");
        }
        Ok(Inflated {
            size: total,
            crc: hasher.finalize(),
        })
    }

    /// The CRC-32 of `len` bytes from `start`.
    fn crc(&mut self, start: u64, len: u64, what: &str) -> Res<u32> {
        let mut hasher = crc32fast::Hasher::new();
        let mut pos = start;
        let end = start
            .checked_add(len)
            .ok_or_else(|| Fault::Damaged(format!("cut short: the file ends inside {what}")))?;
        while pos < end {
            let n = (end - pos).min(WINDOW as u64) as usize;
            hasher.update(self.get(pos, n, what)?);
            pos += n as u64;
        }
        Ok(hasher.finalize())
    }
}

struct Inflated {
    size: u64,
    crc: u32,
}

/// What a file's contents are, from its first bytes, or what its name says it should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Jpeg,
    Png,
    Gif,
    Bmp,
    Tiff,
    Pdf,
    Zip,
    Iso,
    Mp3,
    Riff,
    Rtf,
    Text,
    /// A type found but not checked: its name for people.
    Other(&'static str),
}

impl Type {
    /// For people, with an article: "a JPEG image".
    pub fn label(self) -> &'static str {
        match self {
            Type::Jpeg => "a JPEG image",
            Type::Png => "a PNG image",
            Type::Gif => "a GIF image",
            Type::Bmp => "a BMP image",
            Type::Tiff => "a TIFF image or camera raw photo",
            Type::Pdf => "a PDF document",
            Type::Zip => "a ZIP archive or Office document",
            Type::Iso => "an MP4, MOV or HEIC file",
            Type::Mp3 => "an MP3 file",
            Type::Riff => "a WAV, AVI or WebP file",
            Type::Rtf => "an RTF document",
            Type::Text => "text",
            Type::Other(label) => label,
        }
    }

    /// The kind column for a file of this type that was not checked further.
    fn kind(self) -> &'static str {
        match self {
            Type::Jpeg => "JPEG image",
            Type::Png => "PNG image",
            Type::Gif => "GIF image",
            Type::Bmp => "BMP image",
            Type::Tiff => "TIFF image",
            Type::Pdf => "PDF document",
            Type::Zip => "ZIP archive",
            Type::Iso => "MP4 or MOV",
            Type::Mp3 => "MP3 audio",
            Type::Riff => "RIFF file",
            Type::Rtf => "RTF document",
            Type::Text => "text",
            Type::Other(label) => label.trim_start_matches("an ").trim_start_matches("a "),
        }
    }
}

/// The type a file's extension says, for the types this check reads.
pub fn type_of_extension(ext: &str) -> Option<Type> {
    let ext = ext.to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" | "jpe" | "jfif" => Type::Jpeg,
        "png" => Type::Png,
        "gif" => Type::Gif,
        "bmp" | "dib" => Type::Bmp,
        "tif" | "tiff" | "cr2" | "nef" | "arw" | "dng" | "orf" | "pef" | "srw" | "sr2" => {
            Type::Tiff
        }
        "pdf" => Type::Pdf,
        "zip" | "docx" | "docm" | "dotx" | "dotm" | "xlsx" | "xlsm" | "xltx" | "xltm" | "pptx"
        | "pptm" | "potx" | "ppsx" | "ppsm" | "vsdx" | "odt" | "ods" | "odp" | "odg" | "ott"
        | "ots" | "otp" | "epub" | "xps" | "oxps" | "jar" | "apk" => Type::Zip,
        "mp4" | "m4v" | "m4a" | "mov" | "qt" | "3gp" | "3g2" | "heic" | "heif" | "avif" | "cr3" => {
            Type::Iso
        }
        "mp3" => Type::Mp3,
        "wav" | "avi" | "webp" => Type::Riff,
        "rtf" => Type::Rtf,
        "txt" | "csv" | "tsv" | "log" | "md" | "ini" | "cfg" | "xml" | "html" | "htm" | "json"
        | "srt" | "yaml" | "yml" | "css" | "js" | "vcf" | "ics" => Type::Text,
        _ => return None,
    })
}

/// How many bytes of a file's start `detect` looks at.
pub const HEAD: usize = 64 * 1024;

/// The type a file's first bytes show, if any. `head` is up to `HEAD` bytes of its start.
pub fn detect(head: &[u8]) -> Option<Type> {
    let starts = |magic: &[u8]| head.starts_with(magic);
    let at = |pos: usize, magic: &[u8]| head.get(pos..pos + magic.len()) == Some(magic);
    if head.len() >= 3 && head[..3] == [0xFF, 0xD8, 0xFF] {
        return Some(Type::Jpeg);
    }
    if starts(b"\x89PNG\r\n\x1a\n") {
        return Some(Type::Png);
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Some(Type::Gif);
    }
    if starts(b"BM") && head.len() >= 18 {
        let dib = u32::from_le_bytes([head[14], head[15], head[16], head[17]]);
        if [12, 16, 40, 52, 56, 64, 108, 124].contains(&dib) {
            return Some(Type::Bmp);
        }
    }
    if starts(b"II*\0") || starts(b"MM\0*") {
        return Some(Type::Tiff);
    }
    if starts(b"II+\0") || starts(b"MM\0+") {
        return Some(Type::Other("a BigTIFF image"));
    }
    if head
        .get(..head.len().min(1024))
        .is_some_and(|h| h.windows(5).any(|w| w == b"%PDF-"))
    {
        return Some(Type::Pdf);
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        return Some(Type::Zip);
    }
    if at(4, b"ftyp") {
        return Some(Type::Iso);
    }
    if head.len() >= 16
        && [&b"moov"[..], b"mdat", b"wide", b"free", b"skip", b"pnot"]
            .iter()
            .any(|t| at(4, t))
        && head[..4] != [0, 0, 0, 0]
    {
        return Some(Type::Iso);
    }
    if starts(b"RIFF") && head.len() >= 12 {
        return Some(match &head[8..12] {
            b"WAVE" | b"AVI " | b"WEBP" => Type::Riff,
            _ => Type::Other("a RIFF file"),
        });
    }
    if starts(b"{\\rtf") {
        return Some(Type::Rtf);
    }
    if starts(b"ID3") || media::mp3_starts(head) {
        return Some(Type::Mp3);
    }
    let others: [(&[u8], &'static str); 14] = [
        (b"7z\xBC\xAF\x27\x1C", "a 7z archive"),
        (b"Rar!\x1A\x07", "a RAR archive"),
        (b"\x1F\x8B", "a gzip archive"),
        (b"SQLite format 3\0", "an SQLite database"),
        (
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
            "an older Office document or Outlook message",
        ),
        (b"MZ", "a Windows program"),
        (b"fLaC", "a FLAC audio file"),
        (b"OggS", "an Ogg audio or video file"),
        (b"\x1A\x45\xDF\xA3", "an MKV or WebM video"),
        (b"8BPS", "a Photoshop image"),
        (b"FUJIFILMCCD-RAW", "a Fujifilm raw photo"),
        (b"FORM", "an AIFF audio file"),
        (b"\x00\x00\x01\x00", "an icon"),
        (b"!BDN", "an Outlook data file"),
    ];
    if let Some((_, label)) = others.iter().find(|(magic, _)| starts(magic)) {
        return Some(Type::Other(label));
    }
    if at(0x8001, b"CD001") {
        return Some(Type::Other("a disc image (ISO)"));
    }
    None
}

/// Whether a type found by content is the one a name says, for the mismatch note.
fn same(named: Type, found: Type) -> bool {
    named == found || (named == Type::Text && found == Type::Rtf)
}

/// How a file that is not what its name says starts, for people.
fn how_it_starts(head: &[u8]) -> String {
    let zeros = head.iter().take_while(|b| **b == 0).count();
    if zeros == head.len() {
        return say::all_zeros(zeros as u64, zeros < HEAD);
    }
    if zeros >= 16 {
        return format!("it starts with {zeros} zero bytes");
    }
    let start = &head[..head.len().min(24)];
    if start.len() >= 8 && start.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        return format!(
            "it starts with the text \"{}\"",
            String::from_utf8_lossy(start)
        );
    }
    let hex: Vec<String> = head.iter().take(8).map(|b| format!("{b:02X}")).collect();
    format!("it starts with the bytes {}", hex.join(" "))
}

/// Checks one file within `budget` (made from `LIMITS` or `Options::limits`). `name` is its
/// file name, for what its extension says. A limit of the budget reached makes it not
/// checked, with the limit and how far it was read as its reason.
pub fn check(src: &mut dyn Source, name: &str, budget: &mut Budget) -> Checked {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let named = type_of_extension(&ext);
    let len = src.len();
    let mut d = Data::new(src, budget);
    if len == 0 {
        return match named {
            Some(t) if t != Type::Text => Checked {
                verdict: Verdict::Damaged,
                kind: t.kind(),
                reason: "it is empty: 0 bytes".into(),
            },
            _ => Checked {
                verdict: Verdict::NotChecked,
                kind: "empty",
                reason: "it is empty: 0 bytes".into(),
            },
        };
    }
    let head = match d.upto(0, HEAD) {
        Ok(head) => head,
        Err(fault) => return verdict_of(fault, "unknown", String::new(), &d),
    };
    let found = detect(&head);
    let checked_as = match (found, named) {
        (Some(t), _) => t,
        (None, Some(Type::Text)) => Type::Text,
        (None, Some(Type::Mp3)) if media::mp3_sync(&head).is_some() => Type::Mp3,
        (None, Some(t)) => {
            return Checked {
                verdict: Verdict::Damaged,
                kind: t.kind(),
                reason: format!(
                    "named .{ext}, but it does not start like {}: {}",
                    t.label(),
                    how_it_starts(&head)
                ),
            }
        }
        (None, None) => {
            return Checked {
                verdict: Verdict::NotChecked,
                kind: "unknown",
                reason: "its type is not one this check reads".into(),
            }
        }
    };
    let mismatch = match (named, found) {
        (Some(n), Some(f)) if !same(n, f) => {
            format!("named .{ext}, but it holds {}; ", f.label())
        }
        _ => String::new(),
    };
    let result = match checked_as {
        Type::Jpeg => media::jpeg(&mut d),
        Type::Png => media::png(&mut d),
        Type::Gif => media::gif(&mut d),
        Type::Bmp => media::bmp(&mut d),
        Type::Tiff => media::tiff(&mut d),
        Type::Pdf => pdf::check(&mut d),
        Type::Zip => zip::check(&mut d, &ext),
        Type::Iso => media::iso(&mut d),
        Type::Mp3 => media::mp3(&mut d),
        Type::Riff => media::riff(&mut d),
        Type::Rtf => media::text(&mut d, "RTF document", Some(b"}")),
        Type::Text => match ext.as_str() {
            "xml" => media::text(&mut d, "XML file", Some(b">")),
            "html" | "htm" => media::text(&mut d, "web page", Some(b">")),
            "json" => media::text(&mut d, "JSON file", Some(b"}]")),
            _ => media::text(&mut d, "text", None),
        },
        Type::Other(label) => {
            return Checked {
                verdict: Verdict::NotChecked,
                kind: checked_as.kind(),
                reason: format!("{mismatch}{label} is a kind of file this check does not read"),
            }
        }
    };
    match result {
        Ok(g) => Checked {
            verdict: Verdict::Good,
            kind: g.kind,
            reason: format!(
                "{mismatch}{}",
                if g.note.is_empty() {
                    "its structure is whole".into()
                } else {
                    g.note
                }
            ),
        },
        Err(fault) => verdict_of(fault, checked_as.kind(), mismatch, &d),
    }
}

fn verdict_of(fault: Fault, kind: &'static str, mismatch: String, d: &Data) -> Checked {
    let checked = || {
        format!(
            "nothing wrong in the first {} of {}",
            bytes_text(d.reached),
            bytes_text(d.len)
        )
    };
    let limits = *d.budget.limits();
    let (verdict, reason) = match fault {
        Fault::Damaged(why) => (Verdict::Damaged, why),
        Fault::Limit(Limit::Time) => (
            Verdict::NotChecked,
            format!("the check reached its time limit; {}", checked()),
        ),
        Fault::Limit(Limit::Bytes) => (
            Verdict::NotChecked,
            format!(
                "it holds more than {} of stored and compressed data, more than this check unpacks; {}",
                bytes_text(limits.bytes),
                checked()
            ),
        ),
        Fault::Limit(Limit::Memory) => (
            Verdict::NotChecked,
            format!(
                "its structure needs more than {} of memory to check, more than this check holds; {}",
                bytes_text(limits.memory),
                checked()
            ),
        ),
        Fault::Limit(Limit::Count) => (
            Verdict::NotChecked,
            format!(
                "it holds more than {} parts, more than this check reads; {}",
                crate::tools::drives::details::grouped(u128::from(limits.count)),
                checked()
            ),
        ),
        Fault::Limit(Limit::Stopped) => (
            Verdict::NotChecked,
            "the check was stopped before this file was finished".into(),
        ),
        Fault::Unsupported(why) => (Verdict::NotChecked, why),
    };
    Checked {
        verdict,
        kind,
        reason: format!("{mismatch}{reason}"),
    }
}

// ---- a folder: the engine -----------------------------------------------------------------

/// The report's file name.
pub const REPORT: &str = "File check report.txt";
/// The report's last line, written only when every write before it succeeded.
pub const END: &str = "End of report.";
const COMPLETE_IF: &str =
    "This report is complete only if its last line reads \"End of report\" with a full stop.";

/// What a check of a folder is asked to do: plain data, checked by `run` before anything is
/// read, so a person's window and an agent supply the same thing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    /// The folder of recovered or copied files. Every file below it is checked; links are
    /// not followed. Required.
    pub folder: PathBuf,
    /// The physical disk being recovered, when known. A folder on it is refused before
    /// anything is read, since its files would be read from the failing drive. None refuses
    /// no disk.
    pub source_disk: crate::recovery::dest::Protected,
    /// Bytes one file's check may decompress (ZIP entries, PDF streams), 1,000,000 to
    /// 100,000,000,000. Default 2,000,000,000. A file that needs more is not checked.
    pub inflate_cap: u64,
    /// Seconds one file's check may take, 1 to 3,600. Default 60. A file that needs more is
    /// not checked.
    pub seconds_per_file: u64,
    /// The most files checked, 1 to 1,000,000. Default 200,000. A folder with more is
    /// checked that far and the result says so.
    pub max_files: u64,
    /// Whether `File check report.txt` is written into the folder. Default true.
    pub write_report: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            folder: PathBuf::new(),
            source_disk: Default::default(),
            inflate_cap: 2_000_000_000,
            seconds_per_file: 60,
            max_files: 200_000,
            write_report: true,
        }
    }
}

impl Options {
    /// The defaults, for `folder`.
    pub fn new(folder: impl Into<PathBuf>) -> Self {
        Self {
            folder: folder.into(),
            ..Self::default()
        }
    }

    /// The limits each file is checked within (`LIMITS` with these options' time and bytes),
    /// or why the options are refused.
    pub fn limits(&self) -> Result<Limits, String> {
        if self.folder.as_os_str().is_empty() {
            return Err("no folder was given to check".into());
        }
        if !(1_000_000..=100_000_000_000).contains(&self.inflate_cap) {
            return Err("inflate_cap must be from 1,000,000 to 100,000,000,000 bytes".into());
        }
        if !(1..=3600).contains(&self.seconds_per_file) {
            return Err("seconds_per_file must be from 1 to 3,600".into());
        }
        if !(1..=1_000_000).contains(&self.max_files) {
            return Err("max_files must be from 1 to 1,000,000".into());
        }
        Ok(Limits {
            bytes: self.inflate_cap,
            time: Some(Duration::from_secs(self.seconds_per_file)),
            ..LIMITS
        })
    }
}

/// What a check is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Listing the folder; the totals grow.
    Listing,
    /// Checking files; the totals are fixed.
    Checking,
    /// Writing the report.
    Reporting,
}

/// Progress, sent while the folder is listed (every 256 files), before each file is
/// checked, after each file found damaged, and when the report is written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Event {
    pub phase: Option<Phase>,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub good: u64,
    pub damaged: u64,
    pub not_checked: u64,
    /// The file being checked, below the folder.
    pub current: Option<PathBuf>,
    /// A file just found damaged and why: "Pictures\a.jpg: cut short: ...".
    pub warning: Option<String>,
}

/// One file in the folder and how it came out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    /// Below the folder checked.
    pub path: PathBuf,
    pub size: u64,
    pub checked: Checked,
}

/// How a check ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum Ended {
    /// Every file listed was checked.
    #[default]
    Finished,
    /// Cancelled; the files not reached are rows "not checked".
    Stopped,
}

/// The result of a check of a folder.
#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    pub folder: PathBuf,
    /// Every file found, damaged first, then not checked, then good, each by path.
    pub rows: Vec<Row>,
    pub good: u64,
    pub damaged: u64,
    pub not_checked: u64,
    pub ended: Ended,
    /// The folder held more files than `Options::max_files`; only that many are listed.
    pub more: bool,
    /// The listing of the folder reached a limit of its budget (`LISTING`), in words: the
    /// files below what it reached were not listed.
    pub listing_limit: Option<String>,
    /// The report's path, when it was made.
    pub report: Option<PathBuf>,
    /// The report was written to its last line.
    pub report_whole: bool,
    /// Why the report could not be made or written to its end, if so.
    pub report_error: Option<String>,
    /// The report, entered when it was made and ended whole or partial.
    #[serde(skip)]
    pub ledger: Ledger,
}

impl Outcome {
    pub fn count(&self, verdict: Verdict) -> u64 {
        match verdict {
            Verdict::Good => self.good,
            Verdict::Damaged => self.damaged,
            Verdict::NotChecked => self.not_checked,
        }
    }

    fn tally(&mut self) {
        let count = |v| self.rows.iter().filter(|r| r.checked.verdict == v).count() as u64;
        (self.good, self.damaged, self.not_checked) = (
            count(Verdict::Good),
            count(Verdict::Damaged),
            count(Verdict::NotChecked),
        );
    }
}

/// What the listing of a folder may spend: 4,000,000 entries seen (files, folders, links),
/// four times the most files a check takes; 1 GiB held for the paths kept; folders followed
/// 255 deep, as the copy follows them. No clock limit: the person watches it with a Stop
/// button, checked at every entry. Files past `Options::max_files` are counted, not listed.
pub const LISTING: Limits = Limits {
    what: "the listing of the folder",
    unit: "entries",
    count: 4_000_000,
    bytes: u64::MAX,
    memory: 1 << 30,
    depth: super::copy::MAX_DEPTH as u32,
    nested: "folders",
    time: None,
};

/// Held for one path kept, besides its bytes.
const PATH_HELD: u64 = 64;

/// What `list` found.
struct Listed {
    /// (path below the folder, size) of each file, in name order.
    found: Vec<(PathBuf, u64)>,
    /// What could not be listed or was not followed.
    rows: Vec<Row>,
    /// There were more than `max` files.
    more: bool,
}

/// Every file below `folder`, in name order, links not followed, within `budget` (made from
/// `LISTING`).
fn list(folder: &Path, max: usize, budget: &mut Budget, events: &mut dyn FnMut(&Event)) -> Listed {
    const REPARSE: u32 = 0x400;
    let mut l = Listed {
        found: Vec::new(),
        rows: Vec::new(),
        more: false,
    };
    let mut bytes = 0u64;
    let held = |path: &Path| PATH_HELD + path.as_os_str().len() as u64 * 2;
    let mut stack = vec![(PathBuf::new(), 0usize)];
    let walked: Result<(), Limit> = (|| {
        while let Some((below, depth)) = stack.pop() {
            budget.free(held(&below));
            budget.tick()?;
            let entries = match std::fs::read_dir(folder.join(&below)) {
                Ok(entries) => entries,
                Err(e) => {
                    budget.hold(held(&below))?;
                    l.rows.push(not_listed(
                        below.clone(),
                        "folder",
                        &format!("the folder could not be opened ({e})"),
                    ));
                    continue;
                }
            };
            let mut names: Vec<(OsString, Option<std::fs::Metadata>)> = Vec::new();
            for entry in entries {
                budget.item()?;
                match entry {
                    Ok(e) => names.push((e.file_name(), e.metadata().ok())),
                    // An entry the folder's listing could not give is said, not skipped.
                    Err(e) => {
                        budget.hold(held(&below))?;
                        l.rows.push(not_listed(
                            below.clone(),
                            "folder",
                            &format!("an entry of this folder could not be read ({e})"),
                        ));
                    }
                }
            }
            names.sort_by(|a, b| a.0.cmp(&b.0));
            let mut folders = Vec::new();
            for (name, meta) in names {
                let path = below.join(&name);
                if below.as_os_str().is_empty() && is_report(&name) {
                    continue;
                }
                let Some(meta) = meta else {
                    budget.hold(held(&path))?;
                    l.rows
                        .push(not_listed(path, "", "its details could not be read"));
                    continue;
                };
                if meta.file_attributes() & REPARSE != 0 {
                    budget.hold(held(&path))?;
                    l.rows.push(not_listed(
                        path,
                        "link",
                        "a link to somewhere else; not followed",
                    ));
                } else if meta.is_dir() {
                    if budget.within_depth(depth + 1) {
                        budget.hold(held(&path))?;
                        folders.push((path, depth + 1));
                    }
                } else if l.found.len() >= max {
                    l.more = true;
                } else {
                    budget.hold(held(&path))?;
                    bytes += meta.len();
                    l.found.push((path, meta.len()));
                    if l.found.len().is_multiple_of(256) {
                        events(&Event {
                            phase: Some(Phase::Listing),
                            files_total: l.found.len() as u64,
                            bytes_total: bytes,
                            ..Event::default()
                        });
                    }
                }
            }
            stack.extend(folders.into_iter().rev());
        }
        Ok(())
    })();
    debug_assert!(walked.is_ok() || budget.hit().is_some());
    l
}

fn not_listed(path: PathBuf, kind: &'static str, why: &str) -> Row {
    Row {
        path,
        size: 0,
        checked: Checked {
            verdict: Verdict::NotChecked,
            kind,
            reason: why.into(),
        },
    }
}

/// This check's own report, "File check report.txt" or "File check report (2).txt".
fn is_report(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    let Some(rest) = name.strip_prefix("File check report") else {
        return false;
    };
    rest == ".txt"
        || rest
            .strip_prefix(" (")
            .and_then(|r| r.strip_suffix(").txt"))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Opens one file to read it, shared, never following a link put in its place.
fn open_file(path: &Path) -> io::Result<File> {
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

/// The engine: checks every file below `options.folder`, sending progress to `events`, and
/// writes the report into the folder. Refuses bad options, and a folder on
/// `options.source_disk`, before anything is read. `cancel` stops it between reads; the
/// files not reached are listed as not checked and the report is still written.
pub fn run(
    options: &Options,
    events: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
) -> Result<Outcome, String> {
    let limits = options.limits()?;
    let folder = options.folder.as_path();
    let guard = Guard::of(&options.source_disk);
    guard.check_folder(folder)?;
    // Held for the whole check, so the report goes where the files were read.
    let base = guard
        .base(folder)
        .map_err(|e| format!("{} could not be opened: {e}", folder.display()))?;
    let mut listing = Budget::new(LISTING, Some(cancel));
    let Listed {
        found,
        mut rows,
        more,
    } = list(folder, options.max_files as usize, &mut listing, events);
    let mut progress = Event {
        phase: Some(Phase::Checking),
        files_total: found.len() as u64,
        bytes_total: found.iter().map(|(_, size)| size).sum(),
        ..Event::default()
    };
    let mut stopped = cancel.load(Ordering::Relaxed);
    for (path, size) in found {
        stopped |= cancel.load(Ordering::Relaxed);
        let checked = if stopped {
            Checked {
                verdict: Verdict::NotChecked,
                kind: "",
                reason: "the check was stopped before this file".into(),
            }
        } else {
            progress.current = Some(path.clone());
            progress.warning = None;
            events(&progress);
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let checked = match open_file(&folder.join(&path)) {
                Ok(file) => match OpenFile::new(file) {
                    Ok(mut file) => check(&mut file, &name, &mut Budget::new(limits, Some(cancel))),
                    Err(e) => Checked {
                        verdict: Verdict::NotChecked,
                        kind: "",
                        reason: format!("its size could not be read ({e})"),
                    },
                },
                Err(e) => Checked {
                    verdict: Verdict::NotChecked,
                    kind: "",
                    reason: format!("it could not be opened ({e})"),
                },
            };
            progress.files_done += 1;
            progress.bytes_done += size;
            checked
        };
        match checked.verdict {
            Verdict::Good => progress.good += 1,
            Verdict::Damaged => {
                progress.damaged += 1;
                progress.warning = Some(format!("{}: {}", path.display(), checked.reason));
                events(&progress);
            }
            Verdict::NotChecked => progress.not_checked += 1,
        }
        rows.push(Row {
            path,
            size,
            checked,
        });
    }
    // Damaged first; by path within each, as Explorer orders names.
    rows.sort_by_cached_key(|r| (r.checked.verdict, r.path.to_string_lossy().to_lowercase()));
    let mut outcome = Outcome {
        folder: folder.to_path_buf(),
        rows,
        ended: if stopped {
            Ended::Stopped
        } else {
            Ended::Finished
        },
        more,
        listing_limit: listing.said(),
        ..Outcome::default()
    };
    outcome.tally();
    if !options.write_report {
        return Ok(outcome);
    }
    progress.phase = Some(Phase::Reporting);
    progress.current = None;
    progress.warning = None;
    events(&progress);
    let text = report_text(&outcome);
    let entry = super::writer::Entry {
        tag: 0,
        source: folder.to_path_buf(),
        note: "file check report".into(),
        size: text.len() as u64,
    };
    match super::writer::create(&guard, &base, REPORT, &mut outcome.ledger, entry) {
        Ok(mut made) => {
            if let Err(why) =
                super::writer::write_whole(&mut made, text.as_bytes(), &mut outcome.ledger)
            {
                outcome.report_error = Some(why);
            }
            outcome.report_whole = outcome.ledger.get(made.id).complete();
            outcome.report = Some(made.path);
        }
        Err(e) => outcome.report_error = Some(e.to_string()),
    }
    Ok(outcome)
}

/// The report: a heading, every file damaged first with its reason, a summary, and the last
/// line. Written to the folder only through `write_out`, so a failed write leaves it without
/// its last line.
pub fn report_text(outcome: &Outcome) -> String {
    let stamp = crate::clock::local(std::time::SystemTime::now()).long();
    let mut text = format!(
        "File check report\r\n{COMPLETE_IF}\r\n\r\nFolder: {}\r\nChecked: {stamp}\r\nEach file was checked by its contents, not its name: its structure from start to end, and its checksums where the format has them. Pictures, sound and video are not decoded, so one that passes can still show a fault inside it.\r\n",
        outcome.folder.display()
    );
    for verdict in [Verdict::Damaged, Verdict::NotChecked, Verdict::Good] {
        text.push_str(&format!(
            "\r\n{} ({})\r\n",
            verdict.label(),
            outcome.count(verdict)
        ));
        for row in outcome.rows.iter().filter(|r| r.checked.verdict == verdict) {
            text.push_str(&format!(
                "{}\t{}\t{}\t{}\r\n",
                row.path.display(),
                if row.checked.kind.is_empty() {
                    "-"
                } else {
                    row.checked.kind
                },
                say::count(row.size, "byte", "bytes"),
                row.checked.reason
            ));
        }
    }
    text.push_str(&format!(
        "\r\n{}: {} good, {} damaged, {} not checked.\r\n",
        files(outcome.rows.len()),
        outcome.good,
        outcome.damaged,
        outcome.not_checked
    ));
    if outcome.ended == Ended::Stopped {
        text.push_str("The check was stopped before every file was checked.\r\n");
    }
    if outcome.more {
        text.push_str(&say::more_than_checked(outcome.rows.len() as u64));
        text.push_str("\r\n");
    }
    if let Some(limit) = &outcome.listing_limit {
        text.push_str(&format!(
            "{limit} The files beyond it were not listed or checked.\r\n"
        ));
    }
    // No line break after it: a report cut anywhere short does not end with it.
    text.push_str(END);
    text
}

#[cfg(test)]
mod tests;
