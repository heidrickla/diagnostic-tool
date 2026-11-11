//! Reads a `BlockSource` by byte range for the file system readers, the carver and the copier.
//! An area that fails once is remembered and never asked for again, so a dying drive is
//! not worn down by retries; its bytes come back as zeros and are reported as unreadable.
#![deny(clippy::arithmetic_side_effects)]
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::Range;

use super::{BlockSource, ReadError};

/// The largest single read asked of the source.
pub const CHUNK: u64 = 1 << 20;
/// A failed read is tried again once in pieces of this size, so one bad sector does not
/// cost a whole chunk; each piece is read at most once.
const PIECE: NonZeroU64 = NonZeroU64::new(4096).unwrap();

/// `'s` is how long the source lives: `'static` for an opened disk or image, shorter for
/// a source a rescue lends while it reads a file system's records.
pub struct Reader<'s> {
    source: Box<dyn BlockSource + 's>,
    sector: NonZeroU64,
    /// The size a failed read is tried again in: `PIECE`, or a sector for an image.
    piece: NonZeroU64,
    len: u64,
    /// Byte ranges that failed, sorted and merged. They are never read again.
    bad: Vec<Range<u64>>,
    /// Set when the source stopped answering at all; nothing is read after that.
    gone: Option<String>,
}

/// Bytes read, with the parts that could not be read (filled with zeros).
pub struct Lossy {
    pub data: Vec<u8>,
    /// Unreadable byte ranges of `data`, relative to its start; every byte not read from the
    /// source is in one, so a range that runs past the source or past `u64::MAX` is named too.
    pub unreadable: Vec<Range<usize>>,
}

impl<'s> Reader<'s> {
    pub fn new(source: Box<dyn BlockSource + 's>) -> Self {
        let sector =
            NonZeroU32::new(source.sector_size()).map_or(NonZeroU64::MIN, NonZeroU64::from);
        let len = source.len();
        let piece = if source.sector_exact() {
            sector
        } else {
            PIECE.max(sector)
        };
        Self {
            source,
            sector,
            piece,
            len,
            bad: Vec::new(),
            gone: None,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn sector(&self) -> u64 {
        self.sector.get()
    }

    pub fn describe(&self) -> String {
        self.source.describe()
    }

    pub fn disk_number(&self) -> Option<u32> {
        self.source.disk_number()
    }

    /// What output must not be written to while this source is read (`BlockSource::protected`).
    pub fn protected(&self) -> super::dest::Protected {
        self.source.protected()
    }

    /// Why the source stopped answering, once it has.
    pub fn gone(&self) -> Option<&str> {
        self.gone.as_deref()
    }

    /// The rescue map the source is read under, when it has one.
    pub fn map(&self) -> Option<&super::image::Map> {
        self.source.rescue_map()
    }

    /// Every area that failed so far.
    pub fn bad_areas(&self) -> &[Range<u64>] {
        &self.bad
    }

    /// `end` rounded up to a whole sector, never past the source's end. A bound that does not
    /// fit in a u64 is past the end as well, so it is the end.
    fn aligned_end(&self, end: u64) -> u64 {
        end.div_ceil(self.sector.get())
            .checked_mul(self.sector.get())
            .map_or(self.len, |aligned| aligned.min(self.len))
    }

    /// Reads `len` bytes at `offset` in one read of the sectors around them, never tried
    /// again in pieces; None when it fails, which is recorded, or touches a known bad area,
    /// which is not read at all. For a look that is not worth more than one read.
    pub fn read_once(&mut self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let end = offset
            .checked_add(len as u64)
            .filter(|end| *end <= self.len)?;
        let start = round_down(offset, self.sector);
        let stop = self.aligned_end(end);
        if start == stop {
            return Some(Vec::new());
        }
        if self.bad.iter().any(|b| b.start < stop && start < b.end) {
            return None;
        }
        let bytes = self.fetch(start..stop, true).ok()?;
        let from = index(offset, start);
        bytes.get(from..from.checked_add(len)?).map(<[u8]>::to_vec)
    }

    /// Reads `len` bytes at `offset`, or None when any of them could not be read.
    pub fn read(&mut self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let lossy = self.read_lossy(offset, len);
        lossy.unreadable.is_empty().then_some(lossy.data)
    }

    /// Reads `len` bytes at `offset`, with zeros where the source could not be read or the
    /// range runs past its end.
    pub fn read_lossy(&mut self, offset: u64, len: usize) -> Lossy {
        let mut data = vec![0u8; len];
        let mut unreadable = Vec::new();
        // Bytes the source holds from `offset` on, none from a place past its end; the rest of
        // the buffer is past its end, however close `offset + len` is to the top of the
        // address space.
        let held = self
            .len
            .checked_sub(offset)
            .map_or(0, |held| held.min(len as u64)) as usize;
        if held < len {
            unreadable.push(held..len);
        }
        let want = offset.min(self.len)..bounded(offset, len as u64, self.len);
        if !want.is_empty() {
            // Read whole sectors around the range, then copy out the part asked for.
            let start = round_down(want.start, self.sector);
            let stop = self.aligned_end(want.end);
            let mut at = start;
            while at < stop {
                let piece_end = bounded(at, CHUNK, stop);
                self.read_piece(at..piece_end, &want, offset, &mut data, &mut unreadable);
                at = piece_end;
            }
        }
        Lossy {
            data,
            unreadable: merge(unreadable),
        }
    }

    /// Reads one aligned piece, skipping known bad areas, into `data` (which starts at
    /// `base`), clipped to `want`.
    fn read_piece(
        &mut self,
        piece: Range<u64>,
        want: &Range<u64>,
        base: u64,
        data: &mut [u8],
        unreadable: &mut Vec<Range<usize>>,
    ) {
        for part in self.not_known_bad(piece.clone()) {
            let small = part
                .end
                .checked_sub(part.start)
                .is_some_and(|n| n <= self.sector.get());
            match self.fetch(part.clone(), small) {
                Ok(bytes) => copy_out(&bytes, part.start, want, base, data),
                Err(()) if self.gone.is_some() || small => {}
                Err(()) => {
                    // Once more in small pieces, each read once, to keep what can be read.
                    let mut at = part.start;
                    while at < part.end && self.gone.is_none() {
                        let next = bounded(round_down(at, self.piece), self.piece.get(), part.end);
                        if let Ok(bytes) = self.fetch(at..next, true) {
                            copy_out(&bytes, at, want, base, data);
                        }
                        at = next;
                    }
                }
            }
        }
        // Whatever in the piece is now known bad, or was never read because the source
        // went away, is reported.
        let first = self.bad.partition_point(|b| b.end <= piece.start);
        for bad in &self.bad[first..] {
            if bad.start >= piece.end {
                break;
            }
            let (s, e) = (
                bad.start.max(piece.start).max(want.start),
                bad.end.min(piece.end).min(want.end),
            );
            if s < e {
                unreadable.push(index(s, base)..index(e, base));
            }
        }
        if self.gone.is_some() {
            let (s, e) = (piece.start.max(want.start), piece.end.min(want.end));
            if s < e {
                unreadable.push(index(s, base)..index(e, base));
            }
        }
    }

    /// One read of the source. A failure is recorded, when `record` is set, so the area is
    /// never read again; a large read that fails is left to its pieces to record.
    fn fetch(&mut self, range: Range<u64>, record: bool) -> Result<Vec<u8>, ()> {
        if self.gone.is_some() {
            return Err(());
        }
        let mut buf = vec![0u8; index(range.end, range.start)];
        match self.source.read_at(range.start, &mut buf) {
            Ok(()) => Ok(buf),
            Err(ReadError::Gone(code)) => {
                self.gone = Some(format!("the drive stopped answering (error {code})"));
                Err(())
            }
            Err(ReadError::Bad(_) | ReadError::TimedOut) => {
                if record {
                    self.mark_bad(range);
                }
                Err(())
            }
        }
    }

    fn mark_bad(&mut self, range: Range<u64>) {
        self.bad.push(range);
        self.bad = merge(std::mem::take(&mut self.bad));
    }

    /// The parts of `range` not already known to be bad.
    fn not_known_bad(&self, range: Range<u64>) -> Vec<Range<u64>> {
        let mut parts = Vec::new();
        let mut at = range.start;
        let first = self.bad.partition_point(|b| b.end <= range.start);
        for bad in &self.bad[first..] {
            if bad.start >= range.end {
                break;
            }
            if bad.start > at {
                parts.push(at..bad.start);
            }
            at = at.max(bad.end);
        }
        if at < range.end {
            parts.push(at..range.end);
        }
        parts
    }
}

fn copy_out(bytes: &[u8], at: u64, want: &Range<u64>, base: u64, data: &mut [u8]) {
    let s = at.max(want.start);
    let e = bounded(at, bytes.len() as u64, want.end);
    if s < e {
        data[index(s, base)..index(e, base)].copy_from_slice(&bytes[index(s, at)..index(e, at)]);
    }
}

/// `at` rounded down to a whole `unit`: `at` less its remainder, which is at most `at`, so
/// the distance between them is that difference exactly.
fn round_down(at: u64, unit: NonZeroU64) -> u64 {
    at.abs_diff(at % unit)
}

/// The end of `len` bytes from `at`, no further than `limit`: a range that runs past the top
/// of the address space runs past `limit` too.
fn bounded(at: u64, len: u64, limit: u64) -> u64 {
    at.checked_add(len).map_or(limit, |end| end.min(limit))
}

/// Where source byte `at` lies in a buffer of it that starts at byte `base`. Every caller's
/// `at` lies in that buffer, at or after `base`, so the distance is the difference exactly and
/// fits a usize.
fn index(at: u64, base: u64) -> usize {
    debug_assert!(at >= base, "{at} lies before the buffer at {base}");
    at.abs_diff(base) as usize
}

/// Sorts ranges and joins those that touch or overlap.
pub fn merge<T: Ord + Copy>(mut ranges: Vec<Range<T>>) -> Vec<Range<T>> {
    ranges.retain(|r| r.start < r.end);
    ranges.sort_by_key(|r| r.start);
    let mut out: Vec<Range<T>> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match out.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    use super::*;
    use crate::recovery::MemDisk;
    use std::sync::{Arc, Mutex};

    /// A MemDisk the test keeps a handle on, to look at its reads afterwards.
    pub struct Shared(pub Arc<Mutex<MemDisk>>);

    impl BlockSource for Shared {
        fn len(&self) -> u64 {
            self.0.lock().unwrap().len()
        }
        fn sector_size(&self) -> u32 {
            self.0.lock().unwrap().sector_size()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.0.lock().unwrap().read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.0.lock().unwrap().describe()
        }
    }

    pub fn shared(disk: MemDisk) -> (Reader<'static>, Arc<Mutex<MemDisk>>) {
        let disk = Arc::new(Mutex::new(disk));
        (Reader::new(Box::new(Shared(disk.clone()))), disk)
    }

    /// How many reads touched a byte range.
    pub fn reads_over(disk: &Arc<Mutex<MemDisk>>, range: Range<u64>) -> usize {
        disk.lock()
            .unwrap()
            .reads
            .iter()
            .filter(|(o, l)| *o < range.end && range.start < o + *l as u64)
            .count()
    }

    #[test]
    fn unaligned_reads_come_back_exact() {
        let (mut reader, _) = shared(MemDisk::new((0..8192u32).map(|i| i as u8).collect()));
        assert_eq!(reader.read(3, 4).unwrap(), vec![3, 4, 5, 6]);
        assert_eq!(reader.read(510, 4).unwrap(), vec![254, 255, 0, 1]);
        assert!(reader.read(8190, 4).is_none());
        let lossy = reader.read_lossy(8190, 4);
        assert_eq!(lossy.data, vec![254, 255, 0, 0]);
        assert_eq!(lossy.unreadable, vec![2..4]);
    }

    /// A source as long as an address space allows, whose byte at `i` is `i as u8`.
    struct Huge;

    impl BlockSource for Huge {
        fn len(&self) -> u64 {
            u64::MAX
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (offset + i as u64) as u8;
            }
            Ok(())
        }
        fn describe(&self) -> String {
            "huge".into()
        }
    }

    /// The guard: a range that ends at the top of the address space is aligned and read
    /// without wrapping, on every read path, and a range running past it is reported.
    #[test]
    fn a_range_at_the_top_of_the_address_space_is_read_without_wrapping() {
        let mut reader = Reader::new(Box::new(Huge));
        let top = u64::MAX;
        let expect = |from: u64, n: u64| (from..from + n).map(|i| i as u8).collect::<Vec<_>>();
        let lossy = reader.read_lossy(top - 10, 10);
        assert_eq!(lossy.data, expect(top - 10, 10));
        assert!(lossy.unreadable.is_empty());
        assert_eq!(reader.read(top - 600, 600), Some(expect(top - 600, 600)));
        assert_eq!(reader.read_once(top - 10, 10), Some(expect(top - 10, 10)));
        // A range running past the top is not read whole by any path that asks for all of it.
        assert_eq!(reader.read(top - 4, 8), None);
        assert_eq!(reader.read_once(top - 4, 8), None);
    }

    /// The guard: every byte of the buffer that was not read is listed, also the ones whose
    /// address would lie past `u64::MAX`, which no source offset can name.
    #[test]
    fn bytes_past_the_top_of_the_address_space_are_listed_unreadable() {
        let mut reader = Reader::new(Box::new(Huge));
        let top = u64::MAX;
        let lossy = reader.read_lossy(top - 4, 8);
        assert_eq!(lossy.data.len(), 8);
        assert_eq!(
            lossy.data[..4],
            [
                (top - 4) as u8,
                (top - 3) as u8,
                (top - 2) as u8,
                (top - 1) as u8
            ]
        );
        assert_eq!(lossy.unreadable, vec![4..8]);
        let lossy = reader.read_lossy(top, 3);
        assert_eq!(lossy.unreadable, vec![0..3]);
        assert!(reader.read_lossy(top - 4, 4).unreadable.is_empty());
    }

    #[test]
    fn a_bad_area_is_zeros_and_is_read_at_most_twice() {
        let mut disk = MemDisk::new(vec![7u8; 1 << 21]);
        disk.bad.push(5120..5632);
        let (mut reader, disk) = shared(disk);
        for _ in 0..5 {
            let lossy = reader.read_lossy(0, 16384);
            assert_eq!(lossy.unreadable, vec![4096..8192]);
            assert!(lossy.data[..4096].iter().all(|b| *b == 7));
            assert!(lossy.data[8192..].iter().all(|b| *b == 7));
            assert!(lossy.data[4096..8192].iter().all(|b| *b == 0));
        }
        // Once in the whole read, once in the piece read; never again.
        assert_eq!(reads_over(&disk, 5120..5632), 2);
    }

    #[test]
    fn nothing_is_read_after_the_drive_goes() {
        let mut disk = MemDisk::new(vec![1u8; 1 << 20]);
        disk.dies_after = Some(1);
        let (mut reader, disk) = shared(disk);
        assert!(reader.read(0, 512).is_some());
        assert!(reader.read(512, 512).is_none());
        assert!(reader.gone().is_some());
        for _ in 0..10 {
            assert!(reader.read(4096, 8192).is_none());
        }
        assert_eq!(disk.lock().unwrap().reads.len(), 2);
    }
}
