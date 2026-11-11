//! NTFS: the boot sector, the master file table read through $MFT's own data runs with
//! update-sequence fixups, file records with their names, times and data, paths rebuilt
//! through parent references, and how much of each deleted file $Bitmap now gives to others.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{
    count, cut, le16, le32, le64, overwritten, read_structure, runs_len, tidy, utf16, Data, End,
    Ending, Found, Layout, Listing, Modified, Part, Place, Progress, Run, State, Used, Vol,
    MAX_TABLE,
};
use crate::budget::{Budget, Limit, Limits};

const ROOT: u64 = 5;
const BITMAP: u64 = 6;
const EXTEND: u64 = 11;
/// Records below this number are the file system's own.
const FIRST_USER: u64 = 24;
const MAX_RUNS: usize = 1 << 20;
const MAX_ATTRS: usize = 512;
/// Records read at once.
const BATCH: u64 = 1024;
/// The most file table records one scan reads: 2^23, an 8 GiB table of 1 KiB records, well
/// past the few million files of a Windows volume. Each record read leaves at most one entry
/// and its extension pieces, so this also bounds what the scan keeps.
const MAX_RECORDS: u64 = 1 << 23;
/// The most memory a scan holds: 2 GiB, counted from the size of each kept entry and
/// attribute with its name, values and runs (`kept`), each folder path built, each file
/// listed with its own path and map, and the cluster bitmap. A file with a name and a few
/// runs comes to about 500 bytes kept and as much again listed, so this holds about two
/// million files, past the one to two million of a Windows system volume, while an 8 GiB
/// forged file table of valid records cannot take more; past it the scan stops and says
/// so, and lists what it found.
const MEMORY_BUDGET: u64 = 2 << 30;
/// The most bytes of the volume a scan reads: 16 GiB, twice the largest table it reads,
/// for the table itself and the attribute lists of the files that have one (each at most
/// 1 MiB).
const MAX_BYTES: u64 = 16 << 30;
/// The deepest folder path followed: a folder 64 levels below the root, past any path
/// Windows itself makes; a file deeper than that is listed in a lost folder.
const MAX_DEPTH: u32 = 64;

/// What a scan of an NTFS volume's file table may spend: `MAX_RECORDS` records,
/// `MAX_BYTES` read, `MEMORY_BUDGET` held, folder paths `MAX_DEPTH` deep. No clock limit:
/// the technician starts the scan and watches it with a Stop button, a failing drive's slow
/// reads are timed one by one by the reader, and the stop is checked at every record and
/// every file.
pub const LIMITS: Limits = Limits {
    what: "the scan of the file table",
    unit: "file table records",
    count: MAX_RECORDS,
    bytes: MAX_BYTES,
    memory: MEMORY_BUDGET,
    depth: MAX_DEPTH,
    nested: "folders",
    time: None::<Duration>,
};

const ATTR_STD: u32 = 0x10;
const ATTR_LIST: u32 = 0x20;
const ATTR_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_REPARSE: u32 = 0xC0;
const ATTR_END: u32 = 0xFFFF_FFFF;

#[derive(Clone, Copy, Debug)]
pub struct Boot {
    pub sector: u64,
    pub cluster: u64,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mirror_lcn: u64,
    pub record: u64,
}

impl Boot {
    pub fn parse(b: &[u8]) -> Option<Boot> {
        if b.get(3..11)? != b"NTFS    " {
            return None;
        }
        let sector = u64::from(le16(b, 0x0B));
        if ![512, 1024, 2048, 4096].contains(&sector) {
            return None;
        }
        let raw = b[0x0D];
        let per_cluster = if raw <= 0x80 {
            u64::from(raw)
        } else {
            1u64.checked_shl(256u32.checked_sub(u32::from(raw))?)?
        };
        if per_cluster == 0 || !per_cluster.is_power_of_two() {
            return None;
        }
        let cluster = sector.checked_mul(per_cluster)?;
        let total_sectors = le64(b, 0x28);
        let raw_record = b[0x40] as i8;
        let record = if raw_record > 0 {
            cluster.checked_mul(raw_record as u64)?
        } else {
            1u64.checked_shl(u32::from(raw_record.unsigned_abs()))?
        };
        let boot = Boot {
            sector,
            cluster,
            total_sectors,
            mft_lcn: le64(b, 0x30),
            mirror_lcn: le64(b, 0x38),
            record,
        };
        let clusters = total_sectors.checked_mul(sector)?.checked_div(cluster)?;
        let sane = cluster <= 2 << 20
            && (256..=65536).contains(&record)
            && record.is_power_of_two()
            && total_sectors > 0
            && boot.mft_lcn < clusters
            && boot.mirror_lcn < clusters
            && boot.volume_len().is_some();
        sane.then_some(boot)
    }

    /// The volume's size including the backup boot sector after its last cluster; None when
    /// it does not fit in a u64, which `parse` refuses.
    pub fn volume_len(&self) -> Option<u64> {
        self.total_sectors.checked_add(1)?.checked_mul(self.sector)
    }
}

/// Applies the update-sequence fixups to a record or index block. False when a sector's
/// last two bytes do not carry the sequence number: the block was torn or is not one.
pub fn fixup(rec: &mut [u8]) -> bool {
    let (offset, count) = (le16(rec, 4) as usize, le16(rec, 6) as usize);
    // The array, the sequence number then a saved pair for each sector, must lie in the record.
    let array_end = count.checked_mul(2).and_then(|n| n.checked_add(offset));
    let sectors = count.checked_sub(1).filter(|n| *n > 0);
    let (Some(array_end), Some(sectors)) = (array_end, sectors) else {
        return false;
    };
    if array_end > rec.len() || !rec.len().is_multiple_of(sectors) {
        return false;
    }
    let Some(stride) = rec.len().checked_div(sectors).filter(|s| *s >= 256) else {
        return false;
    };
    let Some(usn) = rec
        .get(offset..array_end)
        .and_then(|a| a.first_chunk::<2>())
    else {
        return false;
    };
    let usn = *usn;
    // Each sector's last two bytes, and the saved pair for it after the sequence number.
    for (end, pair) in (1..count).map(|i| (i.checked_mul(stride), i.checked_mul(2))) {
        let (Some(end), Some(pair)) = (end, pair) else {
            return false;
        };
        let saved = offset
            .checked_add(pair)
            .and_then(|at| rec.get(at..)?.first_chunk::<2>().copied());
        let tail = end
            .checked_sub(2)
            .and_then(|at| rec.get_mut(at..end)?.first_chunk_mut::<2>());
        let (Some(saved), Some(tail)) = (saved, tail) else {
            return false;
        };
        if *tail != usn {
            return false;
        }
        *tail = saved;
    }
    true
}

/// A run of clusters from a runlist: a cluster number, or None for a sparse run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusterRun {
    pub lcn: Option<i64>,
    pub clusters: u64,
}

/// A runlist as decoded: its runs, and how the decoding ended.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Runlist {
    runs: Vec<ClusterRun>,
    end: End,
}

/// No runlist read: a resident attribute's, or one whose place is outside its attribute.
impl Default for Runlist {
    fn default() -> Self {
        Runlist {
            runs: Vec::new(),
            end: End::Broken,
        }
    }
}

/// Decodes a runlist, with how it ended: on its zero header, at the most runs it may have, or
/// on a malformed entry or the end of its bytes, which cut it; the caller sees the shortfall
/// against the attribute's size.
fn decode_runs(b: &[u8]) -> Runlist {
    let mut runs = Vec::new();
    let (mut rest, mut lcn) = (b, 0i64);
    let end = loop {
        let Some((&header, tail)) = rest.split_first() else {
            break End::Broken;
        };
        if header == 0 {
            break End::Marker;
        }
        if runs.len() >= MAX_RUNS {
            break End::Limit;
        }
        let (len_n, off_n) = ((header & 0x0F) as usize, (header >> 4) as usize);
        if len_n == 0 || len_n > 8 || off_n > 8 {
            break End::Broken;
        }
        let Some((len_bytes, tail)) = tail.split_at_checked(len_n) else {
            break End::Broken;
        };
        let Some((off_bytes, tail)) = tail.split_at_checked(off_n) else {
            break End::Broken;
        };
        let mut raw = [0u8; 8];
        raw[..len_n].copy_from_slice(len_bytes);
        let clusters = u64::from_le_bytes(raw);
        if clusters == 0 {
            break End::Broken;
        }
        rest = tail;
        if off_n == 0 {
            runs.push(ClusterRun {
                lcn: None,
                clusters,
            });
            continue;
        }
        // Sign-extended from the top byte stored.
        let negative = off_bytes.last().is_some_and(|top| top & 0x80 != 0);
        let mut raw = [if negative { 0xFF } else { 0 }; 8];
        raw[..off_n].copy_from_slice(off_bytes);
        let delta = i64::from_le_bytes(raw);
        // A cluster number past i64 is malformed: the runlist ends there, so this run and every
        // later one are the shortfall, never a place a later delta brings back into range.
        let Some(next) = lcn.checked_add(delta) else {
            break End::Broken;
        };
        lcn = next;
        runs.push(ClusterRun {
            lcn: Some(lcn),
            clusters,
        });
    };
    Runlist { runs, end }
}

/// One attribute of a record.
#[derive(Clone, Debug)]
struct Attr {
    kind: u32,
    named: bool,
    flags: u16,
    /// Resident value.
    value: Option<Vec<u8>>,
    start_vcn: u64,
    runlist: Runlist,
    data_size: u64,
    init_size: u64,
}

fn attributes(rec: &[u8]) -> Vec<Attr> {
    let mut out = Vec::new();
    let used = (le32(rec, 0x18) as usize).min(rec.len());
    let mut at = le16(rec, 0x14) as usize;
    while at.checked_add(16).is_some_and(|head| head <= used) && out.len() < MAX_ATTRS {
        let kind = le32(rec, at);
        let len = at.checked_add(4).map_or(0, |n| le32(rec, n)) as usize;
        let end = at.checked_add(len).filter(|end| *end <= used);
        let Some(end) = end.filter(|_| kind != ATTR_END && len >= 16 && len.is_multiple_of(8))
        else {
            break;
        };
        let a = &rec[at..end];
        let non_resident = a[8] != 0;
        let named = a[9] != 0;
        let flags = le16(a, 0x0C);
        let attr = if non_resident {
            let runs_at = le16(a, 0x20) as usize;
            Attr {
                kind,
                named,
                flags,
                value: None,
                start_vcn: le64(a, 0x10),
                runlist: a.get(runs_at..).map(decode_runs).unwrap_or_default(),
                data_size: le64(a, 0x30),
                init_size: le64(a, 0x38),
            }
        } else {
            let (vlen, voff) = (le32(a, 0x10) as usize, le16(a, 0x14) as usize);
            let Some(value) = voff.checked_add(vlen).and_then(|e| a.get(voff..e)) else {
                at = end;
                continue;
            };
            Attr {
                kind,
                named,
                flags,
                value: Some(value.to_vec()),
                start_vcn: 0,
                runlist: Runlist::default(),
                data_size: vlen as u64,
                init_size: vlen as u64,
            }
        };
        out.push(attr);
        at = end;
    }
    out
}

/// What the scan keeps of one record.
#[derive(Default)]
struct Entry {
    present: bool,
    in_use: bool,
    is_dir: bool,
    seq: u16,
    /// Name, parent record and parent sequence number.
    name: Option<(String, u64, u16)>,
    name_rank: u8,
    modified: Option<u64>,
    /// Created and last-read times and the file attributes, from $STANDARD_INFORMATION.
    created: Option<u64>,
    accessed: Option<u64>,
    attributes: u32,
    /// The reparse tag of a junction, link or cloud file; 0 when the reparse data is not
    /// held in the record itself.
    reparse: Option<u32>,
    data: Vec<Attr>,
    /// Records named by the attribute list as holding part of the unnamed $DATA, and the
    /// extension records whose pieces were joined.
    list_records: Vec<u64>,
    joined: Vec<u64>,
    damaged: bool,
}

fn rank(namespace: u8) -> u8 {
    match namespace {
        1 | 3 => 3,
        0 => 2,
        _ => 1,
    }
}

impl Entry {
    fn take(&mut self, attrs: Vec<Attr>, this: u64) {
        for a in attrs {
            match a.kind {
                ATTR_STD => {
                    if let Some(v) = &a.value {
                        self.modified = Some(le64(v, 8)).filter(|t| *t != 0);
                        self.created = Some(le64(v, 0)).filter(|t| *t != 0);
                        self.accessed = Some(le64(v, 0x18)).filter(|t| *t != 0);
                        self.attributes = le32(v, 0x20);
                    }
                }
                ATTR_REPARSE => {
                    self.reparse = Some(a.value.as_ref().map_or(0, |v| le32(v, 0)));
                }
                ATTR_NAME => {
                    let Some(v) = &a.value else { continue };
                    let (len, namespace) = (*v.get(0x40).unwrap_or(&0) as usize, v.get(0x41));
                    // A name of at most 255 units.
                    let Some(bytes) = len.checked_mul(2).and_then(|n| v.get(0x42..)?.get(..n))
                    else {
                        continue;
                    };
                    let r = rank(*namespace.unwrap_or(&2));
                    if self.name.is_none() || r > self.name_rank {
                        let parent = le64(v, 0);
                        let name = utf16(bytes);
                        if !name.is_empty() {
                            self.name =
                                Some((name, parent & 0xFFFF_FFFF_FFFF, (parent >> 48) as u16));
                            self.name_rank = r;
                            if self.modified.is_none() {
                                self.modified = Some(le64(v, 0x10)).filter(|t| *t != 0);
                            }
                        }
                    }
                }
                ATTR_DATA if !a.named => self.data.push(a),
                ATTR_LIST => {
                    if let Some(v) = &a.value {
                        self.list_records = list_data_records(v, this);
                    } else {
                        // A non-resident list is read after the pass; remember it as data
                        // of kind LIST.
                        self.data.push(a);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Records other than `this` that the attribute list names for unnamed $DATA.
fn list_data_records(list: &[u8], this: u64) -> Vec<u64> {
    let mut out = Vec::new();
    // A list of 1 MiB names up to 40,000 records; each is taken once, by a set.
    let mut seen = HashSet::new();
    let mut rest = list;
    while rest.len() >= 0x1A {
        let len = le16(rest, 4) as usize;
        if len < 0x1A {
            break;
        }
        let (kind, name_len) = (le32(rest, 0), rest[6]);
        let record = le64(rest, 0x10) & 0xFFFF_FFFF_FFFF;
        if kind == ATTR_DATA && name_len == 0 && record != this && seen.insert(record) {
            out.push(record);
        }
        let Some(next) = rest.get(len..) else {
            break;
        };
        rest = next;
    }
    out
}

/// A stream's runs with the stretch of the stream each holds, so a read from any offset finds
/// its first run by a binary search instead of a walk of every run before it: the file
/// table's runlist may hold a million runs, read a batch at a time. Runs past a stream length
/// that would overflow hold no place in the stream: the map ends before them.
struct Map<'r> {
    runs: &'r [Run],
    spans: Vec<std::ops::Range<u64>>,
    len: u64,
}

impl<'r> Map<'r> {
    fn new(runs: &'r [Run]) -> Self {
        let mut len = 0u64;
        let mut spans = Vec::new();
        for r in runs {
            let Some(end) = len.checked_add(r.len) else {
                break;
            };
            spans.push(len..end);
            len = end;
        }
        Map {
            runs: &runs[..spans.len()],
            spans,
            len,
        }
    }

    /// The first run that may hold stream offset `pos`: the first that ends past it.
    fn first(&self, pos: u64) -> usize {
        self.spans.partition_point(|s| s.end <= pos)
    }
}

/// The most read from the source at once into a stream's buffer, so a long run is never
/// held twice over while it is copied.
const STREAM_PIECE: usize = 1 << 20;

/// Reads bytes of a non-resident stream through its cluster runs, in volume offsets;
/// returns them with whether every byte was read. The `len` bytes are charged to `budget`
/// before the buffer is made, refused past its memory, and stay charged: the caller frees
/// them when it lets them go. Each piece read is charged while it is held.
fn read_stream(
    vol: &mut Vol,
    budget: &mut Budget,
    map: &Map,
    from: u64,
    len: usize,
) -> Result<(Vec<u8>, bool), Limit> {
    let mut out = budget.buffer(len)?;
    // A range that runs past the address space is damage: none of it is a place in the
    // stream, so it is all unread.
    let Some(end) = from.checked_add(len as u64) else {
        return Ok((out, len == 0));
    };
    let mut whole = true;
    let first = map.first(from);
    for (r, span) in map.runs[first..].iter().zip(&map.spans[first..]) {
        let (s, e) = (span.start.max(from), span.end.min(end));
        // `from..end` holds `s..e`, and `span` holds it too.
        let (Some(a), Some(b), Some(skip)) = (
            s.checked_sub(from),
            e.checked_sub(from),
            s.checked_sub(span.start),
        ) else {
            whole = false;
            break;
        };
        if let (Some(dst), Place::At(at)) = (out.get_mut(a as usize..b as usize), r.place) {
            for (k, piece) in (0u64..).zip(dst.chunks_mut(STREAM_PIECE)) {
                // A place within the run, which `Vol::runs` put inside the volume; one that
                // cannot be formed is not read.
                let offset = vol
                    .offset(at)
                    .and_then(|o| o.checked_add(skip))
                    .and_then(|o| o.checked_add(k.checked_mul(STREAM_PIECE as u64)?));
                let Some(offset) = offset else {
                    whole = false;
                    continue;
                };
                match vol.read_lossy(budget, offset, piece.len()) {
                    Ok((bytes, ok)) => {
                        piece.copy_from_slice(&bytes);
                        budget.free(piece.len() as u64);
                        whole &= ok;
                    }
                    Err(limit) => {
                        budget.free(len as u64);
                        return Err(limit);
                    }
                }
            }
        }
        if s < e && r.place == Place::Missing {
            whole = false;
        }
        if span.end >= end {
            break;
        }
    }
    Ok((out, whole && map.len >= end))
}

/// Turns cluster runs into byte runs on the source, clipped to the volume, with whether every
/// run was turned: one whose length in bytes overflows ends them, so nothing after it is
/// placed where a run of that length would have put it.
fn byte_runs(vol: &Vol, cluster: u64, runs: &[ClusterRun]) -> (Vec<Run>, bool) {
    let mut out = Vec::new();
    for r in runs {
        let Some(len) = r.clusters.checked_mul(cluster) else {
            return (tidy(out), false);
        };
        // A cluster before the volume or whose place overflows is outside it: Missing.
        let at = r.lcn.map(|lcn| {
            u64::try_from(lcn)
                .ok()
                .and_then(|lcn| lcn.checked_mul(cluster))
        });
        match at {
            None => out.push(Run {
                place: Place::Zeros,
                len,
            }),
            Some(None) => out.push(Run {
                place: Place::Missing,
                len,
            }),
            Some(Some(at)) => out.extend(vol.runs(at, len)),
        }
    }
    (tidy(out), true)
}

/// A file's unnamed $DATA pieces put in order as byte runs, with its size; the flag says
/// the map has holes.
fn assemble(vol: &Vol, cluster: u64, pieces: &[Attr]) -> Option<(Data, u64, bool)> {
    let first = pieces.iter().find(|a| a.start_vcn == 0)?;
    if let Some(v) = &first.value {
        return Some((Data::Resident(v.clone()), v.len() as u64, false));
    }
    let mut sorted: Vec<&Attr> = pieces.iter().filter(|a| a.value.is_none()).collect();
    sorted.sort_by_key(|a| a.start_vcn);
    let (size, init) = (first.data_size, first.init_size.min(first.data_size));
    let mut runs = Vec::new();
    let mut vcn = 0u64;
    let (mut holes, mut counted) = (false, true);
    // A piece whose place in the file or whose length cannot be counted ends the map: what
    // follows it is the shortfall, Missing, never placed after a stretch of the wrong length.
    for a in sorted {
        if let Some(gap) = a.start_vcn.checked_sub(vcn).filter(|n| *n > 0) {
            holes = true;
            let Some(len) = gap.checked_mul(cluster) else {
                counted = false;
                break;
            };
            runs.push(Run {
                place: Place::Missing,
                len,
            });
        } else if a.start_vcn < vcn {
            continue;
        }
        let (piece, whole) = byte_runs(vol, cluster, &a.runlist.runs);
        runs.extend(piece);
        let end = a
            .runlist
            .runs
            .iter()
            .try_fold(a.start_vcn, |v, r| v.checked_add(r.clusters));
        let Some(end) = end.filter(|_| whole) else {
            (holes, counted) = (true, false);
            break;
        };
        vcn = end;
    }
    let mut runs = tidy(runs);
    // Runs that hold less than the size are damage: the size is kept and the rest is
    // missing, so the file is never shorter than its record says. A size larger than the
    // volume cannot be true, and is cut to what the runs hold; runs too long to count hold
    // any size.
    let size = match runs_len(&runs).filter(|_| counted) {
        Some(held) if size > held => {
            holes = true;
            if size <= vol.len {
                size
            } else {
                held
            }
        }
        _ => size,
    };
    // Past the initialized size the content reads as zeros.
    runs = match size.checked_sub(init).filter(|n| *n > 0) {
        Some(unwritten) => {
            let mut head = cut(runs, init);
            head.push(Run {
                place: Place::Zeros,
                len: unwritten,
            });
            tidy(head)
        }
        None => cut(runs, size),
    };
    Some((Data::Runs(runs), size, holes))
}

/// The most of an attribute list read: one of 1 MiB names up to 40,000 records.
const MAX_LIST: u64 = 1 << 20;

/// A non-resident attribute list, at most `MAX_LIST`, each cluster its own read, charged as
/// `read_structure` charges; whole only when every byte of its stated size was read through
/// a runlist that ended on its zero header and was turned in full.
fn read_list(
    vol: &mut Vol,
    budget: &mut Budget,
    boot: &Boot,
    list: &Attr,
) -> Result<(Vec<u8>, bool), Limit> {
    let (runs, turned) = byte_runs(vol, boot.cluster, &list.runlist.runs);
    // A run too long to place cuts the runlist there, as a malformed entry does.
    let end = if turned {
        list.runlist.end
    } else {
        End::Broken
    };
    let layout = Layout {
        runs,
        extent: list.data_size,
        ending: Ending::Walked(end),
    };
    let read = read_structure(vol, budget, &layout, MAX_LIST, boot.cluster)?;
    Ok((read.bytes, read.whole))
}

/// Reads record 0, falling back to the $MFTMirr copy; charged to `budget` and left
/// charged, as `Vol::read` is, so the caller frees `boot.record` when it is Some.
fn record_zero(vol: &mut Vol, budget: &mut Budget, boot: &Boot) -> Option<Vec<u8>> {
    for lcn in [boot.mft_lcn, boot.mirror_lcn] {
        let Some(at) = lcn.checked_mul(boot.cluster) else {
            continue;
        };
        let read = vol.read(budget, at, boot.record as usize).ok()?;
        if let Some(mut rec) = read {
            if rec.starts_with(b"FILE") && fixup(&mut rec) {
                return Some(rec);
            }
        }
        budget.free(boot.record);
    }
    None
}

/// $MFT's own data runs and record count, following its attribute list when it has one,
/// with whether that list and the records it names were read whole; what it reads is charged
/// to `budget` while it is held.
fn mft_runs(vol: &mut Vol, budget: &mut Budget, boot: &Boot) -> Option<(Vec<Run>, u64, bool)> {
    let rec = record_zero(vol, budget, boot)?;
    budget.free(boot.record);
    let attrs = attributes(&rec);
    let mut pieces: Vec<Attr> = attrs
        .iter()
        .filter(|a| a.kind == ATTR_DATA && !a.named)
        .cloned()
        .collect();
    let (data, _, _) = assemble(vol, boot.cluster, &pieces)?;
    let Data::Runs(mut runs) = data else {
        return None;
    };
    let mut whole = true;
    if let Some(list) = attrs.iter().find(|a| a.kind == ATTR_LIST) {
        let others = match &list.value {
            Some(v) => list_data_records(v, 0),
            None => {
                let (bytes, read) = read_list(vol, budget, boot, list).ok()?;
                budget.free(bytes.len() as u64);
                whole &= read;
                list_data_records(&bytes, 0)
            }
        };
        let map = Map::new(&runs);
        for other in others {
            // A record numbered past the address space is no record of the table: unread.
            let Some(at) = other.checked_mul(boot.record) else {
                whole = false;
                continue;
            };
            let (bytes, ok) = read_stream(vol, budget, &map, at, boot.record as usize).ok()?;
            budget.free(boot.record);
            let mut rec = bytes;
            if ok && rec.starts_with(b"FILE") && fixup(&mut rec) {
                pieces.extend(
                    attributes(&rec)
                        .into_iter()
                        .filter(|a| a.kind == ATTR_DATA && !a.named),
                );
            } else {
                whole = false;
            }
        }
        if let Some((Data::Runs(all), _, _)) = assemble(vol, boot.cluster, &pieces) {
            runs = all;
        }
    }
    // A stretch of the table its map puts outside the volume, or does not place, holds
    // records that cannot be read.
    whole &= runs.iter().all(|r| r.place != Place::Missing);
    let first = pieces.iter().find(|a| a.start_vcn == 0)?;
    let count = record_count(first.data_size, &runs, vol.len, boot.record);
    Some((runs, count, whole))
}

/// The records the file table can hold: its stated size, bounded by its runs, by the
/// stretches of them inside the volume, and by the volume itself, since a damaged or forged
/// runlist can name the same stretch many times. Lengths too long to count bound nothing the
/// volume does not.
fn record_count(data_size: u64, runs: &[Run], vol_len: u64, record: u64) -> u64 {
    let held = runs
        .iter()
        .filter(|r| matches!(r.place, Place::At(_)))
        .try_fold(0u64, |sum, r| sum.checked_add(r.len));
    [runs_len(runs), held]
        .into_iter()
        .flatten()
        .fold(data_size.min(vol_len), u64::min)
        .checked_div(record)
        .unwrap_or(0)
}

/// How many of `count` records a scan reads within what its budget has left, and the note
/// when that cuts it short; the budget is then marked as stopped at its count.
fn scan_limit(count: u64, budget: &mut Budget) -> (u64, Option<String>) {
    let left = count::sub(budget.limits().count, budget.spent().count);
    if count <= left {
        return (count, None);
    }
    budget.reach(Limit::Count);
    (
        left,
        Some(format!(
            "The file table holds {count} records; files described after the first {left} are not listed."
        )),
    )
}

/// The cluster bitmap: whether each cluster is in use, counted by ranges, unknown where it
/// could not be read; with whether it was read whole.
struct Bitmap {
    used: Used,
    whole: bool,
}

/// The bytes of $Bitmap to read: its stated size, bounded by one bit per cluster of the
/// volume; None when that is more than a table may take.
fn bitmap_read_len(stated: u64, volume: u64, cluster: u64) -> Option<u64> {
    let len = stated.min((volume.checked_div(cluster)? / 8).checked_add(1)?);
    (len <= MAX_TABLE).then_some(len)
}

/// $Bitmap as a count by ranges, its bits charged to `budget` before they are made and
/// left charged; None when they do not fit or cannot be found.
fn read_bitmap(vol: &mut Vol, budget: &mut Budget, boot: &Boot, entry: &Entry) -> Option<Bitmap> {
    let (data, size, _) = assemble(vol, boot.cluster, &entry.data)?;
    let Data::Runs(runs) = data else {
        return None;
    };
    let size = bitmap_read_len(size, vol.len, boot.cluster)?;
    let before = vol.unreadable.len();
    let map = Map::new(&runs);
    let (bits, whole) = read_stream(vol, budget, &map, 0, size as usize).ok()?;
    let unknown = match whole {
        true => Some(Vec::new()),
        false => unread_clusters(vol, &map, before),
    };
    // Bits whose unread places cannot be counted are not taken for a record of used space.
    let Some(unknown) = unknown else {
        budget.free(size);
        return None;
    };
    Some(Bitmap {
        used: Used::new(bits, 0, unknown, None),
        whole,
    })
}

/// The clusters whose bits in $Bitmap could not be read, mapped back from the source areas
/// the reader could not read since `before` and the runs the map does not place: each byte of
/// the bitmap is eight clusters. None when a place cannot be counted.
fn unread_clusters(vol: &Vol, map: &Map, before: usize) -> Option<Vec<std::ops::Range<u64>>> {
    let mut bytes = Vec::new();
    for (r, span) in map.runs.iter().zip(&map.spans) {
        match r.place {
            Place::At(at) => {
                let rel = vol.offset(at)?;
                let end = rel.checked_add(r.len)?;
                for bad in &vol.unreadable[before..] {
                    let (s, e) = (bad.start.max(rel), bad.end.min(end));
                    if s < e {
                        let from = span.start.checked_add(s.checked_sub(rel)?)?;
                        let to = span.start.checked_add(e.checked_sub(rel)?)?;
                        bytes.push(from..to);
                    }
                }
            }
            Place::Missing => bytes.push(span.clone()),
            Place::Zeros => {}
        }
    }
    bytes
        .into_iter()
        .map(|r| Some(r.start.checked_mul(8)?..r.end.checked_mul(8)?))
        .collect()
}

/// The file table read whole: its records by number, extension records joined to their
/// base, with what could not be read.
struct Table {
    boot: Boot,
    entries: HashMap<u64, Entry>,
    notes: Vec<String>,
}

/// One attribute kept: the struct, its resident value and its runs.
fn attr_held(a: &Attr) -> u64 {
    count::sum(
        0,
        [
            std::mem::size_of::<Attr>(),
            a.value.as_ref().map_or(0, Vec::len),
            count::mul(a.runlist.runs.len(), std::mem::size_of::<ClusterRun>()),
        ],
    ) as u64
}

/// One entry kept: the entry, its key and the map's own share for it.
const ENTRY_HELD: u64 = (std::mem::size_of::<(u64, Entry)>() + 16) as u64;

/// What a record leaves kept, charged to the scan's memory before anything is kept for it.
/// A base record (`new_entry` when it makes an entry) keeps its unnamed $DATA attributes
/// whole and its name as text, the rest going into the entry's own fields; an extension
/// record keeps each attribute passed whole until it is joined.
fn kept_cost(attrs: &[Attr], base: bool, new_entry: bool) -> u64 {
    let entry = if new_entry { ENTRY_HELD } else { 0 };
    let one = |a: &Attr| match a.kind {
        _ if !base => attr_held(a),
        ATTR_DATA if !a.named => attr_held(a),
        ATTR_NAME => a.value.as_ref().map_or(0, Vec::len) as u64,
        _ => 0,
    };
    count::sum(entry, attrs.iter().map(one))
}

/// At most what an entry was charged when kept: the entry and its $DATA pieces. Freed when
/// the entry is listed and dropped, so a scan's memory follows what it holds.
fn entry_held(e: &Entry) -> u64 {
    count::sum(ENTRY_HELD, e.data.iter().map(attr_held))
}

/// The file table, within `budget`; Ok(None) when the budget refuses its boot sector, a
/// refusal that is the budget's own, which `fs::scan` says.
fn read_table(
    vol: &mut Vol,
    budget: &mut Budget,
    progress: &Progress,
) -> Result<Option<Table>, String> {
    // The first boot sector, or the backup in the volume's last sector.
    let backup_at = vol.len.checked_sub(512);
    let mut boot = None;
    for at in [Some(0), backup_at].into_iter().flatten() {
        let Ok(read) = vol.read(budget, at, 512) else {
            return Ok(None);
        };
        budget.free(512);
        boot = read.as_deref().and_then(Boot::parse);
        if boot.is_some() {
            break;
        }
    }
    let boot = boot.ok_or("neither boot sector could be read as NTFS")?;
    let (runs, count, whole) = mft_runs(vol, budget, &boot)
        .ok_or("the file table's first record and its mirror could not be read")?;
    let mut notes = Vec::new();
    if !whole {
        notes.push(
            "The file table's own map could not be read in full; files described in the parts it does not place are not listed.".into(),
        );
    }
    let (count, cut) = scan_limit(count, budget);
    notes.extend(cut);
    let map = Map::new(&runs);
    let mut entries: HashMap<u64, Entry> = HashMap::new();
    // Pieces of $DATA and names held in extension records, by base record.
    let mut extensions: HashMap<u64, Vec<(u16, u64, Attr)>> = HashMap::new();
    let (mut unreadable, mut torn) = (0u64, 0u64);
    let mut n = 0u64;
    // `count` records fit in the volume (`record_count`), so every record's number and place
    // fit; a batch whose place or size does not is where the scan says it stopped.
    'scan: while n < count {
        let batch = count.checked_sub(n).map_or(0, |left| left.min(BATCH));
        let places = (batch.checked_mul(boot.record), n.checked_mul(boot.record));
        let (Some(batch_held), Some(from)) = places else {
            notes.push(format!("It stopped at file table record {n} of {count}."));
            break;
        };
        // The batch is charged while it is held, and freed once its records are kept.
        let charged = budget.count(batch).and_then(|()| budget.read(batch_held));
        if charged.is_err() {
            break;
        }
        let before = vol.unreadable.len();
        let Ok((mut bytes, whole)) = read_stream(vol, budget, &map, from, batch_held as usize)
        else {
            break;
        };
        let bad = if whole {
            Vec::new()
        } else {
            unreadable_records(vol, &map, &boot, n, batch, before)
        };
        // Each record is fixed up where it lies in the batch.
        for (i, rec) in (0..batch).zip(bytes.chunks_exact_mut(boot.record as usize)) {
            let Some(no) = n.checked_add(i).filter(|no| !bad.contains(no)) else {
                unreadable = count::add(unreadable, 1);
                continue;
            };
            if !rec.starts_with(b"FILE") {
                continue;
            }
            if !fixup(rec) {
                torn = count::add(torn, 1);
                continue;
            }
            let flags = le16(rec, 0x16);
            let base = le64(rec, 0x20);
            let base_no = base & 0xFFFF_FFFF_FFFF;
            // The values copied out of a record are at most its length: charged before they
            // are made, then charged again as what is kept.
            if budget.hold(boot.record).is_err() {
                notes.push(format!("It stopped at file table record {no} of {count}."));
                budget.free(batch_held);
                break 'scan;
            }
            let attrs = attributes(rec);
            budget.free(boot.record);
            let kept: Vec<Attr> = if base_no != 0 {
                attrs
                    .into_iter()
                    .filter(|a| (a.kind == ATTR_DATA && !a.named) || a.kind == ATTR_NAME)
                    .collect()
            } else {
                attrs
            };
            let new_entry = base_no == 0 && !entries.contains_key(&no);
            if budget
                .hold(kept_cost(&kept, base_no == 0, new_entry))
                .is_err()
            {
                notes.push(format!("It stopped at file table record {no} of {count}."));
                budget.free(batch_held);
                break 'scan;
            }
            let attrs = kept;
            if base_no != 0 {
                for a in attrs {
                    extensions
                        .entry(base_no)
                        .or_default()
                        .push(((base >> 48) as u16, no, a));
                }
                continue;
            }
            let entry = entries.entry(no).or_default();
            entry.present = true;
            entry.in_use = flags & 1 != 0;
            entry.is_dir = flags & 2 != 0;
            entry.seq = le16(rec, 0x10);
            entry.take(attrs, no);
        }
        budget.free(batch_held);
        let Some(next) = n.checked_add(batch) else {
            break;
        };
        n = next;
        progress.set(n, count);
    }
    if unreadable > 0 {
        notes.push(format!(
            "{unreadable} records of the file table could not be read; files described there are not listed."
        ));
    }
    if torn > 0 {
        notes.push(format!(
            "{torn} records of the file table were half-written and are skipped."
        ));
    }
    // Join extension records to their base when the base is the same file.
    for (base, parts) in extensions {
        let Some(entry) = entries.get_mut(&base) else {
            continue;
        };
        for (seq, from, a) in parts {
            let same = seq == entry.seq || (!entry.in_use && seq.wrapping_add(1) == entry.seq);
            if !same {
                continue;
            }
            entry.joined.push(from);
            if a.kind == ATTR_NAME {
                entry.take(vec![a], base);
            } else {
                entry.data.push(a);
            }
        }
    }
    Ok(Some(Table {
        boot,
        entries,
        notes,
    }))
}

/// Lists the volume's files, deleted and in use, within `budget` (made from `LIMITS`).
pub fn scan(vol: &mut Vol, budget: &mut Budget, progress: &Progress) -> Result<Listing, String> {
    let Some(Table {
        boot,
        mut entries,
        notes,
    }) = read_table(vol, budget, progress)?
    else {
        return Ok(Listing::default());
    };
    let mut listing = Listing {
        notes,
        ..Listing::default()
    };
    let bitmap = entries
        .get(&BITMAP)
        .filter(|e| e.present)
        .and_then(|e| read_bitmap(vol, budget, &boot, e))
        .filter(|b| {
            // What was charged as it was read is charged again whole, with what was made from it.
            budget.free(b.used.bits_len());
            budget.hold(b.used.held()).is_ok()
        });
    if bitmap.as_ref().is_none_or(|b| !b.whole) {
        listing.notes.push(
            "The volume's record of used space ($Bitmap) could not be read in full, so some deleted files' state is unknown.".into(),
        );
    }
    let mut folders = Folders::default();
    let mut numbers: Vec<u64> = entries
        .keys()
        .copied()
        .filter(|n| *n >= FIRST_USER)
        .collect();
    numbers.sort_unstable();
    for no in numbers {
        if budget.tick().is_err() {
            break;
        }
        let entry = &entries[&no];
        if !entry.present || entry.is_dir {
            continue;
        }
        let Some((name, parent, parent_seq)) = &entry.name else {
            continue;
        };
        let Ok(folder) = folders.path(&entries, *parent, *parent_seq, budget) else {
            break;
        };
        if folder.first().is_some_and(|p| p.name == "$Extend") {
            continue;
        }
        let Ok(Content {
            data,
            size,
            damaged,
            flags,
        }) = content(vol, &boot, entry, no, budget)
        else {
            break;
        };
        let note = if flags & 0x0001 != 0 {
            Some("compressed by NTFS; recovered as stored, not decompressed".to_string())
        } else if flags & 0x4000 != 0 {
            Some("encrypted by Windows; recovered as stored".to_string())
        } else {
            None
        };
        let state = match (&data, entry.in_use) {
            (_, true) | (Data::Resident(_), _) => State::Intact,
            (Data::Runs(runs), false) => match &bitmap {
                Some(b) => overwritten(runs, vol.start, 0, boot.cluster, 0, &b.used),
                None => State::Unknown,
            },
        };
        let found = Found {
            name: name.clone(),
            folder,
            size,
            modified: entry.modified.and_then(Modified::from_filetime),
            deleted: !entry.in_use,
            state,
            data,
            damaged,
            note,
            why: None,
        };
        // A file's entry is not needed again once it is listed; folders' entries are kept
        // for the paths.
        if let Some(entry) = entries.remove(&no) {
            budget.free(entry_held(&entry));
        }
        if budget.hold(found.held()).is_err() {
            break;
        }
        listing.files.push(found);
        progress
            .found
            .store(listing.files.len() as u64, Ordering::Relaxed);
    }
    Ok(listing)
}

/// A file's unnamed $DATA as the scan and the live listing take it.
struct Content {
    data: Data,
    size: u64,
    /// Its map has holes, or a record holding part of it is missing.
    damaged: bool,
    /// The flags of its first piece: 0x0001 compressed, 0x4000 encrypted.
    flags: u16,
}

/// A file's content map; refused when reading its attribute list passes the budget.
fn content(
    vol: &mut Vol,
    boot: &Boot,
    entry: &Entry,
    no: u64,
    budget: &mut Budget,
) -> Result<Content, Limit> {
    let pieces: Vec<Attr> = entry
        .data
        .iter()
        .filter(|a| a.kind == ATTR_DATA)
        .cloned()
        .collect();
    let (data, size, holes) = match assemble(vol, boot.cluster, &pieces) {
        Some(found) => found,
        None => (Data::Runs(Vec::new()), 0, !pieces.is_empty()),
    };
    // A non-resident attribute list is read here, for the files that have one; one not read
    // whole may leave out a record that holds part of the file.
    let mut list_records = entry.list_records.clone();
    let mut list_whole = true;
    if let Some(list) = entry.data.iter().find(|a| a.kind == ATTR_LIST) {
        let (bytes, read) = read_list(vol, budget, boot, list)?;
        list_records = list_data_records(&bytes, no);
        list_whole = read;
        budget.free(bytes.len() as u64);
    }
    let missing_part = !list_whole || list_records.iter().any(|r| !entry.joined.contains(r));
    let flags = pieces
        .iter()
        .find(|a| a.start_vcn == 0)
        .map_or(0, |a| a.flags);
    Ok(Content {
        data,
        size,
        damaged: holes || missing_part || entry.damaged,
        flags,
    })
}

/// The root folder's record number.
pub const ROOT_RECORD: u64 = ROOT;

/// One file or folder in use, as a copy of a volume's files as they are needs it.
#[derive(Clone, Debug)]
pub struct Live {
    pub no: u64,
    pub seq: u16,
    pub name: String,
    /// The folder it is in, by record and sequence number (0 when not checked).
    pub parent: u64,
    pub parent_seq: u16,
    pub is_dir: bool,
    pub size: u64,
    pub data: Data,
    /// Created, modified and last-read times, in NTFS ticks.
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
    /// Windows file attributes (FILE_ATTRIBUTE_*).
    pub attributes: u32,
    /// The reparse tag of a junction, link or cloud file.
    pub reparse: Option<u32>,
    pub compressed: bool,
    pub encrypted: bool,
    pub damaged: bool,
}

/// Every file and folder in use on the volume, with what could not be read, within
/// `budget` (made from `LIMITS`); the caller says the limit it reached, if one. Deleted
/// records and the file system's own are left out.
pub fn live(
    vol: &mut Vol,
    budget: &mut Budget,
    progress: &Progress,
) -> Result<(Vec<Live>, Vec<String>), String> {
    let Some(Table {
        boot,
        mut entries,
        notes,
    }) = read_table(vol, budget, progress)?
    else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut numbers: Vec<u64> = entries
        .iter()
        .filter(|(n, e)| (**n == ROOT || **n >= FIRST_USER) && e.present && e.in_use)
        .map(|(n, _)| *n)
        .collect();
    numbers.sort_unstable();
    let mut out = Vec::new();
    for no in numbers {
        if budget.tick().is_err() {
            break;
        }
        let entry = &entries[&no];
        let Some((name, parent, parent_seq)) = &entry.name else {
            continue;
        };
        let content = if entry.is_dir {
            Content {
                data: Data::Runs(Vec::new()),
                size: 0,
                damaged: entry.damaged,
                flags: 0,
            }
        } else {
            match content(vol, &boot, entry, no, budget) {
                Ok(content) => content,
                Err(_) => break,
            }
        };
        let data = match &content.data {
            Data::Resident(v) => v.len(),
            Data::Runs(r) => count::mul(r.len(), std::mem::size_of::<Run>()),
        };
        let held = count::sum(0, [std::mem::size_of::<Live>(), name.len(), data]);
        let freed = entry_held(entry);
        let live = Live {
            no,
            seq: entry.seq,
            name: name.clone(),
            parent: *parent,
            parent_seq: *parent_seq,
            is_dir: entry.is_dir,
            size: content.size,
            data: content.data,
            created: entry.created,
            modified: entry.modified,
            accessed: entry.accessed,
            attributes: entry.attributes,
            reparse: entry.reparse,
            compressed: content.flags & 0x0001 != 0,
            encrypted: content.flags & 0x4000 != 0,
            damaged: content.damaged,
        };
        entries.remove(&no);
        budget.free(freed);
        if budget.hold(held as u64).is_err() {
            break;
        }
        out.push(live);
    }
    Ok((out, notes))
}

/// Record numbers in a batch that overlap an area the reader could not read.
fn unreadable_records(
    vol: &Vol,
    map: &Map,
    boot: &Boot,
    first: u64,
    batch: u64,
    before: usize,
) -> Vec<u64> {
    let mut out = Vec::new();
    let bad = &vol.unreadable[before..];
    // Records of the batch lie in the volume (`record_count`); one whose number or place
    // cannot be counted is unreadable.
    for i in 0..batch {
        let Some(no) = first.checked_add(i) else {
            break;
        };
        if record_unread(vol, map, bad, no, boot.record).unwrap_or(true) {
            out.push(no);
        }
    }
    out
}

/// Whether record `no` overlaps an area in `bad` or a stretch the map does not place; None
/// when its place cannot be counted.
fn record_unread(
    vol: &Vol,
    map: &Map,
    bad: &[std::ops::Range<u64>],
    no: u64,
    record: u64,
) -> Option<bool> {
    let start = no.checked_mul(record)?;
    let end = start.checked_add(record)?;
    let at = map.first(start);
    for (r, span) in map.runs[at..].iter().zip(&map.spans[at..]) {
        let (s, e) = (span.start.max(start), span.end.min(end));
        if s < e {
            match r.place {
                Place::At(at) => {
                    let on = vol.offset(at)?;
                    let vs = on.checked_add(s.checked_sub(span.start)?)?;
                    let ve = on.checked_add(e.checked_sub(span.start)?)?;
                    if bad.iter().any(|b| b.start < ve && vs < b.end) {
                        return Some(true);
                    }
                }
                Place::Missing => return Some(true),
                Place::Zeros => {}
            }
        }
        if span.end >= end {
            break;
        }
    }
    Some(false)
}

/// Folder paths by record, built once each.
#[derive(Default)]
struct Folders {
    known: HashMap<(u64, u16), Vec<Part>>,
}

impl Folders {
    /// The folder path to `parent`, built once and kept, its memory charged to `budget`. A
    /// path deeper than the budget's depth ends in a lost folder.
    fn path(
        &mut self,
        entries: &HashMap<u64, Entry>,
        parent: u64,
        seq: u16,
        budget: &mut Budget,
    ) -> Result<Vec<Part>, Limit> {
        if let Some(p) = self.known.get(&(parent, seq)) {
            return Ok(p.clone());
        }
        // Walk up to the root, then build down.
        let mut chain: Vec<Part> = Vec::new();
        let (mut at, mut at_seq) = (parent, seq);
        let mut steps = 0usize;
        while at != ROOT {
            steps = count::add(steps, 1);
            let entry = entries.get(&at);
            let fits = entry.is_some_and(|e| {
                e.present
                    && e.is_dir
                    && e.name.is_some()
                    && (at_seq == 0
                        || e.seq == at_seq
                        || (!e.in_use && e.seq == at_seq.wrapping_add(1)))
            });
            if !fits || !budget.within_depth(steps) {
                chain.push(Part {
                    name: format!("Lost folder {at}"),
                    deleted: true,
                });
                break;
            }
            let e = entry.expect("checked above");
            let (name, up, up_seq) = e.name.clone().expect("checked above");
            chain.push(Part {
                name,
                deleted: !e.in_use,
            });
            if at == EXTEND {
                break;
            }
            (at, at_seq) = (up, up_seq);
        }
        chain.reverse();
        let held = count::sum(
            48,
            chain
                .iter()
                .map(|p| count::add(std::mem::size_of::<Part>(), p.name.len())),
        );
        budget.hold(held as u64)?;
        self.known.insert((parent, seq), chain.clone());
        Ok(chain)
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// The guard: $Bitmap is read only as far as one bit per cluster of the volume, and not
    /// at all when even that is more than a table may take.
    #[test]
    fn the_bitmap_read_follows_the_volume() {
        assert_eq!(bitmap_read_len(1 << 40, 1 << 30, 4096), Some((1 << 15) + 1));
        assert_eq!(bitmap_read_len(100, 1 << 30, 4096), Some(100));
        assert_eq!(bitmap_read_len(u64::MAX, u64::MAX, 512), None);
    }

    #[test]
    fn runlists_decode_with_signed_offsets_and_sparse_runs() {
        // 0x18 clusters at 0x5634, then 0x10 sparse, then 0x08 at 0x5634 - 0x10.
        let b = [0x21, 0x18, 0x34, 0x56, 0x01, 0x10, 0x11, 0x08, 0xF0, 0x00];
        let list = decode_runs(&b);
        assert_eq!(list.end, End::Marker);
        assert_eq!(
            list.runs,
            vec![
                ClusterRun {
                    lcn: Some(0x5634),
                    clusters: 0x18
                },
                ClusterRun {
                    lcn: None,
                    clusters: 0x10
                },
                ClusterRun {
                    lcn: Some(0x5624),
                    clusters: 0x08
                },
            ]
        );
    }

    /// The guard: runs that hold less than the file's size leave its size as its record
    /// says, the rest missing, and the file damaged; only a size larger than the volume is
    /// cut to what the runs hold.
    #[test]
    fn a_file_whose_runs_hold_less_than_its_size_keeps_its_size() {
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::MemDisk::new(vec![0u8; 1 << 20]),
        ));
        let vol = Vol::new(&mut reader, 0, 1 << 20);
        let piece = |size: u64| Attr {
            kind: ATTR_DATA,
            named: false,
            flags: 0,
            value: None,
            start_vcn: 0,
            runlist: Runlist {
                runs: vec![ClusterRun {
                    lcn: Some(16),
                    clusters: 4,
                }],
                end: End::Marker,
            },
            data_size: size,
            init_size: size,
        };
        let (data, size, damaged) = assemble(&vol, 4096, &[piece(100_000)]).unwrap();
        assert_eq!(size, 100_000, "the size its record gives");
        assert!(damaged);
        let Data::Runs(runs) = data else {
            panic!("not runs");
        };
        assert_eq!(runs_len(&runs), Some(100_000));
        assert_eq!(
            runs.last(),
            Some(&Run {
                place: Place::Missing,
                len: 100_000 - 4 * 4096
            })
        );
        let (_, size, damaged) = assemble(&vol, 4096, &[piece(u64::MAX / 2)]).unwrap();
        assert_eq!((size, damaged), (4 * 4096, true), "larger than the volume");
        let (_, size, damaged) = assemble(&vol, 4096, &[piece(5000)]).unwrap();
        assert_eq!((size, damaged), (5000, false));
    }

    /// The guard (review F9): a file whose record names runs far past the source reaches
    /// recovery with those bytes unreadable, written as zeros with the file damaged, however
    /// the run's position or length overflows.
    #[test]
    fn a_listed_run_past_the_source_reaches_recovery_unreadable() {
        use crate::recovery::output::{recover, Item, RecoverOptions};
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::MemDisk::new(vec![5u8; 1 << 16]),
        ));
        let vol = Vol::new(&mut reader, 0, 1 << 16);
        let piece = |lcn: i64, clusters: u64, start_vcn: u64| Attr {
            kind: ATTR_DATA,
            named: false,
            flags: 0,
            value: None,
            start_vcn,
            runlist: Runlist {
                runs: vec![ClusterRun {
                    lcn: Some(lcn),
                    clusters,
                }],
                end: End::Marker,
            },
            data_size: 100_000,
            init_size: 100_000,
        };
        // Four clusters in the volume, then a piece at a cluster no source reaches whose
        // length in bytes overflows.
        let pieces = [piece(2, 4, 0), piece(i64::MAX, u64::MAX / 2, 4)];
        let (data, size, _) = assemble(&vol, 4096, &pieces).unwrap();
        assert_eq!(size, 100_000);
        let item = Item {
            name: "far.bin".into(),
            folder: Vec::new(),
            size,
            data,
            state: "intact".into(),
            deleted: false,
            flaw: None,
        };
        let dir = std::env::temp_dir().join(format!("diagtool-far-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = recover(
            &mut reader,
            std::slice::from_ref(&item),
            &dir,
            &RecoverOptions::default(),
            &crate::recovery::dest::Protected::default(),
            &std::sync::atomic::AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        let o = &outcome.ledger.outputs()[0];
        // The four clusters in the volume are read, the rest of the 100,000 bytes is zeros.
        assert!(o.damaged(), "{o:?}");
        assert_eq!(o.zeroed, vec![16_384..100_000], "{o:?}");
        let held = std::fs::read(&o.path).unwrap();
        assert_eq!(held.len(), 100_000);
        assert!(held[..16_384].iter().all(|b| *b == 5));
        assert!(held[16_384..].iter().all(|b| *b == 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the file table's record count is bounded by the volume even when its
    /// runlist names one stretch many times, and a scan reads no more records than its
    /// budget's count, saying so when that cuts it short.
    #[test]
    fn the_file_table_scan_is_bounded_by_the_volume_and_a_limit() {
        let gb500 = 500_000_000_000u64;
        // A forged record 0: one run over the whole volume, named 1,000 times.
        let runs: Vec<Run> = (0..1000)
            .map(|_| Run {
                place: Place::At(0),
                len: gb500,
            })
            .collect();
        assert_eq!(record_count(u64::MAX, &runs, gb500, 1024), gb500 / 1024);
        assert_eq!(record_count(4096, &runs, gb500, 1024), 4);
        assert_eq!(record_count(u64::MAX, &runs, gb500, 0), 0);
        let mut budget = Budget::new(LIMITS, None);
        let (scanned, note) = scan_limit(gb500 / 1024, &mut budget);
        assert_eq!(scanned, MAX_RECORDS);
        assert!(note.unwrap().contains("not listed"));
        assert_eq!(budget.hit(), Some(Limit::Count));
        let mut budget = Budget::new(LIMITS, None);
        assert_eq!(scan_limit(1_000_000, &mut budget), (1_000_000, None));
        assert_eq!(budget.hit(), None);
        let code = include_str!("ntfs.rs");
        let read = &code[code.find("fn read_table(").unwrap()..];
        let limit = read
            .find("let (count, cut) = scan_limit(count, budget);")
            .unwrap();
        assert!(limit < read.find("while n < count {").unwrap());
    }

    /// The guard (cause C): a stream as long as a forged $Bitmap may say is refused by the
    /// budget before its buffer is made. Made first, 64 TiB would fail to allocate and end
    /// the run; within the limit, what is read is charged while it is held.
    #[test]
    fn a_stream_past_the_memory_left_is_refused_before_it_is_made() {
        let image = vec![0xA5u8; 1 << 16];
        let mut reader =
            crate::recovery::reader::Reader::new(Box::new(crate::recovery::MemDisk::new(image)));
        let mut vol = Vol::new(&mut reader, 0, 1 << 16);
        let runs = [Run {
            place: Place::At(0),
            len: 1 << 46,
        }];
        let small = Limits {
            memory: 1 << 20,
            ..LIMITS
        };
        let mut budget = Budget::new(small, None);
        let refused = read_stream(&mut vol, &mut budget, &Map::new(&runs), 0, 1 << 46);
        assert_eq!(refused.err(), Some(Limit::Memory));
        assert_eq!(budget.spent().peak, 0);
        let (bytes, _) = read_stream(&mut vol, &mut budget, &Map::new(&runs), 0, 4096).unwrap();
        assert_eq!(bytes, vec![0xA5u8; 4096]);
        assert_eq!(budget.spent().memory, 4096);
        budget.free(4096);
    }

    /// The guard: what the scan keeps is charged to its budget's memory from the size of
    /// each entry and attribute with its value and runs, before anything is kept for it.
    #[test]
    fn what_the_scan_keeps_is_charged_to_its_memory() {
        let attr = |value: usize, runs: usize| Attr {
            kind: ATTR_DATA,
            named: false,
            flags: 0,
            value: Some(vec![0; value]),
            start_vcn: 0,
            runlist: Runlist {
                runs: vec![
                    ClusterRun {
                        lcn: Some(1),
                        clusters: 1
                    };
                    runs
                ],
                end: End::Marker,
            },
            data_size: 0,
            init_size: 0,
        };
        let one = attr_held(&attr(700, 0));
        assert!(one >= 700 + std::mem::size_of::<Attr>() as u64);
        assert!(attr_held(&attr(0, 1000)) >= 1000 * std::mem::size_of::<ClusterRun>() as u64);
        let entry = (std::mem::size_of::<(u64, Entry)>() + 16) as u64;
        assert_eq!(kept_cost(&[attr(700, 0)], true, true), entry + one);
        // A base record's standard information goes into the entry; an extension record's
        // attributes are kept whole.
        let mut std_info = attr(72, 0);
        std_info.kind = ATTR_STD;
        assert_eq!(kept_cost(std::slice::from_ref(&std_info), true, false), 0);
        assert_eq!(
            kept_cost(std::slice::from_ref(&std_info), false, false),
            attr_held(&std_info)
        );
        // About two million files of a name and a few runs fit the stated budget, kept and
        // listed.
        let mut name = attr(100, 0);
        name.kind = ATTR_NAME;
        let kept = kept_cost(&[std_info, name, attr(0, 3)], true, true);
        assert!(MEMORY_BUDGET / (2 * kept) > 1_500_000, "{kept}");
        let code = include_str!("ntfs.rs");
        let read = &code[code.find("fn read_table(").unwrap()..];
        let charged = read
            .find(".hold(kept_cost(&kept, base_no == 0, new_entry))")
            .unwrap();
        assert!(read[charged..].contains("break 'scan;"));
        assert!(charged < read.find(".push(((base >> 48) as u16, no, a));").unwrap());
        assert!(
            charged
                < read
                    .find("let entry = entries.entry(no).or_default();")
                    .unwrap()
        );
    }

    /// A synthetic NTFS volume: 512-byte sectors, 4 KiB clusters, 1 KiB records, the file
    /// table at cluster 1 holding `files` records after its own, each a file in use in the
    /// root named by `name` and numbered.
    pub(crate) fn forged_volume(files: u64, name: &str) -> Vec<u8> {
        const REC: usize = 1024;
        let records = files + 1;
        let clusters = (records * REC as u64).div_ceil(4096);
        let len = (1 + clusters as usize + 1) * 4096;
        let mut v = vec![0u8; len];
        v[3..11].copy_from_slice(b"NTFS    ");
        v[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        v[0x0D] = 8;
        v[0x28..0x30].copy_from_slice(&((len / 512 - 1) as u64).to_le_bytes());
        v[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
        v[0x38..0x40].copy_from_slice(&1u64.to_le_bytes());
        v[0x40] = 0xF6;
        let record = |attrs: &[Vec<u8>]| {
            let mut r = vec![0u8; REC];
            r[..4].copy_from_slice(b"FILE");
            r[4..6].copy_from_slice(&0x30u16.to_le_bytes());
            r[6..8].copy_from_slice(&3u16.to_le_bytes());
            r[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
            r[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
            r[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
            let mut at = 0x38;
            for a in attrs {
                r[at..at + a.len()].copy_from_slice(a);
                at += a.len();
            }
            r[at..at + 4].copy_from_slice(&ATTR_END.to_le_bytes());
            r[0x18..0x1C].copy_from_slice(&((at + 8) as u32).to_le_bytes());
            // The update sequence: number 1 at each sector's end, the ends kept after it.
            r[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
            for s in 0..2 {
                let end = (s + 1) * 512 - 2;
                let (lo, hi) = (r[end], r[end + 1]);
                r[0x32 + s * 2] = lo;
                r[0x33 + s * 2] = hi;
                r[end..end + 2].copy_from_slice(&1u16.to_le_bytes());
            }
            r
        };
        let attr = |kind: u32, body: Vec<u8>, non_resident: bool| {
            let head = if non_resident { 0x40 } else { 0x18 };
            let len = (head + body.len()).next_multiple_of(8);
            let mut a = vec![0u8; len];
            a[..4].copy_from_slice(&kind.to_le_bytes());
            a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            a[8] = u8::from(non_resident);
            if non_resident {
                a[0x20..0x22].copy_from_slice(&0x40u16.to_le_bytes());
            } else {
                a[0x10..0x14].copy_from_slice(&(body.len() as u32).to_le_bytes());
                a[0x14..0x16].copy_from_slice(&0x18u16.to_le_bytes());
            }
            a[head..head + body.len()].copy_from_slice(&body);
            a
        };
        // Record 0: $DATA over the table's clusters, starting at cluster 1.
        // One run: a 2-byte length of `clusters`, a 3-byte start of cluster 1.
        let runs = vec![0x32u8, clusters as u8, (clusters >> 8) as u8, 1, 0, 0, 0, 0];
        let mut data = attr(ATTR_DATA, runs, true);
        data[0x30..0x38].copy_from_slice(&(records * REC as u64).to_le_bytes());
        data[0x38..0x40].copy_from_slice(&(records * REC as u64).to_le_bytes());
        let mft = 4096;
        v[mft..mft + REC].copy_from_slice(&record(&[data]));
        for n in 1..records as usize {
            let text = format!("{name}{n}");
            let units: Vec<u16> = text.encode_utf16().collect();
            let mut body = vec![0u8; 0x42 + units.len() * 2];
            body[..8].copy_from_slice(&5u64.to_le_bytes());
            body[0x40] = units.len() as u8;
            body[0x41] = 1;
            for (i, u) in units.iter().enumerate() {
                body[0x42 + i * 2..0x44 + i * 2].copy_from_slice(&u.to_le_bytes());
            }
            let at = mft + n * REC;
            v[at..at + REC].copy_from_slice(&record(&[
                attr(ATTR_NAME, body, false),
                attr(ATTR_DATA, b"hello".to_vec(), false),
            ]));
        }
        v
    }

    fn scan_forged(files: u64, limits: Limits, stop: bool) -> (Listing, Budget<'static>) {
        static STOP: AtomicBool = AtomicBool::new(true);
        static GO: AtomicBool = AtomicBool::new(false);
        let image = forged_volume(files, &"n".repeat(200));
        let len = image.len() as u64;
        let mut reader =
            crate::recovery::reader::Reader::new(Box::new(crate::recovery::MemDisk::new(image)));
        let mut vol = Vol::new(&mut reader, 0, len);
        let mut budget = Budget::new(limits, Some(if stop { &STOP } else { &GO }));
        let listing = scan(&mut vol, &mut budget, &Progress::default()).unwrap();
        (listing, budget)
    }

    /// The guard: a forged file table whose every record is a valid file with a long name
    /// is read to its budget and no further, by count, by bytes and by memory, and a stop
    /// is seen at once; each says which limit it reached.
    #[test]
    fn a_forged_file_table_stops_within_its_budget() {
        let started = std::time::Instant::now();
        let (whole, budget) = scan_forged(3000, LIMITS, false);
        // Records 1 to 23 are the file system's own and not listed.
        assert_eq!(whole.files.len(), 3000 - 23, "{:?}", whole.notes);
        assert_eq!(budget.hit(), None);

        let small = Limits {
            count: 1000,
            ..LIMITS
        };
        let (listing, budget) = scan_forged(3000, small, false);
        assert_eq!(budget.hit(), Some(Limit::Count));
        assert!(budget.spent().count <= 1000);
        assert!(listing.files.len() < 1000);
        assert!(budget
            .said()
            .unwrap()
            .contains("limit of 1,000 file table records"));

        let small = Limits {
            bytes: 1536 << 10,
            ..LIMITS
        };
        let (listing, budget) = scan_forged(3000, small, false);
        assert_eq!(budget.hit(), Some(Limit::Bytes));
        assert!(budget.spent().bytes <= 1536 << 10);
        assert!(!listing.files.is_empty() && listing.files.len() <= 1024);

        // A batch of 1,024 records (1 MiB) is charged while it is read, then what it keeps.
        let small = Limits {
            memory: 2 << 20,
            ..LIMITS
        };
        let (listing, budget) = scan_forged(3000, small, false);
        assert_eq!(budget.hit(), Some(Limit::Memory));
        assert!(budget.spent().peak <= 2 << 20);
        assert!(!listing.files.is_empty() && listing.files.len() < 3000);
        assert!(budget.said().unwrap().contains("memory limit"));

        let (listing, budget) = scan_forged(3000, LIMITS, true);
        assert_eq!(budget.hit(), Some(Limit::Stopped));
        assert_eq!((listing.files.len(), budget.spent().count), (0, 0));
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    /// The guard (review F9): an attribute list of the file table's first record that names
    /// record 0xFFFFFFFFFFFF, whose place with 64 KiB records ends past the address space, is
    /// read as a damaged map of the table, never as a read that wraps.
    #[test]
    fn a_record_reference_past_the_address_space_reads_as_damaged() {
        const REC: usize = 65536;
        let mut v = vec![0u8; 20 * 4096];
        v[3..11].copy_from_slice(b"NTFS    ");
        v[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        v[0x0D] = 8;
        let sectors = (v.len() / 512 - 1) as u64;
        v[0x28..0x30].copy_from_slice(&sectors.to_le_bytes());
        v[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
        v[0x38..0x40].copy_from_slice(&1u64.to_le_bytes());
        v[0x40] = 0xF0;
        let mut r = vec![0u8; REC];
        r[..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        r[6..8].copy_from_slice(&129u16.to_le_bytes());
        r[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        r[0x14..0x16].copy_from_slice(&0x138u16.to_le_bytes());
        r[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
        // $DATA: 16 clusters from cluster 1, the record itself.
        let mut data = vec![0u8; 0x48];
        data[..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        data[4..8].copy_from_slice(&0x48u32.to_le_bytes());
        data[8] = 1;
        data[0x20..0x22].copy_from_slice(&0x40u16.to_le_bytes());
        data[0x30..0x38].copy_from_slice(&(REC as u64).to_le_bytes());
        data[0x38..0x40].copy_from_slice(&(REC as u64).to_le_bytes());
        data[0x40..0x44].copy_from_slice(&[0x11, 0x10, 0x01, 0x00]);
        // A resident attribute list naming record 0xFFFFFFFFFFFF for $DATA.
        let mut list = vec![0u8; 0x38];
        list[..4].copy_from_slice(&ATTR_LIST.to_le_bytes());
        list[4..8].copy_from_slice(&0x38u32.to_le_bytes());
        list[0x10..0x14].copy_from_slice(&0x20u32.to_le_bytes());
        list[0x14..0x16].copy_from_slice(&0x18u16.to_le_bytes());
        list[0x18..0x1C].copy_from_slice(&ATTR_DATA.to_le_bytes());
        list[0x1C..0x1E].copy_from_slice(&0x20u16.to_le_bytes());
        list[0x28..0x30].copy_from_slice(&0xFFFF_FFFF_FFFFu64.to_le_bytes());
        let mut at = 0x138;
        for a in [data, list] {
            r[at..at + a.len()].copy_from_slice(&a);
            at += a.len();
        }
        r[at..at + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        r[0x18..0x1C].copy_from_slice(&((at + 8) as u32).to_le_bytes());
        r[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
        for s in 0..REC / 512 {
            let end = (s + 1) * 512 - 2;
            let (lo, hi) = (r[end], r[end + 1]);
            r[0x32 + s * 2] = lo;
            r[0x33 + s * 2] = hi;
            r[end..end + 2].copy_from_slice(&1u16.to_le_bytes());
        }
        v[4096..4096 + REC].copy_from_slice(&r);
        let len = v.len() as u64;
        let mut reader =
            crate::recovery::reader::Reader::new(Box::new(crate::recovery::MemDisk::new(v)));
        let mut vol = Vol::new(&mut reader, 0, len);
        let mut budget = Budget::new(LIMITS, None);
        let listing = scan(&mut vol, &mut budget, &Progress::default()).unwrap();
        assert!(
            listing
                .notes
                .iter()
                .any(|n| n.starts_with("The file table's own map could not be read in full")),
            "{:?}",
            listing.notes
        );
    }

    /// The guard (review R4-1): a file table whose runs reach past the end of a source cut
    /// short lists the records it could read and says the rest are not listed.
    #[test]
    fn a_file_table_cut_short_by_the_source_is_said_to_be_incomplete() {
        let mut image = forged_volume(100, "f");
        image.truncate(4096 + 50 * 1024);
        let len = image.len() as u64;
        let mut reader =
            crate::recovery::reader::Reader::new(Box::new(crate::recovery::MemDisk::new(image)));
        let mut vol = Vol::new(&mut reader, 0, len);
        let mut budget = Budget::new(LIMITS, None);
        let listing = scan(&mut vol, &mut budget, &Progress::default()).unwrap();
        assert_eq!(listing.files.len(), 50 - 24, "{:?}", listing.notes);
        assert!(
            listing
                .notes
                .iter()
                .any(|n| n.starts_with("The file table's own map could not be read in full")),
            "{:?}",
            listing.notes
        );
    }

    /// The guard (review R4-1): a file whose attribute list cannot be read in full may lack
    /// a record that holds part of it, so it is damaged.
    #[test]
    fn a_file_whose_attribute_list_is_cut_short_is_damaged() {
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::MemDisk::new(vec![0u8; 1 << 16]),
        ));
        let mut vol = Vol::new(&mut reader, 0, 1 << 16);
        let boot = Boot {
            sector: 512,
            cluster: 4096,
            total_sectors: 127,
            mft_lcn: 1,
            mirror_lcn: 1,
            record: 1024,
        };
        let list = |lcn: i64| Attr {
            kind: ATTR_LIST,
            named: false,
            flags: 0,
            value: None,
            start_vcn: 0,
            runlist: Runlist {
                runs: vec![ClusterRun {
                    lcn: Some(lcn),
                    clusters: 1,
                }],
                end: End::Marker,
            },
            data_size: 4096,
            init_size: 4096,
        };
        let damaged = |lcn: i64, vol: &mut Vol| {
            let entry = Entry {
                present: true,
                in_use: true,
                data: vec![list(lcn)],
                ..Entry::default()
            };
            let mut budget = Budget::new(LIMITS, None);
            content(vol, &boot, &entry, 30, &mut budget)
                .unwrap()
                .damaged
        };
        assert!(!damaged(2, &mut vol), "a list read whole");
        assert!(damaged(1 << 20, &mut vol), "a list past the source");
    }

    /// The guard (review R4-1, round 6): an attribute list is whole only when its runlist
    /// ended on its zero header; one whose runs cover its size but whose runlist is cut before
    /// that header is damaged, and so is the file it describes.
    #[test]
    fn an_attribute_list_whose_runlist_lacks_its_zero_header_is_damaged() {
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::MemDisk::new(vec![0u8; 1 << 16]),
        ));
        let mut vol = Vol::new(&mut reader, 0, 1 << 16);
        let boot = Boot {
            sector: 512,
            cluster: 4096,
            total_sectors: 127,
            mft_lcn: 1,
            mirror_lcn: 1,
            record: 1024,
        };
        // One cluster at cluster 2, the list's whole 4 KiB, with and without the zero header.
        let damaged = |runlist: &[u8], vol: &mut Vol| {
            let list = Attr {
                kind: ATTR_LIST,
                named: false,
                flags: 0,
                value: None,
                start_vcn: 0,
                runlist: decode_runs(runlist),
                data_size: 4096,
                init_size: 4096,
            };
            let entry = Entry {
                present: true,
                in_use: true,
                data: vec![list],
                ..Entry::default()
            };
            let mut budget = Budget::new(LIMITS, None);
            content(vol, &boot, &entry, 30, &mut budget)
                .unwrap()
                .damaged
        };
        assert!(
            !damaged(&[0x11, 0x01, 0x02, 0x00], &mut vol),
            "a runlist ended"
        );
        assert!(
            damaged(&[0x11, 0x01, 0x02], &mut vol),
            "a runlist cut short"
        );
        assert!(
            damaged(&[0x11, 0x01, 0x02, 0x40], &mut vol),
            "a malformed entry"
        );
    }

    /// The guard (review R4-1, round 5): an attribute list longer than the most this tool
    /// reads is read to that cap and is not whole, so the file it describes is damaged; one
    /// of exactly the cap is whole.
    #[test]
    fn an_attribute_list_past_the_cap_is_damaged() {
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::MemDisk::new(vec![0u8; 4 << 20]),
        ));
        let mut vol = Vol::new(&mut reader, 0, 4 << 20);
        let boot = Boot::parse(&forged_volume(1, "f")).unwrap();
        let damaged = |bytes: u64, vol: &mut Vol| {
            let list = Attr {
                kind: ATTR_LIST,
                named: false,
                flags: 0,
                value: None,
                start_vcn: 0,
                runlist: Runlist {
                    runs: vec![ClusterRun {
                        lcn: Some(2),
                        clusters: bytes / 4096,
                    }],
                    end: End::Marker,
                },
                data_size: bytes,
                init_size: bytes,
            };
            let entry = Entry {
                present: true,
                in_use: true,
                data: vec![list],
                ..Entry::default()
            };
            let mut budget = Budget::new(LIMITS, None);
            let content = content(vol, &boot, &entry, 30, &mut budget).unwrap();
            assert_eq!(budget.spent().memory, 0, "the list's bytes are freed");
            content.damaged
        };
        assert!(
            !damaged(MAX_LIST, &mut vol),
            "a list of the cap, read whole"
        );
        assert!(damaged(2 * MAX_LIST, &mut vol), "a list cut at the cap");
    }

    /// The guard (review F9, round 5): a runlist whose cluster number overflows ends there,
    /// so a later delta cannot bring a saturated number back to a real cluster: the runs after
    /// it are the shortfall, Missing, and nothing of the file is read from the volume.
    #[test]
    fn a_runlist_whose_cluster_number_overflows_places_nothing_after_it() {
        let mut runlist = vec![0x81, 0x01];
        runlist.extend(i64::MAX.to_le_bytes());
        // One cluster one past i64::MAX, then one back down to cluster 2.
        runlist.extend([0x11, 0x01, 0x01, 0x81, 0x01]);
        runlist.extend((i64::MIN + 3).to_le_bytes());
        runlist.push(0);
        assert_eq!(
            decode_runs(&runlist).runs,
            vec![ClusterRun {
                lcn: Some(i64::MAX),
                clusters: 1
            }]
        );
        let mut reader = crate::recovery::reader::Reader::new(Box::new(
            crate::recovery::MemDisk::new(vec![5u8; 1 << 16]),
        ));
        let vol = Vol::new(&mut reader, 0, 1 << 16);
        let piece = Attr {
            kind: ATTR_DATA,
            named: false,
            flags: 0,
            value: None,
            start_vcn: 0,
            runlist: decode_runs(&runlist),
            data_size: 3 * 4096,
            init_size: 3 * 4096,
        };
        let (data, size, damaged) = assemble(&vol, 4096, &[piece]).unwrap();
        assert_eq!((size, damaged), (3 * 4096, true));
        let Data::Runs(runs) = data else {
            panic!("not runs");
        };
        assert_eq!(
            runs,
            vec![Run {
                place: Place::Missing,
                len: 3 * 4096
            }]
        );
    }

    #[test]
    fn a_truncated_runlist_ends_without_panicking() {
        let cut = decode_runs(&[0x48, 0x01]);
        assert!(cut.runs.is_empty() && cut.end == End::Broken);
        let cut = decode_runs(&[0x11, 0x04, 0x02, 0x33]);
        assert_eq!((cut.runs.len(), cut.end), (1, End::Broken));
    }

    #[test]
    fn fixups_restore_sector_ends_and_refuse_torn_records() {
        let mut rec = vec![0u8; 1024];
        rec[..4].copy_from_slice(b"FILE");
        rec[4] = 0x30;
        rec[6] = 3;
        rec[0x30..0x36].copy_from_slice(&[0xAB, 0xCD, 1, 2, 3, 4]);
        rec[510..512].copy_from_slice(&[0xAB, 0xCD]);
        rec[1022..1024].copy_from_slice(&[0xAB, 0xCD]);
        let mut good = rec.clone();
        assert!(fixup(&mut good));
        assert_eq!(&good[510..512], &[1, 2]);
        assert_eq!(&good[1022..1024], &[3, 4]);
        rec[1022] = 0;
        assert!(!fixup(&mut rec));
    }
}
