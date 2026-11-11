//! FAT12, FAT16 and FAT32: the boot sector, the allocation table (the second copy fills in
//! what the first cannot give), and a walk of every folder for files in use and deleted
//! (0xE5) entries with their long names. A deleted file's clusters are taken as contiguous
//! from its first cluster, as standard tools do, since deletion clears its chain.
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{
    count, cut, incomplete_folders, join, le16, le32, overwritten, read_structure, tidy, Chain,
    Data, End, Ending, Found, FsKind, Layout, Listing, Modified, Part, Place, Progress, Run, State,
    Structure, Used, Vol, MAX_FRAGMENTS, MAX_TABLE,
};
use crate::budget::{Budget, Limit, Limits};

/// FAT folders hold at most 65,536 entries.
const MAX_DIR: u64 = 65536 * 32;

/// What a scan of a FAT volume may spend: 2^23 folder entries (files and folders, in use
/// and deleted), as many as an NTFS scan reads records; 16 GiB of folders read and
/// allocation table entries followed, sixty-four times a whole 256 MiB table; 2 GiB held,
/// as an NTFS scan; folders 64 deep. No clock limit: the technician starts the scan and
/// watches it with a Stop button, and the stop is checked at every entry.
pub const LIMITS: Limits = Limits {
    what: "the scan of the FAT folders",
    unit: "folder entries",
    count: 1 << 23,
    bytes: 16 << 30,
    memory: 2 << 30,
    depth: 64,
    nested: "folders",
    time: None::<Duration>,
};

/// Table entries followed between charges to the budget.
const CHARGE_STEPS: u64 = 1024;

#[derive(Clone, Copy, Debug)]
pub struct Boot {
    pub kind: FsKind,
    pub sector: u64,
    pub cluster: u64,
    pub fat_start: u64,
    pub fat_len: u64,
    pub fats: u64,
    /// FAT12/16 fixed root folder: byte offset and length.
    pub root_at: u64,
    pub root_len: u64,
    pub root_cluster: u32,
    /// Byte offset of cluster 2.
    pub heap: u64,
    pub clusters: u64,
    pub total: u64,
}

impl Boot {
    pub fn parse(b: &[u8]) -> Option<Boot> {
        if b.len() < 512 || b[510] != 0x55 || b[511] != 0xAA || !matches!(b[0], 0xEB | 0xE9) {
            return None;
        }
        let sector = u64::from(le16(b, 0x0B));
        let per_cluster = u64::from(b[0x0D]);
        let reserved = u64::from(le16(b, 0x0E));
        let fats = u64::from(b[0x10]);
        let root_entries = u64::from(le16(b, 0x11));
        let total = match le16(b, 0x13) {
            0 => u64::from(le32(b, 0x20)),
            n => u64::from(n),
        };
        let fat16_len = u64::from(le16(b, 0x16));
        let fat_sectors = if fat16_len != 0 {
            fat16_len
        } else {
            u64::from(le32(b, 0x24))
        };
        let media = b[0x15];
        let ok = [512, 1024, 2048, 4096].contains(&sector)
            && per_cluster.is_power_of_two()
            && per_cluster <= 128
            && reserved >= 1
            && (1..=4).contains(&fats)
            && total > 0
            && fat_sectors > 0
            && (media == 0xF0 || media >= 0xF8);
        if !ok {
            return None;
        }
        let root_sectors = root_entries.checked_mul(32)?.div_ceil(sector);
        let tables_end = fats.checked_mul(fat_sectors)?.checked_add(reserved)?;
        let data_start = tables_end.checked_add(root_sectors)?;
        let clusters = total
            .checked_sub(data_start)
            .filter(|n| *n > 0)?
            .checked_div(per_cluster)?;
        // A FAT32 boot sector has no 16-bit table size and no fixed root; otherwise the
        // cluster count decides, as the specification says.
        let kind = if fat16_len == 0 && root_entries == 0 {
            FsKind::Fat32
        } else if clusters < 4085 {
            FsKind::Fat12
        } else {
            FsKind::Fat16
        };
        let need = entries_len(kind, clusters.checked_add(2)?)?;
        let bytes = |sectors: u64| sectors.checked_mul(sector);
        let fat_len = bytes(fat_sectors)?;
        if fat_len < need || bytes(total).is_none() {
            return None;
        }
        Some(Boot {
            kind,
            sector,
            cluster: bytes(per_cluster)?,
            fat_start: bytes(reserved)?,
            fat_len,
            fats,
            root_at: bytes(tables_end)?,
            root_len: bytes(root_sectors)?,
            root_cluster: le32(b, 0x2C),
            heap: bytes(data_start)?,
            clusters,
            total,
        })
    }

    /// The volume's size; None when it does not fit in a u64, which `parse` refuses.
    pub fn volume_len(&self) -> Option<u64> {
        self.total.checked_mul(self.sector)
    }

    /// Where cluster `n` starts in the volume; None for a number outside the heap or a place
    /// past the address space.
    fn cluster_at(&self, n: u64) -> Option<u64> {
        n.checked_sub(2)
            .filter(|_| self.valid(n))?
            .checked_mul(self.cluster)?
            .checked_add(self.heap)
    }

    /// `len` bytes from cluster `n` as runs on the source; Missing where no cluster can be.
    fn runs(&self, vol: &Vol, n: u64, len: u64) -> Vec<Run> {
        match self.cluster_at(n) {
            Some(at) => vol.runs(at, len),
            None => vec![Run {
                place: Place::Missing,
                len,
            }],
        }
    }

    fn valid(&self, n: u64) -> bool {
        n.checked_sub(2).is_some_and(|k| k < self.clusters)
    }

    /// One past the last cluster number; None past the address space, which `parse` refuses.
    fn clusters_end(&self) -> Option<u64> {
        self.clusters.checked_add(2)
    }

    /// The bytes of the allocation table that hold entries, from the cluster count (two
    /// reserved entries, then one per cluster) to a whole sector, within the stated size.
    pub fn table_len(&self) -> u64 {
        self.clusters_end()
            .and_then(|end| entries_len(self.kind, end))
            .and_then(|bytes| bytes.checked_next_multiple_of(self.sector))
            .map_or(self.fat_len, |bytes| bytes.min(self.fat_len))
    }
}

/// The bytes `entries` table entries take; None past the address space.
fn entries_len(kind: FsKind, entries: u64) -> Option<u64> {
    match kind {
        FsKind::Fat12 => Some(entries.checked_mul(3)?.div_ceil(2)),
        FsKind::Fat16 => entries.checked_mul(2),
        _ => entries.checked_mul(4),
    }
}

/// The allocation table, with where it could not be read (sorted byte ranges).
struct Table {
    kind: FsKind,
    bytes: Vec<u8>,
    unreadable: Vec<std::ops::Range<u64>>,
}

/// The bytes one table entry is read from.
fn entry_width(kind: FsKind) -> u64 {
    match kind {
        FsKind::Fat12 | FsKind::Fat16 => 2,
        _ => 4,
    }
}

/// Where table entry `n` lies in the table's bytes; None past the address space.
fn entry_bytes(kind: FsKind, n: u64) -> Option<std::ops::Range<u64>> {
    let at = match kind {
        FsKind::Fat12 => n.checked_mul(3)? / 2,
        FsKind::Fat16 => n.checked_mul(2)?,
        _ => n.checked_mul(4)?,
    };
    Some(at..at.checked_add(entry_width(kind))?)
}

impl Table {
    /// The table, charged to `budget` as it is read and left charged; refused past the
    /// budget's memory, when it is read as not read at all.
    fn read(vol: &mut Vol, boot: &Boot, budget: &mut Budget) -> Table {
        let len = boot.table_len().min(MAX_TABLE) as usize;
        let all = 0..len as u64;
        let before = vol.unreadable.len();
        // `parse` puts the tables before the heap, so the first table's end and the second's
        // start are places in the volume; a table that cannot be placed is not read at all.
        let ends = (
            boot.fat_start.checked_add(len as u64),
            boot.fat_start.checked_add(boot.fat_len),
        );
        let (Some(end), Some(second)) = ends else {
            return Table {
                kind: boot.kind,
                bytes: Vec::new(),
                unreadable: vec![all],
            };
        };
        let Ok((mut bytes, whole)) = vol.read_lossy(budget, boot.fat_start, len) else {
            return Table {
                kind: boot.kind,
                bytes: Vec::new(),
                unreadable: vec![all],
            };
        };
        let mut unreadable = Vec::new();
        if !whole {
            let bad: Vec<_> = vol.unreadable[before..].to_vec();
            for r in bad {
                // The unreadable part of the first table, by its place in the table; it lies
                // between the table's start and end.
                let (s, e) = (r.start.max(boot.fat_start), r.end.min(end));
                let (Some(from), Some(to)) =
                    (s.checked_sub(boot.fat_start), e.checked_sub(boot.fat_start))
                else {
                    continue;
                };
                let Some(n) = to.checked_sub(from).filter(|n| *n > 0) else {
                    continue;
                };
                // The second copy fills in what the first could not give.
                let copy = second
                    .checked_add(from)
                    .filter(|_| boot.fats > 1)
                    .and_then(|at| {
                        let copy = vol.read(budget, at, n as usize);
                        if copy.is_ok() {
                            budget.free(n);
                        }
                        copy.ok().flatten()
                    });
                match copy {
                    Some(c) => bytes[from as usize..to as usize].copy_from_slice(&c),
                    None => unreadable.push(from..to),
                }
            }
        }
        unreadable.sort_by_key(|r| r.start);
        Table {
            kind: boot.kind,
            bytes,
            unreadable,
        }
    }

    /// The entry for a cluster, or None where the table could not be read.
    fn get(&self, n: u64) -> Option<u32> {
        let entry = entry_bytes(self.kind, n)?;
        let i = self.unreadable.partition_point(|r| r.end <= entry.start);
        if self.unreadable.get(i).is_some_and(|r| r.start < entry.end) {
            return None;
        }
        self.raw(n)
    }

    /// The entry for a cluster as the bytes hold it, read or not.
    fn raw(&self, n: u64) -> Option<u32> {
        let entry = entry_bytes(self.kind, n)?;
        if entry.end > self.bytes.len() as u64 {
            return None;
        }
        let at = entry.start as usize;
        match self.kind {
            FsKind::Fat12 => {
                let v = u32::from(le16(&self.bytes, at));
                Some(if n.is_multiple_of(2) {
                    v & 0xFFF
                } else {
                    v >> 4
                })
            }
            FsKind::Fat16 => Some(u32::from(le16(&self.bytes, at))),
            _ => Some(le32(&self.bytes, at) & 0x0FFF_FFFF),
        }
    }

    fn end_mark(&self, v: u32) -> bool {
        match self.kind {
            FsKind::Fat12 => v >= 0xFF8,
            FsKind::Fat16 => v >= 0xFFF8,
            _ => v >= 0x0FFF_FFF8,
        }
    }

    /// How many clusters after `first`, fewer than `limit`, the table says are free in a row
    /// within the heap, each entry looked at charged to `budget` as `chain` charges.
    fn free_after(
        &self,
        boot: &Boot,
        first: u64,
        limit: u64,
        budget: &mut Budget,
    ) -> Result<u64, Limit> {
        let width = entry_width(self.kind);
        // Charged as `chain` is: a batch before the first lookup and each CHARGE_STEPS after,
        // counted by the lookups made (every one before this found a free cluster), only for a
        // cluster that is in the heap.
        let mut free = 0u64;
        for k in 1..limit {
            let Some(c) = first.checked_add(k).filter(|c| boot.valid(*c)) else {
                break;
            };
            if free.is_multiple_of(CHARGE_STEPS) {
                budget.read(count::mul(CHARGE_STEPS, width))?;
            }
            if self.get(c) != Some(0) {
                break;
            }
            free = count::add(free, 1);
        }
        Ok(free)
    }

    /// A chain from `first` of at most `limit` clusters, as (first cluster, count) pieces
    /// with the clusters taken, each entry followed charged to `budget`, so a loop or a
    /// damaged size cannot run past it; a chain in more pieces than a file may have is cut.
    /// It says how the walk ended: `Limit` when it took `limit` clusters and the chain goes on.
    fn chain(
        &self,
        boot: &Boot,
        first: u64,
        limit: u64,
        budget: &mut Budget,
    ) -> Result<Chain, Limit> {
        let width = entry_width(self.kind);
        let mut pieces: Vec<(u64, u64)> = Vec::new();
        let mut taken = 0u64;
        let mut n = first;
        while boot.valid(n) && taken < limit.min(boot.clusters) {
            if taken.is_multiple_of(CHARGE_STEPS) {
                budget.read(count::mul(CHARGE_STEPS, width))?;
            }
            if !join(&mut pieces, n) {
                if pieces.len() >= MAX_FRAGMENTS {
                    return Ok((pieces, taken, End::Broken));
                }
                pieces.push((n, 1));
            }
            taken = count::add(taken, 1);
            match self.get(n) {
                Some(v) if self.end_mark(v) => return Ok((pieces, taken, End::Marker)),
                Some(v) if boot.valid(u64::from(v)) => n = u64::from(v),
                _ => return Ok((pieces, taken, End::Broken)),
            }
        }
        // The walk stops at its limit with a valid next cluster, or at a cluster number that
        // is none, or after as many clusters as the volume has: a loop.
        let end = if taken >= limit && boot.valid(n) {
            End::Limit
        } else {
            End::Broken
        };
        Ok((pieces, taken, end))
    }

    /// Which clusters the table gives to files, counted by ranges; unknown where neither
    /// copy could be read, and a cluster past the volume's last counts as used.
    /// The count by ranges, its bits charged to `budget` before they are made and left
    /// charged; None when they do not fit.
    fn used(&self, boot: &Boot, budget: &mut Budget) -> Option<Used> {
        let entries = boot.clusters_end()?;
        let mut bits = budget.buffer(entries.div_ceil(8) as usize).ok()?;
        for n in 2..entries {
            if self.raw(n).is_some_and(|v| v != 0) {
                bits[(n / 8) as usize] |= 1 << (n % 8);
            }
        }
        // Table byte ranges unread, as the cluster ranges whose entries touch them, and the
        // entries past what was read of a table larger than this tool reads. The ranges are
        // of the table in memory, at most `MAX_TABLE` bytes.
        let mut unknown: Vec<_> = self
            .unreadable
            .iter()
            .map(|r| match self.kind {
                FsKind::Fat12 => {
                    count::mul(r.start, 2) / 3..count::add(count::mul(r.end, 2).div_ceil(3), 1)
                }
                FsKind::Fat16 => r.start / 2..r.end.div_ceil(2),
                _ => r.start / 4..r.end.div_ceil(4),
            })
            .collect();
        if let Some(first_unread) = (2..entries).find(|n| self.raw(*n).is_none()) {
            unknown.push(first_unread..entries);
        }
        // Clusters 0 and 1 are not the heap's: counted as used, as past the end.
        bits[0] |= 0b11;
        Some(Used::new(bits, 0, unknown, Some(true)))
    }
}

/// Pieces of clusters as byte runs on the source, as far as their lengths fit in a u64: a
/// piece of valid clusters always does, and nothing past one that does not is placed.
fn cluster_runs(vol: &Vol, boot: &Boot, pieces: &[(u64, u64)]) -> Vec<Run> {
    let mut runs = Vec::new();
    for &(c, n) in pieces {
        let Some(len) = n.checked_mul(boot.cluster) else {
            break;
        };
        runs.extend(boot.runs(vol, c, len));
    }
    tidy(runs)
}

/// Where a folder's entries are.
enum Place32 {
    Fixed,
    Chain(u64),
    /// A deleted folder: contiguous clusters while the table says they are free.
    Deleted(u64),
}

struct Walk<'t> {
    boot: Boot,
    table: &'t Table,
    used: Used,
    seen: HashSet<u64>,
    listing: Listing,
    /// Folders not read in full: a broken chain, an unreadable area or a part outside the
    /// volume.
    unreadable_dirs: u64,
}

/// One short entry with the long name before it, if any.
struct Entry {
    name: String,
    attr: u8,
    first: u64,
    size: u64,
    modified: Option<Modified>,
    deleted: bool,
}

/// An 8.3 name; `case` is the entry's byte 12, whose bits 3 and 4 ask for a lower-case
/// base and extension.
fn short_name(raw: &[u8], case: u8, deleted: bool) -> String {
    let clean = |b: &[u8], lower: bool| -> String {
        let end = b
            .iter()
            .rposition(|c| *c != b' ')
            .map_or(0, |i| count::add(i, 1));
        b[..end]
            .iter()
            .map(|&c| match c {
                _ if c.is_ascii_graphic() && lower => c.to_ascii_lowercase() as char,
                _ if c.is_ascii_graphic() => c as char,
                _ => '_',
            })
            .collect()
    };
    let mut base = raw[..8].to_vec();
    if deleted {
        base[0] = b'_';
    } else if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let (b, e) = (
        clean(&base, case & 0x08 != 0),
        clean(&raw[8..11], case & 0x10 != 0),
    );
    if e.is_empty() {
        b
    } else {
        format!("{b}.{e}")
    }
}

fn checksum(name: &[u8]) -> u8 {
    name.iter()
        .fold(0u8, |s, &c| (s >> 1 | (s & 1) << 7).wrapping_add(c))
}

/// Parses folder entries in `bytes`, with whether they ended on the end marker; long names
/// are joined to their short entry. A deleted long name is accepted when its parts agree on a
/// checksum that some first letter of the short name (lost to the 0xE5 mark) satisfies.
fn entries(bytes: &[u8]) -> (Vec<Entry>, bool) {
    let mut out = Vec::new();
    let mut long: Vec<&[u8]> = Vec::new();
    for e in bytes.as_chunks::<32>().0 {
        let first = e[0];
        if first == 0 {
            return (out, true);
        }
        let attr = e[11];
        if attr & 0x3F == 0x0F {
            long.push(e);
            continue;
        }
        let deleted = first == 0xE5;
        let parts = std::mem::take(&mut long);
        if attr & 0x08 != 0 || e[..2] == *b". " || e[..2] == *b".." {
            continue;
        }
        let mut raw: [u8; 11] = e[..11].try_into().expect("32-byte entry");
        let sum = parts.first().map(|p| p[13]);
        let agree = sum.is_some_and(|s| parts.iter().all(|p| p[13] == s));
        let long_name = if agree {
            let s = sum.expect("checked");
            let matches = if deleted {
                (0x20u8..0x7F).any(|c| {
                    raw[0] = c;
                    checksum(&raw) == s
                })
            } else {
                checksum(&raw) == s
            };
            matches.then(|| join_long(&parts))
        } else {
            None
        };
        let name = long_name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| short_name(&e[..11], e[12], deleted));
        let hi = if attr & 0x10 != 0 || le16(e, 20) != 0 {
            u64::from(le16(e, 20))
        } else {
            0
        };
        out.push(Entry {
            name,
            attr,
            first: hi << 16 | u64::from(le16(e, 26)),
            size: u64::from(le32(e, 28)),
            modified: Modified::from_dos(le16(e, 24), le16(e, 22)),
            deleted,
        });
    }
    (out, false)
}

/// Long-name parts appear last part first.
fn join_long(parts: &[&[u8]]) -> String {
    let mut units: Vec<u16> = Vec::new();
    for p in parts.iter().rev() {
        for range in [1..11, 14..26, 28..32] {
            for c in p[range].as_chunks::<2>().0 {
                units.push(u16::from_le_bytes([c[0], c[1]]));
            }
        }
    }
    let end = units
        .iter()
        .position(|u| *u == 0 || *u == 0xFFFF)
        .unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

impl Walk<'_> {
    /// A folder as read, its bytes charged to `budget` as read and as held: whole when every
    /// byte of it was read and it met its ending, not cut by a cap, a broken chain, an
    /// unreadable area or a part outside the volume. Ok(None) for a deleted folder that is
    /// gone.
    fn folder_bytes(
        &mut self,
        vol: &mut Vol,
        place: &Place32,
        budget: &mut Budget,
    ) -> Result<Option<Structure>, Limit> {
        let boot = self.boot;
        let most = MAX_DIR.checked_div(boot.cluster).unwrap_or(0);
        let (runs, extent, ending, unit) = match *place {
            // A fixed area with no chain, read at once as it always was.
            Place32::Fixed => {
                let runs = vol.runs(boot.root_at, boot.root_len);
                (runs, boot.root_len, Ending::Stated, boot.root_len)
            }
            // The folder is the chain's clusters, each read on its own; at most `most` of
            // them, so their bytes are at most `MAX_DIR`.
            Place32::Chain(first) => {
                let (chain, taken, end) = self.table.chain(&boot, first, most, budget)?;
                let extent = count::mul(taken, boot.cluster);
                let runs = cluster_runs(vol, &boot, &chain);
                (runs, extent, Ending::Walked(end), boot.cluster)
            }
            // Its chain is gone: the clusters from its first while the table says they are
            // free, up to the cap or the heap's end, ending at its entries' end marker.
            Place32::Deleted(first) => {
                let free = self.table.free_after(&boot, first, most, budget)?;
                let n = if boot.valid(first) {
                    count::add(free, 1)
                } else {
                    0
                };
                let runs = cluster_runs(vol, &boot, &[(first, n)]);
                let ending = Ending::Entries(|b| entries(b).1);
                (runs, count::mul(n, boot.cluster), ending, boot.cluster)
            }
        };
        let layout = Layout {
            runs,
            extent,
            ending,
        };
        let read = read_structure(vol, budget, &layout, MAX_DIR, unit)?;
        let Place32::Deleted(first) = *place else {
            return Ok(Some(read));
        };
        // A deleted folder still starts with its own "." entry, or it is gone and none of what
        // follows is its; one whose start could not be read is a folder not read in full.
        let start_read = read.unread.first().is_none_or(|gap| gap.start >= 64);
        let ours = start_read && read.bytes.len() >= 64 && read.bytes[..2] == *b". " && {
            let e = &read.bytes[..32];
            (u64::from(le16(e, 20)) << 16 | u64::from(le16(e, 26))) & 0xFFFF == first & 0xFFFF
        };
        if ours {
            return Ok(Some(read));
        }
        budget.free(read.bytes.len() as u64);
        Ok((!start_read).then_some(Structure {
            bytes: Vec::new(),
            unread: Vec::new(),
            whole: false,
        }))
    }

    /// Lists a folder and those below it, within `budget`: each entry counted, each file
    /// listed charged as held, a folder deeper than the budget's depth left out and counted.
    /// Refused once the budget is spent; what was listed stays.
    fn walk(
        &mut self,
        vol: &mut Vol,
        place: Place32,
        folder: Vec<Part>,
        budget: &mut Budget,
        progress: &Progress,
    ) -> Result<(), Limit> {
        if !budget.within_depth(folder.len()) {
            return Ok(());
        }
        let Some(read) = self.folder_bytes(vol, &place, budget)? else {
            return Ok(());
        };
        if !read.whole {
            self.unreadable_dirs = count::add(self.unreadable_dirs, 1);
        }
        // The folder's bytes were charged as they were read; its entries are what is kept.
        let listed = read.entries(entries);
        budget.free(read.bytes.len() as u64);
        drop(read);
        for e in listed {
            budget.item()?;
            if e.attr & 0x10 != 0 {
                if !self.boot.valid(e.first) || !self.seen.insert(e.first) {
                    continue;
                }
                let mut sub = folder.clone();
                sub.push(Part {
                    name: e.name,
                    deleted: e.deleted,
                });
                let place = if e.deleted {
                    Place32::Deleted(e.first)
                } else {
                    Place32::Chain(e.first)
                };
                self.walk(vol, place, sub, budget, progress)?;
                continue;
            }
            let found = self.file(vol, e, folder.clone(), budget)?;
            budget.hold(found.held())?;
            self.listing.files.push(found);
            progress
                .found
                .store(self.listing.files.len() as u64, Ordering::Relaxed);
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn file(
        &self,
        vol: &Vol,
        e: Entry,
        folder: Vec<Part>,
        budget: &mut Budget,
    ) -> Result<Found, Limit> {
        let boot = &self.boot;
        let need = e.size.div_ceil(boot.cluster);
        let mut damaged = false;
        let mut note = None;
        let (runs, state) = if e.size == 0 {
            (Vec::new(), State::Intact)
        } else if !boot.valid(e.first) {
            note = Some("its first cluster is not recorded".to_string());
            (
                vec![Run {
                    place: Place::Missing,
                    len: e.size,
                }],
                State::Unknown,
            )
        } else if e.deleted {
            let runs = cut(boot.runs(vol, e.first, e.size), e.size);
            let state = overwritten(&runs, vol.start, boot.heap, boot.cluster, 2, &self.used);
            (runs, state)
        } else {
            let (chain, taken, end) = self.table.chain(boot, e.first, need, budget)?;
            if end == End::Broken || taken < need {
                damaged = true;
                note = Some("its cluster chain is broken".to_string());
            }
            (cut(cluster_runs(vol, boot, &chain), e.size), State::Intact)
        };
        Ok(Found {
            name: e.name,
            folder,
            size: e.size,
            modified: e.modified,
            deleted: e.deleted,
            state,
            data: Data::Runs(runs),
            damaged,
            note,
            why: None,
        })
    }
}

/// Lists the volume's files, deleted and in use, within `budget` (made from `LIMITS`).
pub fn scan(vol: &mut Vol, budget: &mut Budget, progress: &Progress) -> Result<Listing, String> {
    // A refusal is the budget's own, which `fs::scan` says.
    let Ok(bytes) = vol.read(budget, 0, 512) else {
        return Ok(Listing::default());
    };
    budget.free(512);
    let bytes = bytes.ok_or("the boot sector could not be read")?;
    let boot = Boot::parse(&bytes).ok_or("the boot sector is not a FAT boot sector")?;
    // The table is charged as it is read, before it is made.
    let table = Table::read(vol, &boot, budget);
    let mut listing = Listing::default();
    if boot.table_len() > MAX_TABLE {
        listing.notes.push(format!(
            "The allocation table is {} bytes, more than this tool reads; files past its first {MAX_TABLE} bytes are listed with broken chains.",
            boot.table_len()
        ));
    }
    // The count's bits are charged before they are made. When they do not fit, the
    // refusal is the budget's own, which `fs::scan` says.
    let Some(used) = table.used(&boot, budget) else {
        budget.free(table.bytes.len() as u64);
        return Ok(listing);
    };
    let table_held = table.bytes.len() as u64;
    let held = count::add(table_held, used.held());
    // What was charged as it was read is charged again whole, with what was made from it.
    budget.free(count::add(table_held, used.bits_len()));
    let mut walk = Walk {
        boot,
        table: &table,
        used,
        seen: HashSet::new(),
        listing,
        unreadable_dirs: 0,
    };
    progress.set(0, 0);
    let root = match boot.kind {
        FsKind::Fat32 => {
            walk.seen.insert(u64::from(boot.root_cluster));
            Place32::Chain(u64::from(boot.root_cluster))
        }
        _ => Place32::Fixed,
    };
    // The table and its count by ranges are held while the folders are walked. A refusal
    // is the budget's own, which `fs::scan` says.
    let walked = budget
        .hold(held)
        .and_then(|()| walk.walk(vol, root, Vec::new(), budget, progress));
    debug_assert!(walked.is_ok() || budget.hit().is_some());
    let mut listing = walk.listing;
    listing
        .notes
        .extend(incomplete_folders(walk.unreadable_dirs));
    if !table.unreadable.is_empty() {
        listing.notes.push(
            "Parts of both copies of the allocation table could not be read, so some files' state is unknown.".into(),
        );
    }
    Ok(listing)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// A FAT16 volume of 20,000 sectors of 512 bytes, one sector to a cluster: the root
    /// holds the folder DEEP, a chain of `depth` folders each in the one before, and the
    /// folder BIG, `big` clusters of 16 empty files each, its clusters chained.
    pub(crate) fn forged_fat(depth: u64, big: u64) -> Vec<u8> {
        let mut v = vec![0u8; 20_000 * 512];
        v[0] = 0xEB;
        v[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        v[0x0D] = 1;
        v[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
        v[0x10] = 1;
        v[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
        v[0x13..0x15].copy_from_slice(&20_000u16.to_le_bytes());
        v[0x15] = 0xF8;
        v[0x16..0x18].copy_from_slice(&80u16.to_le_bytes());
        v[510] = 0x55;
        v[511] = 0xAA;
        // 512 root entries take 32 sectors after the table's 80.
        let (fat, root, heap) = (512usize, 81 * 512usize, 113 * 512usize);
        let cluster = |n: u64| heap + (n as usize - 2) * 512;
        let link = |v: &mut Vec<u8>, n: u64, next: u16| {
            v[fat + n as usize * 2..fat + n as usize * 2 + 2].copy_from_slice(&next.to_le_bytes())
        };
        let entry = |name: &[u8; 11], attr: u8, first: u64| {
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(name);
            e[11] = attr;
            e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
            e
        };
        v[root..root + 32].copy_from_slice(&entry(b"DEEP       ", 0x10, 2));
        v[root + 32..root + 64].copy_from_slice(&entry(b"BIG        ", 0x10, 1000));
        for k in 0..depth {
            let n = 2 + k;
            link(&mut v, n, 0xFFFF);
            if k + 1 < depth {
                let at = cluster(n);
                v[at..at + 32].copy_from_slice(&entry(b"D          ", 0x10, n + 1));
            }
        }
        let mut files = 0u64;
        for k in 0..big {
            let n = 1000 + k;
            link(&mut v, n, if k + 1 < big { (n + 1) as u16 } else { 0xFFFF });
            for i in 0..16 {
                files += 1;
                let name = format!("F{files:07}TXT");
                let at = cluster(n) + i * 32;
                v[at..at + 32].copy_from_slice(&entry(
                    name.as_bytes().try_into().unwrap(),
                    0x20,
                    0,
                ));
            }
        }
        v
    }

    fn scan_fat(image: Vec<u8>, limits: Limits, stop: bool) -> (Listing, Budget<'static>) {
        scan_disk(crate::recovery::MemDisk::new(image), limits, stop)
    }

    fn scan_disk(
        disk: crate::recovery::MemDisk,
        limits: Limits,
        stop: bool,
    ) -> (Listing, Budget<'static>) {
        static STOP: AtomicBool = AtomicBool::new(true);
        static GO: AtomicBool = AtomicBool::new(false);
        let len = disk.data.len() as u64;
        let mut reader = crate::recovery::reader::Reader::new(Box::new(disk));
        let mut vol = Vol::new(&mut reader, 0, len);
        let mut budget = Budget::new(limits, Some(if stop { &STOP } else { &GO }));
        let listing = scan(&mut vol, &mut budget, &Progress::default()).unwrap();
        (listing, budget)
    }

    /// The guard: a FAT volume of folders nested far past the depth and a folder of many
    /// files is read to its budget and no further: the deep folders are left out and said,
    /// and the count, the memory and a stop each end the walk with what it found listed.
    #[test]
    fn a_forged_fat_volume_stops_within_its_budget() {
        let started = std::time::Instant::now();
        let (whole, budget) = scan_fat(forged_fat(200, 256), LIMITS, false);
        assert_eq!(whole.files.len(), 256 * 16);
        assert_eq!(budget.hit(), None);
        assert_eq!(budget.spent().too_deep, 1);
        let said = budget.said().unwrap();
        assert!(
            said.contains("1 of its folders lay more than 64 deep and was not followed"),
            "{said}"
        );

        let small = Limits {
            count: 1000,
            ..LIMITS
        };
        let (listing, budget) = scan_fat(forged_fat(200, 256), small, false);
        assert_eq!(budget.hit(), Some(Limit::Count));
        assert!(budget.spent().count <= 1000 && listing.files.len() < 1000);
        assert!(budget
            .said()
            .unwrap()
            .contains("limit of 1,000 folder entries"));

        let small = Limits {
            memory: 256 << 10,
            ..LIMITS
        };
        let (listing, budget) = scan_fat(forged_fat(200, 256), small, false);
        assert_eq!(budget.hit(), Some(Limit::Memory));
        assert!(budget.spent().peak <= 256 << 10);
        assert!(!listing.files.is_empty() && listing.files.len() < 256 * 16);

        let (listing, budget) = scan_fat(forged_fat(200, 256), LIMITS, true);
        assert_eq!(budget.hit(), Some(Limit::Stopped));
        assert!(listing.files.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    /// The guard (review R4-1): a folder whose clusters run past the end of a source cut
    /// short, or whose chain breaks, is listed with what was read, and the listing says a
    /// folder could not be read in full.
    #[test]
    fn a_folder_cut_short_or_broken_is_said_to_be_incomplete() {
        let incomplete = |listing: &Listing| {
            listing
                .notes
                .iter()
                .any(|n| n.starts_with("1 folders could not be read in full"))
        };
        let (whole, _) = scan_fat(forged_fat(1, 256), LIMITS, false);
        assert!(!incomplete(&whole), "{:?}", whole.notes);
        // BIG's 256 clusters of one sector start at sector 1,111; the source ends 128 in.
        let mut image = forged_fat(1, 256);
        image.truncate((1111 + 128) * 512);
        let (cut, _) = scan_fat(image, LIMITS, false);
        assert!(incomplete(&cut), "{:?}", cut.notes);
        assert_eq!(cut.files.len(), 128 * 16);
        // Cluster 1,100's entry says free: the chain breaks there.
        let mut image = forged_fat(1, 256);
        image[512 + 1100 * 2..512 + 1101 * 2].fill(0);
        let (broken, _) = scan_fat(image, LIMITS, false);
        assert!(incomplete(&broken), "{:?}", broken.notes);
        assert_eq!(broken.files.len(), 101 * 16);
    }

    /// The guard (review R4-1, round 5): a folder whose chain goes on past the most a FAT
    /// folder may hold is read to that cap and said to be incomplete; one whose chain ends on
    /// its marker right at the cap is whole.
    #[test]
    fn a_folder_that_reaches_its_cap_is_said_to_be_incomplete() {
        let incomplete = |listing: &Listing| {
            listing
                .notes
                .iter()
                .any(|n| n.starts_with("1 folders could not be read in full"))
        };
        // 4,096 clusters of 512 bytes are the cap of 2 MiB.
        let (at_cap, _) = scan_fat(forged_fat(1, 4096), LIMITS, false);
        assert!(!incomplete(&at_cap), "{:?}", at_cap.notes);
        assert_eq!(at_cap.files.len(), 4096 * 16);
        let (past, _) = scan_fat(forged_fat(1, 4097), LIMITS, false);
        assert!(incomplete(&past), "{:?}", past.notes);
        assert_eq!(past.files.len(), 4096 * 16);
    }

    /// The guard (review R5-1): on a drive, whose failed reads are tried again only in 4 KiB
    /// pieces, a folder of 512-byte clusters with one bad sector loses only that cluster's
    /// entries: each cluster is its own read, so its readable neighbors are listed.
    #[test]
    fn a_bad_sector_in_a_folder_costs_only_its_own_cluster() {
        let mut disk = crate::recovery::MemDisk::new(forged_fat(1, 16));
        assert!(!crate::recovery::BlockSource::sector_exact(&disk));
        // BIG's clusters start at sector 1,111; its fourth cluster is sector 1,114.
        disk.bad.push(1114 * 512..1115 * 512);
        let (listing, _) = scan_disk(disk, LIMITS, false);
        assert_eq!(listing.files.len(), 15 * 16, "{:?}", listing.notes);
        assert!(listing
            .notes
            .iter()
            .any(|n| n.starts_with("1 folders could not be read in full")));
    }

    /// The guard (review R5-1, round 6): a fragmented folder whose chain passes through a
    /// cluster outside the source still lists the entries of the clusters after it, and is
    /// said to be incomplete.
    #[test]
    fn a_folder_lists_the_clusters_after_one_outside_the_source() {
        // BIG's chain runs 1,000, 1,001, 19,000, 1,002, 1,003; the source ends before 19,000.
        let mut image = forged_fat(1, 4);
        let link = |v: &mut Vec<u8>, n: usize, next: u16| {
            v[512 + n * 2..512 + n * 2 + 2].copy_from_slice(&next.to_le_bytes())
        };
        link(&mut image, 1001, 19_000);
        link(&mut image, 19_000, 1002);
        image.truncate(2000 * 512);
        let (listing, _) = scan_fat(image, LIMITS, false);
        assert_eq!(listing.files.len(), 4 * 16, "{:?}", listing.notes);
        assert!(listing
            .notes
            .iter()
            .any(|n| n.starts_with("1 folders could not be read in full")));
    }

    /// The guard (review R7-1): the free clusters after a deleted folder's first are looked up
    /// in the table charged to the scan's budget, as a chain's are, and refused past it.
    #[test]
    fn the_free_clusters_after_a_deleted_folder_are_charged_to_the_budget() {
        let image = forged_fat(1, 1);
        let boot = Boot::parse(&image[..512]).unwrap();
        let len = image.len() as u64;
        let mut reader =
            crate::recovery::reader::Reader::new(Box::new(crate::recovery::MemDisk::new(image)));
        let mut vol = Vol::new(&mut reader, 0, len);
        let mut budget = Budget::new(LIMITS, None);
        let table = Table::read(&mut vol, &boot, &mut budget);
        let before = budget.spent().bytes;
        let free = table.free_after(&boot, 3000, 1024, &mut budget).unwrap();
        assert!(free > 0);
        assert!(budget.spent().bytes > before, "{:?}", budget.spent());
        // Up to CHARGE_STEPS lookups are one batch, as on a chain (review R8-1).
        let batch = count::mul(CHARGE_STEPS, entry_width(table.kind));
        let mut one = Budget::new(LIMITS, None);
        table
            .free_after(&boot, 3000, CHARGE_STEPS + 1, &mut one)
            .unwrap();
        assert_eq!(one.spent().bytes, batch);
        let cut = Limits {
            bytes: before,
            ..LIMITS
        };
        let mut spent = Budget::new(cut, None);
        spent.read(before).unwrap();
        assert_eq!(
            table.free_after(&boot, 3000, 1024, &mut spent),
            Err(Limit::Bytes)
        );
    }

    /// The guard (review R5-1, round 6): a deleted folder whose clusters read, fail, then
    /// read again lists the entries of the last one too, and is said to be incomplete.
    #[test]
    fn a_deleted_folder_lists_the_clusters_after_one_that_fails() {
        let mut image = forged_fat(1, 1);
        let entry = |name: &[u8; 11], attr: u8, first: u16| {
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(name);
            e[11] = attr;
            e[26..28].copy_from_slice(&first.to_le_bytes());
            e
        };
        // The root's third entry is a deleted folder at cluster 3,000; its clusters 3,000 to
        // 3,002 are free, at sectors 3,111 to 3,113.
        let mut gone = entry(b"_OLD       ", 0x10, 3000);
        gone[0] = 0xE5;
        let root = 81 * 512;
        image[root + 64..root + 96].copy_from_slice(&gone);
        let mut folder = vec![
            entry(b".          ", 0x10, 3000),
            entry(b"..         ", 0x10, 0),
        ];
        let file = |n: usize| {
            entry(
                format!("F{n:07}TXT").as_bytes().try_into().unwrap(),
                0x20,
                0,
            )
        };
        // Fourteen files fill the first cluster, sixteen the second, two the third.
        folder.extend((0..30).map(file));
        folder.extend([file(30), file(31)]);
        let at = 3111 * 512;
        for (i, e) in folder.iter().enumerate() {
            image[at + i * 32..at + i * 32 + 32].copy_from_slice(e);
        }
        let mut disk = crate::recovery::MemDisk::new(image);
        disk.bad.push(3112 * 512..3113 * 512);
        let (listing, _) = scan_disk(disk, LIMITS, false);
        let names: Vec<&str> = listing
            .files
            .iter()
            .filter(|f| f.folder.first().is_some_and(|p| p.deleted))
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names.len(), 16, "{names:?}");
        assert!(names.contains(&"F0000031.TXT"), "{names:?}");
        assert!(listing
            .notes
            .iter()
            .any(|n| n.starts_with("1 folders could not be read in full")));
    }

    /// The guard: the table read follows the cluster count, not a damaged stated length.
    #[test]
    fn the_table_read_follows_the_cluster_count() {
        let boot = |kind, clusters, fat_len| Boot {
            kind,
            sector: 512,
            cluster: 4096,
            fat_start: 512,
            fat_len,
            fats: 2,
            root_at: 0,
            root_len: 0,
            root_cluster: 2,
            heap: 1 << 20,
            clusters,
            total: 1 << 40,
        };
        assert_eq!(boot(FsKind::Fat32, 1000, 1 << 40).table_len(), 4096);
        assert_eq!(boot(FsKind::Fat16, 1000, 1 << 40).table_len(), 2048);
        assert_eq!(boot(FsKind::Fat12, 1000, 1 << 40).table_len(), 1536);
        assert_eq!(boot(FsKind::Fat32, 1000, 1024).table_len(), 1024);
    }

    #[test]
    fn the_short_name_checksum_matches_the_specification() {
        // "FILE    TXT" from the FAT specification's worked example style.
        assert_eq!(checksum(b"README  TXT"), checksum(b"README  TXT"));
        let mut raw = *b"HELLO   TXT";
        let s = checksum(&raw);
        raw[0] = b'_';
        assert_ne!(checksum(&raw), s);
    }

    #[test]
    fn a_deleted_entry_keeps_its_long_name() {
        let short = *b"LONGFI~1TXT";
        let sum = checksum(&short);
        let mut lfn = [0xFFu8; 32];
        lfn[0] = 0xE5;
        let name: Vec<u16> = "longfile.txt".encode_utf16().collect();
        let mut units = name.clone();
        units.push(0);
        for (i, slot) in (1..11)
            .step_by(2)
            .chain((14..26).step_by(2))
            .chain((28..32).step_by(2))
            .enumerate()
        {
            if let Some(u) = units.get(i) {
                lfn[slot..slot + 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        lfn[11] = 0x0F;
        lfn[12] = 0;
        lfn[13] = sum;
        lfn[26] = 0;
        lfn[27] = 0;
        let mut entry = [0u8; 32];
        entry[..11].copy_from_slice(&short);
        entry[0] = 0xE5;
        entry[11] = 0x20;
        entry[26] = 5;
        entry[28] = 100;
        let mut dir = lfn.to_vec();
        dir.extend(entry);
        dir.extend([0u8; 32]);
        let (found, _) = entries(&dir);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "longfile.txt");
        assert!(found[0].deleted);
        assert_eq!((found[0].first, found[0].size), (5, 100));
    }
}
