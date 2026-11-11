//! exFAT: the boot sector, the allocation bitmap and table, and a walk of every folder for
//! entry sets in use and deleted (in-use bit clear). A file marked NoFatChain is contiguous,
//! so a deleted one is exact; a deleted chained file follows its chain where the table still
//! holds a whole one, and is otherwise taken as contiguous.
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{
    count, cut, incomplete_folders, join, le16, le32, le64, overwritten, read_structure, runs_len,
    tidy, Chain, Data, End, Ending, Found, Layout, Listing, Modified, Part, Place, Progress, Run,
    State, Used, Vol, MAX_FRAGMENTS, MAX_TABLE,
};
use crate::budget::{Budget, Limit, Limits};

/// Folders larger than this are read only this far.
const MAX_DIR: u64 = 32 << 20;

/// What a scan of an exFAT volume may spend: 2^23 entry sets (files and folders, in use
/// and deleted), as many as an NTFS scan reads records; 16 GiB of folders read and
/// allocation table entries followed, sixty-four times a whole 256 MiB table; 2 GiB held,
/// as an NTFS scan; folders 64 deep. No clock limit: the technician starts the scan and
/// watches it with a Stop button, and the stop is checked at every entry set.
pub const LIMITS: Limits = Limits {
    what: "the scan of the exFAT folders",
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
    pub sector: u64,
    pub cluster: u64,
    pub total: u64,
    pub fat_at: u64,
    pub fat_len: u64,
    pub fats: u64,
    pub heap: u64,
    pub clusters: u64,
    pub root: u64,
}

/// The most clusters the exFAT specification allows.
const MAX_CLUSTERS: u64 = (1 << 32) - 11;

impl Boot {
    /// An exFAT boot sector by its signature and sizes; whether its values agree with each
    /// other is `check`'s to say, so a damaged one is still found and reported.
    pub fn parse(b: &[u8]) -> Option<Boot> {
        if b.get(3..11)? != b"EXFAT   " || b.get(510..512)? != [0x55, 0xAA] {
            return None;
        }
        let (sector_shift, cluster_shift) = (u32::from(b[0x6C]), u32::from(b[0x6D]));
        if !(9..=12).contains(&sector_shift)
            || sector_shift
                .checked_add(cluster_shift)
                .is_none_or(|shift| shift > 25)
        {
            return None;
        }
        let sector = 1u64 << sector_shift;
        let sectors = |at: usize| u64::from(le32(b, at)).checked_mul(sector);
        let boot = Boot {
            sector,
            cluster: sector << cluster_shift,
            total: le64(b, 0x48),
            fat_at: sectors(0x50)?,
            fat_len: sectors(0x54)?,
            fats: u64::from(b[0x6E]),
            heap: sectors(0x58)?,
            clusters: u64::from(le32(b, 0x5C)),
            root: u64::from(le32(b, 0x60)),
        };
        (boot.total > 0 && boot.total.checked_mul(sector).is_some()).then_some(boot)
    }

    /// Whether the boot sector's values agree as the specification requires: the tables
    /// lie before the cluster heap, the table holds an entry for every cluster, and the
    /// clusters fit in the volume. Values that disagree are reported, never used.
    pub fn check(&self) -> Result<(), String> {
        let disagree = |why: String| Err(format!("the exFAT boot sector's values disagree: {why}"));
        if !(1..=2).contains(&self.fats) {
            return disagree(format!("it says there are {} allocation tables", self.fats));
        }
        // `parse` refuses a volume size and the count's check a table size that overflows.
        let (Some(volume), Some(entries)) = (self.volume_len(), self.entries_len()) else {
            return disagree(format!("it says there are {} clusters", self.clusters));
        };
        if self.clusters == 0 || self.clusters > MAX_CLUSTERS {
            return disagree(format!("it says there are {} clusters", self.clusters));
        }
        if self.fat_len < entries {
            return disagree(format!(
                "its allocation table of {} bytes cannot hold {} clusters",
                self.fat_len, self.clusters
            ));
        }
        let tables_end = self
            .fat_len
            .checked_mul(self.fats)
            .and_then(|tables| tables.checked_add(self.fat_at));
        if tables_end.is_none_or(|end| end > self.heap) {
            return disagree("its allocation tables run into the cluster heap".into());
        }
        if self
            .clusters
            .checked_mul(self.cluster)
            .and_then(|heap| heap.checked_add(self.heap))
            .is_none_or(|end| end > volume)
        {
            return disagree(format!(
                "{} clusters of {} bytes do not fit in a volume of {volume} bytes",
                self.clusters, self.cluster
            ));
        }
        if !self.valid(self.root) {
            return disagree(format!("its root folder is at cluster {}", self.root));
        }
        Ok(())
    }

    /// The bytes of the allocation table that hold entries, from the cluster count:
    /// two reserved entries, then one per cluster, to a whole sector.
    pub fn fat_read_len(&self) -> u64 {
        self.entries_len()
            .and_then(|bytes| bytes.checked_next_multiple_of(self.sector))
            .map_or(self.fat_len, |bytes| bytes.min(self.fat_len))
    }

    /// One past the last cluster number; the count is a 32-bit field, so it is always Some.
    fn clusters_end(&self) -> Option<u64> {
        self.clusters.checked_add(2)
    }

    /// The bytes of the allocation table's entries: four for each cluster number.
    fn entries_len(&self) -> Option<u64> {
        self.clusters_end()?.checked_mul(4)
    }

    /// The bytes of the allocation bitmap: one bit per cluster.
    pub fn bitmap_len(&self) -> u64 {
        self.clusters.div_ceil(8)
    }

    /// The volume's size; None when it does not fit in a u64, which `parse` refuses.
    pub fn volume_len(&self) -> Option<u64> {
        self.total.checked_mul(self.sector)
    }

    fn valid(&self, n: u64) -> bool {
        n.checked_sub(2).is_some_and(|k| k < self.clusters)
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
}

struct Tables {
    fat: Vec<u8>,
    fat_whole: bool,
    /// The allocation bitmap counted by ranges; None when it could not be read.
    bitmap: Option<Used>,
}

/// The allocation bitmap's bytes as a count by ranges: bit 0 is cluster 2, clusters past
/// those it holds but inside the heap are unknown, and those outside the heap used.
fn used_of(boot: &Boot, bits: Vec<u8>) -> Used {
    // The clusters the bits in memory hold, from cluster 2.
    let have = count::add(count::mul(bits.len() as u64, 8), 2);
    let end = boot.clusters_end().unwrap_or(have);
    let unknown: Vec<std::ops::Range<u64>> =
        (have < end).then_some(have..end).into_iter().collect();
    Used::new(bits, 2, unknown, Some(true))
}

impl Tables {
    fn next(&self, n: u64) -> Option<u64> {
        let at = usize::try_from(n.checked_mul(4)?).ok()?;
        let v = u64::from(le32(&self.fat, at));
        (self.fat_whole || v != 0).then_some(v)
    }

    /// Used clusters in `from..to`, None when the bitmap could not be read.
    fn used(&self, from: u64, to: u64) -> Option<u64> {
        self.bitmap.as_ref()?.count(from, to)
    }

    /// A chain from `first` of at most `limit` clusters, as (first cluster, count) pieces
    /// with the clusters taken, each entry followed charged to `budget`. Neighbouring clusters
    /// join one piece, so memory goes by fragments, and a chain in more pieces than a file may
    /// have is cut. It says how the walk ended, from the entry of the last cluster taken too:
    /// `Limit` when it took `limit` clusters and the chain goes on.
    fn chain(
        &self,
        boot: &Boot,
        first: u64,
        limit: u64,
        budget: &mut Budget,
    ) -> Result<Chain, Limit> {
        let mut pieces: Vec<(u64, u64)> = Vec::new();
        let (mut n, mut taken) = (first, 0u64);
        while boot.valid(n) && taken < limit.min(boot.clusters) {
            if taken.is_multiple_of(CHARGE_STEPS) {
                budget.read(CHARGE_STEPS * 4)?;
            }
            if !join(&mut pieces, n) {
                if pieces.len() >= MAX_FRAGMENTS {
                    return Ok((pieces, taken, End::Broken));
                }
                pieces.push((n, 1));
            }
            taken = count::add(taken, 1);
            match self.next(n) {
                Some(END_OF_CHAIN) => return Ok((pieces, taken, End::Marker)),
                Some(v) if boot.valid(v) => n = v,
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

/// Where a file or folder's content is, with what ends it: its chain as walked, broken when
/// it falls short of the size, its clusters kept as far as the walk went and the rest missing;
/// or its stated size alone, for a file marked contiguous or a deleted one taken as contiguous. Refused when following its chain passes the budget.
#[allow(clippy::too_many_arguments)]
fn content_runs(
    vol: &Vol,
    boot: &Boot,
    tables: &Tables,
    first: u64,
    len: u64,
    contiguous: bool,
    deleted: bool,
    budget: &mut Budget,
) -> Result<(Vec<Run>, Ending), Limit> {
    let need = len.div_ceil(boot.cluster);
    if len == 0 {
        return Ok((Vec::new(), Ending::Stated));
    }
    if !boot.valid(first) {
        let missing = Run {
            place: Place::Missing,
            len,
        };
        return Ok((vec![missing], Ending::Walked(End::Broken)));
    }
    if !contiguous {
        let (chain, taken, end) = tables.chain(boot, first, need, budget)?;
        let end = if taken < need { End::Broken } else { end };
        let runs = cluster_runs(vol, boot, &chain);
        // An in-use chain's clusters are where its bytes are as far as the walk went, the rest
        // is missing, and how the walk ended says only whether it is whole, as on FAT.
        if !deleted {
            return Ok((cut(runs, len), Ending::Walked(end)));
        }
        // A deleted file's chain is only believed whole and while none of it is now used. A
        // piece of valid clusters always has an end and a length in bytes; one that has not is
        // no chain to believe.
        let believable = end != End::Broken
            && chain.iter().all(|&(start, n)| {
                start
                    .checked_add(n)
                    .is_some_and(|end| tables.used(start, end) == Some(0))
            });
        if believable && runs_len(&runs).is_some_and(|held| held >= len) {
            return Ok((cut(runs, len), Ending::Walked(end)));
        }
    }
    Ok((cut(boot.runs(vol, first, len), len), Ending::Stated))
}

struct Set {
    name: String,
    attr: u16,
    deleted: bool,
    modified: Option<Modified>,
    contiguous: bool,
    first: u64,
    len: u64,
    valid_len: u64,
}

/// Entry sets in a folder's bytes: a file entry (0x85, or 0x05 deleted), its stream
/// extension and its name entries, all in use or all not; with the allocation bitmap's entry,
/// and whether they ended on the end marker.
fn sets(bytes: &[u8]) -> (Vec<Set>, Option<(u64, u64)>, bool) {
    let entries: Vec<&[u8]> = bytes.as_chunks::<32>().0.iter().map(|e| &e[..]).collect();
    let mut out = Vec::new();
    let mut bitmap = None;
    let mut i = 0;
    while i < entries.len() {
        let e = entries[i];
        match e[0] {
            0x00 => return (out, bitmap, true),
            0x81 if bitmap.is_none() && e[1] & 1 == 0 => {
                bitmap = Some((u64::from(le32(e, 0x14)), le64(e, 0x18)));
            }
            0x85 | 0x05 => {
                let deleted = e[0] == 0x05;
                let secondary = e[1] as usize;
                let stream_type = if deleted { 0x40 } else { 0xC0 };
                let name_type = if deleted { 0x41 } else { 0xC1 };
                let set = entries
                    .get(count::add(i, 1)..)
                    .and_then(|rest| rest.get(..secondary));
                let stream = set.and_then(|s| s.first()).filter(|s| s[0] == stream_type);
                if let (true, Some(set), Some(stream)) =
                    ((2..=18).contains(&secondary), set, stream)
                {
                    let name_len = stream[3] as usize;
                    let mut units: Vec<u16> = Vec::new();
                    for n in set[1..].iter().take_while(|n| n[0] == name_type) {
                        for c in n[2..32].as_chunks::<2>().0 {
                            units.push(u16::from_le_bytes([c[0], c[1]]));
                        }
                    }
                    units.truncate(name_len);
                    let name = String::from_utf16_lossy(&units);
                    if !name.is_empty() && units.len() == name_len {
                        let stamp = le32(e, 0x0C);
                        out.push(Set {
                            name,
                            attr: le16(e, 4),
                            deleted,
                            modified: Modified::from_dos((stamp >> 16) as u16, stamp as u16),
                            contiguous: stream[1] & 2 != 0,
                            first: u64::from(le32(stream, 0x14)),
                            len: le64(stream, 0x18),
                            valid_len: le64(stream, 0x08),
                        });
                        i = count::add(i, count::add(1, secondary));
                        continue;
                    }
                }
            }
            _ => {}
        }
        i = count::add(i, 1);
    }
    (out, bitmap, false)
}

struct Walk<'t> {
    boot: Boot,
    tables: &'t Tables,
    seen: HashSet<u64>,
    listing: Listing,
    /// Folders not read in full: a broken chain, an unreadable area or a part outside the
    /// volume.
    unreadable: u64,
}

impl Walk<'_> {
    /// Lists a folder laid out as `layout` and those below it, within `budget`: each entry set
    /// counted, each file listed charged as held, a folder deeper than the budget's depth left
    /// out and counted. Refused once the budget is spent; what was listed stays.
    fn walk(
        &mut self,
        vol: &mut Vol,
        layout: Layout,
        folder: Vec<Part>,
        budget: &mut Budget,
        progress: &Progress,
    ) -> Result<(), Limit> {
        if !budget.within_depth(folder.len()) {
            return Ok(());
        }
        // Charged as it is read; the charge goes with it into `bytes`, freed once the
        // folder's entries are read.
        let read = read_structure(vol, budget, &layout, MAX_DIR, self.boot.cluster)?;
        if !read.whole {
            self.unreadable = count::add(self.unreadable, 1);
        }
        let found = read.entries(|part| {
            let (found, _, ended) = sets(part);
            (found, ended)
        });
        budget.free(read.bytes.len() as u64);
        drop(read);
        let boot = self.boot;
        for s in found {
            budget.item()?;
            let (runs, ending) = content_runs(
                vol,
                &boot,
                self.tables,
                s.first,
                s.len,
                s.contiguous,
                s.deleted,
                budget,
            )?;
            if s.attr & 0x10 != 0 {
                if s.len == 0 || !self.seen.insert(s.first) {
                    continue;
                }
                let mut sub = folder.clone();
                sub.push(Part {
                    name: s.name,
                    deleted: s.deleted,
                });
                // The folder declares its size, and its chain or that size ends it.
                let layout = Layout {
                    runs,
                    extent: s.len,
                    ending,
                };
                self.walk(vol, layout, sub, budget, progress)?;
                continue;
            }
            // Past the valid data length the content was never written.
            let runs = match s.len.checked_sub(s.valid_len).filter(|n| *n > 0) {
                Some(unwritten) => {
                    let mut head = cut(runs, s.valid_len);
                    head.push(Run {
                        place: Place::Zeros,
                        len: unwritten,
                    });
                    tidy(head)
                }
                None => runs,
            };
            let state = match (&self.tables.bitmap, s.deleted) {
                (Some(used), true) => {
                    overwritten(&runs, vol.start, boot.heap, boot.cluster, 2, used)
                }
                (None, true) if runs.iter().any(|r| matches!(r.place, Place::At(_))) => {
                    State::Unknown
                }
                _ => State::Intact,
            };
            let broken = matches!(ending, Ending::Walked(End::Broken));
            let note = (broken && !s.deleted).then(|| "its cluster chain is broken".to_string());
            let found = Found {
                name: s.name,
                folder: folder.clone(),
                size: s.len,
                modified: s.modified,
                deleted: s.deleted,
                state,
                data: Data::Runs(runs),
                damaged: note.is_some(),
                note,
                why: None,
            };
            budget.hold(found.held())?;
            self.listing.files.push(found);
            progress
                .found
                .store(self.listing.files.len() as u64, Ordering::Relaxed);
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// The value of a table entry that ends a chain.
const END_OF_CHAIN: u64 = 0xFFFF_FFFF;

/// The root folder as its chain lays it out, followed as far as a folder is read: whole only
/// when the chain ends on its end-of-chain marker, not on an entry the table cannot give, a
/// free or bad cluster, or the cap.
fn root_layout(
    vol: &Vol,
    boot: &Boot,
    tables: &Tables,
    budget: &mut Budget,
) -> Result<Layout, Limit> {
    let most = MAX_DIR.checked_div(boot.cluster).unwrap_or(0);
    let (chain, taken, end) = tables.chain(boot, boot.root, most, budget)?;
    Ok(Layout {
        runs: cluster_runs(vol, boot, &chain),
        extent: count::mul(taken, boot.cluster),
        ending: Ending::Walked(end),
    })
}

/// Lists the volume's files, deleted and in use, within `budget` (made from `LIMITS`).
pub fn scan(vol: &mut Vol, budget: &mut Budget, progress: &Progress) -> Result<Listing, String> {
    // A refusal is the budget's own, which `fs::scan` says.
    let Ok(bytes) = vol.read(budget, 0, 512) else {
        return Ok(Listing::default());
    };
    budget.free(512);
    let bytes = bytes.ok_or("the boot sector could not be read")?;
    let boot = Boot::parse(&bytes).ok_or("the boot sector is not an exFAT boot sector")?;
    boot.check()?;
    let mut listing = Listing::default();
    // A table the volume cuts short is read as far as it goes and is not whole.
    let fat_len = boot.fat_read_len();
    // The tables are charged as they are read, before they are made.
    let (fat, fat_whole) = if fat_len <= MAX_TABLE {
        vol.read_lossy(budget, boot.fat_at, fat_len as usize)
            .unwrap_or_else(|_| (Vec::new(), false))
    } else {
        listing.notes.push(format!(
            "The allocation table is {} bytes, more than this tool reads; fragmented files are taken as contiguous.",
            fat_len
        ));
        (Vec::new(), false)
    };
    let mut tables = Tables {
        fat,
        fat_whole,
        bitmap: None,
    };
    // The root's own chain, then the bitmap named in it.
    // A refusal is the budget's own, which `fs::scan` says.
    let Ok(root) = root_layout(vol, &boot, &tables, budget) else {
        budget.free(tables.fat.len() as u64);
        return Ok(listing);
    };
    let root_at = root.runs.first().and_then(|r| match r.place {
        Place::At(at) => vol.offset(at),
        Place::Zeros | Place::Missing => None,
    });
    if let Some(offset) = root_at {
        let first = vol
            .read_lossy(budget, offset, boot.cluster as usize)
            .map(|(first, _)| first)
            .unwrap_or_default();
        budget.free(boot.cluster);
        if let (_, Some((cluster, len)), _) = sets(&first) {
            let len = len.min(boot.bitmap_len());
            if let (Some(at), true) = (boot.cluster_at(cluster), len <= MAX_TABLE) {
                if let Ok((bits, whole)) = vol.read_lossy(budget, at, len as usize) {
                    if !whole {
                        budget.free(len);
                    }
                    tables.bitmap = whole.then(|| used_of(&boot, bits));
                }
            }
        }
    }
    if tables.bitmap.is_none() {
        listing.notes.push(
            "The allocation bitmap could not be read, so deleted files' state is unknown.".into(),
        );
    }
    let mut walk = Walk {
        boot,
        tables: &tables,
        seen: HashSet::from([boot.root]),
        listing,
        unreadable: 0,
    };
    // The tables are held while the folders are walked. A refusal is the budget's own,
    // which `fs::scan` says.
    let fat_held = tables.fat.len() as u64;
    let held = count::add(fat_held, tables.bitmap.as_ref().map_or(0, Used::held));
    // What was charged as it was read is charged again whole, with what was made from it.
    budget.free(count::add(
        fat_held,
        tables.bitmap.as_ref().map_or(0, Used::bits_len),
    ));
    let walked = budget
        .hold(held)
        .and_then(|()| walk.walk(vol, root, Vec::new(), budget, progress));
    debug_assert!(walked.is_ok() || budget.hit().is_some());
    let mut listing = walk.listing;
    listing.notes.extend(incomplete_folders(walk.unreadable));
    Ok(listing)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::recovery::fs::{self, test_source, FsKind, Origin, Volume};
    use std::sync::atomic::AtomicBool;

    /// An exFAT boot sector: 512-byte sectors, 4 KiB clusters, one table at sector 128 of
    /// `fat_sectors`, the heap right after it, `clusters` clusters and the root at cluster 2.
    fn boot_sector(total: u64, fat_sectors: u32, clusters: u32) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[3..11].copy_from_slice(b"EXFAT   ");
        b[0x48..0x50].copy_from_slice(&total.to_le_bytes());
        b[0x50..0x54].copy_from_slice(&128u32.to_le_bytes());
        b[0x54..0x58].copy_from_slice(&fat_sectors.to_le_bytes());
        b[0x58..0x5C].copy_from_slice(&(128 + fat_sectors).to_le_bytes());
        b[0x5C..0x60].copy_from_slice(&clusters.to_le_bytes());
        b[0x60..0x64].copy_from_slice(&2u32.to_le_bytes());
        b[0x6C] = 9;
        b[0x6D] = 3;
        b[0x6E] = 1;
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    fn scan_of(boot: Vec<u8>) -> (Result<Listing, String>, u64) {
        let (mut reader, read) = test_source(boot, 1 << 40);
        let volume = Volume {
            kind: FsKind::ExFat,
            start: 0,
            len: 1 << 40,
            origin: Origin::Whole,
            claims: Vec::new(),
        };
        let never = AtomicBool::new(false);
        let listing = fs::scan(&mut reader, &volume, &never, &Progress::default());
        (listing, read.load(Ordering::Relaxed))
    }

    /// One entry set: a file or folder named `name`, contiguous from cluster `first` for
    /// `len` bytes.
    fn set(name: &str, folder: bool, first: u32, len: u64) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(15);
        let mut e = vec![0u8; 32 * (2 + names)];
        e[0] = 0x85;
        e[1] = (1 + names) as u8;
        e[4] = if folder { 0x10 } else { 0x20 };
        e[32] = 0xC0;
        e[33] = 0x03;
        e[35] = units.len() as u8;
        e[40..48].copy_from_slice(&len.to_le_bytes());
        e[52..56].copy_from_slice(&first.to_le_bytes());
        e[56..64].copy_from_slice(&len.to_le_bytes());
        for (i, u) in units.iter().enumerate() {
            let at = 64 + (i / 15) * 32;
            e[at] = 0xC1;
            e[at + 2 + (i % 15) * 2..at + 4 + (i % 15) * 2].copy_from_slice(&u.to_le_bytes());
        }
        e
    }

    /// An exFAT volume of 1,024 clusters of 4 KiB: the root at cluster 2 holds the folder
    /// DEEP, a chain of `depth` folders each in the one before, and BIG, 128 clusters of
    /// empty files with long names.
    pub(crate) fn forged_exfat(depth: u32) -> Vec<u8> {
        let mut v = boot_sector(137 + 1024 * 8, 9, 1024);
        v.resize((137 + 1024 * 8) * 512, 0);
        let fat = 128 * 512;
        let cluster = |n: u32| (137 * 512) + (n as usize - 2) * 4096;
        v[fat + 8..fat + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut root = set("DEEP", true, 3, 4096);
        root.extend(set("BIG", true, 300, 128 * 4096));
        let at = cluster(2);
        v[at..at + root.len()].copy_from_slice(&root);
        for k in 0..depth.saturating_sub(1) {
            let at = cluster(3 + k);
            let e = set("D", true, 4 + k, 4096);
            v[at..at + e.len()].copy_from_slice(&e);
        }
        let mut big = Vec::new();
        let mut n = 0;
        loop {
            let e = set(&format!("{n:0>40}.txt"), false, 0, 0);
            if big.len() + e.len() > 128 * 4096 {
                break;
            }
            big.extend(e);
            n += 1;
        }
        let at = cluster(300);
        v[at..at + big.len()].copy_from_slice(&big);
        v
    }

    fn scan_exfat(image: Vec<u8>, limits: Limits, stop: bool) -> (Listing, Budget<'static>) {
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

    /// The guard: an exFAT volume of folders nested far past the depth and a folder of
    /// thousands of files is read to its budget and no further: the deep folders are left
    /// out and said, and the count, the memory and a stop each end the walk with what it
    /// found listed.
    #[test]
    fn a_forged_exfat_volume_stops_within_its_budget() {
        let started = std::time::Instant::now();
        let (whole, budget) = scan_exfat(forged_exfat(200), LIMITS, false);
        assert!(whole.files.len() > 3000, "{}", whole.files.len());
        assert_eq!(budget.hit(), None);
        assert_eq!(budget.spent().too_deep, 1);
        let said = budget.said().unwrap();
        assert!(said.contains("lay more than 64 deep"), "{said}");

        let small = Limits {
            count: 1000,
            ..LIMITS
        };
        let (listing, budget) = scan_exfat(forged_exfat(200), small, false);
        assert_eq!(budget.hit(), Some(Limit::Count));
        assert!(budget.spent().count <= 1000 && listing.files.len() < 1000);

        // The 512 KiB folder is charged while it is read, then what it lists.
        let small = Limits {
            memory: 768 << 10,
            ..LIMITS
        };
        let (listing, budget) = scan_exfat(forged_exfat(200), small, false);
        assert_eq!(budget.hit(), Some(Limit::Memory));
        assert!(budget.spent().peak <= 768 << 10);
        assert!(!listing.files.is_empty() && listing.files.len() < whole.files.len());

        let (listing, budget) = scan_exfat(forged_exfat(200), LIMITS, true);
        assert_eq!(budget.hit(), Some(Limit::Stopped));
        assert!(listing.files.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    /// The guard (review R4-1): a folder whose clusters run past the end of a source cut
    /// short is listed with what was read, and the listing says a folder could not be read in
    /// full, never taking the part outside the volume for the folder's end.
    #[test]
    fn a_folder_cut_short_by_the_source_is_said_to_be_incomplete() {
        let (whole, _) = scan_exfat(forged_exfat(1), LIMITS, false);
        assert!(whole
            .notes
            .iter()
            .all(|n| !n.contains("could not be read in full")));
        let mut image = forged_exfat(1);
        // BIG's 128 clusters start at cluster 300; the source ends 64 clusters in.
        image.truncate(137 * 512 + 298 * 4096 + 64 * 4096);
        let (cut, _) = scan_exfat(image, LIMITS, false);
        assert!(
            cut.notes
                .iter()
                .any(|n| n.starts_with("1 folders could not be read in full")),
            "{:?}",
            cut.notes
        );
        assert!(!cut.files.is_empty() && cut.files.len() < whole.files.len());
    }

    /// The guard (review R4-1, round 5): a root folder whose chain ends on a table entry that
    /// could not be read did not end on its end-of-chain marker, so it is said to be
    /// incomplete, never taken as whole; what it holds is still listed.
    #[test]
    fn a_root_chain_ending_on_an_unread_entry_is_said_to_be_incomplete() {
        let incomplete = |listing: &Listing| {
            listing
                .notes
                .iter()
                .any(|n| n.starts_with("1 folders could not be read in full"))
        };
        let (whole, _) = scan_exfat(forged_exfat(1), LIMITS, false);
        assert!(!incomplete(&whole), "{:?}", whole.notes);
        // The table starts at sector 128 and holds the root's entry for cluster 2.
        let mut disk = crate::recovery::MemDisk::new(forged_exfat(1));
        disk.bad.push(128 * 512..129 * 512);
        let (unread, _) = scan_disk(disk, LIMITS, false);
        assert!(incomplete(&unread), "{:?}", unread.notes);
        assert_eq!(unread.files.len(), whole.files.len());
    }

    /// The guard (review R4-1, round 6): a chained folder whose stated size fits one cluster
    /// is whole only when that cluster's table entry is the end-of-chain marker; one whose
    /// entry points onward, or could not be read, is said to be incomplete, and what it holds
    /// is still listed.
    #[test]
    fn a_chained_folder_is_whole_only_when_its_last_entry_ends_the_chain() {
        let incomplete = |listing: &Listing| {
            listing
                .notes
                .iter()
                .any(|n| n.starts_with("1 folders could not be read in full"))
        };
        // The root's third set is ONE, a folder chained from the last cluster, 1,025, for one
        // cluster, which holds the file inner.txt.
        let image = |entry: u32| {
            let mut v = forged_exfat(1);
            let cluster = |n: usize| 137 * 512 + (n - 2) * 4096;
            let mut one = set("ONE", true, 1025, 4096);
            one[33] = 0x01;
            v[cluster(2) + 192..cluster(2) + 192 + one.len()].copy_from_slice(&one);
            let inner = set("inner.txt", false, 0, 0);
            v[cluster(1025)..cluster(1025) + inner.len()].copy_from_slice(&inner);
            let at = 128 * 512 + 1025 * 4;
            v[at..at + 4].copy_from_slice(&entry.to_le_bytes());
            v
        };
        let listed = |listing: &Listing| listing.files.iter().any(|f| f.name == "inner.txt");
        let (ended, _) = scan_exfat(image(u32::MAX), LIMITS, false);
        assert!(!incomplete(&ended) && listed(&ended), "{:?}", ended.notes);
        let (onward, _) = scan_exfat(image(1024), LIMITS, false);
        assert!(incomplete(&onward) && listed(&onward), "{:?}", onward.notes);
        // The table's sector that holds cluster 1,025's entry, and no other folder's, cannot
        // be read.
        let mut disk = crate::recovery::MemDisk::new(image(u32::MAX));
        disk.bad.push(136 * 512..137 * 512);
        let (unread, _) = scan_disk(disk, LIMITS, false);
        assert!(incomplete(&unread) && listed(&unread), "{:?}", unread.notes);
    }

    /// The guard (review R5-1, round 7): an in-use chain whose last entry cannot be read keeps
    /// the clusters its walk took; it is damaged, and its bytes are never guessed contiguous.
    #[test]
    fn a_broken_chain_keeps_the_clusters_its_walk_took() {
        // FRAG is two clusters, 1,000 then 1,025; the table's sector holding 1,025's entry,
        // and no other chain's, cannot be read.
        let cluster = |n: usize| 137 * 512 + (n - 2) * 4096;
        let mut v = forged_exfat(1);
        let mut frag = set("FRAG", false, 1000, 8192);
        frag[33] = 0x01;
        v[cluster(2) + 192..cluster(2) + 192 + frag.len()].copy_from_slice(&frag);
        let link = |v: &mut Vec<u8>, n: usize, next: u32| {
            let at = 128 * 512 + n * 4;
            v[at..at + 4].copy_from_slice(&next.to_le_bytes());
        };
        link(&mut v, 1000, 1025);
        link(&mut v, 1025, u32::MAX);
        let mut disk = crate::recovery::MemDisk::new(v);
        disk.bad.push(136 * 512..137 * 512);
        let (listing, _) = scan_disk(disk, LIMITS, false);
        let f = listing.files.iter().find(|f| f.name == "FRAG").unwrap();
        assert!(f.damaged, "{f:?}");
        let Data::Runs(runs) = &f.data else {
            panic!("{f:?}")
        };
        let at = |n: usize| Place::At(cluster(n) as u64);
        let want = [(at(1000), 4096), (at(1025), 4096)];
        let got: Vec<_> = runs.iter().map(|r| (r.place, r.len)).collect();
        assert_eq!(got, want, "{f:?}");
    }

    /// The guard: the allocation table is read as far as the cluster count needs, not as
    /// far as the boot sector says it runs (here 200 MiB for 1,000 clusters).
    #[test]
    fn an_oversized_table_is_read_only_as_far_as_the_clusters_go() {
        let (listing, read) = scan_of(boot_sector(1 << 31, 409_600, 1000));
        assert!(listing.is_ok(), "{:?}", listing.err());
        assert!(read < 1 << 20, "{read} bytes read for 1,000 clusters");
    }

    /// The guard: a boot sector whose values cannot all be true is reported, not used.
    #[test]
    fn a_boot_sector_whose_values_disagree_is_reported() {
        // 2^31 clusters of 4 KiB do not fit in a 1 TiB volume.
        let (listing, read) = scan_of(boot_sector(1 << 31, 16_777_217, 1 << 31));
        let err = listing.unwrap_err();
        assert!(
            err.contains("values disagree") && err.contains("do not fit"),
            "{err}"
        );
        assert!(
            read <= 4096,
            "{read} bytes read from a boot sector not believed"
        );
        let mut fats = boot_sector(1 << 31, 614_400, 1000);
        fats[0x58..0x5C].copy_from_slice(&200u32.to_le_bytes());
        let err = scan_of(fats).0.unwrap_err();
        assert!(err.contains("run into the cluster heap"), "{err}");
    }

    /// The guard: a chain that loops is cut once it has more pieces than any file may have,
    /// instead of taking memory for every step a damaged size asks for.
    #[test]
    fn a_looping_chain_is_cut_at_the_fragment_limit() {
        let boot = Boot::parse(&boot_sector(1 << 31, 614_400, 1 << 28)).unwrap();
        let mut fat = vec![0u8; 5 * 4];
        fat[8..12].copy_from_slice(&4u32.to_le_bytes());
        fat[16..20].copy_from_slice(&2u32.to_le_bytes());
        let tables = Tables {
            fat,
            fat_whole: true,
            bitmap: None,
        };
        let mut budget = Budget::new(LIMITS, None);
        assert_eq!(
            tables.chain(&boot, 2, 3, &mut budget),
            Ok((vec![(2, 1), (4, 1), (2, 1)], 3, End::Limit))
        );
        let (pieces, _, end) = tables.chain(&boot, 2, 1 << 24, &mut budget).unwrap();
        assert_eq!((pieces.len(), end), (MAX_FRAGMENTS, End::Broken));
    }
}
