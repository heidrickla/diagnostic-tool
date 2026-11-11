//! Finding volumes: the MBR (with its extended chain) and GPT partition tables, then a
//! search for NTFS, FAT and exFAT boot sectors where partitions start (each 1 MiB) or in
//! every sector. An NTFS volume whose first boot sector is gone is found by the backup copy
//! in its last sector.
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{count, identify, le16, le32, le64, ntfs, Claim, FsKind, Origin, Progress, Volume};
use crate::budget::{Budget, Limit, Limits};
use crate::recovery::reader::{Reader, CHUNK};
use crate::tools::drives::bytes_text;

const MIB: u64 = 1 << 20;

/// What a search for volumes may spend: 4,096 volumes found, far past any real disk's
/// (a damaged or forged disk can hold a boot sector in every sector, each of which would
/// be one); 128 logical partitions in an extended partition's chain, past the most any
/// tool makes. Bytes are not limited: the search reads the source once, and one more
/// sector for each boot sector it confirms, so at most twice. No clock limit: the
/// technician starts the search and watches it with a Stop button, checked at every 1 MiB
/// step or chunk read.
pub const LIMITS: Limits = Limits {
    what: "the search for volumes",
    unit: "volumes",
    count: 4096,
    bytes: u64::MAX,
    memory: u64::MAX,
    depth: 128,
    nested: "logical partitions",
    time: None::<Duration>,
};

/// How far to look beyond the partition tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Search {
    Tables,
    /// Every 1 MiB, where partitions start, and the sector before, where NTFS keeps its
    /// backup boot sector.
    Aligned,
    Every,
}

/// A partition table entry.
struct Entry {
    origin: Origin,
    start: u64,
    len: u64,
}

fn mbr_entries(
    reader: &mut Reader,
    notes: &mut Vec<String>,
    budget: &mut Budget,
) -> (Vec<Entry>, bool) {
    let Some(mbr) = reader.read(0, 512) else {
        notes.push("The first sector, which holds the partition table, could not be read.".into());
        return (Vec::new(), false);
    };
    if mbr[510..512] != [0x55, 0xAA] {
        return (Vec::new(), false);
    }
    let mut out = Vec::new();
    let mut gpt = false;
    let mut extended = None;
    for (n, e) in (1..).zip(mbr[446..510].as_chunks::<16>().0) {
        let (kind, lba, count) = (e[4], u64::from(le32(e, 8)), u64::from(le32(e, 12)));
        match kind {
            0 => {}
            0xEE => gpt = true,
            0x05 | 0x0F | 0x85 => extended = Some(lba),
            // 32-bit sector numbers and counts: always a place and a length.
            _ if count > 0 => {
                if let (Some(start), Some(len)) = (lba.checked_mul(512), count.checked_mul(512)) {
                    out.push(Entry {
                        origin: Origin::Mbr(n),
                        start,
                        len,
                    });
                }
            }
            _ => {}
        }
    }
    // Logical partitions: each EBR's first entry is a partition relative to that EBR, the
    // second points at the next EBR relative to the extended partition.
    if let Some(base) = extended {
        let mut ebr = base;
        for n in 0.. {
            if !budget.within_depth(n) || budget.tick().is_err() {
                break;
            }
            // Sums of two 32-bit sector numbers: a place past the address space is no table.
            let Some(b) = ebr.checked_mul(512).and_then(|at| reader.read(at, 512)) else {
                notes.push("Part of the extended partition table could not be read.".into());
                break;
            };
            if b[510..512] != [0x55, 0xAA] {
                break;
            }
            let (e1, e2) = (&b[446..462], &b[462..478]);
            let start = ebr
                .checked_add(u64::from(le32(e1, 8)))
                .and_then(|lba| lba.checked_mul(512));
            let len = u64::from(le32(e1, 12)).checked_mul(512);
            if let (Some(start), Some(len), true) = (start, len, e1[4] != 0 && le32(e1, 12) > 0) {
                out.push(Entry {
                    origin: Origin::Mbr(count::add(n, 5)),
                    start,
                    len,
                });
            }
            let next = u64::from(le32(e2, 8));
            if e2[4] == 0 || next == 0 {
                break;
            }
            let Some(at) = base.checked_add(next) else {
                break;
            };
            ebr = at;
        }
    }
    (out, gpt)
}

fn gpt_entries(reader: &mut Reader, notes: &mut Vec<String>) -> Vec<Entry> {
    for sector in [512u64, 4096] {
        let last = reader.len().checked_div(sector).unwrap_or(0);
        for header_lba in [Some(1), last.checked_sub(1)].into_iter().flatten() {
            let Some(h) = header_lba
                .checked_mul(sector)
                .and_then(|at| reader.read(at, 92))
            else {
                continue;
            };
            if &h[..8] != b"EFI PART" {
                continue;
            }
            let (lba, count, size) = (le64(&h, 72), le32(&h, 80) as u64, le32(&h, 84) as u64);
            if !(128..=4096).contains(&size) || count == 0 || count > 1024 {
                continue;
            }
            let Some(at) = lba.checked_mul(sector) else {
                continue;
            };
            // At most 1,024 entries of 4 KiB.
            let table = count
                .checked_mul(size)
                .and_then(|bytes| reader.read(at, bytes as usize));
            let Some(table) = table else {
                notes.push("Part of the GPT partition table could not be read.".into());
                continue;
            };
            let mut out = Vec::new();
            for (n, e) in (1..).zip(table.chunks_exact(size as usize)) {
                if e[..16].iter().all(|b| *b == 0) {
                    continue;
                }
                let (first, end) = (le64(e, 32), le64(e, 40));
                let start = first.checked_mul(sector);
                let len = end
                    .checked_sub(first)
                    .and_then(|n| n.checked_add(1))
                    .and_then(|n| n.checked_mul(sector));
                if let (Some(start), Some(len)) = (start, len) {
                    out.push(Entry {
                        origin: Origin::Gpt(n),
                        start,
                        len,
                    });
                }
            }
            return out;
        }
    }
    notes.push("The disk says it uses GPT, but neither GPT header could be read.".into());
    Vec::new()
}

/// Checks a boot sector found at `at` against what it points to, so a stray copy or a
/// FAT32 backup boot sector is not taken for a volume. Returns the volume start.
fn confirm(reader: &mut Reader, at: u64, boot: &[u8], kind: FsKind) -> Option<u64> {
    match kind {
        FsKind::Ntfs => {
            let b = ntfs::Boot::parse(boot)?;
            let has_mft = |reader: &mut Reader, start: u64| {
                b.mft_lcn
                    .checked_mul(b.cluster)
                    .and_then(|mft| start.checked_add(mft))
                    .and_then(|mft| reader.read(mft, 512))
                    .is_some_and(|r| r.starts_with(b"FILE"))
            };
            if has_mft(reader, at) {
                return Some(at);
            }
            // The backup boot sector sits after the volume's last cluster.
            let start = at.checked_sub(b.total_sectors.checked_mul(b.sector)?)?;
            has_mft(reader, start).then_some(start)
        }
        FsKind::ExFat => {
            let reserved = u64::from(le32(boot, 0x50)) << boot[0x6C];
            let fat = reader.read(at.checked_add(reserved)?, 512)?;
            (le32(&fat, 0) == 0xFFFF_FFF8).then_some(at)
        }
        _ => {
            let reserved = u64::from(le16(boot, 0x0E)).checked_mul(u64::from(le16(boot, 0x0B)))?;
            let fat = reader.read(at.checked_add(reserved)?, 512)?;
            (fat[0] == boot[0x15] && fat[1] == 0xFF).then_some(at)
        }
    }
}

struct Finder {
    volumes: Vec<Volume>,
    /// The starts taken, so a volume found again is known in one step.
    starts: HashSet<u64>,
}

impl Finder {
    /// Takes a volume not found before, counted against the budget.
    fn add(&mut self, volume: Volume, budget: &mut Budget) -> Result<(), Limit> {
        if self.starts.contains(&volume.start) {
            return Ok(());
        }
        budget.item()?;
        self.starts.insert(volume.start);
        self.volumes.push(volume);
        Ok(())
    }

    /// Looks for a boot sector in `bytes`, read from `at`.
    fn probe(
        &mut self,
        reader: &mut Reader,
        at: u64,
        bytes: &[u8],
        budget: &mut Budget,
    ) -> Result<(), Limit> {
        let Some((kind, len)) = identify(bytes) else {
            return Ok(());
        };
        let Some(start) = confirm(reader, at, bytes, kind) else {
            return Ok(());
        };
        let origin = if start == at {
            Origin::Found
        } else {
            Origin::Backup
        };
        self.add(
            Volume {
                kind,
                start,
                len,
                origin,
                claims: Vec::new(),
            },
            budget,
        )
    }
}

/// A partition table entry whose area holds no file system this module reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    pub origin: Origin,
    pub start: u64,
    pub len: u64,
}

impl Unread {
    /// "Partition 1, 1.2 GB at 0 B: no file system this tool reads".
    pub fn describe(&self) -> String {
        let name = match self.origin {
            Origin::Mbr(n) | Origin::Gpt(n) => format!("Partition {n}"),
            _ => "A partition".into(),
        };
        format!(
            "{name}, {} at {}: no file system this tool reads",
            bytes_text(self.len),
            bytes_text(self.start)
        )
    }
}

/// What a search found: the volumes, the partitions with nothing readable, and what kept
/// the search from looking everywhere.
#[derive(Debug, Default)]
pub struct Finds {
    pub volumes: Vec<Volume>,
    pub unread: Vec<Unread>,
    /// About the search as a whole: an unreadable table, a stop before the end.
    pub notes: Vec<String>,
}

/// Finds the volumes on a source, within `LIMITS`, stopped by `cancel`.
pub fn find(
    reader: &mut Reader,
    search: Search,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Finds {
    let mut budget = Budget::new(LIMITS, Some(cancel));
    find_within(reader, search, &mut budget, progress)
}

/// Finds the volumes on a source within `budget`, saying in its notes the limit it
/// reached, if one.
pub fn find_within(
    reader: &mut Reader,
    search: Search,
    budget: &mut Budget,
    progress: &Progress,
) -> Finds {
    let mut notes = Vec::new();
    let mut finder = Finder {
        volumes: Vec::new(),
        starts: HashSet::new(),
    };
    // Every current partition entry, readable or not, for what now lies over lost volumes.
    let mut claims = Vec::new();
    let mut unread = Vec::new();
    // A source that is itself one volume, such as an image of a partition or a memory card
    // with no table.
    if let Some(first) = reader.read(0, 512) {
        if let Some((kind, len)) = identify(&first) {
            // The first volume found always fits the budget.
            let whole = Volume {
                kind,
                start: 0,
                len,
                origin: Origin::Whole,
                claims: Vec::new(),
            };
            if finder.add(whole, budget).is_err() {
                notes.extend(budget.said());
                return Finds {
                    volumes: finder.volumes,
                    unread: Vec::new(),
                    notes,
                };
            }
        }
    }
    if finder.volumes.is_empty() {
        let (mut entries, gpt) = mbr_entries(reader, &mut notes, budget);
        if gpt {
            entries = gpt_entries(reader, &mut notes);
        }
        for e in entries {
            // An entry whose end would pass the address space lies on no source.
            if let (Origin::Mbr(n) | Origin::Gpt(n), Some(end)) =
                (&e.origin, e.start.checked_add(e.len))
            {
                claims.push(Claim {
                    name: format!("partition {n}"),
                    range: e.start..end,
                });
            }
            let boot = reader.read(e.start, 512);
            let mut found = boot.as_deref().and_then(identify);
            // A table entry whose first boot sector is gone may still have NTFS's backup.
            if found.is_none() && e.len >= 1024 {
                let backup = e
                    .len
                    .checked_sub(512)
                    .and_then(|last| e.start.checked_add(last))
                    .and_then(|at| reader.read(at, 512));
                found = backup
                    .as_deref()
                    .and_then(identify)
                    .filter(|(k, _)| *k == FsKind::Ntfs);
            }
            match found {
                Some((kind, _)) => {
                    let volume = Volume {
                        kind,
                        start: e.start,
                        len: e.len,
                        origin: e.origin.clone(),
                        claims: Vec::new(),
                    };
                    if finder.add(volume, budget).is_err() {
                        break;
                    }
                }
                None => unread.push(Unread {
                    origin: e.origin,
                    start: e.start,
                    len: e.len,
                }),
            }
        }
    }
    let len = reader.len();
    match search {
        Search::Tables => {}
        Search::Aligned => {
            let steps = len / MIB;
            for k in 1..=steps {
                if budget.tick().is_err() || reader.gone().is_some() {
                    break;
                }
                // `k` MiB is at least 1 MiB and at most the source's length.
                let place = k.checked_mul(MIB).and_then(|step| {
                    let at = step.checked_sub(512)?;
                    Some((step, at, len.checked_sub(at)?))
                });
                let Some((step, at, left)) = place else {
                    break;
                };
                let lossy = reader.read_lossy(at, 1024.min(left as usize));
                let found = finder
                    .probe(reader, at, &lossy.data[..512], budget)
                    .and_then(|()| match lossy.data.len() >= 1024 {
                        true => finder.probe(reader, step, &lossy.data[512..], budget),
                        false => Ok(()),
                    });
                if found.is_err() {
                    break;
                }
                progress.set(k, steps);
            }
        }
        Search::Every => {
            let sector = reader.sector().max(512);
            let mut at = 0;
            'chunks: while at < len {
                if budget.tick().is_err() || reader.gone().is_some() {
                    break;
                }
                // Places within the source, which is no longer than the address space.
                let n = len.checked_sub(at).map_or(0, |left| left.min(CHUNK));
                let lossy = reader.read_lossy(at, n as usize);
                for (s, sector_at) in lossy
                    .data
                    .chunks_exact(sector as usize)
                    .zip((at..).step_by(sector as usize))
                {
                    let found = match s[510..512] == [0x55, 0xAA] {
                        true => finder.probe(reader, sector_at, s, budget),
                        false => Ok(()),
                    };
                    if found.is_err() {
                        break 'chunks;
                    }
                }
                let Some(next) = at.checked_add(n).filter(|_| n > 0) else {
                    break;
                };
                at = next;
                progress.set(at, len);
            }
        }
    }
    notes.extend(budget.said());
    if let Some(why) = reader.gone() {
        notes.push(format!("The search stopped: {why}."));
    }
    let mut volumes = finder.volumes;
    volumes.sort_by_key(|v| v.start);
    for v in volumes.iter_mut().filter(|v| v.is_lost()) {
        // Overlap with the volume's `len` bytes from its start, counted without forming an
        // end that could pass the address space.
        let before_end = |at: u64| at.checked_sub(v.start).is_none_or(|into| into < v.len);
        v.claims = claims
            .iter()
            .filter(|c| {
                let own = c.range.start == v.start
                    && c.range.end.checked_sub(c.range.start) == Some(v.len);
                before_end(c.range.start) && v.start < c.range.end && !own
            })
            .cloned()
            .collect();
    }
    progress
        .found
        .store(volumes.len() as u64, Ordering::Relaxed);
    Finds {
        volumes,
        unread,
        notes,
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::recovery::MemDisk;

    /// The guard: a source of 8 MiB whose every other sector is a FAT boot sector with its
    /// table after it, so each confirms as a volume, is searched to the budget's count of
    /// volumes and no further, each new volume known in one step, and says so; a stop is
    /// seen at once.
    #[test]
    fn a_disk_of_forged_boot_sectors_stops_at_the_volume_limit() {
        let boot = crate::recovery::fs::fat::tests::forged_fat(1, 1)[..512].to_vec();
        let mut disk = Vec::with_capacity(8 << 20);
        while disk.len() < 8 << 20 {
            disk.extend(&boot);
            let mut table = vec![0u8; 512];
            table[..4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
            disk.extend(table);
        }
        let started = std::time::Instant::now();
        let mut reader = Reader::new(Box::new(MemDisk::new(disk.clone())));
        let never = AtomicBool::new(false);
        let finds = find(&mut reader, Search::Every, &never, &Progress::default());
        assert_eq!(finds.volumes.len(), 4096);
        let said = finds.notes.join(" ");
        assert!(said.contains("limit of 4,096 volumes"), "{said}");
        assert!(started.elapsed() < std::time::Duration::from_secs(20));

        let stop = AtomicBool::new(true);
        let mut reader = Reader::new(Box::new(MemDisk::new(disk)));
        let finds = find(&mut reader, Search::Every, &stop, &Progress::default());
        assert!(finds.notes.join(" ").contains("was stopped before the end"));
    }
}
