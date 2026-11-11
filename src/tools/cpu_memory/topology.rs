//! Packages, cores, core types and caches from GetLogicalProcessorInformationEx, and each
//! processor's clocks from CallNtPowerInformation. The record parser takes bytes, so a short
//! or malformed buffer is read as far as it holds together and never past its end.
use serde::{Deserialize, Serialize};

/// Cores of one efficiency class: on a hybrid processor the higher class is the
/// performance cores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreClass {
    pub efficiency_class: u8,
    pub cores: u32,
    pub threads: u32,
}

/// Caches of one level, kind and shape, with how many there are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheGroup {
    pub level: u8,
    /// "data", "instruction", "unified" or "trace".
    pub kind: String,
    pub size_bytes: u64,
    /// None when the cache is fully associative.
    pub ways: Option<u8>,
    pub line_bytes: u16,
    pub count: u32,
    /// Logical processors sharing each one.
    pub shared_by_threads: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topology {
    pub packages: u32,
    pub cores: u32,
    pub logical_processors: u32,
    pub numa_nodes: u32,
    pub processor_groups: u32,
    /// One entry per efficiency class, highest first; two or more on a hybrid processor.
    pub core_classes: Vec<CoreClass>,
    pub caches: Vec<CacheGroup>,
}

const CORE: u32 = 0;
const NUMA: u32 = 1;
const CACHE: u32 = 2;
const PACKAGE: u32 = 3;
const GROUP: u32 = 4;
/// Records read at most, whatever the buffer holds.
const MAX_RECORDS: usize = 65_536;

fn u8_at(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Logical processors in `count` GROUP_AFFINITY entries starting at `at` (16 bytes each:
/// an 8-byte mask, the group, reserved words). A count of 0 is read as 1, as older Windows
/// leaves it.
fn threads_in_masks(record: &[u8], at: usize, count: u16) -> u32 {
    (0..usize::from(count.max(1)))
        .filter_map(|i| u64_at(record, at + i * 16))
        .map(u64::count_ones)
        .sum()
}

/// Parses a RelationAll buffer.
pub fn parse(buffer: &[u8]) -> Topology {
    let mut t = Topology::default();
    let mut classes: Vec<CoreClass> = Vec::new();
    let mut caches: Vec<CacheGroup> = Vec::new();
    let mut at = 0usize;
    for _ in 0..MAX_RECORDS {
        let (Some(relation), Some(size)) = (u32_at(buffer, at), u32_at(buffer, at + 4)) else {
            break;
        };
        let size = size as usize;
        if size < 8 || at + size > buffer.len() {
            break;
        }
        let record = &buffer[at..at + size];
        match relation {
            CORE => {
                if let (Some(class), Some(groups)) = (u8_at(record, 9), u16_at(record, 30)) {
                    let threads = threads_in_masks(record, 32, groups);
                    t.cores += 1;
                    t.logical_processors += threads;
                    match classes.iter_mut().find(|c| c.efficiency_class == class) {
                        Some(c) => {
                            c.cores += 1;
                            c.threads += threads;
                        }
                        None => classes.push(CoreClass {
                            efficiency_class: class,
                            cores: 1,
                            threads,
                        }),
                    }
                }
            }
            PACKAGE => t.packages += 1,
            NUMA => t.numa_nodes += 1,
            GROUP => {
                if let Some(active) = u16_at(record, 10) {
                    t.processor_groups = u32::from(active);
                }
            }
            CACHE => {
                let fields = (
                    u8_at(record, 8),
                    u8_at(record, 9),
                    u16_at(record, 10),
                    u32_at(record, 12),
                    u32_at(record, 16),
                    u16_at(record, 38),
                );
                if let (Some(level), Some(ways), Some(line), Some(size), Some(kind), Some(groups)) =
                    fields
                {
                    let kind = match kind {
                        0 => "unified",
                        1 => "instruction",
                        2 => "data",
                        3 => "trace",
                        _ => "other",
                    };
                    let shared = threads_in_masks(record, 40, groups);
                    let ways = (ways != 0xFF).then_some(ways);
                    let size = u64::from(size);
                    match caches.iter_mut().find(|c| {
                        c.level == level
                            && c.kind == kind
                            && c.size_bytes == size
                            && c.ways == ways
                            && c.line_bytes == line
                            && c.shared_by_threads == shared
                    }) {
                        Some(c) => c.count += 1,
                        None => caches.push(CacheGroup {
                            level,
                            kind: kind.into(),
                            size_bytes: size,
                            ways,
                            line_bytes: line,
                            count: 1,
                            shared_by_threads: shared,
                        }),
                    }
                }
            }
            _ => {}
        }
        at += size;
    }
    classes.sort_by_key(|c| std::cmp::Reverse(c.efficiency_class));
    // By level, then data, instruction and unified, larger first.
    caches.sort_by(|a, b| {
        (a.level, a.kind.as_str(), std::cmp::Reverse(a.size_bytes)).cmp(&(
            b.level,
            b.kind.as_str(),
            std::cmp::Reverse(b.size_bytes),
        ))
    });
    t.core_classes = classes;
    t.caches = caches;
    t
}

/// Reads the processor relations from Windows.
pub fn read() -> Result<Topology, String> {
    use windows_sys::Win32::System::SystemInformation::{
        GetLogicalProcessorInformationEx, RelationAll, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
    };
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer; Windows writes only `len`.
    unsafe { GetLogicalProcessorInformationEx(RelationAll, std::ptr::null_mut(), &mut len) };
    if len == 0 || len > 16 << 20 {
        return Err("Windows did not give the processor layout".into());
    }
    // u64 storage keeps the records 8-byte aligned, as the structures need.
    let mut storage = vec![0u64; (len as usize).div_ceil(8)];
    let mut got = (storage.len() * 8) as u32;
    // SAFETY: the buffer holds `got` bytes, which is at least the size Windows asked for.
    let ok = unsafe {
        GetLogicalProcessorInformationEx(
            RelationAll,
            storage
                .as_mut_ptr()
                .cast::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(),
            &mut got,
        )
    };
    if ok == 0 {
        return Err("Windows did not give the processor layout".into());
    }
    // SAFETY: the u64 storage is viewed as its bytes, no longer than it is.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>(),
            (got as usize).min(storage.len() * 8),
        )
    };
    Ok(parse(bytes))
}

/// One logical processor's clocks as Windows' power manager gives them, in MHz.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorClock {
    pub processor: u32,
    /// The rated (base) clock.
    pub base_mhz: u32,
    /// The clock at the time of reading. Windows caps this figure at the base clock on many
    /// processors, so a boost above it may not show here.
    pub current_mhz: u32,
    /// The highest clock the power policy allows now.
    pub limit_mhz: u32,
}

/// Every logical processor's clocks through CallNtPowerInformation(ProcessorInformation).
pub fn clocks(processors: u32) -> Result<Vec<ProcessorClock>, String> {
    use windows_sys::Win32::System::Power::{
        CallNtPowerInformation, ProcessorInformation, PROCESSOR_POWER_INFORMATION,
    };
    let count = processors.clamp(1, 2048) as usize;
    let mut info = vec![PROCESSOR_POWER_INFORMATION::default(); count];
    let bytes = (count * std::mem::size_of::<PROCESSOR_POWER_INFORMATION>()) as u32;
    // SAFETY: the output buffer holds `bytes` bytes of plain integers.
    let status = unsafe {
        CallNtPowerInformation(
            ProcessorInformation,
            std::ptr::null(),
            0,
            info.as_mut_ptr().cast(),
            bytes,
        )
    };
    if status != 0 {
        return Err(format!(
            "Windows did not give the clocks (status 0x{:08X})",
            status as u32
        ));
    }
    Ok(info
        .iter()
        .map(|p| ProcessorClock {
            processor: p.Number,
            base_mhz: p.MaxMhz,
            current_mhz: p.CurrentMhz,
            limit_mhz: p.MhzLimit,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(relation: u32, body: &[u8]) -> Vec<u8> {
        let mut r = relation.to_le_bytes().to_vec();
        r.extend(((body.len() + 8) as u32).to_le_bytes());
        r.extend(body);
        r
    }

    fn core(class: u8, mask: u64) -> Vec<u8> {
        let mut body = vec![0u8; 24 + 16];
        body[0] = 1;
        body[1] = class;
        body[22..24].copy_from_slice(&1u16.to_le_bytes());
        body[24..32].copy_from_slice(&mask.to_le_bytes());
        record(CORE, &body)
    }

    fn cache(level: u8, kind: u32, size: u32, ways: u8, mask: u64) -> Vec<u8> {
        let mut body = vec![0u8; 32 + 16];
        body[0] = level;
        body[1] = ways;
        body[2..4].copy_from_slice(&64u16.to_le_bytes());
        body[4..8].copy_from_slice(&size.to_le_bytes());
        body[8..12].copy_from_slice(&kind.to_le_bytes());
        body[30..32].copy_from_slice(&1u16.to_le_bytes());
        body[32..40].copy_from_slice(&mask.to_le_bytes());
        record(CACHE, &body)
    }

    /// Two performance cores with two threads each, four efficient cores, one package,
    /// per-core L2 on the performance cores and one shared L2 and L3.
    fn hybrid() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(core(1, 0b11));
        b.extend(core(1, 0b1100));
        for i in 4..8 {
            b.extend(core(0, 1 << i));
        }
        b.extend(record(PACKAGE, &[0u8; 40]));
        b.extend(cache(2, 0, 1280 << 10, 10, 0b11));
        b.extend(cache(2, 0, 1280 << 10, 10, 0b1100));
        b.extend(cache(2, 0, 2 << 20, 16, 0b1111_0000));
        b.extend(cache(3, 0, 12 << 20, 0xFF, 0xFF));
        b.extend(cache(1, 2, 48 << 10, 12, 0b11));
        b.extend(cache(1, 1, 32 << 10, 8, 0b11));
        b
    }

    #[test]
    fn a_hybrid_layout_counts_each_core_type_and_groups_caches() {
        let t = parse(&hybrid());
        assert_eq!((t.packages, t.cores, t.logical_processors), (1, 6, 8));
        assert_eq!(
            t.core_classes,
            vec![
                CoreClass {
                    efficiency_class: 1,
                    cores: 2,
                    threads: 4
                },
                CoreClass {
                    efficiency_class: 0,
                    cores: 4,
                    threads: 4
                },
            ]
        );
        let l2: Vec<_> = t.caches.iter().filter(|c| c.level == 2).collect();
        assert_eq!(l2.len(), 2);
        assert_eq!(l2[0].size_bytes, 2 << 20);
        assert_eq!((l2[1].count, l2[1].shared_by_threads), (2, 2));
        let l3 = t.caches.iter().find(|c| c.level == 3).unwrap();
        assert_eq!((l3.ways, l3.shared_by_threads), (None, 8));
        assert_eq!(t.caches[0].kind, "data");
    }

    #[test]
    fn every_cut_and_every_corrupted_byte_reads_safely() {
        let good = hybrid();
        for end in 0..good.len() {
            let t = parse(&good[..end]);
            assert!(t.cores <= 6 && t.caches.len() <= 6);
        }
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for at in 0..good.len() {
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let mut bad = good.clone();
                bad[at] = seed as u8;
                let t = parse(&bad);
                assert!(t.logical_processors <= 64 * 2048);
            }
        }
        // A size of zero, or one past the end, stops the walk at once.
        let mut zero = core(1, 1);
        zero[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse(&zero), Topology::default());
        let mut long = core(1, 1);
        long[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse(&long), Topology::default());
    }

    #[test]
    fn many_group_masks_are_bounded_by_the_record() {
        let mut body = vec![0u8; 24 + 16];
        body[22..24].copy_from_slice(&u16::MAX.to_le_bytes());
        body[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        let t = parse(&record(CORE, &body));
        assert_eq!((t.cores, t.logical_processors), (1, 64));
    }

    #[test]
    fn this_pc_has_a_layout_and_clocks() {
        let t = read().expect("layout");
        assert!(t.packages >= 1 && t.cores >= 1 && t.logical_processors >= t.cores);
        assert!(t.caches.iter().any(|c| c.level == 1));
        let c = clocks(t.logical_processors).expect("clocks");
        assert_eq!(c.len(), t.logical_processors as usize);
        assert!(c.iter().all(|p| p.base_mhz > 0));
    }
}
