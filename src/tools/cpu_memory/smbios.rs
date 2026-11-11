//! The firmware's SMBIOS table, read with GetSystemFirmwareTable('RSMB') as the current user:
//! BIOS (type 0), baseboard (2), processor sockets (4), memory arrays (16), memory devices
//! (17) and mapped ranges (19). Field offsets and codes are from DMTF DSP0134 (SMBIOS
//! Reference Specification 3.7.0). The table comes from firmware and may be malformed, so
//! every read is bounded: no field is read past its structure, no structure past the table,
//! and the walk runs within a budget (`LIMITS`); a walk that ends before the table's end,
//! at a limit or at a structure that does not fit, says so in `Table::limit`.
use serde::{Deserialize, Serialize};

use crate::budget::{Budget, Limits};

/// What the walk of the table may spend: 4,096 structures (a large server's table holds a
/// few hundred), the 4 MiB the table may be, each byte once, and 16 MiB held for the
/// structures kept (their bytes and strings, at most twice the table, and a little for each).
/// No clock limit: the table is in memory and the walk is linear in it.
pub const LIMITS: Limits = Limits {
    what: "the read of the firmware table (SMBIOS)",
    unit: "structures",
    count: 4096,
    bytes: MAX_TABLE as u64,
    memory: 16 << 20,
    depth: 0,
    nested: "structures",
    time: None,
};
/// Held for one structure, besides its bytes and strings.
const STRUCTURE_HELD: u64 = 96;
/// Characters kept of one string.
const MAX_STRING: usize = 128;
/// The largest table accepted from Windows.
const MAX_TABLE: usize = 4 << 20;

/// One structure: its type, handle, formatted bytes and strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Structure {
    pub kind: u8,
    pub handle: u16,
    pub formatted: Vec<u8>,
    pub strings: Vec<String>,
}

impl Structure {
    fn u8(&self, at: usize) -> Option<u8> {
        self.formatted.get(at).copied()
    }

    fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            self.formatted.get(at..at + 2)?.try_into().ok()?,
        ))
    }

    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.formatted.get(at..at + 4)?.try_into().ok()?,
        ))
    }

    fn u64(&self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.formatted.get(at..at + 8)?.try_into().ok()?,
        ))
    }

    /// The string a field at `at` points to; None for index 0, a missing string, or text
    /// that is empty or a firmware placeholder.
    fn text(&self, at: usize) -> Option<String> {
        let index = usize::from(self.u8(at)?);
        let text = self.strings.get(index.checked_sub(1)?)?;
        usable(text).then(|| text.clone())
    }
}

/// False for the fillers firmware writes where it has nothing to say.
fn usable(text: &str) -> bool {
    let t = text.trim().to_ascii_lowercase();
    !(t.is_empty()
        || t.chars().all(|c| c == '0' || c == 'f' || c == ' ')
        || matches!(
            t.as_str(),
            "to be filled by o.e.m." | "default string" | "unknown" | "not specified" | "none"
        ))
}

/// The version of the table and its structures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub major: u8,
    pub minor: u8,
    pub structures: Vec<Structure>,
    /// The bytes the header gives and the bytes Windows returned, when the header gives
    /// more: the table was cut short, and only the structures present were read.
    pub cut_short: Option<(usize, usize)>,
    /// Why the walk ended before the table's end, in words, when it did: a limit of its
    /// budget, or a structure that does not fit.
    pub limit: Option<String>,
}

/// Parses the RawSMBIOSData Windows returns: an 8-byte header (calling method, major and
/// minor version, DMI revision, length) and then the structures.
pub fn parse_raw(raw: &[u8]) -> Option<Table> {
    let header = raw.get(..8)?;
    let length = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    let data = raw.get(8..)?;
    let cut_short = (length > data.len()).then_some((length, data.len()));
    let data = &data[..length.min(data.len())];
    let mut budget = Budget::new(LIMITS, None);
    let (structures, ended) = parse(data, &mut budget);
    let limit = match (budget.said(), ended) {
        (Some(said), _) => Some(format!(
            "{said} Only the structures before it are shown, so memory slots, sockets or board details may be missing."
        )),
        // A table cut short already says why its last structure does not fit.
        (None, Ended::Unfit(at)) if cut_short.is_none() => Some(format!(
            "The firmware table (SMBIOS) holds a structure at byte {at} that does not fit in it; the structures after it were not read, so memory slots, sockets or board details may be missing."
        )),
        _ => None,
    };
    Some(Table {
        major: header[1],
        minor: header[2],
        structures,
        cut_short,
        limit,
    })
}

/// How a walk of the table ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// At its end-of-table structure (type 127) or the end of the data.
    End,
    /// At a structure, at this byte, that does not fit in the table.
    Unfit(usize),
    /// At a limit of its budget.
    Limit,
}

/// Walks the structure table within `budget` (made from `LIMITS`). Each structure is a
/// 4-byte header (type, length, handle), the rest of its formatted area, then strings each
/// ending with a NUL and the set ending with a second NUL. The walk stops at type 127, at a
/// structure that does not fit, or at a limit of its budget; it returns how it ended.
pub fn parse(data: &[u8], budget: &mut Budget) -> (Vec<Structure>, Ended) {
    let mut out = Vec::new();
    let mut at = 0usize;
    let ended = loop {
        if at >= data.len() {
            break Ended::End;
        }
        let Some(header) = data.get(at..at + 4) else {
            break Ended::Unfit(at);
        };
        let (kind, length) = (header[0], usize::from(header[1]));
        let handle = u16::from_le_bytes([header[2], header[3]]);
        if length < 4 {
            break Ended::Unfit(at);
        }
        let Some(formatted) = data.get(at..at + length) else {
            break Ended::Unfit(at);
        };
        // The strings end at the first double NUL after the formatted area.
        let rest = &data[at + length..];
        let Some(end) = rest.windows(2).position(|w| w == [0, 0]) else {
            break Ended::Unfit(at);
        };
        let size = (length + end + 2) as u64;
        if budget.item().is_err()
            || budget.read(size).is_err()
            || budget.hold(STRUCTURE_HELD + 2 * size).is_err()
        {
            break Ended::Limit;
        }
        let strings: Vec<String> = if end == 0 {
            Vec::new()
        } else {
            rest[..end]
                .split(|b| *b == 0)
                .take(255)
                .map(|s| {
                    let mut text = super::cpuid::clean_text(s);
                    text.truncate(
                        text.char_indices()
                            .nth(MAX_STRING)
                            .map_or(text.len(), |(i, _)| i),
                    );
                    text
                })
                .collect()
        };
        out.push(Structure {
            kind,
            handle,
            formatted: formatted.to_vec(),
            strings,
        });
        at += length + end + 2;
        if kind == 127 {
            break Ended::End;
        }
    };
    (out, ended)
}

/// Reads the table from Windows.
pub fn read() -> Result<Table, String> {
    use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};
    // SAFETY: a size query with a null buffer.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) } as usize;
    if size == 0 {
        return Err("Windows gave no firmware (SMBIOS) table".into());
    }
    if size > MAX_TABLE {
        return Err("the firmware (SMBIOS) table is larger than any real one".into());
    }
    // Charged before it is made, within the read's own memory limit.
    let mut buffer = Budget::new(LIMITS, None)
        .buffer(size)
        .map_err(|_| "the firmware (SMBIOS) table is larger than this tool reads".to_string())?;
    // SAFETY: the buffer holds `size` bytes.
    let got = unsafe { GetSystemFirmwareTable(RSMB, 0, buffer.as_mut_ptr(), size as u32) } as usize;
    if got == 0 || got > size {
        return Err("Windows did not give the firmware (SMBIOS) table".into());
    }
    buffer.truncate(got);
    parse_raw(&buffer).ok_or_else(|| "the firmware (SMBIOS) table is too short to read".into())
}

// ---- decoded structures ----------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bios {
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub date: Option<String>,
    /// "major.minor" of the BIOS release, when given (SMBIOS 2.4 and later).
    pub release: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseboard {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// A processor socket as the firmware describes it (type 4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socket {
    pub designation: Option<String>,
    pub populated: bool,
    pub version: Option<String>,
    pub external_clock_mhz: Option<u16>,
    pub max_speed_mhz: Option<u16>,
    pub current_speed_mhz: Option<u16>,
    /// Millivolts, when the firmware gives the present voltage.
    pub voltage_mv: Option<u16>,
    pub cores: Option<u16>,
    pub threads: Option<u16>,
}

/// A physical memory array (type 16): the board's memory slots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryArray {
    pub handle: u16,
    pub location: String,
    pub used_for: String,
    pub error_correction: String,
    pub max_capacity_bytes: Option<u64>,
    pub slots: Option<u16>,
}

/// One memory slot (type 17), filled or empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDevice {
    pub array_handle: Option<u16>,
    pub locator: Option<String>,
    pub bank: Option<String>,
    /// None for an empty slot; a size the firmware does not know is `size_unknown`.
    pub size_bytes: Option<u64>,
    pub size_unknown: bool,
    pub form_factor: String,
    pub memory_type: String,
    /// The speed the module is rated for, in MT/s (MHz in tables before SMBIOS 3.1).
    pub rated_speed_mts: Option<u32>,
    /// The speed the memory controller runs it at, in MT/s.
    pub configured_speed_mts: Option<u32>,
    pub manufacturer: Option<String>,
    pub part_number: Option<String>,
    pub serial: Option<String>,
    pub rank: Option<u8>,
    pub data_width_bits: Option<u16>,
    pub total_width_bits: Option<u16>,
    pub configured_voltage_mv: Option<u16>,
    pub min_voltage_mv: Option<u16>,
    pub max_voltage_mv: Option<u16>,
}

/// A range of addresses the memory fills (type 19).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappedRange {
    pub start: u64,
    pub end: u64,
    pub array_handle: Option<u16>,
}

impl MappedRange {
    pub fn bytes(&self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

/// Everything decoded from one table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    pub version: String,
    /// Bytes the table's header gives and bytes present, when it was cut short.
    pub cut_short: Option<(usize, usize)>,
    /// Why the walk ended before the table's end, in words, when it did.
    pub limit: Option<String>,
    pub bios: Option<Bios>,
    pub baseboard: Option<Baseboard>,
    pub sockets: Vec<Socket>,
    pub arrays: Vec<MemoryArray>,
    pub devices: Vec<MemoryDevice>,
    pub ranges: Vec<MappedRange>,
}

pub fn decode(table: &Table) -> Decoded {
    let mut d = Decoded {
        version: format!("{}.{}", table.major, table.minor),
        cut_short: table.cut_short,
        limit: table.limit.clone(),
        ..Decoded::default()
    };
    for s in &table.structures {
        match s.kind {
            0 if d.bios.is_none() => d.bios = Some(bios(s)),
            2 if d.baseboard.is_none() => d.baseboard = Some(baseboard(s)),
            4 => d.sockets.push(socket(s)),
            16 => d.arrays.push(array(s)),
            17 => d.devices.push(device(s)),
            19 => {
                if let Some(r) = range(s) {
                    d.ranges.push(r)
                }
            }
            _ => {}
        }
    }
    d
}

fn bios(s: &Structure) -> Bios {
    let release = match (s.u8(0x14), s.u8(0x15)) {
        (Some(major), Some(minor)) if major != 0xFF => Some(format!("{major}.{minor}")),
        _ => None,
    };
    Bios {
        vendor: s.text(0x04),
        version: s.text(0x05),
        date: s.text(0x08),
        release,
    }
}

fn baseboard(s: &Structure) -> Baseboard {
    Baseboard {
        manufacturer: s.text(0x04),
        product: s.text(0x05),
        version: s.text(0x06),
    }
}

fn speed(v: Option<u16>) -> Option<u16> {
    v.filter(|v| *v != 0 && *v != 0xFFFF)
}

fn socket(s: &Structure) -> Socket {
    // Bit 7 set: the low bits are tenths of a volt. Clear: legacy flags for 5, 3.3 and 2.9 V.
    let voltage = s.u8(0x11).and_then(|v| {
        if v & 0x80 != 0 {
            let tenths = v & 0x7F;
            (tenths != 0).then_some(u16::from(tenths) * 100)
        } else if v & 1 != 0 {
            Some(5000)
        } else if v & 2 != 0 {
            Some(3300)
        } else if v & 4 != 0 {
            Some(2900)
        } else {
            None
        }
    });
    // 0xFF in the byte counts means the 16-bit field at 0x2A or 0x2E holds the count.
    let count = |byte: usize, word: usize| match s.u8(byte) {
        Some(0xFF) => s.u16(word).filter(|v| *v != 0 && *v != 0xFFFF),
        Some(0) | None => None,
        Some(v) => Some(u16::from(v)),
    };
    Socket {
        designation: s.text(0x04),
        populated: s.u8(0x18).is_some_and(|v| v & 0x40 != 0),
        version: s.text(0x10),
        external_clock_mhz: speed(s.u16(0x12)),
        max_speed_mhz: speed(s.u16(0x14)),
        current_speed_mhz: speed(s.u16(0x16)),
        voltage_mv: voltage,
        cores: count(0x23, 0x2A),
        threads: count(0x25, 0x2E),
    }
}

fn array(s: &Structure) -> MemoryArray {
    let location = match s.u8(0x04) {
        Some(0x03) => "system board",
        Some(0x04) => "add-in card",
        Some(0x05) => "ISA card",
        Some(0x06) => "EISA card",
        Some(0x07) => "PCI card",
        Some(0x0A) => "PCI Express card",
        Some(0x01) => "other",
        _ => "not given",
    };
    let used_for = match s.u8(0x05) {
        Some(0x03) => "system memory",
        Some(0x04) => "video memory",
        Some(0x05) => "flash memory",
        Some(0x06) => "non-volatile RAM",
        Some(0x07) => "cache memory",
        Some(0x01) => "other",
        _ => "not given",
    };
    let error_correction = match s.u8(0x06) {
        Some(0x03) => "none",
        Some(0x04) => "parity",
        Some(0x05) => "single-bit ECC",
        Some(0x06) => "multi-bit ECC",
        Some(0x07) => "CRC",
        Some(0x01) => "other",
        _ => "not given",
    };
    // KiB, or 0x8000_0000 meaning the 64-bit byte count at 0x0F holds it.
    let max = match s.u32(0x07) {
        Some(0x8000_0000) => s.u64(0x0F),
        Some(0) | None => None,
        Some(kib) => Some(u64::from(kib) * 1024),
    };
    MemoryArray {
        handle: s.handle,
        location: location.into(),
        used_for: used_for.into(),
        error_correction: error_correction.into(),
        max_capacity_bytes: max.filter(|v| *v > 0),
        slots: s.u16(0x0D).filter(|v| *v > 0),
    }
}

/// DSP0134 7.18.2, memory device type.
pub fn memory_type(code: u8) -> String {
    match code {
        0x01 => "other",
        0x02 => "unknown",
        0x03 => "DRAM",
        0x04 => "EDRAM",
        0x05 => "VRAM",
        0x06 => "SRAM",
        0x07 => "RAM",
        0x08 => "ROM",
        0x09 => "flash",
        0x0A => "EEPROM",
        0x0B => "FEPROM",
        0x0C => "EPROM",
        0x0D => "CDRAM",
        0x0E => "3DRAM",
        0x0F => "SDRAM",
        0x10 => "SGRAM",
        0x11 => "RDRAM",
        0x12 => "DDR",
        0x13 => "DDR2",
        0x14 => "DDR2 FB-DIMM",
        0x18 => "DDR3",
        0x19 => "FBD2",
        0x1A => "DDR4",
        0x1B => "LPDDR",
        0x1C => "LPDDR2",
        0x1D => "LPDDR3",
        0x1E => "LPDDR4",
        0x1F => "logical non-volatile device",
        0x20 => "HBM",
        0x21 => "HBM2",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        0x24 => "HBM3",
        other => return format!("type code {other}"),
    }
    .into()
}

/// DSP0134 7.18.1, memory device form factor.
pub fn form_factor(code: u8) -> String {
    match code {
        0x01 => "other",
        0x02 => "unknown",
        0x03 => "SIMM",
        0x04 => "SIP",
        0x05 => "chip",
        0x06 => "DIP",
        0x07 => "ZIP",
        0x08 => "proprietary card",
        0x09 => "DIMM",
        0x0A => "TSOP",
        0x0B => "row of chips",
        0x0C => "RIMM",
        0x0D => "SO-DIMM",
        0x0E => "SRIMM",
        0x0F => "FB-DIMM",
        0x10 => "die",
        other => return format!("form factor code {other}"),
    }
    .into()
}

fn device(s: &Structure) -> MemoryDevice {
    // Size: 0 is an empty slot, 0xFFFF unknown, 0x7FFF means the 32-bit MiB count at 0x1C;
    // otherwise MiB, or KiB when bit 15 is set.
    let (size, unknown) = match s.u16(0x0C) {
        None | Some(0) => (None, false),
        Some(0xFFFF) => (None, true),
        Some(0x7FFF) => match s.u32(0x1C) {
            Some(mib) if mib & 0x7FFF_FFFF > 0 => (Some(u64::from(mib & 0x7FFF_FFFF) << 20), false),
            _ => (None, true),
        },
        Some(v) if v & 0x8000 != 0 => (Some(u64::from(v & 0x7FFF) << 10), false),
        Some(v) => (Some(u64::from(v) << 20), false),
    };
    // A 16-bit speed of 0xFFFF means the 32-bit field holds it (SMBIOS 3.3).
    let wide_speed = |short: usize, long: usize| match s.u16(short) {
        Some(0xFFFF) => s.u32(long).filter(|v| *v != 0),
        Some(0) | None => None,
        Some(v) => Some(u32::from(v)),
    };
    let width = |at: usize| s.u16(at).filter(|v| *v != 0 && *v != 0xFFFF);
    let mv = |at: usize| s.u16(at).filter(|v| *v != 0);
    MemoryDevice {
        array_handle: s.u16(0x04).filter(|h| *h != 0xFFFE && *h != 0xFFFF),
        locator: s.text(0x10),
        bank: s.text(0x11),
        size_bytes: size,
        size_unknown: unknown,
        form_factor: s.u8(0x0E).map_or_else(|| "not given".into(), form_factor),
        memory_type: s.u8(0x12).map_or_else(|| "not given".into(), memory_type),
        rated_speed_mts: wide_speed(0x15, 0x54),
        configured_speed_mts: wide_speed(0x20, 0x58),
        manufacturer: s.text(0x17),
        part_number: s.text(0x1A),
        serial: s.text(0x18),
        rank: s.u8(0x1B).map(|v| v & 0x0F).filter(|v| *v != 0),
        data_width_bits: width(0x0A),
        total_width_bits: width(0x08),
        configured_voltage_mv: mv(0x26),
        min_voltage_mv: mv(0x22),
        max_voltage_mv: mv(0x24),
    }
}

fn range(s: &Structure) -> Option<MappedRange> {
    let (start, end) = match (s.u32(0x04)?, s.u32(0x08)?) {
        (0xFFFF_FFFF, _) => (s.u64(0x0F)?, s.u64(0x17)?),
        (start, end) => (u64::from(start) * 1024, u64::from(end) * 1024 + 1023),
    };
    (end > start).then_some(MappedRange {
        start,
        end,
        array_handle: s.u16(0x0C),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn walk(data: &[u8]) -> Vec<Structure> {
        parse(data, &mut Budget::new(LIMITS, None)).0
    }

    fn structure(kind: u8, handle: u16, body: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut s = vec![kind, (body.len() + 4) as u8];
        s.extend(handle.to_le_bytes());
        s.extend(body);
        if strings.is_empty() {
            s.extend([0, 0]);
        } else {
            for text in strings {
                s.extend(text.as_bytes());
                s.push(0);
            }
            s.push(0);
        }
        s
    }

    fn put(body: &mut [u8], at: usize, bytes: &[u8]) {
        // Offsets in DSP0134 count the 4-byte header.
        body[at - 4..at - 4 + bytes.len()].copy_from_slice(bytes);
    }

    fn memory_device(locator: &str, bank: &str, mib: u16, serial: &str) -> Vec<u8> {
        let mut b = vec![0u8; 0x5C - 4];
        put(&mut b, 0x04, &0x0040u16.to_le_bytes());
        put(&mut b, 0x08, &64u16.to_le_bytes());
        put(&mut b, 0x0A, &64u16.to_le_bytes());
        put(&mut b, 0x0C, &mib.to_le_bytes());
        put(&mut b, 0x0E, &[0x09]);
        put(&mut b, 0x10, &[1, 2]);
        put(&mut b, 0x12, &[0x22]);
        put(&mut b, 0x15, &4800u16.to_le_bytes());
        put(&mut b, 0x17, &[3, 4, 0, 5]);
        put(&mut b, 0x1B, &[0x02]);
        put(&mut b, 0x20, &6000u16.to_le_bytes());
        put(&mut b, 0x22, &1100u16.to_le_bytes());
        put(&mut b, 0x24, &1350u16.to_le_bytes());
        put(&mut b, 0x26, &1350u16.to_le_bytes());
        structure(
            17,
            0x41,
            &b,
            &[
                locator,
                bank,
                "G Skill Intl",
                serial,
                "F5-6000J3238F16G    ",
            ],
        )
    }

    /// A small table: BIOS, board, one populated socket, a 4-slot array, two filled slots
    /// and two empty ones, one mapped range, and the end marker.
    pub(crate) fn sample() -> Vec<u8> {
        let mut t = Vec::new();
        let mut b = vec![0u8; 0x1A - 4];
        put(&mut b, 0x04, &[1, 2]);
        put(&mut b, 0x08, &[3]);
        put(&mut b, 0x14, &[5, 17]);
        t.extend(structure(
            0,
            0,
            &b,
            &[
                "American Megatrends International, LLC.",
                "3080",
                "09/12/2024",
            ],
        ));
        let mut b = vec![0u8; 0x0F - 4];
        put(&mut b, 0x04, &[1, 2, 3]);
        t.extend(structure(
            2,
            2,
            &b,
            &[
                "ASUSTeK COMPUTER INC.",
                "ROG STRIX B650E-F",
                "Default string",
            ],
        ));
        let mut b = vec![0u8; 0x30 - 4];
        put(&mut b, 0x04, &[1]);
        put(&mut b, 0x10, &[2]);
        put(&mut b, 0x11, &[0x80 | 11]);
        put(&mut b, 0x12, &100u16.to_le_bytes());
        put(&mut b, 0x14, &5050u16.to_le_bytes());
        put(&mut b, 0x16, &4200u16.to_le_bytes());
        put(&mut b, 0x18, &[0x41]);
        put(&mut b, 0x23, &[8, 8, 16]);
        t.extend(structure(
            4,
            4,
            &b,
            &["AM5", "AMD Ryzen 7 7800X3D 8-Core Processor"],
        ));
        let mut b = vec![0u8; 0x17 - 4];
        put(&mut b, 0x04, &[0x03, 0x03, 0x03]);
        put(&mut b, 0x07, &0x0800_0000u32.to_le_bytes());
        put(&mut b, 0x0D, &4u16.to_le_bytes());
        t.extend(structure(16, 0x40, &b, &[]));
        t.extend(memory_device("DIMM 0", "P0 CHANNEL A", 0, "Not Specified"));
        t.extend(memory_device("DIMM 1", "P0 CHANNEL A", 16384, "0x0A1B2C3D"));
        t.extend(memory_device("DIMM 0", "P0 CHANNEL B", 0, "Not Specified"));
        t.extend(memory_device("DIMM 1", "P0 CHANNEL B", 16384, "0x0A1B2C3E"));
        let mut b = vec![0u8; 0x1F - 4];
        put(&mut b, 0x04, &0u32.to_le_bytes());
        put(&mut b, 0x08, &(32 * 1024 * 1024 - 1u32).to_le_bytes());
        put(&mut b, 0x0C, &0x0040u16.to_le_bytes());
        t.extend(structure(19, 0x50, &b, &[]));
        t.extend(structure(127, 0xFFFF, &[], &[]));
        let mut raw = vec![0, 3, 7, 0];
        raw.extend((t.len() as u32).to_le_bytes());
        raw.extend(t);
        raw
    }

    #[test]
    fn a_whole_table_decodes_every_field_it_gives() {
        let table = parse_raw(&sample()).unwrap();
        assert_eq!((table.major, table.minor), (3, 7));
        assert_eq!(table.structures.last().unwrap().kind, 127);
        let d = decode(&table);
        let bios = d.bios.unwrap();
        assert_eq!(bios.version.as_deref(), Some("3080"));
        assert_eq!(bios.date.as_deref(), Some("09/12/2024"));
        assert_eq!(bios.release.as_deref(), Some("5.17"));
        let board = d.baseboard.unwrap();
        assert_eq!(board.product.as_deref(), Some("ROG STRIX B650E-F"));
        assert_eq!(board.version, None, "a placeholder is not a fact");
        assert_eq!(d.sockets.len(), 1);
        let s = &d.sockets[0];
        assert!(s.populated);
        assert_eq!(
            (s.max_speed_mhz, s.current_speed_mhz),
            (Some(5050), Some(4200))
        );
        assert_eq!((s.cores, s.threads), (Some(8), Some(16)));
        assert_eq!(s.voltage_mv, Some(1100));
        assert_eq!(d.arrays[0].slots, Some(4));
        assert_eq!(d.arrays[0].max_capacity_bytes, Some(128 << 30));
        assert_eq!(d.devices.len(), 4);
        let m = &d.devices[1];
        assert_eq!(m.size_bytes, Some(16 << 30));
        assert_eq!(m.memory_type, "DDR5");
        assert_eq!(m.form_factor, "DIMM");
        assert_eq!(
            (m.rated_speed_mts, m.configured_speed_mts),
            (Some(4800), Some(6000))
        );
        assert_eq!(m.part_number.as_deref(), Some("F5-6000J3238F16G"));
        assert_eq!(m.serial.as_deref(), Some("0x0A1B2C3D"));
        assert_eq!(m.rank, Some(2));
        assert_eq!(m.configured_voltage_mv, Some(1350));
        assert_eq!(d.devices[0].size_bytes, None);
        assert_eq!(d.ranges[0].bytes(), 32 << 30);
    }

    #[test]
    fn extended_sizes_and_speeds_are_read_from_their_wide_fields() {
        let mut b = vec![0u8; 0x5C - 4];
        put(&mut b, 0x0C, &0x7FFFu16.to_le_bytes());
        put(&mut b, 0x1C, &(64u32 * 1024).to_le_bytes());
        put(&mut b, 0x15, &0xFFFFu16.to_le_bytes());
        put(&mut b, 0x54, &70_000u32.to_le_bytes());
        let table = Table {
            major: 3,
            minor: 7,
            structures: walk(&structure(17, 1, &b, &[])),
            cut_short: None,
            limit: None,
        };
        let m = &decode(&table).devices[0];
        assert_eq!(m.size_bytes, Some(64 << 30));
        assert_eq!(m.rated_speed_mts, Some(70_000));
        // KiB units when bit 15 is set.
        put(&mut b, 0x0C, &(0x8000u16 | 512).to_le_bytes());
        let table = Table {
            major: 2,
            minor: 0,
            structures: walk(&structure(17, 1, &b, &[])),
            cut_short: None,
            limit: None,
        };
        assert_eq!(decode(&table).devices[0].size_bytes, Some(512 << 10));
    }

    #[test]
    fn short_structures_read_what_they_hold_and_nothing_more() {
        // A type 17 cut after its size field: no locator, no speed, no panic.
        let mut b = vec![0u8; 0x0E - 4];
        put(&mut b, 0x0C, &8192u16.to_le_bytes());
        let table = Table {
            major: 2,
            minor: 0,
            structures: walk(&structure(17, 1, &b, &["x"])),
            cut_short: None,
            limit: None,
        };
        let m = &decode(&table).devices[0];
        assert_eq!(m.size_bytes, Some(8 << 30));
        assert_eq!((m.locator.clone(), m.rated_speed_mts), (None, None));
        // A string index past the strings there are reads as none.
        let mut b = vec![0u8; 0x1A - 4];
        put(&mut b, 0x04, &[9, 200]);
        let table = Table {
            major: 3,
            minor: 0,
            structures: walk(&structure(0, 0, &b, &["only"])),
            cut_short: None,
            limit: None,
        };
        assert_eq!(decode(&table).bios.unwrap().vendor, None);
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn malformed_tables_never_read_out_of_bounds_or_run_away() {
        let good = sample();
        // Every cut of a good table.
        for end in 0..good.len() {
            if let Some(t) = parse_raw(&good[..end]) {
                let _ = decode(&t);
            }
        }
        // Every byte of it replaced, several times over.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for at in 0..good.len() {
            for _ in 0..8 {
                let mut bad = good.clone();
                bad[at] = next(&mut seed) as u8;
                if let Some(t) = parse_raw(&bad) {
                    assert!(t.structures.len() <= LIMITS.count as usize);
                    let _ = decode(&t);
                }
            }
        }
        // Random noise of many lengths.
        for round in 0..2000 {
            let len = (next(&mut seed) % 600) as usize + round % 3;
            let noise: Vec<u8> = (0..len).map(|_| next(&mut seed) as u8).collect();
            if let Some(t) = parse_raw(&noise) {
                let _ = decode(&t);
            }
            let _ = walk(&noise);
        }
        // A length field claiming more than the buffer, and one below the header size.
        let mut long = good.clone();
        long[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_raw(&long).is_some());
        assert!(walk(&[17, 2, 0, 0, 0, 0]).is_empty());
        // Structures with no strings at all, repeated past the limit, stop at it.
        let tiny = structure(200, 1, &[], &[]);
        let many: Vec<u8> = tiny
            .iter()
            .copied()
            .cycle()
            .take(tiny.len() * 5000)
            .collect();
        let mut budget = Budget::new(LIMITS, None);
        let (structures, ended) = parse(&many, &mut budget);
        assert_eq!((structures.len(), ended), (4096, Ended::Limit));
        assert!(budget.spent().peak <= LIMITS.memory);
        assert_eq!(
            budget.said().unwrap(),
            "The read of the firmware table (SMBIOS) stopped at its limit of 4,096 structures."
        );
        let mut raw = vec![0, 3, 0, 0];
        raw.extend(((many.len()) as u32).to_le_bytes());
        raw.extend(&many);
        let table = parse_raw(&raw).unwrap();
        assert!(table.limit.unwrap().ends_with("Only the structures before it are shown, so memory slots, sockets or board details may be missing."));
        // A structure that does not fit is said, when the table was not cut short.
        let mut raw = vec![0, 3, 0, 0, 8, 0, 0, 0];
        raw.extend([17, 200, 0, 0, 0, 0, 0, 0]);
        let table = parse_raw(&raw).unwrap();
        assert!(table.structures.is_empty());
        assert!(table
            .limit
            .unwrap()
            .contains("a structure at byte 0 that does not fit"));
        assert_eq!(decode(&parse_raw(&sample()).unwrap()).limit, None);
        // A table without the double NUL ends the walk.
        assert!(walk(&[0, 4, 0, 0, b'a', 0, b'b']).is_empty());
    }

    #[test]
    fn long_and_unprintable_strings_are_cut_and_cleaned() {
        let long = "A".repeat(1000);
        let mut b = vec![0u8; 0x1A - 4];
        put(&mut b, 0x04, &[1, 2]);
        let table = Table {
            major: 3,
            minor: 0,
            structures: walk(&structure(0, 0, &b, &[&long, "v\x07 1"])),
            cut_short: None,
            limit: None,
        };
        let bios = decode(&table).bios.unwrap();
        assert_eq!(bios.vendor.unwrap().len(), MAX_STRING);
        assert_eq!(bios.version.as_deref(), Some("v 1"));
    }

    #[test]
    fn this_pc_gives_a_table_with_memory_devices() {
        let table = read().expect("SMBIOS table");
        let d = decode(&table);
        assert!(d.devices.iter().any(|m| m.size_bytes.is_some()));
    }
}
