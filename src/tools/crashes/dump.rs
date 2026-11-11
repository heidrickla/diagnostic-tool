//! Bounded reads of 64-bit kernel crash dump headers ("PAGE" + "DU64").
//!
//! The 8 KiB file header is `DUMP_HEADER64` as Microsoft's Win32 metadata publishes it
//! (windows-sys `Win32::System::Diagnostics::Debug::DUMP_HEADER64`, generated from the SDK);
//! field offsets below come from that definition by `offset_of!`, and `DUMP_TYPE_*` names
//! the dump kinds. https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/struct.DUMP_HEADER64.html
//!
//! A small (triage) dump has a `TRIAGE_DUMP64` header right after it, at 0x2000. Its layout
//! (`DriverListOffset` +0x30, `DriverCount` +0x34, `StringPoolOffset` +0x38,
//! `StringPoolSize` +0x3C, offsets counted from the start of the file) and the driver entry
//! `DUMP_DRIVER_ENTRY64` (`DriverNameOffset` +0x00, then a 64-bit `KLDR_DATA_TABLE_ENTRY`
//! at +0x08 whose `DllBase` is at +0x30 and `SizeOfImage` at +0x40) are as described by:
//! - Microsoft public symbols for ntoskrnl, as listed in can1357/selene's generated SDK
//!   (resources/sdk/nt/triage_dump64_t.hpp, dump_driver_entry64_t.hpp,
//!   resources/sdk/ldr/km/data_table_entry_t.hpp), https://github.com/can1357/selene
//! - Ghidra's crash dump loader (Apache-2.0), ghidra/file/formats/dump/pagedump/
//!   Pagedump.java and LoadedDriver.java, https://github.com/NationalSecurityAgency/ghidra
//! - rizin's dump format description, librz/bin/format/dmp/dmp_specs.h,
//!   https://github.com/rizinorg/rizin
//!
//! Driver names are `DUMP_STRING`s in the string pool: a 32-bit length, then UTF-16 text
//! ending in a zero. Ghidra and rizin step through the driver list 0x90 bytes at a time;
//! current public symbols give the entry as 0xA8 bytes. Both are tried, and a stride is
//! used only when its entries hold names inside the string pool and kernel addresses.
//! No code was copied from these projects; this is written from the layouts they describe.
use std::io::{Read, Seek, SeekFrom};
use std::mem::{offset_of, size_of};
use std::time::SystemTime;

use windows_sys::Win32::System::Diagnostics::Debug::DUMP_HEADER64;

pub const HEADER_SIZE: usize = size_of::<DUMP_HEADER64>();
const MINOR_VERSION: usize = offset_of!(DUMP_HEADER64, MinorVersion);
const MACHINE: usize = offset_of!(DUMP_HEADER64, MachineImageType);
const PROCESSORS: usize = offset_of!(DUMP_HEADER64, NumberProcessors);
const BUGCHECK_CODE: usize = offset_of!(DUMP_HEADER64, BugCheckCode);
const BUGCHECK_PARAMETERS: [usize; 4] = [
    offset_of!(DUMP_HEADER64, BugCheckParameter1),
    offset_of!(DUMP_HEADER64, BugCheckParameter2),
    offset_of!(DUMP_HEADER64, BugCheckParameter3),
    offset_of!(DUMP_HEADER64, BugCheckParameter4),
];
const DUMP_TYPE: usize = offset_of!(DUMP_HEADER64, DumpType);
const SYSTEM_TIME: usize = offset_of!(DUMP_HEADER64, SystemTime);

pub const TRIAGE: u32 = 4;
const TRIAGE_HEADER_SIZE: usize = 0x80;
const TRIAGE_DRIVER_LIST_OFFSET: usize = 0x30;
const TRIAGE_DRIVER_COUNT: usize = 0x34;
const TRIAGE_STRING_POOL_OFFSET: usize = 0x38;
const TRIAGE_STRING_POOL_SIZE: usize = 0x3C;
/// The two driver entry sizes the format descriptions give; see the module comment.
const DRIVER_STRIDES: [usize; 2] = [0x90, 0xA8];
const DRIVER_NAME_OFFSET: usize = 0x00;
const DRIVER_BASE: usize = 0x08 + 0x30;
const DRIVER_SIZE: usize = 0x08 + 0x40;

/// Read caps: a triage dump's driver list and string pool are tens of kilobytes.
const MAX_DRIVERS: usize = 2048;
const MAX_POOL: usize = 512 * 1024;
const MAX_NAME_CHARS: usize = 260;
const KERNEL_SPACE: u64 = 0xFFFF_8000_0000_0000;

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub code: u32,
    pub parameters: [u64; 4],
    pub dump_type: u32,
    pub time: Option<SystemTime>,
    pub processors: u32,
    /// `MinorVersion`, the Windows build number.
    pub build: u32,
    pub machine: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Driver {
    pub name: String,
    pub base: u64,
    pub size: u32,
}

impl Driver {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < u64::from(self.size)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Drivers {
    /// Only small (triage) dumps carry a driver list this tool reads.
    NotTriage,
    Read {
        list: Vec<Driver>,
        skipped: usize,
    },
    Unreadable(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Dump {
    Kernel64 {
        header: Header,
        drivers: Drivers,
    },
    /// What the file is instead, or why its header could not be read.
    Unreadable(String),
}

pub fn dump_type_name(dump_type: u32) -> String {
    match dump_type {
        1 => "complete memory dump".into(),
        2 => "kernel memory dump".into(),
        3 => "header-only dump".into(),
        4 => "small memory dump".into(),
        5 => "complete memory dump (bitmap)".into(),
        6 => "kernel memory dump (bitmap)".into(),
        7 => "automatic memory dump".into(),
        other => format!("dump of unknown type {other}"),
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Parses the first `HEADER_SIZE` bytes of a dump file (fewer if the file is shorter).
pub fn parse_header(bytes: &[u8]) -> Result<Header, String> {
    let signature = bytes.get(..8).ok_or("too short to be a dump file")?;
    match (&signature[..4], &signature[4..]) {
        (b"PAGE", b"DU64") => {}
        (b"PAGE", b"DUMP") => {
            return Err("a 32-bit kernel dump; this tool reads only 64-bit dumps".into())
        }
        (b"MDMP", _) => return Err("a program (user-mode) dump, not a kernel crash dump".into()),
        _ => return Err("not a kernel dump (unknown signature)".into()),
    }
    if bytes.len() < HEADER_SIZE {
        return Err(format!(
            "truncated: the header needs {HEADER_SIZE} bytes, the file has {}",
            bytes.len()
        ));
    }
    let field = |offset| u32_at(bytes, offset).unwrap_or(0);
    let mut parameters = [0; 4];
    for (value, &offset) in parameters.iter_mut().zip(&BUGCHECK_PARAMETERS) {
        *value = u64_at(bytes, offset).unwrap_or(0);
    }
    let time = u64_at(bytes, SYSTEM_TIME)
        .filter(|&ticks| ticks != 0 && ticks < i64::MAX as u64)
        .map(crate::events::from_filetime);
    Ok(Header {
        code: field(BUGCHECK_CODE),
        parameters,
        dump_type: field(DUMP_TYPE),
        time,
        processors: field(PROCESSORS),
        build: field(MINOR_VERSION),
        machine: field(MACHINE),
    })
}

/// Reads `length` bytes at `offset`, only when they lie inside a file of `file_len` bytes.
fn read_at<R: Read + Seek>(
    file: &mut R,
    file_len: u64,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    let end = offset
        .checked_add(length as u64)
        .ok_or("an offset in the dump is out of range")?;
    if end > file_len {
        return Err(format!(
            "truncated: data at {offset:#x} runs past the end of the file"
        ));
    }
    let mut buffer = vec![0; length];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut buffer))
        .map_err(|error| format!("read failed: {error}"))?;
    Ok(buffer)
}

/// Reads a dump's header and, for a small dump, its driver list; nothing else.
pub fn read<R: Read + Seek>(file: &mut R, file_len: u64) -> Dump {
    let length = (file_len.min(HEADER_SIZE as u64)) as usize;
    let bytes = match read_at(file, file_len, 0, length) {
        Ok(bytes) => bytes,
        Err(reason) => return Dump::Unreadable(reason),
    };
    let header = match parse_header(&bytes) {
        Ok(header) => header,
        Err(reason) => return Dump::Unreadable(reason),
    };
    let drivers = if header.dump_type == TRIAGE {
        read_drivers(file, file_len).unwrap_or_else(Drivers::Unreadable)
    } else {
        Drivers::NotTriage
    };
    Dump::Kernel64 { header, drivers }
}

fn read_drivers<R: Read + Seek>(file: &mut R, file_len: u64) -> Result<Drivers, String> {
    let triage = read_at(file, file_len, HEADER_SIZE as u64, TRIAGE_HEADER_SIZE)?;
    let field = |offset| u32_at(&triage, offset).unwrap_or(0);
    let (list_offset, count) = (
        field(TRIAGE_DRIVER_LIST_OFFSET),
        field(TRIAGE_DRIVER_COUNT) as usize,
    );
    let (pool_offset, pool_size) = (
        field(TRIAGE_STRING_POOL_OFFSET),
        field(TRIAGE_STRING_POOL_SIZE) as usize,
    );
    if count == 0 || list_offset == 0 {
        return Ok(Drivers::Read {
            list: Vec::new(),
            skipped: 0,
        });
    }
    if count > MAX_DRIVERS {
        return Err(format!(
            "the dump claims {count} drivers, more than it can hold"
        ));
    }
    if pool_offset == 0 || pool_size == 0 || pool_size > MAX_POOL {
        return Err("the dump's string pool is missing or too large".into());
    }
    let pool = read_at(file, file_len, pool_offset.into(), pool_size)?;
    let mut last_error = String::from("no known driver entry layout fits this dump");
    for stride in DRIVER_STRIDES {
        let list = match read_at(file, file_len, list_offset.into(), count * stride) {
            Ok(list) => list,
            Err(reason) => {
                last_error = reason;
                continue;
            }
        };
        let entries: Vec<Option<Driver>> = list
            .chunks_exact(stride)
            .map(|entry| driver(entry, &pool, pool_offset))
            .collect();
        let valid = entries.iter().filter(|entry| entry.is_some()).count();
        // A layout is accepted when its first entry and nearly all others make sense.
        if entries.first().is_some_and(Option::is_some) && valid * 20 >= count * 19 {
            return Ok(Drivers::Read {
                list: entries.into_iter().flatten().collect(),
                skipped: count - valid,
            });
        }
    }
    Err(last_error)
}

/// One driver entry, when its name lies in the string pool and its range in kernel space.
fn driver(entry: &[u8], pool: &[u8], pool_offset: u32) -> Option<Driver> {
    let name_offset = u32_at(entry, DRIVER_NAME_OFFSET)?;
    let base = u64_at(entry, DRIVER_BASE)?;
    // SizeOfImage is 32 bits; Ghidra reads the slot as 64, and the upper half is padding.
    let size = u32_at(entry, DRIVER_SIZE)?;
    if base < KERNEL_SPACE || size == 0 || base.checked_add(size.into()).is_none() {
        return None;
    }
    let start = name_offset.checked_sub(pool_offset)? as usize;
    let declared = u32_at(pool, start)? as usize;
    let text = pool.get(start + 4..)?;
    let units: Vec<u16> = text
        .as_chunks::<2>()
        .0
        .iter()
        .take(declared.min(MAX_NAME_CHARS))
        .map(|&pair| u16::from_le_bytes(pair))
        .take_while(|&unit| unit != 0)
        .collect();
    let name = String::from_utf16(&units).ok()?;
    let plain = !name.is_empty() && name.chars().all(|c| !c.is_control() && c != '\u{FFFD}');
    plain.then_some(Driver { name, base, size })
}

/// The driver whose range holds `address`.
pub fn driver_at(drivers: &[Driver], address: u64) -> Option<&Driver> {
    drivers.iter().find(|driver| driver.contains(address))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    /// A 64-bit dump header with the given stop, type and time.
    pub(crate) fn header(code: u32, parameters: [u64; 4], dump_type: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[..8].copy_from_slice(b"PAGEDU64");
        put32(&mut bytes, MINOR_VERSION, 26100);
        put32(&mut bytes, MACHINE, 0x8664);
        put32(&mut bytes, PROCESSORS, 16);
        put32(&mut bytes, BUGCHECK_CODE, code);
        for (value, &offset) in parameters.iter().zip(&BUGCHECK_PARAMETERS) {
            put64(&mut bytes, offset, *value);
        }
        put32(&mut bytes, DUMP_TYPE, dump_type);
        // 2026-11-03 12:00:00 UTC as FILETIME.
        put64(&mut bytes, SYSTEM_TIME, 134_381_808_000_000_000);
        bytes
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// A small dump: header, triage header, driver list with `stride`, string pool.
    pub(crate) fn triage(
        code: u32,
        parameters: [u64; 4],
        drivers: &[(&str, u64, u32)],
        stride: usize,
    ) -> Vec<u8> {
        let mut bytes = header(code, parameters, TRIAGE);
        bytes.resize(HEADER_SIZE + TRIAGE_HEADER_SIZE, 0);
        let list_offset = bytes.len();
        bytes.resize(list_offset + drivers.len() * stride, 0);
        let pool_offset = bytes.len();
        let mut names = Vec::new();
        for (name, _, _) in drivers {
            names.push(bytes.len());
            let units: Vec<u16> = name.encode_utf16().collect();
            bytes.extend((units.len() as u32).to_le_bytes());
            for unit in units.iter().chain([0u16].iter()) {
                bytes.extend(unit.to_le_bytes());
            }
            while !bytes.len().is_multiple_of(8) {
                bytes.push(0);
            }
        }
        let pool_size = bytes.len() - pool_offset;
        for (index, (_, base, size)) in drivers.iter().enumerate() {
            let entry = list_offset + index * stride;
            put32(&mut bytes, entry + DRIVER_NAME_OFFSET, names[index] as u32);
            put64(&mut bytes, entry + DRIVER_BASE, *base);
            put32(&mut bytes, entry + DRIVER_SIZE, *size);
        }
        let triage = HEADER_SIZE;
        put32(
            &mut bytes,
            triage + TRIAGE_DRIVER_LIST_OFFSET,
            list_offset as u32,
        );
        put32(
            &mut bytes,
            triage + TRIAGE_DRIVER_COUNT,
            drivers.len() as u32,
        );
        put32(
            &mut bytes,
            triage + TRIAGE_STRING_POOL_OFFSET,
            pool_offset as u32,
        );
        put32(
            &mut bytes,
            triage + TRIAGE_STRING_POOL_SIZE,
            pool_size as u32,
        );
        bytes
    }

    fn read_bytes(bytes: Vec<u8>) -> Dump {
        let length = bytes.len() as u64;
        read(&mut Cursor::new(bytes), length)
    }

    #[test]
    fn layout_matches_the_published_header() {
        assert_eq!(HEADER_SIZE, 0x2000);
        assert_eq!(BUGCHECK_CODE, 0x38);
        assert_eq!(BUGCHECK_PARAMETERS, [0x40, 0x48, 0x50, 0x58]);
        assert_eq!(PROCESSORS, 0x34);
        assert_eq!(DUMP_TYPE, 0xF98);
        assert_eq!(SYSTEM_TIME, 0xFA8);
    }

    #[test]
    fn every_header_field_is_read() {
        let bytes = header(0xD1, [0x10, 2, 0, 0xFFFF_F801_2345_6789], 2);
        let header = parse_header(&bytes).unwrap();
        assert_eq!(header.code, 0xD1);
        assert_eq!(header.parameters, [0x10, 2, 0, 0xFFFF_F801_2345_6789]);
        assert_eq!(header.dump_type, 2);
        assert_eq!(header.processors, 16);
        assert_eq!(header.build, 26100);
        assert_eq!(header.machine, 0x8664);
        let seconds = header
            .time
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(seconds, 1_793_707_200);
        assert_eq!(
            read_bytes(bytes),
            Dump::Kernel64 {
                header,
                drivers: Drivers::NotTriage
            }
        );
    }

    #[test]
    fn a_small_dump_lists_its_drivers_and_finds_an_address() {
        let drivers = [
            ("ntoskrnl.exe", 0xFFFF_F802_4000_0000, 0x0104_5000),
            ("nvlddmkm.sys", 0xFFFF_F801_63EC_0000, 0x00AE_7000),
        ];
        for stride in DRIVER_STRIDES {
            let bytes = triage(0x116, [0, 0xFFFF_F801_6470_C14C, 0, 0], &drivers, stride);
            let Dump::Kernel64 { header, drivers } = read_bytes(bytes) else {
                panic!("not read");
            };
            let Drivers::Read { list, skipped } = drivers else {
                panic!("no driver list: {drivers:?}");
            };
            assert_eq!(skipped, 0);
            assert_eq!(list.len(), 2);
            assert_eq!(list[1].name, "nvlddmkm.sys");
            assert_eq!(list[1].base, 0xFFFF_F801_63EC_0000);
            assert_eq!(list[1].size, 0x00AE_7000);
            let hit = driver_at(&list, header.parameters[1]).unwrap();
            assert_eq!(hit.name, "nvlddmkm.sys");
            assert!(driver_at(&list, 0xFFFF_F801_63EC_0000 + 0x00AE_7000).is_none());
        }
    }

    #[test]
    fn wrong_signatures_and_short_files_are_named() {
        let mut bytes = header(0x50, [0; 4], 2);
        bytes[4..8].copy_from_slice(b"DUMP");
        assert!(parse_header(&bytes).unwrap_err().contains("32-bit"));
        bytes[..8].copy_from_slice(b"MDMP\x93\xa7\0\0");
        assert!(parse_header(&bytes).unwrap_err().contains("user-mode"));
        bytes[..8].copy_from_slice(b"NOTADUMP");
        assert!(parse_header(&bytes)
            .unwrap_err()
            .contains("unknown signature"));
        assert!(parse_header(b"PAGE").unwrap_err().contains("too short"));
        let truncated = header(0x50, [0; 4], 2)[..0x1000].to_vec();
        let Dump::Unreadable(reason) = read_bytes(truncated) else {
            panic!("truncated header read");
        };
        assert!(reason.starts_with("truncated"), "{reason}");
    }

    #[test]
    fn a_truncated_driver_list_is_reported_not_trusted() {
        let bytes = triage(
            0x0A,
            [0; 4],
            &[("a.sys", 0xFFFF_F800_0000_0000, 0x1000)],
            0x90,
        );
        let cut = bytes[..HEADER_SIZE + TRIAGE_HEADER_SIZE + 0x40].to_vec();
        let Dump::Kernel64 { drivers, .. } = read_bytes(cut) else {
            panic!("header not read");
        };
        assert!(matches!(drivers, Drivers::Unreadable(reason) if reason.starts_with("truncated")));
    }

    #[test]
    fn garbage_driver_entries_fit_no_layout() {
        let mut bytes = triage(
            0x0A,
            [0; 4],
            &[("a.sys", 0xFFFF_F800_0000_0000, 0x1000)],
            0x90,
        );
        let list = HEADER_SIZE + TRIAGE_HEADER_SIZE;
        put64(&mut bytes, list + DRIVER_BASE, 0x1234); // not a kernel address
        let Dump::Kernel64 { drivers, .. } = read_bytes(bytes) else {
            panic!("header not read");
        };
        assert!(matches!(drivers, Drivers::Unreadable(_)), "{drivers:?}");
    }
}
