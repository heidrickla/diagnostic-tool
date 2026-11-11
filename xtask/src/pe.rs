//! Minimal PE32/PE32+ reader for the release checks: imported DLL names,
//! top-level resource ids, debug directory entries and the load configuration. Shared with `tests/release_binary.rs` through
//! `#[path]` so both read executables alike.

use std::fmt;

const IMPORT_DIR: usize = 1;
const RESOURCE_DIR: usize = 2;
const DEBUG_DIR: usize = 6;
const LOAD_CONFIG_DIR: usize = 10;
const DELAY_IMPORT_DIR: usize = 13;

pub const RT_ICON_GROUP: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_MANIFEST: u32 = 24;
pub const DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const DEBUG_TYPE_REPRO: u32 = 16;

#[derive(Debug)]
pub struct PeError(String);

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed PE: {}", self.0)
    }
}

impl std::error::Error for PeError {}

fn err<T>(what: &str) -> Result<T, PeError> {
    Err(PeError(what.to_string()))
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

pub struct DebugEntry {
    pub kind: u32,
    pub data_offset: usize,
    pub data_size: usize,
}

pub struct Pe<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    dirs: Vec<(u32, u32)>,
    pe32_plus: bool,
}

impl<'a> Pe<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PeError> {
        let rd16 = |o: usize| read_u16(bytes, o);
        let rd32 = |o: usize| read_u32(bytes, o);
        if bytes.get(..2) != Some(b"MZ") {
            return err("no MZ header");
        }
        let pe = rd32(0x3c)? as usize;
        if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
            return err("no PE signature");
        }
        let coff = pe + 4;
        let section_count = rd16(coff + 2)? as usize;
        let optional_size = rd16(coff + 16)? as usize;
        let optional = coff + 20;
        let pe32_plus = match rd16(optional)? {
            0x20b => true,
            0x10b => false,
            _ => return err("unknown optional header magic"),
        };
        let dir_start = optional + if pe32_plus { 112 } else { 96 };
        let dir_count = rd32(dir_start - 4)? as usize;
        let mut dirs = Vec::with_capacity(dir_count.min(16));
        for i in 0..dir_count.min(16) {
            dirs.push((rd32(dir_start + i * 8)?, rd32(dir_start + i * 8 + 4)?));
        }
        let table = optional + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let s = table + i * 40;
            sections.push(Section {
                virtual_size: rd32(s + 8)?,
                virtual_address: rd32(s + 12)?,
                raw_size: rd32(s + 16)?,
                raw_offset: rd32(s + 20)?,
            });
        }
        Ok(Pe {
            bytes,
            sections,
            dirs,
            pe32_plus,
        })
    }

    fn offset(&self, rva: u32) -> Result<usize, PeError> {
        for s in &self.sections {
            let span = s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && rva - s.virtual_address < span {
                let delta = rva - s.virtual_address;
                if delta >= s.raw_size {
                    return err("RVA in uninitialized data");
                }
                return Ok((s.raw_offset + delta) as usize);
            }
        }
        err("RVA outside every section")
    }

    fn dir(&self, index: usize) -> Option<(u32, u32)> {
        self.dirs.get(index).copied().filter(|&(rva, _)| rva != 0)
    }

    fn c_string(&self, rva: u32) -> Result<String, PeError> {
        let start = self.offset(rva)?;
        let rest = self.bytes.get(start..).unwrap_or_default();
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(PeError("name".into()))?;
        Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
    }

    /// Every DLL named in the import and delay-import tables.
    pub fn imported_dlls(&self) -> Result<Vec<String>, PeError> {
        let mut names = Vec::new();
        if let Some((rva, _)) = self.dir(IMPORT_DIR) {
            let mut at = self.offset(rva)?;
            loop {
                let name_rva = read_u32(self.bytes, at + 12)?;
                if name_rva == 0 {
                    break;
                }
                names.push(self.c_string(name_rva)?);
                at += 20;
            }
        }
        if let Some((rva, _)) = self.dir(DELAY_IMPORT_DIR) {
            let mut at = self.offset(rva)?;
            loop {
                let name_rva = read_u32(self.bytes, at + 4)?;
                if name_rva == 0 {
                    break;
                }
                names.push(self.c_string(name_rva)?);
                at += 32;
            }
        }
        Ok(names)
    }

    /// Whether the resource tree holds an entry with numeric `kind` and `id`.
    pub fn has_resource(&self, kind: u32, id: u32) -> Result<bool, PeError> {
        let Some((rva, _)) = self.dir(RESOURCE_DIR) else {
            return Ok(false);
        };
        let root = self.offset(rva)?;
        let Some(type_dir) = self.resource_child(root, root, kind)? else {
            return Ok(false);
        };
        Ok(self.resource_child(root, type_dir, id)?.is_some())
    }

    // Returns the subdirectory offset of the numeric entry `id` in the directory at `dir`.
    fn resource_child(&self, root: usize, dir: usize, id: u32) -> Result<Option<usize>, PeError> {
        let named = read_u16(self.bytes, dir + 12)? as usize;
        let numbered = read_u16(self.bytes, dir + 14)? as usize;
        for i in named..named + numbered {
            let entry = dir + 16 + i * 8;
            if read_u32(self.bytes, entry)? == id {
                let target = read_u32(self.bytes, entry + 4)?;
                if target & 0x8000_0000 == 0 {
                    return err("resource entry is not a directory");
                }
                return Ok(Some(root + (target & 0x7fff_ffff) as usize));
            }
        }
        Ok(None)
    }

    pub fn debug_entries(&self) -> Result<Vec<DebugEntry>, PeError> {
        let Some((rva, size)) = self.dir(DEBUG_DIR) else {
            return Ok(Vec::new());
        };
        let start = self.offset(rva)?;
        (0..size as usize / 28)
            .map(|i| {
                let e = start + i * 28;
                Ok(DebugEntry {
                    kind: read_u32(self.bytes, e + 12)?,
                    data_size: read_u32(self.bytes, e + 16)? as usize,
                    data_offset: read_u32(self.bytes, e + 24)? as usize,
                })
            })
            .collect()
    }

    /// The PDB path recorded in the CodeView (RSDS) debug entry, if any.
    pub fn pdb_path(&self) -> Result<Option<String>, PeError> {
        for e in self.debug_entries()? {
            if e.kind != DEBUG_TYPE_CODEVIEW {
                continue;
            }
            let data = self
                .bytes
                .get(e.data_offset..e.data_offset + e.data_size)
                .ok_or(PeError("CodeView data".into()))?;
            if data.len() < 24 || &data[..4] != b"RSDS" {
                return err("CodeView entry is not RSDS");
            }
            let path = &data[24..];
            let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            return Ok(Some(String::from_utf8_lossy(&path[..end]).into_owned()));
        }
        Ok(None)
    }

    /// `DependentLoadFlags` from the load configuration directory, which the
    /// loader uses to search for the exe's own imports.
    pub fn dependent_load_flags(&self) -> Result<Option<u16>, PeError> {
        let Some((rva, _)) = self.dir(LOAD_CONFIG_DIR) else {
            return Ok(None);
        };
        let start = self.offset(rva)?;
        let field = if self.pe32_plus { 0x4e } else { 0x36 };
        let declared = read_u32(self.bytes, start)? as usize;
        if declared < field + 2 {
            return Ok(None);
        }
        Ok(Some(read_u16(self.bytes, start + field)?))
    }
}

/// True for the DLLs of the Visual C++ and Universal C runtimes.
pub fn is_crt_dll(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["vcruntime", "msvcp", "ucrtbase", "api-ms-win-crt-"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, PeError> {
    match bytes.get(at..at + 2) {
        Some(b) => Ok(u16::from_le_bytes([b[0], b[1]])),
        None => err("truncated"),
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, PeError> {
    match bytes.get(at..at + 4) {
        Some(b) => Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        None => err("truncated"),
    }
}
