//! What the crash dump engine reads and changes on a PC, behind one trait, so the engine's
//! logic is tested against an in-memory machine and never needs a real registry.
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    pub fn name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }
}

/// A registry key the engine reads or writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub hive: Hive,
    pub path: &'static str,
}

impl Key {
    pub fn named(self, name: &str) -> String {
        format!("{}\\{}\\{name}", self.hive.name(), self.path)
    }
}

const fn machine(path: &'static str) -> Key {
    Key {
        hive: Hive::LocalMachine,
        path,
    }
}

pub const CRASH_CONTROL: Key = machine(r"SYSTEM\CurrentControlSet\Control\CrashControl");
pub const LOCAL_DUMPS: Key =
    machine(r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps");
pub const ERROR_REPORTING: Key = machine(r"SOFTWARE\Microsoft\Windows\Windows Error Reporting");
pub const ERROR_REPORTING_POLICY: Key =
    machine(r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting");
pub const ERROR_REPORTING_SERVICE: Key = machine(r"SYSTEM\CurrentControlSet\Services\WerSvc");
pub const MEMORY_MANAGEMENT: Key =
    machine(r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
pub const AEDEBUG: Key = machine(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug");
pub const STORAGE_SENSE: Key = Key {
    hive: Hive::CurrentUser,
    path: r"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy",
};
pub const STORAGE_SENSE_POLICY: Key = machine(r"SOFTWARE\Policies\Microsoft\Windows\StorageSense");
pub const CLEANUP_MEMORY_DUMPS: Key = machine(
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files",
);
pub const CLEANUP_MINIDUMPS: Key = machine(
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files",
);

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;

/// A registry value exactly as stored: its type and its bytes, so a saved value is put
/// back byte for byte whatever it held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawValue {
    /// The registry type number (REG_SZ 1, REG_EXPAND_SZ 2, REG_DWORD 4, REG_MULTI_SZ 7).
    pub kind: u32,
    /// The stored bytes, as lowercase hexadecimal.
    #[serde(with = "hex")]
    pub data: Vec<u8>,
}

impl RawValue {
    pub fn dword(value: u32) -> Self {
        Self {
            kind: REG_DWORD,
            data: value.to_le_bytes().to_vec(),
        }
    }

    pub fn expand_string(text: &str) -> Self {
        Self {
            kind: REG_EXPAND_SZ,
            data: utf16_bytes(text),
        }
    }

    pub fn as_dword(&self) -> Option<u32> {
        (self.kind == REG_DWORD && self.data.len() == 4)
            .then(|| u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
    }

    /// The text of a REG_SZ or REG_EXPAND_SZ value, up to its first NUL.
    pub fn as_text(&self) -> Option<String> {
        matches!(self.kind, REG_SZ | REG_EXPAND_SZ).then(|| {
            let units = utf16_units(&self.data);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            String::from_utf16_lossy(&units[..end])
        })
    }

    /// The strings of a REG_MULTI_SZ value.
    pub fn as_strings(&self) -> Option<Vec<String>> {
        (self.kind == REG_MULTI_SZ).then(|| {
            utf16_units(&self.data)
                .split(|&u| u == 0)
                .filter(|part| !part.is_empty())
                .map(String::from_utf16_lossy)
                .collect()
        })
    }

    /// How the value reads to a person: a number, a text, or its type and size.
    pub fn describe(&self) -> String {
        if let Some(number) = self.as_dword() {
            return number.to_string();
        }
        if let Some(text) = self.as_text() {
            return format!("\"{text}\"");
        }
        if let Some(strings) = self.as_strings() {
            return format!("[{}]", strings.join(", "));
        }
        format!("type {} with {} bytes", self.kind, self.data.len())
    }
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect()
}

mod hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd hexadecimal length"));
        }
        (0..text.len())
            .step_by(2)
            .map(|at| {
                u8::from_str_radix(text.get(at..at + 2).unwrap_or("x"), 16)
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

/// What kind of volume holds a path, from GetDriveTypeW.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeKind {
    Fixed,
    Removable,
    Network,
    CdRom,
    RamDisk,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    /// The volume's root, such as `C:\`.
    pub root: PathBuf,
    pub kind: VolumeKind,
    pub free: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    Missing,
    Folder,
    /// A junction, symbolic link or other reparse point.
    Link,
    File,
}

/// The access list a folder the engine makes is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderAccess {
    /// Inherited from the parent folder, as Windows would make it.
    Inherited,
    /// Every signed-in account may add files, each file is its maker's, and only the
    /// maker, administrators and SYSTEM may read it.
    CrashingProcesses,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    pub physical: u64,
    /// Paged and non-paged pool in use now: the measure of a kernel dump's size.
    pub kernel: u64,
}

/// The dump files in one place.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DumpListing {
    pub count: u64,
    pub bytes: u64,
    /// The newest file, its time and size.
    pub newest: Option<(PathBuf, SystemTime, u64)>,
    /// The listing stopped at its limit.
    pub cut: bool,
}

pub use crate::restore::Swap;

/// Why a key or a folder this program made is kept: it holds what was added since.
pub const HOLDS_SETTINGS: &str = "it holds settings added since";
pub const HOLDS_FILES: &str = "it holds files, such as dumps written since set up";

/// Everything the engine reads and changes. Errors are plain sentences for the report.
pub trait Machine {
    /// A value, or `None` when the value or its key is absent.
    fn read_value(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RawValue>, String>;
    fn key_exists(&self, hive: Hive, path: &str) -> Result<bool, String>;
    fn subkeys(&self, hive: Hive, path: &str) -> Result<Vec<String>, String>;
    fn value_names(&self, hive: Hive, path: &str) -> Result<Vec<String>, String>;
    /// Writes a value, making its key if needed.
    fn write_value(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        value: &RawValue,
    ) -> Result<(), String>;
    /// Deletes a value; an absent value or key is not an error.
    fn delete_value(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), String>;
    /// Puts `new` in a value (`None` deletes it) only while it holds `expect`, the compare
    /// and the write as one operation (a registry transaction on Windows). `Changed` with what
    /// it holds otherwise, and nothing written.
    fn swap_value(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        expect: &Option<RawValue>,
        new: &Option<RawValue>,
    ) -> Result<Swap<Option<RawValue>>, String>;
    /// Removes a key only while its last-write time is `stamp` and it holds no values and no
    /// subkeys, as one operation (a registry transaction on Windows). `Changed` with its time
    /// now when it was written to since, `None` when it is gone; Err when it holds settings.
    fn remove_key_if(
        &mut self,
        hive: Hive,
        path: &str,
        stamp: u64,
    ) -> Result<Swap<Option<u64>>, String>;
    /// When a key was last written to (a FILETIME: its values set or deleted, or a subkey
    /// made or removed), or `None` when it does not exist. What tells a key this program
    /// made from one made again since under the same name.
    fn key_stamp(&self, hive: Hive, path: &str) -> Result<Option<u64>, String>;
    /// Expands environment variables in this process's environment.
    fn expand(&self, text: &str) -> Result<String, String>;
    fn memory(&self) -> Result<Memory, String>;
    /// The volume holding `path`, which need not exist yet.
    fn volume(&self, path: &Path) -> Result<Volume, String>;
    /// A file's size, or `None` when it does not exist.
    fn file_size(&self, path: &Path) -> Result<Option<u64>, String>;
    /// What the last part of `path` is. A link in a part above it is followed, so a whole
    /// path is checked part by part (`link_on_path`).
    fn folder(&self, path: &Path) -> Result<PathKind, String>;
    /// The path Windows reaches for an existing file or folder, every link and mount point
    /// followed.
    fn resolved(&self, path: &Path) -> Result<PathBuf, String>;
    /// An existing path with each short (8.3) part written out in full and no link
    /// followed, so it compares with `resolved` by text.
    fn long_name(&self, path: &Path) -> Result<PathBuf, String>;
    /// A folder's identity as Windows numbers it (its volume and file ID), or `None` when
    /// nothing is there. A folder removed and made again under the same name has another.
    fn folder_id(&self, path: &Path) -> Result<Option<String>, String>;
    /// This program's file name, such as `DiagnosticTool.exe`: the name application dump
    /// settings for it go under.
    fn exe_name(&self) -> Result<String, String>;
    /// Whether this program holds, or has held since it started, a BitLocker recovery key
    /// (`bitlocker::key_held`).
    fn key_held(&self) -> bool;
    /// This process: its id and start time, which together name it even once the id is
    /// given to another process. Err when the start time cannot be read: a holder recorded
    /// without it would read as ended.
    fn this_process(&self) -> Result<(u32, u64), String>;
    /// Whether the process with that id and start time still runs; true when that cannot
    /// be told, so nothing it may rely on is taken away from it.
    fn running(&self, pid: u32, started: u64) -> bool;
    /// Makes one folder whose parent exists.
    fn create_folder(&mut self, path: &Path, access: FolderAccess) -> Result<(), String>;
    /// Removes a folder only while it is the folder with identity `id` (`folder_id`) and
    /// empty, through one handle that checks the identity and removes it. `Changed` with what
    /// is there now; Err when it holds files.
    fn remove_folder_if(&mut self, path: &Path, id: &str) -> Result<Swap<Option<String>>, String>;
    /// The `*.dmp` files at `path` (a file or a folder), or `None` when nothing is there.
    /// The listing looks at a bounded number of entries and ends early once `stop` is set.
    fn dumps(
        &self,
        path: &Path,
        limit: usize,
        stop: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<DumpListing>, String>;
    /// Whether this process has administrator rights; `None` when that cannot be read.
    fn elevated(&self) -> Option<bool>;
    /// The settings file the engine keeps, or `None` when there is none.
    fn read_state(&self, path: &Path) -> Result<Option<String>, String>;
    /// Writes the settings file whole, so a cut write never leaves half a file.
    fn write_state(&mut self, path: &Path, text: &str) -> Result<(), String>;
    fn remove_state(&mut self, path: &Path) -> Result<(), String>;
    /// Adds lines to the change record the session report lists.
    fn record_changes(&mut self, what: &str, lines: &[String]) -> Result<(), String>;
}
