//! An in-memory machine for the engine's tests: a registry, volumes, folders and files.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::machine::{
    DumpListing, FolderAccess, Hive, Key, Machine, Memory, PathKind, RawValue, Swap, Volume,
    VolumeKind, CRASH_CONTROL, ERROR_REPORTING_SERVICE, LOCAL_DUMPS, MEMORY_MANAGEMENT,
    REG_MULTI_SZ, REG_SZ,
};

const GIB: u64 = 1 << 30;

#[derive(Clone, Debug, Default)]
pub(crate) struct Fake {
    /// Keys by hive and lowercase path, each with its values by lowercase name.
    pub(crate) keys: BTreeMap<(Hive, String), BTreeMap<String, RawValue>>,
    pub(crate) folders: BTreeMap<String, (PathKind, Option<FolderAccess>)>,
    pub(crate) files: BTreeMap<String, u64>,
    pub(crate) dumps: BTreeMap<String, DumpListing>,
    pub(crate) denied: BTreeSet<String>,
    pub(crate) failing_reads: BTreeSet<String>,
    pub(crate) failing_writes: BTreeSet<String>,
    pub(crate) state: BTreeMap<String, String>,
    pub(crate) record: Vec<String>,
    pub(crate) elevated: Option<bool>,
    pub(crate) memory: Option<Memory>,
    /// Drive letter to kind and free bytes.
    pub(crate) volumes: BTreeMap<char, (VolumeKind, u64)>,
    pub(crate) writes: usize,
    /// Path prefixes that lead elsewhere, by lowercase prefix, for `resolved`.
    pub(crate) redirects: BTreeMap<String, String>,
    /// Short (8.3) path prefixes and their full names, by lowercase prefix, for `long_name`.
    pub(crate) short_names: BTreeMap<String, String>,
    /// Folder identities by lowercase path; a folder without one is "old:<path>".
    pub(crate) ids: BTreeMap<String, String>,
    pub(crate) next_id: u32,
    /// This program's file name; `DiagnosticTool.exe` when `None`.
    pub(crate) exe: Option<String>,
    pub(crate) key_held: bool,
    /// This process's id and start time.
    pub(crate) process: (u32, u64),
    /// Other processes that still run.
    pub(crate) others: BTreeSet<(u32, u64)>,
    /// Each key's last-write time by hive and lowercase path, from `clock`.
    pub(crate) stamps: BTreeMap<(Hive, String), u64>,
    pub(crate) clock: u64,
    /// The start time of this process cannot be read.
    pub(crate) no_start: bool,
    /// The settings files cannot be read.
    pub(crate) state_unreadable: bool,
    /// Another writer's change to a value (hive, path, name, value), made just before this
    /// program's next write or swap of that value: after it was read, before it is written.
    pub(crate) racer: Option<(Hive, String, String, Option<RawValue>)>,
}

fn low(text: &str) -> String {
    text.to_lowercase()
}

impl Fake {
    /// The other writer's change, when it is to this value: made once, now.
    fn race(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), String> {
        let Some((h, p, n, value)) = self.racer.take() else {
            return Ok(());
        };
        if (h, low(&p), low(&n)) != (hive, low(path), low(name)) {
            self.racer = Some((h, p, n, value));
            return Ok(());
        }
        match value {
            Some(value) => self.write_value(h, &p, &n, &value),
            None => self.delete_value(h, &p, &n),
        }
    }

    /// Windows 11 as it ships: automatic memory dump, a managed page file, no local dumps,
    /// with AlwaysKeepMemoryDump set so the stock items are all ready.
    pub(crate) fn windows_default() -> Self {
        let mut m = Self::windows_default_without_keep();
        m.dword(CRASH_CONTROL, "AlwaysKeepMemoryDump", 1);
        m
    }

    pub(crate) fn windows_default_without_keep() -> Self {
        let mut m = Fake {
            elevated: Some(true),
            memory: Some(Memory {
                physical: 16 * GIB,
                kernel: GIB,
            }),
            ..Fake::default()
        };
        m.volumes.insert('C', (VolumeKind::Fixed, 120 * GIB));
        m.volumes.insert('D', (VolumeKind::Fixed, 400 * GIB));
        m.volumes.insert('E', (VolumeKind::Removable, 30 * GIB));
        m.volumes.insert('N', (VolumeKind::Network, 900 * GIB));
        for folder in [
            r"C:\",
            r"C:\Windows",
            r"C:\ProgramData",
            r"C:\Users\tech\AppData\Local",
            r"D:\",
            r"E:\",
            r"N:\",
        ] {
            m.folders.insert(low(folder), (PathKind::Folder, None));
        }
        m.files.insert(low(r"C:\pagefile.sys"), 3 * GIB);
        m.dword(CRASH_CONTROL, "CrashDumpEnabled", 7);
        m.expand_string(CRASH_CONTROL, "DumpFile", r"%SystemRoot%\MEMORY.DMP");
        m.expand_string(CRASH_CONTROL, "MinidumpDir", r"%SystemRoot%\Minidump");
        m.dword(CRASH_CONTROL, "Overwrite", 1);
        m.dword(CRASH_CONTROL, "LogEvent", 1);
        m.dword(CRASH_CONTROL, "AutoReboot", 1);
        m.multi(MEMORY_MANAGEMENT, "PagingFiles", &[r"?:\pagefile.sys"]);
        m.dword(ERROR_REPORTING_SERVICE, "Start", 3);
        m
    }

    /// LocalDumps as set up would leave it, with its folder made.
    pub(crate) fn set_up_app_dumps(&mut self) {
        self.expand_string(LOCAL_DUMPS, "DumpFolder", super::DEFAULT_APP_FOLDER);
        self.dword(LOCAL_DUMPS, "DumpType", 1);
        self.dword(LOCAL_DUMPS, "DumpCount", 10);
        // Set up leaves this program out of application dumps.
        self.keys
            .entry((
                Hive::LocalMachine,
                low(&format!("{}\\DiagnosticTool.exe", LOCAL_DUMPS.path)),
            ))
            .or_default()
            .insert("dumpcount".into(), RawValue::dword(0));
        for folder in [
            r"C:\ProgramData\DiagnosticTool",
            r"C:\ProgramData\DiagnosticTool\CrashDumps",
        ] {
            self.folders.insert(low(folder), (PathKind::Folder, None));
        }
    }

    pub(crate) fn put(&mut self, key: Key, name: &str, value: RawValue) {
        self.keys
            .entry((key.hive, low(key.path)))
            .or_default()
            .insert(low(name), value);
    }

    pub(crate) fn dword(&mut self, key: Key, name: &str, value: u32) {
        self.put(key, name, RawValue::dword(value));
    }

    pub(crate) fn expand_string(&mut self, key: Key, name: &str, value: &str) {
        self.put(key, name, RawValue::expand_string(value));
    }

    pub(crate) fn text(&mut self, key: Key, name: &str, value: &str) {
        let mut raw = RawValue::expand_string(value);
        raw.kind = REG_SZ;
        self.put(key, name, raw);
    }

    pub(crate) fn multi(&mut self, key: Key, name: &str, values: &[&str]) {
        let mut data: Vec<u8> = Vec::new();
        for value in values {
            data.extend(value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        }
        data.extend([0, 0]);
        self.put(
            key,
            name,
            RawValue {
                kind: REG_MULTI_SZ,
                data,
            },
        );
    }

    pub(crate) fn value(&self, key: Key, name: &str) -> Option<&RawValue> {
        self.keys.get(&(key.hive, low(key.path)))?.get(&low(name))
    }

    pub(crate) fn dump_place(&mut self, path: &str, count: u64, bytes: u64) {
        self.dumps.insert(
            low(path),
            DumpListing {
                count,
                bytes,
                newest: Some((
                    PathBuf::from(path),
                    UNIX_EPOCH + Duration::from_secs(1_790_000_000 + count),
                    bytes / count.max(1),
                )),
                cut: false,
            },
        );
    }

    pub(crate) fn denied(&mut self, path: &str) {
        self.denied.insert(low(path));
    }

    pub(crate) fn fail_reads(&mut self, key: Key, name: &str) {
        self.failing_reads.insert(low(&key.named(name)));
    }

    pub(crate) fn fail_writes(&mut self, key: Key, name: &str) {
        self.failing_writes.insert(low(&key.named(name)));
    }

    /// Marks `path` written now, and its parent too when the key is made or removed.
    pub(crate) fn touch(&mut self, hive: Hive, path: &str) {
        self.clock += 1;
        self.stamps.insert((hive, low(path)), self.clock);
    }

    fn touch_parent(&mut self, hive: Hive, path: &str) {
        if let Some((up, _)) = path.rsplit_once('\\') {
            if self.keys.contains_key(&(hive, low(up))) {
                self.touch(hive, up);
            }
        }
    }

    fn full(hive: Hive, path: &str, name: &str) -> String {
        low(&format!("{}\\{path}\\{name}", hive.name()))
    }
}

impl Machine for Fake {
    fn read_value(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RawValue>, String> {
        if self.failing_reads.contains(&Self::full(hive, path, name)) {
            return Err(format!("{name} could not be read (access denied)"));
        }
        Ok(self
            .keys
            .get(&(hive, low(path)))
            .and_then(|values| values.get(&low(name)))
            .cloned())
    }

    fn key_exists(&self, hive: Hive, path: &str) -> Result<bool, String> {
        Ok(self.keys.contains_key(&(hive, low(path))))
    }

    fn subkeys(&self, hive: Hive, path: &str) -> Result<Vec<String>, String> {
        let prefix = format!("{}\\", low(path));
        Ok(self
            .keys
            .keys()
            .filter(|(h, p)| {
                *h == hive && p.starts_with(&prefix) && !p[prefix.len()..].contains('\\')
            })
            .map(|(_, p)| p[prefix.len()..].to_string())
            .collect())
    }

    fn value_names(&self, hive: Hive, path: &str) -> Result<Vec<String>, String> {
        Ok(self
            .keys
            .get(&(hive, low(path)))
            .map(|values| {
                values
                    .keys()
                    .map(|name| {
                        // Names are stored lowercase; give StateFlags back as Windows names them.
                        name.replace("stateflags", "StateFlags")
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn write_value(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        value: &RawValue,
    ) -> Result<(), String> {
        self.race(hive, path, name)?;
        if self.failing_writes.contains(&Self::full(hive, path, name)) {
            return Err(format!("{name} could not be written (access denied)"));
        }
        self.writes += 1;
        if !self.keys.contains_key(&(hive, low(path))) {
            self.touch_parent(hive, path);
        }
        self.keys
            .entry((hive, low(path)))
            .or_default()
            .insert(low(name), value.clone());
        self.touch(hive, path);
        Ok(())
    }

    fn delete_value(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), String> {
        self.race(hive, path, name)?;
        if self.failing_writes.contains(&Self::full(hive, path, name)) {
            return Err(format!("{name} could not be deleted (access denied)"));
        }
        self.writes += 1;
        if let Some(values) = self.keys.get_mut(&(hive, low(path))) {
            values.remove(&low(name));
            self.touch(hive, path);
        }
        Ok(())
    }

    fn swap_value(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        expect: &Option<RawValue>,
        new: &Option<RawValue>,
    ) -> Result<Swap<Option<RawValue>>, String> {
        self.race(hive, path, name)?;
        let now = self.read_value(hive, path, name)?;
        if now != *expect {
            return Ok(Swap::Changed(now));
        }
        match new {
            Some(value) => self.write_value(hive, path, name, value)?,
            None => self.delete_value(hive, path, name)?,
        }
        Ok(Swap::Done)
    }

    fn remove_key_if(
        &mut self,
        hive: Hive,
        path: &str,
        stamp: u64,
    ) -> Result<Swap<Option<u64>>, String> {
        let now = self.key_stamp(hive, path)?;
        if now != Some(stamp) {
            return Ok(Swap::Changed(now));
        }
        let empty = self
            .keys
            .get(&(hive, low(path)))
            .is_none_or(BTreeMap::is_empty)
            && self.subkeys(hive, path)?.is_empty();
        if !empty {
            return Err(super::machine::HOLDS_SETTINGS.into());
        }
        self.keys.remove(&(hive, low(path)));
        self.stamps.remove(&(hive, low(path)));
        self.touch_parent(hive, path);
        Ok(Swap::Done)
    }

    fn key_stamp(&self, hive: Hive, path: &str) -> Result<Option<u64>, String> {
        if !self.keys.contains_key(&(hive, low(path))) {
            return Ok(None);
        }
        Ok(Some(
            self.stamps.get(&(hive, low(path))).copied().unwrap_or(0),
        ))
    }

    fn expand(&self, text: &str) -> Result<String, String> {
        let mut out = text.to_string();
        for (name, value) in [
            ("%SystemRoot%", r"C:\Windows"),
            ("%windir%", r"C:\Windows"),
            ("%SystemDrive%", "C:"),
            ("%ProgramData%", r"C:\ProgramData"),
            ("%LOCALAPPDATA%", r"C:\Users\tech\AppData\Local"),
        ] {
            while let Some(at) = out.to_lowercase().find(&name.to_lowercase()) {
                out.replace_range(at..at + name.len(), value);
            }
        }
        Ok(out)
    }

    fn memory(&self) -> Result<Memory, String> {
        self.memory.ok_or_else(|| "memory could not be read".into())
    }

    fn volume(&self, path: &Path) -> Result<Volume, String> {
        let letter = path
            .to_string_lossy()
            .chars()
            .next()
            .map(|c| c.to_ascii_uppercase())
            .unwrap_or('?');
        let (kind, free) = self
            .volumes
            .get(&letter)
            .copied()
            .ok_or_else(|| format!("{} is on no drive this PC has", path.display()))?;
        Ok(Volume {
            root: PathBuf::from(format!("{letter}:\\")),
            kind,
            free,
        })
    }

    fn file_size(&self, path: &Path) -> Result<Option<u64>, String> {
        Ok(self.files.get(&low(&path.to_string_lossy())).copied())
    }

    fn folder(&self, path: &Path) -> Result<PathKind, String> {
        let key = low(path.to_string_lossy().trim_end_matches('\\'));
        let key = if key.len() == 2 {
            format!("{key}\\")
        } else {
            key
        };
        if let Some((folder, _)) = self.folders.get(&key) {
            return Ok(*folder);
        }
        Ok(if self.files.contains_key(&key) {
            PathKind::File
        } else {
            PathKind::Missing
        })
    }

    fn resolved(&self, path: &Path) -> Result<PathBuf, String> {
        let text = low(path.to_string_lossy().trim_end_matches('\\'));
        for (from, to) in &self.redirects {
            if let Some(rest) = text.strip_prefix(from.as_str()) {
                return Ok(PathBuf::from(format!("{to}{rest}")));
            }
        }
        Ok(PathBuf::from(text))
    }

    fn long_name(&self, path: &Path) -> Result<PathBuf, String> {
        let text = low(path.to_string_lossy().trim_end_matches('\\'));
        for (short, long) in &self.short_names {
            if let Some(rest) = text.strip_prefix(short.as_str()) {
                return Ok(PathBuf::from(format!("{long}{rest}")));
            }
        }
        Ok(PathBuf::from(text))
    }

    fn folder_id(&self, path: &Path) -> Result<Option<String>, String> {
        let key = low(path.to_string_lossy().trim_end_matches('\\'));
        if self.folder(path)? == PathKind::Missing {
            return Ok(None);
        }
        Ok(Some(
            self.ids
                .get(&key)
                .cloned()
                .unwrap_or_else(|| format!("old:{key}")),
        ))
    }

    fn exe_name(&self) -> Result<String, String> {
        Ok(self
            .exe
            .clone()
            .unwrap_or_else(|| "DiagnosticTool.exe".into()))
    }

    fn key_held(&self) -> bool {
        self.key_held
    }

    fn this_process(&self) -> Result<(u32, u64), String> {
        if self.no_start {
            return Err("this program's start time could not be read".into());
        }
        Ok(self.process)
    }

    fn running(&self, pid: u32, started: u64) -> bool {
        (pid, started) == self.process || self.others.contains(&(pid, started))
    }

    fn create_folder(&mut self, path: &Path, access: FolderAccess) -> Result<(), String> {
        let parent = path.parent().ok_or("no parent")?;
        if self.folder(parent)? != PathKind::Folder {
            return Err(format!("{} does not exist", parent.display()));
        }
        if self.folder(path)? != PathKind::Missing {
            return Err(format!("{} already exists", path.display()));
        }
        self.writes += 1;
        self.next_id += 1;
        self.ids.insert(
            low(&path.to_string_lossy()),
            format!("made:{}", self.next_id),
        );
        self.folders.insert(
            low(&path.to_string_lossy()),
            (PathKind::Folder, Some(access)),
        );
        Ok(())
    }

    fn remove_folder_if(&mut self, path: &Path, id: &str) -> Result<Swap<Option<String>>, String> {
        let now = self.folder_id(path)?;
        if now.as_deref() != Some(id) {
            return Ok(Swap::Changed(now));
        }
        let key = low(&path.to_string_lossy());
        let prefix = format!("{key}\\");
        let holds = self.folders.keys().any(|k| k.starts_with(&prefix))
            || self.files.keys().any(|k| k.starts_with(&prefix))
            || self.state.keys().any(|k| k.starts_with(&prefix));
        if holds {
            return Err(super::machine::HOLDS_FILES.into());
        }
        self.writes += 1;
        self.folders.remove(&key);
        Ok(Swap::Done)
    }

    fn dumps(
        &self,
        path: &Path,
        _limit: usize,
        _stop: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<DumpListing>, String> {
        let key = low(&path.to_string_lossy());
        if self.denied.contains(&key) {
            return Err("needs administrator rights".into());
        }
        Ok(self.dumps.get(&key).cloned())
    }

    fn elevated(&self) -> Option<bool> {
        self.elevated
    }

    fn read_state(&self, path: &Path) -> Result<Option<String>, String> {
        if self.state_unreadable {
            return Err("access denied".into());
        }
        Ok(self.state.get(&low(&path.to_string_lossy())).cloned())
    }

    fn write_state(&mut self, path: &Path, text: &str) -> Result<(), String> {
        // As the real one: missing parent folders are made first.
        let mut parent = path.parent();
        while let Some(folder) = parent {
            if self.folder(folder)? == PathKind::Folder {
                break;
            }
            self.folders
                .insert(low(&folder.to_string_lossy()), (PathKind::Folder, None));
            parent = folder.parent();
        }
        self.state.insert(low(&path.to_string_lossy()), text.into());
        Ok(())
    }

    fn remove_state(&mut self, path: &Path) -> Result<(), String> {
        self.state.remove(&low(&path.to_string_lossy()));
        Ok(())
    }

    fn record_changes(&mut self, what: &str, lines: &[String]) -> Result<(), String> {
        self.record.push(what.into());
        self.record.extend(lines.iter().cloned());
        Ok(())
    }
}
