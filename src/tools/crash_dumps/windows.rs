//! The real machine: the registry (64-bit view), volumes, folders and files through Win32.
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegCreateKeyTransactedW, RegDeleteKeyTransactedW,
    RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegOpenKeyTransactedW,
    RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE,
};

use super::machine::{
    DumpListing, FolderAccess, Hive, Machine, Memory, PathKind, RawValue, Swap, Volume, VolumeKind,
    HOLDS_FILES, HOLDS_SETTINGS,
};
use crate::tools::crashes;

pub(crate) struct Windows;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn root(hive: Hive) -> HKEY {
    match hive {
        Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        Hive::CurrentUser => HKEY_CURRENT_USER,
    }
}

fn error_text(code: u32) -> String {
    match code {
        ERROR_ACCESS_DENIED => "access denied".into(),
        other => io::Error::from_raw_os_error(other as i32).to_string(),
    }
}

/// An open registry key, closed when dropped.
struct Opened(HKEY);

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW or RegCreateKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Opens an existing file or folder to ask Windows about it, links followed: attributes
/// only, sharing everything.
fn open_to_query(path: &Path) -> Result<std::os::windows::io::OwnedHandle, String> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let name = wide_path(path);
    // SAFETY: `name` is nul-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "{} could not be opened ({})",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    // SAFETY: the handle is open and owned by nothing else.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) })
}

/// A kernel transaction for registry changes made as one operation: rolled back when dropped
/// unless committed.
struct Transaction {
    handle: windows_sys::Win32::Foundation::HANDLE,
    committed: bool,
}

/// How long a registry transaction may stay open before Windows rolls it back.
const TRANSACTION_MS: u32 = 10_000;

impl Transaction {
    fn begin() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::CreateTransaction;
        // SAFETY: no attributes, no unit of work, no description; the handle is checked.
        let handle =
            unsafe { CreateTransaction(null_mut(), null_mut(), 0, 0, 0, TRANSACTION_MS, null()) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(format!(
                "a registry transaction could not be started ({})",
                io::Error::last_os_error()
            ));
        }
        Ok(Self {
            handle,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), String> {
        use windows_sys::Win32::Storage::FileSystem::CommitTransaction;
        // SAFETY: the transaction is open.
        if unsafe { CommitTransaction(self.handle) } == 0 {
            return Err(format!(
                "the change could not be committed ({})",
                io::Error::last_os_error()
            ));
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Storage::FileSystem::RollbackTransaction;
        // SAFETY: the transaction is open; a rollback of a committed one is not asked.
        unsafe {
            if !self.committed {
                RollbackTransaction(self.handle);
            }
            CloseHandle(self.handle);
        }
    }
}

/// A registry error, with the one a transaction meets when another writer holds the key.
fn transacted_error(what: &str, code: u32) -> String {
    match code {
        windows_sys::Win32::Foundation::ERROR_TRANSACTIONAL_CONFLICT => {
            format!("{what}: another program is changing it at this moment")
        }
        other => format!("{what} ({})", error_text(other)),
    }
}

impl Windows {
    /// `swap_value`, with `between` run after the key is held by the transaction and before
    /// the value is compared: where a live test acts as another writer.
    fn swap_value_between(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        expect: &Option<RawValue>,
        new: &Option<RawValue>,
        between: &mut dyn FnMut(),
    ) -> Result<Swap<Option<RawValue>>, String> {
        // A transaction that another writer aborted is tried again a few times while the
        // value still holds what was expected.
        for _ in 0..3 {
            if let Some(swap) =
                self.swap_value_once(hive, path, name, expect, new, &mut *between)?
            {
                return Ok(swap);
            }
        }
        Err(format!(
            "{name} was left as it is: another program kept changing {path} at the same moment"
        ))
    }

    /// One try of `swap_value_between`; `None` when another writer aborted the transaction
    /// while the value still holds what was expected.
    ///
    /// The transaction writes the value first, then compares what is committed, read outside
    /// it, and commits. Measured (`live_registry_transaction_against_another_writer`): a
    /// writer outside the transaction is not held back, but its write to the value aborts
    /// the transaction, so the commit fails and that writer's value stays. Either the other
    /// write comes before the compare and is seen, or after it and the swap does not take:
    /// no change is overwritten.
    fn swap_value_once(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        expect: &Option<RawValue>,
        new: &Option<RawValue>,
        between: &mut dyn FnMut(),
    ) -> Result<Option<Swap<Option<RawValue>>>, String> {
        let transaction = Transaction::begin()?;
        let path_w = wide(path);
        let name_w = wide(name);
        let mut handle: HKEY = null_mut();
        let status = match new {
            // SAFETY: `path_w` is nul-terminated; `handle` is a valid out pointer.
            Some(_) => unsafe {
                RegCreateKeyTransactedW(
                    root(hive),
                    path_w.as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    null(),
                    &mut handle,
                    null_mut(),
                    transaction.handle,
                    null(),
                )
            },
            // SAFETY: as above.
            None => unsafe {
                RegOpenKeyTransactedW(
                    root(hive),
                    path_w.as_ptr(),
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &mut handle,
                    transaction.handle,
                    null(),
                )
            },
        };
        match status {
            0 => {}
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND if new.is_none() => {
                // The key is gone, so the value is too: nothing to delete.
                return Ok(Some(match self.read_value(hive, path, name)? {
                    now if now == *expect => Swap::Done,
                    now => Swap::Changed(now),
                }));
            }
            other => {
                return Err(transacted_error(
                    &format!("{path} could not be opened"),
                    other,
                ))
            }
        }
        let key = Opened(handle);
        let status = match new {
            // SAFETY: `data` is the value's bytes, passed with its length.
            Some(value) => unsafe {
                RegSetValueExW(
                    key.0,
                    name_w.as_ptr(),
                    0,
                    value.kind,
                    value.data.as_ptr(),
                    value.data.len() as u32,
                )
            },
            // SAFETY: the key is open for setting values and `name_w` is nul-terminated.
            None => match unsafe { RegDeleteValueW(key.0, name_w.as_ptr()) } {
                ERROR_FILE_NOT_FOUND => 0,
                other => other,
            },
        };
        if status != 0 {
            return Err(transacted_error(
                &format!("{name} could not be written"),
                status,
            ));
        }
        between();
        // What is committed now, read outside the transaction.
        let now = self.read_value(hive, path, name)?;
        if now != *expect {
            return Ok(Some(Swap::Changed(now)));
        }
        drop(key);
        if let Err(why) = transaction.commit() {
            // Another writer aborted it: what it wrote stays, and is said.
            return match self.read_value(hive, path, name)? {
                now if now == *new => Ok(Some(Swap::Done)),
                now if now != *expect => Ok(Some(Swap::Changed(now))),
                _ if why.contains("6704") => Ok(None),
                _ => Err(why),
            };
        }
        Ok(Some(Swap::Done))
    }

    /// `remove_key_if`, with `between` as in `swap_value_between`.
    fn remove_key_between(
        &mut self,
        hive: Hive,
        path: &str,
        stamp: u64,
        between: &mut dyn FnMut(),
    ) -> Result<Swap<Option<u64>>, String> {
        let transaction = Transaction::begin()?;
        let path_w = wide(path);
        // SAFETY: `path_w` is nul-terminated; the deletion is held by the transaction.
        let status = unsafe {
            RegDeleteKeyTransactedW(
                root(hive),
                path_w.as_ptr(),
                KEY_WOW64_64KEY,
                0,
                transaction.handle,
                null(),
            )
        };
        between();
        let now = self.key_stamp(hive, path)?;
        if now != Some(stamp) {
            return Ok(Swap::Changed(now));
        }
        if key_counts(hive, path)? != Some((0, 0)) {
            return Err(HOLDS_SETTINGS.into());
        }
        if status != 0 {
            return Err(transacted_error(
                &format!("{path} could not be removed"),
                status,
            ));
        }
        if let Err(why) = transaction.commit() {
            // Another writer aborted it: the key stays, written to since, and is said.
            return match self.key_stamp(hive, path)? {
                None => Ok(Swap::Done),
                Some(now) if now != stamp => Ok(Swap::Changed(Some(now))),
                Some(_) => Err(why),
            };
        }
        Ok(Swap::Done)
    }
}

/// A key's subkeys and values, counted; `None` when it does not exist.
fn key_counts(hive: Hive, path: &str) -> Result<Option<(u32, u32)>, String> {
    let Some(key) = open(hive, path, KEY_READ)? else {
        return Ok(None);
    };
    let (mut subkeys, mut values) = (0u32, 0u32);
    // SAFETY: only the two counts are asked for; every other pointer is null.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null(),
            &mut subkeys,
            null_mut(),
            null_mut(),
            &mut values,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("{path} could not be read ({})", error_text(status)));
    }
    Ok(Some((subkeys, values)))
}

/// A file's or folder's identity through an open handle: its volume serial number and its
/// 128-bit file ID, as hex.
fn file_id(handle: windows_sys::Win32::Foundation::HANDLE, path: &Path) -> Result<String, String> {
    use windows_sys::Win32::Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx};
    // FILE_ID_INFO: the volume serial number (8 bytes) and the 128-bit file ID.
    let mut info = [0u8; 24];
    // SAFETY: the handle is open and `info` is writable for its stated size.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            info.as_mut_ptr().cast(),
            info.len() as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "the identity of {} could not be read ({})",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(info.iter().map(|b| format!("{b:02x}")).collect())
}

/// Opens a key; `Ok(None)` when it does not exist.
fn open(hive: Hive, path: &str, access: u32) -> Result<Option<Opened>, String> {
    let mut handle: HKEY = null_mut();
    let path_w = wide(path);
    // SAFETY: `path_w` is nul-terminated and `handle` is a valid out pointer.
    let status = unsafe {
        RegOpenKeyExW(
            root(hive),
            path_w.as_ptr(),
            0,
            access | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    match status {
        0 => Ok(Some(Opened(handle))),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        other => Err(format!(
            "{}\\{path} could not be opened ({})",
            hive.name(),
            error_text(other)
        )),
    }
}

impl Machine for Windows {
    fn read_value(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RawValue>, String> {
        let Some(key) = open(hive, path, KEY_READ)? else {
            return Ok(None);
        };
        let name_w = wide(name);
        let mut data = vec![0u8; 512];
        loop {
            let mut kind = 0u32;
            let mut size = data.len() as u32;
            // SAFETY: `data` has `size` writable bytes and `name_w` is nul-terminated.
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name_w.as_ptr(),
                    null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut size,
                )
            };
            match status {
                0 => {
                    data.truncate(size as usize);
                    return Ok(Some(RawValue { kind, data }));
                }
                ERROR_MORE_DATA => data.resize((size as usize).max(data.len() * 2), 0),
                ERROR_FILE_NOT_FOUND => return Ok(None),
                other => return Err(format!("{name} could not be read ({})", error_text(other))),
            }
        }
    }

    fn key_exists(&self, hive: Hive, path: &str) -> Result<bool, String> {
        Ok(open(hive, path, KEY_READ)?.is_some())
    }

    fn subkeys(&self, hive: Hive, path: &str) -> Result<Vec<String>, String> {
        let Some(key) = open(hive, path, KEY_READ)? else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        let mut name = vec![0u16; 256];
        for index in 0.. {
            let mut length = name.len() as u32;
            // SAFETY: `name` holds `length` UTF-16 units; the other pointers may be null.
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match status {
                0 => found.push(String::from_utf16_lossy(&name[..length as usize])),
                ERROR_NO_MORE_ITEMS => break,
                other => {
                    return Err(format!(
                        "{path} could not be listed ({})",
                        error_text(other)
                    ))
                }
            }
        }
        Ok(found)
    }

    fn value_names(&self, hive: Hive, path: &str) -> Result<Vec<String>, String> {
        let Some(key) = open(hive, path, KEY_READ)? else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        let mut name = vec![0u16; 16_384];
        for index in 0.. {
            let mut length = name.len() as u32;
            // SAFETY: `name` holds `length` UTF-16 units; no data is asked for.
            let status = unsafe {
                RegEnumValueW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match status {
                0 => found.push(String::from_utf16_lossy(&name[..length as usize])),
                ERROR_NO_MORE_ITEMS => break,
                other => {
                    return Err(format!(
                        "{path} could not be listed ({})",
                        error_text(other)
                    ))
                }
            }
        }
        Ok(found)
    }

    fn write_value(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        value: &RawValue,
    ) -> Result<(), String> {
        let path_w = wide(path);
        let mut handle: HKEY = null_mut();
        // SAFETY: `path_w` is nul-terminated; `handle` is a valid out pointer.
        let status = unsafe {
            RegCreateKeyExW(
                root(hive),
                path_w.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                null(),
                &mut handle,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(format!(
                "{path} could not be opened for writing ({})",
                error_text(status)
            ));
        }
        let key = Opened(handle);
        let name_w = wide(name);
        // SAFETY: `data` is the value's bytes, passed with its length.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name_w.as_ptr(),
                0,
                value.kind,
                value.data.as_ptr(),
                value.data.len() as u32,
            )
        };
        if status != 0 {
            return Err(format!(
                "{name} could not be written ({})",
                error_text(status)
            ));
        }
        Ok(())
    }

    fn delete_value(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), String> {
        let Some(key) = open(hive, path, KEY_SET_VALUE)? else {
            return Ok(());
        };
        let name_w = wide(name);
        // SAFETY: the key is open for setting values and `name_w` is nul-terminated.
        match unsafe { RegDeleteValueW(key.0, name_w.as_ptr()) } {
            0 | ERROR_FILE_NOT_FOUND => Ok(()),
            other => Err(format!(
                "{name} could not be deleted ({})",
                error_text(other)
            )),
        }
    }

    fn swap_value(
        &mut self,
        hive: Hive,
        path: &str,
        name: &str,
        expect: &Option<RawValue>,
        new: &Option<RawValue>,
    ) -> Result<Swap<Option<RawValue>>, String> {
        self.swap_value_between(hive, path, name, expect, new, &mut || {})
    }

    fn remove_key_if(
        &mut self,
        hive: Hive,
        path: &str,
        stamp: u64,
    ) -> Result<Swap<Option<u64>>, String> {
        self.remove_key_between(hive, path, stamp, &mut || {})
    }

    fn key_stamp(&self, hive: Hive, path: &str) -> Result<Option<u64>, String> {
        use windows_sys::Win32::Foundation::FILETIME;
        let Some(key) = open(hive, path, KEY_READ)? else {
            return Ok(None);
        };
        let mut written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: only the last-write time is asked for; every other pointer is null.
        let status = unsafe {
            RegQueryInfoKeyW(
                key.0,
                null_mut(),
                null_mut(),
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut written,
            )
        };
        if status != 0 {
            return Err(format!(
                "when {path} was last written could not be read ({})",
                error_text(status)
            ));
        }
        Ok(Some(
            (u64::from(written.dwHighDateTime) << 32) | u64::from(written.dwLowDateTime),
        ))
    }

    fn expand(&self, text: &str) -> Result<String, String> {
        // As ExpandEnvironmentStrings: a %NAME% that is not set stays as written.
        let parts: Vec<&str> = text.split('%').collect();
        let mut out = String::from(parts[0]);
        let mut index = 1;
        while index < parts.len() {
            let name = parts[index];
            match (index + 1 < parts.len(), std::env::var(name)) {
                (true, Ok(value)) if !name.is_empty() => {
                    out.push_str(&value);
                    out.push_str(parts[index + 1]);
                    index += 2;
                }
                _ => {
                    out.push('%');
                    out.push_str(name);
                    index += 1;
                }
            }
        }
        Ok(out)
    }

    fn memory(&self) -> Result<Memory, String> {
        use windows_sys::Win32::System::ProcessStatus::{
            GetPerformanceInfo, PERFORMANCE_INFORMATION,
        };
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        // SAFETY: the struct is zeroed with its length set, as the call requires.
        if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
            return Err("the memory size could not be read".into());
        }
        let mut info: PERFORMANCE_INFORMATION = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
        // SAFETY: the struct and its size are passed together.
        if unsafe { GetPerformanceInfo(&mut info, size) } == 0 {
            return Err("the kernel memory in use could not be read".into());
        }
        Ok(Memory {
            physical: status.ullTotalPhys,
            kernel: info.KernelTotal as u64 * info.PageSize as u64,
        })
    }

    fn volume(&self, path: &Path) -> Result<Volume, String> {
        use windows_sys::Win32::Storage::FileSystem::{
            GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumePathNameW,
        };
        let target = wide_path(path);
        let mut mount = vec![0u16; 1024];
        // SAFETY: `target` is nul-terminated and `mount` holds its stated length.
        let found =
            unsafe { GetVolumePathNameW(target.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) }
                != 0;
        let root_text = if found {
            let end = mount.iter().position(|&u| u == 0).unwrap_or(mount.len());
            String::from_utf16_lossy(&mount[..end])
        } else {
            let text = path.to_string_lossy();
            text.get(..3)
                .filter(|r| r.ends_with(":\\"))
                .ok_or_else(|| format!("{} is on no volume Windows knows", path.display()))?
                .to_string()
        };
        let root_w = wide(&root_text);
        // SAFETY: `root_w` is a nul-terminated volume root.
        let kind = match unsafe { GetDriveTypeW(root_w.as_ptr()) } {
            3 => VolumeKind::Fixed,
            2 => VolumeKind::Removable,
            4 => VolumeKind::Network,
            5 => VolumeKind::CdRom,
            6 => VolumeKind::RamDisk,
            _ => VolumeKind::Unknown,
        };
        let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
        // SAFETY: the three out pointers are valid u64s.
        let ok =
            unsafe { GetDiskFreeSpaceExW(root_w.as_ptr(), &mut free, &mut total, &mut total_free) };
        if ok == 0 {
            return Err(format!("the free space on {root_text} could not be read"));
        }
        Ok(Volume {
            root: PathBuf::from(root_text),
            kind,
            free,
        })
    }

    fn file_size(&self, path: &Path) -> Result<Option<u64>, String> {
        // std falls back to the folder listing for files in use, such as pagefile.sys.
        match fs::metadata(path) {
            Ok(meta) if meta.is_file() => Ok(Some(meta.len())),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{} could not be read ({e})", path.display())),
        }
    }

    fn folder(&self, path: &Path) -> Result<PathKind, String> {
        use std::os::windows::fs::MetadataExt;
        const REPARSE_POINT: u32 = 0x400;
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_attributes() & REPARSE_POINT != 0 => Ok(PathKind::Link),
            Ok(meta) if meta.is_dir() => Ok(PathKind::Folder),
            Ok(_) => Ok(PathKind::File),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(PathKind::Missing),
            Err(e) => Err(format!("{} could not be read ({e})", path.display())),
        }
    }

    fn resolved(&self, path: &Path) -> Result<PathBuf, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
        let handle = open_to_query(path)?;
        let mut name = vec![0u16; 1024];
        // SAFETY: the handle is open and `name` is writable for its stated length. Flags 0:
        // the normalized name with its drive letter.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_raw_handle(),
                name.as_mut_ptr(),
                name.len() as u32,
                0,
            )
        } as usize;
        if len == 0 || len >= name.len() {
            return Err(format!(
                "where {} leads could not be read ({})",
                path.display(),
                io::Error::last_os_error()
            ));
        }
        let text = String::from_utf16_lossy(&name[..len]);
        Ok(PathBuf::from(match text.strip_prefix(r"\\?\UNC\") {
            Some(share) => format!(r"\\{share}"),
            None => text.strip_prefix(r"\\?\").unwrap_or(&text).to_string(),
        }))
    }

    fn long_name(&self, path: &Path) -> Result<PathBuf, String> {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
        let wide = wide_path(path);
        let mut name = vec![0u16; 1024];
        // SAFETY: `wide` is nul-terminated and `name` is writable for its stated length.
        let len = unsafe { GetLongPathNameW(wide.as_ptr(), name.as_mut_ptr(), name.len() as u32) }
            as usize;
        if len == 0 || len >= name.len() {
            return Err(format!(
                "the full name of {} could not be read ({})",
                path.display(),
                io::Error::last_os_error()
            ));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&name[..len])))
    }

    fn folder_id(&self, path: &Path) -> Result<Option<String>, String> {
        use std::os::windows::io::AsRawHandle;
        if self.folder(path)? == PathKind::Missing {
            return Ok(None);
        }
        let handle = open_to_query(path)?;
        file_id(handle.as_raw_handle(), path).map(Some)
    }

    fn exe_name(&self) -> Result<String, String> {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().into_owned()))
            .ok_or_else(|| "this program's file name could not be read".into())
    }

    fn key_held(&self) -> bool {
        crate::recovery::bitlocker::key_held()
    }

    fn this_process(&self) -> Result<(u32, u64), String> {
        process_identity()
    }

    fn running(&self, pid: u32, started: u64) -> bool {
        process_running(pid, started)
    }

    fn create_folder(&mut self, path: &Path, access: FolderAccess) -> Result<(), String> {
        match access {
            FolderAccess::Inherited => fs::create_dir(path).map_err(|e| e.to_string()),
            FolderAccess::CrashingProcesses => acl::create_shared_dump_folder(path),
        }
    }

    fn remove_folder_if(&mut self, path: &Path, id: &str) -> Result<Swap<Option<String>>, String> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::{ERROR_DIR_NOT_EMPTY, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FileDispositionInfo, SetFileInformationByHandle, DELETE,
            FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        if self.folder(path)? == PathKind::Missing {
            return Ok(Swap::Changed(None));
        }
        let name = wide_path(path);
        // One handle: the identity is read through it and the folder removed through it, so
        // what is removed is the folder compared, whatever happens at its path meanwhile.
        // SAFETY: `name` is nul-terminated and outlives the call.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(format!(
                "{} could not be opened ({})",
                path.display(),
                io::Error::last_os_error()
            ));
        }
        // SAFETY: the handle is open and owned by nothing else.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let now = file_id(handle.as_raw_handle(), path)?;
        if now != id {
            return Ok(Swap::Changed(Some(now)));
        }
        // The file system refuses to mark a folder that holds anything, and nothing can be
        // made in one marked, so the emptiness check and the removal are one step.
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the handle is open with DELETE access; `info` is the class's structure.
        let ok = unsafe {
            SetFileInformationByHandle(
                handle.as_raw_handle(),
                FileDispositionInfo,
                std::ptr::addr_of!(info).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(code) if code as u32 == ERROR_DIR_NOT_EMPTY => HOLDS_FILES.into(),
                _ => format!("{} could not be removed ({error})", path.display()),
            });
        }
        // Removed as the handle closes.
        drop(handle);
        Ok(Swap::Done)
    }

    fn dumps(
        &self,
        path: &Path,
        limit: usize,
        stop: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<DumpListing>, String> {
        let denied = |e: &io::Error| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                "needs administrator rights".to_string()
            } else {
                e.to_string()
            }
        };
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(denied(&e)),
        };
        let mut walk = crashes::Walk::new(stop);
        let files = if meta.is_file() {
            vec![path.to_path_buf()]
        } else {
            let mut files = Vec::new();
            crashes::list_dumps(path, 0, limit, &mut files, &mut walk).map_err(|e| denied(&e))?;
            files
        };
        let mut listing = DumpListing {
            cut: walk.cut,
            ..DumpListing::default()
        };
        for file in files {
            let Ok(meta) = fs::metadata(&file) else {
                continue;
            };
            listing.count += 1;
            listing.bytes += meta.len();
            if let Ok(time) = meta.modified() {
                if listing.newest.as_ref().is_none_or(|n| time > n.1) {
                    listing.newest = Some((file, time, meta.len()));
                }
            }
        }
        Ok(Some(listing))
    }

    fn elevated(&self) -> Option<bool> {
        crashes::elevated()
    }

    fn read_state(&self, path: &Path) -> Result<Option<String>, String> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{} could not be read ({e})", path.display())),
        }
    }

    fn write_state(&mut self, path: &Path, text: &str) -> Result<(), String> {
        let fail = |e: io::Error| format!("{} could not be written ({e})", path.display());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(fail)?;
        }
        let scratch = path.with_extension("json.new");
        let mut file = fs::File::create(&scratch).map_err(fail)?;
        file.write_all(text.as_bytes()).map_err(fail)?;
        file.sync_all().map_err(fail)?;
        drop(file);
        fs::rename(&scratch, path).map_err(fail)
    }

    fn remove_state(&mut self, path: &Path) -> Result<(), String> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn record_changes(&mut self, what: &str, lines: &[String]) -> Result<(), String> {
        crate::change_record::append(what, lines)
    }
}

/// This process's id and start time, which name it for good.
pub(crate) fn process_identity() -> Result<(u32, u64), String> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};
    // SAFETY: both name this process and need no handle closed.
    let (pid, me) = unsafe { (GetCurrentProcessId(), GetCurrentProcess()) };
    let started = process_start(me).ok_or_else(|| {
        format!(
            "this program's start time could not be read ({})",
            io::Error::last_os_error()
        )
    })?;
    Ok((pid, started))
}

/// Whether process `pid` started at `started` still runs; a process that cannot be read is
/// taken as running.
pub(crate) fn process_running(pid: u32, started: u64) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_INVALID_PARAMETER};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE: u32 = 259;
    // SAFETY: the handle is checked and closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        // No such process; any other refusal leaves it counted as running.
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    let mut code = 0u32;
    // SAFETY: `process` is open with query rights.
    let ended = unsafe { GetExitCodeProcess(process, &mut code) } != 0 && code != STILL_ACTIVE;
    let start = process_start(process);
    // SAFETY: opened above.
    unsafe { CloseHandle(process) };
    !ended && start.is_none_or(|s| s == started)
}

/// A process's start time in 100-nanosecond units since 1601, or `None` when unreadable.
fn process_start(process: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut made, mut ended, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the four out-parameters are valid FILETIMEs.
    let ok = unsafe { GetProcessTimes(process, &mut made, &mut ended, &mut kernel, &mut user) };
    (ok != 0).then(|| (u64::from(made.dwHighDateTime) << 32) | u64::from(made.dwLowDateTime))
}

/// Runs `work` while this program holds the machine-wide lock on its crash dump settings,
/// so the recovery window's exclusion and crash dump set up and Put back never act on them
/// at the same moment. Waits up to 20 seconds for another copy.
pub(super) fn exclusive<R>(work: impl FnOnce() -> Result<R, String>) -> Result<R, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
    let mut lock = std::ptr::null_mut();
    for name in [
        "Global\\DiagnosticTool-CrashDumpSettings",
        "Local\\DiagnosticTool-CrashDumpSettings",
    ] {
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated; the handle is closed below.
        lock = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if !lock.is_null() {
            break;
        }
    }
    if lock.is_null() {
        return Err(format!(
            "the lock on the crash dump settings could not be made ({})",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `lock` is a mutex handle of this process.
    let waited = unsafe { WaitForSingleObject(lock, 20_000) };
    let result = if waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED {
        let result = work();
        // SAFETY: this thread owns the mutex.
        unsafe { ReleaseMutex(lock) };
        result
    } else {
        Err("another copy of this program is changing the crash dump settings; try again once it is done".into())
    };
    // SAFETY: made above.
    unsafe { CloseHandle(lock) };
    result
}

/// The application dump folder's access list, built from well-known accounts so it reads
/// the same in every language.
mod acl {
    use std::path::Path;

    use windows_sys::Win32::Security::{
        AddAccessAllowedAceEx, CreateWellKnownSid, InitializeAcl, InitializeSecurityDescriptor,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, WinAuthenticatedUserSid,
        WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid, ACL, ACL_REVISION,
        CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    /// List the folder, add files, read attributes and permissions, traverse: enough to
    /// add a dump, not to open another account's.
    const ADD_FILES: u32 = 0x0012_00AB;
    const SID_MAX: usize = 68;

    fn sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; SID_MAX];
        let mut size = SID_MAX as u32;
        // SAFETY: `buffer` holds `size` bytes, as large as any SID.
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err("an account's identifier could not be made".into());
        }
        buffer.truncate(size as usize);
        Ok(buffer)
    }

    /// Makes `path` with SYSTEM and Administrators in full control, each file its maker's
    /// (CREATOR OWNER) and signed-in accounts able to add files; nothing inherited.
    pub(super) fn create_shared_dump_folder(path: &Path) -> Result<(), String> {
        let inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        let entries = [
            (sid(WinLocalSystemSid)?, inherit, FILE_ALL_ACCESS),
            (sid(WinBuiltinAdministratorsSid)?, inherit, FILE_ALL_ACCESS),
            (
                sid(WinCreatorOwnerSid)?,
                inherit | INHERIT_ONLY_ACE,
                FILE_ALL_ACCESS,
            ),
            (sid(WinAuthenticatedUserSid)?, 0, ADD_FILES),
        ];
        // An ACL header (8 bytes), and per entry an ACE header and mask (8) and its SID.
        let size: usize = 8 + entries.iter().map(|(s, _, _)| 8 + s.len()).sum::<usize>();
        let mut acl = vec![0u64; size.div_ceil(8)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        // SAFETY: `acl` is a 4-byte-aligned buffer of at least `size` bytes.
        if unsafe { InitializeAcl(acl_ptr, size as u32, ACL_REVISION) } == 0 {
            return Err("the folder's access list could not be made".into());
        }
        for (mut account, flags, mask) in entries {
            // SAFETY: the ACL was initialised with room for every entry; the SID is valid.
            let ok = unsafe {
                AddAccessAllowedAceEx(
                    acl_ptr,
                    ACL_REVISION,
                    flags,
                    mask,
                    account.as_mut_ptr().cast(),
                )
            };
            if ok == 0 {
                return Err("the folder's access list could not be made".into());
            }
        }
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let sd: PSECURITY_DESCRIPTOR = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
        // SAFETY: `sd` points at a SECURITY_DESCRIPTOR that outlives the calls below.
        let ok = unsafe {
            InitializeSecurityDescriptor(sd, 1) != 0
                && SetSecurityDescriptorDacl(sd, 1, acl_ptr, 0) != 0
                && SetSecurityDescriptorControl(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0
        };
        if !ok {
            return Err("the folder's permissions could not be made".into());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let path_w = super::wide_path(path);
        // SAFETY: the path is nul-terminated and the descriptor and ACL are alive.
        if unsafe { CreateDirectoryW(path_w.as_ptr(), &attributes) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Another writer, outside any transaction, on a thread of its own: sets `name` to
    /// `value`, making the key if needed, or deletes it. Its Windows status, or `None` when
    /// it did not end within 3 s (held back by the transaction).
    fn other_writer(hive: Hive, path: &str, name: &str, value: Option<u32>) -> Option<u32> {
        let (path, name) = (wide(path), wide(name));
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut handle: HKEY = null_mut();
            // SAFETY: nul-terminated names, a valid out pointer; the key is closed below.
            let mut status = unsafe {
                RegCreateKeyExW(
                    root(hive),
                    path.as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    null(),
                    &mut handle,
                    null_mut(),
                )
            };
            if status == 0 {
                let key = Opened(handle);
                status = match value {
                    // SAFETY: four bytes of a u32.
                    Some(v) => unsafe {
                        RegSetValueExW(key.0, name.as_ptr(), 0, 4, v.to_le_bytes().as_ptr(), 4)
                    },
                    // SAFETY: the key is open for setting values.
                    None => unsafe { RegDeleteValueW(key.0, name.as_ptr()) },
                };
            }
            let _ = done.send(status);
        });
        answer.recv_timeout(std::time::Duration::from_secs(3)).ok()
    }

    /// Needs nothing but HKEY_CURRENT_USER (`Software\DiagnosticToolTest\r4-tx`, removed at
    /// the end); run on the test machine. Measures what a transaction holding a value does
    /// to a writer outside it, and what its commit does after such a write.
    #[test]
    #[ignore]
    fn live_registry_transaction_against_another_writer() {
        const KEY: &str = r"Software\DiagnosticToolTest\r4-tx";
        let hive = Hive::CurrentUser;
        let mut w = Windows;
        for (case, delete) in [("set", false), ("delete", true)] {
            w.write_value(hive, KEY, "V", &RawValue::dword(1)).unwrap();
            let transaction = Transaction::begin().unwrap();
            let (path, name) = (wide(KEY), wide("V"));
            let mut handle: HKEY = null_mut();
            // SAFETY: as in swap_value_between.
            let open = unsafe {
                RegOpenKeyTransactedW(
                    root(hive),
                    path.as_ptr(),
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &mut handle,
                    transaction.handle,
                    null(),
                )
            };
            let key = Opened(handle);
            // SAFETY: as in swap_value_between.
            let wrote = unsafe {
                if delete {
                    RegDeleteValueW(key.0, name.as_ptr())
                } else {
                    RegSetValueExW(key.0, name.as_ptr(), 0, 4, 2u32.to_le_bytes().as_ptr(), 4)
                }
            };
            let seen = w.read_value(hive, KEY, "V");
            let other = other_writer(hive, KEY, "V", Some(3));
            let seen_after = w.read_value(hive, KEY, "V");
            drop(key);
            let committed = transaction.commit();
            println!(
                "{case}: open {open}, transacted write {wrote}, read outside {seen:?}, another writer {other:?}, read outside then {seen_after:?}, commit {committed:?}, value after {:?}",
                w.read_value(hive, KEY, "V")
            );
        }
        let _ = w.delete_value(hive, KEY, "V");
        for key in [KEY, r"Software\DiagnosticToolTest"] {
            let path = wide(key);
            // SAFETY: a nul-terminated path under HKEY_CURRENT_USER this test made.
            let status = unsafe {
                windows_sys::Win32::System::Registry::RegDeleteKeyExW(
                    root(hive),
                    path.as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                )
            };
            println!("removed {key}: status {status}");
        }
    }

    /// Needs nothing but HKEY_CURRENT_USER, where it makes and removes
    /// `Software\DiagnosticToolTest\r4-swap`; run on the test machine, not a technician's PC.
    /// Measures the registry swap: a value or key held by the transaction is refused to
    /// another writer until the commit, the committed value is what is compared, and a
    /// change made before the swap is seen and kept.
    #[test]
    #[ignore]
    fn live_registry_swap_is_one_operation() {
        const KEY: &str = r"Software\DiagnosticToolTest\r4-swap";
        let hive = Hive::CurrentUser;
        let mut w = Windows;
        let dword = |v: u32| Some(RawValue::dword(v));
        w.write_value(hive, KEY, "V", &RawValue::dword(1)).unwrap();
        w.write_value(hive, KEY, "W", &RawValue::dword(1)).unwrap();

        // Another writer while the swap holds the key: of the value, and of another value.
        let (mut same, mut other) = (None, None);
        let got = w.swap_value_between(hive, KEY, "V", &dword(1), &dword(2), &mut || {
            same = Some(other_writer(hive, KEY, "V", Some(3)));
            other = Some(other_writer(hive, KEY, "W", Some(3)));
        });
        println!(
            "set while held: swap {got:?}, another writer of the value {same:?}, of another value {other:?}"
        );
        assert_eq!(
            got,
            Ok(Swap::Changed(dword(3))),
            "the other writer's value is kept"
        );
        assert_eq!(w.read_value(hive, KEY, "V"), Ok(dword(3)));
        // Another writer of another value of the key only.
        w.write_value(hive, KEY, "V", &RawValue::dword(1)).unwrap();
        let mut other = None;
        let got = w.swap_value_between(hive, KEY, "V", &dword(1), &dword(2), &mut || {
            other = Some(other_writer(hive, KEY, "W", Some(4)));
        });
        println!("another value written while held: swap {got:?}, its writer {other:?}");
        println!(
            "after: V {:?}, W {:?}",
            w.read_value(hive, KEY, "V"),
            w.read_value(hive, KEY, "W")
        );

        // A delete while held.
        w.write_value(hive, KEY, "V", &RawValue::dword(2)).unwrap();
        let mut same = None;
        let got = w.swap_value_between(hive, KEY, "V", &dword(2), &None, &mut || {
            same = Some(other_writer(hive, KEY, "V", Some(4)));
        });
        println!(
            "delete while held: swap {got:?}, another writer of the value {same:?}; V now {:?}",
            w.read_value(hive, KEY, "V")
        );

        // A change made before the swap is seen, and nothing is written.
        w.write_value(hive, KEY, "V", &RawValue::dword(5)).unwrap();
        let got = w.swap_value(hive, KEY, "V", &dword(2), &dword(1));
        println!(
            "changed before: swap {got:?}; V now {:?}",
            w.read_value(hive, KEY, "V")
        );
        assert_eq!(got, Ok(Swap::Changed(dword(5))));
        assert_eq!(w.read_value(hive, KEY, "V"), Ok(dword(5)));

        // A key removed while another writer adds a value to it.
        const SUB: &str = r"Software\DiagnosticToolTest\r4-swap\made";
        w.write_value(hive, SUB, "X", &RawValue::dword(1)).unwrap();
        w.swap_value(hive, SUB, "X", &dword(1), &None).unwrap();
        let stamp = w.key_stamp(hive, SUB).unwrap().unwrap();
        let mut added = None;
        let got = w.remove_key_between(hive, SUB, stamp, &mut || {
            added = Some(other_writer(hive, SUB, "Y", Some(1)));
        });
        println!(
            "key removed while held: {got:?}, another writer adding a value {added:?}; key now {:?}, Y {:?}",
            w.key_stamp(hive, SUB),
            w.read_value(hive, SUB, "Y")
        );
        // An empty key removed; one written to since is kept.
        let _ = w.delete_value(hive, SUB, "Y");
        w.write_value(hive, SUB, "Z", &RawValue::dword(1)).unwrap();
        w.delete_value(hive, SUB, "Z").unwrap();
        let stamp = w.key_stamp(hive, SUB).unwrap().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        w.write_value(hive, SUB, "Z", &RawValue::dword(1)).unwrap();
        w.delete_value(hive, SUB, "Z").unwrap();
        let kept = w.remove_key_if(hive, SUB, stamp);
        println!("key written to since: {kept:?}");
        assert!(matches!(kept, Ok(Swap::Changed(Some(_)))));
        let stamp = w.key_stamp(hive, SUB).unwrap().unwrap();
        assert_eq!(w.remove_key_if(hive, SUB, stamp), Ok(Swap::Done));
        assert_eq!(w.key_stamp(hive, SUB), Ok(None));

        // Clean up the test keys.
        for key in [KEY, r"Software\DiagnosticToolTest"] {
            let path = wide(key);
            let _ = w.delete_value(hive, key, "V");
            let _ = w.delete_value(hive, key, "W");
            // SAFETY: a nul-terminated path under HKEY_CURRENT_USER this test made.
            let status = unsafe {
                windows_sys::Win32::System::Registry::RegDeleteKeyExW(
                    root(hive),
                    path.as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                )
            };
            println!("removed {key}: status {status}");
        }
    }

    #[test]
    fn expansion_leaves_unknown_variables_and_lone_percent_signs() {
        let w = Windows;
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(
            w.expand(r"%SystemRoot%\MEMORY.DMP").unwrap(),
            format!(r"{root}\MEMORY.DMP")
        );
        assert_eq!(
            w.expand("%NoSuchVariable_x1%").unwrap(),
            "%NoSuchVariable_x1%"
        );
        assert_eq!(w.expand("50% off").unwrap(), "50% off");
        assert_eq!(w.expand("a%%b").unwrap(), "a%%b");
    }

    #[test]
    fn this_pcs_crash_control_and_memory_read() {
        let w = Windows;
        let value = w
            .read_value(
                Hive::LocalMachine,
                super::super::machine::CRASH_CONTROL.path,
                "CrashDumpEnabled",
            )
            .unwrap();
        assert!(value.and_then(|v| v.as_dword()).is_some());
        let memory = w.memory().unwrap();
        assert!(memory.physical > memory.kernel && memory.kernel > 0);
        let windows = PathBuf::from(std::env::var("SystemRoot").unwrap());
        assert_eq!(w.volume(&windows).unwrap().kind, VolumeKind::Fixed);
        assert_eq!(w.folder(&windows).unwrap(), PathKind::Folder);
    }

    /// A process is known by its id and start time: this one runs, the same id with
    /// another start time is a process that ended, and an id no process has is not running.
    #[test]
    fn a_process_is_known_by_its_id_and_start_time() {
        let m = Windows;
        let (pid, started) = m.this_process().unwrap();
        assert!(started > 0);
        assert!(m.running(pid, started));
        assert!(!m.running(pid, started + 1));
        assert!(!m.running(0xFFFF_FFF0, started));
        assert_eq!(exclusive(|| Ok(7)), Ok(7));
    }

    /// A junction is seen as a link where it sits, a folder below it is found to lead to
    /// the junction's target, and its full name keeps the junction, even where the temp
    /// folder is spelled with a short (8.3) name.
    #[test]
    fn a_folder_under_a_junction_leads_elsewhere() {
        let base =
            std::env::temp_dir().join(format!("crash-dumps-junction-{}", std::process::id()));
        let (target, junction) = (base.join("target"), base.join("junction"));
        fs::create_dir_all(target.join("sub")).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "{}",
            String::from_utf8_lossy(&made.stderr)
        );
        let w = Windows;
        assert_eq!(w.folder(&junction).unwrap(), PathKind::Link);
        let below = junction.join("sub");
        assert_eq!(w.folder(&below).unwrap(), PathKind::Folder);
        let real = w.resolved(&below).unwrap();
        let full = |p: &Path| w.long_name(p).unwrap();
        assert!(
            super::super::same_place(&real, &full(&target.join("sub"))),
            "{}",
            real.display()
        );
        assert!(super::super::same_place(
            &w.resolved(&target).unwrap(),
            &full(&target)
        ));
        // The full name follows no link: the folder below the junction keeps its spelling.
        assert!(super::super::same_place(
            &full(&below),
            &full(&base).join("junction").join("sub")
        ));
        assert!(!super::super::same_place(&real, &full(&below)));
        assert_eq!(
            super::super::link_on_path(&w, &below).unwrap(),
            Some(junction.clone())
        );
        fs::remove_dir(&junction).unwrap();
        fs::remove_dir(target.join("sub")).unwrap();
        fs::remove_dir(&target).unwrap();
        fs::remove_dir(&base).unwrap();
    }

    #[test]
    fn a_shared_dump_folder_is_made_with_its_own_permissions() {
        let base = std::env::temp_dir().join(format!("crash-dumps-acl-{}", std::process::id()));
        let mut w = Windows;
        w.create_folder(&base, FolderAccess::CrashingProcesses)
            .unwrap();
        assert_eq!(w.folder(&base).unwrap(), PathKind::Folder);
        fs::write(base.join("a.dmp"), b"x").unwrap();
        let listing = w.dumps(&base, 10, None).unwrap().unwrap();
        assert_eq!((listing.count, listing.bytes), (1, 1));
        let id = w.folder_id(&base).unwrap().unwrap();
        assert_eq!(w.remove_folder_if(&base, &id), Err(HOLDS_FILES.to_string()));
        fs::remove_file(base.join("a.dmp")).unwrap();
        // A folder made again under the same name is another folder, and is kept.
        fs::remove_dir(&base).unwrap();
        fs::create_dir(&base).unwrap();
        let again = w.folder_id(&base).unwrap().unwrap();
        assert_ne!(again, id);
        assert_eq!(
            w.remove_folder_if(&base, &id),
            Ok(Swap::Changed(Some(again.clone())))
        );
        assert_eq!(w.remove_folder_if(&base, &again), Ok(Swap::Done));
        assert_eq!(w.folder(&base).unwrap(), PathKind::Missing);
    }
}
