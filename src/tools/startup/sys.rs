//! The Win32 side of the startup tool: registry reads, the service manager, file facts and
//! signature checks. Everything here only reads.
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    VS_FIXEDFILEINFO,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};

use super::parse::{trust_from_status, utf16_le, FileFacts, Trust};

const GENERIC_READ: u32 = 0x8000_0000;

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Number(u32),
    Bytes(Vec<u8>),
}

impl Value {
    pub fn text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn number(&self) -> Option<u32> {
        match self {
            Value::Number(number) => Some(*number),
            _ => None,
        }
    }
}

/// Turns a registry value's bytes into text, a number or bytes by its type.
pub fn decode_value(kind: u32, data: &[u8]) -> Value {
    match kind {
        1 | 2 => Value::Text(from_wide(&utf16_le(data))),
        4 if data.len() >= 4 => {
            Value::Number(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        _ => Value::Bytes(data.to_vec()),
    }
}

pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    pub fn open(root: HKEY, path: &str) -> Option<Key> {
        let mut handle: HKEY = null_mut();
        let path = wide(path);
        // SAFETY: `path` is nul-terminated and `handle` is a valid out pointer.
        let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, &mut handle) };
        (status == 0).then_some(Key(handle))
    }

    pub fn value(&self, name: &str) -> Option<Value> {
        let name = wide(name);
        let mut data = vec![0u8; 1024];
        loop {
            let mut kind = 0u32;
            let mut size = data.len() as u32;
            // SAFETY: `data` has `size` writable bytes and `name` is nul-terminated.
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut size,
                )
            };
            match status {
                0 => return Some(decode_value(kind, &data[..size as usize])),
                ERROR_MORE_DATA => data.resize((size as usize).max(data.len() * 2), 0),
                _ => return None,
            }
        }
    }

    pub fn values(&self) -> Vec<(String, Value)> {
        let mut found = Vec::new();
        let mut name = vec![0u16; 16_384];
        let mut data = vec![0u8; 2048];
        let mut index = 0;
        loop {
            let mut name_len = name.len() as u32;
            let mut size = data.len() as u32;
            let mut kind = 0u32;
            // SAFETY: both buffers are writable for the lengths passed.
            let status = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut size,
                )
            };
            match status {
                0 => {
                    found.push((
                        from_wide(&name[..name_len as usize]),
                        decode_value(kind, &data[..size as usize]),
                    ));
                    index += 1;
                }
                ERROR_MORE_DATA => data.resize((size as usize).max(data.len() * 2), 0),
                ERROR_NO_MORE_ITEMS => return found,
                _ => index += 1,
            }
            if index > 100_000 {
                return found;
            }
        }
    }

    pub fn subkeys(&self) -> Vec<String> {
        let mut found = Vec::new();
        let mut name = vec![0u16; 512];
        for index in 0..100_000 {
            let mut len = name.len() as u32;
            // SAFETY: `name` is writable for `len` units; the optional outputs are null.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match status {
                0 => found.push(from_wide(&name[..len as usize])),
                ERROR_NO_MORE_ITEMS => break,
                _ => {}
            }
        }
        found
    }
}

/// Current states of services and drivers by name, from the service manager. The state
/// text is the plain word ("running", "stopped").
pub fn service_states() -> Result<HashMap<String, (String, String)>, String> {
    // SAFETY: null machine and database names select the local active database.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };
    if manager.is_null() {
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { GetLastError() };
        return Err(format!(
            "the service manager could not be opened (error {code})"
        ));
    }
    let mut states = HashMap::new();
    let mut buffer = vec![0u64; 16 * 1024];
    let mut resume = 0u32;
    let result = loop {
        let mut needed = 0u32;
        let mut returned = 0u32;
        // SAFETY: `buffer` is writable for the byte length passed and 8-byte aligned.
        let ok = unsafe {
            EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr().cast::<u8>(),
                (buffer.len() * 8) as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                null(),
            )
        };
        // SAFETY: GetLastError has no preconditions.
        let error = if ok == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if ok == 0 && error != ERROR_MORE_DATA {
            break Err(format!(
                "the service list could not be read (error {error})"
            ));
        }
        let entries = buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>();
        for index in 0..returned as usize {
            // SAFETY: the call filled `returned` entries; their strings point into `buffer`.
            let entry = unsafe { &*entries.add(index) };
            let name = unsafe { pwstr(entry.lpServiceName) };
            let display = unsafe { pwstr(entry.lpDisplayName) };
            states.insert(
                name.to_ascii_lowercase(),
                (
                    state_word(entry.ServiceStatusProcess.dwCurrentState).to_string(),
                    display,
                ),
            );
        }
        if ok != 0 {
            break Ok(());
        }
    };
    // SAFETY: the handle came from OpenSCManagerW and is closed once.
    unsafe { CloseServiceHandle(manager) };
    result.map(|()| states)
}

/// # Safety
/// `text` is null or a nul-terminated wide string that stays valid for the call.
unsafe fn pwstr(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *text.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
}

fn state_word(state: u32) -> &'static str {
    match state {
        1 => "stopped",
        2 => "starting",
        3 => "stopping",
        4 => "running",
        5 => "continuing",
        6 => "pausing",
        7 => "paused",
        _ => "state unknown",
    }
}

/// Signature checking state for one worker: catalog administrator contexts, opened on first
/// use, for the two hash algorithms catalogs use.
pub struct Checker {
    admins: [Option<isize>; 2],
}

impl Checker {
    pub fn new() -> Self {
        Checker {
            admins: [None, None],
        }
    }

    fn admin(&mut self, which: usize) -> Option<isize> {
        if self.admins[which].is_none() {
            let algorithm = wide("SHA256");
            let mut context = 0isize;
            let policy_algorithm = if which == 0 {
                algorithm.as_ptr()
            } else {
                null()
            };
            // SAFETY: the subsystem GUID is a valid constant, the algorithm is null or
            // nul-terminated, and `context` is a valid out pointer.
            let ok = unsafe {
                CryptCATAdminAcquireContext2(
                    &mut context,
                    &DRIVER_ACTION_VERIFY,
                    policy_algorithm,
                    null(),
                    0,
                )
            };
            if ok != 0 {
                self.admins[which] = Some(context);
            }
        }
        self.admins[which]
    }
}

impl Drop for Checker {
    fn drop(&mut self) {
        for context in self.admins.iter().flatten() {
            // SAFETY: each context came from CryptCATAdminAcquireContext2 and is released once.
            unsafe { CryptCATAdminReleaseContext(*context, 0) };
        }
    }
}

/// The subject name of the leaf certificate of the first signature in a verification state.
fn signer_name(state: HANDLE) -> Option<String> {
    if state.is_null() {
        return None;
    }
    // SAFETY: `state` came from a WinVerifyTrust verify call that has not been closed; the
    // returned structures are owned by that state and read before it is closed.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*signer).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        let mut name = [0u16; 256];
        let len = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            name.as_mut_ptr(),
            name.len() as u32,
        );
        (len > 1).then(|| from_wide(&name))
    }
}

/// The result of one WinVerifyTrust call: the status and the signer's name when it verified.
struct Verified {
    status: u32,
    signer: Option<String>,
}

fn verify_embedded(path: &[u16]) -> Verified {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: null_mut(),
        pgKnownSubject: null_mut(),
    };
    let mut data = trust_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    run_verify(&mut data)
}

fn trust_data() -> WINTRUST_DATA {
    // SAFETY: WINTRUST_DATA is plain data for which all-zero is the documented empty value.
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    data
}

/// Runs the verify and close calls for a prepared WINTRUST_DATA.
fn run_verify(data: &mut WINTRUST_DATA) -> Verified {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // SAFETY: `data` and what it points to stay alive until after the close call; the
    // window handle -1 selects no UI.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    } as u32;
    let signer = if status == 0 {
        signer_name(data.hWVTStateData)
    } else {
        None
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: as above; this releases the state the verify call created.
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (data as *mut WINTRUST_DATA).cast::<c_void>(),
        );
    }
    Verified { status, signer }
}

struct FileHandle(HANDLE);

impl FileHandle {
    fn open(path: &[u16]) -> Option<FileHandle> {
        // SAFETY: `path` is nul-terminated; the file is opened for reading only.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        (handle != INVALID_HANDLE_VALUE).then_some(FileHandle(handle))
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateFileW and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Looks the file's hash up in the installed catalogs and verifies the catalog's signature
/// for it. `None` when no catalog lists the file.
fn verify_catalog(checker: &mut Checker, path: &[u16]) -> Option<Verified> {
    let file = FileHandle::open(path)?;
    for which in 0..2 {
        let Some(admin) = checker.admin(which) else {
            continue;
        };
        let mut hash = [0u8; 64];
        let mut hash_len = hash.len() as u32;
        // SAFETY: `hash` is writable for `hash_len` bytes and the file handle is open.
        let ok = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin, file.0, &mut hash_len, hash.as_mut_ptr(), 0)
        };
        if ok == 0 {
            continue;
        }
        let tag: Vec<u16> = hash[..hash_len as usize]
            .iter()
            .flat_map(|byte| format!("{byte:02X}").encode_utf16().collect::<Vec<_>>())
            .chain(std::iter::once(0))
            .collect();
        let mut previous = 0isize;
        let mut last: Option<Verified> = None;
        for _ in 0..4 {
            // SAFETY: `hash` holds `hash_len` bytes; `previous` is 0 or the context returned
            // by the previous call, which this call releases.
            let catalog = unsafe {
                CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash_len, 0, &mut previous)
            };
            if catalog == 0 {
                // The call released the previous context when it found no further one.
                previous = 0;
                break;
            }
            // SAFETY: CATALOG_INFO is plain data; the call fills the path.
            let mut info: CATALOG_INFO = unsafe { std::mem::zeroed() };
            info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
            // SAFETY: `catalog` is a live catalog context and `info` is writable.
            if unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0) } == 0 {
                previous = catalog;
                continue;
            }
            let mut member = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                pcwszMemberTag: tag.as_ptr(),
                pcwszMemberFilePath: path.as_ptr(),
                hMemberFile: file.0,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash_len,
                pcCatalogContext: null_mut(),
                hCatAdmin: admin,
            };
            let mut data = trust_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous.pCatalog = &mut member;
            let verified = run_verify(&mut data);
            let valid = verified.status == 0;
            last = Some(verified);
            if valid {
                // SAFETY: `catalog` is live and released once.
                unsafe { CryptCATAdminReleaseCatalogContext(admin, catalog, 0) };
                return last;
            }
            previous = catalog;
        }
        if previous != 0 {
            // SAFETY: `previous` is a live catalog context that was not passed to a later
            // enumeration call.
            unsafe { CryptCATAdminReleaseCatalogContext(admin, previous, 0) };
        }
        if last.is_some() {
            return last;
        }
    }
    None
}

/// A file's version and company from its version resource.
fn version_info(path: &[u16]) -> (Option<String>, Option<String>) {
    let mut handle = 0u32;
    // SAFETY: `path` is nul-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut handle) };
    if size == 0 {
        return (None, None);
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is writable for `size` bytes.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return (None, None);
    }
    let query = |sub: &str| -> Option<(*const u8, usize)> {
        let sub = wide(sub);
        let mut found: *mut c_void = null_mut();
        let mut len = 0u32;
        // SAFETY: `block` holds a version resource; the returned pointer points into it.
        let ok =
            unsafe { VerQueryValueW(block.as_ptr().cast(), sub.as_ptr(), &mut found, &mut len) };
        (ok != 0 && !found.is_null()).then_some((found as *const u8, len as usize))
    };
    let version = query("\\").and_then(|(pointer, len)| {
        if len < std::mem::size_of::<VS_FIXEDFILEINFO>() {
            return None;
        }
        // SAFETY: the query returned at least a VS_FIXEDFILEINFO inside `block`.
        let fixed = unsafe { std::ptr::read_unaligned(pointer.cast::<VS_FIXEDFILEINFO>()) };
        (fixed.dwSignature == 0xFEEF_04BD).then(|| {
            format!(
                "{}.{}.{}.{}",
                fixed.dwFileVersionMS >> 16,
                fixed.dwFileVersionMS & 0xFFFF,
                fixed.dwFileVersionLS >> 16,
                fixed.dwFileVersionLS & 0xFFFF
            )
        })
    });
    let company = query("\\VarFileInfo\\Translation").and_then(|(pointer, len)| {
        if len < 4 {
            return None;
        }
        // SAFETY: the translation table holds at least one pair of 16-bit values.
        let (language, codepage) = unsafe {
            (
                std::ptr::read_unaligned(pointer.cast::<u16>()),
                std::ptr::read_unaligned(pointer.add(2).cast::<u16>()),
            )
        };
        let sub = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\CompanyName");
        let (text, text_len) = query(&sub)?;
        // SAFETY: a string value is `text_len` wide characters inside `block`.
        let units = unsafe {
            (0..text_len)
                .map(|i| std::ptr::read_unaligned(text.add(i * 2).cast::<u16>()))
                .collect::<Vec<_>>()
        };
        let company = from_wide(&units).trim().to_string();
        (!company.is_empty()).then_some(company)
    });
    (version, company)
}

/// Existence, signature, signer, company, version and date of one file.
pub fn check_file(path: &str, checker: &mut Checker) -> FileFacts {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Some(metadata),
        Ok(_) => return FileFacts::missing(),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // The folder hides the file from this user: it may exist, but nothing more is known.
            return FileFacts {
                exists: true,
                trust: Trust::Unreadable("access denied".into()),
                ..FileFacts::missing()
            };
        }
        Err(_) => return FileFacts::missing(),
    };
    let wide_path = wide(path);
    let (version, company) = version_info(&wide_path);
    let mut facts = FileFacts {
        exists: true,
        trust: Trust::Unsigned,
        signer: None,
        company,
        version,
        modified: metadata.and_then(|m| m.modified().ok()),
    };
    let embedded = verify_embedded(&wide_path);
    if let Some(trust) = trust_from_status(embedded.status) {
        facts.trust = trust;
        facts.signer = embedded.signer;
        if facts.trust == Trust::Valid {
            return facts;
        }
    }
    // No usable embedded signature: the file may be signed through a catalog.
    if let Some(catalog) = verify_catalog(checker, &wide_path) {
        match trust_from_status(catalog.status) {
            Some(Trust::Valid) => {
                facts.trust = Trust::Valid;
                facts.signer = catalog.signer;
            }
            Some(trust) if facts.trust == Trust::Unsigned => facts.trust = trust,
            _ => {}
        }
    }
    facts
}

/// Checks the files on a few threads until the deadline. Results are keyed by lower-case
/// path; the second value is how many files were not reached.
pub fn check_files(paths: &[String], deadline: Instant) -> (HashMap<String, FileFacts>, usize) {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(HashMap::new());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                let mut checker = Checker::new();
                loop {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(path) = paths.get(index) else {
                        break;
                    };
                    let facts = check_file(path, &mut checker);
                    if let Ok(mut map) = results.lock() {
                        map.insert(path.to_ascii_lowercase(), facts);
                    }
                }
            });
        }
    });
    let results = results.into_inner().unwrap_or_default();
    let missed = paths
        .iter()
        .filter(|path| !results.contains_key(&path.to_ascii_lowercase()))
        .count();
    (results, missed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_decode_by_type() {
        let text: Vec<u8> = "C:\\x.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_value(1, &text), Value::Text(r"C:\x.exe".into()));
        assert_eq!(decode_value(2, &text), Value::Text(r"C:\x.exe".into()));
        assert_eq!(decode_value(4, &[2, 0, 0, 0]), Value::Number(2));
        assert_eq!(decode_value(4, &[2, 0]), Value::Bytes(vec![2, 0]));
        assert_eq!(decode_value(3, &[7, 1]), Value::Bytes(vec![7, 1]));
    }

    #[test]
    fn a_catalog_signed_system_file_and_an_unsigned_file_are_told_apart() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let mut checker = Checker::new();
        let kernel = check_file(&format!(r"{root}\System32\kernel32.dll"), &mut checker);
        assert!(kernel.exists);
        assert_eq!(kernel.trust, Trust::Valid, "{kernel:?}");
        assert!(
            kernel
                .signer
                .as_deref()
                .is_some_and(|s| s.starts_with("Microsoft")),
            "{kernel:?}"
        );
        let me = std::env::current_exe().unwrap();
        let own = check_file(&me.to_string_lossy(), &mut checker);
        assert_eq!(own.trust, Trust::Unsigned, "{own:?}");
        let gone = check_file(
            &format!(r"{root}\System32\no-such-file-here.dll"),
            &mut checker,
        );
        assert!(!gone.exists);
    }
}
