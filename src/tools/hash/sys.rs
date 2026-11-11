//! The Win32 side of the hash tool: CNG hashing and the two WinVerifyTrust checks. This
//! is a small copy of the startup tool's signature check (that one is private to it) that
//! also reports the signer of a signature that failed to verify. Everything here reads.
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Instant;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider, CertGetNameStringW,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

use super::Algorithm;

const GENERIC_READ: u32 = 0x8000_0000;
const CHUNK: usize = 1 << 20;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// One WinVerifyTrust call's status and the signer's name when it could be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub status: u32,
    pub signer: Option<String>,
}

/// The embedded check and the catalog check; `None` for one that did not run or found
/// nothing to check (no catalog lists the file).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSignature {
    pub embedded: Option<Check>,
    pub catalog: Option<Check>,
}

struct Provider(*mut c_void);

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: the handle came from BCryptOpenAlgorithmProvider and is closed once.
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

struct HashHandle(*mut c_void);

impl Drop for HashHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from BCryptCreateHash and is destroyed once.
        unsafe { BCryptDestroyHash(self.0) };
    }
}

fn u32_property(handle: *mut c_void, name: &str) -> Option<u32> {
    let name = wide(name);
    let mut value = 0u32;
    let mut written = 0u32;
    // SAFETY: `value` is a writable 4 bytes and `name` is nul-terminated.
    let status = unsafe {
        BCryptGetProperty(
            handle,
            name.as_ptr(),
            (&mut value as *mut u32).cast::<u8>(),
            4,
            &mut written,
            0,
        )
    };
    (status >= 0 && written == 4).then_some(value)
}

/// The hash of the file as lower-case hex, or the reason there is none (including that the
/// deadline passed). The bytes are read in chunks and only fed to the hash.
pub fn digest(path: &Path, algorithm: Algorithm, deadline: Instant) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => "access denied".to_string(),
        _ => format!("the file could not be opened ({error})"),
    })?;
    let id = wide(match algorithm {
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha1 => "SHA1",
    });
    let mut raw = null_mut();
    // SAFETY: `raw` is a valid out pointer and `id` is nul-terminated.
    if unsafe { BCryptOpenAlgorithmProvider(&mut raw, id.as_ptr(), null(), 0) } < 0 {
        return Err("Windows has no hashing provider for this algorithm".into());
    }
    let provider = Provider(raw);
    let object_len = u32_property(provider.0, "ObjectLength").ok_or("hashing is unavailable")?;
    let digest_len =
        u32_property(provider.0, "HashDigestLength").ok_or("hashing is unavailable")?;
    let mut object = vec![0u8; object_len as usize];
    let mut handle = null_mut();
    // SAFETY: `object` is declared before the hash handle, so it outlives it, and has the
    // size the provider asked for.
    let created = unsafe {
        BCryptCreateHash(
            provider.0,
            &mut handle,
            object.as_mut_ptr(),
            object_len,
            null(),
            0,
            0,
        )
    };
    if created < 0 {
        return Err("hashing is unavailable".into());
    }
    let hash = HashHandle(handle);
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "the time limit was reached after reading {}",
                super::super::space::format_size(total)
            ));
        }
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => return Err(format!("reading stopped after {total} bytes ({error})")),
        };
        total += read as u64;
        // SAFETY: the first `read` bytes of `buffer` are initialised.
        if unsafe { BCryptHashData(hash.0, buffer.as_ptr(), read as u32, 0) } < 0 {
            return Err("hashing failed".into());
        }
    }
    let mut out = vec![0u8; digest_len as usize];
    // SAFETY: `out` is writable for `digest_len` bytes.
    if unsafe { BCryptFinishHash(hash.0, out.as_mut_ptr(), digest_len, 0) } < 0 {
        return Err("hashing failed".into());
    }
    drop(hash);
    Ok(out.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn from_wide(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// The leaf certificate's display name of the first signature in a verification state.
fn signer_name(state: HANDLE) -> Option<String> {
    if state.is_null() {
        return None;
    }
    // SAFETY: `state` came from a WinVerifyTrust verify call that has not been closed; the
    // returned structures belong to that state and are read before it is closed.
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

fn trust_data() -> WINTRUST_DATA {
    // SAFETY: WINTRUST_DATA is plain data for which all-zero is the documented empty value.
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    data
}

fn run_verify(data: &mut WINTRUST_DATA) -> Check {
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
    let signer = signer_name(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: as above; this releases the state the verify call created.
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (data as *mut WINTRUST_DATA).cast::<c_void>(),
        );
    }
    Check { status, signer }
}

/// The embedded-signature check of one file (a catalog file included).
pub fn verify_embedded(path: &[u16]) -> Check {
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

struct Admin(isize);

impl Admin {
    /// A catalog administrator context for catalogs hashed with SHA-256 (`sha256`) or the
    /// system default (SHA-1).
    fn acquire(sha256: bool) -> Option<Admin> {
        let algorithm = wide("SHA256");
        let mut context = 0isize;
        let policy = if sha256 { algorithm.as_ptr() } else { null() };
        // SAFETY: the subsystem GUID is a valid constant, the algorithm is null or
        // nul-terminated, and `context` is a valid out pointer.
        let ok = unsafe {
            CryptCATAdminAcquireContext2(&mut context, &DRIVER_ACTION_VERIFY, policy, null(), 0)
        };
        (ok != 0).then_some(Admin(context))
    }
}

impl Drop for Admin {
    fn drop(&mut self) {
        // SAFETY: the context came from CryptCATAdminAcquireContext2 and is released once.
        unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

/// Looks the file up in the installed catalogs and verifies the catalog's signature for
/// it. `None` when no catalog lists the file or the file cannot be opened.
fn verify_catalog(path: &[u16]) -> Option<Check> {
    let file = FileHandle::open(path)?;
    for sha256 in [true, false] {
        let Some(admin) = Admin::acquire(sha256) else {
            continue;
        };
        let mut hash = [0u8; 64];
        let mut hash_len = hash.len() as u32;
        // SAFETY: `hash` is writable for `hash_len` bytes and the file handle is open.
        let ok = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.0,
                file.0,
                &mut hash_len,
                hash.as_mut_ptr(),
                0,
            )
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
        let mut last = None;
        for _ in 0..4 {
            // SAFETY: `hash` holds `hash_len` bytes; `previous` is 0 or the context returned
            // by the previous call, which this call releases.
            let catalog = unsafe {
                CryptCATAdminEnumCatalogFromHash(admin.0, hash.as_ptr(), hash_len, 0, &mut previous)
            };
            if catalog == 0 {
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
                hCatAdmin: admin.0,
            };
            let mut data = trust_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous.pCatalog = &mut member;
            let checked = run_verify(&mut data);
            let valid = checked.status == 0;
            last = Some(checked);
            if valid {
                // SAFETY: `catalog` is live and released once.
                unsafe { CryptCATAdminReleaseCatalogContext(admin.0, catalog, 0) };
                return last;
            }
            previous = catalog;
        }
        if previous != 0 {
            // SAFETY: `previous` is a live catalog context not passed to a later enumeration.
            unsafe { CryptCATAdminReleaseCatalogContext(admin.0, previous, 0) };
        }
        if last.is_some() {
            return last;
        }
    }
    None
}

pub fn check_signature(path: &Path) -> RawSignature {
    let path = wide_path(path);
    let embedded = verify_embedded(&path);
    // A valid embedded signature needs no catalog; otherwise the catalogs get a look.
    let catalog = if embedded.status == 0 {
        None
    } else {
        verify_catalog(&path)
    };
    RawSignature {
        embedded: Some(embedded),
        catalog,
    }
}
