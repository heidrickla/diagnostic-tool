//! BitLocker drives: finding them by their boot sector's "-FVE-FS-" signature, reading
//! their recovery key IDs while they stay locked, and unlocking and locking them through
//! Windows (the Win32_EncryptableVolume class over WMI, reached through COM).
//!
//! The recovery key a technician types is a secret (recovery rule 7): it is held only in a
//! `RecoveryKey`, which zeroes its memory when dropped, is never logged, never written to a
//! report or a file, and is passed to Windows once. Every way of unlocking, typed or found
//! later by a key lookup, goes through `unlock_with_key_text`.
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::timed::Waited;

use super::keylookup::DumpShield;
use super::vdisk::{self, Event, VolumeInfo};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{SysAllocString, SysFreeString, SysStringLen};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
};

/// The signature at byte 3 of a BitLocker volume's boot sector.
pub const SIGNATURE: &[u8; 8] = b"-FVE-FS-";

/// Whether a volume's first sector is a BitLocker boot sector.
pub fn is_bitlocker(boot: &[u8]) -> bool {
    boot.get(3..11) == Some(SIGNATURE.as_slice())
}

// ---- the recovery key -------------------------------------------------------------------

/// A 48-digit recovery password, as eight groups of six digits joined by dashes. Its memory
/// is overwritten with zeros when it is dropped; it has no Debug or Display.
pub struct RecoveryKey {
    /// Declared first: taken back after the text is zeroed and before it is freed.
    _shield: Option<DumpShield>,
    text: Vec<u16>,
    /// This program stays out of crash dumps while the key lives.
    _dumps: Option<crate::tools::crash_dumps::DumpExclusion>,
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        zero_u16(&mut self.text);
    }
}

/// Overwrites with zeros in a way the compiler keeps.
pub fn zero_u16(buffer: &mut [u16]) {
    for c in buffer.iter_mut() {
        // SAFETY: `c` is a valid, aligned element of the slice.
        unsafe { std::ptr::write_volatile(c, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// UTF-16 text that may hold a recovery key, as read from an edit control or the
/// clipboard: zeroed when dropped, on every path.
pub struct WideSecret(pub Vec<u16>);

impl Drop for WideSecret {
    fn drop(&mut self) {
        let len = self.0.len();
        // Within the capacity: nothing is moved.
        self.0.resize(self.0.capacity(), 0);
        zero_u16(&mut self.0);
        self.0.truncate(len);
    }
}

/// Whether the clipboard's text is the key field's text, ignoring spaces around either.
fn same_text(clip: &[u16], field: &[u16]) -> bool {
    let trim = |t: &[u16]| -> (usize, usize) {
        let space = |c: &u16| char::from_u32(u32::from(*c)).is_none_or(char::is_whitespace);
        let start = t
            .iter()
            .position(|c| !space(c) && *c != 0)
            .unwrap_or(t.len());
        let end = t
            .iter()
            .rposition(|c| !space(c) && *c != 0)
            .map_or(start, |e| e + 1);
        (start, end.max(start))
    };
    let (a, b) = (trim(clip), trim(field));
    a.1 > a.0 && clip[a.0..a.1] == field[b.0..b.1]
}

/// Empties the clipboard when it still holds exactly the text of the recovery key field,
/// as after the key was pasted there; anything else on the clipboard is left alone. The
/// copy read out to compare is zeroed. Whether the clipboard was emptied.
pub fn clear_clipboard_if_holding(owner: isize, field: &[u16]) -> bool {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    const CF_UNICODETEXT: u32 = 13;
    if field.iter().all(|c| *c == 0 || *c == u16::from(b' ')) {
        return false;
    }
    // SAFETY: the clipboard is opened, read under its lock and closed on every path; the
    // data is copied out only within its global block's size.
    unsafe {
        if OpenClipboard(owner as _) == 0 {
            return false;
        }
        let mut cleared = false;
        let data = GetClipboardData(CF_UNICODETEXT);
        if !data.is_null() {
            let size = GlobalSize(data as _) / 2;
            let text = GlobalLock(data as _) as *const u16;
            if !text.is_null() {
                let copy = WideSecret(std::slice::from_raw_parts(text, size).to_vec());
                GlobalUnlock(data as _);
                if same_text(&copy.0, field) {
                    cleared = EmptyClipboard() != 0;
                }
                drop(copy);
            }
        }
        CloseClipboard();
        cleared
    }
}

/// The names held while this program may hold a recovery key: the session's, and the
/// machine's when Windows lets it be made. Crash dump set up reads them.
const KEY_HELD: [&str; 2] = [
    "Global\\DiagnosticTool-RecoveryKeyHeld",
    "Local\\DiagnosticTool-RecoveryKeyHeld",
];

/// Marks this process as one that may hold a recovery key, from the first BitLocker window,
/// lookup or unlock until it ends: a key's text can stay in memory the program has freed,
/// so the mark is never taken down early. Crash dump set up refuses full application dumps
/// while it is there.
pub fn mark_key_held() {
    use windows_sys::Win32::System::Threading::CreateMutexW;
    static MARK: std::sync::Once = std::sync::Once::new();
    MARK.call_once(|| {
        let mut made = false;
        for name in KEY_HELD {
            let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
            // SAFETY: `wide` is NUL-terminated. The handle is kept open until the process
            // ends, which is what holds the name.
            let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
            made |= !handle.is_null();
        }
        // A mark that could not be made reads as held in this process (`key_held`), so
        // full application dumps are still refused here.
        if !made {
            MARK_FAILED.store(true, Ordering::SeqCst);
        }
    });
}

/// Set when this process may hold a key but its mark could not be made.
static MARK_FAILED: AtomicBool = AtomicBool::new(false);

/// Whether some process of this program holds the mark `mark_key_held` makes, or this one
/// tried to make it and could not. A name that cannot be read for any reason but absence
/// counts as held.
pub fn key_held() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND};
    use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    if MARK_FAILED.load(Ordering::SeqCst) {
        return true;
    }
    KEY_HELD.iter().any(|name| {
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        // SAFETY: `wide` is NUL-terminated; an opened handle is closed at once.
        let handle = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide.as_ptr()) };
        if handle.is_null() {
            // SAFETY: reads this thread's last error, set by OpenMutexW just above.
            return unsafe { GetLastError() } != ERROR_FILE_NOT_FOUND;
        }
        // SAFETY: the handle came from OpenMutexW.
        unsafe { CloseHandle(handle) };
        true
    })
}

/// Overwrites a String's bytes with zeros, its spare capacity included (it can hold an
/// earlier, longer text), and empties it.
pub fn zero_string(text: &mut String) {
    // SAFETY: zeros are valid UTF-8, so the String stays valid while it is overwritten.
    let bytes = unsafe { text.as_mut_vec() };
    // Within the capacity: nothing is moved.
    bytes.resize(bytes.capacity(), 0);
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid element of the vector.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    text.clear();
}

impl RecoveryKey {
    /// Reads a recovery key as typed: 48 digits, with or without dashes or spaces between
    /// the groups. Each group of six is a multiple of 11 below 720,896, which BitLocker
    /// checks, so a mistyped digit is found here before Windows is asked. The error names
    /// the group, never the digits.
    pub fn parse(typed: &str) -> Result<Self, String> {
        // Zeroed when dropped, on every path, a panic's included.
        let mut digits = Digits([0; 48], 0);
        for c in typed.chars() {
            match c {
                '0'..='9' => {
                    if digits.1 == 48 {
                        return Err("A recovery key has 48 digits; this one has more.".into());
                    }
                    digits.0[digits.1] = c as u8 - b'0';
                    digits.1 += 1;
                }
                '-' | ' ' | '\t' => {}
                _ => {
                    return Err("A recovery key has only digits, in eight groups of six.".into());
                }
            }
        }
        if digits.1 != 48 {
            let n = digits.1;
            return Err(format!(
                "A recovery key has 48 digits, in eight groups of six; {n} were typed."
            ));
        }
        let mut bad = Vec::new();
        for (index, group) in digits.0.chunks(6).enumerate() {
            let mut value = group.iter().fold(0u32, |v, d| v * 10 + u32::from(*d));
            if value % 11 != 0 || value >= 720_896 {
                bad.push(index + 1);
            }
            // SAFETY: `value` is a valid local.
            unsafe { std::ptr::write_volatile(&mut value, 0) };
        }
        if !bad.is_empty() {
            let groups = bad
                .iter()
                .map(|g| g.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let noun = if bad.len() == 1 { "Group" } else { "Groups" };
            return Err(format!(
                "{noun} {groups} of the recovery key cannot be right: check {} against the printout.",
                if bad.len() == 1 { "it" } else { "them" }
            ));
        }
        let mut text: Vec<u16> = Vec::with_capacity(56);
        let shield = DumpShield::over(text.as_ptr().cast(), text.capacity() * 2);
        for (index, d) in digits.0.iter().enumerate() {
            if index > 0 && index % 6 == 0 {
                text.push(u16::from(b'-'));
            }
            text.push(u16::from(b'0' + d));
        }
        drop(digits);
        text.push(0);
        Ok(Self {
            _shield: shield,
            text,
            _dumps: crate::tools::crash_dumps::exclusion_share(),
        })
    }
}

/// A key's digits while it is read, zeroed when dropped.
struct Digits([u8; 48], usize);

impl Drop for Digits {
    fn drop(&mut self) {
        zero_bytes(&mut self.0);
    }
}

fn zero_bytes(buffer: &mut [u8]) {
    for b in buffer.iter_mut() {
        // SAFETY: `b` is a valid element of the slice.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ---- recovery key IDs ---------------------------------------------------------------------

/// The first eight characters of a key ID, as Windows' recovery screen shows it:
/// "{1a2b3c4d-...}" gives "1A2B3C4D".
pub fn short_id(id: &str) -> String {
    id.trim_matches(['{', '}'])
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase()
}

// ---- WMI through COM ----------------------------------------------------------------------

const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0x4590f811_1d3a_11d0_891f_00aa004b2e24);
const IID_IWBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);
const NAMESPACE: &str = r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption";
const CLASS: &str = "Win32_EncryptableVolume";
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;
const WBEM_FLAG_FORWARD_ONLY: i32 = 0x20;
const WBEM_FLAG_RETURN_IMMEDIATELY: i32 = 0x10;
/// How long one wait for the next volume of a listing may take, in milliseconds; the
/// listing as a whole ends at `WMI_LIMIT`.
const NEXT_WAIT_MS: i32 = 1000;
/// IEnumWbemClassObject::Next's answer when no object came within its wait.
const WBEM_S_TIMEDOUT: i32 = 0x0004_0004;
const VT_I4: u16 = 3;
const VT_BSTR: u16 = 8;
const VT_BOOL: u16 = 11;
const VT_ARRAY: u16 = 0x2000;
/// The numerical password (recovery password) protector type of GetKeyProtectors.
const NUMERICAL_PASSWORD: i32 = 3;

/// A VARIANT, laid out as in oaidl.h for 64-bit Windows.
#[repr(C)]
struct Variant {
    vt: u16,
    reserved: [u16; 3],
    value: usize,
    extra: usize,
}

impl Variant {
    fn empty() -> Self {
        Self {
            vt: 0,
            reserved: [0; 3],
            value: 0,
            extra: 0,
        }
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        // SAFETY: the variant is either empty or was filled by WMI or by `Bstr::into_variant`.
        unsafe { windows_sys::Win32::System::Variant::VariantClear((self as *mut Variant).cast()) };
    }
}

/// A BSTR freed on drop.
struct Bstr(*const u16);

impl Bstr {
    fn new(text: &str) -> Self {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated.
        Self(unsafe { SysAllocString(wide.as_ptr()) })
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by SysAllocString and freed once.
            unsafe { SysFreeString(self.0) };
        }
    }
}

fn bstr_text(bstr: *const u16) -> String {
    if bstr.is_null() {
        return String::new();
    }
    // SAFETY: a BSTR's length prefix gives the characters that follow.
    let len = unsafe { SysStringLen(bstr) } as usize;
    // SAFETY: `len` characters are readable at `bstr`.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(bstr, len) })
}

/// A COM interface pointer, released on drop.
struct Com(*mut c_void);

impl Com {
    /// The function at `index` in the interface's table.
    unsafe fn slot(&self, index: usize) -> *const c_void {
        // SAFETY: a COM object starts with a pointer to its function table.
        unsafe {
            let table = *(self.0 as *const *const *const c_void);
            *table.add(index)
        }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: IUnknown::Release is slot 2 of every interface.
            unsafe {
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(self.slot(2));
                release(self.0);
            }
        }
    }
}

fn failed(what: &str, hr: i32) -> String {
    format!("{what} failed (code 0x{:08X})", hr as u32)
}

/// COM for this thread, entered once and left when the thread ends. An interface pointer
/// held anywhere on the thread, even a temporary dropped after its connection, is released
/// while COM is still up. A thread already in a single-threaded apartment (a window's
/// thread) is used as it is.
struct Apartment;

/// Leaves COM at thread exit, if this thread entered it here.
struct Entered;

impl Drop for Entered {
    fn drop(&mut self) {
        // SAFETY: balances the one successful CoInitializeEx of this thread.
        unsafe { CoUninitialize() };
    }
}

thread_local! {
    static ENTERED: std::cell::OnceCell<Option<Entered>> = const { std::cell::OnceCell::new() };
}

const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;

impl Apartment {
    fn enter() -> Result<Self, String> {
        ENTERED.with(|entered| {
            if entered.get().is_some() {
                return Ok(Self);
            }
            // SAFETY: initialises COM for this thread, once; `Entered` balances it.
            let hr = unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) };
            match hr {
                RPC_E_CHANGED_MODE => {
                    let _ = entered.set(None);
                    Ok(Self)
                }
                hr if hr < 0 => Err(failed("Starting COM", hr)),
                _ => {
                    let _ = entered.set(Some(Entered));
                    Ok(Self)
                }
            }
        })
    }
}

/// A connection to the BitLocker WMI namespace. Needs administrator rights.
struct Wmi {
    services: Com,
    _apartment: Apartment,
}

/// One Win32_EncryptableVolume.
struct Instance {
    path: String,
}

impl Wmi {
    fn connect() -> Result<Self, String> {
        let apartment = Apartment::enter()?;
        let mut locator: *mut c_void = null_mut();
        // SAFETY: the CLSID and IID are WMI's; `locator` receives the interface.
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_WBEM_LOCATOR,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_IWBEM_LOCATOR,
                &mut locator,
            )
        };
        if hr < 0 {
            return Err(failed("Reaching Windows Management Instrumentation", hr));
        }
        let locator = Com(locator);
        let namespace = Bstr::new(NAMESPACE);
        let mut services: *mut c_void = null_mut();
        // SAFETY: IWbemLocator::ConnectServer is slot 3; null credentials use this process's.
        let hr = unsafe {
            let connect: unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                *const u16,
                *const u16,
                *const u16,
                i32,
                *const u16,
                *mut c_void,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(locator.slot(3));
            connect(
                locator.0,
                namespace.0,
                null(),
                null(),
                null(),
                0,
                null(),
                null_mut(),
                &mut services,
            )
        };
        if hr < 0 {
            return Err(match hr as u32 {
                0x8004_1003 | 0x8007_0005 => {
                    "Reading BitLocker needs administrator rights.".to_string()
                }
                0x8004_100E => "This copy of Windows has no BitLocker (its WMI class is missing). BitLocker drives open on Windows Pro, Enterprise or Education.".to_string(),
                _ => failed("Connecting to BitLocker's management", hr),
            });
        }
        let services = Com(services);
        // BitLocker's provider accepts only calls with packet privacy.
        // SAFETY: sets the security of the proxy just made.
        let hr = unsafe {
            CoSetProxyBlanket(
                services.0.cast(),
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                null(),
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                null(),
                EOAC_NONE as u32,
            )
        };
        if hr < 0 {
            return Err(failed("Securing the BitLocker connection", hr));
        }
        Ok(Self {
            services,
            _apartment: apartment,
        })
    }

    /// Every encryptable volume, with its DeviceID ("\\?\Volume{guid}\").
    fn volumes(&self) -> Result<Vec<(String, Instance)>, String> {
        let language = Bstr::new("WQL");
        let query = Bstr::new(&format!("SELECT * FROM {CLASS}"));
        let mut enumerator: *mut c_void = null_mut();
        // SAFETY: IWbemServices::ExecQuery is slot 20.
        let hr = unsafe {
            let exec: unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                *const u16,
                i32,
                *mut c_void,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(self.services.slot(20));
            exec(
                self.services.0,
                language.0,
                query.0,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                null_mut(),
                &mut enumerator,
            )
        };
        if hr < 0 {
            return Err(failed("Listing BitLocker volumes", hr));
        }
        let enumerator = Com(enumerator);
        let mut found = Vec::new();
        // Each wait for the next volume is bounded, and so is the listing as a whole, so the
        // thread it runs on ends even when the provider stops answering.
        let deadline = std::time::Instant::now() + WMI_LIMIT;
        loop {
            let mut object: *mut c_void = null_mut();
            let mut returned = 0u32;
            // SAFETY: IEnumWbemClassObject::Next is slot 4.
            let hr = unsafe {
                let next: unsafe extern "system" fn(
                    *mut c_void,
                    i32,
                    u32,
                    *mut *mut c_void,
                    *mut u32,
                ) -> i32 = std::mem::transmute(enumerator.slot(4));
                next(enumerator.0, NEXT_WAIT_MS, 1, &mut object, &mut returned)
            };
            if hr < 0 {
                return Err(failed("Listing BitLocker volumes", hr));
            }
            if hr == WBEM_S_TIMEDOUT && returned == 0 {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Windows' BitLocker management did not finish listing the volumes within {} s.",
                        WMI_LIMIT.as_secs()
                    ));
                }
                continue;
            }
            if returned == 0 {
                break;
            }
            let object = Com(object);
            let device = get_text(&object, "DeviceID").unwrap_or_default();
            let path = get_text(&object, "__PATH").unwrap_or_default();
            found.push((device, Instance { path }));
        }
        Ok(found)
    }

    fn volume(&self, device_id: &str) -> Result<Instance, String> {
        let wanted = normal_device(device_id);
        self.volumes()?
            .into_iter()
            .find(|(device, _)| normal_device(device) == wanted)
            .map(|(_, instance)| instance)
            .ok_or_else(|| "Windows' BitLocker management does not list this volume.".into())
    }

    /// The in-parameters object of one of the class's methods, ready to be filled.
    fn in_params(&self, method: &str) -> Result<Com, String> {
        let class_name = Bstr::new(CLASS);
        let mut class: *mut c_void = null_mut();
        // SAFETY: IWbemServices::GetObject is slot 6.
        let hr = unsafe {
            let get: unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                i32,
                *mut c_void,
                *mut *mut c_void,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(self.services.slot(6));
            get(
                self.services.0,
                class_name.0,
                0,
                null_mut(),
                &mut class,
                null_mut(),
            )
        };
        if hr < 0 {
            return Err(failed("Reading the BitLocker class", hr));
        }
        let class = Com(class);
        let name = wide(method);
        let mut signature: *mut c_void = null_mut();
        // SAFETY: IWbemClassObject::GetMethod is slot 19.
        let hr = unsafe {
            let get: unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                i32,
                *mut *mut c_void,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(class.slot(19));
            get(class.0, name.as_ptr(), 0, &mut signature, null_mut())
        };
        if hr < 0 || signature.is_null() {
            return Err(failed(&format!("Reading BitLocker's {method}"), hr));
        }
        let signature = Com(signature);
        let mut instance: *mut c_void = null_mut();
        // SAFETY: IWbemClassObject::SpawnInstance is slot 15.
        let hr = unsafe {
            let spawn: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32 =
                std::mem::transmute(signature.slot(15));
            spawn(signature.0, 0, &mut instance)
        };
        if hr < 0 {
            return Err(failed(&format!("Preparing BitLocker's {method}"), hr));
        }
        Ok(Com(instance))
    }

    /// Runs a method on a volume and returns its out-parameters.
    fn call(&self, volume: &Instance, method: &str, input: Option<&Com>) -> Result<Com, String> {
        let path = Bstr::new(&volume.path);
        let name = Bstr::new(method);
        let mut out: *mut c_void = null_mut();
        // SAFETY: IWbemServices::ExecMethod is slot 24.
        let hr = unsafe {
            let exec: unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                *const u16,
                i32,
                *mut c_void,
                *mut c_void,
                *mut *mut c_void,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(self.services.slot(24));
            exec(
                self.services.0,
                path.0,
                name.0,
                0,
                null_mut(),
                input.map_or(null_mut(), |i| i.0),
                &mut out,
                null_mut(),
            )
        };
        if hr < 0 || out.is_null() {
            return Err(failed(&format!("BitLocker's {method}"), hr));
        }
        Ok(Com(out))
    }
}

/// How long one BitLocker job through WMI may take: connecting, finding the volume and its
/// calls together.
pub const WMI_LIMIT: Duration = Duration::from_secs(60);

/// The longest the process's end waits for BitLocker's management to answer one job, a
/// chosen bound twice the limit (none was measured past it).
pub const WMI_ANSWER: Duration = Duration::from_secs(120);

/// How long locking a volume again takes as an undo: the relock, and its drop's second try.
pub const RELOCK_UNDO: Duration = Duration::from_secs(240);

fn no_answer(what: &str) -> String {
    format!(
        "Windows' BitLocker management did not answer within {} s while {what}.",
        WMI_LIMIT.as_secs()
    )
}

/// Runs `work`, which changes nothing, on a WMI connection of a thread of its own, within
/// `WMI_LIMIT` or until `cancel` is set (`timed::in_time`). Every BitLocker read goes
/// through here.
fn reading<T: Send + 'static>(
    what: &str,
    cancel: Option<&AtomicBool>,
    work: impl FnOnce(&Wmi) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    match super::timed::in_time(WMI_LIMIT, cancel, move || {
        Wmi::connect().and_then(|wmi| work(&wmi))
    }) {
        Waited::Done(answer) => answer,
        Waited::NoAnswer => Err(no_answer(what)),
        Waited::Stopped => Err(format!("Stopped while {what}.")),
    }
}

/// Runs `work`, which changes a volume, as `reading` does, but through `timed::owned`: when
/// it ends after its time limit or Stop, `late` is given its outcome on its own thread, to
/// put back what it changed or record it. Every BitLocker change goes through here.
/// `undo` is how long `late` takes.
fn changing<T: Send + 'static>(
    what: &str,
    undo: Duration,
    cancel: Option<&AtomicBool>,
    work: impl FnOnce(&Wmi) -> Result<T, String> + Send + 'static,
    late: impl FnOnce(Result<T, String>) + Send + 'static,
) -> Result<T, String> {
    match super::timed::owned(
        super::timed::Job::new(what, WMI_LIMIT)
            .answered_within(WMI_ANSWER)
            .undone_within(undo),
        cancel,
        move || Wmi::connect().and_then(|wmi| work(&wmi)),
        late,
    ) {
        Waited::Done(answer) => answer,
        Waited::NoAnswer => Err(no_answer(what)),
        Waited::Stopped => Err(format!("Stopped while {what}.")),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// "\\?\Volume{GUID}" without the closing backslash, lower case, for comparing.
fn normal_device(device: &str) -> String {
    device.trim_end_matches('\\').to_ascii_lowercase()
}

fn get(object: &Com, name: &str) -> Result<Variant, String> {
    let name_w = wide(name);
    let mut value = Variant::empty();
    // SAFETY: IWbemClassObject::Get is slot 4; the variant is filled by WMI.
    let hr = unsafe {
        let get: unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            i32,
            *mut Variant,
            *mut i32,
            *mut i32,
        ) -> i32 = std::mem::transmute(object.slot(4));
        get(
            object.0,
            name_w.as_ptr(),
            0,
            &mut value,
            null_mut(),
            null_mut(),
        )
    };
    if hr < 0 {
        return Err(failed(&format!("Reading {name}"), hr));
    }
    Ok(value)
}

fn get_text(object: &Com, name: &str) -> Option<String> {
    let value = get(object, name).ok()?;
    (value.vt == VT_BSTR).then(|| bstr_text(value.value as *const u16))
}

fn get_u32(object: &Com, name: &str) -> Option<u32> {
    let value = get(object, name).ok()?;
    (value.vt == VT_I4).then_some(value.value as u32)
}

fn put(object: &Com, name: &str, value: &mut Variant) -> Result<(), String> {
    let name_w = wide(name);
    // SAFETY: IWbemClassObject::Put is slot 5; WMI copies the value.
    let hr = unsafe {
        let put: unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut Variant, i32) -> i32 =
            std::mem::transmute(object.slot(5));
        put(object.0, name_w.as_ptr(), 0, value, 0)
    };
    if hr < 0 {
        return Err(failed(&format!("Setting {name}"), hr));
    }
    Ok(())
}

fn put_i32(object: &Com, name: &str, number: i32) -> Result<(), String> {
    let mut value = Variant::empty();
    value.vt = VT_I4;
    value.value = number as u32 as usize;
    put(object, name, &mut value)
}

fn put_bool(object: &Com, name: &str, on: bool) -> Result<(), String> {
    let mut value = Variant::empty();
    value.vt = VT_BOOL;
    value.value = if on { 0xFFFF } else { 0 };
    put(object, name, &mut value)
}

/// The strings of a VT_ARRAY | VT_BSTR variant.
fn strings(value: &Variant) -> Vec<String> {
    use windows_sys::Win32::System::Ole::{
        SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
    };
    if value.vt != VT_ARRAY | VT_BSTR || value.value == 0 {
        return Vec::new();
    }
    let array = value.value as *const _;
    let (mut low, mut high) = (0i32, -1i32);
    // SAFETY: a one-dimensional SAFEARRAY of BSTRs from WMI.
    unsafe {
        if SafeArrayGetLBound(array, 1, &mut low) < 0 || SafeArrayGetUBound(array, 1, &mut high) < 0
        {
            return Vec::new();
        }
    }
    let mut out = Vec::new();
    for index in low..=high {
        let mut element: *const u16 = null();
        // SAFETY: the element is copied out as a new BSTR, freed below.
        let hr =
            unsafe { SafeArrayGetElement(array, &index, (&mut element as *mut *const u16).cast()) };
        if hr >= 0 {
            out.push(bstr_text(element));
            drop(Bstr(element));
        }
    }
    out
}

/// The method's ReturnValue: 0 for success, else an HRESULT-style code.
fn return_value(out: &Com) -> u32 {
    get_u32(out, "ReturnValue").unwrap_or(u32::MAX)
}

/// What a BitLocker return code means, for people.
pub fn code_text(code: u32) -> String {
    match code {
        0x8031_0027 | 0x8031_0033 => "The recovery key does not unlock this drive. Check it against the printout, or look for another key: the ID shown must match the key's ID.".into(),
        0x8031_0000 => "The drive is locked.".into(),
        0x8031_0008 => "BitLocker is not turned on for this drive.".into(),
        0x8031_0043 => "Windows refused this recovery key's format.".into(),
        0x8031_0019 | 0x8031_0034 => "This drive has no recovery key; it was locked with another kind of key.".into(),
        other => format!("Windows did not do it (code 0x{other:08X})."),
    }
}

/// A BitLocker volume as Windows sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// "\\?\Volume{guid}\".
    pub device_id: String,
    /// `None` when Windows did not say whether it is locked: never shown as either.
    pub locked: Option<bool>,
    /// The recovery key IDs, in full ("{1A2B3C4D-....}").
    pub key_ids: Vec<String>,
}

/// Reads a volume's lock state and recovery key IDs without unlocking it. The key IDs are
/// what a later lookup of the customer's Microsoft account matches on.
pub fn status(device_id: &str) -> Result<Status, String> {
    status_within(device_id, None)
}

/// `status`, given up when `cancel` is set.
fn status_within(device_id: &str, cancel: Option<&AtomicBool>) -> Result<Status, String> {
    let device_id = device_id.to_string();
    reading("reading a volume's lock state", cancel, move |wmi| {
        let volume = wmi.volume(&device_id)?;
        let lock = wmi.call(&volume, "GetLockStatus", None)?;
        let locked = match get_u32(&lock, "LockStatus") {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        };
        let key_ids = key_ids_with(wmi, &volume)?;
        Ok(Status {
            device_id,
            locked,
            key_ids,
        })
    })
}

fn key_ids_with(wmi: &Wmi, volume: &Instance) -> Result<Vec<String>, String> {
    let input = wmi.in_params("GetKeyProtectors")?;
    put_i32(&input, "KeyProtectorType", NUMERICAL_PASSWORD)?;
    let out = wmi.call(volume, "GetKeyProtectors", Some(&input))?;
    match return_value(&out) {
        0 => Ok(strings(&get(&out, "VolumeKeyProtectorID")?)),
        code => Err(code_text(code)),
    }
}

/// The full recovery key IDs of a volume, read while it stays locked. For the lookup of a
/// customer's recovery key by its ID.
pub fn recovery_key_ids(device_id: &str) -> Result<Vec<String>, String> {
    let device_id = device_id.to_string();
    reading("reading a volume's recovery key IDs", None, move |wmi| {
        let volume = wmi.volume(&device_id)?;
        key_ids_with(wmi, &volume)
    })
}

/// The one way a volume is unlocked: `text` is the key as typed or as found by a lookup.
/// It is checked, passed to Windows once, and `text` is overwritten with zeros and
/// emptied whatever happens. Never logged and never stored. `identity` is the volume as
/// read just before: an unlock that ends after its time limit or Stop locks it again.
pub fn unlock_with_key_text(
    device_id: &str,
    text: &mut String,
    identity: VolumeIdentity,
    cancel: Option<&AtomicBool>,
) -> Result<Relock, String> {
    mark_key_held();
    // Kept out of crash dumps until the key is passed to Windows and dropped.
    let _dumps = match crate::tools::crash_dumps::keep_out_of_dumps() {
        Ok(kept) => kept,
        Err(why) => {
            zero_string(text);
            return Err(why);
        }
    };
    let parsed = RecoveryKey::parse(text);
    zero_string(text);
    let key = parsed?;
    unlock_parsed(device_id, key, identity, cancel)
}

/// Unlocks through `changing`: the key moves to the call's thread and is zeroed there when
/// the call is done with it. The `Relock` that locks the volume again is made on the call's
/// thread as the unlock answers, so the unlocked volume is counted before the job ends. An
/// unlock that ends after its caller gave up is locked again at once through it, and what
/// happened goes in the change record.
fn unlock_parsed(
    device_id: &str,
    key: RecoveryKey,
    identity: VolumeIdentity,
    cancel: Option<&AtomicBool>,
) -> Result<Relock, String> {
    let device = device_id.to_string();
    let late_device = device.clone();
    changing(
        &format!("unlocking {device_id}"),
        RELOCK_UNDO,
        cancel,
        move |wmi| {
            let volume = wmi.volume(&device)?;
            let len = key.text.len().saturating_sub(1);
            let input = key_input(wmi, key)?;
            let out = wmi.call(&volume, "UnlockWithNumericalPassword", Some(&input));
            release_key_input(input, len);
            match return_value(&out?) {
                0 => Ok(Relock::with(device, identity, WINDOWS_VOLUMES)),
                code => Err(code_text(code)),
            }
        },
        move |late| {
            let Ok(mut relock) = late else {
                // It did not unlock, so nothing changed.
                return;
            };
            let outcome = relock.relock(false);
            crate::handles::record_unseen(
                "Unlock a BitLocker drive",
                &format!(
                    "An unlock ended after its time limit or Stop; {}",
                    outcome.text(&late_device)
                ),
            );
            // Still unlocked: the relock's drop tries once more and records how it ended.
            drop(relock);
        },
    )
}

/// The in-parameters of UnlockWithNumericalPassword holding `key`. Every copy of the key
/// this program holds is zeroed before this returns, on every path: the BSTR handed to
/// `Put` here, and the parsed key when it is dropped.
///
/// Residual: `Put` copies the key into WMI's own in-parameters object, and the call
/// marshals it to the WMI service, which hands it to BitLocker. Those copies are WMI's and
/// Windows' and this program cannot zero them; it overwrites the copy in the object and
/// releases the object as soon as the call returns (`release_key_input`). Measured
/// (`live_wmi_key_copies`): 6 UTF-16 copies and 1 ASCII copy in this process once WMI holds
/// the key; 1 or 2 left after the overwrite and release, 5 or 6 without the overwrite.
fn key_input(wmi: &Wmi, key: RecoveryKey) -> Result<Com, String> {
    let input = wmi.in_params("UnlockWithNumericalPassword")?;
    // SAFETY: the key's text is NUL-terminated.
    let bstr = unsafe { SysAllocString(key.text.as_ptr()) };
    drop(key);
    if bstr.is_null() {
        return Err("Out of memory for the recovery key.".into());
    }
    let mut value = Variant::empty();
    value.vt = VT_BSTR;
    value.value = bstr as usize;
    let result = put(&input, "NumericalPassword", &mut value);
    // The copy in the BSTR is zeroed before it is freed with the variant.
    // SAFETY: the BSTR holds SysStringLen characters and is still owned by `value`.
    unsafe {
        let len = SysStringLen(bstr) as usize;
        zero_u16(std::slice::from_raw_parts_mut(bstr as *mut u16, len));
    }
    drop(value);
    result.map(|()| input)
}

/// Overwrites the key in the in-parameters object with as many zeros, which WMI may store
/// where the key was, and releases the object at once.
fn release_key_input(input: Com, len: usize) {
    let zeros: Vec<u16> = std::iter::repeat_n(u16::from(b'0'), len)
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `zeros` is NUL-terminated.
    let bstr = unsafe { SysAllocString(zeros.as_ptr()) };
    if !bstr.is_null() {
        let mut value = Variant::empty();
        value.vt = VT_BSTR;
        value.value = bstr as usize;
        let _ = put(&input, "NumericalPassword", &mut value);
    }
    drop(input);
}

/// Locks a volume. With `force` allowed, a volume still in use is dismounted when locking
/// it otherwise fails: nothing here writes to it, but files open on it are closed. Ok says
/// whether it had to be dismounted.
pub fn lock(device_id: &str, force: bool) -> Result<bool, String> {
    lock_within(device_id, force, None)
}

/// `lock` through `changing`: a lock that ends after its caller gave up is recorded, and
/// whoever asked for it (a `Relock`) still holds the volume and reads it again.
fn lock_within(device_id: &str, force: bool, cancel: Option<&AtomicBool>) -> Result<bool, String> {
    let device = device_id.to_string();
    let late_device = device.clone();
    changing(
        &format!("locking {device_id}"),
        Duration::ZERO,
        cancel,
        move |wmi| lock_on(wmi, &wmi.volume(&device)?, force),
        move |late| {
            crate::handles::record_unseen(
                "Lock a BitLocker drive",
                &match late {
                    Ok(false) => format!("{late_device} was locked after its time limit."),
                    Ok(true) => format!(
                        "{late_device} was locked after its time limit; it was in use, so files open on it were closed."
                    ),
                    Err(why) => format!(
                        "{late_device} was not locked: a lock that ran past its time limit ended with: {why}"
                    ),
                },
            );
        },
    )
}

/// Locks `volume` on `wmi`; with `force`, dismounting it when locking it otherwise fails. Ok
/// says whether it had to be dismounted.
fn lock_on(wmi: &Wmi, volume: &Instance, force: bool) -> Result<bool, String> {
    let mut last = 0;
    for dismount in [false, true] {
        if dismount && !force {
            break;
        }
        let input = wmi.in_params("Lock")?;
        put_bool(&input, "ForceDismount", dismount)?;
        let out = wmi.call(volume, "Lock", Some(&input))?;
        match return_value(&out) {
            0 => return Ok(dismount),
            code => last = code,
        }
    }
    Err(code_text(last))
}

/// Which volume a BitLocker volume is: what a relock compares before it locks, so it never
/// locks a volume that is not the one this program unlocked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeIdentity {
    /// "\\?\Volume{guid}\", upper case.
    pub device_id: String,
    /// Where it lies: disk number, byte offset and length of each piece.
    pub extents: Vec<(u32, u64, u64)>,
    /// Its recovery key IDs, sorted.
    pub key_ids: Vec<String>,
}

/// A volume's lock state with its identity, as read now. `locked` is `None` when Windows
/// did not say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeState {
    pub locked: Option<bool>,
    pub identity: VolumeIdentity,
}

/// Reads a volume's lock state and identity.
pub fn volume_state(device_id: &str) -> Result<VolumeState, String> {
    volume_state_within(device_id, None)
}

/// `volume_state`, given up when `cancel` is set.
fn volume_state_within(
    device_id: &str,
    cancel: Option<&AtomicBool>,
) -> Result<VolumeState, String> {
    let extents = crate::tools::drives::device::volume_extents(device_id)?;
    let status = status_within(device_id, cancel)?;
    let mut key_ids: Vec<String> = status
        .key_ids
        .iter()
        .map(|id| id.to_ascii_uppercase())
        .collect();
    key_ids.sort();
    Ok(VolumeState {
        locked: status.locked,
        identity: VolumeIdentity {
            device_id: normal_device(device_id).to_ascii_uppercase(),
            extents,
            key_ids,
        },
    })
}

// ---- the engine ----------------------------------------------------------------------------

/// A recovery key as given in options: as typed by the technician, told to an agent, or
/// found by a key lookup. Zeroed when dropped; never shown by Debug and never written by
/// serde ("withheld" is written in its place).
/// Its text is left out of dumps of this process while it lives (`DumpShield`).
#[derive(Default)]
pub struct KeyText {
    /// Declared first: taken back after the text is zeroed and before it is freed.
    shield: Option<DumpShield>,
    text: String,
    /// This program stays out of crash dumps while the text lives.
    dumps: Option<crate::tools::crash_dumps::DumpExclusion>,
}

impl KeyText {
    /// Takes `text` over: it is zeroed when this is dropped. For a key handed in as a
    /// `String` already; text read from somewhere goes through `copy_of` or `from_wide`, so
    /// no other `String` ever holds it.
    pub fn new(text: String) -> Self {
        Self {
            shield: DumpShield::over(text.as_ptr(), text.capacity()),
            text,
            dumps: crate::tools::crash_dumps::exclusion_share(),
        }
    }

    /// A copy of `text` made straight into this type's own buffer, sized first, so the copy
    /// never moves and is left out of dumps from before it is written.
    pub fn copy_of(text: &str) -> Self {
        let mut own = String::with_capacity(text.len());
        let shield = DumpShield::over(own.as_ptr(), own.capacity());
        own.push_str(text);
        Self {
            shield,
            text: own,
            dumps: crate::tools::crash_dumps::exclusion_share(),
        }
    }

    /// UTF-16 text, as an edit control gives it, decoded straight into this type's own
    /// buffer, sized for the longest decoding first so it never moves.
    pub fn from_wide(units: &[u16]) -> Self {
        let mut own = String::with_capacity(units.len() * 3);
        let shield = DumpShield::over(own.as_ptr(), own.capacity());
        for c in char::decode_utf16(units.iter().copied()) {
            own.push(c.unwrap_or('\u{FFFD}'));
        }
        Self {
            shield,
            text: own,
            dumps: crate::tools::crash_dumps::exclusion_share(),
        }
    }

    /// The length of the text in bytes.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether no text was given.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The share of the exclusion from crash dumps this text holds.
    pub fn exclusion(&self) -> Option<&crate::tools::crash_dumps::DumpExclusion> {
        self.dumps.as_ref()
    }

    /// Whether Windows took the request to leave the text out of dumps.
    pub fn shielded(&self) -> bool {
        self.shield.is_some()
    }
}

impl Drop for KeyText {
    fn drop(&mut self) {
        zero_string(&mut self.text);
    }
}

impl std::fmt::Debug for KeyText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyText(withheld)")
    }
}

impl Serialize for KeyText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("withheld")
    }
}

/// Reads a key from serialized options straight into `KeyText`'s own buffer. A key the
/// format hands over as an owned `String` (JSON text with escapes in it) is copied and that
/// `String` zeroed. Residual: the caller's serialized text itself, and the format's own
/// scratch buffer for escaped text, are the caller's and the format's, and are not zeroed
/// here.
struct KeyTextVisitor;

impl serde::de::Visitor<'_> for KeyTextVisitor {
    type Value = KeyText;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a recovery key as text")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<KeyText, E> {
        Ok(KeyText::copy_of(text))
    }

    fn visit_string<E: serde::de::Error>(self, mut text: String) -> Result<KeyText, E> {
        let key = KeyText::copy_of(&text);
        zero_string(&mut text);
        Ok(key)
    }
}

impl<'de> Deserialize<'de> for KeyText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(KeyTextVisitor)
    }
}

/// Options of the BitLocker scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanOptions {
    /// The disk to look on: the drive being recovered, or an image attached as a drive.
    pub disk: u32,
}

/// A BitLocker volume the scan found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    /// "\\?\Volume{guid}\", what unlock and lock take.
    pub device_id: String,
    pub letter: Option<String>,
    /// Byte offset on the disk, and length.
    pub offset: u64,
    pub len: u64,
    /// None when Windows' BitLocker management could not be read for it (see `error`).
    pub locked: Option<bool>,
    /// The recovery key IDs in full ("{1A2B3C4D-...}"), what a key lookup matches on.
    pub key_ids: Vec<String>,
    /// Their first eight characters, as Windows' recovery screen shows them.
    pub key_ids_short: Vec<String>,
    pub error: Option<String>,
}

/// What the BitLocker scan found.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub disk: u32,
    pub volumes: Vec<Found>,
}

/// Offsets of the volumes among `volumes` whose first sector, read from `disk` through the
/// time-limited read-only reader, is a BitLocker boot sector. A volume whose first sector
/// cannot be read is not among them; `boot_sectors` says which those are.
pub fn bitlocker_offsets(disk: u32, volumes: &[VolumeInfo]) -> Result<Vec<u64>, String> {
    boot_sectors(disk, volumes).map(|sorted| sorted.bitlocker)
}

/// The volumes of a disk sorted by their first sector.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootSectors {
    /// Offsets of the volumes whose first sector is BitLocker's.
    pub bitlocker: Vec<u64>,
    /// Offsets of the volumes whose first sector could not be read, with why: whether they
    /// are BitLocker is not known.
    pub unread: Vec<(u64, String)>,
}

/// Reads the first sector of each of `volumes` from `disk` through the time-limited
/// read-only reader.
pub fn boot_sectors(disk: u32, volumes: &[VolumeInfo]) -> Result<BootSectors, String> {
    let mut sorted = BootSectors::default();
    if volumes.is_empty() {
        return Ok(sorted);
    }
    let mut source = super::timed::open_source_within(
        super::SourceChoice::Disk(disk),
        super::timed::OPEN_LIMIT,
    )?;
    let sector = source.sector_size().max(512) as usize;
    let mut boot = vec![0u8; sector];
    for v in volumes {
        match source.read_at(v.offset, &mut boot) {
            Ok(_) if is_bitlocker(&boot) => sorted.bitlocker.push(v.offset),
            Ok(_) => {}
            Err(e) => sorted.unread.push((
                v.offset,
                match e {
                    super::ReadError::Bad(code) => format!("the drive answered with error {code}"),
                    super::ReadError::TimedOut => "the read did not finish in time".into(),
                    super::ReadError::Gone(code) => {
                        format!("the drive stopped answering (error {code})")
                    }
                },
            )),
        }
    }
    Ok(sorted)
}

/// The BitLocker scan: Windows' volumes on the disk whose boot sector is BitLocker's, each
/// with its lock state and recovery key IDs, read without unlocking anything.
pub fn scan(
    options: &ScanOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<ScanResult, String> {
    events(Event::Phase {
        text: format!("Reading the volumes of Disk {}", options.disk),
    });
    let volumes = vdisk::volumes_of_disk(options.disk);
    let sorted = boot_sectors(options.disk, &volumes)?;
    let mut found = Vec::new();
    // A volume whose first sector could not be read may be BitLocker: listed, and said.
    for v in volumes
        .iter()
        .filter(|v| sorted.unread.iter().any(|(at, _)| *at == v.offset))
    {
        let why = sorted
            .unread
            .iter()
            .find(|(at, _)| *at == v.offset)
            .map_or(String::new(), |(_, why)| why.clone());
        events(Event::Warning {
            text: format!(
                "{}: its first sector could not be read ({why})",
                v.describe()
            ),
        });
        found.push(Found {
            letter: v.letter(),
            device_id: v.guid_path.clone(),
            offset: v.offset,
            len: v.len,
            locked: None,
            key_ids_short: Vec::new(),
            key_ids: Vec::new(),
            error: Some(format!(
                "Its first sector could not be read ({why}), so whether it is BitLocker is not known"
            )),
        });
    }
    let offsets = sorted.bitlocker;
    for v in volumes.into_iter().filter(|v| offsets.contains(&v.offset)) {
        if cancel.load(Ordering::Relaxed) {
            events(Event::Warning {
                text: "Stopped before every volume was read.".into(),
            });
            break;
        }
        events(Event::Item { text: v.describe() });
        let (locked, key_ids, error) = match status_within(&v.guid_path, Some(cancel)) {
            Ok(s) if s.locked.is_none() => (
                None,
                s.key_ids,
                Some("Windows did not say whether it is locked".to_string()),
            ),
            Ok(s) => (s.locked, s.key_ids, None),
            Err(why) => (None, Vec::new(), Some(why)),
        };
        found.push(Found {
            letter: v.letter(),
            device_id: v.guid_path,
            offset: v.offset,
            len: v.len,
            locked,
            key_ids_short: key_ids.iter().map(|id| short_id(id)).collect(),
            key_ids,
            error,
        });
    }
    Ok(ScanResult {
        disk: options.disk,
        volumes: found,
    })
}

/// Options of an unlock.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockOptions {
    /// "\\?\Volume{guid}\" of a BitLocker volume, as the scan gives it.
    pub device_id: String,
    /// The 48-digit recovery key, eight groups of six digits, dashes or spaces optional.
    pub recovery_key: KeyText,
    /// The disk being recovered, if the work is on a drive and not only on images.
    #[serde(default)]
    pub source_disk: Option<u32>,
    /// Confirms unlocking a volume on the drive being recovered itself, after the advice to
    /// image a failing drive first and unlock the image instead. Without it such a volume
    /// is refused.
    #[serde(default)]
    pub unlock_source_drive: bool,
}

/// What an unlock did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlockResult {
    pub device_id: String,
    pub disk: u32,
    pub letter: Option<String>,
    /// The source the recovery tools read the unlocked volume through.
    pub source: super::SourceChoice,
    /// The volume was unlocked already, so the key was not used and nothing locks it again.
    #[serde(default)]
    pub already_unlocked: bool,
}

/// The advice for unlocking a drive that may be failing.
pub const SOURCE_ADVICE: &str = "Unlocking puts the drive's file system in use, and Windows can write to a file system in use. If the drive is failing, make a rescue image first, open the image as a drive, and unlock the image instead: nothing can be written to it.";

/// Unlocks a BitLocker volume with its recovery key, through `unlock_with_key_text`. The
/// key is zeroed when the options are dropped here, whatever happens. A volume already
/// unlocked is left as it is and the key is not used (`already_unlocked`); one whose lock
/// state Windows does not give is refused.
pub fn unlock(
    options: UnlockOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<UnlockResult, String> {
    unlock_noting(options, events, cancel).map(|(result, relock)| {
        if let Some(relock) = relock {
            relock.keep_unlocked();
        }
        result
    })
}

/// `unlock`, with the `Relock` when this unlock is what changed it from locked to unlocked.
fn unlock_noting(
    mut options: UnlockOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<(UnlockResult, Option<Relock>), String> {
    let before = volume_state_within(&options.device_id, Some(cancel))?;
    let disks: Vec<u32> = before
        .identity
        .extents
        .iter()
        .map(|(disk, _, _)| *disk)
        .collect();
    let Some(&disk) = disks.first() else {
        return Err("Windows does not say which disk this volume is on.".into());
    };
    if options.source_disk.is_some_and(|s| disks.contains(&s)) && !options.unlock_source_drive {
        return Err(format!(
            "This volume is on the drive being recovered. {SOURCE_ADVICE} To unlock the drive itself, confirm it."
        ));
    }
    let already_unlocked =
        match before.locked {
            Some(true) => false,
            Some(false) => true,
            None => return Err(
                "Windows does not say whether this volume is locked, so it is not unlocked here."
                    .into(),
            ),
        };
    let relock = if already_unlocked {
        events(Event::Warning {
            text: "The volume is already unlocked; the recovery key was not used.".into(),
        });
        None
    } else {
        events(Event::Phase {
            text: "Unlocking".into(),
        });
        Some(unlock_with_key_text(
            &options.device_id,
            &mut options.recovery_key.text,
            before.identity.clone(),
            Some(cancel),
        )?)
    };
    let letter = vdisk::volumes_of_disk(disk)
        .into_iter()
        .find(|v| v.guid_path.eq_ignore_ascii_case(&options.device_id))
        .and_then(|v| v.letter());
    let place = letter
        .clone()
        .unwrap_or_else(|| "with no drive letter".into());
    let result = UnlockResult {
        source: super::SourceChoice::Volume {
            path: options.device_id.trim_end_matches('\\').to_string(),
            disk,
            name: format!("BitLocker volume {place} on Disk {disk}"),
        },
        device_id: options.device_id.clone(),
        disk,
        letter,
        already_unlocked,
    };
    Ok((result, relock))
}

/// Options of a lock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockOptions {
    /// "\\?\Volume{guid}\" of a volume to lock again.
    pub device_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockResult {
    pub device_id: String,
    /// Read after locking; `None` when Windows did not say, which is never shown as locked.
    pub locked: Option<bool>,
    /// The volume was in use and was dismounted to lock it.
    pub dismounted: bool,
}

/// Locks a BitLocker volume, dismounting it when it is in use. One already locked is left as
/// it is and said.
pub fn lock_volume(
    options: &LockOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<LockResult, String> {
    events(Event::Phase {
        text: "Locking".into(),
    });
    // Windows refuses to lock a locked volume ("The drive is locked."): that is the state
    // asked for, not a failure.
    if status_within(&options.device_id, Some(cancel))?.locked == Some(true) {
        events(Event::Warning {
            text: "The volume is already locked.".into(),
        });
        return Ok(LockResult {
            device_id: options.device_id.clone(),
            locked: Some(true),
            dismounted: false,
        });
    }
    let dismounted = lock_within(&options.device_id, true, Some(cancel))?;
    let locked = status(&options.device_id).ok().and_then(|s| s.locked);
    if locked != Some(true) {
        events(Event::Warning {
            text: match locked {
                Some(_) => "Windows says the volume is still unlocked.".into(),
                None => "Whether the volume is locked now could not be read.".into(),
            },
        });
    }
    Ok(LockResult {
        device_id: options.device_id.clone(),
        locked,
        dismounted,
    })
}

/// What a relock found and did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RelockOutcome {
    /// Locked again, read back; `dismounted` when it was in use and was dismounted.
    Locked { dismounted: bool },
    /// It was locked already; nothing was done.
    AlreadyLocked,
    /// It is not the volume this program unlocked, or it changed since: left as it is.
    LeftAlone { why: String },
    /// It could not be locked, or its state could not be read: it may still be unlocked.
    NotLocked { why: String },
}

impl RelockOutcome {
    /// Whether the volume is known to be locked.
    pub fn locked(&self) -> bool {
        matches!(
            self,
            RelockOutcome::Locked { .. } | RelockOutcome::AlreadyLocked
        )
    }

    /// The outcome for people, naming the volume.
    pub fn text(&self, volume: &str) -> String {
        match self {
            RelockOutcome::Locked { dismounted: false } => format!("{volume} is locked again."),
            RelockOutcome::Locked { dismounted: true } => {
                format!("{volume} is locked again; it was in use, so files open on it were closed.")
            }
            RelockOutcome::AlreadyLocked => format!("{volume} was already locked."),
            RelockOutcome::LeftAlone { why } => format!("{volume} was left as it is: {why}."),
            RelockOutcome::NotLocked { why } => {
                format!("{volume} may still be unlocked: {why}.")
            }
        }
    }
}

/// A volume's state as a relock compares it: locked or not, and which volume it is.
type Held = (bool, VolumeIdentity);

/// Locks a volume while it is still as expected; with whether it had to dismount it.
type LockIf = fn(&str, bool, &Held) -> Result<(crate::restore::Swap<Held>, bool), String>;

/// How a relock reads a volume and locks it while it is still as expected: Windows' own,
/// or a test's.
#[derive(Clone, Copy)]
struct Volumes {
    read: fn(&str) -> Result<VolumeState, String>,
    lock_if: LockIf,
}

const WINDOWS_VOLUMES: Volumes = Volumes {
    read: volume_state,
    lock_if: lock_if_still,
};

/// Locks a volume only while it is still `expect` (unlocked, the same volume): its state
/// is read and the lock sent on one WMI connection, one call after the other, through
/// `changing`.
///
/// Residual: Windows has no lock-if-unlocked for a BitLocker volume, so the read and the
/// lock are two calls. The window between them is one call long; a volume locked and
/// unlocked again by someone else in it would be locked again. No other volume can be
/// locked: the lock names the volume by its GUID, read in the same job.
fn lock_if_still(
    device_id: &str,
    force: bool,
    expect: &Held,
) -> Result<(crate::restore::Swap<Held>, bool), String> {
    let extents = crate::tools::drives::device::volume_extents(device_id)?;
    let device = device_id.to_string();
    let late_device = device.clone();
    let expect = expect.clone();
    changing(
        &format!("locking {device_id} again"),
        Duration::ZERO,
        None,
        move |wmi| {
            let volume = wmi.volume(&device)?;
            let lock = wmi.call(&volume, "GetLockStatus", None)?;
            let locked = match get_u32(&lock, "LockStatus") {
                Some(0) => false,
                Some(1) => true,
                _ => return Err("Windows did not say whether it is locked".into()),
            };
            let mut key_ids: Vec<String> = key_ids_with(wmi, &volume)?
                .iter()
                .map(|id| id.to_ascii_uppercase())
                .collect();
            key_ids.sort();
            let now = (
                locked,
                VolumeIdentity {
                    device_id: normal_device(&device).to_ascii_uppercase(),
                    extents,
                    key_ids,
                },
            );
            if now != expect {
                return Ok((crate::restore::Swap::Changed(now), false));
            }
            lock_on(wmi, &volume, force).map(|dismounted| (crate::restore::Swap::Done, dismounted))
        },
        move |late| {
            crate::handles::record_unseen(
                "Lock a BitLocker drive",
                &match late {
                    Ok((crate::restore::Swap::Done, _)) => {
                        format!("{late_device} was locked after its time limit.")
                    }
                    Ok((crate::restore::Swap::Changed(_), _)) => format!(
                        "{late_device} was left as it is: it had changed since this program unlocked it."
                    ),
                    Err(why) => format!(
                        "{late_device} may still be unlocked: a lock that ran past its time limit ended with: {why}"
                    ),
                },
            );
        },
    )
}

/// The volume as a relock compares it: locked or not, and which volume it is. A state
/// Windows does not give cannot be compared, so it is read as unknown.
struct VolumePlace {
    device_id: String,
    volumes: Volumes,
    force: bool,
    dismounted: bool,
}

impl crate::restore::Place for VolumePlace {
    type Value = Held;
    fn read(&mut self) -> Result<Held, String> {
        let state = (self.volumes.read)(&self.device_id)?;
        let locked = state
            .locked
            .ok_or("Windows did not say whether it is locked")?;
        Ok((locked, state.identity))
    }
    /// Residual: see `lock_if_still`; Windows has no lock-if-unlocked.
    fn swap(&mut self, expect: &Held, value: &Held) -> Result<crate::restore::Swap<Held>, String> {
        if !value.0 || value.1 != expect.1 {
            return Err("a volume is never unlocked by locking it again".into());
        }
        let (swap, dismounted) = (self.volumes.lock_if)(&self.device_id, self.force, expect)?;
        self.dismounted = dismounted;
        Ok(swap)
    }
}

/// A volume this program unlocked, and what locks it again: `relock` locks it only while
/// it is still unlocked and still the same volume (its device, place on disk and recovery
/// key IDs), through the program's compare-and-swap (`crate::restore`). Dropped without
/// `relock`, as when an unlock's result reaches a window that closed while it ran, it
/// locks the volume the same way without dismounting it, and enters any outcome but locked
/// in the session's change record.
pub struct Relock {
    device_id: Option<String>,
    identity: VolumeIdentity,
    volumes: Volumes,
    /// Counted while the volume is still to be locked again, so the process's end waits for
    /// it and the next start locks it again if the end comes first.
    duty: Option<super::timed::Duty>,
}

impl Relock {
    fn with(device_id: String, identity: VolumeIdentity, volumes: Volumes) -> Self {
        let duty = super::timed::DUTIES.holder(
            &format!("locking {device_id} again"),
            RELOCK_UNDO,
            super::pending::Pending::Relock {
                device_id: device_id.clone(),
                identity: identity.clone(),
            },
        );
        Self {
            device_id: Some(device_id),
            identity,
            volumes,
            duty: Some(duty),
        }
    }

    /// Leaves the volume unlocked on purpose: nothing locks it again.
    pub fn keep_unlocked(mut self) {
        self.device_id = None;
        self.duty = None;
    }

    /// The volume it locks again.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Locks the volume again if it is still unlocked and still the volume this program
    /// unlocked. `force` allows dismounting it when it is in use. A volume that could not
    /// be locked stays held, so a later `relock`, or the drop, tries again.
    pub fn relock(&mut self, force: bool) -> RelockOutcome {
        let Some(device_id) = self.device_id.clone() else {
            return RelockOutcome::AlreadyLocked;
        };
        let mut place = VolumePlace {
            device_id,
            volumes: self.volumes,
            force,
            dismounted: false,
        };
        let wrote = (false, self.identity.clone());
        let before = (true, self.identity.clone());
        let outcome = match crate::restore::put_back_if_still(&mut place, &wrote, &before) {
            crate::restore::PutBack::PutBack => RelockOutcome::Locked {
                dismounted: place.dismounted,
            },
            crate::restore::PutBack::AlreadyBack => RelockOutcome::AlreadyLocked,
            crate::restore::PutBack::LeftChanged { now } if now.1 != self.identity => {
                RelockOutcome::LeftAlone {
                    why: "it is no longer the volume this program unlocked".into(),
                }
            }
            crate::restore::PutBack::LeftChanged { .. } => RelockOutcome::LeftAlone {
                why: "it was locked and unlocked again since".into(),
            },
            crate::restore::PutBack::Unknown { why } | crate::restore::PutBack::Failed { why } => {
                RelockOutcome::NotLocked { why }
            }
        };
        if !matches!(outcome, RelockOutcome::NotLocked { .. }) {
            self.device_id = None;
            self.duty = None;
        }
        outcome
    }
}

/// Relock outcomes from a drop that could not be entered in the change record, for a
/// window to show (`unsaid_relocks`).
static UNSAID: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Outcomes of relocks run on a drop that are not "locked" and could not be entered in the
/// session's change record, emptied as they are read.
pub fn unsaid_relocks() -> Vec<String> {
    std::mem::take(
        &mut *UNSAID
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

impl Drop for Relock {
    fn drop(&mut self) {
        let Some(device_id) = self.device_id.clone() else {
            return;
        };
        let outcome = self.relock(false);
        if outcome.locked() {
            return;
        }
        // Still unlocked: the next start locks it again.
        if matches!(outcome, RelockOutcome::NotLocked { .. }) {
            if let Some(duty) = self.duty.take() {
                duty.leave();
            }
        }
        let line = outcome.text(&device_id);
        if crate::change_record::append(
            "A BitLocker volume this program unlocked was not locked again",
            std::slice::from_ref(&line),
        )
        .is_err()
        {
            UNSAID
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }
    }
}

impl std::fmt::Debug for Relock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relock")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// `unlock`, for a holder that locks what it unlocked when it is done: when this unlock is
/// what unlocked the volume, the result comes with a `Relock`; a volume that was unlocked
/// already comes with none, and is left as it was.
pub fn unlock_held(
    options: UnlockOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<(UnlockResult, Option<Relock>), String> {
    unlock_noting(options, events, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The volumes the relock tests see: device id, lock state, identity.
    static VOLUMES: std::sync::Mutex<Vec<(String, Option<bool>, VolumeIdentity)>> =
        std::sync::Mutex::new(Vec::new());
    static LOCKED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    fn fake_read(device_id: &str) -> Result<VolumeState, String> {
        let volumes = VOLUMES.lock().unwrap();
        let (_, locked, identity) = volumes
            .iter()
            .find(|(d, _, _)| d == device_id)
            .ok_or("no such volume")?;
        Ok(VolumeState {
            locked: *locked,
            identity: identity.clone(),
        })
    }

    fn fake_lock(
        device_id: &str,
        _force: bool,
        expect: &Held,
    ) -> Result<(crate::restore::Swap<Held>, bool), String> {
        let mut volumes = VOLUMES.lock().unwrap();
        let v = volumes
            .iter_mut()
            .find(|(d, _, _)| d == device_id)
            .ok_or("no such volume")?;
        let now = (
            v.1.ok_or("Windows did not say whether it is locked")?,
            v.2.clone(),
        );
        if now != *expect {
            return Ok((crate::restore::Swap::Changed(now), false));
        }
        LOCKED.lock().unwrap().push(device_id.to_string());
        v.1 = Some(true);
        Ok((crate::restore::Swap::Done, false))
    }

    const FAKE: Volumes = Volumes {
        read: fake_read,
        lock_if: fake_lock,
    };

    fn identity(device_id: &str, key: &str) -> VolumeIdentity {
        VolumeIdentity {
            device_id: device_id.to_ascii_uppercase(),
            extents: vec![(7, 1 << 20, 1 << 30)],
            key_ids: vec![key.into()],
        }
    }

    /// An unlocked volume this program unlocked, and its `Relock`.
    fn unlocked(device_id: &str) -> Relock {
        let id = identity(device_id, "{A}");
        VOLUMES
            .lock()
            .unwrap()
            .push((device_id.into(), Some(false), id.clone()));
        Relock::with(device_id.into(), id, FAKE)
    }

    fn set(device_id: &str, locked: Option<bool>, key: &str) {
        let mut volumes = VOLUMES.lock().unwrap();
        let v = volumes.iter_mut().find(|(d, _, _)| d == device_id).unwrap();
        v.1 = locked;
        v.2 = identity(device_id, key);
    }

    fn locks(device_id: &str) -> usize {
        LOCKED
            .lock()
            .unwrap()
            .iter()
            .filter(|d| *d == device_id)
            .count()
    }

    /// The guard: an unlock's result carries what locks the volume again, so a result
    /// sent to a window that closed while the unlock ran, or left unread in its channel,
    /// still locks the volume. A relock locks only a volume still unlocked and still the
    /// one this program unlocked, says every other outcome, and tries again later when the
    /// lock state could not be read. An unlock of a volume already unlocked makes no relock.
    #[test]
    fn an_unlock_nobody_takes_in_is_locked_again() {
        let (sender, receiver) = std::sync::mpsc::channel::<Relock>();
        drop(receiver);
        assert!(sender.send(unlocked("late")).is_err());
        let (sender, receiver) = std::sync::mpsc::channel::<Relock>();
        sender.send(unlocked("unread")).unwrap();
        drop(receiver);
        assert_eq!((locks("late"), locks("unread")), (1, 1));

        let mut mine = unlocked("mine");
        assert_eq!(
            mine.relock(true),
            RelockOutcome::Locked { dismounted: false }
        );
        drop(mine);
        assert_eq!(locks("mine"), 1, "locked once, not again on drop");

        let mut locked_since = unlocked("locked since");
        set("locked since", Some(true), "{A}");
        assert_eq!(locked_since.relock(true), RelockOutcome::AlreadyLocked);
        assert_eq!(locks("locked since"), 0);

        let mut another = unlocked("another");
        set("another", Some(false), "{B}");
        assert!(matches!(
            another.relock(true),
            RelockOutcome::LeftAlone { .. }
        ));
        drop(another);
        assert_eq!(locks("another"), 0, "a different volume is never locked");

        let mut unknown = unlocked("unknown");
        set("unknown", None, "{A}");
        assert!(matches!(
            unknown.relock(true),
            RelockOutcome::NotLocked { .. }
        ));
        assert_eq!(locks("unknown"), 0);
        set("unknown", Some(false), "{A}");
        assert_eq!(
            unknown.relock(true),
            RelockOutcome::Locked { dismounted: false }
        );
        assert_eq!(locks("unknown"), 1);

        // The window unlocks only through `unlock_held`, keeps each `Relock` it gets and
        // locks through it; an unlock that found the volume unlocked hands none.
        let window = include_str!("../gui/bitlocker_view.rs");
        let window = window.split("#[cfg(test)]").next().unwrap();
        assert!(
            !window.contains("bitlocker::unlock("),
            "an unlock without its relock"
        );
        assert!(window.contains("bitlocker::unlock_held("));
        assert!(window.contains("self.held.push(relock);"));
        assert!(
            !window.contains("lock_volume("),
            "a lock that skips the relock's check"
        );
        let code = include_str!("bitlocker.rs");
        let code = code.split("#[cfg(test)]").next().unwrap();
        // The relock comes from the unlock itself, and only when it unlocked the volume.
        assert!(code.contains("Ok((result, relock))"));
        assert!(code.contains("let relock = if already_unlocked {"));
        let drop_code = &code[code.find("impl Drop for Relock").unwrap()..];
        let drop_code = &drop_code[..drop_code.find("\n}\n").unwrap()];
        assert!(
            drop_code.contains("self.relock(false)"),
            "a drop that dismounts unsaid"
        );
    }

    /// The guard: the unlock overwrites the key WMI copied into its in-parameters object
    /// with as many zeros and releases the object as soon as the call returns, before its
    /// answer is looked at, so no early return keeps it.
    #[test]
    fn the_key_in_wmis_object_is_overwritten_and_released_at_once() {
        let code = include_str!("bitlocker.rs");
        let code = &code[..code.find("#[cfg(test)]").unwrap()];
        let unlock = &code[code.find("fn unlock_parsed(").unwrap()..];
        let unlock = &unlock[..unlock.find("\n}\n").unwrap()];
        let call = unlock
            .find("\"UnlockWithNumericalPassword\", Some(&input)")
            .unwrap();
        let release = unlock.find("release_key_input(input, len);").unwrap();
        let answer = unlock.find("out?").unwrap();
        assert!(call < release && release < answer, "{unlock}");
        assert_eq!(
            unlock.matches("input").count(),
            5,
            "the input is used elsewhere"
        );
        let scrub = &code[code.find("fn release_key_input(").unwrap()..];
        let scrub = &scrub[..scrub.find("\n}\n").unwrap()];
        assert!(scrub.contains("repeat_n(u16::from(b'0'), len)"));
        assert!(scrub.contains("put(&input, \"NumericalPassword\""));
        assert!(scrub.trim_end().ends_with("drop(input);"));
        let input = &code[code.find("fn key_input(").unwrap()..];
        let input = &input[..input.find("\n}\n").unwrap()];
        assert!(input.contains("drop(key);") && input.contains("zero_u16("));
    }

    /// The guard: no instruction tells the technician to copy a key to the clipboard, and a
    /// key pasted into the key box leaves the clipboard empty once the box holds it, only
    /// when the clipboard still holds that same text.
    #[test]
    fn a_key_is_typed_and_a_pasted_one_leaves_the_clipboard() {
        for (name, code) in [
            ("keylookup.rs", include_str!("keylookup.rs")),
            (
                "bitlocker_view.rs",
                include_str!("../gui/bitlocker_view.rs"),
            ),
        ] {
            let code = &code[..code.find("#[cfg(test)]").unwrap_or(code.len())];
            for told in ["Ctrl+C", "paste it", "copy the key", "clipboard and"] {
                assert!(!code.contains(told), "{name} says {told}");
            }
        }
        let lookup = include_str!("keylookup.rs");
        assert!(lookup.contains("type its 48 digits into the"));
        let w = |t: &str| t.encode_utf16().chain([0]).collect::<Vec<u16>>();
        assert!(same_text(&w(KEY), &w(KEY)));
        assert!(same_text(
            &w(&format!("{KEY}\r\n")),
            &w(&format!("  {KEY}"))
        ));
        assert!(!same_text(&w("something else"), &w(KEY)));
        assert!(!same_text(&w(""), &w("")));
        assert!(!same_text(&w(&KEY[..20]), &w(KEY)));
        let view = include_str!("../gui/bitlocker_view.rs");
        assert!(view.contains("KEY if u32::from(code) == EN_CHANGE => self.key_changed(hwnd),"));
        let changed = &view[view.find("fn key_changed(").unwrap()..];
        let changed = &changed[..changed.find("\n    }\n").unwrap()];
        assert!(changed.contains("let field = read_key_box(c.key);"));
        assert!(changed.contains("bitlocker::clear_clipboard_if_holding(hwnd as isize, &field.0);"));
        let clear = &s_code()[s_code().find("pub fn clear_clipboard_if_holding(").unwrap()..];
        let clear = &clear[..clear.find("\n}\n").unwrap()];
        assert!(clear.contains("let copy = WideSecret("));
        assert!(clear.contains("if same_text(&copy.0, field) {"));
    }

    /// The mark crash dump set up reads is there once a key may be held.
    #[test]
    fn the_key_mark_is_seen_once_made() {
        mark_key_held();
        assert!(key_held());
    }

    fn s_code() -> &'static str {
        let code = include_str!("bitlocker.rs");
        &code[..code.find("#[cfg(test)]").unwrap()]
    }

    /// A valid-looking key: every group a multiple of 11.
    const KEY: &str = "111111-222222-333333-444444-555555-666666-700007-000000";

    #[test]
    fn the_signature_is_found_at_byte_three() {
        let mut boot = vec![0u8; 512];
        boot[3..11].copy_from_slice(b"-FVE-FS-");
        assert!(is_bitlocker(&boot));
        boot[3..11].copy_from_slice(b"NTFS    ");
        assert!(!is_bitlocker(&boot));
        assert!(!is_bitlocker(&[0u8; 4]));
    }

    #[test]
    fn a_recovery_key_is_checked_before_windows_is_asked() {
        let key = RecoveryKey::parse(KEY).unwrap();
        assert_eq!(
            String::from_utf16_lossy(&key.text[..key.text.len() - 1]),
            KEY
        );
        // Without dashes, or with spaces, it reads the same.
        let bare = RecoveryKey::parse(&KEY.replace('-', "")).unwrap();
        assert_eq!(bare.text, key.text);
        assert!(RecoveryKey::parse(&KEY.replace('-', " ")).is_ok());
        // One wrong digit makes its group fail the multiple-of-11 check.
        let typo = KEY.replacen("333333", "333334", 1);
        let err = RecoveryKey::parse(&typo).err().unwrap();
        assert!(err.starts_with("Group 3 "), "{err}");
        assert!(!err.contains("333334"), "the digits are never repeated");
        assert!(RecoveryKey::parse(&KEY[..50]).is_err());
        assert!(RecoveryKey::parse(&format!("{KEY}-1")).is_err());
        assert!(RecoveryKey::parse(&KEY.replacen('1', "a", 1)).is_err());
        // A group at or above 65536 x 11 is not a key BitLocker makes.
        let high = KEY.replacen("700007", "720896", 1);
        assert!(RecoveryKey::parse(&high).is_err());
    }

    /// The guard: the single unlock path empties the text it was given, whether the key is
    /// accepted or refused, and a parsed key is zeroed when dropped.
    #[test]
    fn the_typed_key_is_wiped_on_every_path() {
        let mut typed = KEY.replacen("333333", "333334", 1);
        let nowhere = VolumeIdentity {
            device_id: r"\\?\VOLUME{NONE}".into(),
            extents: Vec::new(),
            key_ids: Vec::new(),
        };
        assert!(unlock_with_key_text(r"\\?\Volume{none}\", &mut typed, nowhere, None).is_err());
        assert!(typed.is_empty());
        let mut text = vec![u16::from(b'7'); 8];
        zero_u16(&mut text);
        assert!(text.iter().all(|c| *c == 0));
        let mut s = String::from("123456");
        zero_string(&mut s);
        assert!(s.is_empty());
    }

    /// The guard: a key in options never shows in Debug or serde output.
    #[test]
    fn a_key_in_options_is_never_shown() {
        let options: UnlockOptions = serde_json::from_str(&format!(
            r#"{{"device_id":"\\\\?\\Volume{{x}}\\","recovery_key":"{KEY}"}}"#
        ))
        .unwrap();
        assert_eq!(options.recovery_key.text, KEY);
        assert!(!format!("{options:?}").contains("111111"));
        let json = serde_json::to_string(&options).unwrap();
        assert!(!json.contains("111111"), "{json}");
        assert!(json.contains("withheld"));
        assert!(!options.unlock_source_drive);
    }

    #[test]
    fn key_ids_are_shortened_as_windows_shows_them() {
        assert_eq!(
            short_id("{1a2b3c4d-0000-1111-2222-333344445555}"),
            "1A2B3C4D"
        );
        assert_eq!(short_id("1A2B3C4D-0000"), "1A2B3C4D");
    }

    fn com_is_up() -> bool {
        use windows_sys::Win32::System::Com::CoGetApartmentType;
        let (mut kind, mut qualifier) = (0, 0);
        // SAFETY: two out-parameters on this thread.
        unsafe { CoGetApartmentType(&mut kind, &mut qualifier) >= 0 }
    }

    /// A WMI object released after its connection (an edition 2021 tail temporary) once
    /// crashed the unlock: COM was left when the connection dropped. COM now stays up for
    /// the thread's life.
    #[test]
    fn com_stays_up_after_a_connection_is_dropped() {
        std::thread::spawn(|| {
            assert!(!com_is_up());
            for _ in 0..2 {
                // One connection's lifetime.
                let _apartment = Apartment::enter().unwrap();
            }
            assert!(com_is_up());
        })
        .join()
        .unwrap();
    }

    /// A window's thread is already in a single-threaded apartment; locking on close runs
    /// there and must still reach WMI.
    #[test]
    fn a_window_thread_in_its_own_apartment_is_used_as_it_is() {
        std::thread::spawn(|| {
            use windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED;
            // SAFETY: this test thread enters a single-threaded apartment and leaves it.
            unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) };
            assert!(Apartment::enter().is_ok());
            // SAFETY: balances the CoInitializeEx above.
            unsafe { CoUninitialize() };
        })
        .join()
        .unwrap();
    }

    #[test]
    fn return_codes_read_plainly() {
        assert!(code_text(0x8031_0027).contains("does not unlock"));
        assert!(code_text(0x1234).contains("0x00001234"));
    }

    /// Needs administrator rights and a disk or image with a BitLocker volume on it:
    /// DIAGTOOL_BITLOCKER_IMAGE is a raw image to attach read-only (or DIAGTOOL_BITLOCKER_DISK
    /// a disk number), and DIAGTOOL_BITLOCKER_KEY its throwaway test key, never printed.
    /// Drives the engine: scan, the source-drive refusal, a wrong key, the right key, a
    /// decrypted read through `SourceChoice::Volume`, and lock again.
    #[test]
    #[ignore]
    fn live_bitlocker_scan_unlock_read_and_lock() {
        let cancel = AtomicBool::new(false);
        let events = |e: Event| println!("  event {e:?}");
        let attached = std::env::var("DIAGTOOL_BITLOCKER_IMAGE").ok().map(|image| {
            let options = vdisk::AttachOptions {
                image: image.into(),
                make_plain: false,
            };
            let (attached, result) = vdisk::attach_image(&options, &events, &cancel).unwrap();
            println!(
                "attached as disk {}, letters {:?}, BitLocker at {:?}",
                result.disk, result.letters, result.bitlocker
            );
            assert!(!result.bitlocker.is_empty());
            (attached, result.image_len)
        });
        let disk = match &attached {
            Some((a, _)) => a.disk,
            None => std::env::var("DIAGTOOL_BITLOCKER_DISK")
                .unwrap()
                .parse()
                .unwrap(),
        };
        let found = scan(&ScanOptions { disk }, &events, &cancel).unwrap();
        for f in &found.volumes {
            println!(
                "found {} locked {:?} Recovery key ID: {:?} (full ID {} characters)",
                f.device_id,
                f.locked,
                f.key_ids_short,
                f.key_ids.first().map_or(0, String::len)
            );
        }
        let f = found.volumes.first().expect("a BitLocker volume").clone();
        assert_eq!(f.locked, Some(true));
        assert!(f.key_ids_short.iter().all(|id| id.len() == 8));
        assert_eq!(recovery_key_ids(&f.device_id).unwrap(), f.key_ids);
        let options = |key: String, source_disk, confirmed| UnlockOptions {
            device_id: f.device_id.clone(),
            recovery_key: KeyText::new(key),
            source_disk,
            unlock_source_drive: confirmed,
        };
        let key = std::env::var("DIAGTOOL_BITLOCKER_KEY").unwrap();
        println!("test key: {} characters", key.len());
        // A volume on the drive being recovered is refused without the confirmation.
        let refused = unlock(options(key.clone(), Some(disk), false), &events, &cancel);
        println!("source drive, not confirmed: {:?}", refused.as_ref().err());
        assert!(refused.is_err());
        let wrong = unlock(options(KEY.into(), None, false), &events, &cancel);
        println!("a wrong key: {:?}", wrong.as_ref().err());
        assert!(wrong.is_err());
        let (done, relock) =
            unlock_held(options(key.clone(), None, false), &events, &cancel).unwrap();
        println!(
            "unlocked: disk {} letter {:?} source {:?} already unlocked {}",
            done.disk, done.letter, done.source, done.already_unlocked
        );
        assert!(!done.already_unlocked);
        let mut relock = relock.expect("a volume this program unlocked carries a relock");
        let mut source = super::super::open_source(&done.source).unwrap();
        let mut boot = vec![0u8; 512];
        source.read_at(0, &mut boot).unwrap();
        println!(
            "first sector of the decrypted volume: {:?}",
            String::from_utf8_lossy(&boot[3..11])
        );
        assert_eq!(&boot[3..11], b"NTFS    ");
        drop(source);
        // A second unlock finds it already unlocked: no key is used and no relock is made,
        // so closing that one leaves the volume as it was.
        let (again, none) = unlock_held(options(key, None, false), &events, &cancel).unwrap();
        println!(
            "unlocked again: already unlocked {}, relock made {}",
            again.already_unlocked,
            none.is_some()
        );
        assert!(again.already_unlocked && none.is_none());
        assert_eq!(volume_state(&f.device_id).unwrap().locked, Some(false));
        let outcome = relock.relock(false);
        println!("relock: {}", outcome.text(&f.device_id));
        assert!(outcome.locked());
        assert_eq!(volume_state(&f.device_id).unwrap().locked, Some(true));
        let locked = lock_volume(
            &LockOptions {
                device_id: f.device_id.clone(),
            },
            &events,
            &cancel,
        )
        .unwrap();
        println!("lock on a locked volume: {:?}", locked.locked);
        assert_eq!(locked.locked, Some(true));
        if let Some((attached, image_len)) = attached {
            let image = attached.image().to_path_buf();
            attached.close().unwrap();
            assert_eq!(std::fs::metadata(image).unwrap().len(), image_len);
            println!("detached, image back to {image_len} bytes");
        }
    }

    /// How many places in this process's memory hold `pattern` (kept XORed with 0x5A5A so
    /// the pattern itself is not found), as UTF-16 and as ASCII. The scan reads through a
    /// buffer outside the heap, skipped and zeroed after each piece.
    fn copies_in_memory(pattern: &[u16]) -> (usize, usize) {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
            MEM_RELEASE, MEM_RESERVE, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        const PIECE: usize = 1 << 20;
        let real = |i: usize| pattern[i] ^ 0x5A5A;
        let n = pattern.len();
        // SAFETY: a fresh read-write allocation of PIECE bytes, released below.
        let buffer =
            unsafe { VirtualAlloc(null(), PIECE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }
                as *mut u8;
        assert!(!buffer.is_null());
        let (mut wide, mut ascii) = (0, 0);
        let mut at = 0usize;
        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: queries this process's address space.
            let got = unsafe {
                VirtualQuery(
                    at as *const c_void,
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if got == 0 {
                break;
            }
            let base = info.BaseAddress as usize;
            let size = info.RegionSize;
            let readable = info.State == MEM_COMMIT
                && info.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
                && info.Protect != 0
                && base != buffer as usize;
            let mut off = 0;
            while readable && off < size {
                let take = PIECE.min(size - off);
                let mut read = 0usize;
                // SAFETY: reads this process's own memory into the scan buffer.
                let ok = unsafe {
                    ReadProcessMemory(
                        GetCurrentProcess(),
                        (base + off) as *const c_void,
                        buffer.cast(),
                        take,
                        &mut read,
                    )
                };
                if ok != 0 {
                    // SAFETY: `read` bytes were written to the buffer.
                    let bytes = unsafe { std::slice::from_raw_parts_mut(buffer, read) };
                    for start in 0..read.saturating_sub(2 * n) {
                        if (0..n).all(|i| {
                            u16::from_le_bytes([bytes[start + 2 * i], bytes[start + 2 * i + 1]])
                                == real(i)
                        }) {
                            wide += 1;
                        }
                        if (0..n).all(|i| u16::from(bytes[start + i]) == real(i)) {
                            ascii += 1;
                        }
                    }
                    bytes.fill(0);
                }
                off += take;
            }
            at = base + size;
        }
        // SAFETY: releases the allocation made above.
        unsafe { VirtualFree(buffer.cast(), 0, MEM_RELEASE) };
        (wide, ascii)
    }

    /// Needs administrator rights (the BitLocker WMI namespace) and no BitLocker volume:
    /// nothing is unlocked. Puts a made-up recovery key into WMI's in-parameters object
    /// the way an unlock does, and counts the places this process's memory holds the key
    /// while the parsed key is held, after `key_input` (this program's copies zeroed, WMI's
    /// copy in the object), and after `release_key_input`.
    #[test]
    #[ignore]
    fn live_wmi_key_copies() {
        for overwrite in [true, false] {
            println!("overwrite before release: {overwrite}");
            wmi_key_copies(overwrite);
        }
    }

    fn wmi_key_copies(overwrite: bool) {
        let mut typed: String = (0..8)
            .map(|_| format!("{:06}", rand::random::<u32>() % 65_536 * 11))
            .collect::<Vec<_>>()
            .join("-");
        let key = RecoveryKey::parse(&typed).unwrap();
        zero_string(&mut typed);
        let pattern: Vec<u16> = key.text[..key.text.len() - 1]
            .iter()
            .map(|c| c ^ 0x5A5A)
            .collect();
        let len = key.text.len() - 1;
        println!("parsed key held: {:?}", copies_in_memory(&pattern));
        let wmi = Wmi::connect().unwrap();
        let input = key_input(&wmi, key).unwrap();
        println!(
            "after key_input (WMI's object holds it): {:?}",
            copies_in_memory(&pattern)
        );
        if overwrite {
            release_key_input(input, len);
        } else {
            drop(input);
        }
        println!(
            "after the object's release: {:?}",
            copies_in_memory(&pattern)
        );
        drop(wmi);
        println!(
            "after the connection is released: {:?}",
            copies_in_memory(&pattern)
        );
    }

    /// The guard: the key types' memory holds only zeros when it is freed: a key typed or
    /// copied in, one read from serialized options (escaped text too), a parsed key, and a
    /// key box's text.
    #[test]
    fn key_text_holds_only_zeros_when_freed() {
        use crate::recovery::keylookup::tests::zero_watch::freed_zeroed;
        let copied = KeyText::copy_of(KEY);
        let at = copied.text.as_ptr();
        assert!(freed_zeroed(at, || drop(copied)));
        let wide: Vec<u16> = KEY.encode_utf16().collect();
        let typed = KeyText::from_wide(&wide);
        assert_eq!(typed.text, KEY);
        let at = typed.text.as_ptr();
        assert!(freed_zeroed(at, || drop(typed)));
        let plain = serde_json::from_str::<KeyText>(&format!("\"{KEY}\"")).unwrap();
        assert_eq!(plain.text, KEY);
        let at = plain.text.as_ptr();
        assert!(freed_zeroed(at, || drop(plain)));
        let escaped = serde_json::from_str::<KeyText>(&format!("\"{KEY}\\u0020\"")).unwrap();
        assert_eq!(escaped.text.trim_end(), KEY);
        let at = escaped.text.as_ptr();
        assert!(freed_zeroed(at, || drop(escaped)));
        let parsed = RecoveryKey::parse(KEY).unwrap();
        let at = parsed.text.as_ptr().cast::<u8>();
        assert!(freed_zeroed(at, || drop(parsed)));
        let field = WideSecret(wide);
        let at = field.0.as_ptr().cast::<u8>();
        assert!(freed_zeroed(at, || drop(field)));
    }

    /// The guard: a lock asked of a volume already locked reads its state first and is not
    /// an error (measured: Windows' Lock answers "The drive is locked.").
    #[test]
    fn a_lock_of_a_locked_volume_reads_its_state_first() {
        let code = include_str!("bitlocker.rs");
        let code = code.split("#[cfg(test)]").next().unwrap();
        let body = &code[code.find("pub fn lock_volume(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let read =
            body.find("status_within(&options.device_id, Some(cancel))?.locked == Some(true)");
        let write = body.find("lock_within(&options.device_id, true, Some(cancel))");
        assert!(
            matches!((read, write), (Some(r), Some(w)) if r < w),
            "{body}"
        );
    }

    /// The guard: a mark that could not be made reads as held, so crash dump set up still
    /// refuses full application dumps in this process.
    #[test]
    fn a_mark_that_could_not_be_made_reads_as_held() {
        MARK_FAILED.store(true, Ordering::SeqCst);
        assert!(key_held());
    }
}
