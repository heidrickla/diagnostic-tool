//! A minimal binding to the Microsoft Edge WebView2 runtime, enough for the sign-in window:
//! an environment with its own data folder, one controller and its web view, the settings
//! that close the browser's side doors, the navigation, new-window, download, permission and
//! process events, and running one script.
//!
//! Hand-written instead of the `webview2-com` crate: that crate imports the loader from
//! `WebView2Loader.dll` (raw-dylib), which would have to ship beside the exe and be loaded
//! from its folder, against the one-exe build and /DEPENDENTLOADFLAG:0x800; it also brings
//! the `windows` crate. Only the interface methods used are declared, by their vtable slot.
//! The slot numbers and interface IDs are from Microsoft's WebView2 SDK headers (WebView2.h,
//! as generated into webview2-com-sys 0.39.1's bindings).
//!
//! The loader does what Microsoft's WebView2Loader does for the installed runtime: read the
//! runtime folder from the `EBWebView` value under EdgeUpdate\ClientState\{stable runtime},
//! load `EBWebView\<arch>\EmbeddedBrowserWebView.dll` from it and call its
//! `CreateWebViewEnvironmentWithOptionsInternal`. It accepts only a DLL with a valid
//! Microsoft signature, and ignores the WEBVIEW2_* environment variables and the loader
//! override policies, so nothing but the installed runtime can be loaded this way.
//!
//! Everything here runs on the window's thread, which is a COM single-threaded apartment
//! with a message loop; handlers are called from that loop.
use std::cell::RefCell;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut, NonNull};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY,
};

use super::{decode_script_string, scrub_wide, ScrubbedText};

pub type HRESULT = i32;
const S_OK: HRESULT = 0;
const E_NOINTERFACE: HRESULT = 0x8000_4002_u32 as i32;
const E_POINTER: HRESULT = 0x8000_4003_u32 as i32;
const E_FAIL: HRESULT = 0x8000_4005_u32 as i32;

/// What the technician reads when the runtime is not there.
pub const MISSING: &str = "This PC does not have the Microsoft Edge WebView2 Runtime, which \
the sign-in window needs. Type the recovery key in instead; the customer can see it at \
aka.ms/myrecoverykey on another device.";

const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_c000_000000000046);
const IID_ENVIRONMENT_COMPLETED: GUID = GUID::from_u128(0x4e8a3389_c9d8_4bd2_b6b5_124fee6cc14d);
const IID_CONTROLLER_COMPLETED: GUID = GUID::from_u128(0x6c4819f3_c9b7_4260_8127_c9f5bde7f68c);
const IID_NAVIGATION_STARTING: GUID = GUID::from_u128(0x9adbe429_f36d_432b_9ddc_f8881fbd76e3);
const IID_NAVIGATION_COMPLETED: GUID = GUID::from_u128(0xd33a35bf_1c49_4f98_93ab_006e0533fe1c);
const IID_NEW_WINDOW_REQUESTED: GUID = GUID::from_u128(0xd4c185fe_c81c_4989_97af_2d3fa7ab5651);
const IID_EXECUTE_SCRIPT_COMPLETED: GUID = GUID::from_u128(0x49511172_cc67_4bca_9923_137112f4c4cc);
const IID_DOWNLOAD_STARTING: GUID = GUID::from_u128(0xefedc989_c396_41ca_83f7_07f845a55724);
const IID_PERMISSION_REQUESTED: GUID = GUID::from_u128(0x15e1c6a3_c72a_4df3_91d7_d097fbec6bfd);
const IID_PROCESS_FAILED: GUID = GUID::from_u128(0x79e0aea4_990b_42d9_aa1d_0fcc2e5bc7f1);
const IID_WEBVIEW_4: GUID = GUID::from_u128(0x20d02d59_6df2_42dc_bd06_f98a694b1302);
const IID_SETTINGS_3: GUID = GUID::from_u128(0xfdb5ab74_af33_4854_84f0_0a631deb5eba);
const IID_SETTINGS_4: GUID = GUID::from_u128(0xcb56846c_4168_4d53_b04f_03b6d6796ff2);

/// Vtable slots of the methods used, counted from 0 with IUnknown's three first, in the
/// order WebView2.h declares them.
mod slot {
    pub const QUERY_INTERFACE: usize = 0;
    pub const ADD_REF: usize = 1;
    pub const RELEASE: usize = 2;
    // ICoreWebView2Environment
    pub const CREATE_CONTROLLER: usize = 3;
    // ICoreWebView2Controller
    pub const SET_BOUNDS: usize = 6;
    pub const MOVE_FOCUS: usize = 12;
    pub const NOTIFY_PARENT_MOVED: usize = 23;
    pub const CLOSE: usize = 24;
    pub const CORE_WEBVIEW: usize = 25;
    // ICoreWebView2
    pub const SETTINGS: usize = 3;
    pub const SOURCE: usize = 4;
    pub const NAVIGATE: usize = 5;
    pub const ADD_NAVIGATION_STARTING: usize = 7;
    pub const ADD_NAVIGATION_COMPLETED: usize = 15;
    pub const ADD_FRAME_NAVIGATION_STARTING: usize = 17;
    pub const ADD_PERMISSION_REQUESTED: usize = 23;
    pub const ADD_PROCESS_FAILED: usize = 25;
    pub const EXECUTE_SCRIPT: usize = 29;
    pub const BROWSER_PROCESS_ID: usize = 37;
    pub const ADD_NEW_WINDOW_REQUESTED: usize = 44;
    // ICoreWebView2_4 (after ICoreWebView2's 61 slots, _2's 7 and _3's 5)
    pub const ADD_DOWNLOAD_STARTING: usize = 75;
    // ICoreWebView2Settings, Settings3 and Settings4
    pub const SET_IS_WEB_MESSAGE_ENABLED: usize = 6;
    pub const SET_IS_STATUS_BAR_ENABLED: usize = 10;
    pub const SET_ARE_DEV_TOOLS_ENABLED: usize = 12;
    pub const SET_ARE_DEFAULT_CONTEXT_MENUS_ENABLED: usize = 14;
    pub const SET_ARE_HOST_OBJECTS_ALLOWED: usize = 16;
    pub const SET_ARE_BROWSER_ACCELERATOR_KEYS_ENABLED: usize = 24;
    pub const SET_IS_PASSWORD_AUTOSAVE_ENABLED: usize = 26;
    pub const SET_IS_GENERAL_AUTOFILL_ENABLED: usize = 28;
    // Event arguments
    pub const ARGS_URI: usize = 3;
    pub const NAVIGATION_SET_CANCEL: usize = 8;
    pub const NAVIGATION_COMPLETED_IS_SUCCESS: usize = 3;
    pub const NEW_WINDOW_SET_HANDLED: usize = 6;
    pub const PERMISSION_SET_STATE: usize = 7;
    pub const DOWNLOAD_SET_CANCEL: usize = 5;
}

const PERMISSION_STATE_DENY: i32 = 2;
const MOVE_FOCUS_PROGRAMMATIC: i32 = 0;

type Raw = *mut c_void;
type Call0 = unsafe extern "system" fn(Raw) -> HRESULT;
type PutBool = unsafe extern "system" fn(Raw, i32) -> HRESULT;
type GetPtr = unsafe extern "system" fn(Raw, *mut Raw) -> HRESULT;
type GetText = unsafe extern "system" fn(Raw, *mut *mut u16) -> HRESULT;
type AddEvent = unsafe extern "system" fn(Raw, Raw, *mut i64) -> HRESULT;

// ---------------------------------------------------------------- references

/// One counted reference to a COM object, released when dropped.
pub struct Com(NonNull<c_void>);

impl Com {
    /// Takes over a reference the caller already owns.
    unsafe fn own(raw: Raw) -> Option<Com> {
        NonNull::new(raw).map(Com)
    }

    /// Adds a reference to an object the caller only borrows (an argument of a call).
    unsafe fn borrowed(raw: Raw) -> Option<Com> {
        let com = NonNull::new(raw).map(Com)?;
        let add_ref: unsafe extern "system" fn(Raw) -> u32 = com.slot(slot::ADD_REF);
        add_ref(raw);
        Some(com)
    }

    fn raw(&self) -> Raw {
        self.0.as_ptr()
    }

    /// The method in vtable slot `index`.
    ///
    /// SAFETY: `F` must be the method's real signature and `index` inside the vtable.
    unsafe fn slot<F: Copy>(&self, index: usize) -> F {
        let vtable = *(self.raw() as *const *const usize);
        std::mem::transmute_copy::<usize, F>(&*vtable.add(index))
    }

    fn query(&self, iid: &GUID) -> Option<Com> {
        let mut out: Raw = null_mut();
        // SAFETY: slot 0 of every COM interface is QueryInterface.
        unsafe {
            let query: unsafe extern "system" fn(Raw, *const GUID, *mut Raw) -> HRESULT =
                self.slot(slot::QUERY_INTERFACE);
            if query(self.raw(), iid, &mut out) < 0 {
                return None;
            }
            Com::own(out)
        }
    }

    /// Calls a method taking one BOOL.
    fn put_bool(&self, index: usize, value: bool) -> HRESULT {
        // SAFETY: callers pass the slot of a `put_X(BOOL)` method of this interface.
        unsafe { self.slot::<PutBool>(index)(self.raw(), i32::from(value)) }
    }

    /// Calls a method returning an interface.
    fn get_object(&self, index: usize) -> Option<Com> {
        let mut out: Raw = null_mut();
        // SAFETY: callers pass the slot of a `get_X(IUnknown**)`-shaped method.
        unsafe {
            if self.slot::<GetPtr>(index)(self.raw(), &mut out) < 0 {
                return None;
            }
            Com::own(out)
        }
    }

    /// Calls a method returning a string the callee allocated; frees it.
    fn get_text(&self, index: usize) -> Option<String> {
        let mut out: *mut u16 = null_mut();
        // SAFETY: callers pass the slot of a `get_X(LPWSTR*)` method; the string is freed
        // with CoTaskMemFree as the API says.
        unsafe {
            if self.slot::<GetText>(index)(self.raw(), &mut out) < 0 || out.is_null() {
                return None;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(out, wide_len(out)));
            CoTaskMemFree(out as *const c_void);
            Some(text)
        }
    }

    /// Subscribes `handler` to the event whose `add_X` method is in slot `index`. The
    /// subscription lasts until the controller is closed.
    fn add_event(&self, index: usize, handler: &Com) -> Result<(), HRESULT> {
        let mut token = 0i64;
        // SAFETY: callers pass the slot of an `add_X(handler, token*)` method.
        let hr = unsafe { self.slot::<AddEvent>(index)(self.raw(), handler.raw(), &mut token) };
        if hr < 0 {
            Err(hr)
        } else {
            Ok(())
        }
    }
}

impl Clone for Com {
    fn clone(&self) -> Self {
        // SAFETY: the object is alive while `self` holds its reference.
        unsafe { Com::borrowed(self.raw()) }.expect("a live object is not null")
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: this reference was counted when the Com was made.
        unsafe {
            let release: unsafe extern "system" fn(Raw) -> u32 = self.slot(slot::RELEASE);
            release(self.raw());
        }
    }
}

/// Characters before the terminating nul.
unsafe fn wide_len(text: *const u16) -> usize {
    let mut len = 0;
    while *text.add(len) != 0 {
        len += 1;
    }
    len
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

// ---------------------------------------------------------------- handlers

type Invoke = Box<dyn FnMut(usize, usize) -> HRESULT>;

/// A COM object for any of WebView2's handler interfaces: each has one method after
/// IUnknown's, `Invoke(this, a, b)`, whose two arguments are pointer-sized (an HRESULT
/// arrives in the low 32 bits).
#[repr(C)]
struct Handler {
    vtable: *const HandlerVtable,
    refs: AtomicU32,
    iid: GUID,
    invoke: RefCell<Option<Invoke>>,
}

#[repr(C)]
struct HandlerVtable {
    query: unsafe extern "system" fn(*mut Handler, *const GUID, *mut Raw) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut Handler) -> u32,
    release: unsafe extern "system" fn(*mut Handler) -> u32,
    invoke: unsafe extern "system" fn(*mut Handler, usize, usize) -> HRESULT,
}

static HANDLER_VTABLE: HandlerVtable = HandlerVtable {
    query: handler_query,
    add_ref: handler_add_ref,
    release: handler_release,
    invoke: handler_invoke,
};

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe extern "system" fn handler_query(
    this: *mut Handler,
    iid: *const GUID,
    out: *mut Raw,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if iid.is_null() || !(same_guid(&*iid, &IID_IUNKNOWN) || same_guid(&*iid, &(*this).iid)) {
        *out = null_mut();
        return E_NOINTERFACE;
    }
    handler_add_ref(this);
    *out = this.cast();
    S_OK
}

unsafe extern "system" fn handler_add_ref(this: *mut Handler) -> u32 {
    (*this).refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn handler_release(this: *mut Handler) -> u32 {
    let left = (*this).refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(Box::from_raw(this));
    }
    left
}

unsafe extern "system" fn handler_invoke(this: *mut Handler, a: usize, b: usize) -> HRESULT {
    let handler = &*this;
    // The closure is taken out while it runs, so a nested call of the same handler is
    // skipped rather than re-entering it; a panic is caught here, at the COM boundary.
    let Some(mut call) = handler.invoke.borrow_mut().take() else {
        return S_OK;
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| call(a, b))).unwrap_or(E_FAIL);
    let mut slot = handler.invoke.borrow_mut();
    if slot.is_none() {
        *slot = Some(call);
    }
    result
}

fn handler(iid: GUID, invoke: impl FnMut(usize, usize) -> HRESULT + 'static) -> Com {
    let object = Box::new(Handler {
        vtable: &HANDLER_VTABLE,
        refs: AtomicU32::new(1),
        iid,
        invoke: RefCell::new(Some(Box::new(invoke))),
    });
    // SAFETY: a fresh box is not null; its one reference goes to the Com.
    unsafe { Com::own(Box::into_raw(object).cast()) }.expect("a box is not null")
}

/// A handler that runs `done` on its first call only.
fn once(iid: GUID, done: impl FnOnce(usize, usize) + 'static) -> Com {
    let mut done = Some(done);
    handler(iid, move |a, b| {
        if let Some(done) = done.take() {
            done(a, b);
        }
        S_OK
    })
}

// ---------------------------------------------------------------- finding the runtime

const STABLE_RUNTIME: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x64";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "arm64";
#[cfg(target_arch = "x86")]
const ARCH: &str = "x86";

fn registry_text(hive: HKEY, key: &str, value: &str) -> Option<String> {
    let (key, value) = (wide(key), wide(value));
    let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY;
    let mut size = 0u32;
    // SAFETY: the names are nul-terminated; the first call only measures.
    let status = unsafe {
        RegGetValueW(
            hive,
            key.as_ptr(),
            value.as_ptr(),
            flags,
            null_mut(),
            null_mut(),
            &mut size,
        )
    };
    if status != 0 || size < 2 {
        return None;
    }
    let mut buffer = vec![0u16; size as usize / 2];
    // SAFETY: `buffer` holds `size` bytes.
    let status = unsafe {
        RegGetValueW(
            hive,
            key.as_ptr(),
            value.as_ptr(),
            flags,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// The installed WebView2 runtime's client DLL, from the machine-wide install first and then
/// the per-user one. Err with `MISSING` when there is none.
pub fn runtime_dll() -> Result<PathBuf, String> {
    let key = format!("Software\\Microsoft\\EdgeUpdate\\ClientState\\{STABLE_RUNTIME}");
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let Some(folder) = registry_text(hive, &key, "EBWebView") else {
            continue;
        };
        let dll = PathBuf::from(folder)
            .join("EBWebView")
            .join(ARCH)
            .join("EmbeddedBrowserWebView.dll");
        if dll.is_absolute() && dll.is_file() {
            return Ok(dll);
        }
    }
    Err(MISSING.to_string())
}

/// Whether `path` carries a valid Authenticode signature from Microsoft.
fn signed_by_microsoft(path: &Path) -> bool {
    let check = crate::tools::hash::sys::verify_embedded(&crate::tools::hash::sys::wide_path(path));
    check.status == 0 && check.signer.as_deref() == Some("Microsoft Corporation")
}

type CreateEnvironment = unsafe extern "system" fn(bool, i32, *const u16, Raw, Raw) -> HRESULT;

/// Loads the runtime once, checking its signature first.
fn create_function() -> Result<CreateEnvironment, String> {
    static LOADED: OnceLock<Result<usize, String>> = OnceLock::new();
    let address = LOADED.get_or_init(|| {
        let dll = runtime_dll()?;
        if !signed_by_microsoft(&dll) {
            return Err(format!(
                "The WebView2 runtime at {} does not carry Microsoft's signature, so it was \
                 not loaded. Type the recovery key in instead.",
                dll.display()
            ));
        }
        let path: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: an absolute, nul-terminated path; its own folder and System32 serve its
        // imports. The module stays loaded for the life of the process.
        let module = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!(
                "The WebView2 runtime could not be loaded ({}).",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: a loaded module and a nul-terminated export name.
        let export = unsafe {
            GetProcAddress(
                module,
                c"CreateWebViewEnvironmentWithOptionsInternal"
                    .as_ptr()
                    .cast(),
            )
        };
        export
            .map(|f| f as usize)
            .ok_or_else(|| "This WebView2 runtime is not one this program can use.".to_string())
    });
    // SAFETY: the address is the export named above, whose signature `CreateEnvironment`
    // states (the same call Microsoft's loader makes).
    address
        .clone()
        .map(|address| unsafe { std::mem::transmute::<usize, CreateEnvironment>(address) })
}

// ---------------------------------------------------------------- environment and controller

/// A browser environment: one browser process with its own data folder.
#[derive(Clone)]
pub struct Environment(Com);

/// Starts a browser environment whose data lives in `user_data` (cookies, cache, the
/// signed-in session). `done` runs on this thread when it is ready or has failed.
pub fn create_environment(
    user_data: &Path,
    done: impl FnOnce(Result<Environment, HRESULT>) + 'static,
) -> Result<(), String> {
    let create = create_function()?;
    let folder: Vec<u16> = user_data.as_os_str().encode_wide().chain(Some(0)).collect();
    let completed = once(IID_ENVIRONMENT_COMPLETED, move |code, environment| {
        let code = code as u32 as HRESULT;
        // SAFETY: the environment is an argument of the call: borrowed, so referenced here.
        let environment = unsafe { Com::borrowed(environment as Raw) };
        done(match environment {
            Some(environment) if code >= 0 => Ok(Environment(environment)),
            _ => Err(if code < 0 { code } else { E_POINTER }),
        });
    });
    // SAFETY: as Microsoft's loader calls it: check for a running instance, the installed
    // runtime (0), the data folder, no options, the completion handler.
    let code = unsafe { create(true, 0, folder.as_ptr(), null_mut(), completed.raw()) };
    if code < 0 {
        return Err(format!(
            "The sign-in window could not start its browser (error 0x{:08X}).",
            code as u32
        ));
    }
    Ok(())
}

impl Environment {
    /// Makes a browser view inside `parent`; `done` runs when it is ready or has failed.
    // The window handle is passed to the runtime as a value, never dereferenced here.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn create_controller(
        &self,
        parent: HWND,
        done: impl FnOnce(Result<Controller, HRESULT>) + 'static,
    ) -> Result<(), HRESULT> {
        let completed = once(IID_CONTROLLER_COMPLETED, move |code, controller| {
            let code = code as u32 as HRESULT;
            // SAFETY: borrowed argument, referenced here.
            let controller = unsafe { Com::borrowed(controller as Raw) };
            done(match controller {
                Some(controller) if code >= 0 => Ok(Controller(controller)),
                _ => Err(if code < 0 { code } else { E_POINTER }),
            });
        });
        type Create = unsafe extern "system" fn(Raw, HWND, Raw) -> HRESULT;
        // SAFETY: ICoreWebView2Environment::CreateCoreWebView2Controller.
        let code = unsafe {
            self.0.slot::<Create>(slot::CREATE_CONTROLLER)(self.0.raw(), parent, completed.raw())
        };
        if code < 0 {
            Err(code)
        } else {
            Ok(())
        }
    }
}

/// The browser view hosted in a window.
#[derive(Clone)]
pub struct Controller(Com);

impl Controller {
    pub fn set_bounds(&self, bounds: RECT) {
        type SetBounds = unsafe extern "system" fn(Raw, RECT) -> HRESULT;
        // SAFETY: ICoreWebView2Controller::put_Bounds.
        unsafe { self.0.slot::<SetBounds>(slot::SET_BOUNDS)(self.0.raw(), bounds) };
    }

    /// Tells the view its window moved, so its popups (menus, pickers) follow.
    pub fn notify_parent_moved(&self) {
        // SAFETY: ICoreWebView2Controller::NotifyParentWindowPositionChanged.
        unsafe { self.0.slot::<Call0>(slot::NOTIFY_PARENT_MOVED)(self.0.raw()) };
    }

    /// Gives the page the keyboard.
    pub fn focus(&self) {
        type MoveFocus = unsafe extern "system" fn(Raw, i32) -> HRESULT;
        // SAFETY: ICoreWebView2Controller::MoveFocus.
        unsafe {
            self.0.slot::<MoveFocus>(slot::MOVE_FOCUS)(self.0.raw(), MOVE_FOCUS_PROGRAMMATIC)
        };
    }

    /// Closes the view; its events stop and the browser process can end once every
    /// reference is released.
    pub fn close(&self) {
        // SAFETY: ICoreWebView2Controller::Close.
        unsafe { self.0.slot::<Call0>(slot::CLOSE)(self.0.raw()) };
    }

    pub fn webview(&self) -> Option<WebView> {
        self.0.get_object(slot::CORE_WEBVIEW).map(WebView)
    }
}

// ---------------------------------------------------------------- the web view

#[derive(Clone)]
pub struct WebView(Com);

/// A navigation about to start, given to `on_navigation_starting` handlers.
pub struct Navigation(Raw);

impl Navigation {
    /// The address. It can carry sign-in codes: use it to decide, never keep or log it.
    pub fn uri(&self) -> String {
        // SAFETY: the arguments object is alive for the handler's call.
        unsafe { Com::borrowed(self.0) }
            .and_then(|args| args.get_text(slot::ARGS_URI))
            .unwrap_or_default()
    }

    /// Cancels the navigation; false when the browser did not take the cancel, so the
    /// page may open.
    #[must_use = "a navigation that could not be cancelled may open"]
    pub fn cancel(&self) -> bool {
        // SAFETY: as above.
        unsafe { Com::borrowed(self.0) }
            .is_some_and(|args| args.put_bool(slot::NAVIGATION_SET_CANCEL, true) >= 0)
    }
}

/// A request to open a new window, given to `on_new_window` handlers. No window is ever
/// opened: the request is always marked handled.
pub struct NewWindow(Raw);

impl NewWindow {
    pub fn uri(&self) -> String {
        // SAFETY: the arguments object is alive for the handler's call.
        unsafe { Com::borrowed(self.0) }
            .and_then(|args| args.get_text(slot::ARGS_URI))
            .unwrap_or_default()
    }
}

impl WebView {
    /// Turns off what the sign-in window does not need: developer tools, the context menu
    /// (Save as, Print), browser shortcut keys (copy and paste still work), messages and host
    /// objects from the page, the status bar, and saving passwords or form entries. Err when
    /// the runtime is too old to offer these settings.
    pub fn lock_down(&self) -> Result<(), String> {
        let too_old = || "The WebView2 runtime on this PC is too old for the sign-in window.";
        let settings = self.0.get_object(slot::SETTINGS).ok_or_else(too_old)?;
        let settings3 = settings.query(&IID_SETTINGS_3).ok_or_else(too_old)?;
        let settings4 = settings.query(&IID_SETTINGS_4).ok_or_else(too_old)?;
        let changes = [
            (&settings, slot::SET_IS_WEB_MESSAGE_ENABLED, false),
            (&settings, slot::SET_IS_STATUS_BAR_ENABLED, false),
            (&settings, slot::SET_ARE_DEV_TOOLS_ENABLED, false),
            (
                &settings,
                slot::SET_ARE_DEFAULT_CONTEXT_MENUS_ENABLED,
                false,
            ),
            (&settings, slot::SET_ARE_HOST_OBJECTS_ALLOWED, false),
            (
                &settings3,
                slot::SET_ARE_BROWSER_ACCELERATOR_KEYS_ENABLED,
                false,
            ),
            (&settings4, slot::SET_IS_PASSWORD_AUTOSAVE_ENABLED, false),
            (&settings4, slot::SET_IS_GENERAL_AUTOFILL_ENABLED, false),
        ];
        for (object, index, value) in changes {
            if object.put_bool(index, value) < 0 {
                return Err(too_old().to_string());
            }
        }
        Ok(())
    }

    pub fn navigate(&self, url: &str) {
        let url = wide(url);
        type Navigate = unsafe extern "system" fn(Raw, *const u16) -> HRESULT;
        // SAFETY: ICoreWebView2::Navigate with a nul-terminated address.
        unsafe { self.0.slot::<Navigate>(slot::NAVIGATE)(self.0.raw(), url.as_ptr()) };
    }

    /// The address of the page shown.
    pub fn source(&self) -> Option<String> {
        self.0.get_text(slot::SOURCE)
    }

    /// The browser process, to wait for its end before the data folder is removed.
    pub fn browser_process_id(&self) -> Option<u32> {
        type Get = unsafe extern "system" fn(Raw, *mut u32) -> HRESULT;
        let mut id = 0u32;
        // SAFETY: ICoreWebView2::get_BrowserProcessId.
        let code = unsafe { self.0.slot::<Get>(slot::BROWSER_PROCESS_ID)(self.0.raw(), &mut id) };
        (code >= 0 && id != 0).then_some(id)
    }

    /// Calls `decide` before every navigation of the page (`frames` false) or of a frame in
    /// it (`frames` true); it may cancel it.
    pub fn on_navigation_starting(
        &self,
        frames: bool,
        mut decide: impl FnMut(&Navigation) + 'static,
    ) -> Result<(), HRESULT> {
        let handler = handler(IID_NAVIGATION_STARTING, move |_sender, args| {
            decide(&Navigation(args as Raw));
            S_OK
        });
        let index = if frames {
            slot::ADD_FRAME_NAVIGATION_STARTING
        } else {
            slot::ADD_NAVIGATION_STARTING
        };
        self.0.add_event(index, &handler)
    }

    /// Calls `seen` for every request to open a window, with whether the request was
    /// refused; when it was not (the browser did not take "handled"), a window may open.
    pub fn on_new_window(
        &self,
        mut seen: impl FnMut(&NewWindow, bool) + 'static,
    ) -> Result<(), HRESULT> {
        let handler = handler(IID_NEW_WINDOW_REQUESTED, move |_sender, args| {
            // SAFETY: the arguments object is alive for this call.
            let refused = unsafe { Com::borrowed(args as Raw) }
                .is_some_and(|object| object.put_bool(slot::NEW_WINDOW_SET_HANDLED, true) >= 0);
            seen(&NewWindow(args as Raw), refused);
            S_OK
        });
        self.0.add_event(slot::ADD_NEW_WINDOW_REQUESTED, &handler)
    }

    /// Calls `done` when a page navigation ends, with whether it succeeded.
    pub fn on_navigation_completed(
        &self,
        mut done: impl FnMut(bool) + 'static,
    ) -> Result<(), HRESULT> {
        let handler = handler(IID_NAVIGATION_COMPLETED, move |_sender, args| {
            let mut success = 0i32;
            // SAFETY: the arguments object is alive for this call.
            if let Some(object) = unsafe { Com::borrowed(args as Raw) } {
                type Get = unsafe extern "system" fn(Raw, *mut i32) -> HRESULT;
                // SAFETY: ICoreWebView2NavigationCompletedEventArgs::get_IsSuccess.
                unsafe {
                    object.slot::<Get>(slot::NAVIGATION_COMPLETED_IS_SUCCESS)(
                        object.raw(),
                        &mut success,
                    )
                };
            }
            done(success != 0);
            S_OK
        });
        self.0.add_event(slot::ADD_NAVIGATION_COMPLETED, &handler)
    }

    /// Refuses every permission a page asks for (camera, location, notifications and the
    /// rest); signing in needs none.
    pub fn deny_permissions(&self) -> Result<(), HRESULT> {
        let handler = handler(IID_PERMISSION_REQUESTED, |_sender, args| {
            // SAFETY: the arguments object is alive for this call.
            if let Some(object) = unsafe { Com::borrowed(args as Raw) } {
                type Put = unsafe extern "system" fn(Raw, i32) -> HRESULT;
                // SAFETY: ICoreWebView2PermissionRequestedEventArgs::put_State.
                unsafe {
                    object.slot::<Put>(slot::PERMISSION_SET_STATE)(
                        object.raw(),
                        PERMISSION_STATE_DENY,
                    )
                };
            }
            S_OK
        });
        self.0.add_event(slot::ADD_PERMISSION_REQUESTED, &handler)
    }

    /// Cancels every download (a page could otherwise save the key to the Downloads folder)
    /// and calls `seen` for each, with whether the cancel was taken; when it was not, the
    /// download may go ahead.
    pub fn cancel_downloads(&self, mut seen: impl FnMut(bool) + 'static) -> Result<(), HRESULT> {
        let webview4 = self.0.query(&IID_WEBVIEW_4).ok_or(E_NOINTERFACE)?;
        let handler = handler(IID_DOWNLOAD_STARTING, move |_sender, args| {
            // SAFETY: the arguments object is alive for this call.
            let cancelled = unsafe { Com::borrowed(args as Raw) }
                .is_some_and(|object| object.put_bool(slot::DOWNLOAD_SET_CANCEL, true) >= 0);
            seen(cancelled);
            S_OK
        });
        webview4.add_event(slot::ADD_DOWNLOAD_STARTING, &handler)
    }

    /// Calls `failed` when a browser process behind the page fails.
    pub fn on_process_failed(&self, mut failed: impl FnMut() + 'static) -> Result<(), HRESULT> {
        let handler = handler(IID_PROCESS_FAILED, move |_sender, _args| {
            failed();
            S_OK
        });
        self.0.add_event(slot::ADD_PROCESS_FAILED, &handler)
    }

    /// Runs `script` in the page and gives `done` its result when it is a string, decoded
    /// into text that is zeroed when dropped.
    pub fn execute_script(
        &self,
        script: &str,
        done: impl FnOnce(Option<ScrubbedText>) + 'static,
    ) -> Result<(), HRESULT> {
        let completed = once(IID_EXECUTE_SCRIPT_COMPLETED, move |code, json| {
            let code = code as u32 as HRESULT;
            let json = json as *const u16;
            if code < 0 || json.is_null() {
                done(None);
                return;
            }
            // SAFETY: the result string is the callee's and alive for this call; it is read
            // into zeroing buffers and never copied elsewhere.
            let units = unsafe { std::slice::from_raw_parts(json, wide_len(json)) };
            let mut raw = ScrubbedText::with_capacity(units.len() * 3);
            for c in char::decode_utf16(units.iter().copied()) {
                raw.push(c.unwrap_or('\u{FFFD}'));
            }
            done(decode_script_string(raw.as_str()));
        });
        let mut script = wide(script);
        type Execute = unsafe extern "system" fn(Raw, *const u16, Raw) -> HRESULT;
        // SAFETY: ICoreWebView2::ExecuteScript with a nul-terminated script.
        let code = unsafe {
            self.0.slot::<Execute>(slot::EXECUTE_SCRIPT)(
                self.0.raw(),
                script.as_ptr(),
                completed.raw(),
            )
        };
        scrub_wide(&mut script);
        if code < 0 {
            Err(code)
        } else {
            Ok(())
        }
    }
}

/// Unused handles kept from tripping the unused-constant lint on targets without them.
const _: (*const u16, &str) = (null(), STABLE_RUNTIME);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handler_answers_for_its_interface_and_iunknown_only() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = calls.clone();
        let object = handler(IID_NAVIGATION_STARTING, move |a, b| {
            seen.set(seen.get() + a + b);
            S_OK
        });
        assert!(object.query(&IID_IUNKNOWN).is_some());
        assert!(object.query(&IID_NAVIGATION_STARTING).is_some());
        assert!(object.query(&IID_NAVIGATION_COMPLETED).is_none());
        // SAFETY: slot 3 of a handler is Invoke(this, a, b).
        let invoke: unsafe extern "system" fn(Raw, usize, usize) -> HRESULT =
            unsafe { object.slot(3) };
        assert_eq!(unsafe { invoke(object.raw(), 2, 3) }, S_OK);
        assert_eq!(calls.get(), 5);
    }

    #[test]
    fn a_panicking_handler_returns_a_failure_instead_of_unwinding_into_the_caller() {
        let object = handler(IID_PROCESS_FAILED, |_, _| panic!("handler fault"));
        let invoke: unsafe extern "system" fn(Raw, usize, usize) -> HRESULT =
            // SAFETY: as above.
            unsafe { object.slot(3) };
        assert_eq!(unsafe { invoke(object.raw(), 0, 0) }, E_FAIL);
    }

    #[test]
    fn a_once_handler_runs_its_work_one_time() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = calls.clone();
        let object = once(IID_EXECUTE_SCRIPT_COMPLETED, move |_, _| {
            seen.set(seen.get() + 1)
        });
        // SAFETY: as above.
        let invoke: unsafe extern "system" fn(Raw, usize, usize) -> HRESULT =
            unsafe { object.slot(3) };
        unsafe {
            invoke(object.raw(), 0, 0);
            invoke(object.raw(), 0, 0);
        }
        assert_eq!(calls.get(), 1);
    }

    /// Needs the WebView2 runtime installed (Windows 11 has it).
    #[test]
    #[ignore = "needs the WebView2 runtime installed"]
    fn the_installed_runtime_is_found_and_signed_by_microsoft() {
        let dll = runtime_dll().expect("the runtime");
        assert!(signed_by_microsoft(&dll), "{}", dll.display());
        assert!(create_function().is_ok());
        eprintln!("runtime: {}", dll.display());
    }
}
