//! The sign-in window that reads a BitLocker recovery key from the customer's Microsoft
//! account, so it does not have to be typed: `fetch_recovery_key`.
//!
//! The customer signs in on Microsoft's own pages inside the window; this program never
//! reads, fills or keeps the password and does not script the sign-in pages. Once the page
//! that lists recovery keys is showing, its visible text (and nothing else) is read and the
//! key under the drive's key ID is picked out. The browser keeps its data in a new folder
//! under %TEMP% that is removed when the window closes, so nothing stays signed in, and it
//! only goes to Microsoft's sign-in and account hosts (`keylookup::ALLOWED_HOSTS`).
//!
//! Every decision (allowed hosts, when and how the page is read, what the technician is
//! told, the outcome) is made by `keylookup::SignIn` in the library; this window hosts the
//! browser, feeds it events and shows what it says.
//!
//! The BitLocker unlock window calls `fetch_recovery_key`; until it is wired in, only the
//! debug-build demo switch calls it.
#![cfg_attr(not(debug_assertions), allow(dead_code))]
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use diagnostics::recovery::keylookup::{
    self as lookup, webview2, Account, ReadStep, SignIn, SignInEvent, SignInOptions, SignInResult,
};
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::InvalidateRect;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::ui::{self, wide, Kind, Tone};

const CLASS: &str = "DiagnosticToolKeyLookup";
const PERSONAL: usize = 201;
const WORK: usize = 202;
const CLOSE: usize = 203;
const TIMER: usize = 1;
/// How often the key page is read while it is showing, and the cancel flag checked.
const TICK_MS: u32 = 1000;
/// How long a read of the page's text may go unanswered before it is asked for again.
const READ_LIMIT: Duration = Duration::from_secs(10);
/// An allowed address a page asked to open in a new window, opened here instead.
const OPEN_PENDING: u32 = WM_APP + 1;
/// Lay the window out again (the status text changed, or the browser view arrived).
const RELAYOUT: u32 = WM_APP + 2;
/// Go to an account's sign-in page (wParam 0 personal, 1 work or school).
const CHOOSE: u32 = WM_APP + 3;

struct Session {
    hwnd: HWND,
    sign_in: SignIn,
    folder: PathBuf,
    status: HWND,
    texts: Vec<HWND>,
    buttons: Vec<HWND>,
    /// Muted words where the sign-in page will open, until it does.
    placeholder: HWND,
    environment: Option<webview2::Environment>,
    controller: Option<webview2::Controller>,
    webview: Option<webview2::WebView>,
    /// The browser process, waited for before the folder is removed.
    browser: HANDLE,
    starting: bool,
    /// When the page's text was asked for; a read that never answers is given up after
    /// `READ_LIMIT`.
    reading: Option<Instant>,
    pending: Option<String>,
    done: bool,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// Runs `f` on the open session; None when there is none (the window has closed) or it is
/// in use further up the stack.
fn with<T>(f: impl FnOnce(&mut Session) -> T) -> Option<T> {
    SESSION.with(|cell| cell.try_borrow_mut().ok()?.as_mut().map(f))
}

impl Session {
    fn say(&self, text: &str) {
        ui::set_text(self.status, text);
        unsafe {
            InvalidateRect(self.status, std::ptr::null(), 1);
            // Laid out from the message loop: the session is borrowed here.
            PostMessageW(self.hwnd, RELAYOUT, 0, 0);
        }
    }
}

// ---------------------------------------------------------------- the browser

fn start_browser() {
    let Some(folder) = with(|s| {
        s.starting = true;
        s.folder.clone()
    }) else {
        return;
    };
    if let Err(why) = webview2::create_environment(&folder, on_environment) {
        with(|s| {
            s.starting = false;
            s.say(&why);
        });
    }
}

fn could_not_open(s: &mut Session) {
    s.starting = false;
    s.say("The sign-in window could not open its page. Close this window and type the key in.");
}

fn on_environment(result: Result<webview2::Environment, webview2::HRESULT>) {
    let environment = match result {
        Ok(environment) => environment,
        Err(code) => {
            with(|s| {
                s.starting = false;
                s.say(&format!(
                    "The sign-in window could not start its browser (error 0x{:08X}). Close \
                     this window and type the key in.",
                    code as u32
                ));
            });
            return;
        }
    };
    let Some(hwnd) = with(|s| {
        s.environment = Some(environment.clone());
        (!s.done).then_some(s.hwnd)
    })
    .flatten() else {
        with(|s| s.starting = false);
        return;
    };
    if environment.create_controller(hwnd, on_controller).is_err() {
        with(could_not_open);
    }
}

fn on_controller(result: Result<webview2::Controller, webview2::HRESULT>) {
    let Ok(controller) = result else {
        with(could_not_open);
        return;
    };
    let open = with(|s| !s.done).unwrap_or(false);
    let webview = controller.webview();
    let ready = match &webview {
        Some(webview) if open => set_up(webview),
        Some(_) => Err(String::new()),
        None => Err("The sign-in window could not open its page.".to_string()),
    };
    let (Ok(()), Some(webview)) = (ready.clone(), webview) else {
        controller.close();
        with(|s| {
            s.starting = false;
            if let Err(why) = &ready {
                if !why.is_empty() {
                    s.say(&format!("{why} Close this window and type the key in."));
                }
            }
        });
        return;
    };
    let browser = webview
        .browser_process_id()
        // SAFETY: plain call; a null handle means the wait is skipped.
        .map(|pid| unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) })
        .unwrap_or(std::ptr::null_mut());
    let account = with(|s| {
        s.starting = false;
        s.controller = Some(controller.clone());
        s.webview = Some(webview.clone());
        s.browser = browser;
        unsafe { PostMessageW(s.hwnd, RELAYOUT, 0, 0) };
        s.sign_in.account()
    })
    .flatten();
    if let Some(account) = account {
        webview.navigate(account.start_url());
        controller.focus();
    }
}

/// Settings and event handlers for a new view; Err with what to tell the technician.
fn set_up(webview: &webview2::WebView) -> Result<(), String> {
    webview.lock_down()?;
    let failed = |_| "The sign-in window could not be set up.".to_string();
    for frame in [false, true] {
        webview
            .on_navigation_starting(frame, move |navigation| {
                let uri = navigation.uri();
                let decision = with(|s| {
                    let decision = s.sign_in.navigation(&uri, frame);
                    if let (Err(text), false) = (&decision, frame) {
                        s.say(text);
                    }
                    decision.is_ok()
                });
                // With no session (the window closing) nothing more opens.
                if decision != Some(true) && !navigation.cancel() {
                    refusal_failed(if frame {
                        "a frame outside Microsoft's sign-in"
                    } else {
                        "a page outside Microsoft's sign-in"
                    });
                }
            })
            .map_err(failed)?;
    }
    webview
        .on_new_window(|request, refused| {
            if !refused {
                refusal_failed("a new window");
                return;
            }
            let uri = request.uri();
            with(|s| match s.sign_in.new_window(&uri) {
                Ok(()) => {
                    s.pending = Some(uri);
                    unsafe { PostMessageW(s.hwnd, OPEN_PENDING, 0, 0) };
                }
                Err(text) => s.say(&text),
            });
        })
        .map_err(failed)?;
    webview
        .on_navigation_completed(|_| {
            // Read at once rather than at the next tick.
            with(|s| unsafe { PostMessageW(s.hwnd, WM_TIMER, TIMER, 0) });
        })
        .map_err(failed)?;
    webview.deny_permissions().map_err(failed)?;
    webview
        .cancel_downloads(|cancelled| {
            if !cancelled {
                refusal_failed("a download");
                return;
            }
            with(|s| {
                let text = s.sign_in.download_cancelled();
                s.say(text);
            });
        })
        .map_err(|_| {
            "The WebView2 runtime on this PC is too old for the sign-in window.".to_string()
        })?;
    webview
        .on_process_failed(|| {
            with(|s| {
                let text = s.sign_in.browser_failed();
                s.say(text);
            });
        })
        .map_err(failed)?;
    Ok(())
}

/// A refusal the browser did not take: the sign-in ends without a key and the window
/// closes.
fn refusal_failed(what: &str) {
    with(|s| {
        let text = s.sign_in.could_not_refuse(what);
        s.say(&text);
        s.done = true;
    });
}

fn choose(account: Account) {
    let Some((webview, url, start)) = with(|s| {
        let url = s.sign_in.choose(account);
        s.say(lookup::SIGNING_IN);
        (
            s.webview.clone(),
            url,
            s.webview.is_none() && s.environment.is_none() && !s.starting,
        )
    }) else {
        return;
    };
    if let Some(webview) = webview {
        webview.navigate(url);
    } else if start {
        start_browser();
    }
}

/// Reads the key page when it is showing; called every second and after each navigation.
fn tick() {
    #[cfg(test)]
    probe::step();
    let busy = |s: &Session| s.reading.is_some_and(|since| since.elapsed() < READ_LIMIT);
    let Some((Some(webview), false)) = with(|s| (s.webview.clone(), busy(s))) else {
        return;
    };
    let source = webview.source().unwrap_or_default();
    let read = with(|s| {
        let (read, text) = s.sign_in.should_read(&source);
        if let Some(text) = text {
            s.say(text);
        }
        s.reading = read.then(Instant::now);
        read
    });
    if read == Some(true)
        && webview
            .execute_script(lookup::PAGE_TEXT_SCRIPT, on_page_text)
            .is_err()
    {
        with(|s| s.reading = None);
    }
}

fn on_page_text(text: Option<lookup::ScrubbedText>) {
    with(|s| {
        s.reading = None;
        match s
            .sign_in
            .page_text(text.as_ref().map(lookup::ScrubbedText::as_str))
        {
            ReadStep::Done => s.done = true,
            ReadStep::Tell(text) => s.say(&text),
            ReadStep::Wait => {}
        }
    });
}

// ---------------------------------------------------------------- the window

fn relayout(hwnd: HWND) {
    let mut rect: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetClientRect(hwnd, &mut rect) };
    layout(hwnd, rect.right - rect.left, rect.bottom - rect.top);
}

fn layout(hwnd: HWND, w: i32, h: i32) {
    let Some((texts, status, buttons, placeholder, controller)) = with(|s| {
        (
            s.texts.clone(),
            s.status,
            s.buttons.clone(),
            s.placeholder,
            s.controller.clone(),
        )
    }) else {
        return;
    };
    let dpi = ui::dpi_of(hwnd);
    let fonts = ui::fonts(dpi);
    let s = |v| scale(dpi, v);
    let x = s(grid::OUTER);
    let width = (w - 2 * x).max(s(200));
    let mut y = s(grid::OUTER - 8);
    for (index, text) in texts.iter().enumerate() {
        let font = if index == 0 { fonts.title } else { fonts.body };
        let height =
            ui::text_height(hwnd, font, &ui::window_text(*text), width).max(s(grid::BODY_H));
        ui::place(
            *text,
            Rect {
                x,
                y,
                w: width,
                h: height,
            },
        );
        y += height + s(6);
    }
    y += s(4);
    let mut bx = x;
    for button in &buttons {
        let bw = ui::button_width(*button, &ui::window_text(*button));
        ui::place(
            *button,
            Rect {
                x: bx,
                y,
                w: bw,
                h: s(grid::BUTTON_H),
            },
        );
        bx += bw + s(grid::BUTTON_GAP);
    }
    y += s(grid::BUTTON_H) + s(grid::GAP);
    let status_h =
        ui::text_height(hwnd, fonts.body, &ui::window_text(status), width).max(s(grid::BODY_H));
    ui::place(
        status,
        Rect {
            x,
            y,
            w: width,
            h: status_h,
        },
    );
    y += status_h + s(grid::GAP);
    let bottom = (h - x).max(y + s(100));
    // Until the browser opens, its place is a card that says what will appear there.
    ui::show(placeholder, controller.is_none());
    if controller.is_none() {
        let pad = s(grid::CARD_PAD);
        ui::place(
            placeholder,
            Rect {
                x: x + pad,
                y: y + pad,
                w: width - 2 * pad,
                h: s(grid::BODY_H) * 2,
            },
        );
        ui::set_cards(
            hwnd,
            vec![Rect {
                x,
                y,
                w: width,
                h: bottom - y,
            }],
        );
    } else {
        ui::set_cards(hwnd, Vec::new());
    }
    if let Some(controller) = controller {
        controller.set_bounds(RECT {
            left: x,
            top: y,
            right: x + width,
            bottom,
        });
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            ui::paint_surface(hwnd);
            0
        }
        WM_ERASEBKGND => 1,
        WM_DRAWITEM => ui::draw_item(l),
        WM_SIZE => {
            layout(hwnd, (l & 0xFFFF) as i32, ((l >> 16) & 0xFFFF) as i32);
            0
        }
        WM_MOVE => {
            if let Some(Some(controller)) = with(|s| s.controller.clone()) {
                controller.notify_parent_moved();
            }
            0
        }
        WM_DPICHANGED => {
            let r = &*(l as *const RECT);
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                r.left,
                r.top,
                r.right - r.left,
                r.bottom - r.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            0
        }
        WM_COMMAND => {
            match w & 0xFFFF {
                PERSONAL => choose(Account::Personal),
                WORK => choose(Account::WorkOrSchool),
                CLOSE => {
                    with(|s| s.done = true);
                }
                _ => return DefWindowProcW(hwnd, msg, w, l),
            }
            0
        }
        CHOOSE => {
            choose(if w == 0 {
                Account::Personal
            } else {
                Account::WorkOrSchool
            });
            0
        }
        WM_TIMER if w == TIMER => {
            tick();
            0
        }
        RELAYOUT => {
            relayout(hwnd);
            0
        }
        OPEN_PENDING => {
            if let Some((Some(webview), Some(uri))) =
                with(|s| (s.webview.clone(), s.pending.take()))
            {
                webview.navigate(&uri);
            }
            0
        }
        WM_CLOSE => {
            with(|s| s.done = true);
            0
        }
        WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
            ui::refresh_palette();
            ui::style_frame(hwnd);
            InvalidateRect(hwnd, std::ptr::null(), 1);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

fn register() -> bool {
    static DONE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DONE.get_or_init(|| {
        let name = wide(CLASS);
        let class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: unsafe { GetModuleHandleW(std::ptr::null()) },
            hIcon: crate::app_icon(),
            hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: name.as_ptr(),
        };
        unsafe { RegisterClassW(&class) != 0 }
    })
}

/// Pumps this thread's messages until `until` says stop, `wait_on` is signalled or `limit`
/// passes. The browser answers through the message loop, so waiting on it must keep the
/// loop running.
fn pump(limit: Duration, wait_on: HANDLE, mut until: impl FnMut() -> bool) {
    let end = Instant::now() + limit;
    let handles = [wait_on];
    let count = u32::from(!wait_on.is_null());
    loop {
        if until() {
            return;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        let ms = left.as_millis().min(250) as u32;
        let woke =
            unsafe { MsgWaitForMultipleObjects(count, handles.as_ptr(), 0, ms, QS_ALLINPUT) };
        if count == 1 && woke == 0 {
            return;
        }
        let mut message: MSG = unsafe { std::mem::zeroed() };
        while unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            if message.message == WM_QUIT {
                // WM_QUIT belongs to the outer loop.
                unsafe { PostQuitMessage(message.wParam as i32) };
                return;
            }
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

/// The sign-in step: opens the sign-in window over `owner` (disabled meanwhile), lets the
/// customer sign in, and reads the recovery key listed for one of the options' key IDs on
/// the account's key page.
///
/// It is a person's step (the customer signs in), but an agent can open it: set
/// `options.account` to open straight to that sign-in, watch `progress` (events go to it
/// on this thread), and set `cancel` to close the window within a second. The result says
/// how it ended; its serialized form never carries the key.
///
/// - `KeyRead`: `result.key` holds the key. Pass `key.as_str()` to the unlock step and drop
///   it.
/// - `NoMatch`, `NotUnderstood`, `Cancelled`: no key; go on to manual entry (the window told
///   the technician which key ID to copy).
/// - `Unavailable`: the window cannot work on this PC (no WebView2 runtime) or the options
///   are out of bounds; show `reason`, then manual entry.
///
/// Before returning, the browser is closed and its data folder (cookies, the signed-in
/// session) is removed.
pub fn fetch_recovery_key(
    owner: HWND,
    options: &SignInOptions,
    progress: &mut dyn FnMut(&SignInEvent),
    cancel: &AtomicBool,
) -> SignInResult {
    let sign_in = match SignIn::new(options) {
        Ok(sign_in) => sign_in,
        Err(why) => return SignInResult::unavailable(why),
    };
    // A key read from the account page lands in this process's memory: kept out of crash
    // dumps until this returns.
    let _dumps = match diagnostics::tools::crash_dumps::keep_out_of_dumps() {
        Ok(kept) => kept,
        Err(why) => return SignInResult::unavailable(why),
    };
    if let Err(why) = webview2::runtime_dll() {
        return SignInResult::unavailable(why);
    }
    if !register() {
        return SignInResult::unavailable("The sign-in window could not be opened.".to_string());
    }
    // Folders an earlier window could not remove (the program was ended, or the browser
    // held on to them) go first.
    let old_left = lookup::sweep_old_sign_in_folders(None).left;
    let folder = match lookup::new_sign_in_folder() {
        Ok(folder) => folder,
        Err(e) => {
            return SignInResult::unavailable(format!(
                "The sign-in window could not make its temporary folder: {e}"
            ))
        }
    };
    #[cfg(test)]
    probe::LAST_FOLDER.with(|last| *last.borrow_mut() = Some(folder.clone()));
    let area = crate::dialog::work_area(owner);
    let dpi = if owner.is_null() {
        96
    } else {
        ui::dpi_of(owner)
    };
    let (aw, ah) = (area.right - area.left, area.bottom - area.top);
    let (w, h) = (scale(dpi, 980).min(aw), scale(dpi, 780).min(ah));
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_CONTROLPARENT,
            wide(CLASS).as_ptr(),
            wide("Find the recovery key").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            area.left + (aw - w) / 2,
            area.top + (ah - h) / 2,
            w,
            h,
            owner,
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        let _ = std::fs::remove_dir(&folder);
        return SignInResult::unavailable("The sign-in window could not be opened.".to_string());
    }
    ui::style_frame(hwnd);
    let texts = vec![
        ui::text(
            hwnd,
            Kind::Title,
            Tone::Neutral,
            false,
            &format!("Find the recovery key for key ID {}", sign_in.shown_ids()),
        ),
        ui::text(
            hwnd,
            Kind::Body,
            Tone::Neutral,
            false,
            "Sign in with the customer's Microsoft account to read the key from it. The \
             customer types their password on Microsoft's page; this program does not see or \
             keep it, and nothing stays signed in after this window closes.",
        ),
    ];
    let buttons = vec![
        ui::button(hwnd, PERSONAL, Kind::Primary, "Personal Microsoft account"),
        ui::button(hwnd, WORK, Kind::Secondary, "Work or school account"),
        ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
    ];
    let status = ui::text(
        hwnd,
        Kind::Muted,
        Tone::Neutral,
        false,
        "Choose the kind of account the customer signs in to Windows with.",
    );
    let placeholder = ui::text(
        hwnd,
        Kind::Muted,
        Tone::Neutral,
        true,
        "Microsoft's sign-in page opens here once the kind of account is chosen.",
    );
    let first = buttons[0];
    SESSION.with(|cell| {
        *cell.borrow_mut() = Some(Session {
            hwnd,
            sign_in,
            folder: folder.clone(),
            status,
            texts,
            buttons,
            placeholder,
            environment: None,
            controller: None,
            webview: None,
            browser: std::ptr::null_mut(),
            starting: false,
            reading: None,
            pending: None,
            done: false,
        })
    });
    relayout(hwnd);
    unsafe {
        if !owner.is_null() {
            EnableWindow(owner, 0);
        }
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(first);
        SendMessageW(hwnd, WM_CHANGEUISTATE, UIS_INITIALIZE as usize, 0);
        SetTimer(hwnd, TIMER, TICK_MS, None);
        if let Some(account) = options.account {
            PostMessageW(
                hwnd,
                CHOOSE,
                usize::from(account == Account::WorkOrSchool),
                0,
            );
        }
    }
    let mut message: MSG = unsafe { std::mem::zeroed() };
    loop {
        let events = with(|s| s.sign_in.take_events()).unwrap_or_default();
        events.iter().for_each(&mut *progress);
        if cancel.load(Ordering::Relaxed) {
            with(|s| s.done = true);
        }
        if with(|s| s.done).unwrap_or(true) {
            break;
        }
        if unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) } <= 0 {
            unsafe { PostQuitMessage(message.wParam as i32) };
            break;
        }
        let ours = message.hwnd == hwnd || unsafe { IsChild(hwnd, message.hwnd) } != 0;
        if ours && message.message == WM_KEYDOWN && message.wParam == 0x1B {
            with(|s| s.done = true);
            continue;
        }
        if ours && unsafe { IsDialogMessageW(hwnd, &message) } != 0 {
            continue;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    let result = close(hwnd, owner);
    if let Some(mut sign_in) = result.1 {
        sign_in.take_events().iter().for_each(&mut *progress);
        let mut finished = sign_in.finish(result.0);
        finished.old_folders_left = old_left;
        return finished;
    }
    SignInResult::unavailable("The sign-in window closed unexpectedly.".to_string())
}

/// Closes the browser, waits for its process to end, removes its data folder and the
/// window. Gives back whether the folder was removed, and the sign-in state.
fn close(hwnd: HWND, owner: HWND) -> (bool, Option<SignIn>) {
    unsafe { KillTimer(hwnd, TIMER) };
    // A browser still starting finishes first, so nothing is left running.
    pump(Duration::from_secs(15), std::ptr::null_mut(), || {
        !with(|s| s.starting).unwrap_or(false)
    });
    let Some(session) = SESSION.with(|cell| cell.borrow_mut().take()) else {
        return (false, None);
    };
    let Session {
        controller,
        webview,
        environment,
        browser,
        folder,
        sign_in,
        ..
    } = session;
    if let Some(controller) = &controller {
        controller.close();
    }
    drop(webview);
    drop(controller);
    drop(environment);
    unsafe { ShowWindow(hwnd, SW_HIDE) };
    if !owner.is_null() {
        unsafe { EnableWindow(owner, 1) };
    }
    if !browser.is_null() {
        pump(Duration::from_secs(20), browser, || false);
        unsafe { CloseHandle(browser) };
    }
    // Child processes can hold files a moment after the browser process ends.
    let mut removed = false;
    pump(Duration::from_secs(10), std::ptr::null_mut(), || {
        removed = !folder.exists() || std::fs::remove_dir_all(&folder).is_ok();
        removed
    });
    ui::forget_window(hwnd);
    unsafe { DestroyWindow(hwnd) };
    (removed, Some(sign_in))
}

/// The debug-build demo: `DiagnosticTool.exe --key-lookup-demo <key ID> [<key ID>...]`. It
/// searches the drives for saved key files, then opens the sign-in window, and shows what
/// was found and the serialized results (which never carry a key). No digit of a key read
/// is shown.
#[cfg(debug_assertions)]
pub fn demo(key_ids: &[String]) {
    let cancel = AtomicBool::new(false);
    let mut lines = Vec::new();
    let search = lookup::KeyFileSearchOptions {
        key_ids: key_ids.to_vec(),
        ..Default::default()
    };
    match lookup::search_key_files(&search, &mut |_| {}, &cancel) {
        Ok(found) => {
            for saved in &found.keys {
                lines.push(format!(
                    "Saved key file {} for key ID {}: a valid key. No part of it is shown.",
                    saved.path.display(),
                    saved.key_id
                ));
            }
            lines.push(format!(
                "Key file search: {}",
                serde_json::to_string(&found).unwrap_or_default()
            ));
        }
        Err(why) => lines.push(why),
    }
    let options = SignInOptions {
        key_ids: key_ids.to_vec(),
        account: None,
    };
    let result = fetch_recovery_key(std::ptr::null_mut(), &options, &mut |_| {}, &cancel);
    if result.key.is_some() {
        lines.push("The sign-in window read the key. No part of it is shown.".into());
    }
    lines.push(format!(
        "Sign-in: {}",
        serde_json::to_string(&result).unwrap_or_default()
    ));
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(&lines.join("\n\n")).as_ptr(),
            wide("Recovery key lookup demo").as_ptr(),
            MB_OK,
        )
    };
}

/// The live check: drives the window without signing in. It runs only in the ignored test
/// below and is the only place a script other than the page-text read runs (to make a page
/// ask for a new window, which nothing else can do without a person).
#[cfg(test)]
mod probe {
    use super::*;

    thread_local! {
        pub static LAST_FOLDER: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static STEP: RefCell<(usize, Option<Instant>)> = const { RefCell::new((0, None)) };
    }

    /// Each step waits this long, in seconds, after the one before. The window opened
    /// straight to the personal sign-in (the options chose it).
    const PAUSES: [u64; 8] = [12, 1, 4, 1, 4, 1, 12, 1];

    pub fn step() {
        let (index, since) = STEP.with(|s| *s.borrow());
        let since = since.unwrap_or_else(Instant::now);
        let Some(pause) = PAUSES.get(index) else {
            return;
        };
        if since.elapsed() < Duration::from_secs(*pause) {
            STEP.with(|s| s.borrow_mut().1 = Some(since));
            return;
        }
        STEP.with(|s| *s.borrow_mut() = (index + 1, Some(Instant::now())));
        let webview = with(|s| s.webview.clone()).flatten();
        match (index, webview) {
            (0, Some(webview)) => webview.navigate("https://www.example.com/"),
            (2, Some(webview)) => {
                let _ = webview.execute_script("window.open('https://www.example.com/')", |_| {});
            }
            (4, _) => choose(Account::WorkOrSchool),
            (6, Some(webview)) => webview.navigate("http://login.live.com/"),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_out_of_bounds_are_refused_before_any_window_opens() {
        let options = SignInOptions {
            key_ids: vec!["not an id".to_string()],
            account: None,
        };
        let result = fetch_recovery_key(
            std::ptr::null_mut(),
            &options,
            &mut |_| {},
            &AtomicBool::new(false),
        );
        assert!(matches!(
            result.outcome,
            lookup::SignInOutcome::Unavailable { .. }
        ));
        assert!(result.key.is_none());
    }

    /// Opens the sign-in window on this PC's WebView2 runtime and Microsoft's live sign-in
    /// pages, without signing in: checks the hosts opened and refused, the events, the
    /// cancel flag, the result, and that the data folder is gone afterwards. Needs the
    /// WebView2 runtime and the internet; run with
    /// `cargo test --bin DiagnosticTool -- --ignored --nocapture sign_in_window`.
    #[test]
    #[ignore = "opens a WebView2 window on Microsoft's live sign-in pages"]
    fn sign_in_window_keeps_to_microsoft_and_leaves_no_folder() {
        unsafe {
            windows_sys::Win32::System::Com::CoInitializeEx(
                std::ptr::null(),
                windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
            )
        };
        ui::refresh_palette();
        let options = SignInOptions {
            key_ids: vec!["5A1B2C3D".to_string()],
            account: Some(Account::Personal),
        };
        let cancel = AtomicBool::new(false);
        let mut events = Vec::new();
        let result = std::thread::scope(|scope| {
            // The agent's cancel, once the last probe step has had its time.
            scope.spawn(|| {
                std::thread::sleep(Duration::from_secs(42));
                cancel.store(true, Ordering::Relaxed);
            });
            fetch_recovery_key(
                std::ptr::null_mut(),
                &options,
                &mut |event| {
                    eprintln!("{}", serde_json::to_string(event).unwrap_or_default());
                    events.push(event.clone());
                },
                &cancel,
            )
        });
        let json = serde_json::to_string(&result).expect("serializes");
        eprintln!("result {json}");
        let folder = probe::LAST_FOLDER
            .with(|f| f.borrow().clone())
            .expect("a folder");
        eprintln!(
            "folder {} exists afterwards: {}",
            folder.display(),
            folder.exists()
        );
        assert!(!folder.exists());
        assert!(result.folder_removed);
        assert_eq!(result.outcome, lookup::SignInOutcome::Cancelled);
        for host in [
            "login.live.com",
            "login.microsoftonline.com",
            "myaccount.microsoft.com",
        ] {
            assert!(result.hosts_opened.iter().any(|h| h == host), "{json}");
        }
        for host in ["www.example.com", "an address starting http:"] {
            assert!(result.hosts_refused.iter().any(|h| h == host), "{json}");
        }
        assert!(events.contains(&SignInEvent::NewWindowRefused {
            host: "www.example.com".to_string()
        }));
        assert!(events.contains(&SignInEvent::AccountChosen {
            account: Account::Personal
        }));
    }
}
