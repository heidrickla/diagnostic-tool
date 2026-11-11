#![cfg(windows)]
#![windows_subsystem = "windows"]

mod app;
mod bitlocker_view;
mod condition_strip;
mod cpumem_view;
mod crashdump_view;
mod dialog;
mod drive_view;
mod ending_view;
mod event_view;
mod graph;
mod help;
mod help_pane;
mod inspect_view;
mod keylookup_view;
mod migrate_view;
mod notify;
mod recover_files;
mod recovery_view;
mod relaunch;
mod remote;
mod rescue_copy_view;
mod rescue_image_view;
mod restore_view;
mod space_view;
mod tools;
mod toolwin;
mod ui;
mod vdisk_view;
mod verify_view;

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use diagnostics::{clock, report};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HMODULE, HWND};
use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SetUnhandledExceptionFilter, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, SetDefaultDllDirectories,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::dialog::{Dialog, Item, Section};
use crate::ui::wide;

/// The icon embedded as resource 1, or none in a build without resources.
pub fn app_icon() -> HICON {
    unsafe {
        LoadImageW(
            GetModuleHandleW(std::ptr::null()),
            1 as _,
            IMAGE_ICON,
            0,
            0,
            LR_DEFAULTSIZE | LR_SHARED,
        ) as HICON
    }
}

/// Writes a crash note beside the reports and returns where it went.
fn write_crash_note(thread: &str, cause: &str) -> Option<std::path::PathBuf> {
    let stamp = clock::local(SystemTime::now());
    let note = format!(
        "Diagnostic Tool {} stopped unexpectedly.\r\nTime: {}\r\nThread: {thread}\r\n{cause}\r\n",
        env!("CARGO_PKG_VERSION"),
        stamp.long(),
    );
    let folder = report::documents_folder().unwrap_or_else(|_| std::env::temp_dir());
    let path = folder.join(format!("Diagnostic-Tool-crash-{}.txt", stamp.file()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(note.as_bytes()))
        .ok()
        .map(|()| path)
}

fn tell_friend(saved: Option<&std::path::Path>) {
    let text = match saved {
        Some(path) => format!("Diagnostic Tool stopped unexpectedly. No checks are running now.\n\nA short note for {} was saved here:\n{}", diagnostics::site::operator(), path.display()),
        None => "Diagnostic Tool stopped unexpectedly. No checks are running now.".to_string(),
    };
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(&text).as_ptr(),
            wide("Diagnostic Tool").as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        )
    };
}

/// Names a fault like `0xC0000005 at user32.dll+0x24702`.
fn fault_text(code: u32, module: Option<&str>, offset: usize) -> String {
    let name = module
        .and_then(|path| path.rsplit(['\\', '/']).next())
        .unwrap_or("unknown module");
    format!("Exception 0x{code:08X} at {name}+0x{offset:X}")
}

/// A native fault (an access violation, say) ends the process wherever it happens, so the
/// note is written and the friend told from the faulting thread. Windows Error Reporting
/// still sees the fault afterwards.
unsafe extern "system" fn on_fault(info: *const EXCEPTION_POINTERS) -> i32 {
    static ONCE: AtomicBool = AtomicBool::new(false);
    if ONCE.swap(true, Ordering::SeqCst) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let record = unsafe { &*(*info).ExceptionRecord };
    let address = record.ExceptionAddress as usize;
    let mut module: HMODULE = std::ptr::null_mut();
    let mut path = [0u16; 260];
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            address as *const u16,
            &mut module,
        )
    } != 0;
    let name = found.then(|| {
        let len = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) };
        String::from_utf16_lossy(&path[..len as usize])
    });
    let offset = if found {
        address - module as usize
    } else {
        address
    };
    let cause = format!(
        "{}\r\n{}",
        fault_text(record.ExceptionCode as u32, name.as_deref(), offset),
        std::backtrace::Backtrace::force_capture()
    );
    let thread = std::thread::current();
    let saved = write_crash_note(thread.name().unwrap_or("worker"), &cause);
    // The message box runs on its own thread: a box on this thread would dispatch this
    // thread's paint messages and fault again.
    let _ = std::thread::spawn(move || tell_friend(saved.as_deref())).join();
    EXCEPTION_CONTINUE_SEARCH
}

/// A panic or a native fault writes a short note beside the reports. A panic on the window
/// thread ends the app, so the friend is told where the note is; a worker panic only marks
/// its check.
fn install_crash_note() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("worker");
        let saved = write_crash_note(name, &info.to_string());
        if name == "main" {
            tell_friend(saved.as_deref());
        }
    }));
    unsafe { SetUnhandledExceptionFilter(Some(on_fault)) };
}

/// Brings an already running copy forward. Returns true when one exists.
fn focus_running_copy() -> bool {
    let mutex = unsafe {
        CreateMutexW(
            std::ptr::null(),
            0,
            wide("Local\\DiagnosticTool.Session").as_ptr(),
        )
    };
    if mutex.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        // The handle stays open for the life of the process.
        return false;
    }
    for class in [app::CLASS, "DiagnosticToolDialog"] {
        let hwnd = unsafe { FindWindowW(wide(class).as_ptr(), std::ptr::null()) };
        if !hwnd.is_null() {
            unsafe {
                if IsIconic(hwnd) != 0 {
                    ShowWindow(hwnd, SW_RESTORE);
                }
                SetForegroundWindow(hwnd);
            }
            break;
        }
    }
    true
}

/// Pixels the start heading has on its one line at `dpi`, beside the icon.
fn heading_room(dpi: u32) -> i32 {
    use diagnostics::ui_layout::{grid, scale};
    scale(dpi, grid::DIALOG_WIDTH) - 2 * scale(dpi, grid::OUTER) - scale(dpi, 54)
}

/// Every Windows display scale step, 100 % to 500 %, as DPI.
const SCALE_DPIS: [u32; 12] = [96, 120, 144, 168, 192, 216, 240, 288, 336, 384, 432, 480];

/// Whether `text` fits the heading's line at every scale step the window can run at.
fn heading_fits(text: &str) -> bool {
    SCALE_DPIS.into_iter().all(|dpi| {
        ui::text_width(std::ptr::null_mut(), ui::fonts(dpi).title, text) <= heading_room(dpi)
    })
}

/// The generic heading, which a test proves fits; the fallback for any name too wide.
const GENERIC_HEADING: &str = "Your technician will fix this PC";

/// The full heading when it fits, else the shorter one, else the generic one, so the
/// heading never ellipsizes; `name` starts the sentence.
fn heading_for(name: &str) -> String {
    let long = format!("{name} will check and fix this PC");
    let short = format!("{name} will fix this PC");
    [long, short]
        .into_iter()
        .find(|text| heading_fits(text))
        .unwrap_or_else(|| GENERIC_HEADING.into())
}

/// The start screen's heading, chosen by measurement so it stays on one line.
fn start_heading() -> String {
    heading_for(diagnostics::site::operator_first())
}

/// The start screen. Asking for help and choosing Start is the friend's authorization.
fn consent(remote: bool) -> Dialog {
    let intro = if remote {
        format!("Choose Start and the tool checks the whole system while you work, shows a code to read to {} and saves a findings report in your Documents folder. Closing the window ends it.", diagnostics::site::operator())
    } else {
        "Choose Start and the tool checks the whole system while you work and saves a findings report in your Documents folder. Closing the window ends it.".into()
    };
    Dialog {
        window_title: "Diagnostic Tool".into(),
        heading: start_heading(),
        intro,
        sections: vec![Section {
            heading: Some("What it reads".into()),
            items: vec![
                Item::Yes("Windows, hardware, drive, event, crash and update information".into()),
                Item::No("Not your personal files, passwords or screen".into()),
            ],
        }],
        accept: "Start".into(),
        decline: Some("Close".into()),
        copy: None,
    }
}

/// After a self-update the new copy waits for the old one to close, then removes the
/// program the update moved aside.
fn after_update() {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
    };
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("--after-update") {
        if let Some(pid) = args.next().and_then(|pid| pid.parse::<u32>().ok()) {
            let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if !process.is_null() {
                unsafe {
                    WaitForSingleObject(process, 15_000);
                    windows_sys::Win32::Foundation::CloseHandle(process);
                }
            }
        }
    }
    if let Ok(program) = std::env::current_exe() {
        diagnostics::update::remove_old(&program);
    }
}

/// Says why a launch could not go on.
fn tell_launch_failed(why: &str) {
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(why).as_ptr(),
            wide("Diagnostic Tool").as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

/// The elevated recovery copy: no consent and no check session, its own single-instance
/// mutex so it runs beside the normal window, only the recovery windows, and it ends when
/// the last of them closes. A second launch hands its arguments to the running copy.
fn run_recovery(args: &[String]) {
    let mutex = unsafe {
        CreateMutexW(
            std::ptr::null(),
            0,
            wide("Local\\DiagnosticTool.Recovery").as_ptr(),
        )
    };
    if !mutex.is_null() && unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        if let Err(why) = relaunch::forward(args) {
            tell_launch_failed(&why);
        }
        return;
    }
    // An exclusion from crash dumps a recovery window left when it ended without letting
    // go is put back first.
    diagnostics::tools::crash_dumps::settle_left_exclusion();
    // What an earlier recovery window left not yet put back when it ended, or was killed,
    // is put back next, and this window's own changes are journalled from here.
    let settled = diagnostics::recovery::pending::settle_at_start();
    ui::start_gdiplus();
    ui::refresh_palette();
    // What it found is said before the window opens: only a footer and a read limit
    // proven to be the ended run's are put back; the rest is for the technician.
    if !settled.is_empty() {
        dialog::show(
            std::ptr::null_mut(),
            &Dialog {
                window_title: "Recovery".into(),
                heading: "An earlier recovery window ended before it had put everything back"
                    .into(),
                intro: "This is also in the session's change record.".into(),
                sections: vec![Section {
                    heading: None,
                    items: settled.into_iter().map(Item::Para).collect(),
                }],
                accept: "OK".into(),
                decline: None,
                copy: None,
            },
        );
    }
    let Some(listener) = relaunch::listen() else {
        return;
    };
    if let Err(why) = relaunch::accept(args, &mut recovery_view::open_main) {
        tell_launch_failed(&why);
        return;
    }
    message_loop(listener);
    // The window is gone; every change still in flight and every change held to be undone
    // ends, with its undo, before the process does, since ending would cut it off: each is
    // waited for as long as it stated, in a small window saying what is being put back.
    // What Windows has still not answered then is entered in the change record, and the
    // next start settles it from the journal.
    let left = ending_view::wait_for_duties(message_loop);
    for what in &left {
        diagnostics::handles::record_unseen(
            "Not yet put back when the recovery window ended",
            &format!(
                "Still {what}; the recovery window says what it finds of it when it next starts."
            ),
        );
    }
}

fn main() {
    install_crash_note();
    unsafe {
        // DLLs load from System32 only, never from the folder the exe was downloaded to.
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        // The manifest declares this too; the call covers a build without resources.
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }
    let args: Vec<String> = std::env::args().collect();
    // Debug builds only: opens the recovery key sign-in window on its own.
    #[cfg(debug_assertions)]
    if args.get(1).map(String::as_str) == Some("--key-lookup-demo") {
        ui::start_gdiplus();
        ui::refresh_palette();
        keylookup_view::demo(&args[2..]);
        return;
    }
    // Debug builds only: opens the processor and memory window on its own at a tab.
    #[cfg(debug_assertions)]
    if args.get(1).map(String::as_str) == Some("--cpu-memory-demo") {
        ui::start_gdiplus();
        ui::refresh_palette();
        cpumem_view::demo(&args[2..]);
        return;
    }
    if let Some(code) = run_command_line(&args) {
        std::process::exit(code);
    }
    if let Some(launch) = recovery_view::parse_args(&args) {
        if let Some(record) = launch.ok().and_then(|launch| launch.record) {
            diagnostics::change_record::use_file(record);
        }
        run_recovery(&args);
        return;
    }
    if crashdump_view::run_if_asked(&args) {
        return;
    }
    after_update();
    if focus_running_copy() {
        return;
    }
    ui::start_gdiplus();
    ui::refresh_palette();
    if !dialog::show(std::ptr::null_mut(), &consent(remote::remote_enabled())) {
        return;
    }
    let Some(window) = app::open() else {
        return;
    };
    message_loop(window);
}

/// Set by Ctrl+C or the console closing, for the command line recover to stop cleanly.
static STOP: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn stop_on_ctrl_c(_event: u32) -> i32 {
    STOP.store(true, Ordering::Relaxed);
    1
}

/// The command line modes: help, and the file recover without a window. A GUI-subsystem
/// exe starts with no console, so it attaches to its parent's to print there; when the
/// parent has none (output redirected to a pipe or file) the redirected handles already
/// work. Returns the exit value, None when the command line is not one of these.
fn run_command_line(args: &[String]) -> Option<i32> {
    use diagnostics::recovery::headless::{self, Command, Exit};
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetConsoleCtrlHandler, SetStdHandle, ATTACH_PARENT_PROCESS,
        STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };
    let parsed = headless::parse(args)?;
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
        for (which, name) in [
            (STD_OUTPUT_HANDLE, "CONOUT$"),
            (STD_ERROR_HANDLE, "CONOUT$"),
        ] {
            let handle = GetStdHandle(which);
            if handle.is_null() || handle as isize == -1 {
                if let Ok(console) = OpenOptions::new().write(true).open(name) {
                    SetStdHandle(which, console.into_raw_handle() as _);
                }
            }
        }
        SetConsoleCtrlHandler(Some(stop_on_ctrl_c), 1);
    }
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let exit = match parsed {
        Ok(Command::Help) => {
            let _ = out.write_all(headless::USAGE.as_bytes());
            Exit::Complete
        }
        Ok(Command::Recover(request)) => {
            headless::run(&request, &STOP, headless::EVERY, &mut out, &mut err)
        }
        Err(why) => {
            let _ = writeln!(err, "{why}\n\n{}", headless::USAGE);
            Exit::Usage
        }
    };
    Some(exit as i32)
}

/// Runs until WM_QUIT; Tab and Enter work in whichever of our windows has the message.
fn message_loop(window: HWND) {
    let mut message: MSG = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) } > 0 {
        unsafe {
            // Tab and Enter work in whichever of our windows has the message.
            let root = GetAncestor(message.hwnd, GA_ROOT);
            let target = if root.is_null() { window } else { root };
            if IsDialogMessageW(target, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

#[cfg(all(test, not(feature = "live_support")))]
mod tests {
    #[test]
    fn empty_text_draws_and_measures() {
        use windows_sys::Win32::Graphics::Gdi::{
            CreateCompatibleDC, DeleteDC, GetStockObject, DEFAULT_GUI_FONT, DT_END_ELLIPSIS,
            DT_SINGLELINE, HFONT,
        };
        let dc = unsafe { CreateCompatibleDC(std::ptr::null_mut()) };
        let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) } as HFONT;
        let rect = windows_sys::Win32::Foundation::RECT {
            left: 0,
            top: 0,
            right: 200,
            bottom: 20,
        };
        crate::ui::draw_text(dc, "", &rect, font, 0, DT_SINGLELINE | DT_END_ELLIPSIS);
        assert_eq!(crate::ui::text_width(std::ptr::null_mut(), font, ""), 0);
        assert_eq!(
            crate::ui::text_height(std::ptr::null_mut(), font, "", 200),
            0
        );
        unsafe { DeleteDC(dc) };
    }

    /// Every row text the in-process checks can produce (the event survey, App crashes,
    /// Service failures, Hardware and driver events, drive space, drive health and crash
    /// dump readiness) fits its place in the window, measured in the window's own font at
    /// 96 DPI.
    #[test]
    fn event_briefs_fit_the_check_row() {
        use diagnostics::ui_layout::{grid, main_layout};
        let row = main_layout(96, diagnostics::checks::CHECKS.len(), 1).rows[0];
        let room = row.w - grid::ROW_LABEL_X - grid::ROW_LABEL_W - 2 * grid::ROW_TEXT_GAP;
        let font = crate::ui::fonts(96).body;
        let briefs = diagnostics::checks::widest_briefs();
        assert!(briefs.len() > 100, "only {} row texts listed", briefs.len());
        let too_wide: Vec<String> = briefs
            .iter()
            .filter_map(|brief| {
                let width = crate::ui::text_width(std::ptr::null_mut(), font, brief);
                (width > room).then(|| format!("{brief:?} is {width} px"))
            })
            .collect();
        assert!(
            too_wide.is_empty(),
            "the row has {room} px: {}",
            too_wide.join("; ")
        );
    }

    /// The start screen says the operator fixes the PC, what is read and how to end it, and asks
    /// for no approval beyond Start.
    #[test]
    fn start_screen_says_the_operator_fixes_and_closing_ends_it() {
        use crate::dialog::Item;
        for remote in [false, true] {
            let dialog = super::consent(remote);
            assert_eq!(dialog.heading, super::start_heading());
            assert!(dialog.intro.contains("Closing the window ends it."));
            assert_eq!(dialog.accept, "Start");
            assert_eq!(dialog.decline.as_deref(), Some("Close"));
            assert_eq!(
                remote,
                dialog.intro.contains(&format!(
                    "code to read to {}",
                    diagnostics::site::operator()
                ))
            );
            let mut texts = vec![dialog.heading.clone(), dialog.intro.clone()];
            for item in dialog.sections.iter().flat_map(|section| &section.items) {
                if let Item::Yes(text) | Item::No(text) | Item::Para(text) = item {
                    texts.push(text.clone());
                }
                if let Item::No(text) = item {
                    assert!(!text.to_lowercase().contains("repair"), "{text}");
                    assert!(!text.to_lowercase().contains("change"), "{text}");
                }
            }
            for text in &texts {
                assert!(!text.to_lowercase().contains("approv"), "{text}");
            }
        }
    }

    /// The heading is one line with an ellipsis, so it must fit beside the icon.
    #[test]
    fn start_screen_heading_fits_one_line() {
        let heading = super::consent(false).heading;
        assert!(super::heading_fits(&heading), "{heading}");
    }

    /// Whatever the name, the chosen heading fits, falling back to the generic one.
    #[test]
    fn any_name_gives_a_heading_that_fits() {
        assert!(super::heading_fits(super::GENERIC_HEADING));
        for name in [
            "Avery",
            "Your technician",
            "\u{FF37}".repeat(12).as_str(),
            "\u{5B57}".repeat(12).as_str(),
        ] {
            let heading = super::heading_for(name);
            assert!(super::heading_fits(&heading), "{heading}");
        }
    }

    /// The cap is the largest name of the widest glyph whose short heading fits at every DPI.
    #[test]
    fn the_operator_name_cap_is_the_largest_that_fits() {
        use diagnostics::site_rules::OPERATOR_NAME_MAX;
        let short = |n: usize| format!("{} will fix this PC", "W".repeat(n));
        assert!(super::heading_fits(&short(OPERATOR_NAME_MAX)));
        assert!(!super::heading_fits(&short(OPERATOR_NAME_MAX + 1)));
        let widest = "W".repeat(OPERATOR_NAME_MAX);
        assert_eq!(super::heading_for(&widest), short(OPERATOR_NAME_MAX));
        assert_eq!(super::heading_for("Al"), "Al will check and fix this PC");
    }

    #[test]
    fn a_fault_note_names_the_module_and_offset() {
        assert_eq!(
            super::fault_text(
                0xC000_0005,
                Some(r"C:\WINDOWS\System32\user32.dll"),
                0x24702
            ),
            "Exception 0xC0000005 at user32.dll+0x24702"
        );
        assert_eq!(
            super::fault_text(0xC000_0005, None, 0x10),
            "Exception 0xC0000005 at unknown module+0x10"
        );
    }

    #[test]
    fn ordinary_gui_build_has_no_remote_session() {
        assert!(!super::remote::remote_enabled());
    }
}
