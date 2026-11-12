//! The screenshot mode, `DiagnosticTool.exe --screenshots <folder>` in a debug build: each
//! main window opens with the made-up readings of `screenshot_data`, on a desktop of its own
//! so nothing shows on the user's screen or taskbar, and its client area is captured with
//! PrintWindow at `DPI` and written as a PNG. Readings of this PC are forbidden throughout.
use std::cell::RefCell;
use std::path::{Path, PathBuf};

use diagnostics::recovery::SourceChoice;
use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    ClientToScreen, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GdiFlush, GetDC,
    ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
};
use windows_sys::Win32::Storage::Xps::{PrintWindow, PW_CLIENTONLY};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, SetThreadDesktop, HDESK,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::cpumem_view::{self, CpuMemView, Tab};
use crate::dialog::{self, Dialog};
use crate::drive_view::DriveView;
use crate::event_view::EventView;
use crate::recover_files::{RecoverPage, TypePage};
use crate::recovery_view::{self, RecoveryView};
use crate::rescue_copy_view::CopyView;
use crate::rescue_image_view::ImageView;
use crate::screenshot_data as data;
use crate::space_view::SpaceView;
use crate::toolwin::{self, Page};
use crate::ui::{self, wide};

/// Every image is laid out at 150 %, whatever the monitor's scale.
pub const DPI: u32 = 144;

/// The subclass id of `unbounded`.
const UNBOUNDED: usize = 0x5348;

/// Writes every screenshot into the folder named in `args`; the process's exit code.
pub fn run(args: &[String]) -> i32 {
    let [folder] = args else {
        eprintln!("usage: DiagnosticTool.exe --screenshots <folder>");
        return 2;
    };
    let folder = PathBuf::from(folder);
    diagnostics::live::forbid();
    let worker = std::thread::Builder::new()
        .name("screenshots".into())
        .spawn(move || on_own_desktop(|| take_all(&folder)));
    let (outcome, desktop) = match worker.map(std::thread::JoinHandle::join) {
        Ok(Ok(done)) => done,
        Ok(Err(_)) => (
            Err("the screenshot thread stopped unexpectedly".into()),
            None,
        ),
        Err(error) => (
            Err(format!("no thread for the screenshots ({error})")),
            None,
        ),
    };
    // The thread that used the desktop has ended, so it can be closed now.
    if let Some(desktop) = desktop {
        unsafe { CloseDesktop(desktop as HDESK) };
    }
    let reached = diagnostics::live::reached();
    match outcome {
        Ok(written) if reached.is_empty() => {
            for line in written {
                println!("{line}");
            }
            0
        }
        Ok(_) => {
            eprintln!(
                "screenshots: these were read from this PC: {}",
                reached.join(", ")
            );
            1
        }
        Err(why) => {
            eprintln!("screenshots: {why}");
            1
        }
    }
}

/// Runs `work` on this thread with a new desktop as the thread's desktop, so its windows are
/// never on the user's. Returns the desktop's handle for closing once the thread has ended.
fn on_own_desktop(
    work: impl FnOnce() -> Result<Vec<String>, String>,
) -> (Result<Vec<String>, String>, Option<isize>) {
    let name = wide(&format!("DiagnosticToolScreenshots{}", std::process::id()));
    let desktop = unsafe {
        CreateDesktopW(
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            windows_sys::Win32::Foundation::GENERIC_ALL,
            std::ptr::null(),
        )
    };
    if desktop.is_null() {
        let error = unsafe { GetLastError() };
        return (
            Err(format!(
                "no desktop of its own could be made (error {error})"
            )),
            None,
        );
    }
    if unsafe { SetThreadDesktop(desktop) } == 0 {
        let error = unsafe { GetLastError() };
        unsafe { CloseDesktop(desktop) };
        return (
            Err(format!(
                "the desktop of its own could not be used (error {error})"
            )),
            None,
        );
    }
    (work(), Some(desktop as isize))
}

/// The start screen as a build without an operator name shows it, whatever site.toml holds.
pub fn start_screen() -> Dialog {
    Dialog {
        heading: crate::heading_for(diagnostics::site::GENERIC_OPERATOR_FIRST),
        ..crate::consent(false)
    }
}

fn take_all(folder: &Path) -> Result<Vec<String>, String> {
    ui::force_dpi(DPI);
    ui::start_gdiplus();
    let hook = unsafe {
        SetWindowsHookExW(
            WH_CBT,
            Some(on_create),
            std::ptr::null_mut(),
            GetCurrentThreadId(),
        )
    };
    if hook.is_null() {
        return Err("windows could not be let grow past the screen".into());
    }
    let taken = take_each(folder);
    unsafe { UnhookWindowsHookEx(hook) };
    taken
}

/// Gives each top-level window this thread makes `unbounded`, as it is made.
unsafe extern "system" fn on_create(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
    if code == HCBT_CREATEWND as i32 {
        let create = &*(*(l as *const CBT_CREATEWNDW)).lpcs;
        if (create.style as u32) & WS_CHILD == 0 {
            SetWindowSubclass(w as HWND, Some(unbounded), UNBOUNDED, 0);
        }
    }
    CallNextHookEx(std::ptr::null_mut(), code, w, l)
}

/// Lets a window be larger than this PC's screen, which is the default limit, since every
/// image is laid out at `DPI` whatever the screen's size and scale.
unsafe extern "system" fn unbounded(
    hwnd: HWND,
    msg: u32,
    w: WPARAM,
    l: LPARAM,
    _: usize,
    _: usize,
) -> LRESULT {
    let result = DefSubclassProc(hwnd, msg, w, l);
    if msg == WM_GETMINMAXINFO {
        let info = &mut *(l as *mut MINMAXINFO);
        info.ptMaxTrackSize = POINT { x: 8_192, y: 8_192 };
    }
    result
}

fn take_each(folder: &Path) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(folder)
        .map_err(|error| format!("{} could not be made ({error})", folder.display()))?;
    let mut written = Vec::new();
    let mut save = |name: &str, image: Result<Image, String>| -> Result<(), String> {
        let image = image.map_err(|why| format!("{name}: {why}"))?;
        let path = folder.join(format!("{name}.png"));
        let bytes = write_png(&path, &image).map_err(|why| format!("{name}: {why}"))?;
        written.push(format!(
            "{} {}x{} {bytes} bytes",
            path.display(),
            image.width,
            image.height
        ));
        Ok(())
    };
    save(
        "start",
        capture_modal(std::ptr::null_mut(), &start_screen()),
    )?;
    let main = crate::app::open_finished(data::session(), data::report_path())
        .ok_or("the main window did not open")?;
    pump();
    save("main", capture(main))?;
    save(
        "hardware",
        capture_modal(main, &crate::app::hardware_dialog(&data::inventory())),
    )?;
    save(
        "drive-space",
        capture_tool(main, "space", || {
            Box::new(SpaceView::measured(
                'C',
                data::space_disk(),
                data::space_map(),
            ))
        }),
    )?;
    let events = data::events();
    let chosen = data::chosen_event(&events);
    let view = EventView::loaded(data::EVENTS_CHECK, events, chosen)
        .ok_or("the event viewer has no preset for its check")?;
    save(
        "events",
        capture_tool(main, &format!("events:{}", data::EVENTS_CHECK), || {
            Box::new(view)
        }),
    )?;
    save(
        "drive",
        capture_tool(main, "drive", || {
            Box::new(DriveView::read_as(data::drives(), Some(false)))
        }),
    )?;
    save(
        "cpu-graph",
        capture_tool(main, cpumem_view::KEY, || {
            Box::new(CpuMemView::read_as(
                Tab::Cpu,
                data::cpu_details(),
                data::cpu_samples(),
            ))
        }),
    )?;
    // The data recovery windows, all on one made-up failing drive.
    let source = SourceChoice::Disk(data::RECOVERY_DISK);
    save(
        "recovery",
        capture_tool(main, &recovery_view::key_of(&source), || {
            Box::new(RecoveryView::read_as(data::recovery_disk(), Some(true)))
        }),
    )?;
    save(
        "rescue-copy",
        capture_tool(main, "rescue-copy", || {
            Box::new(CopyView::copying(
                data::RECOVERY_DISK,
                data::recovery_disk().volumes,
                data::rescue_copy(),
            ))
        }),
    )?;
    save(
        "rescue-image",
        capture_tool(main, "rescue-image", || {
            Box::new(ImageView::mid_run(data::RECOVERY_DISK, data::rescue_run()))
        }),
    )?;
    let (about, protected) = data::recovery_source();
    save(
        "recover-files",
        capture_tool(main, "recover-files", || {
            Box::new(RecoverPage::listed(
                about.clone(),
                protected.clone(),
                data::recovery_volumes(),
                data::recovery_listing(),
                &data::RECOVER_CHECKED,
                data::good_versions(),
            ))
        }),
    )?;
    let (searched, unreadable) = data::carve_search();
    save(
        "files-by-type",
        capture_tool(main, "files-by-type", || {
            Box::new(TypePage::after_search(
                about,
                protected,
                data::carved(),
                &data::CARVED_CHECKED,
                searched,
                unreadable,
            ))
        }),
    )?;
    unsafe { DestroyWindow(main) };
    Ok(written)
}

/// Handles every message waiting on this thread, so posted layout and paint work is done.
fn pump() {
    let mut message: MSG = unsafe { std::mem::zeroed() };
    for _ in 0..10_000 {
        if unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) } == 0 {
            break;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

/// Opens a tool window over `make`'s page, lets it take its readings, captures it and closes it.
fn capture_tool(
    owner: HWND,
    key: &str,
    make: impl FnOnce() -> Box<dyn Page>,
) -> Result<Image, String> {
    toolwin::open(owner, key, make);
    let hwnd = toolwin::window_of(key).ok_or("the window did not open")?;
    for _ in 0..3 {
        toolwin::tick_now(hwnd);
        pump();
    }
    let image = capture(hwnd);
    unsafe { DestroyWindow(hwnd) };
    pump();
    image
}

thread_local! {
    static CAUGHT: RefCell<Option<Result<Image, String>>> = const { RefCell::new(None) };
}

/// Shows a modal dialog and captures it from inside its own message loop, then closes it.
fn capture_modal(owner: HWND, content: &Dialog) -> Result<Image, String> {
    CAUGHT.with(|caught| caught.borrow_mut().take());
    unsafe {
        SetTimer(
            std::ptr::null_mut(),
            0,
            USER_TIMER_MINIMUM,
            Some(catch_dialog),
        )
    };
    dialog::show(owner, content);
    pump();
    CAUGHT
        .with(|caught| caught.borrow_mut().take())
        .unwrap_or_else(|| Err("the dialog closed before it was captured".into()))
}

/// The thread timer `capture_modal` sets, run by the dialog's loop once it is shown.
unsafe extern "system" fn catch_dialog(_: HWND, _: u32, id: usize, _: u32) {
    KillTimer(std::ptr::null_mut(), id);
    // Only this mode's windows are on its desktop.
    let dialog = FindWindowW(wide("DiagnosticToolDialog").as_ptr(), std::ptr::null());
    let image = if dialog.is_null() {
        Err("the dialog did not open".to_string())
    } else {
        capture(dialog)
    };
    CAUGHT.with(|caught| *caught.borrow_mut() = Some(image));
    if dialog.is_null() {
        // Ends whatever loop is waiting; the dialog's loop declines on it.
        PostQuitMessage(0);
    } else {
        PostMessageW(dialog, WM_CLOSE, 0, 0);
    }
}

/// A captured client area, three bytes a pixel, rows top first.
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut client: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetClientRect(hwnd, &mut client) };
    (client.right, client.bottom)
}

/// The window's client area as the window draws it into a bitmap of its own. Windows draws
/// only the part of a window that lies on its desktop, which is the size of this PC's
/// screen, so a larger window is moved over the desktop part by part and the parts joined.
fn capture(hwnd: HWND) -> Result<Image, String> {
    let (width, height) = client_size(hwnd);
    if width <= 0 || height <= 0 {
        return Err("the window has no client area".into());
    }
    let mut desktop: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetWindowRect(GetDesktopWindow(), &mut desktop) };
    let (screen_w, screen_h) = (desktop.right - desktop.left, desktop.bottom - desktop.top);
    if screen_w <= 0 || screen_h <= 0 {
        return Err("the desktop has no size".into());
    }
    let mut frame: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetWindowRect(hwnd, &mut frame) };
    let mut origin = POINT { x: 0, y: 0 };
    unsafe { ClientToScreen(hwnd, &mut origin) };
    let (inset_x, inset_y) = (origin.x - frame.left, origin.y - frame.top);
    let row = width as usize * 3;
    let mut rgb = vec![0u8; row * height as usize];
    let mut taken = Ok(());
    'parts: for top in (0..height).step_by(screen_h as usize) {
        for left in (0..width).step_by(screen_w as usize) {
            // This part of the client area goes to the desktop's top left corner.
            unsafe {
                SetWindowPos(
                    hwnd,
                    std::ptr::null_mut(),
                    desktop.left - left - inset_x,
                    desktop.top - top - inset_y,
                    0,
                    0,
                    SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                )
            };
            if client_size(hwnd) != (width, height) {
                taken = Err("the window changed size as it was moved".to_string());
                break 'parts;
            }
            let part = match print(hwnd, width, height) {
                Ok(part) => part,
                Err(why) => {
                    taken = Err(why);
                    break 'parts;
                }
            };
            let (from, to) = (left as usize * 3, (left + screen_w).min(width) as usize * 3);
            for y in top as usize..(top + screen_h).min(height) as usize {
                rgb[y * row + from..y * row + to]
                    .copy_from_slice(&part[y * row + from..y * row + to]);
            }
        }
    }
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            frame.left,
            frame.top,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    taken?;
    let image = Image {
        width: width as u32,
        height: height as u32,
        rgb,
    };
    if colors(&image) < 16 {
        return Err("the capture is blank".into());
    }
    Ok(image)
}

/// The whole client area, `width` by `height`, as the window draws it with PrintWindow:
/// three bytes a pixel, rows top first.
fn print(hwnd: HWND, width: i32, height: i32) -> Result<Vec<u8>, String> {
    let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
    info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    let screen = unsafe { GetDC(std::ptr::null_mut()) };
    let bitmap = unsafe {
        CreateDIBSection(
            screen,
            &info,
            DIB_RGB_COLORS,
            &mut bits,
            std::ptr::null_mut(),
            0,
        )
    };
    let memory = unsafe { CreateCompatibleDC(screen) };
    unsafe { ReleaseDC(std::ptr::null_mut(), screen) };
    if bitmap.is_null() || bits.is_null() || memory.is_null() {
        unsafe {
            DeleteObject(bitmap);
            DeleteDC(memory);
        }
        return Err("no bitmap for the capture".into());
    }
    let old = unsafe { SelectObject(memory, bitmap) };
    // PrintWindow has the window paint into the bitmap though no screen shows it.
    let printed = unsafe { PrintWindow(hwnd, memory, PW_CLIENTONLY) } != 0;
    unsafe { GdiFlush() };
    let len = width as usize * height as usize * 4;
    // SAFETY: the section holds `len` bytes of 32-bit pixels and lives until DeleteObject.
    let pixels = unsafe { std::slice::from_raw_parts(bits as *const u8, len) };
    let rgb: Vec<u8> = pixels
        .as_chunks::<4>()
        .0
        .iter()
        .flat_map(|&[b, g, r, _]| [r, g, b])
        .collect();
    unsafe {
        SelectObject(memory, old);
        DeleteObject(bitmap);
        DeleteDC(memory);
    }
    if !printed {
        return Err("PrintWindow drew nothing".into());
    }
    Ok(rgb)
}

/// How many different colors an image holds, counted up to 256.
fn colors(image: &Image) -> usize {
    let mut seen = std::collections::HashSet::new();
    for pixel in image.rgb.as_chunks::<3>().0 {
        seen.insert(*pixel);
        if seen.len() >= 256 {
            break;
        }
    }
    seen.len()
}

/// Writes the image as an 8-bit RGB PNG; the file's size in bytes.
fn write_png(path: &Path, image: &Image) -> Result<u64, String> {
    let file = std::fs::File::create(path)
        .map_err(|error| format!("{} could not be written ({error})", path.display()))?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), image.width, image.height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::High);
    let mut writer = encoder.write_header().map_err(|error| error.to_string())?;
    writer
        .write_image_data(&image.rgb)
        .map_err(|error| error.to_string())?;
    writer.finish().map_err(|error| error.to_string())?;
    std::fs::metadata(path)
        .map(|meta| meta.len())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start screen in the screenshots names no operator, whatever site.toml set.
    #[test]
    fn the_start_screen_shot_names_no_operator() {
        let dialog = start_screen();
        assert_eq!(
            dialog.heading,
            crate::heading_for(diagnostics::site::GENERIC_OPERATOR_FIRST)
        );
        assert!(
            dialog.heading.starts_with("Your technician"),
            "{}",
            dialog.heading
        );
        if let Some(name) = diagnostics::site::OPERATOR_NAME {
            let mut texts = vec![dialog.heading.clone(), dialog.intro.clone()];
            for item in dialog.sections.iter().flat_map(|section| &section.items) {
                if let dialog::Item::Yes(text) | dialog::Item::No(text) = item {
                    texts.push(text.clone());
                }
            }
            for text in texts {
                assert!(!text.contains(name), "{text}");
            }
        }
    }
}
