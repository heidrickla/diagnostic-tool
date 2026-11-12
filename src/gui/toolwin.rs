//! Tool windows opened from a result row: a themed, resizable window that hosts one page,
//! and the scrolling owner-drawn list the pages share. One window per tool; opening a tool
//! that is already open brings its window forward.
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;

use diagnostics::ui_layout::scale;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::GetStockObject;
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, InvalidateRect, MonitorFromWindow, ScreenToClient, SetBkColor,
    SetDCBrushColor, SetTextColor, DC_BRUSH, HDC, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    SetWindowTheme, DRAWITEMSTRUCT, MEASUREITEMSTRUCT, ODS_SELECTED, ODT_LISTBOX, WM_MOUSELEAVE,
};
use windows_sys::Win32::UI::HiDpi::AdjustWindowRectExForDpi;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetCapture, ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT, VK_RETURN, VK_SPACE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::dialog::{self, Dialog};
use crate::help_pane;
use crate::ui::{self, wide, Kind};
use diagnostics::ui_layout::{self, grid, Rect};

pub const CLASS: &str = "DiagnosticToolTool";
const STYLE: u32 = WS_OVERLAPPEDWINDOW;
const EX_STYLE: u32 = WS_EX_CONTROLPARENT;
/// Polls the page's background work.
const TIMER: usize = 1;
/// Posted by `fit` with a client height in pixels: grows the window to show it all.
const FIT: u32 = WM_APP + 1;
/// The notification code a list sends its parent when an item is clicked or Enter is pressed.
pub const ACTIVATE: u16 = 0x7F01;

/// A confirmation a page asks for; `then` is the command run if the user accepts.
pub struct Ask {
    pub dialog: Dialog,
    pub then: usize,
}

pub trait Page {
    fn title(&self) -> String;
    /// Client size in 96-dpi pixels to open at, and the smallest allowed.
    fn size(&self) -> ((i32, i32), (i32, i32));
    /// Creates the page's controls.
    fn build(&mut self, hwnd: HWND);
    /// Places the controls in a client area `w` by `h` pixels.
    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32);
    /// A button, edit or list notification. Returning an Ask shows it, and runs `then`
    /// through this same call if accepted.
    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask>;
    /// Called four times a second, to pick up background results.
    fn tick(&mut self, hwnd: HWND);
    /// Draws one item of one of the page's lists.
    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState);
    /// The pointer for a point on the window's own surface, outside any control.
    fn cursor_at(&self, _x: i32, _y: i32) -> Option<PCWSTR> {
        None
    }
    /// A button press, move or release on the window's own surface. Returning true from a
    /// press captures the mouse until the release.
    fn mouse(&mut self, _hwnd: HWND, _msg: u32, _x: i32, _y: i32) -> bool {
        false
    }
    /// Asked before the window closes: an Ask is shown, the window closes only if it is
    /// accepted, and `then` runs first.
    fn close_ask(&mut self) -> Option<Ask> {
        None
    }
    /// The client height in pixels the content needs at the last layout's width, lists at
    /// their preferred number of rows. The window opens at it, so no band is left empty.
    fn natural_height(&self) -> Option<i32> {
        None
    }
    /// The window's help topic (`help::topic`): its "?" button at the right of the title row
    /// opens the topic in a pane docked on the right. None for a window with no help yet.
    fn help_key(&self) -> Option<&'static str> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ItemState {
    pub selected: bool,
    pub hot: bool,
    pub dpi: u32,
}

thread_local! {
    static PAGES: RefCell<HashMap<isize, Box<dyn Page>>> = RefCell::new(HashMap::new());
    static OPEN: RefCell<HashMap<String, isize>> = RefCell::new(HashMap::new());
    /// Item heights in 96-dpi pixels by list control id, read during WM_MEASUREITEM.
    static HEIGHTS: RefCell<HashMap<usize, i32>> = RefCell::new(HashMap::new());
    /// Control ids of owner-drawn surfaces the page paints itself (`canvas`).
    static CANVASES: RefCell<std::collections::HashSet<usize>> = RefCell::new(Default::default());
    /// The tool group whose last window ends the message loop when it closes (`end_process_with`).
    static QUIT_WITH: RefCell<Option<String>> = const { RefCell::new(None) };
    /// What an empty list or text box says instead of nothing, by control (`set_empty`).
    static EMPTY: RefCell<HashMap<isize, String>> = RefCell::new(HashMap::new());
    /// The content height each window was last fitted to, so `fit` acts only on growth.
    static FITTED: RefCell<HashMap<isize, i32>> = RefCell::new(HashMap::new());
}

/// Runs `f` on a window's page with the page taken out of the map, so a nested message
/// (a dialog's loop, a synchronous notification) never finds it borrowed.
fn with_page<T>(hwnd: HWND, f: impl FnOnce(&mut dyn Page) -> T) -> Option<T> {
    let mut page = PAGES.with(|p| p.borrow_mut().remove(&(hwnd as isize)))?;
    let result = f(page.as_mut());
    // A page that closed its own window is dropped here, so its background work stops.
    if unsafe { IsWindow(hwnd) } != 0 {
        PAGES.with(|p| p.borrow_mut().insert(hwnd as isize, page));
    }
    Some(result)
}

/// Answers a WM_MEASUREITEM with the item height registered for its list.
///
/// # Safety
/// `l` must be the LPARAM of a WM_MEASUREITEM.
pub unsafe fn measure_item(hwnd: HWND, l: LPARAM) -> LRESULT {
    let item = &mut *(l as *mut MEASUREITEMSTRUCT);
    let height = HEIGHTS.with(|h| h.borrow().get(&(item.CtlID as usize)).copied());
    item.itemHeight = scale(ui::dpi_of(hwnd), height.unwrap_or(32)) as u32;
    1
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetClientRect(hwnd, &mut rect) };
    (rect.right, rect.bottom)
}

fn relayout(hwnd: HWND) {
    let (w, h) = client_size(hwnd);
    let dpi = ui::dpi_of(hwnd);
    let w = help_pane::place(hwnd, w, h, dpi);
    with_page(hwnd, |page| page.layout(hwnd, w, h, dpi));
    unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
}

/// The outer size for a client of `(w, h)` 96-dpi pixels laid out at `dpi`, with the frame
/// Windows draws at `frame_dpi`.
fn outer_size(dpi: u32, frame_dpi: u32, (w, h): (i32, i32)) -> (i32, i32) {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: scale(dpi, w),
        bottom: scale(dpi, h),
    };
    unsafe { AdjustWindowRectExForDpi(&mut rect, STYLE, 0, EX_STYLE, frame_dpi) };
    (rect.right - rect.left, rect.bottom - rect.top)
}

fn run_command(hwnd: HWND, id: usize, code: u16) {
    let ask = with_page(hwnd, |page| page.command(hwnd, id, code)).flatten();
    if let Some(ask) = ask {
        if dialog::show(hwnd, &ask.dialog) {
            with_page(hwnd, |page| page.command(hwnd, ask.then, 0));
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            ui::paint_surface(hwnd);
            0
        }
        WM_ERASEBKGND => 1,
        WM_SETCURSOR if w as HWND == hwnd && (l & 0xFFFF) as u32 == HTCLIENT => {
            let mut point = POINT { x: 0, y: 0 };
            GetCursorPos(&mut point);
            ScreenToClient(hwnd, &mut point);
            let cursor = PAGES.with(|p| {
                p.borrow()
                    .get(&(hwnd as isize))
                    .and_then(|page| page.cursor_at(point.x, point.y))
            });
            match cursor {
                Some(name) => {
                    SetCursor(LoadCursorW(std::ptr::null_mut(), name));
                    1
                }
                None => DefWindowProcW(hwnd, msg, w, l),
            }
        }
        WM_LBUTTONDOWN | WM_MOUSEMOVE | WM_LBUTTONUP | WM_RBUTTONUP => {
            let (x, y) = (
                (l & 0xFFFF) as i16 as i32,
                ((l >> 16) & 0xFFFF) as i16 as i32,
            );
            let capture = with_page(hwnd, |page| page.mouse(hwnd, msg, x, y)).unwrap_or(false);
            if msg == WM_LBUTTONDOWN && capture {
                SetCapture(hwnd);
            } else if msg == WM_LBUTTONUP && GetCapture() == hwnd {
                ReleaseCapture();
            }
            0
        }
        WM_MEASUREITEM => measure_item(hwnd, l),
        WM_DRAWITEM => {
            let item = &*(l as *const DRAWITEMSTRUCT);
            if item.CtlType != ODT_LISTBOX {
                let id = item.CtlID as usize;
                if !CANVASES.with(|c| c.borrow().contains(&id)) {
                    return ui::draw_item(l);
                }
                let state = ItemState {
                    selected: false,
                    hot: false,
                    dpi: ui::dpi_of(hwnd),
                };
                let rect = item.rcItem;
                ui::buffered_at_origin(item.hDC, &rect, |dc, local| {
                    with_page(hwnd, |page| page.draw_item(id, 0, dc, local, state));
                });
                return 1;
            }
            if let Some(done) = help_pane::draw(hwnd, l) {
                return done;
            }
            if item.itemID == u32::MAX {
                return 1;
            }
            let state = ItemState {
                selected: item.itemState & ODS_SELECTED != 0,
                hot: hot_item(item.hwndItem) == Some(item.itemID as usize),
                dpi: ui::dpi_of(hwnd),
            };
            let rect = item.rcItem;
            ui::buffered_at_origin(item.hDC, &rect, |dc, local| {
                with_page(hwnd, |page| {
                    page.draw_item(item.CtlID as usize, item.itemID as usize, dc, local, state)
                });
            });
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => {
            let colors = ui::current();
            let dc = w as HDC;
            SetTextColor(dc, colors.text);
            SetBkColor(dc, colors.card);
            SetDCBrushColor(dc, colors.card);
            GetStockObject(DC_BRUSH) as LRESULT
        }
        WM_COMMAND => {
            match w & 0xFFFF {
                help_pane::BUTTON => help_pane::toggle(hwnd, relayout),
                // The pane's paragraphs are to read; a click on one does nothing.
                help_pane::LIST => {}
                id => {
                    run_command(hwnd, id, ((w >> 16) & 0xFFFF) as u16);
                    fit_page(hwnd);
                }
            }
            0
        }
        WM_TIMER if w == TIMER => {
            with_page(hwnd, |page| page.tick(hwnd));
            fit_page(hwnd);
            0
        }
        FIT => {
            grow_to(hwnd, w as i32, l != 0);
            0
        }
        WM_SIZE => {
            relayout(hwnd);
            0
        }
        WM_GETMINMAXINFO => {
            if let Some((w, h)) = min_outer(hwnd) {
                let info = &mut *(l as *mut MINMAXINFO);
                info.ptMinTrackSize = POINT { x: w, y: h };
            }
            0
        }
        WM_DPICHANGED => {
            let suggested = &*(l as *const RECT);
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            relayout(hwnd);
            0
        }
        WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
            ui::refresh_palette();
            ui::style_frame(hwnd);
            InvalidateRect(hwnd, std::ptr::null(), 1);
            0
        }
        WM_CLOSE => {
            match with_page(hwnd, |page| page.close_ask()).flatten() {
                Some(ask) => {
                    if dialog::show(hwnd, &ask.dialog) {
                        with_page(hwnd, |page| page.command(hwnd, ask.then, 0));
                        DestroyWindow(hwnd);
                    }
                }
                None => {
                    DestroyWindow(hwnd);
                }
            }
            0
        }
        WM_DESTROY => {
            KillTimer(hwnd, TIMER);
            // Dropping the page drops its channels; background work sees the window gone.
            PAGES.with(|p| p.borrow_mut().remove(&(hwnd as isize)));
            let key = OPEN.with(|o| {
                let mut open = o.borrow_mut();
                let key = open
                    .iter()
                    .find(|(_, h)| **h == hwnd as isize)
                    .map(|(k, _)| k.clone());
                open.retain(|_, h| *h != hwnd as isize);
                key
            });
            ui::forget_window(hwnd);
            FITTED.with(|f| f.borrow_mut().remove(&(hwnd as isize)));
            help_pane::forget(hwnd);
            if key.is_some_and(|key| ends_process(&key)) {
                close_all();
                PostQuitMessage(0);
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

fn register() -> bool {
    static DONE: OnceLock<bool> = OnceLock::new();
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
/// A worker's result, polled from the window's timer: None while it runs, Some(Ok) once it
/// sent its result, and Some(Err(why)) when its thread ended without sending one, so a
/// window never shows a run as going on forever after its worker stopped.
pub fn poll_result<T>(result: &std::sync::mpsc::Receiver<T>) -> Option<Result<T, String>> {
    use std::sync::mpsc::TryRecvError;
    match result.try_recv() {
        Ok(done) => Some(Ok(done)),
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => Some(Err(
            "The run ended without a result: its work stopped with an internal error".into(),
        )),
    }
}

/// Waits for a worker that ended without a result, and gives `why` with what it stopped
/// on, when its thread said.
pub fn without_result(why: String, worker: Option<std::thread::JoinHandle<()>>) -> String {
    let said = worker.and_then(|w| w.join().err()).and_then(|payload| {
        payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
    });
    match said {
        Some(said) => format!("{why} ({said})."),
        None => format!("{why}."),
    }
}

/// Restores a minimised window and brings it forward.
pub fn raise(hwnd: HWND) {
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        SetForegroundWindow(hwnd);
    }
}

/// Opens the tool `key` beside `owner`, or brings it forward if it is already open.
pub fn open(owner: HWND, key: &str, make: impl FnOnce() -> Box<dyn Page>) {
    if let Some(existing) = OPEN.with(|o| o.borrow().get(key).copied()) {
        raise(existing as HWND);
        return;
    }
    if !register() {
        return;
    }
    let mut page = make();
    let dpi = ui::dpi_of(owner);
    let (w, h) = outer_size(dpi, ui::frame_dpi(owner), page.size().0);
    let mut owner_rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetWindowRect(owner, &mut owner_rect) };
    let offset = scale(dpi, 32);
    let hwnd = unsafe {
        CreateWindowExW(
            EX_STYLE,
            wide(CLASS).as_ptr(),
            wide(&page.title()).as_ptr(),
            STYLE,
            owner_rect.left + offset,
            owner_rect.top + offset,
            w,
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return;
    }
    ui::style_frame(hwnd);
    page.build(hwnd);
    if let Some(key) = page.help_key() {
        help_pane::make(hwnd, key);
    }
    PAGES.with(|p| p.borrow_mut().insert(hwnd as isize, page));
    OPEN.with(|o| o.borrow_mut().insert(key.to_string(), hwnd as isize));
    relayout(hwnd);
    let natural = PAGES.with(|p| {
        p.borrow()
            .get(&(hwnd as isize))
            .and_then(|page| page.natural_height())
    });
    if let Some(natural) = natural {
        FITTED.with(|f| f.borrow_mut().insert(hwnd as isize, natural));
        grow_to(hwnd, natural, true);
    }
    unsafe {
        SetTimer(hwnd, TIMER, 250, None);
        ShowWindow(hwnd, SW_SHOW);
    }
}

/// Ends the message loop when the last window of the tool group `group` closes, after
/// closing the other tool windows: for a process whose only windows are that tool's. A
/// group is a key, and the keys `group:more` that a tool opens once per subject.
pub fn end_process_with(group: &str) {
    QUIT_WITH.with(|q| *q.borrow_mut() = Some(group.to_string()));
}

fn in_group(key: &str, group: &str) -> bool {
    key == group || key.strip_prefix(group).is_some_and(|r| r.starts_with(':'))
}

/// Whether the window of `closed` just went was the last of the group that ends the process.
fn ends_process(closed: &str) -> bool {
    QUIT_WITH.with(|q| {
        q.borrow().as_deref().is_some_and(|group| {
            in_group(closed, group) && !OPEN.with(|o| o.borrow().keys().any(|k| in_group(k, group)))
        })
    })
}

/// The window of tool `key`, if it is open.
pub fn window_of(key: &str) -> Option<HWND> {
    OPEN.with(|o| o.borrow().get(key).map(|h| *h as HWND))
}

/// Runs a window's tick now, as its timer would, for the screenshot mode.
#[cfg(debug_assertions)]
pub fn tick_now(hwnd: HWND) {
    unsafe { SendMessageW(hwnd, WM_TIMER, TIMER, 0) };
}

/// An owner-drawn surface the page paints itself: its `draw_item` is called with the
/// control id as the list and index 0, into a buffer starting at 0,0.
pub fn canvas(parent: HWND, id: usize) -> HWND {
    CANVASES.with(|c| c.borrow_mut().insert(id));
    unsafe {
        CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | windows_sys::Win32::System::SystemServices::SS_OWNERDRAW,
            0,
            0,
            0,
            0,
            parent,
            id as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    }
}

/// Repaints a canvas.
pub fn redraw(hwnd: HWND) {
    unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
}

/// Fits the window, once the current message is done, so its client area is `height`
/// pixels high: for a page whose content changed after it opened. While the window is the
/// height it was last fitted to, it follows the content both ways; once the user has
/// resized it, it only grows, so the user's size is never undone.
fn fit(hwnd: HWND, height: i32) {
    let (_, client_h) = client_size(hwnd);
    let exact = FITTED.with(|f| {
        let mut fitted = f.borrow_mut();
        let last = fitted.entry(hwnd as isize).or_insert(0);
        let exact = fit_exactly(*last, client_h, height)?;
        *last = height;
        Some(exact)
    });
    if let Some(exact) = exact {
        unsafe { PostMessageW(hwnd, FIT, height.max(0) as usize, isize::from(exact)) };
    }
}

/// Fits the window to its page's content height, after a command or a tick may have
/// changed what the page shows.
fn fit_page(hwnd: HWND) {
    let natural = PAGES.with(|p| {
        p.borrow()
            .get(&(hwnd as isize))
            .and_then(|page| page.natural_height())
    });
    if let Some(natural) = natural {
        fit(hwnd, natural);
    }
}

/// Whether a window last fitted to `last`, now `client_h` high, follows content `height`
/// exactly (it has not been resized since), only grows (it has), or is left alone (None).
fn fit_exactly(last: i32, client_h: i32, height: i32) -> Option<bool> {
    if height == last {
        None
    } else if client_h == last {
        Some(true)
    } else if height > last {
        Some(false)
    } else {
        None
    }
}

/// The smallest outer size the window may be dragged to: the page's smallest size, but no
/// taller than its content, so a window fitted to short content is not held open by a
/// minimum meant for long content.
fn min_outer(hwnd: HWND) -> Option<(i32, i32)> {
    let dpi = ui::dpi_of(hwnd);
    let (min, natural) = PAGES.with(|p| {
        p.borrow()
            .get(&(hwnd as isize))
            .map(|page| (page.size().1, page.natural_height()))
    })?;
    let (w, h) = outer_size(dpi, ui::frame_dpi(hwnd), min);
    let frame_h = outer_size(dpi, ui::frame_dpi(hwnd), (0, 0)).1;
    let pane = help_pane::room(hwnd, dpi);
    Some((w + pane, min_height(h, natural.map(|n| n + frame_h))))
}

/// The page's smallest height, capped at its content's height when it has one.
fn min_height(min: i32, natural: Option<i32>) -> i32 {
    natural.map_or(min, |n| min.min(n))
}

/// Sets the client height to `height` (exactly when `exact`, else only growing), within
/// the page's smallest size and the screen the window is on, keeping its top edge there.
fn grow_to(hwnd: HWND, height: i32, exact: bool) {
    let (_, client_h) = client_size(hwnd);
    if height <= 0 || (!exact && height <= client_h) {
        return;
    }
    let mut frame = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetWindowRect(hwnd, &mut frame) };
    let mut screen: MONITORINFO = unsafe { std::mem::zeroed() };
    screen.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    let work = if unsafe { GetMonitorInfoW(monitor, &mut screen) } != 0 {
        screen.rcWork
    } else {
        frame
    };
    let min_h = min_outer(hwnd).map_or(0, |(_, h)| h);
    let outer_h = (frame.bottom - frame.top) - client_h + height;
    let outer_h = outer_h.max(min_h).min(work.bottom - work.top);
    let top = frame.top.min(work.bottom - outer_h).max(work.top);
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            frame.left,
            top,
            frame.right - frame.left,
            outer_h,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
}

// ---- empty panes -------------------------------------------------------------------------

const EMPTY_SUBCLASS: usize = 0x454D;

/// Sets the muted words a list or a read-only text box shows while it holds nothing, saying
/// what will appear there. Changing them repaints the pane.
pub fn set_empty(control: HWND, text: &str) {
    use windows_sys::Win32::UI::Shell::SetWindowSubclass;
    let before = EMPTY.with(|e| e.borrow_mut().insert(control as isize, text.to_string()));
    if before.is_none() {
        unsafe { SetWindowSubclass(control, Some(empty_proc), EMPTY_SUBCLASS, 0) };
    }
    if before.as_deref() != Some(text) {
        unsafe { InvalidateRect(control, std::ptr::null(), 1) };
    }
}

/// True when a list has no items, or a text box no text.
fn holds_nothing(control: HWND) -> bool {
    let mut class = [0u16; 16];
    let len = unsafe { GetClassNameW(control, class.as_mut_ptr(), class.len() as i32) };
    let class = String::from_utf16_lossy(&class[..len.max(0) as usize]);
    if class.eq_ignore_ascii_case("ListBox") {
        unsafe { SendMessageW(control, LB_GETCOUNT, 0, 0) == 0 }
    } else {
        unsafe { GetWindowTextLengthW(control) == 0 }
    }
}

unsafe extern "system" fn empty_proc(
    hwnd: HWND,
    msg: u32,
    w: WPARAM,
    l: LPARAM,
    id: usize,
    _data: usize,
) -> LRESULT {
    use windows_sys::Win32::Graphics::Gdi::{BeginPaint, EndPaint, PAINTSTRUCT};
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass};
    match msg {
        WM_ERASEBKGND if holds_nothing(hwnd) => return 1,
        WM_PAINT if holds_nothing(hwnd) => {
            let mut paint: PAINTSTRUCT = std::mem::zeroed();
            let dc = BeginPaint(hwnd, &mut paint);
            let mut rect: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rect);
            let colors = ui::current();
            let dpi = ui::dpi_of(hwnd);
            ui::fill_rect(dc, &rect, colors.card);
            let text = EMPTY.with(|e| e.borrow().get(&(hwnd as isize)).cloned());
            let inner = RECT {
                left: rect.left + scale(dpi, 10),
                top: rect.top + scale(dpi, 8),
                right: rect.right - scale(dpi, 10),
                bottom: rect.bottom - scale(dpi, 8),
            };
            ui::draw_text(
                dc,
                &text.unwrap_or_default(),
                &inner,
                ui::fonts(dpi).body,
                colors.muted,
                windows_sys::Win32::Graphics::Gdi::DT_WORDBREAK,
            );
            EndPaint(hwnd, &paint);
            return 0;
        }
        // The words wrap to the pane's width.
        WM_SIZE => {
            InvalidateRect(hwnd, std::ptr::null(), 1);
        }
        WM_NCDESTROY => {
            EMPTY.with(|e| e.borrow_mut().remove(&(hwnd as isize)));
            RemoveWindowSubclass(hwnd, Some(empty_proc), id);
        }
        _ => {}
    }
    DefSubclassProc(hwnd, msg, w, l)
}

// ---- layout ------------------------------------------------------------------------------

/// Places a page's controls top to bottom in one column. Text takes the height its words
/// wrap to, and a text with nothing to say is hidden and takes no room, so a page's layout
/// leaves no empty band for a line that is not showing.
pub struct Flow {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub dpi: u32,
}

impl Flow {
    /// The column of a client area `w` pixels wide: the page margin each side, from the top.
    pub fn new(w: i32, dpi: u32) -> Self {
        let m = scale(dpi, grid::OUTER);
        Self {
            x: m,
            y: scale(dpi, 16),
            w: w - 2 * m,
            dpi,
        }
    }

    pub fn s(&self, v: i32) -> i32 {
        scale(self.dpi, v)
    }

    /// Adds `v` pixels at 96 dpi below what was placed last.
    pub fn space(&mut self, v: i32) {
        self.y += self.s(v);
    }

    /// A control the column's width and `h` pixels high.
    pub fn block(&mut self, hwnd: HWND, h: i32) {
        ui::place(
            hwnd,
            Rect {
                x: self.x,
                y: self.y,
                w: self.w,
                h,
            },
        );
        self.y += h;
    }

    /// The height a text control's words take at `width`, at least one line; 0 when empty.
    pub fn text_h(&self, hwnd: HWND, width: i32) -> i32 {
        let text = ui::window_text(hwnd);
        if text.is_empty() {
            return 0;
        }
        let fonts = ui::fonts(self.dpi);
        let font = if ui::kind(hwnd) == Some(Kind::Title) {
            fonts.title
        } else {
            fonts.body
        };
        ui::text_height(hwnd, font, &text, width).max(self.s(grid::BODY_H))
    }

    /// A text control at its wrapped height, then `after` pixels at 96 dpi; an empty one is
    /// hidden and takes no room.
    pub fn text(&mut self, hwnd: HWND, after: i32) {
        let h = self.text_h(hwnd, self.w);
        ui::show(hwnd, h > 0);
        if h > 0 {
            self.block(hwnd, h);
            self.space(after);
        }
    }

    /// The title and its muted line under it. The title leaves room at its right for the
    /// help button (`ui_layout::help_button`).
    pub fn header(&mut self, title: HWND, subtitle: HWND) {
        ui::place(
            title,
            Rect {
                x: self.x,
                y: self.y,
                w: self.w - ui_layout::help_room(self.dpi),
                h: self.s(grid::TITLE_H),
            },
        );
        self.y += self.s(grid::TITLE_H);
        self.space(2);
        self.text(subtitle, 10);
    }

    /// Visible buttons left to right at their captions' widths, wrapping to another row
    /// when the next would pass the right edge, then `after` pixels at 96 dpi.
    pub fn buttons(&mut self, buttons: &[HWND], after: i32) {
        let (bh, gap) = (self.s(grid::BUTTON_H), self.s(grid::BUTTON_GAP));
        let shown: Vec<HWND> = buttons
            .iter()
            .copied()
            .filter(|b| ui::visible(*b))
            .collect();
        if shown.is_empty() {
            return;
        }
        let mut x = self.x;
        for b in shown {
            let bw = ui::button_width(b, &ui::window_text(b)).min(self.w);
            if x > self.x && x + bw > self.x + self.w {
                x = self.x;
                self.y += bh + gap;
            }
            ui::place(
                b,
                Rect {
                    x,
                    y: self.y,
                    w: bw,
                    h: bh,
                },
            );
            x += bw + gap;
        }
        self.y += bh;
        self.space(after);
    }
}

/// The bottom row of a page: `left` buttons from the left edge, `right` ones against the
/// right edge, each at its caption's width. Returns the row's top.
pub fn footer(w: i32, h: i32, dpi: u32, left: &[HWND], right: &[HWND]) -> i32 {
    let s = |v: i32| scale(dpi, v);
    let (m, bh, gap) = (s(grid::OUTER), s(grid::BUTTON_H), s(grid::BUTTON_GAP));
    let top = h - m - bh;
    let mut x = m;
    for b in left.iter().filter(|b| ui::visible(**b)) {
        let bw = ui::button_width(*b, &ui::window_text(*b));
        ui::place(
            *b,
            Rect {
                x,
                y: top,
                w: bw,
                h: bh,
            },
        );
        x += bw + gap;
    }
    let mut x = w - m;
    for b in right.iter().rev().filter(|b| ui::visible(**b)) {
        let bw = ui::button_width(*b, &ui::window_text(*b));
        x -= bw;
        ui::place(
            *b,
            Rect {
                x,
                y: top,
                w: bw,
                h: bh,
            },
        );
        x -= gap;
    }
    top
}

/// The height the footer takes below a page's content: a gap, the buttons, the margin.
pub fn footer_h(dpi: u32) -> i32 {
    scale(dpi, grid::GAP + grid::BUTTON_H + grid::OUTER)
}

/// Closes every open tool window, for when the main window goes.
pub fn close_all() {
    let open: Vec<isize> = OPEN.with(|o| o.borrow().values().copied().collect());
    for hwnd in open {
        unsafe { DestroyWindow(hwnd as HWND) };
    }
}

// ---- the list --------------------------------------------------------------------------

static LIST_PROC: OnceLock<isize> = OnceLock::new();

/// The item under the pointer, stored in the list's user data as index + 1.
fn hot_item(list: HWND) -> Option<usize> {
    let word = unsafe { GetWindowLongPtrW(list, GWLP_USERDATA) };
    (word > 0).then(|| word as usize - 1)
}

fn set_hot(list: HWND, item: Option<usize>) {
    let word = item.map_or(0, |i| i as isize + 1);
    if unsafe { GetWindowLongPtrW(list, GWLP_USERDATA) } != word {
        unsafe {
            SetWindowLongPtrW(list, GWLP_USERDATA, word);
            InvalidateRect(list, std::ptr::null(), 0);
        }
    }
}

fn item_at(list: HWND, l: LPARAM) -> Option<usize> {
    const LB_ITEMFROMPOINT: u32 = 0x01A9;
    let result = unsafe { SendMessageW(list, LB_ITEMFROMPOINT, 0, l) } as usize;
    let count = unsafe { SendMessageW(list, LB_GETCOUNT, 0, 0) } as usize;
    let (index, outside) = (result & 0xFFFF, (result >> 16) & 0xFFFF);
    (outside == 0 && index < count).then_some(index)
}

fn activate(list: HWND) {
    let id = unsafe { GetDlgCtrlID(list) } as usize;
    let parent = unsafe { GetParent(list) };
    unsafe {
        PostMessageW(
            parent,
            WM_COMMAND,
            id | ((ACTIVATE as usize) << 16),
            list as LPARAM,
        )
    };
}

unsafe extern "system" fn list_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    let original: WNDPROC = std::mem::transmute(*LIST_PROC.get().unwrap_or(&0));
    let call = |msg, w, l| CallWindowProcW(original, hwnd, msg, w, l);
    match msg {
        WM_MOUSEMOVE => {
            let mut track = TRACKMOUSEEVENT {
                cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE,
                hwndTrack: hwnd,
                dwHoverTime: 0,
            };
            TrackMouseEvent(&mut track);
            set_hot(hwnd, item_at(hwnd, l));
        }
        WM_MOUSELEAVE => set_hot(hwnd, None),
        WM_MOUSEWHEEL => {
            let result = call(msg, w, l);
            // The item under the pointer changes as the list scrolls.
            let mut point = POINT {
                x: (l & 0xFFFF) as i16 as i32,
                y: ((l >> 16) & 0xFFFF) as i16 as i32,
            };
            ScreenToClient(hwnd, &mut point);
            let packed = ((point.y as u32 & 0xFFFF) << 16 | (point.x as u32 & 0xFFFF)) as LPARAM;
            set_hot(hwnd, item_at(hwnd, packed));
            return result;
        }
        WM_LBUTTONUP => {
            let result = call(msg, w, l);
            if item_at(hwnd, l).is_some() {
                activate(hwnd);
            }
            return result;
        }
        WM_GETDLGCODE if w == VK_RETURN as usize => {
            return call(msg, w, l) | DLGC_WANTALLKEYS as LRESULT;
        }
        WM_KEYDOWN if w == VK_RETURN as usize || w == VK_SPACE as usize => {
            if SendMessageW(hwnd, LB_GETCURSEL, 0, 0) >= 0 {
                activate(hwnd);
            }
            return 0;
        }
        _ => {}
    }
    call(msg, w, l)
}

/// Creates a scrolling owner-drawn list with items `height` pixels high at 96 dpi. Each
/// item's text is what screen readers announce; the page draws it.
pub fn list(parent: HWND, id: usize, height: i32) -> HWND {
    list_of(parent, id, height, LBS_OWNERDRAWFIXED as u32)
}

fn list_of(parent: HWND, id: usize, height: i32, drawn: u32) -> HWND {
    HEIGHTS.with(|h| h.borrow_mut().insert(id, height));
    let style = WS_CHILD
        | WS_VISIBLE
        | WS_TABSTOP
        | WS_VSCROLL
        | drawn
        | (LBS_HASSTRINGS | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT) as u32;
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            wide("LISTBOX").as_ptr(),
            std::ptr::null(),
            style,
            0,
            0,
            0,
            0,
            parent,
            id as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    if !ui::current().high_contrast {
        unsafe { SetWindowTheme(hwnd, wide("DarkMode_Explorer").as_ptr(), std::ptr::null()) };
    }
    let previous =
        unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, list_proc as *const () as isize) };
    let _ = LIST_PROC.set(previous);
    hwnd
}

/// Replaces a list's items, keeping the scroll position when `keep` is set.
pub fn set_items(list: HWND, items: &[String], keep: bool) {
    unsafe {
        let top = SendMessageW(list, LB_GETTOPINDEX, 0, 0);
        SendMessageW(list, WM_SETREDRAW, 0, 0);
        SendMessageW(list, LB_RESETCONTENT, 0, 0);
        SendMessageW(
            list,
            LB_INITSTORAGE,
            items.len(),
            (items.len() * 64) as LPARAM,
        );
        for item in items {
            SendMessageW(list, LB_ADDSTRING, 0, wide(item).as_ptr() as LPARAM);
        }
        if keep {
            SendMessageW(list, LB_SETTOPINDEX, top.max(0) as usize, 0);
        }
        SetWindowLongPtrW(list, GWLP_USERDATA, 0);
        SendMessageW(list, WM_SETREDRAW, 1, 0);
        InvalidateRect(list, std::ptr::null(), 1);
    }
}

/// How many items a list holds.
pub fn count(list: HWND) -> usize {
    unsafe { SendMessageW(list, LB_GETCOUNT, 0, 0) }.max(0) as usize
}

/// The selected item, if any.
pub fn selected(list: HWND) -> Option<usize> {
    let index = unsafe { SendMessageW(list, LB_GETCURSEL, 0, 0) };
    (index >= 0).then_some(index as usize)
}

pub fn select(list: HWND, index: Option<usize>) {
    let value = index.unwrap_or(usize::MAX);
    unsafe { SendMessageW(list, LB_SETCURSEL, value, 0) };
}

/// A list whose items each have their own height (`set_heights`), for rows whose text wraps
/// instead of being cut short.
pub fn list_wrapping(parent: HWND, id: usize, height: i32) -> HWND {
    list_of(parent, id, height, LBS_OWNERDRAWVARIABLE as u32)
}

/// Sets each item's height in pixels in a `list_wrapping` list, repainting only on a change.
pub fn set_heights(list: HWND, heights: &[i32]) {
    let mut changed = false;
    for (index, h) in heights.iter().enumerate() {
        // A list box keeps an item's height in a byte.
        let h = (*h).clamp(1, 255) as isize;
        if unsafe { SendMessageW(list, LB_GETITEMHEIGHT, index, 0) } != h {
            unsafe { SendMessageW(list, LB_SETITEMHEIGHT, index, h) };
            changed = true;
        }
    }
    if changed {
        unsafe { InvalidateRect(list, std::ptr::null(), 1) };
    }
}

/// A single-line edit for typing a filter, coloured like the cards.
pub fn search_box(parent: HWND, id: usize, cue: &str) -> HWND {
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            wide("EDIT").as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32,
            0,
            0,
            0,
            0,
            parent,
            id as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    const EM_SETCUEBANNER: u32 = 0x1501;
    unsafe { SendMessageW(hwnd, EM_SETCUEBANNER, 1, wide(cue).as_ptr() as LPARAM) };
    hwnd
}

// ---- the shell ---------------------------------------------------------------------------

/// Checks `folder` as output while a source that protects `protected` is read. The drive
/// being recovered, by its number or serial number, is refused. A disk that cannot be told
/// apart from it is put to the person, who checks it is not that drive;
/// a yes is kept in `protected.granted`, which every later check and writer honours. Err,
/// for a notice, when refused or declined.
pub fn confirm_destination(
    owner: HWND,
    folder: &std::path::Path,
    protected: &mut diagnostics::recovery::dest::Protected,
) -> Result<(), String> {
    loop {
        let refused = match diagnostics::recovery::destination_refusal(folder, protected) {
            Ok(()) => return Ok(()),
            Err(refused) => refused,
        };
        // A disk confirmed already and refused again was not cleared by the yes: say why.
        if refused.firm || refused.key.is_empty() || protected.granted.contains(&refused.key) {
            return Err(refused.why);
        }
        let asked = Dialog {
            window_title: "Check the output drive".into(),
            heading: format!("Is disk {} the drive being recovered?", refused.disk),
            intro: format!(
                "{} is on a disk that could not be told apart from the drive being recovered ({}). That drive must never be written. Check this disk's model, serial number and size against the drive you mean to write to.",
                folder.display(),
                refused.reason
            ),
            sections: vec![dialog::Section {
                heading: None,
                items: vec![
                    dialog::Item::Pair("Output folder".into(), folder.display().to_string()),
                    dialog::Item::Pair("On".into(), refused.about.clone()),
                ],
            }],
            accept: format!("Disk {} is not it; write there", refused.disk),
            decline: Some("Choose another folder".into()),
            copy: None,
        };
        if !dialog::show(owner, &asked) {
            return Err(format!(
                "{} is not written: choose a folder on another drive",
                folder.display()
            ));
        }
        protected.granted.push(refused.key);
    }
}

/// Asks for a folder with Windows' folder browser. None when cancelled.
pub fn pick_folder(owner: HWND, title: &str) -> Option<std::path::PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS,
        BROWSEINFOW,
    };
    let title = wide(title);
    let mut name = [0u16; 260];
    let info = BROWSEINFOW {
        hwndOwner: owner,
        pidlRoot: std::ptr::null_mut(),
        pszDisplayName: name.as_mut_ptr(),
        lpszTitle: title.as_ptr(),
        ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
        lpfn: None,
        lParam: 0,
        iImage: 0,
    };
    let item = unsafe { SHBrowseForFolderW(&info) };
    if item.is_null() {
        return None;
    }
    let mut path = [0u16; 1024];
    let ok = unsafe { SHGetPathFromIDListW(item, path.as_mut_ptr()) } != 0;
    unsafe { CoTaskMemFree(item as *const _) };
    let len = path.iter().position(|c| *c == 0)?;
    (ok && len > 0).then(|| std::path::PathBuf::from(String::from_utf16_lossy(&path[..len])))
}

/// Asks for an existing file with Windows' open dialog. `filter` is pairs of
/// "name\0pattern\0". None when cancelled.
pub fn pick_file(owner: HWND, title: &str, filter: &str) -> Option<std::path::PathBuf> {
    use windows_sys::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };
    let mut file = [0u16; 1024];
    let filter = wide(filter);
    let title = wide(title);
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = owner;
    dialog.lpstrFilter = filter.as_ptr();
    dialog.nFilterIndex = 1;
    dialog.lpstrFile = file.as_mut_ptr();
    dialog.nMaxFile = file.len() as u32;
    dialog.lpstrTitle = title.as_ptr();
    dialog.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        return None;
    }
    let len = file.iter().position(|value| *value == 0)?;
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &file[..len],
    )))
}

/// Opens a file or folder the way Explorer would. False when Windows refused.
pub fn open_path(owner: HWND, path: &std::path::Path) -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let code = unsafe {
        ShellExecuteW(
            owner,
            wide("open").as_ptr(),
            wide(&path.to_string_lossy()).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    code > 32
}

/// Opens Explorer at a file's folder with the file selected. False when Windows refused.
pub fn reveal(owner: HWND, path: &std::path::Path) -> bool {
    use windows_sys::Win32::UI::Shell::{ILCreateFromPathW, ILFree, SHOpenFolderAndSelectItems};
    let item = unsafe { ILCreateFromPathW(wide(&path.to_string_lossy()).as_ptr()) };
    if item.is_null() {
        return path.parent().is_some_and(|folder| open_path(owner, folder));
    }
    let result = unsafe { SHOpenFolderAndSelectItems(item, 0, std::ptr::null(), 0) };
    unsafe { ILFree(item) };
    result >= 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_group_holds_its_key_and_the_keys_opened_per_subject() {
        assert!(super::in_group("recovery", "recovery"));
        assert!(super::in_group("recovery:disk 3", "recovery"));
        assert!(!super::in_group("recoveryx", "recovery"));
        assert!(!super::in_group("image", "recovery"));
    }

    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A window fitted to short content can be that short: the page's smallest size does
    /// not hold it open past its content, and still holds a page with long content.
    /// A window nobody has resized follows its content down as well as up, so a line that
    /// goes away leaves no empty band; a window the user resized is only ever grown.
    #[test]
    fn an_untouched_window_follows_its_content_both_ways() {
        assert_eq!(fit_exactly(500, 500, 440), Some(true));
        assert_eq!(fit_exactly(500, 500, 560), Some(true));
        assert_eq!(fit_exactly(500, 700, 560), Some(false));
        assert_eq!(fit_exactly(500, 700, 440), None);
        assert_eq!(fit_exactly(500, 500, 500), None);
    }

    #[test]
    fn the_smallest_height_is_no_taller_than_the_content() {
        assert_eq!(min_height(600, Some(450)), 450);
        assert_eq!(min_height(600, Some(900)), 600);
        assert_eq!(min_height(600, None), 600);
    }

    /// A page that closes its own window from a button, and records being dropped.
    struct Probe(Rc<Cell<bool>>);

    impl Drop for Probe {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    impl Page for Probe {
        fn title(&self) -> String {
            "probe".into()
        }
        fn size(&self) -> ((i32, i32), (i32, i32)) {
            ((200, 100), (100, 50))
        }
        fn build(&mut self, _hwnd: HWND) {}
        fn layout(&mut self, _hwnd: HWND, _w: i32, _h: i32, _dpi: u32) {}
        fn command(&mut self, hwnd: HWND, _id: usize, _code: u16) -> Option<Ask> {
            unsafe { DestroyWindow(hwnd) };
            None
        }
        fn tick(&mut self, _hwnd: HWND) {}
        fn draw_item(&self, _: usize, _: usize, _: HDC, _: &RECT, _: ItemState) {}
    }

    #[test]
    fn a_page_that_closes_its_own_window_is_dropped() {
        let dropped = Rc::new(Cell::new(false));
        let probe = dropped.clone();
        open(std::ptr::null_mut(), "probe", move || {
            Box::new(Probe(probe))
        });
        let hwnd = OPEN
            .with(|o| o.borrow().get("probe").copied())
            .expect("opened") as HWND;
        run_command(hwnd, 1, 0);
        assert!(dropped.get(), "the page outlived its window");
        assert!(PAGES.with(|p| p.borrow().is_empty()));
        assert!(OPEN.with(|o| o.borrow().is_empty()));
    }

    /// The guard: a worker that ends without sending its result is seen as ended, with what
    /// it stopped on, never as still running.
    #[test]
    fn a_worker_that_ends_without_a_result_is_seen() {
        let (send, result) = std::sync::mpsc::channel::<u32>();
        assert_eq!(poll_result(&result), None);
        let worker = std::thread::spawn(move || {
            let _keep = send;
            panic!("the drive went away");
        });
        while !worker.is_finished() {
            std::thread::yield_now();
        }
        let why = poll_result(&result).unwrap().unwrap_err();
        let said = without_result(why, Some(worker));
        assert!(said.starts_with("The run ended without a result"), "{said}");
        assert!(said.contains("the drive went away"), "{said}");
        let (send, result) = std::sync::mpsc::channel::<u32>();
        send.send(7).unwrap();
        assert_eq!(poll_result(&result), Some(Ok(7)));
    }
}
