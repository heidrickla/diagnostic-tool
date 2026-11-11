//! One modal dialog component for the start screen and the hardware view. Enter takes
//! the focused button, Escape and Close decline.
use std::cell::{Cell, RefCell};

use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, InvalidateRect, MonitorFromPoint, MonitorFromWindow, MONITORINFO,
    MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::AdjustWindowRectExForDpi;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, GetFocus, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::ui::{self, wide, Kind, Tone};

pub enum Item {
    Para(String),
    Yes(String),
    No(String),
    Pair(String, String),
}

pub struct Section {
    pub heading: Option<String>,
    pub items: Vec<Item>,
}

pub struct Dialog {
    pub window_title: String,
    pub heading: String,
    pub intro: String,
    pub sections: Vec<Section>,
    pub accept: String,
    pub decline: Option<String>,
    /// A button that copies every pair to the clipboard, one "key: value" line each.
    pub copy: Option<String>,
}

const ACCEPT: usize = 101;
const DECLINE: usize = 102;
const COPY: usize = 103;
const STYLE: u32 = WS_POPUP | WS_CAPTION | WS_SYSMENU;
const EX_STYLE: u32 = WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME;

/// Built controls in layout order, kept for relayout on a DPI change.
enum Placed {
    Icon(HWND),
    Heading(HWND),
    Intro(HWND),
    SectionStart,
    SectionHeading(HWND),
    Item(HWND),
    /// A muted key and its value as selectable read-only text.
    Pair(HWND, HWND),
    SectionEnd,
    Buttons(HWND, Option<HWND>, Option<HWND>),
}

thread_local! {
    static RESULT: Cell<Option<bool>> = const { Cell::new(None) };
    static PLACED: RefCell<Vec<Placed>> = const { RefCell::new(Vec::new()) };
    static CLASS: Cell<u16> = const { Cell::new(0) };
    /// The text the copy button puts on the clipboard.
    static COPY_TEXT: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Every pair as "key: value" lines, the form the copy button puts on the clipboard.
pub fn copy_text(dialog: &Dialog) -> String {
    let mut lines = Vec::new();
    for section in &dialog.sections {
        if let Some(heading) = &section.heading {
            lines.push(String::new());
            lines.push(heading.clone());
        }
        for item in &section.items {
            match item {
                Item::Pair(key, value) => lines.push(format!("{key}: {value}")),
                Item::Para(text) => lines.push(text.clone()),
                Item::Yes(_) | Item::No(_) => {}
            }
        }
    }
    lines.join("\r\n").trim_start().to_string()
}

unsafe extern "system" fn dialog_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            ui::paint_surface(hwnd);
            0
        }
        WM_ERASEBKGND => 1,
        WM_DRAWITEM => ui::draw_item(l),
        // Read-only edits ask for their colours here; match the card they sit on.
        WM_CTLCOLORSTATIC => ui::selectable_colors(w as _),
        WM_COMMAND => {
            match w & 0xFFFF {
                ACCEPT => RESULT.with(|r| r.set(Some(true))),
                DECLINE => RESULT.with(|r| r.set(Some(false))),
                COPY => {
                    let copied = COPY_TEXT.with(|text| ui::copy_to_clipboard(hwnd, &text.borrow()));
                    let button = l as HWND;
                    let caption = if copied { "Copied" } else { "Copy failed" };
                    SetWindowTextW(button, wide(caption).as_ptr());
                    InvalidateRect(button, std::ptr::null(), 0);
                }
                _ => return DefWindowProcW(hwnd, msg, w, l),
            }
            0
        }
        WM_CLOSE => {
            RESULT.with(|r| r.set(Some(false)));
            0
        }
        WM_DPICHANGED => {
            let suggested = &*(l as *const RECT);
            layout(hwnd, Some((suggested.left, suggested.top)));
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

fn register() -> u16 {
    CLASS.with(|class| {
        if class.get() == 0 {
            let name = wide("DiagnosticToolDialog");
            let descriptor = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(dialog_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: unsafe { GetModuleHandleW(std::ptr::null()) },
                hIcon: crate::app_icon(),
                hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: name.as_ptr(),
            };
            class.set(unsafe { RegisterClassW(&descriptor) });
        }
        class.get()
    })
}

/// Sizes and places every control for the window's current DPI, then fits the window.
fn layout(hwnd: HWND, origin: Option<(i32, i32)>) {
    let dpi = ui::dpi_of(hwnd);
    let fonts = ui::fonts(dpi);
    let s = |v| scale(dpi, v);
    let width = s(grid::DIALOG_WIDTH);
    let inner_x = s(grid::OUTER);
    let inner_w = width - 2 * inner_x;
    let pad = s(grid::CARD_PAD);
    let mut y = s(grid::OUTER);
    let mut cards = Vec::new();
    let mut card_top = 0;
    let mut heading_x = inner_x;
    PLACED.with(|placed| {
        for item in placed.borrow().iter() {
            match item {
                Placed::Icon(icon) => {
                    ui::place(
                        *icon,
                        Rect {
                            x: inner_x,
                            y,
                            w: s(40),
                            h: s(40),
                        },
                    );
                    heading_x = inner_x + s(40) + s(14);
                }
                Placed::Heading(text) => {
                    let h = s(40);
                    ui::place(
                        *text,
                        Rect {
                            x: heading_x,
                            y,
                            w: inner_w - (heading_x - inner_x),
                            h,
                        },
                    );
                    y += h + s(12);
                }
                Placed::Intro(text) => {
                    let h = ui::text_height(*text, fonts.body, &ui::window_text(*text), inner_w);
                    ui::place(
                        *text,
                        Rect {
                            x: inner_x,
                            y,
                            w: inner_w,
                            h,
                        },
                    );
                    y += h + s(16);
                }
                Placed::SectionStart => {
                    card_top = y;
                    y += pad;
                }
                Placed::SectionHeading(text) => {
                    let h = s(grid::BODY_H);
                    ui::place(
                        *text,
                        Rect {
                            x: inner_x + pad,
                            y,
                            w: inner_w - 2 * pad,
                            h,
                        },
                    );
                    y += h + s(8);
                }
                Placed::Item(text) => {
                    let value = ui::window_text(*text);
                    let offset = if is_bullet(*text) { s(24) } else { 0 };
                    let measured = value;
                    let w = inner_w - 2 * pad;
                    let h = ui::text_height(*text, fonts.body, &measured, w - offset)
                        .max(s(grid::BODY_H));
                    ui::place(
                        *text,
                        Rect {
                            x: inner_x + pad,
                            y,
                            w,
                            h,
                        },
                    );
                    y += h + s(8);
                }
                Placed::Pair(key, value) => {
                    let w = inner_w - 2 * pad;
                    let offset = s(132);
                    ui::set_font(*value, fonts.body);
                    let text = ui::window_text(*value);
                    let h =
                        ui::text_height(*value, fonts.body, &text, w - offset).max(s(grid::BODY_H));
                    ui::place(
                        *key,
                        Rect {
                            x: inner_x + pad,
                            y,
                            w: offset - s(12),
                            h,
                        },
                    );
                    ui::place(
                        *value,
                        Rect {
                            x: inner_x + pad + offset,
                            y,
                            w: w - offset,
                            h,
                        },
                    );
                    y += h + s(8);
                }
                Placed::SectionEnd => {
                    y += pad - s(8);
                    cards.push(Rect {
                        x: inner_x,
                        y: card_top,
                        w: inner_w,
                        h: y - card_top,
                    });
                    y += s(16);
                }
                Placed::Buttons(accept, decline, copy) => {
                    y += s(8);
                    let accept_w = ui::button_width(*accept, &ui::window_text(*accept));
                    let decline_w = decline.map(|d| ui::button_width(d, &ui::window_text(d)));
                    if let Some(copy) = copy {
                        // Sized for its longest caption so "Copy failed" fits after a click.
                        let copy_w = ui::button_width(*copy, "Copy failed");
                        ui::place(
                            *copy,
                            Rect {
                                x: inner_x,
                                y,
                                w: copy_w,
                                h: s(grid::BUTTON_H),
                            },
                        );
                    }
                    let right = inner_x + inner_w;
                    let gap = s(grid::BUTTON_GAP);
                    let h = s(grid::BUTTON_H);
                    ui::place(
                        *accept,
                        Rect {
                            x: right - accept_w,
                            y,
                            w: accept_w,
                            h,
                        },
                    );
                    if let (Some(decline), Some(dw)) = (decline, decline_w) {
                        ui::place(
                            *decline,
                            Rect {
                                x: right - accept_w - gap - dw,
                                y,
                                w: dw,
                                h,
                            },
                        );
                    }
                    y += h;
                }
            }
        }
    });
    let height = y + s(grid::OUTER);
    let mut frame = RECT {
        left: 0,
        top: 0,
        right: width,
        bottom: height,
    };
    unsafe { AdjustWindowRectExForDpi(&mut frame, STYLE, 0, EX_STYLE, dpi) };
    let (fw, fh) = (frame.right - frame.left, frame.bottom - frame.top);
    let (x, y) = origin.unwrap_or_else(|| {
        let mut current = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        unsafe { GetWindowRect(hwnd, &mut current) };
        (current.left, current.top)
    });
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            x,
            y,
            fw,
            fh,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    ui::set_cards(hwnd, cards);
}

fn is_bullet(hwnd: HWND) -> bool {
    BULLETS.with(|bullets| bullets.borrow().contains(&(hwnd as isize)))
}

thread_local! {
    static BULLETS: RefCell<Vec<isize>> = const { RefCell::new(Vec::new()) };
}

/// The work area of the monitor showing the owner, or the cursor's monitor.
pub(crate) fn work_area(owner: HWND) -> RECT {
    let monitor = unsafe {
        if owner.is_null() {
            let mut cursor = POINT { x: 0, y: 0 };
            GetCursorPos(&mut cursor);
            MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST)
        } else {
            MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST)
        }
    };
    let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
    unsafe { GetMonitorInfoW(monitor, &mut info) };
    info.rcWork
}

/// Shows the dialog and returns true for the accept button. The caller holds no state lock.
pub fn show(owner: HWND, dialog: &Dialog) -> bool {
    RESULT.with(|r| r.set(None));
    if register() == 0 {
        return false;
    }
    let area = work_area(owner);
    let hwnd = unsafe {
        CreateWindowExW(
            EX_STYLE,
            wide("DiagnosticToolDialog").as_ptr(),
            wide(&dialog.window_title).as_ptr(),
            STYLE,
            area.left + 40,
            area.top + 40,
            200,
            200,
            owner,
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return false;
    }
    ui::style_frame(hwnd);
    let mut placed = vec![
        Placed::Icon(ui::text(hwnd, Kind::Icon, Tone::Neutral, false, "")),
        Placed::Heading(ui::text(
            hwnd,
            Kind::Title,
            Tone::Neutral,
            false,
            &dialog.heading,
        )),
    ];
    if !dialog.intro.is_empty() {
        placed.push(Placed::Intro(ui::text(
            hwnd,
            Kind::Muted,
            Tone::Neutral,
            false,
            &dialog.intro,
        )));
    }
    BULLETS.with(|b| b.borrow_mut().clear());
    for section in &dialog.sections {
        placed.push(Placed::SectionStart);
        if let Some(heading) = &section.heading {
            placed.push(Placed::SectionHeading(ui::text(
                hwnd,
                Kind::Heading,
                Tone::Neutral,
                true,
                heading,
            )));
        }
        for item in &section.items {
            let control = match item {
                Item::Para(text) => ui::text(hwnd, Kind::Body, Tone::Neutral, true, text),
                Item::Yes(text) | Item::No(text) => {
                    let tone = if matches!(item, Item::Yes(_)) {
                        Tone::Yes
                    } else {
                        Tone::No
                    };
                    let control = ui::text(hwnd, Kind::Bullet, tone, true, text);
                    BULLETS.with(|b| b.borrow_mut().push(control as isize));
                    control
                }
                Item::Pair(key, value) => {
                    let key = ui::text(hwnd, Kind::Muted, Tone::Neutral, true, key);
                    placed.push(Placed::Pair(key, ui::selectable(hwnd, value)));
                    continue;
                }
            };
            placed.push(Placed::Item(control));
        }
        placed.push(Placed::SectionEnd);
    }
    let decline = dialog
        .decline
        .as_ref()
        .map(|caption| ui::button(hwnd, DECLINE, Kind::Ghost, caption));
    let copy = dialog
        .copy
        .as_ref()
        .map(|caption| ui::button(hwnd, COPY, Kind::Ghost, caption));
    COPY_TEXT.with(|text| *text.borrow_mut() = copy_text(dialog));
    let accept = ui::button(hwnd, ACCEPT, Kind::Primary, &dialog.accept);
    placed.push(Placed::Buttons(accept, decline, copy));
    PLACED.with(|p| *p.borrow_mut() = placed);
    layout(hwnd, None);
    // Centre on the work area once the DPI-correct size is known.
    let mut frame = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetWindowRect(hwnd, &mut frame) };
    let (fw, fh) = (frame.right - frame.left, frame.bottom - frame.top);
    let x = area.left + ((area.right - area.left) - fw).max(0) / 2;
    let y = area.top + ((area.bottom - area.top) - fh).max(0) / 2;
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            x,
            y,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER,
        )
    };
    if !owner.is_null() {
        unsafe { EnableWindow(owner, 0) };
    }
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(accept);
        // Focus rings appear only once the keyboard is used, as in Windows' own dialogs.
        SendMessageW(hwnd, WM_CHANGEUISTATE, UIS_INITIALIZE as usize, 0);
    }
    let mut message: MSG = unsafe { std::mem::zeroed() };
    while RESULT.with(Cell::get).is_none() {
        if unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) } <= 0 {
            // WM_QUIT belongs to the outer loop; put it back and decline.
            unsafe { PostQuitMessage(message.wParam as i32) };
            RESULT.with(|r| r.set(Some(false)));
            break;
        }
        let ours = message.hwnd == hwnd || unsafe { IsChild(hwnd, message.hwnd) } != 0;
        if ours && message.message == WM_KEYDOWN {
            match message.wParam as u16 {
                0x1B => {
                    RESULT.with(|r| r.set(Some(false)));
                    continue;
                }
                0x0D => {
                    let focused = unsafe { GetDlgCtrlID(GetFocus()) } as usize;
                    RESULT.with(|r| r.set(Some(focused != DECLINE)));
                    continue;
                }
                _ => {}
            }
        }
        if unsafe { IsDialogMessageW(hwnd, &message) } != 0 {
            continue;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if !owner.is_null() {
        unsafe { EnableWindow(owner, 1) };
    }
    ui::forget_window(hwnd);
    unsafe { DestroyWindow(hwnd) };
    PLACED.with(|p| p.borrow_mut().clear());
    RESULT.with(Cell::get).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_all_gives_one_line_per_pair_under_its_section() {
        let dialog = Dialog {
            window_title: String::new(),
            heading: String::new(),
            intro: String::new(),
            sections: vec![
                Section {
                    heading: None,
                    items: vec![
                        Item::Pair("Processor".into(), "AMD Ryzen 9 7950X".into()),
                        Item::Pair("Board".into(), "ASUS ROG STRIX X670E-E".into()),
                    ],
                },
                Section {
                    heading: Some("Memory modules".into()),
                    items: vec![Item::Pair(
                        "Slot A1".into(),
                        "16 GiB F5-6000J3038F16G".into(),
                    )],
                },
            ],
            accept: "Done".into(),
            decline: None,
            copy: Some("Copy all".into()),
        };
        assert_eq!(
            copy_text(&dialog),
            "Processor: AMD Ryzen 9 7950X\r\nBoard: ASUS ROG STRIX X670E-E\r\n\r\nMemory modules\r\nSlot A1: 16 GiB F5-6000J3038F16G"
        );
    }
}
