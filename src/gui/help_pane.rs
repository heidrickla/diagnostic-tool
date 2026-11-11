//! The help pane both the tool windows and the status window use: a "?" button at the right
//! of the title row and, once pressed, a pane docked on the right that shows the window's
//! topic. The window grows by the pane so its own controls do not move, and shrinks back.
use diagnostics::ui_layout::{self, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromWindow, DT_SINGLELINE, DT_WORDBREAK, HDC, HFONT, MONITORINFO,
    MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::UI::Controls::{DRAWITEMSTRUCT, ODT_LISTBOX};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowRect, IsZoomed, SetWindowPos, SWP_NOACTIVATE, SWP_NOZORDER,
};

use crate::help::{self, Line};
use crate::toolwin;
use crate::ui::{self, Kind};

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    /// Each window's help button and pane.
    static HELP: RefCell<HashMap<isize, Help>> = RefCell::new(HashMap::new());
}

/// The "?" button and the help pane's list; ids no page uses.
pub const BUTTON: usize = 0x7E01;
pub const LIST: usize = 0x7E02;

/// One window's help: its button, its pane, whether the pane is open, and how much the
/// window grew to make room for it.
struct Help {
    button: HWND,
    list: HWND,
    open: bool,
    grown: i32,
    lines: Vec<Line>,
    /// The paragraphs as last laid out, split to fit the pane's width.
    pieces: Vec<Piece>,
}

/// One item of the help pane: a paragraph, or the next part of one too tall for a list item.
#[derive(Clone)]
struct Piece {
    line: Line,
    text: String,
    first: bool,
}

/// A list item's height is kept in a byte: a paragraph taller than this is shown in parts.
const PIECE_MAX: i32 = 240;

fn help_pieces(lines: &[Line]) -> Vec<Piece> {
    lines
        .iter()
        .map(|line| Piece {
            line: *line,
            text: line.text(),
            first: true,
        })
        .collect()
}

/// The pane's font, text indent and space above, for a piece.
fn piece_style(piece: &Piece, dpi: u32) -> (HFONT, i32, i32) {
    let fonts = ui::fonts(dpi);
    let s = |v| scale(dpi, v);
    match piece.line {
        Line::Title(_) => (fonts.strong, 0, s(14)),
        Line::About(_) => (fonts.body, 0, s(4)),
        Line::Heading(_) => (fonts.caption, 0, s(16)),
        _ if !piece.first => (fonts.body, s(18), 0),
        _ => (fonts.body, s(18), s(6)),
    }
}

/// Splits a piece too tall for a list item at the sentence nearest its middle.
fn split_tall(piece: Piece, fits: &dyn Fn(&Piece) -> bool) -> Vec<Piece> {
    if fits(&piece) {
        return vec![piece];
    }
    let middle = piece.text.len() / 2;
    let cut = piece
        .text
        .match_indices(". ")
        .map(|(i, _)| i + 2)
        .min_by_key(|i| i.abs_diff(middle))
        .or_else(|| {
            piece
                .text
                .match_indices(' ')
                .map(|(i, _)| i + 1)
                .min_by_key(|i| i.abs_diff(middle))
        });
    let Some(cut) = cut.filter(|c| *c > 0 && *c < piece.text.len()) else {
        return vec![piece];
    };
    let (head, tail) = piece.text.split_at(cut);
    let head = Piece {
        text: head.trim_end().to_string(),
        ..piece.clone()
    };
    let tail = Piece {
        text: tail.to_string(),
        first: false,
        ..piece
    };
    let mut out = split_tall(head, fits);
    out.extend(split_tall(tail, fits));
    out
}

/// Makes a window's help button and its pane, hidden until the button is pressed.
pub fn make(hwnd: HWND, key: &str) {
    let Some(topic) = help::topic(key) else {
        return;
    };
    let button = ui::button(hwnd, BUTTON, Kind::Secondary, "?");
    let list = toolwin::list_wrapping(hwnd, LIST, 28);
    ui::show(list, false);
    HELP.with(|h| {
        h.borrow_mut().insert(
            hwnd as isize,
            Help {
                button,
                list,
                open: false,
                grown: 0,
                lines: help::lines(topic),
                pieces: Vec::new(),
            },
        )
    });
}

/// Places the help button at the right of the page's title row and, while open, the pane
/// beside the page. Returns the width the page gets.
pub fn place(hwnd: HWND, w: i32, h: i32, dpi: u32) -> i32 {
    HELP.with(|map| {
        let mut map = map.borrow_mut();
        let Some(help) = map.get_mut(&(hwnd as isize)) else {
            return w;
        };
        let (page_w, pane) = ui_layout::help_split(w, h, help.open, dpi);
        ui::place(help.button, ui_layout::help_button(page_w, dpi));
        ui::show(help.list, pane.is_some());
        if let Some(pane) = pane {
            let inset = scale(dpi, 1);
            ui::place(
                help.list,
                Rect {
                    x: pane.x + inset,
                    y: pane.y,
                    w: pane.w - inset,
                    h: pane.h,
                },
            );
            let text_w = pane.w - scale(dpi, 16 + 14);
            let list = help.list;
            let fits = |piece: &Piece| {
                let (font, indent, above) = piece_style(piece, dpi);
                ui::text_height(list, font, &piece.text, text_w - indent) + above + scale(dpi, 6)
                    <= PIECE_MAX
            };
            let pieces: Vec<Piece> = help_pieces(&help.lines)
                .into_iter()
                .flat_map(|p| split_tall(p, &fits))
                .collect();
            let texts = |pieces: &[Piece]| -> Vec<String> {
                pieces.iter().map(|p| p.text.clone()).collect()
            };
            let items = texts(&pieces);
            if toolwin::count(list) != items.len() || texts(&help.pieces) != items {
                toolwin::set_items(list, &items, true);
            }
            help.pieces = pieces;
            let heights: Vec<i32> = help
                .pieces
                .iter()
                .map(|p| {
                    let (font, indent, above) = piece_style(p, dpi);
                    let text = if matches!(p.line, Line::Heading(_)) {
                        p.text.to_uppercase()
                    } else {
                        p.text.clone()
                    };
                    ui::text_height(list, font, &text, text_w - indent) + above + scale(dpi, 6)
                })
                .collect();
            toolwin::set_heights(list, &heights);
        }
        page_w
    })
}

/// Opens or closes the help pane: the window grows by the pane so the page keeps its width
/// and nothing on it moves, and gives the room back when it closes.
pub fn toggle(hwnd: HWND, relayout: fn(HWND)) {
    let dpi = ui::dpi_of(hwnd);
    let Some((open, grown, button)) = HELP.with(|map| {
        map.borrow()
            .get(&(hwnd as isize))
            .map(|h| (h.open, h.grown, h.button))
    }) else {
        return;
    };
    let mut frame: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetWindowRect(hwnd, &mut frame) };
    let zoomed = unsafe { IsZoomed(hwnd) } != 0;
    let (left, width, grown_now) = if open {
        (frame.left, frame.right - frame.left - grown, 0)
    } else if zoomed {
        (frame.left, frame.right - frame.left, 0)
    } else {
        let mut screen: MONITORINFO = unsafe { std::mem::zeroed() };
        screen.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
        let work = if unsafe { GetMonitorInfoW(monitor, &mut screen) } != 0 {
            (screen.rcWork.left, screen.rcWork.right)
        } else {
            (frame.left, frame.right)
        };
        ui_layout::help_opened(
            frame.left,
            frame.right - frame.left,
            scale(dpi, ui_layout::HELP_PANE_W),
            work,
        )
    };
    HELP.with(|map| {
        if let Some(help) = map.borrow_mut().get_mut(&(hwnd as isize)) {
            help.open = !open;
            help.grown = grown_now;
        }
    });
    ui::set_kind(button, if open { Kind::Secondary } else { Kind::Primary });
    if !zoomed && (width != frame.right - frame.left || left != frame.left) {
        unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                left,
                frame.top,
                width,
                frame.bottom - frame.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
    }
    relayout(hwnd);
}

/// Draws one item of the help pane.
fn draw_piece(hwnd: HWND, index: usize, dc: HDC, rect: &RECT, dpi: u32) {
    let Some(piece) = HELP.with(|map| {
        map.borrow()
            .get(&(hwnd as isize))
            .and_then(|h| h.pieces.get(index).cloned())
    }) else {
        return;
    };
    let colors = ui::current();
    ui::fill_rect(dc, rect, colors.card);
    let (font, indent, above) = piece_style(&piece, dpi);
    let s = |v| scale(dpi, v);
    let text_rect = RECT {
        left: rect.left + s(16) + indent,
        top: rect.top + above,
        right: rect.right - s(14),
        bottom: rect.bottom,
    };
    let (text, color) = match piece.line {
        Line::Heading(t) => (t.to_uppercase(), colors.muted),
        Line::Title(_) | Line::About(_) => (piece.text.clone(), colors.text),
        _ => (piece.text.clone(), colors.text),
    };
    let marker = match piece.line {
        Line::Watch(_) => Some(colors.serious),
        Line::Judgment(_) => Some(colors.warn),
        Line::Color(_) => Some(colors.muted),
        _ => None,
    };
    let line_h = ui::text_height(hwnd, font, "X", s(100));
    if piece.first {
        if let Some(color) = marker {
            if let Some(canvas) = ui::Canvas::new(dc) {
                canvas.circle(
                    (rect.left + s(16) + s(5)) as f32,
                    (text_rect.top + line_h / 2) as f32,
                    s(3) as f32,
                    color,
                );
            }
        }
    }
    // A step's number sits in the indent, its text beside it.
    let text = match piece.line {
        Line::Step(n, body) if piece.first => {
            ui::draw_text(
                dc,
                &format!("{n}."),
                &RECT {
                    left: rect.left + s(16),
                    ..text_rect
                },
                font,
                colors.muted,
                DT_SINGLELINE,
            );
            piece
                .text
                .strip_prefix(&format!("{n}. "))
                .unwrap_or(body)
                .to_string()
        }
        _ => text,
    };
    ui::draw_text(dc, &text, &text_rect, font, color, DT_WORDBREAK);
}

/// The width the open pane adds to a window's client area; nothing while it is closed or the
/// window has no help.
pub fn room(hwnd: HWND, dpi: u32) -> i32 {
    HELP.with(|map| {
        map.borrow()
            .get(&(hwnd as isize))
            .filter(|h| h.open)
            .map_or(0, |_| scale(dpi, ui_layout::HELP_PANE_W))
    })
}

/// Drops a closed window's help.
pub fn forget(hwnd: HWND) {
    HELP.with(|h| h.borrow_mut().remove(&(hwnd as isize)));
}

/// Draws the pane's item when `l` (a WM_DRAWITEM's DRAWITEMSTRUCT) is one; None for any
/// other control, which the window draws itself.
///
/// # Safety
/// `l` must be the LPARAM of a WM_DRAWITEM.
pub unsafe fn draw(hwnd: HWND, l: LPARAM) -> Option<LRESULT> {
    let item = &*(l as *const DRAWITEMSTRUCT);
    if item.CtlType != ODT_LISTBOX || item.CtlID as usize != LIST {
        return None;
    }
    if item.itemID != u32::MAX {
        let rect = item.rcItem;
        let dpi = ui::dpi_of(hwnd);
        ui::buffered_at_origin(item.hDC, &rect, |dc, local| {
            draw_piece(hwnd, item.itemID as usize, dc, local, dpi);
        });
    }
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A paragraph too tall for one list item is shown in parts at its sentences, each
    /// fitting, together the whole paragraph, the first with its marker.
    #[test]
    fn a_tall_paragraph_is_shown_in_parts() {
        let text = "One sentence here. Another sentence there. A third one follows. And a fourth.";
        let piece = Piece {
            line: help::Line::Watch(text),
            text: text.into(),
            first: true,
        };
        let parts = split_tall(piece.clone(), &|p: &Piece| p.text.len() <= 30);
        assert!(parts.len() > 1);
        assert!(
            parts.iter().all(|p| p.text.len() <= 30),
            "{:?}",
            parts.len()
        );
        assert!(parts[0].first && parts[1..].iter().all(|p| !p.first));
        let joined = parts
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(joined, text);
        assert_eq!(split_tall(piece, &|_| true).len(), 1);
    }
}
