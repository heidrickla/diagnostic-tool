//! The inspector: one square of the rescue strip drawn as its own grid, in the strip's
//! colors, and any square of that grid opened the same way, down to single sectors, at the
//! block level of the square clicked. It reads the rescue window's map as that window last had it, so it follows a run.
use std::cell::RefCell;
use std::ops::Range;
use std::rc::Rc;

use diagnostics::recovery::image::{Directed, Map};
use diagnostics::tools::drives::bytes_text;
use diagnostics::tools::drives::details::grouped;
use diagnostics::ui_layout::{grid, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    PostMessageW, IDC_HAND, WM_CLOSE, WM_COMMAND, WM_LBUTTONDOWN, WM_MOUSEMOVE, WM_RBUTTONUP,
};

use crate::rescue_image_view::{self as rescue, Blocks};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const GRID: usize = 50;
const AMOUNTS: usize = 51;
const LEGEND: usize = 52;
const BACK: usize = 53;
const CLOSE: usize = 54;
const LEFT: usize = 55;
const RIGHT: usize = 56;
const FOLLOW: usize = 57;
const READ_BLOCK: usize = 58;
const SCAN_FROM: usize = 59;
/// The command the inspector posts its owner when a directed read is asked (`Live::directed`).
pub const DIRECTED: usize = 60;
/// The inspector's grid rows; its columns are as many as fit the window.
const ROWS: i32 = 20;
const KEY: &str = "rescue-inspect";

/// What the rescue window hands the inspector: its map and where its run reads, and a
/// square clicked while the inspector was already open.
#[derive(Default)]
pub struct Live {
    pub map: Option<Map>,
    pub running: bool,
    pub reading: Option<u64>,
    pub disk: u32,
    /// The drive's sector size: the smallest square.
    pub sector: u64,
    pub jump: Option<Range<u64>>,
    /// The run is Fill the gaps, which takes a directed read as it runs.
    pub filling: bool,
    /// A directed read asked from the inspector, for the owner to take (`DIRECTED`).
    pub directed: Option<Directed>,
    /// The map as the run began, for marking what it recovered.
    pub before: Option<Map>,
}

/// Opens the inspector on `square`, or turns the open one to it.
pub fn open(owner: HWND, live: Rc<RefCell<Live>>, square: Range<u64>) {
    if toolwin::window_of(KEY).is_some() {
        live.borrow_mut().jump = Some(square.clone());
    }
    toolwin::open(owner, KEY, move || {
        let first = aligned(&square, &live.borrow());
        Box::new(Inspector {
            live,
            owner: owner as isize,
            selected: None,
            path: vec![first],
            hover: None,
            follow: false,
            controls: None,
            area: (0, 0, 96),
            natural: None,
        })
    });
}

/// `range` widened to whole sectors within the map, so the deepest grid is one sector a
/// square.
fn aligned(range: &Range<u64>, live: &Live) -> Range<u64> {
    let sector = live.sector.max(512);
    let len = live.map.as_ref().map_or(range.end, Map::len);
    let start = range.start / sector * sector;
    let end = range.end.div_ceil(sector).saturating_mul(sector).min(len);
    start..end.max(start)
}

/// How a shown range is drawn in a grid of `room` blocks: each square the same whole
/// number of sectors, `per`, as few as fit, so a sector is never split between two squares
/// (at 1.2 kB a square, one bad sector colored two); the grid's bytes run from the range's
/// start over `cells` squares, past its end to the last square's end.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Squares {
    grid: Range<u64>,
    cells: usize,
    per: u64,
    /// The blocks the grid has room for.
    room: usize,
}

fn squares(range: &Range<u64>, sector: u64, room: usize) -> Squares {
    let sector = sector.max(1);
    let sectors = (range.end - range.start).div_ceil(sector).max(1);
    let per = sectors.div_ceil(room.max(1) as u64).max(1);
    let cells = sectors.div_ceil(per);
    Squares {
        grid: range.start..range.start + cells * per * sector,
        cells: cells as usize,
        per,
        room,
    }
}

/// What clicking `clicked`, a square of `parent`, opens: the square itself while it holds
/// more sectors than the grid has room for; else as many sectors as fit, centred on it
/// within `parent`, so the last level is a full grid of single sectors around the click,
/// not a few squares in an empty one (2026-11-10, four sectors in a grid of 1,250).
fn opened(clicked: &Range<u64>, parent: &Range<u64>, sector: u64, room: usize) -> Range<u64> {
    let sector = sector.max(1);
    let want = room as u64 * sector;
    if clicked.end - clicked.start >= want {
        return clicked.clone();
    }
    let centre = clicked.start + (clicked.end - clicked.start) / 2;
    let mut start = (centre.saturating_sub(want / 2) / sector * sector).max(parent.start);
    let mut end = start + want;
    if end > parent.end {
        end = parent.end;
        start = (end.saturating_sub(want) / sector * sector).max(parent.start);
    }
    start..end
}

/// The stretch as wide as `range` that holds `pos`, in steps of its width from it, kept
/// within the map's `len`: the block beside it or the one being read, at the same zoom.
fn holding(range: &Range<u64>, pos: u64, len: u64) -> Range<u64> {
    let width = (range.end - range.start).max(1);
    let steps = if pos >= range.start {
        ((pos - range.start) / width) as i128
    } else {
        -(((range.start - pos).div_ceil(width)) as i128)
    };
    let start = (range.start as i128 + steps * width as i128).max(0) as u64;
    let start = start.min(len.saturating_sub(width));
    start..start + width.min(len)
}

/// `path` moved so its last level holds `pos`, each level above moved to hold that level
/// in turn, so Back goes to the block that holds where the inspector is now.
fn moved(path: &[Range<u64>], pos: u64, len: u64) -> Vec<Range<u64>> {
    let mut out = path.to_vec();
    let mut at = pos;
    for level in out.iter_mut().rev() {
        if !level.contains(&at) {
            *level = holding(level, at, len);
        }
        at = level.start;
    }
    out
}

/// Square `i` of `cells` over `range`.
fn square(range: &Range<u64>, i: usize, cells: usize) -> Range<u64> {
    Map::strip_edge_in(range, i, cells)..Map::strip_edge_in(range, i + 1, cells)
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    amounts: HWND,
    grid: HWND,
    legend: HWND,
    hover: HWND,
    back: HWND,
    close: HWND,
    left: HWND,
    right: HWND,
    follow: HWND,
    read_block: HWND,
    scan_from: HWND,
}

struct Inspector {
    live: Rc<RefCell<Live>>,
    /// The rescue window, which runs a directed read.
    owner: isize,
    /// The square picked with a right click (a left click on a sector): what Read this
    /// block and Continue scan from here act on; else the block shown.
    selected: Option<Range<u64>>,
    /// The squares opened, the first from the strip, the last shown.
    path: Vec<Range<u64>>,
    /// The square under the pointer.
    hover: Option<usize>,
    /// Follow mode: the shown block moves to the one being read.
    follow: bool,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    natural: Option<i32>,
}

impl Inspector {
    fn shown(&self) -> Range<u64> {
        self.path.last().cloned().unwrap_or(0..0)
    }

    /// What a directed read acts on: the square picked, else the block shown.
    fn target(&self) -> Range<u64> {
        self.selected.clone().unwrap_or_else(|| self.shown())
    }

    fn sector(&self) -> u64 {
        self.live.borrow().sector.max(512)
    }

    /// The map's length, or the shown block's end without a map.
    fn len(&self) -> u64 {
        self.live
            .borrow()
            .map
            .as_ref()
            .map_or(self.shown().end, Map::len)
    }

    /// Moves to the block beside the shown one, `-1` left or `1` right, at the same zoom.
    fn step(&mut self, by: i64) {
        let shown = self.shown();
        let width = shown.end - shown.start;
        let pos = if by < 0 {
            shown.start.checked_sub(width.max(1))
        } else {
            Some(shown.end).filter(|end| *end < self.len())
        };
        if let Some(pos) = pos {
            self.path = moved(&self.path, pos, self.len());
            self.hover = None;
        }
    }

    /// In follow mode, moves to the block being read when it is elsewhere.
    fn keep_up(&mut self) {
        if !self.follow {
            return;
        }
        let reading = {
            let live = self.live.borrow();
            live.map
                .as_ref()
                .and_then(|map| rescue::ring_at(map, live.running, live.reading))
        };
        if let Some(pos) = reading {
            if !self.shown().contains(&pos) {
                self.path = moved(&self.path, pos, self.len());
                self.hover = None;
            }
        }
    }

    /// The arrow under `x`, `y` in the window that can move: -1 left, 1 right.
    fn arrow_at(&self, x: i32, y: i32) -> Option<i64> {
        let c = self.controls.as_ref()?;
        let inside = |hwnd: HWND| {
            ui::rect_in_parent(hwnd)
                .is_some_and(|r| x >= r.left && x < r.right && y >= r.top && y < r.bottom)
        };
        let shown = self.shown();
        if inside(c.left) && shown.start > 0 {
            Some(-1)
        } else if inside(c.right) && shown.end < self.len() {
            Some(1)
        } else {
            None
        }
    }

    fn draw_arrow(&self, dc: HDC, rect: &RECT, dpi: u32, by: i64) {
        let colors = ui::current();
        ui::fill_rect(dc, rect, colors.card);
        let shown = self.shown();
        let can = if by < 0 {
            shown.start > 0
        } else {
            shown.end < self.len()
        };
        let Some(canvas) = ui::Canvas::new(dc) else {
            return;
        };
        let cx = (rect.left + rect.right) as f32 / 2.0;
        let cy = (rect.top + rect.bottom) as f32 / 2.0;
        let arm = diagnostics::ui_layout::scale(dpi, 8) as f32;
        let dir = by as f32;
        canvas.polyline(
            &[
                (cx - dir * arm / 2.0, cy - arm),
                (cx + dir * arm / 2.0, cy),
                (cx - dir * arm / 2.0, cy + arm),
            ],
            if can {
                colors.text
            } else {
                colors.raised_hover
            },
            diagnostics::ui_layout::scale(dpi, 3) as f32,
        );
    }

    /// The grid for the grid control's width, and the squares it draws.
    fn grid(&self, width: i32, dpi: u32) -> (Blocks, Squares) {
        let blocks = Blocks::with_rows(width, dpi, ROWS);
        let squares = squares(&self.shown(), self.sector(), blocks.count());
        (blocks, squares)
    }

    /// The square under `x`, `y` in the window, and the squares drawn.
    fn square_at(&self, x: i32, y: i32) -> Option<(usize, Squares)> {
        let c = self.controls.as_ref()?;
        let rect = ui::rect_in_parent(c.grid)?;
        let (blocks, squares) = self.grid(rect.right - rect.left, self.area.2);
        let i = blocks.at(x - rect.left, y - rect.top)?;
        (i < squares.cells).then_some((i, squares))
    }

    fn render(&mut self) {
        let Some(c) = &self.controls else {
            return;
        };
        let live = self.live.borrow();
        ui::set_text(c.title, &format!("Inspect disk {}", live.disk));
        let width = ui::rect_in_parent(c.grid).map_or(0, |r| r.right - r.left);
        let (_, sq) = self.grid(width.max(1), self.area.2);
        let range = sq.grid.clone();
        let cells = sq.cells;
        let each = if sq.per == 1 {
            format!("each square one {}-byte sector", self.sector())
        } else {
            format!(
                "each square {} sectors, {}",
                sq.per,
                bytes_text(sq.per * self.sector())
            )
        };
        ui::set_text(
            c.subtitle,
            &format!(
                "Bytes {} to {} ({}, at {}); {each}.",
                grouped(range.start.into()),
                grouped(range.end.into()),
                bytes_text(range.end - range.start),
                bytes_text(range.start),
            ),
        );
        let hover = match (self.hover, live.map.as_ref()) {
            (Some(i), Some(map)) if i < cells => {
                let part = square(&range, i, cells);
                let [rescued, untried, retry, bad] = map.amounts_in(&part);
                let gained = live
                    .before
                    .as_ref()
                    .map_or(0, |before| map.strip_gained_in(before, &part, 1)[0]);
                let mut said = Vec::new();
                for (amount, name) in [
                    (rescued, "rescued"),
                    (retry, "to be read again"),
                    (bad, "bad"),
                    (untried, "not read yet"),
                ] {
                    if amount > 0 {
                        said.push(format!("{} {name}", bytes_text(amount)));
                    }
                }
                if gained > 0 {
                    said.push(format!("{} of it recovered this run", bytes_text(gained)));
                }
                let what = if sq.per == 1 {
                    format!("Sector {}", grouped((part.start / self.sector()).into()))
                } else {
                    format!("Square {}", i + 1)
                };
                let more = if sq.per == 1 {
                    ""
                } else {
                    " Click to look inside."
                };
                format!(
                    "{what}: bytes {} to {}: {}.{more}",
                    grouped(part.start.into()),
                    grouped(part.end.into()),
                    said.join(", ")
                )
            }
            _ if sq.per == 1 => "Point at a sector to see its bytes.".into(),
            _ => "Point at a square to see its bytes; click one to look inside it.".into(),
        };
        let target = self.target();
        let which = if self.selected.is_some() {
            "the square picked"
        } else {
            "the block shown"
        };
        let hover = format!(
            "{hover}\nRead this block and Continue scan from here act on {which}: bytes {} to {} ({}). Right-click a square to pick it.",
            grouped(target.start.into()),
            grouped(target.end.into()),
            bytes_text(target.end - target.start)
        );
        ui::set_text(c.hover, &hover);
        let can_read = live.map.is_some() && (!live.running || live.filling);
        ui::enable(c.read_block, can_read);
        ui::enable(c.scan_from, can_read);
        ui::show(c.back, self.path.len() > 1);
        ui::set_text(
            c.follow,
            if self.follow {
                "Follow reading: on"
            } else {
                "Follow reading: off"
            },
        );
        toolwin::redraw(c.left);
        toolwin::redraw(c.right);
        toolwin::redraw(c.grid);
        toolwin::redraw(c.amounts);
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    fn draw_grid(&self, dc: HDC, rect: &RECT, dpi: u32) {
        let live = self.live.borrow();
        let (blocks, sq) = self.grid(rect.right - rect.left, dpi);
        let (range, cells) = (sq.grid, sq.cells);
        let Some(map) = live.map.as_ref() else {
            rescue::draw_grid(
                dc,
                rect,
                dpi,
                &blocks,
                &rescue::Shown {
                    cells: &vec![diagnostics::recovery::image::Cell::Untried; cells],
                    shares: &[],
                    gained: &[],
                    reading: None,
                    picked: None,
                },
            );
            return;
        };
        let reading = rescue::ring_at(map, live.running, live.reading)
            .and_then(|pos| Map::strip_cell_in(&range, pos, cells));
        let gained = live.before.as_ref().map_or_else(Vec::new, |before| {
            map.strip_gained_in(before, &range, cells)
        });
        rescue::draw_grid(
            dc,
            rect,
            dpi,
            &blocks,
            &rescue::Shown {
                cells: &map.strip_in(&range, cells),
                shares: &map.strip_rescued_in(&range, cells),
                gained: &gained,
                reading,
                picked: self
                    .selected
                    .as_ref()
                    .and_then(|picked| Map::strip_cell_in(&range, picked.start, cells)),
            },
        );
    }

    fn draw_amounts(&self, dc: HDC, rect: &RECT, dpi: u32) {
        let (Some(c), Some(map)) = (&self.controls, self.live.borrow().map.clone()) else {
            return;
        };
        let width = ui::rect_in_parent(c.grid).map_or(1, |r| (r.right - r.left).max(1));
        let (_, sq) = self.grid(width, dpi);
        let [rescued, untried, retry, bad] = map.amounts_in(&sq.grid);
        let gained = self
            .live
            .borrow()
            .before
            .as_ref()
            .map_or(0, |before| map.strip_gained_in(before, &sq.grid, 1)[0]);
        let mut amounts = vec![(0, rescued), (2, retry), (3, bad), (4, untried)];
        if gained > 0 {
            amounts.push((rescue::GAINED, gained));
        }
        let texts: Vec<(usize, String)> = amounts
            .into_iter()
            .map(|(item, amount)| {
                (
                    item,
                    format!("{} {}", rescue::LEGEND_ITEMS[item], bytes_text(amount)),
                )
            })
            .collect();
        let items: Vec<(usize, &str)> = texts.iter().map(|(i, s)| (*i, s.as_str())).collect();
        let colors = ui::current();
        rescue::draw_dots(
            dc,
            rect,
            dpi,
            c.amounts,
            ui::fonts(dpi).body,
            colors.text,
            &items,
        );
    }
}

impl Page for Inspector {
    fn title(&self) -> String {
        "Inspect the rescue map".into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((620, 560), (420, 460))
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::INSPECT)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        self.controls = Some(Controls {
            title: text(Kind::Title, "Inspect"),
            subtitle: text(Kind::Muted, ""),
            amounts: toolwin::canvas(hwnd, AMOUNTS),
            grid: toolwin::canvas(hwnd, GRID),
            legend: toolwin::canvas(hwnd, LEGEND),
            hover: text(Kind::Body, ""),
            back: ui::button(hwnd, BACK, Kind::Secondary, "Back"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
            left: toolwin::canvas(hwnd, LEFT),
            right: toolwin::canvas(hwnd, RIGHT),
            follow: ui::button(hwnd, FOLLOW, Kind::Secondary, "Follow reading: off"),
            read_block: ui::button(hwnd, READ_BLOCK, Kind::Secondary, "Read this block"),
            scan_from: ui::button(hwnd, SCAN_FROM, Kind::Secondary, "Continue scan from here"),
        });
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        f.header(c.title, c.subtitle);
        let line = f.s(rescue::LEGEND_LINE);
        let width = f.w;
        let lines = |hwnd: HWND, labels: &[String], font| {
            rescue::dot_spots(labels.iter().map(String::as_str), width, dpi, |s| {
                ui::text_width(hwnd, font, s)
            })
            .last()
            .map_or(0, |spot| spot.1 + 1)
        };
        let widest: Vec<String> = [0usize, 2, 3, 4]
            .iter()
            .map(|&i| format!("{} 999.9 GB", rescue::LEGEND_ITEMS[i]))
            .collect();
        let amounts_h = lines(c.amounts, &widest, ui::fonts(dpi).body) * line;
        ui::place(
            c.amounts,
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h: amounts_h,
            },
        );
        f.y += amounts_h;
        f.space(8);
        let pad = f.s(8);
        let grid_h = Blocks::rows_height(dpi, ROWS);
        let card = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: grid_h + 2 * pad,
        };
        // An arrow each side of the grid moves to the block beside the shown one.
        let arrow_w = f.s(28);
        for (hwnd, x) in [(c.left, f.x + pad), (c.right, f.x + f.w - pad - arrow_w)] {
            ui::place(
                hwnd,
                Rect {
                    x,
                    y: f.y + pad,
                    w: arrow_w,
                    h: grid_h,
                },
            );
        }
        ui::place(
            c.grid,
            Rect {
                x: f.x + pad + arrow_w,
                y: f.y + pad,
                w: f.w - 2 * pad - 2 * arrow_w,
                h: grid_h,
            },
        );
        f.y += card.h;
        f.space(6);
        let legend: Vec<String> = rescue::LEGEND_ITEMS.iter().map(|s| s.to_string()).collect();
        let legend_h = lines(c.legend, &legend, ui::fonts(dpi).caption) * line;
        ui::place(
            c.legend,
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h: legend_h,
            },
        );
        f.y += legend_h;
        f.space(10);
        f.text(c.hover, 0);
        // The directed read acts on the grid: its buttons sit under it, not in the footer,
        // where with Back, Follow and Close they ran under Close.
        f.space(8);
        f.buttons(&[c.read_block, c.scan_from], grid::BUTTON_GAP);
        self.natural = Some(f.y + toolwin::footer_h(dpi));
        toolwin::footer(w, h, dpi, &[c.back, c.follow], &[c.close]);
        ui::set_cards(hwnd, vec![card]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, _code: u16) -> Option<Ask> {
        match id {
            BACK if self.path.len() > 1 => {
                self.path.pop();
                self.hover = None;
            }
            FOLLOW => {
                self.follow = !self.follow;
                self.keep_up();
            }
            READ_BLOCK | SCAN_FROM => {
                let target = self.target();
                if !target.is_empty() {
                    let (start, end) = (target.start, target.end);
                    self.live.borrow_mut().directed = Some(if id == READ_BLOCK {
                        Directed::Block { start, end }
                    } else {
                        Directed::From { start, end }
                    });
                    // SAFETY: posts to the rescue window, which takes it from `Live`.
                    unsafe {
                        PostMessageW(self.owner as HWND, WM_COMMAND, DIRECTED, 0);
                    }
                }
            }
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        self.relayout(hwnd);
        None
    }

    fn tick(&mut self, hwnd: HWND) {
        let jump = self.live.borrow_mut().jump.take();
        if let Some(square) = jump {
            let first = aligned(&square, &self.live.borrow());
            self.path = vec![first];
            self.hover = None;
        }
        self.keep_up();
        self.render();
        self.relayout(hwnd);
    }

    fn cursor_at(&self, x: i32, y: i32) -> Option<windows_sys::core::PCWSTR> {
        if self.arrow_at(x, y).is_some() {
            return Some(IDC_HAND);
        }
        let (_, squares) = self.square_at(x, y)?;
        (squares.per > 1).then_some(IDC_HAND)
    }

    fn mouse(&mut self, hwnd: HWND, msg: u32, x: i32, y: i32) -> bool {
        let at = self.square_at(x, y);
        match msg {
            WM_MOUSEMOVE => {
                let hover = at.map(|(i, _)| i);
                if hover != self.hover {
                    self.hover = hover;
                    self.render();
                    self.relayout(hwnd);
                }
            }
            WM_LBUTTONDOWN if self.arrow_at(x, y).is_some() => {
                if let Some(by) = self.arrow_at(x, y) {
                    // Moving by hand ends following, which would move it straight back.
                    self.follow = false;
                    self.step(by);
                    self.render();
                    self.relayout(hwnd);
                }
            }
            // A right click picks the square for a directed read, or lets it go.
            WM_RBUTTONUP => {
                if let Some((i, sq)) = at {
                    let picked = aligned(&square(&sq.grid, i, sq.cells), &self.live.borrow());
                    self.selected = (self.selected.as_ref() != Some(&picked)).then_some(picked);
                    self.render();
                    self.relayout(hwnd);
                }
            }
            WM_LBUTTONDOWN => {
                if let Some((i, sq)) = at {
                    if sq.per == 1 {
                        let picked = aligned(&square(&sq.grid, i, sq.cells), &self.live.borrow());
                        self.selected = (self.selected.as_ref() != Some(&picked)).then_some(picked);
                        self.render();
                        self.relayout(hwnd);
                    }
                    if sq.per > 1 {
                        let live = self.live.borrow();
                        let clicked = aligned(&square(&sq.grid, i, sq.cells), &live);
                        let inside = opened(&clicked, &self.shown(), live.sector.max(512), sq.room);
                        drop(live);
                        self.path.push(inside);
                        self.hover = None;
                        self.render();
                        self.relayout(hwnd);
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn draw_item(&self, list: usize, _index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        match list {
            GRID => self.draw_grid(dc, rect, state.dpi),
            LEFT => self.draw_arrow(dc, rect, state.dpi, -1),
            RIGHT => self.draw_arrow(dc, rect, state.dpi, 1),
            AMOUNTS => self.draw_amounts(dc, rect, state.dpi),
            LEGEND => {
                let Some(c) = &self.controls else {
                    return;
                };
                let items: Vec<(usize, &str)> =
                    rescue::LEGEND_ITEMS.iter().copied().enumerate().collect();
                rescue::draw_dots(
                    dc,
                    rect,
                    state.dpi,
                    c.legend,
                    ui::fonts(state.dpi).caption,
                    ui::current().muted,
                    &items,
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::recovery::image::Status;

    fn live(len: u64) -> Live {
        let mut map = Map::new(len);
        map.set(0, len, Status::Rescued);
        Live {
            map: Some(map),
            sector: 512,
            ..Live::default()
        }
    }

    /// The guard: a square opened is widened to whole sectors within the map; every square
    /// of every level is the same whole number of sectors, so no sector is split between two
    /// (one bad sector colored two 1.2 kB squares, 2026-11-10); and single sectors are reached
    /// in a few clicks.
    #[test]
    fn squares_are_whole_sectors_down_to_one() {
        let live = live(2_000_398_933_504);
        let room = 1250;
        let whole = 0..live.map.as_ref().unwrap().len();
        let mut shown = aligned(&square(&whole, 72, 1428), &live);
        assert_eq!(shown.start % 512, 0);
        assert_eq!(shown.end % 512, 0);
        let mut clicks = 0;
        loop {
            let sq = squares(&shown, 512, room);
            assert!(sq.cells <= room, "{sq:?}");
            assert!(
                sq.grid.end >= shown.end && sq.grid.start == shown.start,
                "{sq:?}"
            );
            for i in 0..sq.cells {
                let part = square(&sq.grid, i, sq.cells);
                assert_eq!(part.end - part.start, sq.per * 512, "square {i} of {sq:?}");
                assert_eq!(part.start % 512, 0, "square {i} of {sq:?}");
            }
            if sq.per == 1 {
                break;
            }
            shown = aligned(&square(&sq.grid, sq.cells / 2, sq.cells), &live);
            clicks += 1;
            assert!(clicks < 6, "{shown:?}");
        }
        assert!(clicks <= 3, "{clicks} clicks to sectors");
        // 1.5 MB in 1250 blocks: three sectors a square, not 1.2 kB.
        let sq = squares(&(0..1_459_712), 512, 1250);
        assert_eq!((sq.per, sq.cells), (3, 951));
        // A square smaller than the grid opens as a full grid of sectors around it, within
        // the level it was clicked in.
        let parent = 0..1_459_712;
        let open = opened(&(4096..5632), &parent, 512, 1250);
        assert_eq!(open.end - open.start, 1250 * 512);
        assert!(
            open.start <= 4096 && open.end >= 5632 && open.start == 0,
            "{open:?}"
        );
        let open = opened(&(700_416..701_952), &parent, 512, 1250);
        assert!(
            open.start < 700_416 && open.end > 701_952,
            "centered: {open:?}"
        );
        assert_eq!(open.start % 512, 0);
        let open = opened(&(1_458_176..1_459_712), &parent, 512, 1250);
        assert_eq!(open.end, parent.end, "{open:?}");
        assert_eq!(open.end - open.start, 1250 * 512);
        let big = 0..10_000_000;
        assert_eq!(opened(&big, &(0..20_000_000), 512, 1250), big);
        // The map's last, partial stretch stays within the map.
        let end = aligned(&(whole.end - 100..whole.end), &live);
        assert_eq!(end.end, whole.end);
    }

    /// The guard: the arrows and follow mode move the shown block by its own width to the
    /// one beside it or the one being read, either way, within the map; the levels above
    /// move to hold it, so Back goes to the block around where the inspector is now.
    #[test]
    fn the_shown_block_moves_by_its_width_to_follow_the_reading() {
        let len = 10_000;
        let shown = 2_000..2_500;
        assert_eq!(holding(&shown, 2_600, len), 2_500..3_000, "right");
        assert_eq!(holding(&shown, 1_999, len), 1_500..2_000, "left");
        assert_eq!(holding(&shown, 7_321, len), 7_000..7_500, "far right");
        assert_eq!(holding(&shown, 0, len), 0..500, "far left");
        assert_eq!(
            holding(&shown, 9_999, len),
            9_500..10_000,
            "kept in the map"
        );
        assert_eq!(
            holding(&(9_700..10_000), 9_800, len),
            9_700..10_000,
            "already holds it"
        );
        let path = vec![0..5_000, 2_000..3_000, 2_000..2_500];
        let moved = moved(&path, 6_100, len);
        assert_eq!(moved[2], 6_000..6_500);
        assert_eq!(moved[1], 6_000..7_000, "the level above holds it");
        assert_eq!(moved[0], 5_000..10_000, "and the level above that");
        // A wide block stepped past the map's end is kept within it.
        assert_eq!(holding(&(0..3_000), 9_999, len), 7_000..10_000);
        // A block that straddles two of the level above: that level holds where it starts.
        let straddle = vec![0..5_000, 2_000..3_000, 2_000..2_700];
        let moved_on = super::moved(&straddle, 3_000, len);
        assert_eq!(moved_on[2], 2_700..3_400);
        assert_eq!(moved_on[1], 2_000..3_000, "holds the block's start");
        let back = super::moved(&path, 2_100, len);
        assert_eq!(back, path, "a level that holds it stays");
    }
}
