//! The event viewer, opened from the four event rows: the events behind the row, read
//! again with their messages, filtered by level, time range and text, with the selected
//! event's fields and message. The model is `diagnostics::event_list`.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Instant, SystemTime};

use diagnostics::event_list::{self, Filter, Level, Loaded, Mark, Preset, Progress, Range, View};
use diagnostics::events::{self, Query, ReadError};
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    InvalidateRect, DT_END_ELLIPSIS, DT_LEFT, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow;

use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

/// Level toggles take four ids from here, in `Level::ALL` order.
const LEVELS: usize = 10;
/// Range buttons take three ids from here, in `Range::ALL` order.
const RANGES: usize = 14;
const SEARCH: usize = 17;
const COPY: usize = 18;
const WEB: usize = 19;
const CLOSE: usize = 20;
/// Distinct from other pages' lists: toolwin keeps item heights by control id.
const LIST: usize = 31;
const ITEM_H: i32 = 32;
const EN_CHANGE: u16 = 0x0300;
const LBN_SELCHANGE: u16 = 1;
const COPY_TEXT: &str = "Copy details";
const WEB_TEXT: &str = "Search the web";
const PICK_TEXT: &str = "Select an event to see its fields and message.";

/// Whether this build has the event viewer.
pub fn available() -> bool {
    true
}

/// Opens the viewer for a row's check, preset to that row's events. Each row has its own
/// window, so a second row never brings forward a viewer showing another row's events.
pub fn open(owner: HWND, check: &str) {
    let Some(preset) = event_list::preset(check) else {
        return;
    };
    toolwin::open(owner, &format!("events:{check}"), move || {
        Box::new(EventView::new(preset))
    });
}

enum Reading {
    Idle,
    Running {
        cancel: Arc<AtomicBool>,
        progress: Arc<Progress>,
        result: mpsc::Receiver<Result<Loaded, ReadError>>,
        started: Instant,
        queries: Vec<Query>,
    },
}

#[derive(Clone, Copy)]
struct Controls {
    title: HWND,
    description: HWND,
    scope: HWND,
    levels: [HWND; 4],
    ranges: [HWND; 3],
    search: HWND,
    status: HWND,
    bar: HWND,
    notice: HWND,
    list: HWND,
    details: HWND,
    copy: HWND,
    web: HWND,
    close: HWND,
}

pub struct EventView {
    preset: Preset,
    filter: Filter,
    controls: Option<Controls>,
    reading: Reading,
    loaded: Option<Loaded>,
    view: View,
    /// Why the last read failed as a whole.
    failure: Option<String>,
    /// What the last button could not do.
    notice: Option<String>,
    /// The loaded row whose details are shown, kept across filtering.
    chosen: Option<usize>,
    /// The window and its last layout, to lay out again when the notice changes height.
    window: Option<(HWND, i32, i32, u32)>,
    shown_notice: String,
    /// The bar between the list and the details, from the last layout.
    split: Option<Split>,
    /// Where in the bar the drag started, while the bar is dragged.
    dragging: Option<i32>,
}

/// The draggable bar between the event list and the details.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Split {
    /// Top of the space the list and the details share, and its height without the bar.
    pub top: i32,
    pub usable: i32,
    pub left: i32,
    pub right: i32,
    pub bar: i32,
    pub min: i32,
}

impl Split {
    /// The list's height for a details share.
    pub fn list_height(&self, share: f32) -> i32 {
        let details = ((self.usable as f32) * share).round() as i32;
        let details = details.clamp(self.min, (self.usable - self.min).max(self.min));
        self.usable - details
    }

    pub fn bar_top(&self, share: f32) -> i32 {
        self.top + self.list_height(share)
    }

    pub fn on_bar(&self, share: f32, x: i32, y: i32) -> bool {
        let top = self.bar_top(share);
        x >= self.left && x < self.right && y >= top && y < top + self.bar
    }

    /// The details share that puts the bar's top at `bar_top`, kept within the minimums.
    pub fn share_for(&self, bar_top: i32) -> f32 {
        let list = (bar_top - self.top).clamp(self.min, (self.usable - self.min).max(self.min));
        1.0 - list as f32 / self.usable.max(1) as f32
    }
}

thread_local! {
    /// The details' share of the space below the filters, kept while the program runs.
    static DETAILS_SHARE: std::cell::Cell<f32> = const { std::cell::Cell::new(0.4) };
}

impl Drop for EventView {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl EventView {
    fn new(preset: Preset) -> Self {
        let filter = preset.default_filter();
        let mut view = Self {
            preset,
            filter,
            controls: None,
            reading: Reading::Idle,
            loaded: None,
            view: View::default(),
            failure: None,
            notice: None,
            chosen: None,
            window: None,
            shown_notice: String::new(),
            split: None,
            dragging: None,
        };
        view.start_read();
        view
    }

    fn cancel(&self) {
        if let Reading::Running { cancel, .. } = &self.reading {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Reads the preset's queries for the current filter on a background thread. The
    /// list empties meanwhile, so it never shows a range or level that was not read.
    fn start_read(&mut self) {
        self.cancel();
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let (sender, result) = mpsc::channel();
        let (preset, filter) = (self.preset.clone(), self.filter.clone());
        let (c, p) = (cancel.clone(), progress.clone());
        thread::spawn(move || {
            let _ = sender.send(event_list::read(&preset, &filter, &c, &p));
        });
        self.reading = Reading::Running {
            cancel,
            progress,
            result,
            started: Instant::now(),
            queries: self.preset.queries(&self.filter),
        };
        self.loaded = None;
        self.failure = None;
        self.refilter();
    }

    /// After a level or range change: filter again when the events read hold the answer,
    /// otherwise read again.
    fn filter_changed(&mut self) {
        self.notice = None;
        let wanted = self.preset.queries(&self.filter);
        let held = match &self.reading {
            Reading::Running { queries, .. } => event_list::covers(queries, &wanted),
            Reading::Idle => self
                .loaded
                .as_ref()
                .is_some_and(|loaded| event_list::covers(&loaded.queries, &wanted)),
        };
        if held {
            self.refilter();
        } else {
            self.start_read();
        }
    }

    fn refilter(&mut self) {
        self.view = match &self.loaded {
            Some(loaded) => event_list::view(
                loaded,
                &self.filter,
                self.preset.hide_routine,
                SystemTime::now(),
            ),
            None => View::default(),
        };
        let position = self
            .chosen
            .and_then(|chosen| self.view.rows.iter().position(|&row| row == chosen));
        if position.is_none() {
            self.chosen = None;
        }
        if let Some(c) = self.controls {
            let texts: Vec<String> = match &self.loaded {
                Some(loaded) => self
                    .view
                    .rows
                    .iter()
                    .map(|&index| {
                        let row = &loaded.rows[index];
                        event_list::row_text(row, &event_list::local(&row.event))
                    })
                    .collect(),
                None => Vec::new(),
            };
            toolwin::set_items(c.list, &texts, false);
            toolwin::select(c.list, position);
        }
        self.show_details();
        self.render();
    }

    fn chosen_row(&self) -> Option<&event_list::Row> {
        self.loaded.as_ref()?.rows.get(self.chosen?)
    }

    fn show_details(&self) {
        let Some(c) = self.controls else {
            return;
        };
        let text = self.chosen_row().map_or_else(
            || PICK_TEXT.to_string(),
            |row| event_list::details_text(row, &event_list::local(&row.event)),
        );
        ui::set_text(c.details, &text);
    }

    /// The status line, and the progress bar's value while reading.
    fn status(&self) -> (String, Option<u32>) {
        if let Reading::Running {
            progress, started, ..
        } = &self.reading
        {
            let part = progress.part.load(Ordering::Relaxed);
            let parts = self.preset.parts.len().max(1);
            let text = event_list::reading_text(
                &self.preset,
                part,
                progress.events.load(Ordering::Relaxed),
                started.elapsed().as_secs(),
            );
            return (text, Some((part * 1000 / parts) as u32));
        }
        let text = match (&self.failure, &self.loaded) {
            (Some(reason), _) => format!("The events could not be read: {reason}."),
            (None, Some(loaded)) => event_list::summary_text(loaded, &self.view, &self.filter),
            (None, None) => String::new(),
        };
        (text, None)
    }

    /// What could not be read or done, in amber under the status line.
    fn notice_text(&self) -> String {
        let mut lines = match &self.loaded {
            Some(loaded) => event_list::notes(loaded, self.filter.range, SystemTime::now()),
            None => Vec::new(),
        };
        lines.extend(self.notice.clone());
        lines.join(" ")
    }

    fn render(&mut self) {
        let Some(c) = self.controls else {
            return;
        };
        ui::set_text(c.scope, &event_list::scope_line(&self.preset, &self.filter));
        for (level, hwnd) in Level::ALL.into_iter().zip(c.levels) {
            let on = self.filter.levels[level.index()];
            ui::set_kind(hwnd, if on { Kind::Secondary } else { Kind::Ghost });
        }
        for (range, hwnd) in Range::ALL.into_iter().zip(c.ranges) {
            let on = self.filter.range == range;
            ui::set_kind(hwnd, if on { Kind::Secondary } else { Kind::Ghost });
        }
        let (status, progress) = self.status();
        ui::set_text(c.status, &status);
        ui::show(c.bar, progress.is_some());
        if let Some(value) = progress {
            ui::set_value(c.bar, value);
        }
        let chosen = self.chosen.is_some();
        ui::enable(c.copy, chosen);
        ui::enable(c.web, chosen);
        let notice = self.notice_text();
        if notice != self.shown_notice {
            ui::set_text(c.notice, &notice);
            self.shown_notice = notice;
            // The notice's height moves everything below it.
            if let Some((hwnd, w, h, dpi)) = self.window {
                self.layout(hwnd, w, h, dpi);
                unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
            }
        }
    }

    fn choose(&mut self) {
        let selected = self.controls.and_then(|c| toolwin::selected(c.list));
        self.chosen = selected.and_then(|index| self.view.rows.get(index).copied());
        self.notice = None;
        self.show_details();
        self.render();
    }

    fn copy(&mut self, hwnd: HWND) {
        let Some(row) = self.chosen_row() else {
            return;
        };
        let text = event_list::details_text(row, &event_list::local(&row.event));
        self.notice =
            (!ui::copy_to_clipboard(hwnd, &text)).then(|| "Windows did not allow copying.".into());
        self.render();
    }

    fn search_web(&mut self, hwnd: HWND) {
        let Some(row) = self.chosen_row() else {
            return;
        };
        let url = event_list::search_url(&row.event.provider, row.event.id, &events::local_names());
        self.notice = (!toolwin::open_path(hwnd, Path::new(&url)))
            .then(|| "Windows could not open the web browser.".into());
        self.render();
    }
}

impl Page for EventView {
    fn title(&self) -> String {
        self.preset.title.into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((860, 760), (620, 560))
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::EVENTS)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, tone, value: &str| ui::text(hwnd, kind, tone, false, value);
        let controls = Controls {
            title: text(Kind::Title, Tone::Neutral, self.preset.title),
            description: text(Kind::Muted, Tone::Neutral, &self.preset.description),
            scope: text(Kind::Caption, Tone::Neutral, ""),
            levels: Level::ALL
                .map(|level| ui::button(hwnd, LEVELS + level.index(), Kind::Ghost, level.label())),
            ranges: [0, 1, 2].map(|index| {
                ui::button(hwnd, RANGES + index, Kind::Ghost, Range::ALL[index].label())
            }),
            search: toolwin::search_box(hwnd, SEARCH, "Search source, event id or message"),
            status: text(Kind::Caption, Tone::Neutral, ""),
            bar: text(Kind::Progress, Tone::Neutral, ""),
            notice: text(Kind::Muted, Tone::Warn, ""),
            list: toolwin::list(hwnd, LIST, ITEM_H),
            details: ui::selectable_scrolling(hwnd, PICK_TEXT),
            copy: ui::button(hwnd, COPY, Kind::Secondary, COPY_TEXT),
            web: ui::button(hwnd, WEB, Kind::Secondary, WEB_TEXT),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        self.controls = Some(controls);
        self.refilter();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.window = Some((hwnd, w, h, dpi));
        let Some(c) = self.controls else {
            return;
        };
        let fonts = ui::fonts(dpi);
        for control in [c.list, c.details, c.search] {
            ui::set_font(control, fonts.body);
        }
        let s = |v: i32| scale(dpi, v);
        let m = s(grid::OUTER);
        let inner = w - 2 * m;
        let right = m + inner;
        let at = |x, y, w, h| Rect { x, y, w, h };
        let mut y = s(16);
        ui::place(c.title, at(m, y, inner, s(grid::TITLE_H)));
        y += s(grid::TITLE_H) + s(4);
        let description =
            ui::text_height(hwnd, fonts.body, &self.preset.description, inner).max(s(grid::BODY_H));
        ui::place(c.description, at(m, y, inner, description));
        y += description + s(4);
        ui::place(c.scope, at(m, y, inner, s(grid::CAPTION_H + 2)));
        y += s(grid::CAPTION_H + 2) + s(12);

        // Level toggles on the left, ranges on the right; the ranges wrap when narrow.
        let bh = s(grid::BUTTON_H);
        let gap = s(grid::BUTTON_GAP);
        let mut x = m;
        for (level, hwnd) in Level::ALL.into_iter().zip(c.levels) {
            let bw = ui::button_width(hwnd, level.label());
            ui::place(hwnd, at(x, y, bw, bh));
            x += bw + gap;
        }
        let range_widths: Vec<i32> = Range::ALL
            .into_iter()
            .zip(c.ranges)
            .map(|(range, hwnd)| ui::button_width(hwnd, range.label()))
            .collect();
        let ranges_w: i32 = range_widths.iter().sum::<i32>() + gap * 2;
        if x + s(16) + ranges_w > right {
            y += bh + gap;
        }
        let mut x = right - ranges_w;
        for (hwnd, bw) in c.ranges.into_iter().zip(range_widths) {
            ui::place(hwnd, at(x, y, bw, bh));
            x += bw + gap;
        }
        y += bh + s(10);

        // The search box sits on a card of its own, like a field.
        let field = at(m, y, inner, bh);
        let edit_h = s(grid::BODY_H);
        ui::place(
            c.search,
            at(m + s(12), y + (bh - edit_h) / 2, inner - s(24), edit_h),
        );
        y += bh + s(8);
        ui::place(c.status, at(m, y, inner, s(grid::CAPTION_H + 2)));
        y += s(grid::CAPTION_H + 2) + s(4);
        ui::place(c.bar, at(m, y, inner, s(4)));
        y += s(4) + s(8);
        if self.shown_notice.is_empty() {
            ui::show(c.notice, false);
        } else {
            let notice = ui::text_height(hwnd, fonts.body, &self.shown_notice, inner);
            ui::place(c.notice, at(m, y, inner, notice));
            ui::show(c.notice, true);
            y += notice + s(8);
        }

        let bottom_y = h - m - bh;
        let room = (bottom_y - s(16) - y).max(s(200));
        let split = Split {
            top: y,
            usable: room - s(12),
            left: m,
            right,
            bar: s(12),
            min: s(80),
        };
        self.split = Some(split);
        let share = DETAILS_SHARE.with(|d| d.get());
        let list_h = split.list_height(share);
        let details_h = split.usable - list_h;
        let pad = s(8);
        let list_card = at(m, y, inner, list_h);
        ui::place(
            c.list,
            at(
                list_card.x + pad,
                list_card.y + pad,
                list_card.w - 2 * pad,
                list_card.h - 2 * pad,
            ),
        );
        let details_card = at(m, y + list_h + s(12), inner, details_h);
        ui::place(
            c.details,
            at(
                details_card.x + s(14),
                details_card.y + s(10),
                details_card.w - s(20),
                details_card.h - s(20),
            ),
        );
        // A short grip in the bar shows it can be dragged.
        let grip = at(m + inner / 2 - s(20), y + list_h + s(4), s(40), s(4));
        ui::set_cards(hwnd, vec![field, list_card, details_card, grip]);

        let mut x = m;
        for (hwnd, caption) in [(c.copy, COPY_TEXT), (c.web, WEB_TEXT)] {
            let bw = ui::button_width(hwnd, caption);
            ui::place(hwnd, at(x, bottom_y, bw, bh));
            x += bw + gap;
        }
        let bw = ui::button_width(c.close, "Close");
        ui::place(c.close, at(right - bw, bottom_y, bw, bh));
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        match id {
            _ if (LEVELS..LEVELS + 4).contains(&id) => {
                let index = id - LEVELS;
                self.filter.levels[index] = !self.filter.levels[index];
                self.filter_changed();
            }
            _ if (RANGES..RANGES + 3).contains(&id) => {
                let range = Range::ALL[id - RANGES];
                if range != self.filter.range {
                    self.filter.range = range;
                    self.filter_changed();
                }
            }
            SEARCH if code == EN_CHANGE => {
                if let Some(c) = self.controls {
                    self.filter.text = ui::window_text(c.search);
                }
                self.refilter();
            }
            LIST if code == LBN_SELCHANGE || code == toolwin::ACTIVATE => self.choose(),
            COPY => self.copy(hwnd),
            WEB => self.search_web(hwnd),
            CLOSE => unsafe {
                DestroyWindow(hwnd);
            },
            _ => {}
        }
        None
    }

    fn tick(&mut self, _hwnd: HWND) {
        if let Reading::Running { result, .. } = &self.reading {
            match result.try_recv() {
                Ok(Ok(loaded)) => {
                    self.reading = Reading::Idle;
                    self.loaded = Some(loaded);
                    self.refilter();
                }
                Ok(Err(ReadError::Cancelled)) => self.reading = Reading::Idle,
                Ok(Err(ReadError::Invalid(reason) | ReadError::Unavailable(reason))) => {
                    self.reading = Reading::Idle;
                    self.failure = Some(reason);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.reading = Reading::Idle;
                    self.failure = Some("the reading stopped unexpectedly".into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.render();
    }

    fn cursor_at(&self, x: i32, y: i32) -> Option<windows_sys::core::PCWSTR> {
        let share = DETAILS_SHARE.with(|d| d.get());
        let on = self.dragging.is_some() || self.split.is_some_and(|s| s.on_bar(share, x, y));
        on.then_some(windows_sys::Win32::UI::WindowsAndMessaging::IDC_SIZENS)
    }

    fn mouse(&mut self, hwnd: HWND, msg: u32, x: i32, y: i32) -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
        };
        let Some(split) = self.split else {
            return false;
        };
        let share = DETAILS_SHARE.with(|d| d.get());
        match msg {
            WM_LBUTTONDOWN if split.on_bar(share, x, y) => {
                self.dragging = Some(y - split.bar_top(share));
                true
            }
            WM_MOUSEMOVE => {
                if let Some(offset) = self.dragging {
                    let next = split.share_for(y - offset);
                    if (next - share).abs() > f32::EPSILON {
                        DETAILS_SHARE.with(|d| d.set(next));
                        if let Some((_, w, h, dpi)) = self.window {
                            self.layout(hwnd, w, h, dpi);
                            unsafe {
                                windows_sys::Win32::Graphics::Gdi::InvalidateRect(
                                    hwnd,
                                    std::ptr::null(),
                                    1,
                                )
                            };
                        }
                    }
                }
                false
            }
            WM_LBUTTONUP => {
                self.dragging = None;
                false
            }
            _ => false,
        }
    }

    fn draw_item(&self, _list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        let background = if state.selected {
            colors.raised_hover
        } else if state.hot {
            colors.raised
        } else {
            colors.card
        };
        ui::fill_rect(dc, rect, colors.card);
        let canvas = ui::Canvas::new(dc);
        if let Some(canvas) = &canvas {
            if background != colors.card {
                canvas.fill_round(
                    (
                        rect.left as f32,
                        (rect.top + s(2)) as f32,
                        (rect.right - rect.left) as f32,
                        (rect.bottom - rect.top - s(4)) as f32,
                    ),
                    s(6) as f32,
                    background,
                );
            }
        }
        let Some(row) = self
            .view
            .rows
            .get(index)
            .and_then(|&i| self.loaded.as_ref()?.rows.get(i))
        else {
            return;
        };
        let mid = (rect.top + rect.bottom) / 2;
        let mark = row.mark();
        let tone = match mark {
            Mark::Serious => colors.serious,
            Mark::Warn => colors.warn,
            Mark::Muted => colors.muted,
        };
        if let Some(canvas) = &canvas {
            level_icon(
                canvas,
                ((rect.left + s(18)) as f32, mid as f32),
                s(8) as f32,
                Level::of(row.event.level),
                tone,
                &colors,
                mark == Mark::Serious,
            );
        }
        let line = |left: i32, right: i32| RECT {
            left,
            top: rect.top,
            right,
            bottom: rect.bottom,
        };
        let one = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
        let stamp = event_list::local(&row.event);
        let time_x = rect.left + s(36);
        ui::draw_text(
            dc,
            &event_list::short_time(&stamp),
            &line(time_x, time_x + s(108)),
            fonts.body,
            colors.muted,
            one | DT_LEFT,
        );
        let id_x = time_x + s(112);
        ui::draw_text(
            dc,
            &row.event.id.to_string(),
            &line(id_x, id_x + s(48)),
            fonts.body,
            colors.muted,
            one | DT_RIGHT,
        );
        let source_x = id_x + s(60);
        let end = rect.right - s(10);
        let kind_w = match row.kind {
            Some(_) => s(190).min((end - source_x) * 2 / 5),
            None => 0,
        };
        if let Some(kind) = row.kind {
            let color = if row.serious && !colors.high_contrast {
                colors.serious
            } else {
                colors.muted
            };
            ui::draw_text(
                dc,
                kind,
                &line(end - kind_w, end),
                fonts.body,
                color,
                one | DT_RIGHT,
            );
        }
        let source_end = if kind_w > 0 {
            end - kind_w - s(12)
        } else {
            end
        };
        ui::draw_text(
            dc,
            &row.event.provider,
            &line(source_x, source_end),
            fonts.body,
            colors.text,
            one | DT_LEFT,
        );
    }
}

/// A level's icon: a filled circle with ! for critical and x for error, a triangle with !
/// for warning, a ring with i for information.
fn level_icon(
    canvas: &ui::Canvas,
    (cx, cy): (f32, f32),
    r: f32,
    level: Level,
    color: u32,
    colors: &ui::Palette,
    serious: bool,
) {
    let stroke = (r / 4.0).max(1.5);
    match level {
        Level::Critical => {
            canvas.circle(cx, cy, r, color);
            canvas.polyline(
                &[(cx, cy - r * 0.45), (cx, cy + r * 0.1)],
                colors.card,
                stroke,
            );
            canvas.circle(cx, cy + r * 0.45, stroke * 0.6, colors.card);
        }
        Level::Error => {
            canvas.circle(cx, cy, r, color);
            ui::cross(canvas, cx, cy, r * 0.38, colors.card, stroke.round() as i32);
        }
        Level::Warning => {
            let top = (cx, cy - r);
            canvas.polyline(
                &[top, (cx + r, cy + r * 0.8), (cx - r, cy + r * 0.8), top],
                color,
                stroke * 0.8,
            );
            canvas.polyline(&[(cx, cy - r * 0.3), (cx, cy + r * 0.25)], color, stroke);
            canvas.circle(cx, cy + r * 0.55, stroke * 0.5, color);
        }
        Level::Information => {
            canvas.arc((cx, cy, r - stroke / 2.0), 0.0, 360.0, color, stroke * 0.75);
            canvas.circle(cx, cy - r * 0.4, stroke * 0.5, color);
            canvas.polyline(&[(cx, cy - r * 0.05), (cx, cy + r * 0.5)], color, stroke);
        }
    }
    if serious && colors.high_contrast {
        // A second ring tells serious from the rest when every tone is one colour.
        canvas.arc((cx, cy, r + stroke * 1.5), 0.0, 360.0, color, stroke * 0.75);
    }
}

#[cfg(test)]
mod tests {
    use super::Split;

    fn split() -> Split {
        Split {
            top: 300,
            usable: 400,
            left: 24,
            right: 600,
            bar: 12,
            min: 80,
        }
    }

    #[test]
    fn the_bar_sits_below_the_list_and_takes_its_whole_width() {
        let s = split();
        assert_eq!(s.list_height(0.4), 240);
        assert_eq!(s.bar_top(0.4), 540);
        assert!(s.on_bar(0.4, 24, 540) && s.on_bar(0.4, 599, 551));
        assert!(!s.on_bar(0.4, 23, 545) && !s.on_bar(0.4, 100, 552) && !s.on_bar(0.4, 100, 539));
    }

    #[test]
    fn dragging_moves_the_bar_but_keeps_both_panes_usable() {
        let s = split();
        assert!((s.share_for(400) - 0.75).abs() < 1e-6);
        assert_eq!(s.list_height(s.share_for(400)), 100);
        // Past either end the panes stop at their minimum height.
        assert_eq!(s.list_height(s.share_for(0)), 80);
        assert_eq!(s.list_height(s.share_for(10_000)), 320);
        assert_eq!(s.list_height(0.0), 320);
        assert_eq!(s.list_height(1.0), 80);
    }
}
