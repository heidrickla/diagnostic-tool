//! The drive's condition strip: one fixed row of six cells under the title of every window
//! that reads a live drive, with the drive's temperature, reallocated, pending and
//! uncorrectable sectors, the drops this run and the reading speed, each with its change
//! over 30 minutes and a two-hour line, so the technician can watch the drive's status
//! during recovery and make judgment calls. The cells never move:
//! their rectangles depend on the window's width alone (`ui_layout::strip_cells`).
//!
//! What it shows is shared by every window of the process, by disk: the rescue image window
//! hands over its event log, its readings and its speed, and the recovery window the reading
//! it made when it opened. Nothing here reads the drive.
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use diagnostics::recovery::condition::{self, Cell, Condition, History, Live, Speed, State, Tail};
use diagnostics::recovery::health_log::Reading;
use diagnostics::recovery::image::WearRate;
use diagnostics::recovery::timed::Throttle;
use diagnostics::ui_layout::{cell_parts, grid, scale, strip_cells, CellParts, Rect, STRIP_H};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{DT_END_ELLIPSIS, DT_SINGLELINE, DT_VCENTER, HDC};

use crate::toolwin::{self, Flow};
use crate::ui::{self, Kind, Tone};

/// The strip's canvas id; one strip per window.
pub const ID: usize = 0x7D01;
/// How often a followed event log is read again.
const POLL: Duration = Duration::from_secs(2);

/// What is known of one drive.
#[derive(Default)]
struct Feed {
    history: History,
    tail: Option<Tail>,
    polled: Option<Instant>,
    speed: Option<Speed>,
    every: Option<String>,
    pauses: Option<(Throttle, WearRate)>,
}

thread_local! {
    static FEEDS: RefCell<HashMap<u32, Feed>> = RefCell::new(HashMap::new());
}

fn with_feed<T>(disk: u32, f: impl FnOnce(&mut Feed) -> T) -> T {
    FEEDS.with(|feeds| f(feeds.borrow_mut().entry(disk).or_default()))
}

/// Follows the event log of a rescue of `disk` (`events::path_for` of its image).
pub fn follow(disk: u32, events: &Path) {
    with_feed(disk, |feed| {
        if feed.tail.as_ref().map(Tail::path) != Some(events) {
            feed.tail = Some(Tail::new(events.to_path_buf()));
            feed.polled = None;
        }
    });
}

/// A reading of `disk` made by a window or its run, and how often such readings come.
pub fn reading(disk: u32, reading: &Reading, every: &str) {
    with_feed(disk, |feed| {
        feed.history.reading(reading);
        feed.every = Some(every.to_string());
    });
}

/// How fast `disk` is read now; None once nothing reads it.
pub fn speed(disk: u32, speed: Option<Speed>) {
    with_feed(disk, |feed| feed.speed = speed);
}

/// The heat and error pauses set for `disk`, for the states before a run has logged its own.
pub fn pauses(disk: u32, heat: Throttle, wear: WearRate) {
    with_feed(disk, |feed| feed.pauses = Some((heat, wear)));
}

fn now() -> i64 {
    diagnostics::clock::local(SystemTime::now()).seconds()
}

/// The strip of `disk` as it is now.
pub fn condition_of(disk: u32) -> Condition {
    with_feed(disk, |feed| {
        if let Some(tail) = &mut feed.tail {
            if feed.polled.is_none_or(|at| at.elapsed() >= POLL) {
                feed.polled = Some(Instant::now());
                for line in tail.read() {
                    feed.history.line(&line);
                }
            }
        }
        let now = now();
        feed.history.trim(now);
        let (heat, wear) = feed.pauses.unwrap_or_default();
        condition::condition(
            &feed.history,
            &Live {
                now,
                heat,
                wear,
                speed: feed.speed.clone(),
                every: feed
                    .every
                    .clone()
                    .unwrap_or_else(|| "when a rescue reads it".into()),
            },
        )
    })
}

/// The strip in one window: its canvas and the muted line under it. A window reading an
/// image file has none: there is no drive to show.
pub struct Strip {
    disk: Option<u32>,
    canvas: HWND,
    stamp: HWND,
    shown: Option<Condition>,
}

impl Strip {
    pub fn new(hwnd: HWND, disk: Option<u32>) -> Self {
        let canvas = toolwin::canvas(hwnd, ID);
        let stamp = ui::text(hwnd, Kind::Muted, Tone::Neutral, false, "");
        ui::show(canvas, disk.is_some());
        ui::show(stamp, disk.is_some());
        let mut strip = Self {
            disk,
            canvas,
            stamp,
            shown: None,
        };
        strip.refresh();
        strip
    }

    /// The drive shown, which follows a drive that came back under another number.
    pub fn set_disk(&mut self, disk: Option<u32>) {
        if self.disk != disk {
            self.disk = disk;
            ui::show(self.canvas, disk.is_some());
            ui::show(self.stamp, disk.is_some());
            self.shown = None;
            self.refresh();
        }
    }

    /// Places the strip and its line at the flow's place: always the same height, whatever
    /// they say. A strip with no drive takes no room.
    pub fn place(&self, f: &mut Flow) {
        if self.disk.is_none() {
            return;
        }
        let h = f.s(STRIP_H);
        ui::place(
            self.canvas,
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h,
            },
        );
        f.y += h;
        f.space(4);
        let line = f.s(grid::CAPTION_H + 4);
        ui::place(
            self.stamp,
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h: line,
            },
        );
        f.y += line;
        f.space(10);
    }

    /// Takes what is known now, repainting only when it changed.
    pub fn refresh(&mut self) {
        let Some(disk) = self.disk else {
            return;
        };
        let now = condition_of(disk);
        if self.shown.as_ref() != Some(&now) {
            ui::set_text(self.stamp, &now.stamp);
            self.shown = Some(now);
            toolwin::redraw(self.canvas);
        }
    }

    /// Draws the strip when `list` is its canvas; false for another.
    pub fn draw(&self, list: usize, dc: HDC, rect: &RECT, dpi: u32) -> bool {
        if list != ID {
            return false;
        }
        if let Some(shown) = &self.shown {
            paint(shown, dc, rect, dpi);
        }
        true
    }
}

/// Where each cell's parts go in `area`: by the area alone, never by what the cells say.
fn cell_rects(area: Rect, dpi: u32, _shown: &Condition) -> Vec<CellParts> {
    strip_cells(area.x, area.y, area.w, dpi)
        .iter()
        .map(|cell| cell_parts(*cell, dpi))
        .collect()
}

fn state_color(state: State, colors: &ui::Palette) -> u32 {
    match state {
        State::Ok => colors.ok,
        State::Warn => colors.warn,
        State::Bad => colors.serious,
        State::Unknown => colors.subtle,
    }
}

fn paint(shown: &Condition, dc: HDC, rect: &RECT, dpi: u32) {
    let colors = ui::current();
    ui::fill_rect(dc, rect, colors.page);
    let area = Rect {
        x: rect.left,
        y: rect.top,
        w: rect.right - rect.left,
        h: rect.bottom - rect.top,
    };
    let parts = cell_rects(area, dpi, shown);
    let cells = strip_cells(area.x, area.y, area.w, dpi);
    let s = |v| scale(dpi, v);
    let fonts = ui::fonts(dpi);
    // GDI+ shapes first, then the GDI text (see `rescue_image_view::draw_dots`).
    if let Some(canvas) = ui::Canvas::new(dc) {
        let whole = (area.x as f32, area.y as f32, area.w as f32, area.h as f32);
        canvas.fill_round(whole, s(8) as f32, colors.card);
        canvas.stroke_round(whole, s(8) as f32, colors.border, s(1) as f32);
        for (i, (cell, part)) in shown.cells.iter().zip(&parts).enumerate() {
            let color = state_color(cell.state, &colors);
            if i > 0 {
                let x = cells[i].x as f32;
                canvas.polyline(
                    &[(x, area.y as f32 + 1.0), (x, area.bottom() as f32 - 1.0)],
                    colors.border,
                    s(1) as f32,
                );
            }
            canvas.circle(
                (part.label.x + s(4)) as f32,
                (part.label.y + part.label.h / 2) as f32,
                s(4) as f32,
                color,
            );
            let points = trend_points(cell, part.trend);
            canvas.trace(&points, color, s(2) as f32 * 0.75);
        }
    }
    let line = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
    for (i, (cell, part)) in shown.cells.iter().zip(&parts).enumerate() {
        let label = RECT {
            left: part.label.x + s(14),
            ..as_rect(part.label)
        };
        ui::draw_text(dc, &cell.label, &label, fonts.caption, colors.muted, line);
        ui::draw_text(
            dc,
            &cell.value,
            &as_rect(part.value),
            fonts.title,
            colors.text,
            line,
        );
        // A count rising is the change to notice.
        let rising = (1..=4).contains(&i) && cell.change.starts_with('+');
        let change_color = if rising { colors.warn } else { colors.muted };
        ui::draw_text(
            dc,
            &cell.change,
            &as_rect(part.change),
            fonts.caption,
            change_color,
            line,
        );
        ui::draw_text(
            dc,
            &cell.note,
            &as_rect(part.note),
            fonts.caption,
            colors.muted,
            line,
        );
    }
}

fn as_rect(r: Rect) -> RECT {
    RECT {
        left: r.x,
        top: r.y,
        right: r.right(),
        bottom: r.bottom(),
    }
}

/// The cell's two hours as points in `area`: time across, the value scaled to the lowest
/// and highest it reached, a flat line through the middle when it did not change.
fn trend_points(cell: &Cell, area: Rect) -> Vec<(f32, f32)> {
    let (low, high) = cell.trend.iter().fold((f64::MAX, f64::MIN), |(lo, hi), p| {
        (lo.min(p.1), hi.max(p.1))
    });
    let span = high - low;
    let mut points: Vec<(f32, f32)> = cell
        .trend
        .iter()
        .map(|&(x, v)| {
            let level = if span > 0.0 {
                ((v - low) / span) as f32
            } else {
                0.5
            };
            (
                area.x as f32 + x * area.w as f32,
                area.bottom() as f32 - 1.0 - level * (area.h - 2) as f32,
            )
        })
        .collect();
    // One reading is a level, not a dot: drawn to now.
    if let [only] = points[..] {
        points.push((area.right() as f32, only.1));
    }
    points
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(value: &str, change: &str) -> Condition {
        let cell = |label: &str| Cell {
            label: label.into(),
            value: value.into(),
            change: change.into(),
            note: change.into(),
            state: State::Warn,
            trend: vec![(0.0, 1.0), (1.0, 2.0)],
        };
        Condition {
            cells: [
                cell("Temperature"),
                cell("Reallocated"),
                cell("Pending"),
                cell("Uncorrectable"),
                cell("Drops this run"),
                cell("Reading"),
            ],
            stamp: change.into(),
        }
    }

    /// The guard: the strip's cells keep their rectangles whatever their values say, short
    /// or long, so a value changing never moves anything.
    #[test]
    fn the_cells_keep_their_place_whatever_they_say() {
        for dpi in [96, 144, 192] {
            let area = Rect {
                x: 24,
                y: 80,
                w: scale(dpi, 732),
                h: scale(dpi, STRIP_H),
            };
            let short = cell_rects(area, dpi, &shown("1", ""));
            let long = cell_rects(
                area,
                dpi,
                &shown("15,657,000,000 sectors", "+1,234,567 in 30 min, and more"),
            );
            assert_eq!(short, long, "{dpi}");
            assert_eq!(short.len(), 6);
            for part in &short {
                assert!(part.trend.bottom() <= area.bottom(), "{dpi}");
            }
        }
    }

    #[test]
    fn a_trend_spans_its_area_and_a_single_reading_is_a_level() {
        let area = Rect {
            x: 10,
            y: 10,
            w: 100,
            h: 20,
        };
        let mut cell = shown("1", "").cells[0].clone();
        let points = trend_points(&cell, area);
        assert_eq!(points.first().unwrap().0, 10.0);
        assert_eq!(points.last().unwrap().0, 110.0);
        assert!(
            points[0].1 > points[1].1,
            "the higher value is drawn higher"
        );
        cell.trend = vec![(0.5, 7.0)];
        let points = trend_points(&cell, area);
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].1, points[1].1);
        cell.trend.clear();
        assert!(trend_points(&cell, area).is_empty());
    }
}
