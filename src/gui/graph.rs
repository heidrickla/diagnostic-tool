//! Live graphs for the processor and memory window, drawn with GDI+ into a canvas's buffer:
//! a trace over a time window with the newest sample at the right edge, a grid of small
//! traces, and a bar split into parts. The geometry is plain functions, tested on its own.
use diagnostics::ui_layout::scale;
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{
    DT_END_ELLIPSIS, DT_LEFT, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, HDC,
};

use crate::ui::{self, rgb, Canvas, Palette};

/// Which series a trace draws; each has its own colour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ink {
    Cpu,
    Memory,
}

// Series colours on the dark surface, in the 400 weight of the palette's status colours:
// sky for processor use and violet for memory, amber for modified pages, sky for standby.
const CPU_INK: u32 = rgb(0x38BDF8);
const MEMORY_INK: u32 = rgb(0xA78BFA);
const MODIFIED_INK: u32 = rgb(0xFBBF24);
const STANDBY_INK: u32 = rgb(0x38BDF8);
/// Thousandths of the line colour in the fill under it.
const FILL_KEEP: u32 = 300;

/// A trace's line and the fill under it. In high contrast the line takes the system highlight
/// colour and there is no fill, so only system colours are drawn.
pub fn ink(colors: &Palette, which: Ink) -> (u32, Option<u32>) {
    if colors.high_contrast {
        return (colors.primary, None);
    }
    let line = match which {
        Ink::Cpu => CPU_INK,
        Ink::Memory => MEMORY_INK,
    };
    (line, Some(blend(line, colors.card, FILL_KEEP)))
}

/// The memory composition bar's colours: in use, modified, standby and free. High contrast
/// uses the system highlight, hot-track, grey-text and window-text colours.
pub fn composition(colors: &Palette) -> [u32; 4] {
    if colors.high_contrast {
        use windows_sys::Win32::Graphics::Gdi::{GetSysColor, COLOR_GRAYTEXT, COLOR_HOTLIGHT};
        let sys = |index| unsafe { GetSysColor(index) };
        return [
            colors.primary,
            sys(COLOR_HOTLIGHT),
            sys(COLOR_GRAYTEXT),
            colors.text,
        ];
    }
    [MEMORY_INK, MODIFIED_INK, STANDBY_INK, colors.subtle]
}

/// Mixes `a` over `b`, keeping `keep` thousandths of `a`, for COLORREF values.
pub fn blend(a: u32, b: u32, keep: u32) -> u32 {
    let channel = |shift: u32| {
        let (x, y) = ((a >> shift) & 0xFF, (b >> shift) & 0xFF);
        ((x * keep + y * (1000 - keep)) / 1000) << shift
    };
    channel(0) | channel(8) | channel(16)
}

/// The points of a trace through `values` (0 to 100, oldest first, newest at the right
/// edge), in a plot `slots` samples wide. Samples one pixel apart or closer share a column,
/// which takes the highest, so a short peak is never lost. A missing value ends a segment.
pub fn plot(
    values: &[Option<f64>],
    slots: usize,
    area: (f32, f32, f32, f32),
) -> Vec<Vec<(f32, f32)>> {
    let (x0, y0, w, h) = area;
    let slots = slots.max(2);
    let step = w / (slots - 1) as f32;
    let shown = &values[values.len().saturating_sub(slots)..];
    let n = shown.len();
    let mut segments: Vec<Vec<(f32, f32)>> = Vec::new();
    let mut current: Vec<(f32, f32)> = Vec::new();
    for (i, v) in shown.iter().enumerate() {
        let x = x0 + w - (n - 1 - i) as f32 * step;
        let Some(v) = v.filter(|v| v.is_finite()) else {
            if current.len() > 1 {
                segments.push(std::mem::take(&mut current));
            }
            current.clear();
            continue;
        };
        let y = y0 + h - (v.clamp(0.0, 100.0) as f32 / 100.0) * h;
        match current.last_mut() {
            // Same pixel column: keep the higher point (the smaller y).
            Some(last) if (x - last.0).abs() < 1.0 => last.1 = last.1.min(y),
            _ => current.push((x, y)),
        }
    }
    if current.len() > 1 {
        segments.push(current);
    } else if current.len() == 1 && segments.is_empty() {
        // A single sample shows as a short level line ending at the right edge.
        let (x, y) = current[0];
        segments.push(vec![(x - step.min(w), y), (x, y)]);
    }
    segments
}

/// Which of the newest `n` samples (0 the oldest of them) lies nearest pixel `x` in a plot
/// `slots` samples wide; None when `x` is outside the plot or before the first sample.
pub fn sample_at(x: f32, plot_x: f32, w: f32, slots: usize, n: usize) -> Option<usize> {
    if n == 0 || x < plot_x - 1.0 || x > plot_x + w + 1.0 {
        return None;
    }
    let slots = slots.max(2);
    let shown = n.min(slots);
    let step = w / (slots - 1) as f32;
    let back = ((plot_x + w - x) / step).round().max(0.0) as usize;
    (back < shown).then(|| shown - 1 - back + (n - shown))
}

/// Columns and rows for `n` small graphs in a `w` by `h` area, chosen so each cell is
/// closest to twice as wide as it is high and the last row is not left half empty.
pub fn grid_shape(n: usize, w: i32, h: i32) -> (usize, usize) {
    let n = n.max(1);
    let mut best = (n, 1usize, f32::MAX);
    for cols in 1..=n {
        let rows = n.div_ceil(cols);
        let cell_w = w as f32 / cols as f32;
        let cell_h = h as f32 / rows as f32;
        if cell_h <= 0.0 {
            continue;
        }
        // Empty cells in the last row count against a layout as well.
        let empty = (cols * rows - n) as f32 / n as f32;
        let miss = ((cell_w / cell_h) / 2.0).ln().abs() + empty;
        // On a tie the wider layout wins.
        if miss <= best.2 {
            best = (cols, rows, miss);
        }
    }
    (best.0, best.1)
}

/// What a trace graph shows besides its values.
pub struct Look<'a> {
    pub title: &'a str,
    /// The figure at the top right: the scale's top, or the value now.
    pub top_right: &'a str,
    /// Under the plot, left and right: how far back it reaches, and "Now" or the pause time.
    pub from: &'a str,
    pub to: &'a str,
    pub slots: usize,
    /// Pixels the plot ends at on each side, inside the rect.
    pub compact: bool,
    /// The sample under the pointer, its index into `values`, and its label.
    pub hover: Option<(usize, String)>,
    pub ink: Ink,
}

/// The plot area inside a graph's rect: room for the title above and the times below.
pub fn plot_area(rect: &RECT, dpi: u32, compact: bool) -> (f32, f32, f32, f32) {
    let s = |v: i32| scale(dpi, v) as f32;
    let (top, bottom) = if compact {
        (s(20), s(4))
    } else {
        (s(26), s(22))
    };
    let side = if compact { s(4) } else { s(10) };
    (
        rect.left as f32 + side,
        rect.top as f32 + top,
        (rect.right - rect.left) as f32 - 2.0 * side,
        ((rect.bottom - rect.top) as f32 - top - bottom).max(1.0),
    )
}

/// Draws one trace graph into `rect`.
pub fn draw_trace(
    dc: HDC,
    canvas: Option<&Canvas>,
    rect: &RECT,
    dpi: u32,
    colors: &Palette,
    values: &[Option<f64>],
    look: &Look<'_>,
) {
    let s = |v: i32| scale(dpi, v);
    let fonts = ui::fonts(dpi);
    let (x, y, w, h) = plot_area(rect, dpi, look.compact);
    let (line, fill) = ink(colors, look.ink);
    let grid = colors.border;
    if let Some(canvas) = canvas {
        // The plot's frame and quarter lines.
        canvas.stroke_round((x, y, w, h), s(4) as f32, grid, s(1).max(1) as f32);
        for quarter in 1..4 {
            let gy = y + h * quarter as f32 / 4.0;
            canvas.polyline(&[(x, gy), (x + w, gy)], grid, 1.0);
        }
        if !look.compact {
            // Six time divisions.
            for part in 1..6 {
                let gx = x + w * part as f32 / 6.0;
                canvas.polyline(&[(gx, y), (gx, y + h)], grid, 1.0);
            }
        }
        for segment in plot(values, look.slots, (x, y, w, h)) {
            let mut area = segment.clone();
            if let (Some(first), Some(last)) = (segment.first(), segment.last()) {
                area.push((last.0, y + h));
                area.push((first.0, y + h));
            }
            if let Some(fill) = fill {
                canvas.fill_polygon(&area, fill);
            }
            // A full-size graph's line is 2 px at 96 dpi; the small ones' 1.5 px.
            let stroke = s(2).max(1) as f32 * if look.compact { 0.75 } else { 1.0 };
            canvas.trace(&segment, line, stroke);
        }
        if let Some((index, _)) = &look.hover {
            let n = values.len();
            let shown = n.min(look.slots.max(2));
            let step = w / (look.slots.max(2) - 1) as f32;
            if *index + shown >= n {
                let back = (n - 1 - index) as f32;
                let hx = x + w - back * step;
                canvas.polyline(&[(hx, y), (hx, y + h)], colors.muted, 1.0);
                if let Some(Some(v)) = values.get(*index) {
                    let hy = y + h - (v.clamp(0.0, 100.0) as f32 / 100.0) * h;
                    canvas.circle(hx, hy, s(3) as f32, colors.text);
                }
            }
        }
    }
    let flags = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
    let title_h = if look.compact { s(18) } else { s(22) };
    let head = RECT {
        left: x as i32,
        top: rect.top,
        right: (x + w) as i32,
        bottom: rect.top + title_h,
    };
    let title_font = if look.compact {
        fonts.caption
    } else {
        fonts.strong
    };
    ui::draw_text(
        dc,
        look.title,
        &head,
        title_font,
        colors.text,
        flags | DT_LEFT,
    );
    // The hover label takes the right of the title line while the pointer is on the plot.
    let right_text = look
        .hover
        .as_ref()
        .map_or(look.top_right, |(_, label)| label.as_str());
    let right_ink = if look.hover.is_some() {
        colors.text
    } else {
        colors.muted
    };
    let right_font = if look.compact || look.hover.is_none() {
        fonts.caption
    } else {
        fonts.body
    };
    ui::draw_text(
        dc,
        right_text,
        &head,
        right_font,
        right_ink,
        flags | DT_RIGHT,
    );
    if !look.compact {
        let foot = RECT {
            left: x as i32,
            top: (y + h) as i32 + s(2),
            right: (x + w) as i32,
            bottom: rect.bottom,
        };
        ui::draw_text(
            dc,
            look.from,
            &foot,
            fonts.caption,
            colors.subtle,
            flags | DT_LEFT,
        );
        ui::draw_text(
            dc,
            look.to,
            &foot,
            fonts.caption,
            colors.subtle,
            flags | DT_RIGHT,
        );
    }
}

/// One part of a split bar.
pub struct Part {
    pub name: &'static str,
    pub bytes: u64,
    pub color: u32,
}

/// Draws a bar split into `parts` across `rect`'s top, with a legend under it. Parts are
/// separated by a gap in the card colour, so they stay apart in high contrast too.
pub fn draw_split_bar(
    dc: HDC,
    canvas: Option<&Canvas>,
    rect: &RECT,
    dpi: u32,
    colors: &Palette,
    parts: &[Part],
    legend: &[String],
) {
    let s = |v: i32| scale(dpi, v);
    let fonts = ui::fonts(dpi);
    let total: u64 = parts.iter().map(|p| p.bytes).sum();
    let (x, y) = (
        rect.left as f32 + s(10) as f32,
        rect.top as f32 + s(10) as f32,
    );
    let w = (rect.right - rect.left) as f32 - 2.0 * s(10) as f32;
    let h = s(18) as f32;
    if let Some(canvas) = canvas {
        canvas.fill_round((x, y, w, h), s(4) as f32, colors.raised);
        if total > 0 {
            let gap = s(2) as f32;
            let mut at = x;
            for (i, p) in parts.iter().enumerate() {
                let share = p.bytes as f32 / total as f32 * w;
                let last = i + 1 == parts.len();
                let width = if last { x + w - at } else { share };
                if width >= 1.0 {
                    let drawn = if last { width } else { (width - gap).max(1.0) };
                    canvas.fill_round((at, y, drawn, h), s(3) as f32, p.color);
                }
                at += share;
            }
        }
    }
    // The legend: a dot and a text per part, in rows of up to four.
    let row_h = s(20);
    let top = (y + h) as i32 + s(10);
    let columns = parts.len().clamp(1, 4) as i32;
    let col_w = (w as i32) / columns;
    for (i, (p, text)) in parts.iter().zip(legend).enumerate() {
        let (row, col) = (i as i32 / columns, i as i32 % columns);
        let left = x as i32 + col * col_w;
        let cy = top + row * row_h + row_h / 2;
        if let Some(canvas) = canvas {
            canvas.circle((left + s(5)) as f32, cy as f32, s(4) as f32, p.color);
        }
        let r = RECT {
            left: left + s(14),
            top: top + row * row_h,
            right: left + col_w - s(6),
            bottom: top + (row + 1) * row_h,
        };
        ui::draw_text(
            dc,
            text,
            &r,
            fonts.caption,
            colors.muted,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
    }
}

/// The height a split bar with `parts` needs.
pub fn split_bar_height(dpi: u32, parts: usize) -> i32 {
    let rows = parts.div_ceil(4).max(1) as i32;
    scale(dpi, 10 + 18 + 10 + 10) + rows * scale(dpi, 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG 2 relative luminance of a COLORREF.
    fn luminance(c: u32) -> f64 {
        let lin = |v: u32| {
            let v = f64::from(v & 0xFF) / 255.0;
            if v <= 0.040_45 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(c) + 0.7152 * lin(c >> 8) + 0.0722 * lin(c >> 16)
    }

    fn contrast(a: u32, b: u32) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn every_series_colour_stands_out_on_the_dark_surface() {
        let colors = ui::current();
        assert!(!colors.high_contrast);
        let (cpu, cpu_fill) = ink(&colors, Ink::Cpu);
        let (memory, memory_fill) = ink(&colors, Ink::Memory);
        assert_ne!(cpu, memory);
        for (line, fill) in [(cpu, cpu_fill), (memory, memory_fill)] {
            let fill = fill.expect("a fill on the dark surface");
            // WCAG 1.4.11 asks 3:1 for the parts of a graphic needed to read it.
            assert!(contrast(line, colors.card) >= 3.0, "{line:06X} on the card");
            assert!(contrast(line, fill) >= 3.0, "{line:06X} over its fill");
            assert!(
                contrast(fill, colors.card) > 1.2,
                "the fill shows on the card"
            );
        }
        let parts = composition(&colors);
        for (i, a) in parts.iter().enumerate() {
            assert!(contrast(*a, colors.card) >= 3.0, "segment {i} on the card");
            for b in &parts[i + 1..] {
                assert_ne!(a, b, "every segment has its own color");
            }
        }
    }

    #[test]
    fn high_contrast_draws_traces_in_the_system_highlight_without_a_fill() {
        let colors = Palette {
            high_contrast: true,
            primary: 0x00FF00,
            text: 0xFFFFFF,
            ..ui::current()
        };
        assert_eq!(ink(&colors, Ink::Cpu), (0x00FF00, None));
        assert_eq!(ink(&colors, Ink::Memory), (0x00FF00, None));
        let parts = composition(&colors);
        assert_eq!((parts[0], parts[3]), (0x00FF00, 0xFFFFFF));
    }

    #[test]
    fn the_newest_sample_sits_at_the_right_edge() {
        let values = vec![Some(0.0), Some(50.0), Some(100.0)];
        let segs = plot(&values, 60, (0.0, 0.0, 590.0, 100.0));
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].last(), Some(&(590.0, 0.0)));
        assert_eq!(segs[0][0], (570.0, 100.0));
    }

    #[test]
    fn a_missing_sample_splits_the_trace() {
        let values = vec![Some(10.0), Some(20.0), None, Some(30.0), Some(40.0)];
        let segs = plot(&values, 10, (0.0, 0.0, 90.0, 100.0));
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].len(), 2);
    }

    #[test]
    fn a_long_window_on_a_narrow_plot_keeps_each_columns_peak() {
        // 1,800 samples on 300 pixels: six to a column, one spike among them.
        let mut values = vec![Some(5.0); 1800];
        values[900] = Some(95.0);
        let segs = plot(&values, 1800, (0.0, 0.0, 300.0, 100.0));
        let points: usize = segs.iter().map(Vec::len).sum();
        assert!(points <= 302, "{points} points");
        let lowest_y = segs.iter().flatten().map(|p| p.1).fold(f32::MAX, f32::min);
        assert!(
            (lowest_y - 5.0).abs() < 0.01,
            "the spike is gone: {lowest_y}"
        );
    }

    #[test]
    fn values_out_of_range_stay_inside_the_plot() {
        let values = vec![Some(-20.0), Some(250.0), Some(f64::NAN)];
        let segs = plot(&values, 3, (0.0, 0.0, 20.0, 100.0));
        assert_eq!(segs, vec![vec![(0.0, 100.0), (10.0, 0.0)]]);
        assert_eq!(plot(&[], 60, (0.0, 0.0, 10.0, 10.0)), Vec::<Vec<_>>::new());
    }

    #[test]
    fn hovering_picks_the_nearest_sample() {
        // 60 slots over 590 pixels: 10 pixels a sample; 100 samples held.
        assert_eq!(sample_at(590.0, 0.0, 590.0, 60, 100), Some(99));
        assert_eq!(sample_at(584.0, 0.0, 590.0, 60, 100), Some(98));
        assert_eq!(sample_at(0.0, 0.0, 590.0, 60, 100), Some(40));
        // Only five samples so far: the left part of the plot holds none.
        assert_eq!(sample_at(100.0, 0.0, 590.0, 60, 5), None);
        assert_eq!(sample_at(560.0, 0.0, 590.0, 60, 5), Some(1));
        assert_eq!(sample_at(700.0, 0.0, 590.0, 60, 5), None);
        assert_eq!(sample_at(10.0, 0.0, 590.0, 60, 0), None);
    }

    #[test]
    fn small_graphs_are_laid_out_about_twice_as_wide_as_high() {
        assert_eq!(grid_shape(16, 800, 400), (4, 4));
        let (c, r) = grid_shape(8, 800, 400);
        assert!(c * r >= 8 && c >= r, "{c} by {r}");
        assert_eq!(grid_shape(1, 800, 400), (1, 1));
        // The window's own shape at 144 dpi: four by four, not five with a row of one.
        assert_eq!(grid_shape(16, 1220, 520), (4, 4));
        let (c, r) = grid_shape(24, 900, 360);
        assert!(c * r >= 24);
    }

    #[test]
    fn blending_mixes_each_channel() {
        assert_eq!(blend(0xFFFFFF, 0x000000, 500), 0x7F7F7F);
        assert_eq!(blend(0x123456, 0xABCDEF, 1000), 0x123456);
        assert_eq!(blend(0x123456, 0xABCDEF, 0), 0xABCDEF);
    }
}
