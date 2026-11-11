//! Window geometry on a 4 px logical grid, scaled to the window's DPI. Pure arithmetic,
//! so every DPI the app supports is tested without a display.

/// Logical pixels at 96 DPI to physical pixels, rounded to nearest.
pub fn scale(dpi: u32, logical: i32) -> i32 {
    let dpi = i64::from(dpi.max(96));
    ((i64::from(logical) * dpi + 48) / 96) as i32
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
}

/// Logical sizes shared by every window.
pub mod grid {
    pub const OUTER: i32 = 24;
    pub const CARD_PAD: i32 = 16;
    pub const GAP: i32 = 12;
    pub const BUTTON_H: i32 = 36;
    pub const BUTTON_GAP: i32 = 8;
    pub const BUTTON_PAD_X: i32 = 16;
    pub const ROW_H: i32 = 32;
    /// A check row: status mark, then the label, then the result right-aligned.
    pub const ROW_LABEL_X: i32 = 34;
    pub const ROW_LABEL_W: i32 = 210;
    pub const ROW_TEXT_GAP: i32 = 8;
    pub const TITLE_H: i32 = 28;
    pub const BODY_H: i32 = 20;
    pub const CAPTION_H: i32 = 16;
    pub const BADGE_H: i32 = 24;
    pub const PROGRESS_H: i32 = 6;
    pub const MAIN_WIDTH: i32 = 560;
    pub const DIALOG_WIDTH: i32 = 480;
    pub const CARD_RADIUS: i32 = 12;
    pub const BUTTON_RADIUS: i32 = 8;
}

#[derive(Debug, PartialEq)]
pub struct MainLayout {
    pub client_w: i32,
    pub client_h: i32,
    pub title: Rect,
    /// Right edge and top for the status badge; its width follows its caption.
    pub badge_right: i32,
    pub badge_y: i32,
    pub subtitle: Rect,
    pub progress_label: Rect,
    pub progress_bar: Rect,
    pub card: Rect,
    pub rows: Vec<Rect>,
    pub message: Rect,
    pub buttons_y: i32,
    pub footer: Rect,
}

/// The status window: header, progress, the check list card, a message, buttons and footer.
pub fn main_layout(dpi: u32, rows: usize, message_lines: i32) -> MainLayout {
    use grid::*;
    let s = |v| scale(dpi, v);
    let client_w = s(MAIN_WIDTH);
    let inner_x = s(OUTER);
    let inner_w = client_w - 2 * inner_x;
    let mut y = s(OUTER);
    let title = Rect {
        x: inner_x,
        y,
        w: inner_w - s(160) - help_room(dpi),
        h: s(TITLE_H),
    };
    let badge_y = y + (s(TITLE_H) - s(BADGE_H)) / 2;
    y += s(TITLE_H) + s(4);
    let subtitle = Rect {
        x: inner_x,
        y,
        w: inner_w,
        h: s(BODY_H),
    };
    y += s(BODY_H) + s(20);
    let progress_label = Rect {
        x: inner_x,
        y,
        w: inner_w,
        h: s(CAPTION_H),
    };
    y += s(CAPTION_H) + s(8);
    let progress_bar = Rect {
        x: inner_x,
        y,
        w: inner_w,
        h: s(PROGRESS_H),
    };
    y += s(PROGRESS_H) + s(16);
    let row_h = s(ROW_H);
    let card_h = 2 * s(8) + row_h * rows as i32;
    let card = Rect {
        x: inner_x,
        y,
        w: inner_w,
        h: card_h,
    };
    let row_x = inner_x + s(CARD_PAD) - s(4);
    let row_w = inner_w - 2 * (s(CARD_PAD) - s(4));
    let rows = (0..rows as i32)
        .map(|index| Rect {
            x: row_x,
            y: y + s(8) + index * row_h,
            w: row_w,
            h: row_h,
        })
        .collect();
    y += card_h + s(GAP);
    let message_h = s(BODY_H) * message_lines.max(1);
    let message = Rect {
        x: inner_x,
        y,
        w: inner_w,
        h: message_h,
    };
    y += message_h + s(16);
    let buttons_y = y;
    y += s(BUTTON_H) + s(20);
    let footer = Rect {
        x: inner_x,
        y,
        w: inner_w,
        h: s(CAPTION_H),
    };
    y += s(CAPTION_H) + s(OUTER) - s(4);
    MainLayout {
        client_w,
        client_h: y,
        title,
        badge_right: inner_x + inner_w - help_room(dpi),
        badge_y,
        subtitle,
        progress_label,
        progress_bar,
        card,
        rows,
        message,
        buttons_y,
        footer,
    }
}

/// Button width for a measured caption: horizontal padding on both sides, at least 88 px.
pub fn button_width(dpi: u32, caption_px: i32) -> i32 {
    (caption_px.max(0) + 2 * scale(dpi, grid::BUTTON_PAD_X)).max(scale(dpi, 88))
}

/// Places a left-aligned group and a right-aligned group of buttons on one line.
/// Returns None when they would overlap or leave the given width.
pub fn place_buttons(
    dpi: u32,
    left: &[i32],
    right: &[i32],
    x: i32,
    width: i32,
    y: i32,
) -> Option<(Vec<Rect>, Vec<Rect>)> {
    let gap = scale(dpi, grid::BUTTON_GAP);
    let h = scale(dpi, grid::BUTTON_H);
    let mut cursor = x;
    let lefts: Vec<_> = left
        .iter()
        .map(|w| {
            let rect = Rect {
                x: cursor,
                y,
                w: *w,
                h,
            };
            cursor += w + gap;
            rect
        })
        .collect();
    let left_end = lefts.last().map_or(x, Rect::right);
    let mut cursor = x + width;
    let mut rights: Vec<_> = right
        .iter()
        .rev()
        .map(|w| {
            cursor -= w;
            let rect = Rect {
                x: cursor,
                y,
                w: *w,
                h,
            };
            cursor -= gap;
            rect
        })
        .collect();
    rights.reverse();
    let right_start = rights.first().map_or(x + width, |r| r.x);
    let separated = lefts.is_empty() || rights.is_empty() || left_end + gap <= right_start;
    (separated && right_start >= x && left_end <= x + width).then_some((lefts, rights))
}

// ---- the help pane -----------------------------------------------------------------------

/// The help pane's width, and the "?" button's side, at 96 dpi.
pub const HELP_PANE_W: i32 = 360;
pub const HELP_BUTTON: i32 = 28;

/// The room a title row leaves at its right for the "?" button.
pub fn help_room(dpi: u32) -> i32 {
    scale(dpi, HELP_BUTTON + grid::GAP)
}

/// The page's width and the pane's rectangle in a client area `client_w` by `client_h`: the
/// pane takes the right side while it is open, and the page the rest.
pub fn help_split(client_w: i32, client_h: i32, open: bool, dpi: u32) -> (i32, Option<Rect>) {
    let pane_w = scale(dpi, HELP_PANE_W).min(client_w / 2);
    if !open {
        return (client_w, None);
    }
    let page_w = client_w - pane_w;
    (
        page_w,
        Some(Rect {
            x: page_w,
            y: 0,
            w: pane_w,
            h: client_h,
        }),
    )
}

/// The "?" button at the right of the title row of a page `page_w` wide.
pub fn help_button(page_w: i32, dpi: u32) -> Rect {
    let side = scale(dpi, HELP_BUTTON);
    Rect {
        x: page_w - scale(dpi, grid::OUTER) - side,
        y: scale(dpi, 16) + (scale(dpi, grid::TITLE_H) - side) / 2,
        w: side,
        h: side,
    }
}

/// The window's left edge and outer width once the pane opens: it grows by the pane so the
/// page keeps its width, moving left where the screen's right edge is in the way, and only
/// where the screen is too narrow does the page narrow instead. Returns the growth too.
pub fn help_opened(left: i32, width: i32, pane_w: i32, work: (i32, i32)) -> (i32, i32, i32) {
    let (work_left, work_right) = work;
    let wanted = (width + pane_w).min(work_right - work_left).max(width);
    let left = left.min(work_right - wanted).max(work_left);
    (left, wanted, wanted - width)
}

// ---- the condition strip ---------------------------------------------------------------

/// The strip's height and the muted line under it, at 96 dpi.
pub const STRIP_H: i32 = 108;
pub const STRIP_CELLS: usize = 6;

/// The strip's six cells across `w`: equal widths, the last taking the odd pixels. Nothing
/// in them depends on what they show, so a value that changes never moves a cell.
pub fn strip_cells(x: i32, y: i32, w: i32, dpi: u32) -> [Rect; STRIP_CELLS] {
    let h = scale(dpi, STRIP_H);
    let each = w / STRIP_CELLS as i32;
    std::array::from_fn(|i| {
        let i = i as i32;
        let cell_x = x + i * each;
        let cell_w = if i == STRIP_CELLS as i32 - 1 {
            x + w - cell_x
        } else {
            each
        };
        Rect {
            x: cell_x,
            y,
            w: cell_w,
            h,
        }
    })
}

/// The parts of one cell: label, value, change, note and trend line, top to bottom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellParts {
    pub label: Rect,
    pub value: Rect,
    pub change: Rect,
    pub note: Rect,
    pub trend: Rect,
}

pub fn cell_parts(cell: Rect, dpi: u32) -> CellParts {
    let s = |v| scale(dpi, v);
    let (x, w) = (cell.x + s(12), (cell.w - s(24)).max(0));
    let row = |top: i32, h: i32| Rect {
        x,
        y: cell.y + s(top),
        w,
        h: s(h),
    };
    CellParts {
        label: row(8, 16),
        value: row(25, 26),
        change: row(52, 15),
        note: row(67, 15),
        trend: row(85, 16),
    }
}

/// A settings table of `rows` rows across `w`: each row a label and a value, twice; a label
/// column takes a fifth of the width. Fixed, so a value's caption never moves another.
pub fn table_rows(x: i32, y: i32, w: i32, dpi: u32, rows: usize) -> Vec<[Rect; 4]> {
    let h = scale(dpi, grid::ROW_H);
    let label = w / 5;
    let value = w / 2 - label;
    (0..rows as i32)
        .map(|row| {
            let top = y + row * h;
            let at = |x, w| Rect { x, y: top, w, h };
            [
                at(x, label),
                at(x + label, value),
                at(x + w / 2, label),
                at(x + w / 2 + label, w - w / 2 - label),
            ]
        })
        .collect()
}

/// The saved report as two lines that always fit the message area: the file name whole,
/// then its folder, shortened in the middle when it is longer than `width_chars`.
pub fn saved_lines(path: &str, width_chars: usize) -> String {
    let Some(split) = path.rfind(['\\', '/']) else {
        return path.to_string();
    };
    let (folder, name) = (&path[..split], &path[split + 1..]);
    format!(
        "{name}\nin {}",
        shorten_middle(folder, width_chars.saturating_sub(3))
    )
}

fn shorten_middle(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(1);
    let head = keep / 3;
    let tail = keep - head;
    chars[..head]
        .iter()
        .chain(std::iter::once(&'\u{2026}'))
        .chain(&chars[chars.len() - tail..])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DPIS: [u32; 4] = [96, 120, 144, 192];

    #[test]
    fn scaling_rounds_and_never_shrinks_below_96_dpi() {
        assert_eq!(scale(96, 24), 24);
        assert_eq!(scale(144, 24), 36);
        assert_eq!(scale(120, 5), 6);
        assert_eq!(scale(72, 24), 24);
    }

    #[test]
    fn main_layout_stacks_without_overlap_inside_the_client_area_at_every_dpi() {
        for dpi in DPIS {
            let layout = main_layout(dpi, 11, 2);
            let blocks = [
                layout.title,
                layout.subtitle,
                layout.progress_label,
                layout.progress_bar,
                layout.card,
                layout.message,
                layout.footer,
            ];
            for pair in blocks.windows(2) {
                assert!(pair[0].bottom() <= pair[1].y, "{dpi}: {pair:?}");
            }
            assert!(layout.message.bottom() <= layout.buttons_y);
            assert!(layout.buttons_y + scale(dpi, grid::BUTTON_H) <= layout.footer.y);
            assert!(layout.footer.bottom() <= layout.client_h);
            for block in blocks {
                assert!(
                    block.x >= 0 && block.right() <= layout.client_w,
                    "{dpi}: {block:?}"
                );
            }
            for row in &layout.rows {
                assert!(row.x > layout.card.x && row.right() < layout.card.right());
                assert!(row.y >= layout.card.y && row.bottom() <= layout.card.bottom());
            }
            assert_eq!(layout.rows.len(), 11);
        }
    }

    #[test]
    fn layout_grows_in_proportion_to_dpi() {
        let small = main_layout(96, 11, 2);
        let large = main_layout(192, 11, 2);
        assert_eq!(large.client_w, 2 * small.client_w);
        assert!((large.client_h - 2 * small.client_h).abs() <= 8);
    }

    #[test]
    fn the_widest_button_line_fits_at_every_dpi() {
        // Widest caption set (Open report, Show in folder | View hardware, Close) in
        // Segoe UI 14 px at 96 DPI, scaled per DPI.
        for dpi in DPIS {
            let caption = |px| button_width(dpi, scale(dpi, px));
            let layout = main_layout(dpi, 11, 2);
            let placed = place_buttons(
                dpi,
                &[caption(78), caption(92)],
                &[caption(96), caption(36)],
                layout.title.x,
                layout.client_w - 2 * layout.title.x,
                layout.buttons_y,
            );
            assert!(placed.is_some(), "buttons overlap at {dpi} DPI");
        }
    }

    #[test]
    fn overlapping_button_groups_are_reported() {
        assert!(place_buttons(96, &[200, 200], &[200], 0, 500, 0).is_none());
        let (left, right) = place_buttons(96, &[100], &[100], 0, 500, 0).unwrap();
        assert_eq!(left[0].x, 0);
        assert_eq!(right[0].right(), 500);
    }

    #[test]
    fn measured_caption_grows_button_without_truncation() {
        assert_eq!(button_width(96, 110), 142);
        assert_eq!(button_width(96, 20), 88);
        assert_eq!(button_width(144, 165), 213);
    }

    #[test]
    fn a_deep_report_path_keeps_the_file_name_in_two_lines() {
        let path = "C:\\Users\\Example\\AppData\\Local\\Temp\\toolbox\\fe4af0ee3f0f3609\\7f24d59b-23b4-41b2-a004-b203a3ad8550\\workspace\\qa-reports\\Café-Report-20261103-1.pdf";
        let message = saved_lines(path, 60);
        let lines: Vec<&str> = message.lines().collect();
        assert_eq!(lines.len(), 2, "{message}");
        assert_eq!(lines[0], "Café-Report-20261103-1.pdf");
        assert!(lines[1].starts_with("in C:\\Users"), "{message}");
        assert!(lines[1].ends_with("qa-reports"), "{message}");
        assert!(lines[1].chars().count() <= 60, "{message}");
    }

    /// The guard: opening the help pane grows the window by the pane, so the page keeps its
    /// width, its strip cells and its button row; closing it gives the same back. Only on a
    /// screen too narrow does the page narrow, and its buttons still fit their row.
    #[test]
    fn the_help_pane_leaves_the_page_where_it_was() {
        for dpi in DPIS {
            let (client_w, client_h) = (scale(dpi, 780), scale(dpi, 680));
            let (page_w, pane) = help_split(client_w, client_h, false, dpi);
            assert_eq!((page_w, pane), (client_w, None));
            let pane_w = scale(dpi, HELP_PANE_W);
            let (left, outer, grown) = help_opened(100, client_w + 16, pane_w, (0, 8000));
            assert_eq!((left, grown), (100, pane_w));
            let (open_w, pane) = help_split(client_w + grown, client_h, true, dpi);
            assert_eq!(open_w, page_w, "{dpi}");
            assert_eq!(outer, client_w + 16 + pane_w);
            let pane = pane.unwrap();
            assert_eq!((pane.x, pane.right()), (page_w, client_w + grown));
            assert_eq!(
                strip_cells(24, 80, open_w - 48, dpi),
                strip_cells(24, 80, page_w - 48, dpi)
            );
            assert_eq!(help_button(open_w, dpi), help_button(page_w, dpi));
            let row = |w: i32| {
                place_buttons(
                    dpi,
                    &[button_width(dpi, scale(dpi, 40)); 3],
                    &[button_width(dpi, scale(dpi, 36))],
                    scale(dpi, grid::OUTER),
                    w - 2 * scale(dpi, grid::OUTER),
                    client_h - scale(dpi, grid::OUTER + grid::BUTTON_H),
                )
            };
            assert_eq!(row(open_w), row(page_w));
            // Against the screen's right edge the window moves left instead.
            let (left, _, grown) = help_opened(1000, client_w, pane_w, (0, 1000 + client_w));
            assert_eq!((left, grown), (1000 - pane_w, pane_w));
            // A screen too narrow for both: the page narrows, the buttons keep their row.
            let (_, outer, grown) = help_opened(0, client_w, pane_w, (0, client_w + 40));
            assert_eq!((outer, grown), (client_w + 40, 40));
            let (narrow_w, _) = help_split(outer, client_h, true, dpi);
            assert!(narrow_w < page_w);
            let placed = row(narrow_w).expect("the buttons fit the narrowed page");
            assert!(placed.0.iter().all(|b| b.y == placed.1[0].y));
        }
    }

    /// The guard: the status window's "?" sits right of its badge, and opening the pane,
    /// which grows the client width by the pane's, leaves the controls where they were.
    #[test]
    fn the_status_window_keeps_its_place_when_the_help_pane_opens() {
        for dpi in DPIS {
            let layout = main_layout(dpi, 11, 2);
            let pane_w = scale(dpi, HELP_PANE_W);
            let (page_w, pane) = help_split(layout.client_w + pane_w, layout.client_h, true, dpi);
            assert_eq!(page_w, layout.client_w, "{dpi}");
            assert_eq!(pane.unwrap().x, layout.client_w);
            assert_eq!(main_layout(dpi, 11, 2), layout);
            let button = help_button(page_w, dpi);
            let badge_widest = scale(dpi, 160);
            assert!(layout.badge_right <= button.x, "{dpi}");
            assert!(
                layout.badge_right - badge_widest >= layout.title.right(),
                "{dpi}"
            );
            let middle = button.y + button.h / 2;
            assert!(
                layout.title.y <= middle && middle <= layout.title.bottom(),
                "{dpi}"
            );
            assert!(button.right() <= layout.client_w);
        }
    }

    #[test]
    fn the_strip_cells_tile_their_width_and_their_parts_stay_inside() {
        for dpi in DPIS {
            for w in [scale(dpi, 520), scale(dpi, 732), scale(dpi, 1400) + 5] {
                let cells = strip_cells(10, 20, w, dpi);
                assert_eq!(cells[0].x, 10);
                assert_eq!(cells[STRIP_CELLS - 1].right(), 10 + w);
                for pair in cells.windows(2) {
                    assert_eq!(pair[0].right(), pair[1].x);
                    assert!((pair[0].w - pair[1].w).abs() <= STRIP_CELLS as i32);
                }
                for cell in cells {
                    let p = cell_parts(cell, dpi);
                    let parts = [p.label, p.value, p.change, p.note, p.trend];
                    for pair in parts.windows(2) {
                        assert!(pair[0].bottom() <= pair[1].y, "{dpi} {pair:?}");
                    }
                    for part in parts {
                        assert!(part.x >= cell.x && part.right() <= cell.right());
                        assert!(part.y >= cell.y && part.bottom() <= cell.bottom());
                    }
                }
            }
        }
    }

    #[test]
    fn the_settings_table_keeps_its_columns() {
        let rows = table_rows(24, 100, 700, 96, 4);
        assert_eq!(rows.len(), 4);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row[0].x, 24);
            assert_eq!(row[3].right(), 724);
            assert_eq!(row[0].y, 100 + 32 * i as i32);
            for pair in row.windows(2) {
                assert_eq!(pair[0].right(), pair[1].x);
            }
            assert_eq!(row[1].x, rows[0][1].x);
            assert_eq!(row[2].x, rows[0][2].x);
        }
    }

    #[test]
    fn a_short_report_path_is_shown_whole() {
        let message = saved_lines("C:\\Users\\Ana\\Documents\\Report.pdf", 60);
        assert_eq!(message, "Report.pdf\nin C:\\Users\\Ana\\Documents");
    }
}
