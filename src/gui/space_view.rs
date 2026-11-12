//! The drive space window: which folders and files take the most room on the Windows drive,
//! and a cleanup of week-old temporary files and the Recycle Bin.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Instant, SystemTime};

use diagnostics::tools::cleanup::{self, Removed, TempPlan};
use diagnostics::tools::space::{disk_space, format_size, windows_dir};
use diagnostics::tools::space_map::{self, File, Line, Map, Progress};
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyWindow, PostMessageW, WM_COMMAND};

use crate::dialog::{Dialog, Item, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const UP: usize = 10;
const FOLDERS: usize = 11;
const FILES: usize = 12;
const EXPLORER: usize = 13;
const CLEAN: usize = 14;
const RESCAN: usize = 15;
const CLOSE: usize = 16;
const LIST: usize = 20;
/// Posted by the tick when the cleanup plan is ready, so the confirmation can be asked.
const CONFIRM: usize = 30;
const DO_CLEAN: usize = 31;
const ITEM_H: i32 = 44;
const LARGEST_FILES: usize = 200;

/// Groups digits in threes: 182331 reads 182,331.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn usage_text(drive: char, free: u64, total: u64) -> String {
    format!(
        "{drive}: drive  ·  {} used of {}  ·  {} free",
        format_size(total.saturating_sub(free)),
        format_size(total),
        format_size(free)
    )
}

pub fn scanning_text(folders: u64, bytes: u64, seconds: u64) -> String {
    format!(
        "Measuring: {} folders, {} so far ({seconds} s)",
        count(folders),
        format_size(bytes)
    )
}

pub fn scanned_text(map: &Map) -> String {
    let folders = count(map.folders.len() as u64);
    let seconds = map.elapsed.as_secs();
    let mut text = if map.cancelled {
        format!("Stopped after {folders} folders; sizes are a minimum.")
    } else {
        format!("Measured {folders} folders in {seconds} s.")
    };
    if map.unreadable > 0 {
        text.push_str(&format!(
            " {} need administrator rights and are not counted.",
            count(map.unreadable)
        ));
    }
    text
}

fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{} {many}", count(n))
    }
}

/// What the cleanup found, before anything is removed.
pub struct Offer {
    pub temp: TempPlan,
    pub bin: Result<(u64, u64), String>,
}

/// The confirmation for an offer, or None when there is nothing to remove.
pub fn offer_dialog(offer: &Offer) -> Option<Dialog> {
    let bin = offer.bin.as_ref().ok().copied().unwrap_or((0, 0));
    if offer.temp.files.is_empty() && bin.1 == 0 {
        return None;
    }
    let mut sections = Vec::new();
    if !offer.temp.files.is_empty() {
        sections.push(Section {
            heading: Some("Temporary files".into()),
            items: vec![
                Item::Pair(
                    "Files".into(),
                    format!(
                        "{}, unchanged for 7 days or more",
                        count(offer.temp.files.len() as u64)
                    ),
                ),
                Item::Pair("Size".into(), format_size(offer.temp.bytes)),
                Item::Pair(
                    "From".into(),
                    offer
                        .temp
                        .roots
                        .iter()
                        .map(|r| r.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        });
    }
    if bin.1 > 0 {
        sections.push(Section {
            heading: Some("Recycle Bin".into()),
            items: vec![
                Item::Pair("Items".into(), count(bin.1)),
                Item::Pair("Size".into(), format_size(bin.0)),
            ],
        });
    }
    sections.push(Section {
        heading: None,
        items: vec![Item::Para(
            "Files a program has open, read-only files and anything changed in the past week are left alone."
                .into(),
        )],
    });
    let total = offer.temp.bytes + bin.0;
    Some(Dialog {
        window_title: "Clean up".into(),
        heading: format!("Free about {}?", format_size(total)),
        intro: "These are removed for good and cannot be brought back.".into(),
        sections,
        accept: "Clean up".into(),
        decline: Some("Cancel".into()),
        copy: None,
    })
}

/// What was removed, once the cleanup ran.
pub struct Outcome {
    pub removed: Removed,
    /// The bin's contents before it was emptied, or why it could not be.
    pub bin: Option<Result<(u64, u64), String>>,
}

pub fn outcome_text(outcome: &Outcome) -> String {
    let mut parts = Vec::new();
    let r = &outcome.removed;
    if r.files > 0 {
        parts.push(format!(
            "Removed {} of temporary files ({}).",
            format_size(r.bytes),
            plural(r.files, "file", "files")
        ));
    }
    match &outcome.bin {
        Some(Ok((bytes, items))) if *items > 0 => parts.push(format!(
            "Emptied the Recycle Bin ({}, {}).",
            format_size(*bytes),
            plural(*items, "item", "items")
        )),
        Some(Err(why)) => parts.push(format!("The Recycle Bin was not emptied: {why}.")),
        _ => {}
    }
    let left = r.failed + r.changed;
    if left > 0 {
        parts.push(format!(
            "{} in use or changed meanwhile {} left.",
            plural(left, "file", "files"),
            if left == 1 { "was" } else { "were" }
        ));
    }
    if parts.is_empty() {
        "Nothing was removed.".into()
    } else {
        parts.join(" ")
    }
}

enum Scan {
    Running {
        cancel: Arc<AtomicBool>,
        progress: Arc<Progress>,
        result: mpsc::Receiver<Map>,
        started: Instant,
    },
    Done,
}

enum Clean {
    Idle,
    Planning(mpsc::Receiver<Offer>),
    Offered(Offer),
    Removing(mpsc::Receiver<Outcome>),
}

enum Row {
    Line(Line),
    File {
        folder: usize,
        file: File,
    },
    /// Files in the folder too small to be kept by name.
    Rest {
        items: u64,
        bytes: u64,
    },
}

struct Controls {
    title: HWND,
    usage_text: HWND,
    usage: HWND,
    status: HWND,
    scan_bar: HWND,
    up: HWND,
    path: HWND,
    folders: HWND,
    files: HWND,
    list: HWND,
    explorer: HWND,
    clean: HWND,
    rescan: HWND,
    close: HWND,
}

pub struct SpaceView {
    drive: char,
    disk: Option<(u64, u64)>,
    controls: Option<Controls>,
    scan: Scan,
    map: Option<Map>,
    at: usize,
    showing_files: bool,
    rows: Vec<Row>,
    notice: Option<String>,
    clean: Clean,
}

impl Drop for SpaceView {
    fn drop(&mut self) {
        if let Scan::Running { cancel, .. } = &self.scan {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

impl SpaceView {
    pub fn new() -> Self {
        let drive = windows_dir()
            .and_then(|p| p.to_string_lossy().chars().next())
            .filter(char::is_ascii_alphabetic)
            .unwrap_or('C')
            .to_ascii_uppercase();
        let mut view = Self::idle(drive, disk_space(drive).ok());
        view.start_scan();
        view
    }

    fn idle(drive: char, disk: Option<(u64, u64)>) -> Self {
        Self {
            drive,
            disk,
            controls: None,
            scan: Scan::Done,
            map: None,
            at: 0,
            showing_files: false,
            rows: Vec::new(),
            notice: None,
            clean: Clean::Idle,
        }
    }

    /// The window for `drive` with `disk` (free, total) whose measuring gives `map` at its
    /// first tick, reading nothing itself: for the screenshot mode.
    #[cfg(debug_assertions)]
    pub fn measured(drive: char, disk: (u64, u64), map: Map) -> Self {
        let mut view = Self::idle(drive, Some(disk));
        let (sender, result) = mpsc::channel();
        let _ = sender.send(map);
        view.scan = Scan::Running {
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Progress::default()),
            result,
            started: Instant::now(),
        };
        view
    }

    fn root(&self) -> PathBuf {
        PathBuf::from(format!("{}:\\", self.drive))
    }

    fn start_scan(&mut self) {
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let (sender, result) = mpsc::channel();
        let root = self.root();
        let (c, p) = (cancel.clone(), progress.clone());
        thread::spawn(move || {
            let map = space_map::scan(&root, space_map::THREADS, &c, &p);
            let _ = sender.send(map);
        });
        self.scan = Scan::Running {
            cancel,
            progress,
            result,
            started: Instant::now(),
        };
    }

    fn row_text(&self, row: &Row) -> String {
        let total = self.map.as_ref().map_or(0, |m| m.folders[self.at].total);
        match row {
            Row::Line(line) => format!(
                "{}, {}, {}{}",
                line.name,
                if line.folder.is_some() {
                    "folder"
                } else {
                    "file"
                },
                format_size(line.bytes),
                percent(line.bytes, total).map_or(String::new(), |p| format!(", {p} percent")),
            ),
            Row::File { folder, file } => format!(
                "{}, in {}, {}",
                file.name,
                self.map
                    .as_ref()
                    .map_or(PathBuf::new(), |m| m.path(*folder))
                    .display(),
                format_size(file.bytes)
            ),
            Row::Rest { items, bytes } => format!(
                "{} more, {} together",
                plural(*items, "small item", "small items"),
                format_size(*bytes)
            ),
        }
    }

    fn refresh_list(&mut self, keep: bool) {
        self.rows.clear();
        if let Some(map) = &self.map {
            if self.showing_files {
                self.rows = map
                    .largest_files(LARGEST_FILES)
                    .into_iter()
                    .map(|(folder, file)| Row::File { folder, file })
                    .collect();
            } else {
                let view = map.view(self.at, usize::MAX);
                self.rows = view.lines.into_iter().map(Row::Line).collect();
                if view.rest_items > 0 {
                    self.rows.push(Row::Rest {
                        items: view.rest_items,
                        bytes: view.rest_bytes,
                    });
                }
            }
        }
        let texts: Vec<String> = self.rows.iter().map(|r| self.row_text(r)).collect();
        if let Some(c) = &self.controls {
            toolwin::set_items(c.list, &texts, keep);
        }
        self.render();
    }

    fn render(&self) {
        let Some(c) = &self.controls else {
            return;
        };
        match self.disk {
            Some((free, total)) => {
                ui::set_text(c.usage_text, &usage_text(self.drive, free, total));
                let used = total.saturating_sub(free);
                ui::set_value(c.usage, (used.saturating_mul(1000) / total.max(1)) as u32);
            }
            None => ui::set_text(c.usage_text, &format!("{}: drive", self.drive)),
        }
        let scanning = matches!(self.scan, Scan::Running { .. });
        let status = if let Some(notice) = &self.notice {
            notice.clone()
        } else if let Scan::Running {
            progress, started, ..
        } = &self.scan
        {
            scanning_text(
                progress.folders.load(Ordering::Relaxed),
                progress.bytes.load(Ordering::Relaxed),
                started.elapsed().as_secs(),
            )
        } else if let Some(map) = &self.map {
            scanned_text(map)
        } else {
            String::new()
        };
        ui::set_text(c.status, &status);
        if let Scan::Running { progress, .. } = &self.scan {
            let used = self
                .disk
                .map_or(1, |(free, total)| total.saturating_sub(free).max(1));
            let counted = progress.bytes.load(Ordering::Relaxed);
            ui::set_value(
                c.scan_bar,
                (counted.saturating_mul(1000) / used).min(990) as u32,
            );
        }
        ui::show(c.scan_bar, scanning);
        let path = match &self.map {
            Some(_) if self.showing_files => "The largest files on the drive".to_string(),
            Some(map) => map.path(self.at).display().to_string(),
            None => self.root().display().to_string(),
        };
        ui::set_text(c.path, &path);
        ui::enable(
            c.up,
            self.map.is_some() && !self.showing_files && self.at != 0,
        );
        ui::set_kind(
            c.folders,
            if self.showing_files {
                Kind::Ghost
            } else {
                Kind::Secondary
            },
        );
        ui::set_kind(
            c.files,
            if self.showing_files {
                Kind::Secondary
            } else {
                Kind::Ghost
            },
        );
        ui::enable(c.folders, self.map.is_some());
        ui::enable(c.files, self.map.is_some());
        ui::enable(c.explorer, self.map.is_some() && !self.showing_files);
        let busy = !matches!(self.clean, Clean::Idle);
        ui::enable(c.clean, !busy);
        ui::set_text(
            c.clean,
            match self.clean {
                Clean::Planning(_) => "Looking…",
                Clean::Removing(_) => "Cleaning…",
                _ => "Clean up…",
            },
        );
        ui::enable(c.rescan, !scanning && !busy);
    }

    fn activate(&mut self, hwnd: HWND, index: usize) {
        let Some(map) = &self.map else {
            return;
        };
        match self.rows.get(index) {
            Some(Row::Line(Line {
                folder: Some(folder),
                ..
            })) => {
                self.at = *folder;
                self.notice = None;
                self.refresh_list(false);
            }
            Some(Row::Line(Line {
                name, folder: None, ..
            })) => {
                let path = map.path(self.at).join(name);
                self.notice = (!toolwin::reveal(hwnd, &path))
                    .then(|| format!("Windows could not show {}.", path.display()));
                self.render();
            }
            Some(Row::File { folder, file }) => {
                let path = map.path(*folder).join(&file.name);
                self.notice = (!toolwin::reveal(hwnd, &path))
                    .then(|| format!("Windows could not show {}.", path.display()));
                self.render();
            }
            _ => {}
        }
    }

    fn up(&mut self) {
        if let Some(map) = &self.map {
            let child = self.at;
            self.at = map.folders[self.at].parent;
            self.refresh_list(false);
            // Keep the folder just left selected, so the way back is visible.
            let position = self
                .rows
                .iter()
                .position(|r| matches!(r, Row::Line(Line { folder: Some(f), .. }) if *f == child));
            if let Some(c) = &self.controls {
                toolwin::select(c.list, position);
            }
        }
    }

    fn start_plan(&mut self) {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let temp = cleanup::plan_temp(&cleanup::temp_roots(), SystemTime::now());
            let bin = cleanup::recycle_bin();
            let _ = sender.send(Offer { temp, bin });
        });
        self.notice = Some("Looking for temporary files and the Recycle Bin's size…".into());
        self.clean = Clean::Planning(receiver);
    }

    fn start_removal(&mut self) {
        let Clean::Offered(offer) = std::mem::replace(&mut self.clean, Clean::Idle) else {
            return;
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let removed = cleanup::remove_temp(&offer.temp, SystemTime::now());
            let bin = match offer.bin {
                Ok((bytes, items)) if items > 0 => {
                    Some(cleanup::empty_recycle_bin().map(|()| (bytes, items)))
                }
                _ => None,
            };
            let _ = sender.send(Outcome { removed, bin });
        });
        self.notice = Some("Cleaning up…".into());
        self.clean = Clean::Removing(receiver);
    }
}

fn percent(part: u64, whole: u64) -> Option<u64> {
    (whole > 0).then(|| (part.saturating_mul(100) + whole / 2) / whole)
}

impl Page for SpaceView {
    fn title(&self) -> String {
        "Drive space".into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((640, 640), (480, 420))
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::DRIVE_SPACE)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let controls = Controls {
            title: text(Kind::Title, "Windows drive space"),
            usage_text: text(Kind::Muted, ""),
            usage: text(Kind::Progress, ""),
            status: text(Kind::Caption, ""),
            scan_bar: text(Kind::Progress, ""),
            up: ui::button(hwnd, UP, Kind::Secondary, "Up"),
            path: text(Kind::Heading, ""),
            folders: ui::button(hwnd, FOLDERS, Kind::Secondary, "Folders"),
            files: ui::button(hwnd, FILES, Kind::Ghost, "Largest files"),
            list: toolwin::list(hwnd, LIST, ITEM_H),
            explorer: ui::button(hwnd, EXPLORER, Kind::Secondary, "Open in Explorer"),
            clean: ui::button(hwnd, CLEAN, Kind::Primary, "Clean up…"),
            rescan: ui::button(hwnd, RESCAN, Kind::Secondary, "Measure again"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        ui::set_font(controls.list, ui::fonts(ui::dpi_of(hwnd)).body);
        self.controls = Some(controls);
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_font(c.list, ui::fonts(dpi).body);
        let s = |v: i32| scale(dpi, v);
        let m = s(grid::OUTER);
        let inner = w - 2 * m;
        let mut y = s(16);
        ui::place(
            c.title,
            Rect {
                x: m,
                y,
                w: inner,
                h: s(grid::TITLE_H),
            },
        );
        y += s(grid::TITLE_H) + s(6);
        ui::place(
            c.usage_text,
            Rect {
                x: m,
                y,
                w: inner,
                h: s(grid::BODY_H),
            },
        );
        y += s(grid::BODY_H) + s(6);
        ui::place(
            c.usage,
            Rect {
                x: m,
                y,
                w: inner,
                h: s(grid::PROGRESS_H + 2),
            },
        );
        y += s(grid::PROGRESS_H + 2) + s(10);
        ui::place(
            c.status,
            Rect {
                x: m,
                y,
                w: inner,
                h: s(grid::CAPTION_H + 2),
            },
        );
        y += s(grid::CAPTION_H + 2) + s(4);
        ui::place(
            c.scan_bar,
            Rect {
                x: m,
                y,
                w: inner,
                h: s(4),
            },
        );
        y += s(4) + s(12);
        let bh = s(grid::BUTTON_H);
        let gap = s(grid::BUTTON_GAP);
        let up_w = ui::button_width(c.up, "Up");
        let files_w = ui::button_width(c.files, "Largest files");
        let folders_w = ui::button_width(c.folders, "Folders");
        ui::place(
            c.up,
            Rect {
                x: m,
                y,
                w: up_w,
                h: bh,
            },
        );
        let right = m + inner;
        ui::place(
            c.files,
            Rect {
                x: right - files_w,
                y,
                w: files_w,
                h: bh,
            },
        );
        ui::place(
            c.folders,
            Rect {
                x: right - files_w - gap - folders_w,
                y,
                w: folders_w,
                h: bh,
            },
        );
        let path_x = m + up_w + s(12);
        let path_w = (right - files_w - gap - folders_w - s(12) - path_x).max(s(40));
        ui::place(
            c.path,
            Rect {
                x: path_x,
                y,
                w: path_w,
                h: bh,
            },
        );
        y += bh + s(12);
        let bottom_y = h - m - bh;
        let pad = s(8);
        let card = Rect {
            x: m,
            y,
            w: inner,
            h: (bottom_y - s(16) - y).max(s(80)),
        };
        ui::place(
            c.list,
            Rect {
                x: card.x + pad,
                y: card.y + pad,
                w: card.w - 2 * pad,
                h: card.h - 2 * pad,
            },
        );
        ui::set_cards(hwnd, vec![card]);
        let mut x = m;
        for (hwnd, caption) in [(c.clean, "Clean up…"), (c.explorer, "Open in Explorer")] {
            let bw = ui::button_width(hwnd, caption);
            ui::place(
                hwnd,
                Rect {
                    x,
                    y: bottom_y,
                    w: bw,
                    h: bh,
                },
            );
            x += bw + gap;
        }
        let mut x = right;
        for (hwnd, caption) in [(c.close, "Close"), (c.rescan, "Measure again")] {
            let bw = ui::button_width(hwnd, caption);
            x -= bw;
            ui::place(
                hwnd,
                Rect {
                    x,
                    y: bottom_y,
                    w: bw,
                    h: bh,
                },
            );
            x -= gap;
        }
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        match id {
            LIST if code == toolwin::ACTIVATE => {
                let selected = self
                    .controls
                    .as_ref()
                    .and_then(|c| toolwin::selected(c.list));
                if let Some(index) = selected {
                    self.activate(hwnd, index);
                }
            }
            UP => self.up(),
            FOLDERS | FILES => {
                self.showing_files = id == FILES;
                self.refresh_list(false);
            }
            EXPLORER => {
                if let Some(map) = &self.map {
                    let path = map.path(self.at);
                    self.notice = (!toolwin::open_path(hwnd, &path))
                        .then(|| format!("Windows could not open {}.", path.display()));
                    self.render();
                }
            }
            CLEAN => {
                self.start_plan();
                self.render();
            }
            CONFIRM => {
                if let Clean::Offered(offer) = &self.clean {
                    match offer_dialog(offer) {
                        Some(dialog) => {
                            self.notice = None;
                            self.render();
                            return Some(Ask {
                                dialog,
                                then: DO_CLEAN,
                            });
                        }
                        None => {
                            self.clean = Clean::Idle;
                            self.notice = Some(
                                "Nothing to clean up: no temporary files a week old, and the Recycle Bin is empty."
                                    .into(),
                            );
                            self.render();
                        }
                    }
                }
            }
            // A declined confirmation leaves the offer; Cleanup starts over next time.
            DO_CLEAN => {
                self.start_removal();
                self.render();
            }
            RESCAN => {
                self.notice = None;
                self.disk = disk_space(self.drive).ok();
                self.start_scan();
                self.render();
            }
            CLOSE => unsafe {
                DestroyWindow(hwnd);
            },
            _ => {}
        }
        None
    }

    fn tick(&mut self, hwnd: HWND) {
        if let Scan::Running { result, .. } = &self.scan {
            if let Ok(map) = result.try_recv() {
                // A new measurement keeps the folder being looked at when it still exists.
                let keep = self
                    .map
                    .as_ref()
                    .map(|old| old.path(self.at))
                    .and_then(|path| (0..map.folders.len()).find(|&i| map.path(i) == path));
                self.at = keep.unwrap_or(0);
                self.map = Some(map);
                self.scan = Scan::Done;
                self.refresh_list(keep.is_some());
            }
        }
        match &self.clean {
            Clean::Planning(receiver) => {
                if let Ok(offer) = receiver.try_recv() {
                    self.clean = Clean::Offered(offer);
                    unsafe { PostMessageW(hwnd, WM_COMMAND, CONFIRM, 0) };
                }
            }
            Clean::Offered(_) => {
                // Declined: back to idle so the button works again.
                self.clean = Clean::Idle;
            }
            Clean::Removing(receiver) => {
                if let Ok(outcome) = receiver.try_recv() {
                    self.clean = Clean::Idle;
                    self.notice = Some(outcome_text(&outcome));
                    self.disk = disk_space(self.drive).ok();
                    if matches!(self.scan, Scan::Done) {
                        self.start_scan();
                    }
                }
            }
            Clean::Idle => {}
        }
        self.render();
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
        let Some(row) = self.rows.get(index) else {
            return;
        };
        let total = self.map.as_ref().map_or(0, |m| m.folders[self.at].total);
        let (name, bytes, is_folder, second, share) = match row {
            Row::Line(line) => (
                line.name.clone(),
                line.bytes,
                line.folder.is_some(),
                None,
                Some(if total > 0 {
                    line.bytes as f64 / total as f64
                } else {
                    0.0
                }),
            ),
            Row::File { folder, file } => (
                file.name.clone(),
                file.bytes,
                false,
                self.map
                    .as_ref()
                    .map(|m| m.path(*folder).display().to_string()),
                None,
            ),
            Row::Rest { items, bytes } => (
                format!("{} more", plural(*items, "small item", "small items")),
                *bytes,
                false,
                None,
                None,
            ),
        };
        let is_rest = matches!(row, Row::Rest { .. });
        let mid = (rect.top + rect.bottom) / 2;
        let icon_x = rect.left + s(10);
        if let Some(canvas) = &canvas {
            let (x, y, size) = (icon_x as f32, (mid - s(8)) as f32, s(16) as f32);
            let line = s(1).max(1) as f32 * 1.5;
            if is_folder {
                canvas.fill_round(
                    (x, y + size * 0.18, size, size * 0.72),
                    size * 0.12,
                    colors.warn,
                );
                canvas.fill_round(
                    (x, y + size * 0.05, size * 0.45, size * 0.3),
                    size * 0.1,
                    colors.warn,
                );
            } else if !is_rest {
                canvas.stroke_round(
                    (x + size * 0.15, y, size * 0.7, size),
                    size * 0.12,
                    colors.muted,
                    line,
                );
            }
        }
        let text_left = icon_x + s(26);
        let size_w = s(96);
        let chevron_w = if is_folder { s(18) } else { 0 };
        let size_right = rect.right - s(10) - chevron_w;
        let top_line = RECT {
            left: text_left,
            top: rect.top + s(4),
            right: size_right - size_w - s(8),
            bottom: mid + s(2),
        };
        let name_color = if is_rest { colors.muted } else { colors.text };
        use windows_sys::Win32::Graphics::Gdi::{
            DT_END_ELLIPSIS, DT_PATH_ELLIPSIS, DT_RIGHT, DT_SINGLELINE, DT_VCENTER,
        };
        ui::draw_text(
            dc,
            &name,
            &top_line,
            fonts.body,
            name_color,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
        let size_rect = RECT {
            left: size_right - size_w,
            right: size_right,
            ..top_line
        };
        ui::draw_text(
            dc,
            &format_size(bytes),
            &size_rect,
            fonts.body,
            colors.text,
            DT_SINGLELINE | DT_VCENTER | DT_RIGHT,
        );
        let bottom = RECT {
            left: text_left,
            top: mid + s(2),
            right: size_right,
            bottom: rect.bottom - s(4),
        };
        if let (Some(share), Some(canvas)) = (share, &canvas) {
            let bar_h = s(6) as f32;
            let width = (bottom.right - bottom.left - s(52)) as f32;
            let y = (bottom.top + (bottom.bottom - bottom.top) / 2) as f32 - bar_h / 2.0;
            canvas.fill_round(
                (bottom.left as f32, y, width, bar_h),
                bar_h / 2.0,
                colors.border,
            );
            let filled = (width * share as f32).max(if bytes > 0 { bar_h } else { 0.0 });
            if filled > 0.0 {
                canvas.fill_round(
                    (bottom.left as f32, y, filled, bar_h),
                    bar_h / 2.0,
                    colors.primary,
                );
            }
            let pct = RECT {
                left: bottom.right - s(48),
                ..bottom
            };
            let text = format!("{}%", percent(bytes, total).unwrap_or(0));
            ui::draw_text(
                dc,
                &text,
                &pct,
                fonts.caption,
                colors.muted,
                DT_SINGLELINE | DT_VCENTER | DT_RIGHT,
            );
        } else if let Some(second) = second {
            ui::draw_text(
                dc,
                &second,
                &bottom,
                fonts.caption,
                colors.muted,
                DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS,
            );
        }
        if is_folder {
            if let Some(canvas) = &canvas {
                let cx = (rect.right - s(14)) as f32;
                let cy = mid as f32;
                let r = s(4) as f32;
                canvas.polyline(
                    &[
                        (cx - r * 0.5, cy - r),
                        (cx + r * 0.5, cy),
                        (cx - r * 0.5, cy + r),
                    ],
                    colors.muted,
                    s(2) as f32,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn counts_are_grouped_in_threes() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(182_331), "182,331");
        assert_eq!(count(12_345_678), "12,345,678");
    }

    #[test]
    fn usage_reads_used_total_and_free() {
        let gib = 1u64 << 30;
        assert_eq!(
            usage_text('C', 64 * gib, 476 * gib),
            "C: drive  ·  412.0 GiB used of 476.0 GiB  ·  64.0 GiB free"
        );
    }

    #[test]
    fn a_stopped_or_partial_measurement_says_so() {
        let mut map = Map {
            folders: vec![Default::default(); 3],
            elapsed: Duration::from_secs(41),
            ..Map::default()
        };
        assert_eq!(scanned_text(&map), "Measured 3 folders in 41 s.");
        map.unreadable = 2;
        map.cancelled = true;
        assert_eq!(
            scanned_text(&map),
            "Stopped after 3 folders; sizes are a minimum. 2 need administrator rights and are not counted."
        );
    }

    fn offer(files: usize, bin: Result<(u64, u64), String>) -> Offer {
        Offer {
            temp: TempPlan {
                roots: vec![PathBuf::from(r"C:\Users\x\AppData\Local\Temp")],
                files: (0..files)
                    .map(|i| (PathBuf::from(format!("f{i}")), 1024))
                    .collect(),
                bytes: files as u64 * 1024,
                ..TempPlan::default()
            },
            bin,
        }
    }

    #[test]
    fn nothing_to_remove_asks_nothing() {
        assert!(offer_dialog(&offer(0, Ok((0, 0)))).is_none());
        assert!(offer_dialog(&offer(0, Err("no".into()))).is_none());
    }

    #[test]
    fn the_confirmation_names_both_parts_and_says_it_is_for_good() {
        let dialog = offer_dialog(&offer(3, Ok((2048, 2)))).unwrap();
        assert_eq!(dialog.heading, "Free about 5.0 KiB?");
        assert!(dialog.intro.contains("for good"));
        let headings: Vec<_> = dialog
            .sections
            .iter()
            .filter_map(|s| s.heading.clone())
            .collect();
        assert_eq!(headings, ["Temporary files", "Recycle Bin"]);
        assert_eq!(dialog.decline.as_deref(), Some("Cancel"));
        let only_bin = offer_dialog(&offer(0, Ok((2048, 2)))).unwrap();
        assert!(only_bin
            .sections
            .iter()
            .all(|s| s.heading.as_deref() != Some("Temporary files")));
    }

    #[test]
    fn the_outcome_reports_what_was_removed_and_what_was_left() {
        let outcome = Outcome {
            removed: Removed {
                files: 3,
                bytes: 3072,
                folders: 1,
                failed: 1,
                changed: 1,
            },
            bin: Some(Ok((2048, 2))),
        };
        assert_eq!(
            outcome_text(&outcome),
            "Removed 3.0 KiB of temporary files (3 files). Emptied the Recycle Bin (2.0 KiB, 2 items). 2 files in use or changed meanwhile were left."
        );
        let failed = Outcome {
            removed: Removed::default(),
            bin: Some(Err(
                "the Recycle Bin could not be emptied (0x80004005)".into()
            )),
        };
        assert!(outcome_text(&failed).starts_with("The Recycle Bin was not emptied"));
        let none = Outcome {
            removed: Removed::default(),
            bin: None,
        };
        assert_eq!(outcome_text(&none), "Nothing was removed.");
    }
}
