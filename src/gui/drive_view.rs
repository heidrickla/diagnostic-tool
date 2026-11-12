//! The drive tool, opened from the two drive rows: for each physical drive its identity, link,
//! partitions, health verdict and figures, the full health table, and a speed test and a read
//! check run from the window. Everything reads as the current user.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use diagnostics::tools::drives::details::{self, Details, Grade, Line};
use diagnostics::tools::drives::health::Disk;
use diagnostics::tools::drives::read_check::{self, Failure};
use diagnostics::tools::drives::speed::{self, Phase};
use diagnostics::tools::drives::{self};
use diagnostics::tools::space::{disk_space, format_size, windows_dir};
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    DT_END_ELLIPSIS, DT_PATH_ELLIPSIS, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::dialog::{Dialog, Item, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const TAB_DETAILS: usize = 10;
const TAB_SPEED: usize = 11;
const TAB_CHECK: usize = 12;
const ACTION: usize = 13;
const VOLUME: usize = 14;
const SIZE: usize = 15;
const REREAD: usize = 16;
const CLOSE: usize = 17;
/// Opens the elevated recovery window for the shown disk.
const RECOVERY: usize = 18;
const DISKS: usize = 20;
const DETAILS: usize = 21;
const RESULTS: usize = 22;
/// Accepting the speed test's confirmation.
const DO_SPEED: usize = 30;
/// LBN_SELCHANGE: the picker's selection moved with the keyboard.
const SELCHANGE: u16 = 1;
const TILES: usize = 10;
const SIZES: [u64; 3] = [256 << 20, 1 << 30, 4 << 30];

pub fn available() -> bool {
    true
}

pub fn open(owner: HWND, _check: &str) {
    toolwin::open(owner, "drive", || Box::new(DriveView::new()));
}

fn tone(grade: Grade) -> Tone {
    match grade {
        Grade::Good => Tone::Ok,
        Grade::Flagged => Tone::Warn,
        Grade::Serious => Tone::Serious,
        Grade::Unknown => Tone::Unavailable,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Details,
    Speed,
    Check,
}

struct Loaded {
    disks: Vec<(Disk, Details)>,
    elevated: Option<bool>,
    cut_short: bool,
}

enum Load {
    Reading(mpsc::Receiver<Loaded>),
    Ready(Loaded),
}

enum Test {
    Idle,
    Speed {
        volume: char,
        cancel: Arc<AtomicBool>,
        progress: Arc<speed::Progress>,
        result: mpsc::Receiver<Result<speed::Report, String>>,
    },
    Check {
        volume: char,
        used: u64,
        cancel: Arc<AtomicBool>,
        progress: Arc<read_check::Progress>,
        result: mpsc::Receiver<read_check::Report>,
    },
}

/// A row of the results list on the speed tab.
#[derive(Clone, Copy, PartialEq)]
enum SpeedRow {
    Phase(Phase),
    Verify,
}

struct Controls {
    disks: HWND,
    title: HWND,
    subtitle: HWND,
    badge: HWND,
    verdict: HWND,
    tiles: Vec<HWND>,
    tab_details: HWND,
    tab_speed: HWND,
    tab_check: HWND,
    volume: HWND,
    size: HWND,
    status: HWND,
    bar: HWND,
    details: HWND,
    results: HWND,
    action: HWND,
    reread: HWND,
    recovery: HWND,
    close: HWND,
}

pub struct DriveView {
    controls: Option<Controls>,
    load: Load,
    started: Instant,
    current: usize,
    tab: Tab,
    lines: Vec<Line>,
    volume: Option<char>,
    size: u64,
    test: Test,
    speed: Option<(char, Result<speed::Report, String>)>,
    check: Option<(char, read_check::Report)>,
    notice: Option<String>,
    /// The last client size and DPI, to lay out again when the content changes.
    area: (i32, i32, u32),
    /// What the results list holds, so it is only refilled when that changes.
    shown: Vec<String>,
}

impl Drop for DriveView {
    fn drop(&mut self) {
        // The test threads see the flag, stop, and delete their test file.
        match &self.test {
            Test::Speed { cancel, .. } | Test::Check { cancel, .. } => {
                cancel.store(true, Ordering::Relaxed)
            }
            Test::Idle => {}
        }
    }
}

fn read_drives() -> mpsc::Receiver<Loaded> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let gathered = drives::gather(Instant::now() + Duration::from_secs(20));
        let disks = gathered
            .disks
            .into_iter()
            .map(|disk| {
                let bus = disk.identity.as_ref().ok().map(|i| i.bus);
                let found = drives::details(disk.number, bus);
                (disk, found)
            })
            .collect();
        let _ = sender.send(Loaded {
            disks,
            elevated: gathered.elevated,
            cut_short: gathered.cut_short,
        });
    });
    receiver
}

fn system_letter() -> Option<char> {
    windows_dir()
        .and_then(|p| p.to_string_lossy().chars().next())
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
}

fn size_caption(size: u64) -> String {
    format!("Test size {}", format_size(size).replace(".0 ", " "))
}

/// The speed tab's status line while a test runs.
pub fn speed_running_text(volume: char, phase: Option<Phase>, permille: u32) -> String {
    match phase {
        Some(phase) => format!(
            "{volume}:  ·  {} ({}): {} %",
            phase.name(),
            phase.how(),
            permille / 10
        ),
        None => format!("{volume}:  ·  Starting…"),
    }
}

/// The speed tab's bar: phases done plus the share of the current one, in permille.
pub fn speed_overall(phase: Option<Phase>, permille: u32) -> u32 {
    let Some(phase) = phase else {
        return 0;
    };
    let index = Phase::ALL.iter().position(|p| *p == phase).unwrap_or(0) as u32;
    (index * 1000 + permille.min(1000)) / Phase::ALL.len() as u32
}

/// The read check's status line while it runs.
pub fn check_running_text(volume: char, files: u64, bytes: u64, used: u64, bad: u64) -> String {
    let share = (used > 0).then(|| (bytes.saturating_mul(100) / used).min(99));
    format!(
        "{volume}:  ·  Read {} {}, {}{}  ·  {} unreadable so far",
        details::grouped(files.into()),
        if files == 1 { "file" } else { "files" },
        format_size(bytes),
        share.map_or(String::new(), |p| format!(
            " of about {} ({p} %)",
            format_size(used)
        )),
        bad
    )
}

impl DriveView {
    pub fn new() -> Self {
        Self::reading(read_drives())
    }

    /// The window as if reading the drives had given `disks`, reading nothing itself: for
    /// the screenshot mode.
    #[cfg(debug_assertions)]
    pub fn read_as(disks: Vec<(Disk, Details)>, elevated: Option<bool>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let _ = sender.send(Loaded {
            disks,
            elevated,
            cut_short: false,
        });
        Self::reading(receiver)
    }

    fn reading(load: mpsc::Receiver<Loaded>) -> Self {
        Self {
            controls: None,
            load: Load::Reading(load),
            started: Instant::now(),
            current: 0,
            tab: Tab::Details,
            lines: Vec::new(),
            volume: None,
            size: speed::DEFAULT_SIZE,
            test: Test::Idle,
            speed: None,
            check: None,
            notice: None,
            area: (0, 0, 96),
            shown: Vec::new(),
        }
    }

    fn loaded(&self) -> Option<&Loaded> {
        match &self.load {
            Load::Ready(loaded) => Some(loaded),
            Load::Reading(_) => None,
        }
    }

    fn disk(&self) -> Option<&(Disk, Details)> {
        self.loaded().and_then(|l| l.disks.get(self.current))
    }

    fn many(&self) -> bool {
        self.loaded().is_some_and(|l| l.disks.len() > 1)
    }

    fn running(&self) -> bool {
        !matches!(self.test, Test::Idle)
    }

    /// Shows disk `index`: its lines, and the first volume a test can use.
    fn show_disk(&mut self, index: usize) {
        self.current = index;
        let elevated = self.loaded().and_then(|l| l.elevated);
        let (lines, volumes) = match self.disk() {
            Some((disk, found)) => (
                details::detail_lines(disk, found, elevated),
                details::test_volumes(found),
            ),
            None => (Vec::new(), Vec::new()),
        };
        self.lines = lines;
        // A running test keeps its own volume; this one is for the next start.
        self.volume = volumes.first().copied();
        let texts: Vec<String> = self.lines.iter().map(details::line_text).collect();
        if let Some(c) = &self.controls {
            toolwin::set_items(c.details, &texts, false);
            toolwin::select(c.disks, Some(index));
        }
        // Texts first: the layout measures the verdict's height.
        self.render();
        self.relayout();
    }

    fn relayout(&mut self) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            if let Some(hwnd) = self.controls.as_ref().map(|c| c.title) {
                let parent =
                    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetParent(hwnd) };
                self.layout(parent, w, h, dpi);
            }
        }
    }

    fn speed_rows(&self) -> Vec<SpeedRow> {
        let mut rows: Vec<SpeedRow> = Phase::MEASURED
            .iter()
            .map(|p| SpeedRow::Phase(*p))
            .collect();
        rows.push(SpeedRow::Verify);
        rows
    }

    /// The measures to show: the running test's so far, else the last finished run's.
    fn measures(&self) -> Vec<speed::Measure> {
        match &self.test {
            Test::Speed { progress, .. } => progress.measures(),
            _ => match &self.speed {
                Some((_, Ok(report))) => report.measures.clone(),
                _ => Vec::new(),
            },
        }
    }

    fn speed_row_text(&self, row: SpeedRow) -> String {
        let measures = self.measures();
        let running = match &self.test {
            Test::Speed { progress, .. } => progress.phase(),
            _ => None,
        };
        match row {
            SpeedRow::Phase(phase) => {
                let result = match measures.iter().find(|m| m.phase == phase) {
                    Some(m) => speed::result_text(m),
                    None if running == Some(phase) => "running".into(),
                    None if running.is_some() => "waiting".into(),
                    None => "not run".into(),
                };
                format!("{}, {}: {result}", phase.name(), phase.how())
            }
            SpeedRow::Verify => {
                let result = match &self.speed {
                    _ if running == Some(Phase::Verify) => "running".into(),
                    _ if running.is_some() => "waiting".into(),
                    Some((_, Ok(report))) => report
                        .verify
                        .as_ref()
                        .map_or("not run".into(), speed::verify_text),
                    _ => "not run".into(),
                };
                format!("Read-back check: {result}")
            }
        }
    }

    fn failed(&self) -> Vec<read_check::Failed> {
        match &self.test {
            Test::Check { progress, .. } => progress
                .failed
                .lock()
                .map(|f| f.clone())
                .unwrap_or_default(),
            _ => self
                .check
                .as_ref()
                .map(|(_, r)| r.failed.clone())
                .unwrap_or_default(),
        }
    }

    fn results_texts(&self) -> Vec<String> {
        match self.tab {
            Tab::Speed => self
                .speed_rows()
                .into_iter()
                .map(|row| self.speed_row_text(row))
                .collect(),
            Tab::Check => self
                .failed()
                .iter()
                .map(|f| format!("{}: {}", f.path.display(), read_check::failure_text(f.code)))
                .collect(),
            Tab::Details => Vec::new(),
        }
    }

    fn refresh_results(&mut self) {
        let texts = self.results_texts();
        if texts != self.shown {
            if let Some(c) = &self.controls {
                toolwin::set_items(c.results, &texts, true);
            }
            self.shown = texts;
        }
    }

    fn status_text(&self) -> String {
        if let Some(notice) = &self.notice {
            return notice.clone();
        }
        match self.tab {
            Tab::Details => match self.loaded() {
                None => format!(
                    "Reading the drives… ({} s)",
                    self.started.elapsed().as_secs()
                ),
                Some(l) if l.disks.is_empty() => "Windows listed no physical drive.".into(),
                Some(l) => {
                    let mut text = match l.elevated {
                        Some(true) => "Read with administrator rights.".to_string(),
                        _ => "Read as the current user; readings that need administrator rights say so.".to_string(),
                    };
                    if l.cut_short {
                        text.push_str(" Some drives did not answer in time and are missing.");
                    }
                    text
                }
            },
            Tab::Speed => match &self.test {
                Test::Speed {
                    volume, progress, ..
                } => speed_running_text(*volume, progress.phase(), progress.permille()),
                Test::Check { .. } => "The read check is running; one test runs at a time.".into(),
                Test::Idle => match &self.speed {
                    Some((volume, Ok(report))) => format!("{volume}:  ·  {}", speed::summary(report)),
                    Some((volume, Err(why))) => format!("{volume}:  ·  {why}"),
                    None => match self.volume {
                        Some(volume) => format!(
                            "Writes a {} test file on {volume}: in a folder of the current user's, times reads and writes without Windows' cache, checks what was written, and deletes the file.",
                            format_size(self.size)
                        ),
                        None => "This drive has no lettered volume, so the speed test has nowhere to put its file.".into(),
                    },
                },
            },
            Tab::Check => match &self.test {
                Test::Check {
                    volume,
                    used,
                    progress,
                    ..
                } => check_running_text(
                    *volume,
                    progress.files.load(Ordering::Relaxed),
                    progress.bytes.load(Ordering::Relaxed),
                    *used,
                    self.failed()
                        .iter()
                        .filter(|f| read_check::classify(f.code) == Failure::Bad)
                        .count() as u64,
                ),
                Test::Speed { .. } => "The speed test is running; one test runs at a time.".into(),
                Test::Idle => match &self.check {
                    Some((volume, report)) => format!("{volume}:  ·  {}", read_check::summary(report)),
                    None => match self.volume {
                        Some(volume) => format!(
                            "Reads every file the current user can open on {volume}: and lists any the drive cannot read back. Nothing is written; online-only cloud files are skipped."
                        ),
                        None => "This drive has no lettered volume to read.".into(),
                    },
                },
            },
        }
    }

    fn render(&mut self) {
        self.refresh_results();
        let status = self.status_text();
        let Some(c) = &self.controls else {
            return;
        };
        match self.disk() {
            Some((disk, found)) => {
                let verdict = details::verdict(disk);
                ui::set_text(c.title, &details::name(disk));
                ui::set_text(c.subtitle, &details::subtitle(disk, found));
                ui::set_text(c.badge, verdict.headline);
                ui::set_tone(c.badge, tone(verdict.grade));
                ui::set_text(c.verdict, &details::verdict_text(&verdict));
                let figures = details::figures(disk);
                for (index, tile) in c.tiles.iter().enumerate() {
                    match figures.get(index) {
                        Some(f) => {
                            ui::set_text(*tile, &format!("{}\n{}", f.label, f.value));
                            // Only amber and red mark a tile; a green dot on each would be noise.
                            let mark = match f.grade {
                                Grade::Good => Tone::Neutral,
                                other => tone(other),
                            };
                            ui::set_tone(*tile, mark);
                        }
                        None => ui::set_text(*tile, ""),
                    }
                }
            }
            None => {
                ui::set_text(
                    c.title,
                    if self.loaded().is_some() {
                        "No drive found"
                    } else {
                        "Drive health"
                    },
                );
                ui::set_text(c.subtitle, "");
                ui::set_text(c.verdict, "");
            }
        }
        ui::set_text(c.status, &status);
        for (hwnd, tab) in [
            (c.tab_details, Tab::Details),
            (c.tab_speed, Tab::Speed),
            (c.tab_check, Tab::Check),
        ] {
            ui::set_kind(
                hwnd,
                if self.tab == tab {
                    Kind::Secondary
                } else {
                    Kind::Ghost
                },
            );
        }
        let (bar, permille) = match &self.test {
            Test::Speed { progress, .. } if self.tab == Tab::Speed => {
                (true, speed_overall(progress.phase(), progress.permille()))
            }
            Test::Check { progress, used, .. } if self.tab == Tab::Check => {
                let bytes = progress.bytes.load(Ordering::Relaxed);
                (
                    true,
                    (bytes.saturating_mul(1000) / (*used).max(1)).min(990) as u32,
                )
            }
            _ => (false, 0),
        };
        ui::show(c.bar, bar);
        ui::set_value(c.bar, permille);
        let volumes = self
            .disk()
            .map(|(_, found)| details::test_volumes(found))
            .unwrap_or_default();
        ui::set_text(
            c.volume,
            &match self.volume {
                Some(v) => format!("Volume {v}:"),
                None => "No volume".into(),
            },
        );
        ui::enable(c.volume, volumes.len() > 1 && !self.running());
        ui::set_text(c.size, &size_caption(self.size));
        ui::enable(c.size, !self.running());
        let (caption, enabled) = match (self.tab, &self.test) {
            (Tab::Details, _) => ("Copy details", self.disk().is_some()),
            (Tab::Speed, Test::Speed { .. }) | (Tab::Check, Test::Check { .. }) => ("Stop", true),
            (Tab::Speed, test) => (
                "Start speed test…",
                matches!(test, Test::Idle) && self.volume.is_some(),
            ),
            (Tab::Check, test) => (
                "Start read check",
                matches!(test, Test::Idle) && self.volume.is_some(),
            ),
        };
        ui::set_text(c.action, caption);
        ui::enable(c.action, enabled);
        ui::enable(c.reread, matches!(self.load, Load::Ready(_)));
        ui::enable(c.recovery, self.disk().is_some());
    }

    fn ask_speed(&mut self) -> Option<Ask> {
        let volume = self.volume?;
        let free = match disk_space(volume) {
            Ok((free, _)) => free,
            Err(why) => {
                self.speed = Some((volume, Err(why)));
                return None;
            }
        };
        if let Err(why) = speed::check_space(volume, free, self.size) {
            self.speed = Some((volume, Err(why)));
            return None;
        }
        let folder = speed::folder_for(volume);
        let mut items = vec![
            Item::Pair("Test file".into(), format_size(speed::file_size(self.size))),
            Item::Pair("Folder".into(), folder.display().to_string()),
            Item::Pair("Free now".into(), format_size(free)),
        ];
        if let Some((_, found)) = self.disk() {
            if let Some(v) = found.volumes.iter().find(|v| v.letter == volume) {
                if !v.other_disks.is_empty() {
                    items.push(Item::Pair(
                        "Note".into(),
                        format!(
                            "{volume}: also lies on disk {}, so the result is for the whole volume",
                            v.other_disks
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }
        Some(Ask {
            dialog: Dialog {
                window_title: "Speed test".into(),
                heading: format!("Test the speed of {volume}:?"),
                intro: "The test writes its file twice, reads it, writes and reads small blocks at random for a few seconds each, checks everything it wrote and deletes the file. It takes about half a minute on an SSD and longer on a hard drive or USB stick; other programs may be slower meanwhile.".into(),
                sections: vec![Section {
                    heading: None,
                    items,
                }],
                accept: "Start".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_SPEED,
        })
    }

    fn start_speed(&mut self) {
        let Some(volume) = self.volume else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(speed::Progress::default());
        let (sender, result) = mpsc::channel();
        let settings = speed::Settings {
            size: self.size,
            ..speed::Settings::default()
        };
        let (c, p) = (cancel.clone(), progress.clone());
        thread::spawn(move || {
            let _ = sender.send(speed::run(volume, &settings, &c, &p));
        });
        self.speed = None;
        self.test = Test::Speed {
            volume,
            cancel,
            progress,
            result,
        };
    }

    fn start_check(&mut self) {
        let Some(volume) = self.volume else {
            return;
        };
        let used = disk_space(volume)
            .map(|(free, total)| total.saturating_sub(free))
            .unwrap_or(0);
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(read_check::Progress::default());
        let (sender, result) = mpsc::channel();
        let (c, p) = (cancel.clone(), progress.clone());
        let root = PathBuf::from(format!("{volume}:\\"));
        thread::spawn(move || {
            let _ = sender.send(read_check::run(&root, &c, &p));
        });
        self.check = None;
        self.test = Test::Check {
            volume,
            used,
            cancel,
            progress,
            result,
        };
    }

    fn copy(&mut self, hwnd: HWND) {
        let elevated = self.loaded().and_then(|l| l.elevated);
        if let Some((disk, found)) = self.disk() {
            let text = details::copy_text(disk, found, elevated);
            self.notice = Some(if ui::copy_to_clipboard(hwnd, &text) {
                "Copied this drive's details to the clipboard.".into()
            } else {
                "Windows did not let the details be copied.".into()
            });
        }
    }

    fn draw_disk(&self, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let Some((disk, _)) = self.loaded().and_then(|l| l.disks.get(index)) else {
            return;
        };
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        let canvas = background(dc, rect, state);
        let mid = (rect.top + rect.bottom) / 2;
        if let Some(canvas) = &canvas {
            let dot = match details::verdict(disk).grade {
                Grade::Good => colors.ok,
                Grade::Flagged => colors.warn,
                Grade::Serious => colors.serious,
                Grade::Unknown => colors.subtle,
            };
            canvas.circle((rect.left + s(14)) as f32, mid as f32, s(4) as f32, dot);
        }
        let left = rect.left + s(28);
        ui::draw_text(
            dc,
            &details::name(disk),
            &RECT {
                left,
                top: rect.top + s(4),
                right: rect.right - s(8),
                bottom: mid + s(1),
            },
            fonts.body,
            colors.text,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
        ui::draw_text(
            dc,
            &details::caption(disk),
            &RECT {
                left,
                top: mid + s(1),
                right: rect.right - s(8),
                bottom: rect.bottom - s(4),
            },
            fonts.caption,
            colors.muted,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
    }

    fn draw_line(&self, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        let canvas = background(dc, rect, state);
        drop(canvas);
        let Some(line) = self.lines.get(index) else {
            return;
        };
        let flags = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
        let width = rect.right - rect.left;
        let key_w = s(64);
        let raw_w = (width / 5).clamp(s(90), s(200));
        let value_w = (width * 3 / 10).clamp(s(150), s(300));
        let pad = s(8);
        let col = |left: i32, right: i32| RECT {
            left: rect.left + left,
            top: rect.top,
            right: rect.left + right,
            bottom: rect.bottom,
        };
        let raw_col = col(width - raw_w, width - pad);
        let value_col = col(width - raw_w - value_w, width - raw_w - pad);
        let key_col = col(pad, pad + key_w - s(6));
        let name_col = col(pad + key_w, width - raw_w - value_w - pad);
        match line {
            Line::Heading(text) => {
                let r = RECT {
                    top: rect.top + s(6),
                    ..col(pad, width - pad)
                };
                ui::draw_text(dc, text, &r, fonts.strong, colors.text, flags);
            }
            Line::Columns(r) => {
                for (text, area) in [
                    (&r.key, key_col),
                    (&r.name, name_col),
                    (&r.value, value_col),
                    (&r.raw, raw_col),
                ] {
                    ui::draw_text(dc, text, &area, fonts.caption, colors.subtle, flags);
                }
            }
            Line::Row(r) => {
                let ink = match r.grade {
                    Grade::Flagged => colors.warn,
                    Grade::Serious => colors.serious,
                    _ => colors.text,
                };
                if r.key.is_empty() && r.raw.is_empty() {
                    // A fact: its name, then its value across the value and raw columns.
                    let split = pad + s(180);
                    ui::draw_text(
                        dc,
                        &r.name,
                        &col(pad, split - pad),
                        fonts.body,
                        colors.muted,
                        flags,
                    );
                    ui::draw_text(
                        dc,
                        &r.value,
                        &col(split, width - pad),
                        fonts.body,
                        ink,
                        flags,
                    );
                } else {
                    ui::draw_text(dc, &r.key, &key_col, fonts.caption, colors.subtle, flags);
                    ui::draw_text(dc, &r.name, &name_col, fonts.body, colors.muted, flags);
                    ui::draw_text(dc, &r.value, &value_col, fonts.body, ink, flags);
                    ui::draw_text(dc, &r.raw, &raw_col, fonts.caption, colors.muted, flags);
                }
            }
        }
    }

    fn draw_result(&self, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        let canvas = background(dc, rect, state);
        let mid = (rect.top + rect.bottom) / 2;
        let left = rect.left + s(10);
        let right = rect.right - s(10);
        let top_line = RECT {
            left,
            top: rect.top + s(4),
            right,
            bottom: mid + s(2),
        };
        let bottom_line = RECT {
            left,
            top: mid + s(2),
            right,
            bottom: rect.bottom - s(4),
        };
        let flags = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
        match self.tab {
            Tab::Speed => {
                let Some(row) = self.speed_rows().get(index).copied() else {
                    return;
                };
                let text = self.speed_row_text(row);
                let (head, result) = text.split_once(": ").unwrap_or((&text, ""));
                let result_w = s(300).min((right - left) / 2);
                let name_rect = RECT {
                    right: right - result_w - s(8),
                    ..top_line
                };
                let result_rect = RECT {
                    left: right - result_w,
                    ..top_line
                };
                let (name, how) = head.split_once(", ").unwrap_or((head, ""));
                let (name, how) = match row {
                    SpeedRow::Phase(phase) => (phase.name(), phase.how()),
                    SpeedRow::Verify => (name, how),
                };
                ui::draw_text(dc, name, &name_rect, fonts.body, colors.text, flags);
                let waiting = matches!(result, "not run" | "waiting" | "running");
                let ink = match row {
                    SpeedRow::Verify => match &self.speed {
                        Some((_, Ok(r))) if r.verify.is_some_and(|v| v.bad_sectors > 0) => {
                            colors.serious
                        }
                        Some((_, Ok(r))) if r.verify.is_some() => colors.ok,
                        _ => colors.muted,
                    },
                    _ if waiting => colors.muted,
                    _ => colors.text,
                };
                match row {
                    SpeedRow::Verify => {
                        ui::draw_text(dc, result, &bottom_line, fonts.caption, ink, flags);
                    }
                    SpeedRow::Phase(phase) => {
                        ui::draw_text(dc, result, &result_rect, fonts.body, ink, flags | DT_RIGHT);
                        ui::draw_text(
                            dc,
                            how,
                            &RECT {
                                right: bottom_line.left + s(220),
                                ..bottom_line
                            },
                            fonts.caption,
                            colors.muted,
                            flags,
                        );
                        // A bar against the fastest phase of the same kind.
                        let measures = self.measures();
                        let best = measures
                            .iter()
                            .filter(|m| m.phase.random() == phase.random())
                            .map(|m| m.mb_per_s())
                            .fold(0.0, f64::max);
                        if let (Some(m), Some(canvas)) =
                            (measures.iter().find(|m| m.phase == phase), &canvas)
                        {
                            let x = (bottom_line.left + s(230)) as f32;
                            let width = (right - s(230) - bottom_line.left) as f32;
                            let bar_h = s(6) as f32;
                            let y =
                                ((bottom_line.top + bottom_line.bottom) / 2) as f32 - bar_h / 2.0;
                            if width > 0.0 {
                                canvas.fill_round((x, y, width, bar_h), bar_h / 2.0, colors.border);
                                let share = if best > 0.0 { m.mb_per_s() / best } else { 0.0 };
                                let filled = (width * share as f32).max(bar_h);
                                canvas.fill_round(
                                    (x, y, filled, bar_h),
                                    bar_h / 2.0,
                                    colors.primary,
                                );
                            }
                        }
                    }
                }
            }
            Tab::Check => {
                let failed = self.failed();
                let Some(f) = failed.get(index) else {
                    return;
                };
                ui::draw_text(
                    dc,
                    &f.path.display().to_string(),
                    &top_line,
                    fonts.body,
                    colors.text,
                    DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS,
                );
                let ink = if read_check::classify(f.code) == Failure::Bad {
                    colors.serious
                } else {
                    colors.muted
                };
                ui::draw_text(
                    dc,
                    &read_check::failure_text(f.code),
                    &bottom_line,
                    fonts.caption,
                    ink,
                    flags,
                );
            }
            Tab::Details => {}
        }
    }

    fn select_disk_from_list(&mut self) {
        let selected = self
            .controls
            .as_ref()
            .and_then(|c| toolwin::selected(c.disks));
        if let Some(index) = selected {
            if index != self.current {
                self.notice = None;
                self.show_disk(index);
            }
        }
    }
}

/// Fills an item's background, with the hover or selection highlight, and returns the canvas.
fn background(dc: HDC, rect: &RECT, state: ItemState) -> Option<ui::Canvas> {
    let colors = ui::current();
    let s = |v: i32| scale(state.dpi, v);
    ui::fill_rect(dc, rect, colors.card);
    let canvas = ui::Canvas::new(dc);
    let fill = if state.selected {
        colors.raised_hover
    } else if state.hot {
        colors.raised
    } else {
        colors.card
    };
    if let Some(canvas) = &canvas {
        if fill != colors.card {
            canvas.fill_round(
                (
                    rect.left as f32,
                    (rect.top + s(1)) as f32,
                    (rect.right - rect.left) as f32,
                    (rect.bottom - rect.top - s(2)) as f32,
                ),
                s(6) as f32,
                fill,
            );
        }
    }
    canvas
}

impl Page for DriveView {
    fn title(&self) -> String {
        "Drive health and tests".into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((940, 780), (720, 600))
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::DRIVE_HEALTH)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let controls = Controls {
            disks: toolwin::list(hwnd, DISKS, 52),
            title: text(Kind::Title, "Drive health"),
            subtitle: text(Kind::Muted, ""),
            badge: text(Kind::Badge, ""),
            verdict: text(Kind::Body, ""),
            tiles: (0..TILES).map(|_| text(Kind::Tile, "")).collect(),
            tab_details: ui::button(hwnd, TAB_DETAILS, Kind::Secondary, "Details"),
            tab_speed: ui::button(hwnd, TAB_SPEED, Kind::Ghost, "Speed test"),
            tab_check: ui::button(hwnd, TAB_CHECK, Kind::Ghost, "Read check"),
            volume: ui::button(hwnd, VOLUME, Kind::Ghost, "Volume C:"),
            size: ui::button(hwnd, SIZE, Kind::Ghost, &size_caption(speed::DEFAULT_SIZE)),
            status: text(Kind::Muted, ""),
            bar: text(Kind::Progress, ""),
            details: toolwin::list(hwnd, DETAILS, 28),
            results: toolwin::list(hwnd, RESULTS, 48),
            action: ui::button(hwnd, ACTION, Kind::Primary, "Copy details"),
            reread: ui::button(hwnd, REREAD, Kind::Secondary, "Read again"),
            recovery: ui::button(hwnd, RECOVERY, Kind::Secondary, "Recovery…"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        let body = ui::fonts(ui::dpi_of(hwnd)).body;
        for list in [controls.disks, controls.details, controls.results] {
            ui::set_font(list, body);
        }
        self.controls = Some(controls);
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let many = self.many();
        let ready = self.disk().is_some();
        let figures = self
            .disk()
            .map_or(0, |(disk, _)| details::figures(disk).len());
        let tab = self.tab;
        let Some(c) = &self.controls else {
            return;
        };
        let body = ui::fonts(dpi).body;
        for list in [c.disks, c.details, c.results] {
            ui::set_font(list, body);
        }
        let s = |v: i32| scale(dpi, v);
        let m = s(grid::OUTER);
        let gap = s(grid::BUTTON_GAP);
        let bh = s(grid::BUTTON_H);
        let bottom_y = h - m - bh;
        let mut cards = Vec::new();
        let side = if many { s(240) } else { 0 };
        ui::show(c.disks, many);
        if many {
            let card = Rect {
                x: m,
                y: s(16),
                w: side,
                h: bottom_y - s(16) - s(16),
            };
            ui::place(
                c.disks,
                Rect {
                    x: card.x + s(6),
                    y: card.y + s(6),
                    w: card.w - s(12),
                    h: card.h - s(12),
                },
            );
            cards.push(card);
        }
        let x = if many { m + side + s(16) } else { m };
        let cw = w - x - m;
        let mut y = s(16);
        let place = |hwnd, x, y, w, h| ui::place(hwnd, Rect { x, y, w, h });
        place(c.title, x, y, cw, s(grid::TITLE_H));
        y += s(grid::TITLE_H) + s(2);
        place(c.subtitle, x, y, cw, s(grid::BODY_H));
        y += s(grid::BODY_H) + s(12);
        let badge_w = s(132);
        ui::show(c.badge, ready);
        place(c.badge, x, y, badge_w, s(grid::BADGE_H));
        let verdict_x = x + badge_w + s(12);
        let verdict_w = (cw - badge_w - s(12)).max(s(80));
        let verdict_h = ui::text_height(c.verdict, body, &ui::window_text(c.verdict), verdict_w)
            .clamp(s(grid::BODY_H), s(grid::BODY_H) * 3);
        place(c.verdict, verdict_x, y + s(2), verdict_w, verdict_h);
        y += verdict_h.max(s(grid::BADGE_H)) + s(14);
        let tile_gap = s(8);
        let columns = ((cw + tile_gap) / (s(112) + tile_gap)).clamp(2, 5);
        let tile_w = (cw - (columns - 1) * tile_gap) / columns;
        let tile_h = s(58);
        for (index, tile) in c.tiles.iter().enumerate() {
            let shown = index < figures;
            ui::show(*tile, shown);
            if shown {
                let (row, column) = (index as i32 / columns, index as i32 % columns);
                place(
                    *tile,
                    x + column * (tile_w + tile_gap),
                    y + row * (tile_h + tile_gap),
                    tile_w,
                    tile_h,
                );
            }
        }
        if figures > 0 {
            let rows = (figures as i32 + columns - 1) / columns;
            y += rows * (tile_h + tile_gap) + s(8);
        }
        let mut bx = x;
        for (hwnd, caption) in [
            (c.tab_details, "Details"),
            (c.tab_speed, "Speed test"),
            (c.tab_check, "Read check"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            place(hwnd, bx, y, bw, bh);
            bx += bw + gap;
        }
        let mut rx = x + cw;
        let size_w = ui::button_width(c.size, "Test size 256.0 MiB");
        let volume_w = ui::button_width(c.volume, "Volume W:");
        ui::show(c.size, tab == Tab::Speed);
        ui::show(c.volume, tab != Tab::Details);
        if tab == Tab::Speed {
            rx -= size_w;
            place(c.size, rx, y, size_w, bh);
            rx -= gap;
        }
        place(c.volume, rx - volume_w, y, volume_w, bh);
        y += bh + s(10);
        place(c.status, x, y, cw, s(grid::BODY_H) * 2);
        y += s(grid::BODY_H) * 2 + s(4);
        place(c.bar, x, y, cw, s(4));
        y += s(4) + s(10);
        let card = Rect {
            x,
            y,
            w: cw,
            h: (bottom_y - s(16) - y).max(s(80)),
        };
        let inner = Rect {
            x: card.x + s(6),
            y: card.y + s(6),
            w: card.w - s(12),
            h: card.h - s(12),
        };
        ui::show(c.details, tab == Tab::Details);
        ui::show(c.results, tab != Tab::Details);
        ui::place(c.details, inner);
        ui::place(c.results, inner);
        cards.push(card);
        ui::set_cards(hwnd, cards);
        let action_w = ui::button_width(c.action, "Start speed test…");
        place(c.action, x, bottom_y, action_w, bh);
        let mut rx = w - m;
        for (hwnd, caption) in [
            (c.close, "Close"),
            (c.reread, "Read again"),
            (c.recovery, "Recovery…"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            rx -= bw;
            place(hwnd, rx, bottom_y, bw, bh);
            rx -= gap;
        }
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            DISKS if code == toolwin::ACTIVATE || code == SELCHANGE => self.select_disk_from_list(),
            TAB_DETAILS | TAB_SPEED | TAB_CHECK => {
                self.tab = match id {
                    TAB_SPEED => Tab::Speed,
                    TAB_CHECK => Tab::Check,
                    _ => Tab::Details,
                };
                self.notice = None;
                self.shown.clear();
                if let Some(c) = &self.controls {
                    toolwin::set_items(c.results, &[], false);
                }
                self.relayout();
            }
            VOLUME => {
                let volumes = self
                    .disk()
                    .map(|(_, found)| details::test_volumes(found))
                    .unwrap_or_default();
                if let Some(at) = self
                    .volume
                    .and_then(|v| volumes.iter().position(|x| *x == v))
                {
                    self.volume = volumes.get((at + 1) % volumes.len()).copied();
                }
            }
            SIZE => {
                let at = SIZES.iter().position(|s| *s == self.size).unwrap_or(1);
                self.size = SIZES[(at + 1) % SIZES.len()];
            }
            ACTION => match (self.tab, &self.test) {
                (Tab::Details, _) => self.copy(hwnd),
                (Tab::Speed, Test::Speed { cancel, .. })
                | (Tab::Check, Test::Check { cancel, .. }) => {
                    cancel.store(true, Ordering::Relaxed);
                    self.notice = Some("Stopping…".into());
                }
                (Tab::Speed, Test::Idle) => ask = self.ask_speed(),
                (Tab::Check, Test::Idle) => {
                    self.notice = None;
                    self.start_check();
                }
                _ => {}
            },
            DO_SPEED => {
                self.notice = None;
                self.start_speed();
            }
            RECOVERY => {
                if let Some(number) = self.disk().map(|(disk, _)| disk.number) {
                    self.notice = Some(
                        match crate::recovery_view::launch_elevated(hwnd, number) {
                            Ok(()) => format!("Recovery for disk {number} opened in its own window, with administrator rights for that window only."),
                            Err(why) => why,
                        },
                    );
                }
            }
            REREAD => {
                self.notice = None;
                self.started = Instant::now();
                self.load = Load::Reading(read_drives());
            }
            // Posted, so the window closes after this call returns and the page is dropped,
            // which stops a running test.
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        ask
    }

    fn tick(&mut self, _hwnd: HWND) {
        if let Load::Reading(receiver) = &self.load {
            if let Ok(loaded) = receiver.try_recv() {
                // Reading again keeps the same disk in view when it is still there.
                let keep = self.disk().map(|(d, _)| d.number);
                let disks: Vec<Disk> = loaded.disks.iter().map(|(d, _)| d.clone()).collect();
                let first = keep
                    .and_then(|n| disks.iter().position(|d| d.number == n))
                    .unwrap_or_else(|| details::first_shown(&disks, system_letter()));
                let texts: Vec<String> = disks
                    .iter()
                    .map(|d| {
                        format!(
                            "{}, {}, {}",
                            details::name(d),
                            details::caption(d),
                            details::verdict(d).headline
                        )
                    })
                    .collect();
                self.load = Load::Ready(loaded);
                if let Some(c) = &self.controls {
                    toolwin::set_items(c.disks, &texts, false);
                }
                self.show_disk(first);
            }
        }
        let finished_speed = match &self.test {
            Test::Speed { volume, result, .. } => result.try_recv().ok().map(|r| (*volume, r)),
            _ => None,
        };
        if let Some(done) = finished_speed {
            self.test = Test::Idle;
            self.notice = None;
            self.speed = Some(done);
        }
        let finished_check = match &self.test {
            Test::Check { volume, result, .. } => result.try_recv().ok().map(|r| (*volume, r)),
            _ => None,
        };
        if let Some(done) = finished_check {
            self.test = Test::Idle;
            self.notice = None;
            self.check = Some(done);
        }
        self.render();
    }

    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        match list {
            DISKS => self.draw_disk(index, dc, rect, state),
            DETAILS => self.draw_line(index, dc, rect, state),
            _ => self.draw_result(index, dc, rect, state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_texts_name_the_phase_and_the_share_done() {
        assert_eq!(
            speed_running_text('C', Some(Phase::SeqRead), 455),
            "C:  ·  Sequential read (1 MiB blocks, 8 in flight): 45 %"
        );
        assert_eq!(speed_running_text('D', None, 0), "D:  ·  Starting…");
        assert_eq!(speed_overall(None, 500), 0);
        assert_eq!(speed_overall(Some(Phase::Prepare), 1000), 125);
        assert_eq!(speed_overall(Some(Phase::Verify), 1000), 1000);
        let gib = 1u64 << 30;
        assert_eq!(
            check_running_text('C', 12_345, 10 * gib, 100 * gib, 0),
            "C:  ·  Read 12,345 files, 10.0 GiB of about 100.0 GiB (10 %)  ·  0 unreadable so far"
        );
        assert_eq!(
            check_running_text('C', 1, 5, 0, 2),
            "C:  ·  Read 1 file, 5 B  ·  2 unreadable so far"
        );
    }

    #[test]
    fn size_captions_are_short() {
        assert_eq!(size_caption(1 << 30), "Test size 1 GiB");
        assert_eq!(size_caption(256 << 20), "Test size 256 MiB");
        assert_eq!(size_caption(4 << 30), "Test size 4 GiB");
    }
}
