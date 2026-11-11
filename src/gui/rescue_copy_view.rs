//! The rescue copy window: copies chosen folders from the failing drive to a folder on
//! another drive, readable parts first, and lists damaged and skipped files as it goes.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use diagnostics::recovery::check_destination;
use diagnostics::recovery::copy::{self, Outcome, Progress, Report, Settings, Volume};
use diagnostics::tools::drives::bytes_text;
use diagnostics::tools::drives::device;
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    DT_PATH_ELLIPSIS, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::condition_strip::{self, Strip};
use crate::dialog::{Dialog, Item, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};
use crate::verify_view;

const ADD: usize = 10;
const REMOVE: usize = 11;
const DESTINATION: usize = 12;
const DAMAGED: usize = 13;
const ACTION: usize = 14;
const SHOW_LOG: usize = 15;
const CLOSE: usize = 16;
const CHECK: usize = 17;
const SOURCES: usize = 20;
const NOTES: usize = 21;
/// Accepting the start confirmation.
const DO_START: usize = 30;

pub fn open(owner: HWND, disk: u32, letters: Vec<char>) {
    toolwin::open(owner, "rescue-copy", || {
        Box::new(CopyView::new(disk, letters))
    });
}

struct Running {
    stop: Arc<AtomicBool>,
    progress: Arc<Progress>,
    /// Bytes copied over the last few seconds, for the strip's reading speed.
    samples: std::collections::VecDeque<(std::time::Instant, u64)>,
    result: mpsc::Receiver<Report>,
    worker: Option<JoinHandle<()>>,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    strip: Strip,
    sources: HWND,
    add: HWND,
    remove: HWND,
    destination: HWND,
    damaged: HWND,
    status: HWND,
    notes: HWND,
    action: HWND,
    show_log: HWND,
    check: HWND,
    close: HWND,
}

pub struct CopyView {
    disk: u32,
    letters: Vec<char>,
    sources: Vec<PathBuf>,
    destination: Option<PathBuf>,
    skip_damaged: bool,
    running: Option<Running>,
    report: Option<Report>,
    notes: Vec<String>,
    notice: Option<(String, Tone)>,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

impl Drop for CopyView {
    fn drop(&mut self) {
        condition_strip::speed(self.disk, None);
        if let Some(running) = &mut self.running {
            running.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = running.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// The status line while a copy runs.
pub fn running_text(pass: u64, files: u64, bytes: u64, damaged: u64, skipped: u64) -> String {
    let what = if pass >= 2 {
        "Second pass: reading failed parts again"
    } else {
        "First pass: copying what reads easily"
    };
    format!(
        "{what}  ·  {} {} ({})  ·  {damaged} damaged  ·  {skipped} skipped",
        files,
        if files == 1 { "file" } else { "files" },
        bytes_text(bytes)
    )
}

impl CopyView {
    pub fn new(disk: u32, letters: Vec<char>) -> Self {
        Self {
            disk,
            letters,
            sources: Vec::new(),
            destination: None,
            skip_damaged: false,
            running: None,
            report: None,
            notes: Vec::new(),
            notice: None,
            controls: None,
            area: (0, 0, 96),
            natural: None,
        }
    }

    fn status_text(&self) -> (String, Tone) {
        if let Some(run) = &self.running {
            let p = &run.progress;
            let mut text = running_text(
                p.pass.load(Ordering::Relaxed),
                p.files.load(Ordering::Relaxed),
                p.bytes.load(Ordering::Relaxed),
                p.damaged.load(Ordering::Relaxed),
                p.skipped.load(Ordering::Relaxed),
            );
            if let Ok(current) = p.current.lock() {
                if !current.is_empty() {
                    text.push_str(&format!("\n{current}"));
                }
            }
            return (text, Tone::Neutral);
        }
        if let Some(notice) = &self.notice {
            return notice.clone();
        }
        if self.letters.is_empty() {
            return (
                format!("Disk {} has no lettered volume Windows can open, so its files cannot be copied this way; make a rescue image instead.", self.disk),
                Tone::Warn,
            );
        }
        (
            "Add the folders to rescue, choose where to copy them, then Start. Unreadable parts become zeros and the log in the destination lists each damaged file; or choose to leave damaged files out.".into(),
            Tone::Neutral,
        )
    }

    fn render(&mut self) {
        let (status, status_tone) = self.status_text();
        let Some(c) = &self.controls else {
            return;
        };
        let letters: Vec<String> = self.letters.iter().map(|l| format!("{l}:")).collect();
        ui::set_text(
            c.subtitle,
            &if letters.is_empty() {
                format!("Disk {}", self.disk)
            } else {
                format!("Disk {}, volumes {}", self.disk, letters.join(" "))
            },
        );
        ui::set_text(
            c.destination,
            &match &self.destination {
                Some(folder) => format!("Copy to: {}", folder.display()),
                None => "Choose where to copy to…".into(),
            },
        );
        ui::set_text(
            c.damaged,
            if self.skip_damaged {
                "Damaged files: leave out"
            } else {
                "Damaged files: copy with zeros"
            },
        );
        ui::set_text(c.status, &status);
        ui::set_tone(c.status, status_tone);
        let running = self.running.is_some();
        for hwnd in [c.add, c.destination, c.damaged] {
            ui::enable(hwnd, !running && !self.letters.is_empty());
        }
        ui::enable(c.remove, !running && toolwin::selected(c.sources).is_some());
        let (caption, enabled) = match &self.running {
            Some(run) if run.stop.load(Ordering::Relaxed) => ("Stopping…", false),
            Some(_) => ("Stop", true),
            None => ("Start…", !self.sources.is_empty()),
        };
        ui::set_text(c.action, caption);
        ui::enable(c.action, enabled);
        ui::enable(c.show_log, self.report.is_some());
        ui::enable(c.check, self.report.is_some());
        toolwin::set_empty(
            c.sources,
            if self.letters.is_empty() {
                "No folder can be added: the drive has no volume with a drive letter."
            } else {
                "The folders to copy are listed here. Add folder chooses one on the failing drive."
            },
        );
        toolwin::set_empty(
            c.notes,
            if self.report.is_some() {
                "No file was damaged or left out."
            } else {
                "Each damaged or left-out file is listed here as the copy runs."
            },
        );
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    fn refresh_sources(&self) {
        if let Some(c) = &self.controls {
            let texts: Vec<String> = self
                .sources
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            toolwin::set_items(c.sources, &texts, false);
        }
    }

    fn add_folder(&mut self, hwnd: HWND) {
        let Some(folder) =
            toolwin::pick_folder(hwnd, "Choose a folder on the failing drive to copy")
        else {
            return;
        };
        match device::disks_of_path(&folder) {
            Ok(disks) if disks.contains(&self.disk) => {
                if !self.sources.contains(&folder) {
                    self.sources.push(folder);
                    self.refresh_sources();
                }
                self.notice = None;
            }
            Ok(_) => {
                self.notice = Some((
                    format!(
                        "{} is not on disk {}; choose a folder on the drive being rescued.",
                        folder.display(),
                        self.disk
                    ),
                    Tone::Warn,
                ))
            }
            Err(why) => self.notice = Some((why, Tone::Warn)),
        }
    }

    fn ask_start(&mut self, hwnd: HWND) -> Option<Ask> {
        if self.destination.is_none() {
            self.destination =
                toolwin::pick_folder(hwnd, "Choose a folder on another drive to copy into");
        }
        let destination = self.destination.clone()?;
        if let Err(why) = check_destination(
            &destination,
            &diagnostics::recovery::dest::Protected::disk(self.disk),
        ) {
            self.notice = Some((why, Tone::Warn));
            return None;
        }
        let mut items: Vec<Item> = self
            .sources
            .iter()
            .map(|s| Item::Pair("Copy".into(), s.display().to_string()))
            .collect();
        items.push(Item::Pair("Into".into(), into_text(&destination)));
        items.push(Item::Pair(
            "Damaged files".into(),
            if self.skip_damaged {
                "left out"
            } else {
                "copied, with zeros where unreadable"
            }
            .into(),
        ));
        Some(Ask {
            dialog: Dialog {
                window_title: "Rescue copy".into(),
                heading: "Copy these folders?".into(),
                intro: "The drive is only read. Junctions and links are not followed. A log of what was copied, damaged and skipped goes into the new folder.".into(),
                sections: vec![Section { heading: None, items }],
                accept: "Start".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_START,
        })
    }

    fn start(&mut self) {
        let Some(destination) = self.destination.clone() else {
            return;
        };
        // The disk this window was opened for is guarded too, whatever the folders say.
        let (folder, guard) = match copy::prepare(&self.sources, &destination, Some(self.disk)) {
            Ok(prepared) => prepared,
            Err(why) => {
                self.notice = Some((why, Tone::Warn));
                return;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let (sender, result) = mpsc::channel();
        let sources = self.sources.clone();
        let settings = Settings {
            skip_damaged: self.skip_damaged,
            ..Settings::default()
        };
        let (s, p) = (stop.clone(), progress.clone());
        let worker = thread::spawn(move || {
            let mut volume = Volume::new(&sources[0]);
            let report = copy::run(&mut volume, &sources, &folder, &guard, &settings, &s, &p);
            let _ = sender.send(report);
        });
        self.notes.clear();
        self.report = None;
        self.notice = None;
        self.running = Some(Running {
            stop,
            progress,
            samples: Default::default(),
            result,
            worker: Some(worker),
        });
    }

    /// Hands the condition strip how fast the copy reads the drive, and refreshes it.
    fn share_speed(&mut self) {
        let speed = self.running.as_mut().map(|run| {
            let now = std::time::Instant::now();
            run.samples
                .push_back((now, run.progress.bytes.load(Ordering::Relaxed)));
            while run
                .samples
                .front()
                .is_some_and(|(at, _)| now.duration_since(*at).as_secs() > 5)
            {
                run.samples.pop_front();
            }
            let pass = run.progress.pass.load(Ordering::Relaxed);
            diagnostics::recovery::condition::Speed {
                bytes_per_second: diagnostics::recovery::image::window_rate(
                    &run.samples.iter().copied().collect::<Vec<_>>(),
                ),
                left: Some(if pass >= 2 {
                    "second pass: failed parts".into()
                } else {
                    "first pass of two".into()
                }),
                waiting: false,
            }
        });
        condition_strip::speed(self.disk, speed);
        if let Some(c) = &mut self.controls {
            c.strip.refresh();
        }
    }

    fn refresh_notes(&mut self) {
        let notes = match &self.running {
            Some(run) => run
                .progress
                .notes
                .lock()
                .map(|n| n.clone())
                .unwrap_or_default(),
            None => return,
        };
        if notes.len() != self.notes.len() {
            self.notes = notes;
            if let Some(c) = &self.controls {
                toolwin::set_items(c.notes, &self.notes, true);
            }
        }
    }
}

impl Page for CopyView {
    fn title(&self) -> String {
        "Rescue copy of files".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::RESCUE_COPY)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((760, 620), (600, 520))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let controls = Controls {
            title: text(Kind::Title, "Rescue copy of files"),
            subtitle: text(Kind::Muted, ""),
            strip: Strip::new(hwnd, Some(self.disk)),
            sources: toolwin::list(hwnd, SOURCES, 30),
            add: ui::button(hwnd, ADD, Kind::Secondary, "Add folder…"),
            remove: ui::button(hwnd, REMOVE, Kind::Secondary, "Remove"),
            destination: ui::button(
                hwnd,
                DESTINATION,
                Kind::Secondary,
                "Choose where to copy to…",
            ),
            damaged: ui::button(
                hwnd,
                DAMAGED,
                Kind::Secondary,
                "Damaged files: copy with zeros",
            ),
            status: text(Kind::Body, ""),
            notes: toolwin::list_wrapping(hwnd, NOTES, 28),
            action: ui::button(hwnd, ACTION, Kind::Primary, "Start…"),
            show_log: ui::button(hwnd, SHOW_LOG, Kind::Secondary, "Show log"),
            check: ui::button(hwnd, CHECK, Kind::Secondary, "Check recovered files"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        let body = ui::fonts(ui::dpi_of(hwnd)).body;
        for list in [controls.sources, controls.notes] {
            ui::set_font(list, body);
        }
        self.controls = Some(controls);
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        let pad = f.s(6);
        let mut cards = Vec::new();
        f.header(c.title, c.subtitle);
        c.strip.place(&mut f);
        f.space(2);
        let card = |f: &toolwin::Flow, list: HWND, h: i32| {
            ui::place(
                list,
                Rect {
                    x: f.x + pad,
                    y: f.y + pad,
                    w: f.w - 2 * pad,
                    h: h - 2 * pad,
                },
            );
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h,
            }
        };
        let sources = card(&f, c.sources, f.s(30) * 3 + 2 * pad);
        f.y += sources.h;
        cards.push(sources);
        f.space(10);
        f.buttons(&[c.add, c.remove], grid::BUTTON_GAP);
        f.buttons(&[c.destination, c.damaged], 12);
        f.text(c.status, 8);
        // The notes take what is left above the footer; each wraps to its own height.
        let heights: Vec<i32> = self
            .notes
            .iter()
            .map(|n| {
                ui::text_height(c.notes, ui::fonts(dpi).body, n, f.w - 2 * pad - f.s(16)) + f.s(8)
            })
            .collect();
        toolwin::set_heights(c.notes, &heights);
        let footer = toolwin::footer_h(dpi);
        self.natural = Some(f.y + f.s(28) * 6 + 2 * pad + footer);
        let notes = card(&f, c.notes, (h - footer - f.y).max(f.s(60)));
        cards.push(notes);
        toolwin::footer(w, h, dpi, &[c.action, c.show_log, c.check], &[c.close]);
        ui::set_cards(hwnd, cards);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, _code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            ADD => self.add_folder(hwnd),
            REMOVE => {
                let selected = self
                    .controls
                    .as_ref()
                    .and_then(|c| toolwin::selected(c.sources));
                if let Some(index) = selected.filter(|i| *i < self.sources.len()) {
                    self.sources.remove(index);
                    self.refresh_sources();
                }
            }
            DESTINATION => {
                if let Some(folder) =
                    toolwin::pick_folder(hwnd, "Choose a folder on another drive to copy into")
                {
                    match check_destination(
                        &folder,
                        &diagnostics::recovery::dest::Protected::disk(self.disk),
                    ) {
                        Ok(()) => {
                            self.destination = Some(folder);
                            self.notice = None;
                        }
                        Err(why) => self.notice = Some((why, Tone::Warn)),
                    }
                }
            }
            DAMAGED => self.skip_damaged = !self.skip_damaged,
            ACTION => match &self.running {
                Some(run) => run.stop.store(true, Ordering::Relaxed),
                None => ask = self.ask_start(hwnd),
            },
            DO_START => self.start(),
            SHOW_LOG => {
                if let Some(report) = &self.report {
                    toolwin::open_path(hwnd, &report.log);
                }
            }
            CHECK => {
                if let Some(folder) = self.report.as_ref().and_then(|r| r.log.parent()) {
                    verify_view::open(
                        hwnd,
                        Some(folder.to_path_buf()),
                        diagnostics::recovery::dest::Protected::disk(self.disk),
                    );
                }
            }
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        self.relayout(hwnd);
        ask
    }

    fn tick(&mut self, hwnd: HWND) {
        self.refresh_notes();
        self.share_speed();
        let done = self
            .running
            .as_ref()
            .and_then(|run| toolwin::poll_result(&run.result));
        if let Some(Err(why)) = done {
            let worker = self.running.take().and_then(|mut run| run.worker.take());
            let why = toolwin::without_result(why, worker);
            self.notice = Some((
                format!("{why} The files made so far are listed in the copy's log."),
                Tone::Warn,
            ));
        } else if let Some(Ok(report)) = done {
            self.refresh_notes();
            if let Some(mut run) = self.running.take() {
                if let Some(worker) = run.worker.take() {
                    let _ = worker.join();
                }
            }
            self.notice = Some(finished_notice(&report));
            self.report = Some(report);
        }
        self.render();
        self.relayout(hwnd);
    }

    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        if self
            .controls
            .as_ref()
            .is_some_and(|c| c.strip.draw(list, dc, rect, state.dpi))
        {
            return;
        }
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        ui::fill_rect(
            dc,
            rect,
            if state.selected {
                colors.raised_hover
            } else if state.hot {
                colors.raised
            } else {
                colors.card
            },
        );
        let text_rect = RECT {
            left: rect.left + s(8),
            right: rect.right - s(8),
            ..*rect
        };
        match list {
            SOURCES => {
                if let Some(path) = self.sources.get(index) {
                    ui::draw_text(
                        dc,
                        &path.display().to_string(),
                        &text_rect,
                        fonts.body,
                        colors.text,
                        DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS,
                    );
                }
            }
            _ => {
                if let Some(note) = self.notes.get(index) {
                    let ink = if note.starts_with("Damaged") {
                        colors.warn
                    } else {
                        colors.muted
                    };
                    let text_rect = RECT {
                        top: rect.top + s(4),
                        ..text_rect
                    };
                    ui::draw_text(dc, note, &text_rect, fonts.body, ink, DT_WORDBREAK);
                }
            }
        }
    }
}

/// Where the copy goes, as the confirmation shows it: one separator after a drive root too.
fn into_text(destination: &std::path::Path) -> String {
    destination
        .join("Rescued files <date>")
        .display()
        .to_string()
}

/// The notice when a copy ends: its summary and where the log is, and whether the log
/// could be written to its end; the tone says whether all went well.
fn finished_notice(report: &copy::Report) -> (String, Tone) {
    let tone = match report.outcome {
        _ if report.log_error.is_some() => Tone::Warn,
        Outcome::Finished
            if report.damaged() == 0 && report.partial() == 0 && report.skipped.is_empty() =>
        {
            Tone::Ok
        }
        Outcome::Finished | Outcome::Stopped => Tone::Neutral,
        _ => Tone::Warn,
    };
    let mut text = format!(
        "{}\nLog: {}",
        copy::summary(report, &report.outcome),
        report.log.display()
    );
    if let Some(why) = &report.log_error {
        text.push_str(&format!(
            "\nThe log could not be written in full ({why}); it lacks its last line, \"{}\".",
            copy::LOG_END
        ));
    }
    if report.unlisted > 0 {
        let verb = if report.unlisted == 1 { "is" } else { "are" };
        text.push_str(&format!(
            "\n{} made {verb} not listed in it.",
            diagnostics::recovery::ledger::files(report.unlisted)
        ));
    }
    (text, tone)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard: a copy whose log could not be written to its end says so, as a warning,
    /// even when the copy itself went well.
    #[test]
    fn a_log_cut_short_is_shown_as_such() {
        let mut report = copy::Report {
            outcome: Outcome::Finished,
            ledger: Default::default(),
            skipped: Vec::new(),
            log: std::path::PathBuf::from(r"X:\Rescued files\Rescue copy log.txt"),
            log_error: None,
            unlisted: 0,
        };
        assert_eq!(finished_notice(&report).1, Tone::Ok);
        report.log_error = Some("the destination is full".into());
        let (text, tone) = finished_notice(&report);
        assert!(
            text.contains("The log could not be written in full (the destination is full)"),
            "{text}"
        );
        assert!(!text.contains("not listed"), "{text}");
        report.unlisted = 3;
        let (text, _) = finished_notice(&report);
        assert!(
            text.ends_with("\n3 files made are not listed in it."),
            "{text}"
        );
        assert_eq!(tone, Tone::Warn);
    }

    #[test]
    fn the_destination_text_has_one_separator_at_a_drive_root() {
        assert_eq!(
            into_text(std::path::Path::new("X:\\")),
            "X:\\Rescued files <date>"
        );
        assert_eq!(
            into_text(std::path::Path::new("D:\\Backups")),
            "D:\\Backups\\Rescued files <date>"
        );
    }

    #[test]
    fn the_running_line_names_the_pass_and_counts() {
        assert_eq!(
            running_text(1, 12, 3 << 20, 1, 2),
            "First pass: copying what reads easily  ·  12 files (3.1 MB)  ·  1 damaged  ·  2 skipped"
        );
        assert!(running_text(2, 1, 0, 0, 0).starts_with("Second pass"));
    }
}
