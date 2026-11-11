//! The file check window: the technician picks a folder of recovered or copied files, and
//! every file in it is sorted into good, damaged or not checked by its contents, damaged
//! first, each with its reason, and `File check report.txt` is written into the folder.
//! The window only builds the engine's options, shows its events and renders its result;
//! every rule and limit is in `diagnostics::recovery::verify`.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use diagnostics::recovery::ledger::files;
use diagnostics::recovery::verify::{self, Ended, Event, Options, Outcome, Phase, Row, Verdict};
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    DT_END_ELLIPSIS, DT_LEFT, DT_PATH_ELLIPSIS, DT_SINGLELINE, DT_VCENTER, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const CHOOSE: usize = 10;
const ACTION: usize = 11;
const REPORT: usize = 12;
const SHOW: usize = 13;
const CLOSE: usize = 14;
const LIST: usize = 20;

/// Opens the check, on `folder` at once when one is given. `source_disk` is the drive being
/// recovered, whose folders are refused: they are read from the failing drive itself.
pub fn open(
    owner: HWND,
    folder: Option<PathBuf>,
    source_disk: diagnostics::recovery::dest::Protected,
) {
    let key = match &folder {
        Some(folder) => format!("file-check:{}", folder.display()),
        None => "file-check".into(),
    };
    toolwin::open(owner, &key, move || {
        let mut view = VerifyView::new(source_disk);
        if let Some(folder) = folder {
            view.folder = Some(folder);
            view.start();
        }
        Box::new(view)
    });
}

struct Running {
    stop: Arc<AtomicBool>,
    events: mpsc::Receiver<Event>,
    /// The latest event, and the last file found damaged.
    last: Event,
    result: mpsc::Receiver<Result<Outcome, String>>,
    worker: Option<JoinHandle<()>>,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    choose: HWND,
    action: HWND,
    bar: HWND,
    status: HWND,
    list: HWND,
    report: HWND,
    show: HWND,
    close: HWND,
}

pub struct VerifyView {
    source_disk: diagnostics::recovery::dest::Protected,
    folder: Option<PathBuf>,
    running: Option<Running>,
    outcome: Option<Outcome>,
    notice: Option<(String, Tone)>,
    controls: Option<Controls>,
    shown_rows: usize,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

impl Drop for VerifyView {
    fn drop(&mut self) {
        if let Some(running) = &mut self.running {
            running.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = running.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// The status line while a check runs, from its latest event.
pub fn running_text(e: &Event) -> String {
    match e.phase {
        None => "Opening the folder…".into(),
        Some(Phase::Listing) => format!(
            "Listing the folder: {} found so far",
            files(e.files_total as usize)
        ),
        Some(Phase::Checking) | Some(Phase::Reporting) => format!(
            "Checked {} of {} ({} of {})  ·  {} damaged  ·  {} not checked",
            e.files_done,
            files(e.files_total as usize),
            bytes_text(e.bytes_done),
            bytes_text(e.bytes_total),
            e.damaged,
            e.not_checked
        ),
    }
}

/// The notice when a check ends, from its rows and its report's ledger entry; the tone
/// says whether every file came out good.
pub fn finished_notice(outcome: &Outcome) -> (String, Tone) {
    let (good, damaged, unchecked) = (
        outcome.count(Verdict::Good),
        outcome.count(Verdict::Damaged),
        outcome.count(Verdict::NotChecked),
    );
    let mut text = format!(
        "{}: {good} good, {damaged} damaged, {unchecked} not checked.",
        files(outcome.rows.len())
    );
    let stopped = outcome.ended == Ended::Stopped;
    if stopped {
        text.push_str(" Stopped before every file was checked.");
    }
    if outcome.more {
        text.push_str(" The folder holds more files than were checked; the rest are not listed.");
    }
    match (&outcome.report, &outcome.report_error) {
        (Some(path), None) if outcome.report_whole => {
            text.push_str(&format!("\nThe report is in {}.", path.display()))
        }
        (Some(path), why) => text.push_str(&format!(
            "\n{} could not be written in full{}; it lacks its last line, \"{}\".",
            path.display(),
            why.as_ref().map(|w| format!(" ({w})")).unwrap_or_default(),
            verify::END
        )),
        (None, why) => text.push_str(&format!(
            "\nThe report could not be made{}.",
            why.as_ref().map(|w| format!(" ({w})")).unwrap_or_default()
        )),
    }
    let tone = if outcome.report_error.is_some() || outcome.report.is_none() || damaged > 0 {
        Tone::Warn
    } else if unchecked > 0 || stopped {
        Tone::Neutral
    } else {
        Tone::Ok
    };
    (text, tone)
}

/// A row as screen readers hear it.
fn row_text(row: &Row) -> String {
    format!(
        "{}: {}, {}",
        row.checked.verdict.label(),
        row.path.display(),
        row.checked.reason
    )
}

impl VerifyView {
    pub fn new(source_disk: diagnostics::recovery::dest::Protected) -> Self {
        Self {
            source_disk,
            folder: None,
            running: None,
            outcome: None,
            notice: None,
            controls: None,
            shown_rows: 0,
            area: (0, 0, 96),
            natural: None,
        }
    }

    fn start(&mut self) {
        let Some(folder) = self.folder.clone() else {
            return;
        };
        let options = Options {
            source_disk: self.source_disk.clone(),
            ..Options::new(folder)
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, result) = mpsc::channel();
        let (event_sender, events) = mpsc::channel();
        let s = stop.clone();
        let worker = thread::spawn(move || {
            let mut send = |e: &Event| {
                let _ = event_sender.send(e.clone());
            };
            let outcome = verify::run(&options, &mut send, &s);
            let _ = sender.send(outcome);
        });
        self.outcome = None;
        self.notice = None;
        self.shown_rows = usize::MAX;
        self.running = Some(Running {
            stop,
            events,
            last: Event::default(),
            result,
            worker: Some(worker),
        });
    }

    fn status_text(&self) -> (String, Tone) {
        if let Some(run) = &self.running {
            let mut text = running_text(&run.last);
            if let Some(current) = &run.last.current {
                text.push_str(&format!("\n{}", current.display()));
            }
            return (text, Tone::Neutral);
        }
        if let Some(notice) = &self.notice {
            return notice.clone();
        }
        (
            "Choose a folder of recovered or copied files. Every file in it is checked by its contents: pictures, documents, videos and archives are walked from start to end, and their checksums tested where they have them. Nothing in the folder is changed; a report is added to it.".into(),
            Tone::Neutral,
        )
    }

    fn render(&mut self) {
        let (status, tone) = self.status_text();
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_text(
            c.subtitle,
            &match &self.folder {
                Some(folder) => folder.display().to_string(),
                None => "No folder chosen".into(),
            },
        );
        ui::set_text(c.status, &status);
        ui::set_tone(c.status, tone);
        let running = self.running.is_some();
        let (caption, enabled) = match &self.running {
            Some(run) if run.stop.load(Ordering::Relaxed) => ("Stopping…", false),
            Some(_) => ("Stop", true),
            None => ("Check", self.folder.is_some()),
        };
        ui::set_text(c.action, caption);
        ui::enable(c.action, enabled);
        ui::enable(c.choose, !running);
        ui::show(c.bar, running);
        if let Some(run) = &self.running {
            let e = &run.last;
            let permille = e.bytes_done.saturating_mul(1000) / e.bytes_total.max(1);
            ui::set_value(c.bar, permille as u32);
        }
        let report = self.outcome.as_ref().and_then(|o| o.report.as_ref());
        ui::enable(c.report, report.is_some());
        ui::enable(
            c.show,
            self.outcome.is_some() && toolwin::selected(c.list).is_some(),
        );
        let rows = self.outcome.as_ref().map_or(0, |o| o.rows.len());
        if rows != self.shown_rows {
            let texts: Vec<String> = self
                .outcome
                .as_ref()
                .map(|o| o.rows.iter().map(row_text).collect())
                .unwrap_or_default();
            toolwin::set_items(c.list, &texts, false);
            self.shown_rows = rows;
        }
        toolwin::set_empty(
            c.list,
            match (&self.running, &self.outcome) {
                (Some(_), _) => "Each file is listed here when the check ends.",
                (None, Some(_)) => "The folder held no files to check.",
                (None, None) => "Each file is listed here after the check: good, damaged or not checked, with the reason.",
            },
        );
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    fn selected_row(&self) -> Option<&Row> {
        let c = self.controls.as_ref()?;
        let index = toolwin::selected(c.list)?;
        self.outcome.as_ref()?.rows.get(index)
    }
}

impl Page for VerifyView {
    fn title(&self) -> String {
        "Check recovered files".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::CHECK_FILES)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((880, 660), (620, 480))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let controls = Controls {
            title: text(Kind::Title, "Check recovered files"),
            subtitle: text(Kind::Muted, ""),
            choose: ui::button(hwnd, CHOOSE, Kind::Secondary, "Choose folder…"),
            action: ui::button(hwnd, ACTION, Kind::Primary, "Check"),
            bar: text(Kind::Progress, ""),
            status: text(Kind::Body, ""),
            list: toolwin::list(hwnd, LIST, 30),
            report: ui::button(hwnd, REPORT, Kind::Secondary, "Open report"),
            show: ui::button(hwnd, SHOW, Kind::Secondary, "Show file"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        ui::set_font(controls.list, ui::fonts(ui::dpi_of(hwnd)).body);
        self.controls = Some(controls);
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        f.header(c.title, c.subtitle);
        f.space(2);
        f.buttons(&[c.choose, c.action], 12);
        if ui::visible(c.bar) {
            f.block(c.bar, f.s(4));
            f.space(6);
        }
        f.text(c.status, 12);
        // The list takes what is left above the footer.
        let pad = f.s(6);
        let footer = toolwin::footer_h(dpi);
        self.natural = Some(f.y + f.s(30) * 10 + 2 * pad + footer);
        let list = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: (h - footer - f.y).max(f.s(80)),
        };
        ui::place(
            c.list,
            Rect {
                x: list.x + pad,
                y: list.y + pad,
                w: list.w - 2 * pad,
                h: list.h - 2 * pad,
            },
        );
        toolwin::footer(w, h, dpi, &[c.report, c.show], &[c.close]);
        ui::set_cards(hwnd, vec![list]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        match id {
            CHOOSE => {
                if let Some(folder) =
                    toolwin::pick_folder(hwnd, "Choose the folder of recovered or copied files")
                {
                    self.folder = Some(folder);
                    self.outcome = None;
                    self.notice = None;
                }
            }
            ACTION => match &self.running {
                Some(run) => run.stop.store(true, Ordering::Relaxed),
                None => {
                    // The report is written into the folder: a doubt about its disk is asked.
                    let checked = match self.folder.clone() {
                        Some(folder) => {
                            toolwin::confirm_destination(hwnd, &folder, &mut self.source_disk)
                        }
                        None => Ok(()),
                    };
                    match checked {
                        Ok(()) => self.start(),
                        Err(why) => self.notice = Some((format!("{why}."), Tone::Warn)),
                    }
                }
            },
            REPORT => {
                if let Some(path) = self.outcome.as_ref().and_then(|o| o.report.clone()) {
                    if !toolwin::open_path(hwnd, &path) {
                        self.notice =
                            Some(("Windows could not open the report.".into(), Tone::Warn));
                    }
                }
            }
            SHOW => {
                if let Some(path) = self.selected_row().map(|r| r.path.clone()) {
                    if let Some(folder) = &self.folder {
                        toolwin::reveal(hwnd, &folder.join(path));
                    }
                }
            }
            LIST if code == toolwin::ACTIVATE => {
                if let (Some(path), Some(folder)) =
                    (self.selected_row().map(|r| r.path.clone()), &self.folder)
                {
                    toolwin::reveal(hwnd, &folder.join(path));
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
        if let Some(run) = &mut self.running {
            while let Ok(e) = run.events.try_recv() {
                run.last = e;
            }
        }
        let done = self
            .running
            .as_ref()
            .and_then(|run| toolwin::poll_result(&run.result));
        if let Some(Err(why)) = done {
            let worker = self.running.take().and_then(|mut run| run.worker.take());
            self.notice = Some((toolwin::without_result(why, worker), Tone::Warn));
        } else if let Some(Ok(result)) = done {
            if let Some(mut run) = self.running.take() {
                if let Some(worker) = run.worker.take() {
                    let _ = worker.join();
                }
            }
            match result {
                Ok(outcome) => {
                    self.notice = Some(finished_notice(&outcome));
                    self.outcome = Some(outcome);
                }
                Err(why) => self.notice = Some((format!("Nothing was checked: {why}"), Tone::Warn)),
            }
        }
        self.render();
        self.relayout(hwnd);
    }

    fn draw_item(&self, _list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
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
        let Some(row) = self.outcome.as_ref().and_then(|o| o.rows.get(index)) else {
            return;
        };
        let line = |left: i32, right: i32| RECT {
            left,
            top: rect.top,
            right,
            bottom: rect.bottom,
        };
        let one = DT_SINGLELINE | DT_VCENTER | DT_LEFT;
        let (label, ink) = match row.checked.verdict {
            Verdict::Damaged => ("Damaged", colors.serious),
            Verdict::NotChecked => ("Not checked", colors.muted),
            Verdict::Good => ("Good", colors.ok),
        };
        let left = rect.left + s(8);
        let label_w = s(96);
        ui::draw_text(dc, label, &line(left, left + label_w), fonts.body, ink, one);
        let path_left = left + label_w + s(8);
        let path_w = ((rect.right - path_left) * 2 / 5).max(s(120));
        ui::draw_text(
            dc,
            &row.path.display().to_string(),
            &line(path_left, path_left + path_w),
            fonts.body,
            colors.text,
            one | DT_PATH_ELLIPSIS,
        );
        let reason_left = path_left + path_w + s(12);
        if reason_left < rect.right - s(8) {
            let kind = if row.checked.kind.is_empty() {
                String::new()
            } else {
                format!("{}: ", row.checked.kind)
            };
            ui::draw_text(
                dc,
                &format!("{kind}{}", row.checked.reason),
                &line(reason_left, rect.right - s(8)),
                fonts.body,
                colors.muted,
                one | DT_END_ELLIPSIS,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::recovery::verify::Checked;

    fn row(verdict: Verdict) -> Row {
        Row {
            path: PathBuf::from("a.jpg"),
            size: 1,
            checked: Checked {
                verdict,
                kind: "JPEG image",
                reason: String::new(),
            },
        }
    }

    /// The guard: a check whose report could not be written says so, as a warning, even
    /// when every file is good.
    #[test]
    fn a_report_not_written_in_full_is_shown_as_such() {
        let mut outcome = Outcome {
            rows: vec![row(Verdict::Good)],
            good: 1,
            report: Some(PathBuf::from(r"X:\Recovered\File check report.txt")),
            report_whole: true,
            ..Outcome::default()
        };
        assert_eq!(finished_notice(&outcome).1, Tone::Ok);
        outcome.report_error = Some("the disk is full".into());
        outcome.report_whole = false;
        let (text, tone) = finished_notice(&outcome);
        assert_eq!(tone, Tone::Warn);
        assert!(
            text.contains("could not be written in full (the disk is full)"),
            "{text}"
        );
        outcome.report_error = None;
        outcome.report_whole = true;
        outcome.rows.push(row(Verdict::Damaged));
        outcome.damaged = 1;
        let (text, tone) = finished_notice(&outcome);
        assert_eq!(tone, Tone::Warn);
        assert!(
            text.starts_with("2 files: 1 good, 1 damaged, 0 not checked."),
            "{text}"
        );
    }

    #[test]
    fn the_running_line_lists_then_counts() {
        let mut e = Event {
            phase: Some(Phase::Listing),
            files_total: 3,
            ..Event::default()
        };
        assert_eq!(running_text(&e), "Listing the folder: 3 files found so far");
        e.phase = Some(Phase::Checking);
        e.files_done = 1;
        e.damaged = 1;
        assert!(running_text(&e).starts_with("Checked 1 of 3 files"));
    }
}
