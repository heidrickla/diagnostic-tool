//! The "Copy the customer's files" window. It drives the engine in
//! `diagnostics::recovery::migrate`: builds its options, shows its events and renders its
//! plan and result. Every check (the destination's disk, the people chosen) is the
//! engine's.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use diagnostics::recovery::ledger::files;
use diagnostics::recovery::migrate::{
    self, Ended, Event, Found, MigrateResult, Options, Phase, Plan,
};
use diagnostics::recovery::SourceChoice;
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{DT_WORDBREAK, HDC};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::dialog::{Dialog, Item, Section};
use crate::rescue_copy_view::running_text;
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const DESTINATION: usize = 10;
const DAMAGED: usize = 11;
const ACTION: usize = 12;
const SHOW_REPORT: usize = 13;
const CLOSE: usize = 14;
const LINES: usize = 20;
/// Accepting the start confirmation.
const DO_START: usize = 30;

pub fn open(owner: HWND, source: SourceChoice) {
    toolwin::open(owner, "customer-files", || {
        Box::new(MigrateView::new(source))
    });
}

/// Work on the engine's thread: its events, and what it hands back at the end.
struct Work<T> {
    cancel: Arc<AtomicBool>,
    events: mpsc::Receiver<Event>,
    result: mpsc::Receiver<T>,
    worker: Option<JoinHandle<()>>,
}

impl<T: Send + 'static> Work<T> {
    fn start(f: impl FnOnce(&(dyn Fn(Event) + Sync), &AtomicBool) -> T + Send + 'static) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let (send_event, events) = mpsc::channel();
        let (send_result, result) = mpsc::channel();
        let c = cancel.clone();
        let worker = thread::spawn(move || {
            let sink = move |event: Event| {
                let _ = send_event.send(event);
            };
            let _ = send_result.send(f(&sink, &c));
        });
        Work {
            cancel,
            events,
            result,
            worker: Some(worker),
        }
    }

    fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

enum Stage {
    Finding(Work<Result<Found, String>>),
    Ready(Box<Found>),
    Copying(Work<(Box<Found>, MigrateResult)>),
    Done(Box<Found>, Box<MigrateResult>),
    Failed(String),
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    strip: crate::condition_strip::Strip,
    status: HWND,
    lines: HWND,
    destination: HWND,
    damaged: HWND,
    action: HWND,
    show_report: HWND,
    close: HWND,
}

pub struct MigrateView {
    source: SourceChoice,
    stage: Stage,
    destination: Option<PathBuf>,
    skip_damaged: bool,
    /// The last phase and progress event, for the status line.
    phase: Option<(Phase, String)>,
    progress: Option<Event>,
    /// The plan's lines, then the engine's warnings as they come.
    lines: Vec<String>,
    plan_lines: usize,
    notice: Option<(String, Tone)>,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

impl Drop for MigrateView {
    fn drop(&mut self) {
        match &mut self.stage {
            Stage::Finding(work) => work.stop(),
            Stage::Copying(work) => work.stop(),
            _ => {}
        }
    }
}

/// The lines that show what was found and what will be copied.
pub fn plan_lines(plan: &Plan) -> Vec<String> {
    let mut lines = Vec::new();
    for w in &plan.windows {
        let product = w.key_lines.first().cloned().unwrap_or_else(|| {
            format!(
                "Windows (the registry could not be read: {})",
                w.registry_error.as_deref().unwrap_or("unknown")
            )
        });
        let key = w
            .windows
            .as_ref()
            .and_then(|x| x.key.as_deref())
            .map_or("no product key recorded".to_string(), |k| {
                format!("product key {k}")
            });
        lines.push(format!("{product}, {key}  ·  {}", w.volume));
        for p in &w.people {
            let parts: Vec<&str> = p.parts.iter().map(|x| x.label.as_str()).collect();
            lines.push(format!(
                "{}: {} ({})  ·  {}",
                p.name,
                files(p.files as usize),
                bytes_text(p.bytes),
                if parts.is_empty() {
                    "nothing to copy".to_string()
                } else {
                    parts.join(", ")
                }
            ));
        }
        for s in &w.skipped {
            lines.push(format!("Not copied: {} ({})", s.name, s.why));
        }
        match &w.wifi_error {
            None => lines.push(format!(
                "Wi-Fi: {} saved {} (names only, no passwords)",
                w.wifi.len(),
                if w.wifi.len() == 1 {
                    "network"
                } else {
                    "networks"
                }
            )),
            Some(why) => lines.push(format!("Wi-Fi networks could not be read: {why}")),
        }
        for note in &w.notes {
            lines.push(format!("Note: {note}"));
        }
    }
    for note in &plan.notes {
        lines.push(format!("Note: {note}"));
    }
    lines
}

/// The notice when the engine ends: how it went and where the report is.
pub fn finished_notice(result: &MigrateResult) -> (String, Tone) {
    let how = match &result.ended {
        Ended::NotStarted(why) => return (format!("Nothing was copied: {why}"), Tone::Warn),
        Ended::Planned => "Planned".to_string(),
        Ended::Finished => "Finished".to_string(),
        Ended::Stopped => "Stopped before the end".to_string(),
        Ended::DriveGone(why) | Ended::WriteFailed(why) => format!("Ended early: {why}"),
    };
    let mut text = format!(
        "{how}. Copied {} ({}), {} damaged, {} incomplete, {} not copied.",
        files(result.copied),
        bytes_text(result.bytes),
        result.damaged,
        result.incomplete,
        result.not_copied
    );
    match (&result.report, &result.report_error) {
        (_, Some(why)) => text.push_str(&format!(
            "\nThe report could not be written in full ({why})."
        )),
        (Some(path), None) => text.push_str(&format!("\nReport: {}", path.display())),
        (None, None) => {}
    }
    if result.report_error.is_none() && !result.report_complete {
        text.push_str(&format!(
            "\nA write failed, so the report does not end with \"{}\".",
            migrate::END
        ));
    }
    let tone = if !result.report_complete {
        Tone::Warn
    } else if result.ended == Ended::Finished && result.damaged == 0 && result.incomplete == 0 {
        Tone::Ok
    } else {
        Tone::Neutral
    };
    (text, tone)
}

impl MigrateView {
    pub fn new(source: SourceChoice) -> Self {
        let options = Options {
            source: source.clone(),
            destination: None,
            people: None,
            skip_damaged: false,
        };
        Self {
            stage: Stage::Finding(Work::start(move |events, cancel| {
                migrate::find(&options, events, cancel)
            })),
            source,
            destination: None,
            skip_damaged: false,
            phase: None,
            progress: None,
            lines: Vec::new(),
            plan_lines: 0,
            notice: None,
            controls: None,
            area: (0, 0, 96),
            natural: None,
        }
    }

    fn options(&self) -> Options {
        Options {
            source: self.source.clone(),
            destination: self.destination.clone(),
            people: None,
            skip_damaged: self.skip_damaged,
        }
    }

    fn status_text(&self) -> (String, Tone) {
        match &self.stage {
            Stage::Finding(_) => {
                let (phase, about) = self
                    .phase
                    .clone()
                    .unwrap_or((Phase::Opening, self.source.label()));
                let what = match phase {
                    Phase::Opening => format!("Opening {about}"),
                    Phase::ReadingPartitions => "Reading the partition tables".into(),
                    Phase::ReadingFileTable => format!("Reading the file table of {about}"),
                    _ => format!("Reading the registry and profiles on {about}"),
                };
                let done = match &self.progress {
                    Some(Event::Reading { done, total }) if *total > 0 && phase == Phase::ReadingFileTable => {
                        format!(": {}%", done * 100 / total)
                    }
                    _ => "…".into(),
                };
                (
                    format!("Looking for Windows and the people's files. {what}{done}"),
                    Tone::Neutral,
                )
            }
            Stage::Copying(_) => match &self.progress {
                Some(Event::Copying {
                    person,
                    pass,
                    files,
                    bytes,
                    planned_bytes,
                    damaged,
                    skipped,
                    current,
                    ..
                }) => {
                    let mut text = format!(
                        "{person}: {}",
                        running_text(*pass, *files, *bytes, *damaged, *skipped)
                    );
                    if *planned_bytes > 0 {
                        text.push_str(&format!("  ·  {} planned", bytes_text(*planned_bytes)));
                    }
                    if !current.is_empty() {
                        text.push_str(&format!("\n{current}"));
                    }
                    (text, Tone::Neutral)
                }
                _ => ("Starting the copy…".into(), Tone::Neutral),
            },
            Stage::Failed(why) => (why.clone(), Tone::Warn),
            Stage::Ready(_) | Stage::Done(..) => match &self.notice {
                Some(notice) => notice.clone(),
                None => (
                    "Choose where to copy to, on another drive, then Start. The drive is only read; each person's files go into a folder of their own, with a report to hand over.".into(),
                    Tone::Neutral,
                ),
            },
        }
    }

    fn render(&mut self) {
        let (status, tone) = self.status_text();
        let Some(c) = &self.controls else {
            return;
        };
        let from = match &self.stage {
            Stage::Ready(found) | Stage::Done(found, _) => found.source.clone(),
            _ => self.source.label(),
        };
        ui::set_text(c.subtitle, &format!("From {from}"));
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
        ui::set_tone(c.status, tone);
        let ready = matches!(self.stage, Stage::Ready(_));
        ui::enable(c.destination, ready);
        ui::enable(c.damaged, ready);
        let stopping = match &self.stage {
            Stage::Finding(w) => w.cancel.load(Ordering::Relaxed),
            Stage::Copying(w) => w.cancel.load(Ordering::Relaxed),
            _ => false,
        };
        let (caption, enabled) = match &self.stage {
            Stage::Finding(_) | Stage::Copying(_) if stopping => ("Stopping…", false),
            Stage::Finding(_) | Stage::Copying(_) => ("Stop", true),
            Stage::Ready(found) => ("Start…", found.installs.iter().any(|i| !i.users.is_empty())),
            _ => ("Start…", false),
        };
        ui::set_text(c.action, caption);
        ui::enable(c.action, enabled);
        let report = matches!(&self.stage, Stage::Done(_, r) if r.report.is_some());
        ui::enable(c.show_report, report);
        toolwin::set_empty(
            c.lines,
            match &self.stage {
                Stage::Failed(_) => "Nothing was found to copy.",
                _ => "Windows on the drive, its product key and each person's folders are listed here once they are found.",
            },
        );
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    /// Each line's height at a list `width` pixels wide: its words wrapped, nothing cut.
    fn line_heights(&self, list: HWND, width: i32, dpi: u32) -> Vec<i32> {
        let body = ui::fonts(dpi).body;
        self.lines
            .iter()
            .map(|text| ui::text_height(list, body, text, width - scale(dpi, 16)) + scale(dpi, 8))
            .collect()
    }

    fn set_lines(&self) {
        if let Some(c) = &self.controls {
            toolwin::set_items(c.lines, &self.lines, true);
        }
    }

    fn ask_start(&mut self, hwnd: HWND) -> Option<Ask> {
        if !matches!(self.stage, Stage::Ready(_)) {
            return None;
        }
        if self.destination.is_none() {
            self.destination =
                toolwin::pick_folder(hwnd, "Choose a folder on another drive to copy into");
        }
        let destination = self.destination.clone()?;
        // Checked here to tell the technician at once, and a doubt put to them; the engine
        // checks again with what they confirmed.
        let Stage::Ready(found) = &mut self.stage else {
            return None;
        };
        if let Err(why) = toolwin::confirm_destination(hwnd, &destination, &mut found.source_disk) {
            self.notice = Some((why, Tone::Warn));
            return None;
        }
        let Stage::Ready(found) = &self.stage else {
            return None;
        };
        let mut items = Vec::new();
        for w in &found.plan().windows {
            for p in &w.people {
                items.push(Item::Pair(
                    p.name.clone(),
                    format!("{} ({})", files(p.files as usize), bytes_text(p.bytes)),
                ));
            }
        }
        items.push(Item::Pair(
            "Into".into(),
            destination
                .join("Customer files <date>")
                .display()
                .to_string(),
        ));
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
                window_title: "Copy the customer's files".into(),
                heading: "Copy these people's files?".into(),
                intro: "The drive is only read. Saved passwords and Wi-Fi passwords are not copied; the report says what does not carry over.".into(),
                sections: vec![Section { heading: None, items }],
                accept: "Start".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_START,
        })
    }

    fn start(&mut self) {
        if !matches!(self.stage, Stage::Ready(_)) || self.destination.is_none() {
            return;
        }
        let Stage::Ready(mut found) =
            std::mem::replace(&mut self.stage, Stage::Failed(String::new()))
        else {
            return;
        };
        let options = self.options();
        self.stage = Stage::Copying(Work::start(move |events, cancel| {
            let result = migrate::copy(&mut found, &options, events, cancel);
            (found, result)
        }));
        self.notice = None;
        self.progress = None;
        self.lines.truncate(self.plan_lines);
        self.set_lines();
    }

    /// Takes the engine's events; returns whether any warning was added.
    fn take_events(&mut self) -> bool {
        let events: Vec<Event> = match &self.stage {
            Stage::Finding(w) => w.events.try_iter().collect(),
            Stage::Copying(w) => w.events.try_iter().collect(),
            _ => return false,
        };
        let mut added = false;
        for event in events {
            match event {
                Event::Phase { phase, about } => self.phase = Some((phase, about)),
                Event::Warning { text } => {
                    self.lines.push(text);
                    added = true;
                }
                other => self.progress = Some(other),
            }
        }
        added
    }
}

impl Page for MigrateView {
    fn title(&self) -> String {
        "Copy the customer's files".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::CUSTOMER_FILES)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((800, 620), (620, 520))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let controls = Controls {
            title: text(Kind::Title, "Copy the customer's files"),
            subtitle: text(Kind::Muted, ""),
            strip: crate::condition_strip::Strip::new(
                hwnd,
                match self.source {
                    SourceChoice::Disk(number) => Some(number),
                    _ => None,
                },
            ),
            status: text(Kind::Body, ""),
            lines: toolwin::list_wrapping(hwnd, LINES, 28),
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
            action: ui::button(hwnd, ACTION, Kind::Primary, "Start…"),
            show_report: ui::button(hwnd, SHOW_REPORT, Kind::Secondary, "Show report"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        ui::set_font(controls.lines, ui::fonts(ui::dpi_of(hwnd)).body);
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
        c.strip.place(&mut f);
        f.space(2);
        f.text(c.status, 8);
        f.buttons(&[c.destination, c.damaged], 12);
        // The list takes what is left above the footer; each line wraps to its own height.
        let pad = f.s(6);
        let heights = self.line_heights(c.lines, f.w - 2 * pad, dpi);
        toolwin::set_heights(c.lines, &heights);
        let footer = toolwin::footer_h(dpi);
        let preferred = heights.iter().take(14).sum::<i32>().max(f.s(28) * 8) + 2 * pad;
        self.natural = Some(f.y + preferred + footer);
        let lines = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: (h - footer - f.y).max(f.s(80)),
        };
        ui::place(
            c.lines,
            Rect {
                x: lines.x + pad,
                y: lines.y + pad,
                w: lines.w - 2 * pad,
                h: lines.h - 2 * pad,
            },
        );
        ui::set_cards(hwnd, vec![lines]);
        toolwin::footer(w, h, dpi, &[c.action, c.show_report], &[c.close]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, _code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            DESTINATION => {
                if let Some(folder) =
                    toolwin::pick_folder(hwnd, "Choose a folder on another drive to copy into")
                {
                    let mut nothing = Default::default();
                    let disk = match &mut self.stage {
                        Stage::Ready(found) => &mut found.source_disk,
                        _ => &mut nothing,
                    };
                    match toolwin::confirm_destination(hwnd, &folder, disk) {
                        Ok(()) => {
                            self.destination = Some(folder);
                            self.notice = None;
                        }
                        Err(why) => self.notice = Some((why, Tone::Warn)),
                    }
                }
                let (w, h, dpi) = self.area;
                self.render();
                self.layout(hwnd, w, h, dpi);
            }
            DAMAGED => self.skip_damaged = !self.skip_damaged,
            ACTION => match &self.stage {
                Stage::Copying(w) => w.cancel.store(true, Ordering::Relaxed),
                Stage::Finding(w) => w.cancel.store(true, Ordering::Relaxed),
                Stage::Ready(_) => ask = self.ask_start(hwnd),
                _ => {}
            },
            DO_START => self.start(),
            SHOW_REPORT => {
                if let Stage::Done(_, result) = &self.stage {
                    if let Some(report) = &result.report {
                        toolwin::open_path(hwnd, report);
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
        ask
    }

    fn tick(&mut self, hwnd: HWND) {
        if let Some(c) = &mut self.controls {
            c.strip.refresh();
        }
        if self.take_events() {
            self.set_lines();
        }
        match &mut self.stage {
            Stage::Finding(work) => {
                if let Some(polled) = toolwin::poll_result(&work.result) {
                    let found = match polled {
                        Ok(found) => {
                            work.stop();
                            found
                        }
                        Err(why) => Err(toolwin::without_result(why, work.worker.take())),
                    };
                    match found {
                        Ok(found) => {
                            self.lines = plan_lines(&found.plan());
                            self.plan_lines = self.lines.len();
                            self.set_lines();
                            self.stage = Stage::Ready(Box::new(found));
                        }
                        Err(why) => self.stage = Stage::Failed(why),
                    }
                }
            }
            Stage::Copying(work) => {
                let polled = toolwin::poll_result(&work.result);
                if let Some(Err(why)) = polled {
                    let worker = work.worker.take();
                    let why = toolwin::without_result(why, worker);
                    self.stage = Stage::Failed(format!(
                        "{why} The files copied so far are in the folder made for them; its \
                         report may be missing."
                    ));
                } else if let Some(Ok((found, result))) = polled {
                    work.stop();
                    if self.take_events() {
                        self.set_lines();
                    }
                    self.notice = Some(finished_notice(&result));
                    self.stage = Stage::Done(found, Box::new(result));
                }
            }
            _ => {}
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
        if let Some(text) = self.lines.get(index) {
            let ink = if text.starts_with("Damaged") {
                colors.warn
            } else if index >= self.plan_lines
                || text.starts_with("Not copied")
                || text.starts_with("Note")
            {
                colors.muted
            } else {
                colors.text
            };
            let text_rect = RECT {
                top: rect.top + s(4),
                ..text_rect
            };
            ui::draw_text(dc, text, &text_rect, fonts.body, ink, DT_WORDBREAK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(ended: Ended, complete: bool) -> MigrateResult {
        MigrateResult {
            ended,
            plan: None,
            folder: None,
            report: Some(PathBuf::from(
                r"X:\Customer files\Customer files report.txt",
            )),
            report_complete: complete,
            report_error: None,
            report_ended: None,
            people: Vec::new(),
            copied: 3,
            bytes: 3000,
            damaged: 0,
            incomplete: 0,
            not_copied: 0,
        }
    }

    /// The guard: a run whose writes did not all succeed is never shown as finished well,
    /// and says its report lacks the last line.
    #[test]
    fn a_failed_write_is_shown_as_a_warning() {
        assert_eq!(finished_notice(&result(Ended::Finished, true)).1, Tone::Ok);
        let (text, tone) = finished_notice(&result(Ended::Finished, false));
        assert_eq!(tone, Tone::Warn);
        assert!(
            text.contains("does not end with \"End of report.\""),
            "{text}"
        );
        let (text, tone) = finished_notice(&result(Ended::NotStarted("no Windows".into()), false));
        assert_eq!(
            (text.as_str(), tone),
            ("Nothing was copied: no Windows", Tone::Warn)
        );
    }
}
