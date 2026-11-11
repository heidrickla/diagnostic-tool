//! The window for writing a rescue image to a replacement drive. It drives two engines in
//! `recovery::target`: `candidates` lists every disk with the reasons it may not be written,
//! and `write_image` erases and writes the chosen one from `WriteOptions`. The window builds
//! the options from what the technician picks and types (the last four characters of the
//! disk's serial number), shows the engine's events and renders its result; every guard and
//! the confirmation are checked again by the engine.
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use diagnostics::recovery::image;
use diagnostics::recovery::restore::{self, Confirm, DiskInfo, Event, ImageSummary, Layout, Step};
use diagnostics::recovery::target::{self, Candidate, WriteOptions, WriteResult};
use diagnostics::recovery::timed;
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{DT_WORDBREAK, HDC};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::dialog::{Dialog, Item, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const CHOOSE_IMAGE: usize = 10;
const REFRESH: usize = 11;
const DISKS: usize = 12;
const CONFIRM: usize = 13;
const GROW: usize = 14;
const ACTION: usize = 15;
const SHOW_REPORT: usize = 16;
const CLOSE: usize = 17;
/// Accepting the write confirmation.
const DO_WRITE: usize = 30;
/// Accepting the stop confirmation.
const DO_STOP: usize = 31;
const EN_CHANGE: u16 = 0x0300;
const LBN_SELCHANGE: u16 = 1;
/// How long listing the disks may take before it is given up.
const LIST_LIMIT: Duration = Duration::from_secs(30);

pub fn open(owner: HWND, image: Option<PathBuf>) {
    toolwin::open(owner, "write-image", || Box::new(RestoreView::new(image)));
}

type Listed = Result<Vec<Candidate>, String>;

enum Listing {
    Reading(mpsc::Receiver<Listed>),
    Ready,
    Failed(String),
}

struct Running {
    stop: Arc<AtomicBool>,
    events: mpsc::Receiver<Event>,
    result: mpsc::Receiver<WriteResult>,
    worker: Option<JoinHandle<()>>,
    disk: DiskInfo,
    step: Step,
    done: u64,
    total: u64,
    mismatches: u64,
    started: Instant,
    samples: VecDeque<(Instant, u64)>,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    about: HWND,
    choose: HWND,
    facts: HWND,
    refresh: HWND,
    list_label: HWND,
    disks: HWND,
    prompt: HWND,
    confirm: HWND,
    grow: HWND,
    phase: HWND,
    counts: HWND,
    rates: HWND,
    notice: HWND,
    action: HWND,
    report: HWND,
    close: HWND,
}

pub struct RestoreView {
    image_path: Option<PathBuf>,
    image: Option<ImageSummary>,
    listing: Listing,
    /// Each disk with every reason it may not be written, from the list engine.
    rows: Vec<Candidate>,
    selected: Option<usize>,
    typed: String,
    grow: bool,
    running: Option<Running>,
    report: Option<PathBuf>,
    notice: Option<(String, Tone)>,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

impl Drop for RestoreView {
    fn drop(&mut self) {
        // A write still going stops at its next chunk and writes its report first.
        if let Some(running) = &mut self.running {
            running.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = running.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// Runs the list engine off the window's thread, with a time limit. Without an image the
/// disks are listed with nothing to judge them against.
fn list_in_background(image: Option<PathBuf>) -> mpsc::Receiver<Listed> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let listed = match timed::in_time(LIST_LIMIT, None, move || match image {
            Some(path) => target::candidates(&path).map(|c| c.disks),
            None => {
                let listed = target::list_disks()?;
                Ok(listed
                    .iter()
                    .map(|disk| {
                        let confirm = Confirm::of(disk, &listed);
                        Candidate {
                            refusals: vec!["choose an image first".into()],
                            confirm_prompt: confirm.prompt(disk.number),
                            confirm,
                            disk: disk.clone(),
                        }
                    })
                    .collect())
            }
        }) {
            timed::Waited::Done(listed) => listed,
            _ => Err(format!(
                "Windows did not list the disks within {} s; a failing drive may be holding it up. Unplug it and refresh.",
                LIST_LIMIT.as_secs()
            )),
        };
        let _ = sender.send(listed);
    });
    receiver
}

/// The line under the image: its size, stated once, the drive it was made from and what was
/// not rescued. The drive's size is named only when it differs from the image's. With no map
/// there is nothing to say about the source or the rescue, so only that is said.
pub fn image_facts(info: &ImageSummary) -> String {
    let size = bytes_text(info.len);
    let table = match info.layout {
        Layout::Gpt(_) => "a GPT partition table",
        Layout::Mbr => "an MBR partition table",
        Layout::None => "no partition table",
    };
    if info.map.is_none() {
        return format!(
            "{size}, {table}. No map was found beside it, so every byte is written as it is in the image."
        );
    }
    let made_from = info.made_from.as_ref().map_or_else(
        || "its map does not name the drive it was made from".to_string(),
        |id| {
            let serial = if id.serial.trim().is_empty() {
                "no serial number".to_string()
            } else {
                format!("serial {}", id.serial.trim())
            };
            let size = if id.size == info.len {
                String::new()
            } else {
                format!(", a {} drive", bytes_text(id.size))
            };
            format!("made from {} ({serial}{size})", id.model.trim())
        },
    );
    let zeros = if info.not_rescued.is_empty() {
        "Every part was rescued.".to_string()
    } else {
        format!(
            "Not rescued, written as zeros: {} in {}.",
            bytes_text(info.not_rescued_bytes),
            restore::areas(info.not_rescued.len())
        )
    };
    format!("{size}, {table}, {made_from}. {zeros}")
}

impl RestoreView {
    pub fn new(image: Option<PathBuf>) -> Self {
        let mut view = Self {
            image_path: None,
            image: None,
            listing: Listing::Ready,
            rows: Vec::new(),
            selected: None,
            typed: String::new(),
            grow: false,
            running: None,
            report: None,
            notice: None,
            controls: None,
            area: (0, 0, 96),
            natural: None,
        };
        match image {
            Some(path) => view.load(path),
            None => view.listing = Listing::Reading(list_in_background(None)),
        }
        view
    }

    /// Reads what the image is, then lists the disks against it.
    fn load(&mut self, path: PathBuf) {
        match restore::load_image(&path) {
            Ok((info, _held)) => {
                self.image = Some(info.summary());
                self.image_path = Some(path);
                self.notice = None;
            }
            Err(why) => {
                self.image = None;
                self.image_path = None;
                self.notice = Some((why, Tone::Warn));
            }
        }
        self.relist();
    }

    fn relist(&mut self) {
        self.selected = None;
        self.rows.clear();
        self.show_rows();
        self.listing = Listing::Reading(list_in_background(self.image_path.clone()));
    }

    fn show_rows(&mut self) {
        let Some(c) = &self.controls else {
            return;
        };
        let texts: Vec<String> = self
            .rows
            .iter()
            .map(|row| {
                if row.refusals.is_empty() {
                    row.name_text()
                } else {
                    format!(
                        "{}. Cannot be written: {}",
                        row.name_text(),
                        row.refusals.join("; ")
                    )
                }
            })
            .collect();
        toolwin::set_items(c.disks, &texts, true);
        let keep = self.selected.filter(|i| *i < self.rows.len());
        toolwin::select(c.disks, keep);
        self.selected = keep;
    }

    /// One disk row's three parts: its name, its volumes and whether it can be written.
    fn row_lines(row: &Candidate) -> [String; 3] {
        let status = if row.refusals.is_empty() {
            "Can be written".to_string()
        } else {
            format!("Cannot be written: {}", row.refusals.join("; "))
        };
        [row.name_text(), row.disk.volumes_text(), status]
    }

    /// Each disk row's height at a list `width` pixels wide: its lines wrapped, nothing cut.
    fn row_heights(&self, list: HWND, width: i32, dpi: u32) -> Vec<i32> {
        let fonts = ui::fonts(dpi);
        let text_w = width - scale(dpi, 12 + 8);
        self.rows
            .iter()
            .map(|row| {
                let [name, volumes, status] = Self::row_lines(row);
                let h = ui::text_height(list, fonts.strong, &name, text_w)
                    + ui::text_height(list, fonts.caption, &volumes, text_w)
                    + ui::text_height(list, fonts.caption, &status, text_w);
                h + scale(dpi, 14)
            })
            .collect()
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    fn chosen(&self) -> Option<&DiskInfo> {
        let row = self.rows.get(self.selected?)?;
        row.refusals.is_empty().then_some(&row.disk)
    }

    /// Checked against the confirmation the list engine chose for the row, which knew every
    /// listed disk; the engine checks it again against the disks as they are at Start.
    fn confirmed(&self) -> bool {
        self.selected
            .and_then(|i| self.rows.get(i))
            .is_some_and(|row| row.refusals.is_empty() && row.confirm.matches(&self.typed))
    }

    fn render(&mut self) {
        let Some(c) = &self.controls else {
            return;
        };
        let running = self.running.is_some();
        ui::set_text(
            c.subtitle,
            &self.image_path.as_ref().map_or_else(
                || "No image chosen".to_string(),
                |p| p.display().to_string(),
            ),
        );
        ui::set_text(
            c.facts,
            &self.image.as_ref().map(image_facts).unwrap_or_default(),
        );
        ui::set_text(
            c.list_label,
            &match &self.listing {
                Listing::Reading(_) => "Reading the list of drives…".to_string(),
                Listing::Failed(why) => why.clone(),
                Listing::Ready => {
                    "Choose the drive to write to. Everything on it is erased.".to_string()
                }
            },
        );
        let prompt = match (self.selected.and_then(|i| self.rows.get(i)), running) {
            (_, true) => String::new(),
            (Some(row), false) if row.refusals.is_empty() => row.confirm_prompt.clone(),
            (Some(row), false) => format!(
                "Disk {} cannot be written: {}.",
                row.disk.number,
                row.refusals.join("; ")
            ),
            (None, false) => "Choose a drive in the list.".into(),
        };
        ui::set_text(c.prompt, &prompt);
        toolwin::set_empty(
            c.disks,
            match &self.listing {
                Listing::Reading(_) => "The drives appear here once they are read.",
                Listing::Failed(_) => "The drives could not be listed; Refresh list tries again.",
                Listing::Ready => "No drive was found.",
            },
        );
        ui::show(c.confirm, self.chosen().is_some() && !running);
        ui::set_text(
            c.grow,
            if self.grow {
                "Grow the last partition to fill the drive: On"
            } else {
                "Grow the last partition to fill the drive: Off"
            },
        );
        for hwnd in [c.choose, c.refresh, c.disks, c.grow, c.confirm] {
            ui::enable(hwnd, !running);
        }
        let (phase, counts, rates) = match &self.running {
            Some(run) => {
                let (done, total) = (run.done, run.total);
                let counts = match run.step {
                    Step::Writing => {
                        format!("Written {} of {}", bytes_text(done), bytes_text(total))
                    }
                    Step::Checking => format!(
                        "Checked {} of {}  ·  {} read back differently",
                        bytes_text(done),
                        bytes_text(total),
                        run.mismatches
                    ),
                    _ => String::new(),
                };
                let samples: Vec<(Instant, u64)> = run.samples.iter().copied().collect();
                let current = image::window_rate(&samples);
                let average = done as f64 / run.started.elapsed().as_secs_f64().max(0.001);
                let rate = if current > 0.0 { current } else { average };
                let rates = if matches!(run.step, Step::Writing | Step::Checking) {
                    format!(
                        "Now {}  ·  {}",
                        image::rate_text(current),
                        image::time_left_text(total.saturating_sub(done), rate)
                            .unwrap_or_else(|| "time left not known yet".into())
                    )
                } else {
                    String::new()
                };
                (
                    format!("{} on disk {}", run.step.text(), run.disk.number),
                    counts,
                    rates,
                )
            }
            None => (String::new(), String::new(), String::new()),
        };
        ui::set_text(c.phase, &phase);
        ui::set_text(c.counts, &counts);
        ui::set_text(c.rates, &rates);
        let (notice, tone) = self
            .notice
            .clone()
            .unwrap_or((String::new(), Tone::Neutral));
        ui::set_text(c.notice, &notice);
        ui::set_tone(c.notice, tone);
        let (caption, enabled) = match &self.running {
            Some(run) if run.stop.load(Ordering::Relaxed) => ("Stopping…", false),
            Some(_) => ("Stop", true),
            None => (
                "Write to this drive…",
                self.confirmed() && self.image.is_some(),
            ),
        };
        ui::set_text(c.action, caption);
        ui::enable(c.action, enabled);
        ui::enable(c.report, self.report.is_some());
    }

    fn ask_write(&mut self) -> Option<Ask> {
        if !self.confirmed() {
            return None;
        }
        let disk = self.chosen()?.clone();
        let info = self.image.as_ref()?;
        let mut items = vec![
            Item::Pair("Drive".into(), disk.text()),
            Item::Pair("Erased".into(), disk.volumes_text()),
            Item::Pair("Image".into(), info.image.display().to_string()),
            Item::Pair("Image size".into(), bytes_text(info.len)),
            Item::Pair(
                "Grow the last partition".into(),
                if self.grow { "Yes" } else { "No" }.into(),
            ),
        ];
        if !info.not_rescued.is_empty() {
            items.push(Item::Pair(
                "Not rescued".into(),
                format!(
                    "{} in {}, written as zeros",
                    bytes_text(info.not_rescued_bytes),
                    restore::areas(info.not_rescued.len())
                ),
            ));
        }
        Some(Ask {
            dialog: Dialog {
                window_title: "Write image to a replacement drive".into(),
                heading: format!("Erase disk {} and write the image to it?", disk.number),
                intro: format!(
                    "Everything on disk {} is erased and replaced by the image. This cannot be undone. The drive is read back and checked after writing, and the report is saved beside the image.",
                    disk.number
                ),
                sections: vec![Section {
                    heading: None,
                    items,
                }],
                accept: "Erase and write".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_WRITE,
        })
    }

    fn ask_stop(&self) -> Option<Ask> {
        let run = self.running.as_ref()?;
        let n = run.disk.number;
        let intro = match run.step {
            Step::Checking => "The image is written. Stopping now skips the rest of the check, so the drive is not known to hold exactly the image.".to_string(),
            Step::Growing | Step::Finishing => return None,
            _ => format!("Disk {n} is only partly written. If you stop now it has no partition table and cannot be used until it is written again."),
        };
        Some(Ask {
            dialog: Dialog {
                window_title: "Write image to a replacement drive".into(),
                heading: "Stop writing?".into(),
                intro,
                sections: Vec::new(),
                accept: "Stop".into(),
                decline: Some("Keep going".into()),
                copy: None,
            },
            then: DO_STOP,
        })
    }

    fn start(&mut self) {
        if !self.confirmed() || self.running.is_some() {
            return;
        }
        let (Some(disk), Some(image)) = (self.chosen().cloned(), self.image_path.clone()) else {
            return;
        };
        let options = WriteOptions {
            image,
            disk: disk.number,
            confirm: self.typed.clone(),
            grow: self.grow,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (event_sender, events) = mpsc::channel();
        let (sender, result) = mpsc::channel();
        let s = stop.clone();
        let worker = thread::spawn(move || {
            let sink = Box::new(move |event| {
                let _ = event_sender.send(event);
            });
            let _ = sender.send(target::write_image(&options, sink, &s));
        });
        self.running = Some(Running {
            stop,
            events,
            result,
            worker: Some(worker),
            disk,
            step: Step::Preparing,
            done: 0,
            total: 0,
            mismatches: 0,
            started: Instant::now(),
            samples: VecDeque::new(),
        });
        self.typed.clear();
        if let Some(c) = &self.controls {
            ui::set_text(c.confirm, "");
        }
        self.report = None;
        self.notice = None;
    }

    fn finished(&mut self, result: WriteResult) {
        self.report = result.report.clone();
        let tone = if result.clean() { Tone::Ok } else { Tone::Warn };
        self.notice = Some((result.summary, tone));
        // The drive's volumes changed; list them again.
        self.relist();
    }
}

impl Page for RestoreView {
    fn title(&self) -> String {
        "Write image to a replacement drive".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::WRITE_IMAGE)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((820, 880), (640, 640))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        self.controls = Some(Controls {
            title: text(Kind::Title, "Write image to a replacement drive"),
            subtitle: text(Kind::Muted, ""),
            about: text(Kind::Body, "Writes a rescue image to a new drive, so it holds what the failing drive held. The whole new drive is erased first. Parts the rescue could not read are written as zeros and listed. The drive is read back and checked after writing, and the report is saved beside the image. The drive the image came from, the drive holding the image, and the drives Windows and this program run from are never offered."),
            choose: ui::button(hwnd, CHOOSE_IMAGE, Kind::Secondary, "Choose image…"),
            facts: text(Kind::Body, ""),
            refresh: ui::button(hwnd, REFRESH, Kind::Secondary, "Refresh list"),
            list_label: text(Kind::Body, ""),
            disks: toolwin::list_wrapping(hwnd, DISKS, 64),
            prompt: text(Kind::Body, ""),
            confirm: toolwin::search_box(hwnd, CONFIRM, "Type to confirm"),
            grow: ui::button(hwnd, GROW, Kind::Secondary, ""),
            phase: text(Kind::Body, ""),
            counts: text(Kind::Body, ""),
            rates: text(Kind::Muted, ""),
            notice: text(Kind::Body, ""),
            action: ui::button(hwnd, ACTION, Kind::Primary, "Write to this drive…"),
            report: ui::button(hwnd, SHOW_REPORT, Kind::Secondary, "Show report"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        });
        self.show_rows();
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        let bh = f.s(grid::BUTTON_H);
        f.header(c.title, c.subtitle);
        f.text(c.about, 10);
        f.buttons(&[c.choose], 6);
        f.text(c.facts, 10);
        let refresh_w = ui::button_width(c.refresh, "Refresh list");
        let label_w = f.w - refresh_w - f.s(grid::BUTTON_GAP);
        let label_h = f.text_h(c.list_label, label_w).max(bh);
        ui::place(
            c.list_label,
            Rect {
                x: f.x,
                y: f.y + (label_h - f.text_h(c.list_label, label_w)) / 2,
                w: label_w,
                h: f.text_h(c.list_label, label_w),
            },
        );
        ui::place(
            c.refresh,
            Rect {
                x: f.x + f.w - refresh_w,
                y: f.y + (label_h - bh) / 2,
                w: refresh_w,
                h: bh,
            },
        );
        f.y += label_h;
        f.space(4);
        // Each disk row is as tall as its wrapped lines.
        let pad = f.s(6);
        let heights = self.row_heights(c.disks, f.w - 2 * pad, dpi);
        toolwin::set_heights(c.disks, &heights);
        let list_top = f.y;
        // Below the list: the prompt, the confirmation, Grow, the progress and the notice,
        // each only while it shows something.
        let mut below = toolwin::Flow { y: 0, ..f };
        below.space(8);
        below.y += below.text_h(c.prompt, below.w);
        if ui::visible(c.confirm) {
            below.y += below.s(4) + bh;
        }
        below.space(8);
        below.y += bh;
        below.space(10);
        for hwnd in [c.phase, c.counts, c.rates, c.notice] {
            let th = below.text_h(hwnd, below.w);
            if th > 0 {
                below.y += th + below.s(4);
            }
        }
        let below_h = below.y + toolwin::footer_h(dpi);
        // The list shows every disk, up to six, when the window opens.
        let preferred: i32 = heights.iter().take(6).sum::<i32>().max(f.s(64) * 2) + 2 * pad;
        self.natural = Some(list_top + preferred + below_h);
        let list_h = (h - below_h - list_top).max(f.s(64) * 2 + 2 * pad);
        let card = Rect {
            x: f.x,
            y: list_top,
            w: f.w,
            h: list_h,
        };
        ui::place(
            c.disks,
            Rect {
                x: f.x + pad,
                y: list_top + pad,
                w: f.w - 2 * pad,
                h: list_h - 2 * pad,
            },
        );
        f.y = list_top + list_h;
        f.space(8);
        f.text(c.prompt, 4);
        if ui::visible(c.confirm) {
            ui::place(
                c.confirm,
                Rect {
                    x: f.x,
                    y: f.y,
                    w: f.s(200),
                    h: bh,
                },
            );
            f.y += bh;
        }
        f.space(8);
        f.buttons(&[c.grow], 10);
        for hwnd in [c.phase, c.counts, c.rates, c.notice] {
            f.text(hwnd, 4);
        }
        toolwin::footer(w, h, dpi, &[c.action, c.report], &[c.close]);
        ui::set_cards(hwnd, vec![card]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            CHOOSE_IMAGE => {
                if let Some(path) = toolwin::pick_file(
                    hwnd,
                    "Choose the rescue image to write",
                    "Disk images (*.img, *.dd, *.raw, *.bin)\0*.img;*.dd;*.raw;*.bin\0All files\0*.*\0",
                ) {
                    self.load(path);
                }
            }
            REFRESH => self.relist(),
            DISKS if code == LBN_SELCHANGE || code == toolwin::ACTIVATE => {
                let picked = self
                    .controls
                    .as_ref()
                    .and_then(|c| toolwin::selected(c.disks));
                if picked != self.selected {
                    self.selected = picked;
                    self.typed.clear();
                    if let Some(c) = &self.controls {
                        ui::set_text(c.confirm, "");
                    }
                }
            }
            CONFIRM if code == EN_CHANGE => {
                if let Some(c) = &self.controls {
                    self.typed = ui::window_text(c.confirm);
                }
            }
            GROW => self.grow = !self.grow,
            ACTION => match &self.running {
                Some(_) => ask = self.ask_stop(),
                None => ask = self.ask_write(),
            },
            DO_WRITE => self.start(),
            DO_STOP => {
                if let Some(run) = &self.running {
                    run.stop.store(true, Ordering::Relaxed);
                }
            }
            SHOW_REPORT => {
                if let Some(report) = &self.report {
                    toolwin::reveal(hwnd, report);
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

    fn close_ask(&mut self) -> Option<Ask> {
        self.ask_stop()
    }

    fn tick(&mut self, hwnd: HWND) {
        if let Listing::Reading(receiver) = &self.listing {
            match receiver.try_recv() {
                Ok(Ok(rows)) => {
                    self.rows = rows;
                    self.listing = Listing::Ready;
                    self.show_rows();
                }
                Ok(Err(why)) => self.listing = Listing::Failed(why),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.listing = Listing::Failed("The drives could not be listed.".into())
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let mut finished = None;
        let mut lost = None;
        if let Some(run) = &mut self.running {
            while let Ok(event) = run.events.try_recv() {
                match event {
                    Event::Step { step, total } => {
                        run.step = step;
                        run.total = total;
                        run.done = 0;
                        run.samples.clear();
                    }
                    Event::Bytes { done, total, .. } => {
                        run.done = done;
                        run.total = total;
                    }
                    Event::Mismatch { .. } => run.mismatches += 1,
                    Event::Warning { .. } => {}
                }
            }
            run.samples.push_back((Instant::now(), run.done));
            while run
                .samples
                .front()
                .is_some_and(|(at, _)| at.elapsed() > Duration::from_secs(5))
            {
                run.samples.pop_front();
            }
            match toolwin::poll_result(&run.result) {
                Some(Ok(done)) => finished = Some(done),
                Some(Err(why)) => lost = Some(why),
                None => {}
            }
        }
        if let Some(why) = lost {
            let worker = self.running.take().and_then(|mut run| run.worker.take());
            let why = toolwin::without_result(why, worker);
            self.notice = Some((
                format!(
                    "{why} What was written to the drive is not known: treat it as unfinished \
                     and write the image again."
                ),
                Tone::Warn,
            ));
            self.relist();
        }
        if let Some(result) = finished {
            if let Some(mut run) = self.running.take() {
                if let Some(worker) = run.worker.take() {
                    let _ = worker.join();
                }
            }
            self.finished(result);
        }
        self.render();
        self.relayout(hwnd);
    }

    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        if list != DISKS {
            return;
        }
        let Some(row) = self.rows.get(index) else {
            return;
        };
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        ui::fill_rect(dc, rect, colors.card);
        if let Some(canvas) = ui::Canvas::new(dc) {
            let fill = if state.selected {
                colors.raised_hover
            } else if state.hot {
                colors.raised
            } else {
                colors.card
            };
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
        // The three parts wrap, as `row_heights` measured them.
        let ink = if row.refusals.is_empty() {
            colors.ok
        } else {
            colors.serious
        };
        let mut top = rect.top + s(7);
        let parts = Self::row_lines(row);
        let looks = [
            (fonts.strong, colors.text),
            (fonts.caption, colors.muted),
            (fonts.caption, ink),
        ];
        for (text, (font, color)) in parts.iter().zip(looks) {
            let width = rect.right - rect.left - s(12 + 8);
            let h = ui::text_height(std::ptr::null_mut(), font, text, width);
            let line = RECT {
                left: rect.left + s(12),
                top,
                right: rect.right - s(8),
                bottom: top + h,
            };
            ui::draw_text(dc, text, &line, font, color, DT_WORDBREAK);
            top += h;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_line_says_size_source_and_what_was_not_rescued() {
        let info = ImageSummary {
            image: PathBuf::from(r"D:\rescue\a.img"),
            map: Some(PathBuf::from(r"D:\rescue\a.map")),
            len: 2_000_000_000,
            layout: Layout::Gpt(512),
            made_from: None,
            not_rescued: std::iter::once(1_000_000_000..1_000_008_192).collect(),
            not_rescued_bytes: 8192,
        };
        assert_eq!(
            image_facts(&info),
            "2.0 GB, a GPT partition table, its map does not name the drive it was made from. Not rescued, written as zeros: 8.2 kB in 1 area."
        );
        // The drive's size is said once, in decimal units, and only when it differs.
        let same = ImageSummary {
            made_from: Some(restore::MadeFrom {
                model: "Msft Virtual Disk".into(),
                serial: String::new(),
                size: 2_000_000_000,
            }),
            ..info.clone()
        };
        let text = image_facts(&same);
        assert!(
            text.starts_with(
                "2.0 GB, a GPT partition table, made from Msft Virtual Disk (no serial number). "
            ),
            "{text}"
        );
        assert_eq!(text.matches("2.0 GB").count(), 1, "{text}");
        assert!(!text.contains("bytes"), "{text}");
        // With no map, the line does not speak of one in its first half and deny it in its second.
        let bare = ImageSummary {
            map: None,
            not_rescued: Default::default(),
            not_rescued_bytes: 0,
            ..info.clone()
        };
        assert_eq!(
            image_facts(&bare),
            "2.0 GB, a GPT partition table. No map was found beside it, so every byte is written as it is in the image."
        );
        let larger = ImageSummary {
            made_from: Some(restore::MadeFrom {
                model: "WDC WD5000".into(),
                serial: "WX12".into(),
                size: 500_107_862_016,
            }),
            ..info
        };
        assert!(
            image_facts(&larger).contains("made from WDC WD5000 (serial WX12, a 500.1 GB drive)."),
            "{}",
            image_facts(&larger)
        );
    }
}
