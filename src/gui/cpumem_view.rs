//! The processor and memory window, opened from the CPU and memory row: the details engine's
//! result as Processor, Memory and Board tabs, and live CPU and memory graphs fed by the
//! sampler engine. Both engines live in `tools::cpu_memory`; this window only builds their
//! options, takes their events and draws.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use diagnostics::clock;
use diagnostics::tools::cpu_memory::details::{self, Line, Section};
use diagnostics::tools::cpu_memory::monitor::{self, Event, History, MonitorOptions, Sample};
use diagnostics::tools::cpu_memory::{Details, DetailsOptions};
use diagnostics::tools::drives::details::{decimal_size, grouped};
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    ScreenToClient, DT_END_ELLIPSIS, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetParent, PostMessageW, WM_CLOSE, WM_MOUSEMOVE,
};

use crate::graph::{self, Look, Part};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

pub const KEY: &str = "cpu-memory";
pub const TITLE: &str = "Processor and memory";

const TAB_PROCESSOR: usize = 10;
const TAB_MEMORY: usize = 11;
const TAB_BOARD: usize = 12;
const TAB_CPU: usize = 13;
const TAB_MEM_GRAPH: usize = 14;
const ACTION: usize = 15;
const RANGE: usize = 16;
const VIEW: usize = 17;
const REREAD: usize = 18;
const CLOSE: usize = 19;
const LIST: usize = 20;
const GRAPH: usize = 21;
const BAR: usize = 22;
const TILES: usize = 8;

/// The graph windows, in seconds.
const RANGES: [usize; 3] = [60, 300, 1800];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Processor,
    Memory,
    Board,
    Cpu,
    MemoryGraph,
}

impl Tab {
    const ALL: [(Tab, usize, &'static str); 5] = [
        (Tab::Processor, TAB_PROCESSOR, "Processor"),
        (Tab::Memory, TAB_MEMORY, "Memory"),
        (Tab::Board, TAB_BOARD, "Board"),
        (Tab::Cpu, TAB_CPU, "CPU graph"),
        (Tab::MemoryGraph, TAB_MEM_GRAPH, "Memory graph"),
    ];

    fn section(self) -> Option<Section> {
        match self {
            Tab::Processor => Some(Section::Processor),
            Tab::Memory => Some(Section::Memory),
            Tab::Board => Some(Section::Board),
            Tab::Cpu | Tab::MemoryGraph => None,
        }
    }

    /// The tab a demo argument names; the demo is in debug builds only.
    #[cfg(any(debug_assertions, test))]
    pub fn named(name: &str) -> Option<Tab> {
        match name {
            "processor" => Some(Tab::Processor),
            "memory" => Some(Tab::Memory),
            "board" => Some(Tab::Board),
            "cpu" => Some(Tab::Cpu),
            "memory-graph" => Some(Tab::MemoryGraph),
            _ => None,
        }
    }
}

pub fn available() -> bool {
    true
}

/// Opens the window beside `owner`.
pub fn open(owner: HWND) {
    toolwin::open(owner, KEY, || {
        Box::new(CpuMemView::new(Tab::Processor, false))
    });
}

/// Debug builds only: the window on its own at a chosen tab, for screenshots.
#[cfg(debug_assertions)]
pub fn demo(args: &[String]) {
    let tab = args
        .first()
        .and_then(|a| Tab::named(a))
        .unwrap_or(Tab::Processor);
    let per = args.iter().any(|a| a == "per-processor");
    toolwin::open(std::ptr::null_mut(), KEY, || {
        Box::new(CpuMemView::new(tab, per))
    });
    toolwin::end_process_with(KEY);
    if let Some(window) = toolwin::window_of(KEY) {
        crate::message_loop(window);
    }
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    tabs: Vec<(Tab, HWND)>,
    list: HWND,
    graph: HWND,
    bar: HWND,
    tiles: Vec<HWND>,
    status: HWND,
    action: HWND,
    range: HWND,
    view: HWND,
    reread: HWND,
    close: HWND,
}

enum Load {
    Reading(mpsc::Receiver<Details>),
    Ready(Box<Details>),
}

struct Sampler {
    cancel: Arc<AtomicBool>,
    events: mpsc::Receiver<Event>,
}

pub struct CpuMemView {
    controls: Option<Controls>,
    load: Load,
    tab: Tab,
    lines: Vec<Line>,
    sampler: Sampler,
    history: History,
    /// The history as it was when Pause was pressed; the graphs show it until Resume.
    frozen: Option<History>,
    processors: u32,
    base_mhz: Option<f64>,
    unavailable: Vec<String>,
    range: usize,
    per_processor: bool,
    /// The pointer over the graph canvas, in the canvas's own pixels.
    hover: Option<(i32, i32)>,
    /// Where the graph canvas sits in the window.
    graph_at: Rect,
    notice: Option<String>,
    area: (i32, i32, u32),
}

impl Drop for CpuMemView {
    fn drop(&mut self) {
        self.sampler.cancel.store(true, Ordering::Relaxed);
    }
}

fn read_details() -> mpsc::Receiver<Details> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let found = details::details(&DetailsOptions {
            serials: true,
            ..DetailsOptions::default()
        });
        let _ = sender.send(found);
    });
    receiver
}

fn start_sampler() -> Sampler {
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, events) = mpsc::channel();
    let stop = cancel.clone();
    thread::spawn(move || {
        let _ = monitor::run(
            &MonitorOptions::default(),
            &mut |event| {
                let _ = sender.send(event);
            },
            &stop,
        );
    });
    Sampler { cancel, events }
}

fn ghz(mhz: f64) -> String {
    format!("{:.2} GHz", mhz / 1000.0)
}

fn bytes(v: u64) -> String {
    decimal_size(u128::from(v))
}

fn uptime_text(seconds: u64) -> String {
    let (d, h, m, s) = (
        seconds / 86_400,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
    );
    if d > 0 {
        format!("{d} d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

fn range_caption(seconds: usize) -> String {
    if seconds < 120 {
        format!("Last {seconds} s")
    } else {
        format!("Last {} min", seconds / 60)
    }
}

fn range_words(seconds: usize) -> String {
    if seconds < 120 {
        format!("{seconds} seconds ago")
    } else {
        format!("{} minutes ago", seconds / 60)
    }
}

fn time_of(sample: &Sample) -> String {
    clock::local(UNIX_EPOCH + Duration::from_millis(sample.unix_ms)).time()
}

/// "67.9 of 91.9 GB": a part and its whole, the unit said once when both share it.
fn share_of(part: u64, whole: u64) -> String {
    let (a, b) = (bytes(part), bytes(whole));
    match (a.rsplit_once(' '), b.rsplit_once(' ')) {
        (Some((x, ua)), Some((_, ub))) if ua == ub => format!("{x} of {b}"),
        _ => format!("{a} of {b}"),
    }
}

/// The widest values each tile can realistically hold, so the grid leaves room for them
/// before they arrive and does not reflow as the values change.
fn widest_tiles(tab: Tab) -> Vec<(String, String)> {
    let big = 999_900_000_000;
    let pair = |label: &str, value: String| (label.to_string(), value);
    match tab {
        Tab::Cpu => vec![
            pair("Use", percent(100.0)),
            pair("Speed now", ghz(10_000.0)),
            pair("Base speed", ghz(10_000.0)),
            pair("Maximum speed", ghz(10_000.0)),
            pair("Processes", grouped(99_999)),
            pair("Threads", grouped(999_999)),
            pair("Handles", grouped(9_999_999)),
            pair("Up time", uptime_text(999 * 86_400 + 86_399)),
            pair("Use", "not read".into()),
        ],
        Tab::MemoryGraph => vec![
            pair("In use", format!("{} ({:.0} %)", bytes(big), 100.0)),
            pair("Available", bytes(big)),
            pair("Committed", share_of(big, big)),
            pair("Committed", share_of(big, 1_999_900_000_000)),
            pair("Committed", share_of(999_900_000, 99_900_000_000)),
            pair("Cached", bytes(big)),
            pair("Paged pool", bytes(big)),
            pair("Non-paged pool", bytes(big)),
            pair("Cached", "not read".into()),
        ],
        _ => Vec::new(),
    }
}

/// The narrowest a tile can be and still show every label and value whole: the tile's
/// padding (see ui.rs's Tile painting) around the widest text in the tile's own fonts.
fn tile_min_width(dpi: u32, tiles: &[(String, String)]) -> i32 {
    let s = |v: i32| scale(dpi, v);
    let fonts = ui::fonts(dpi);
    let pad = s(12);
    let none = std::ptr::null_mut();
    tiles
        .iter()
        .map(|(label, value)| {
            let label_w = ui::text_width(none, fonts.caption, label) + 2 * pad + s(10);
            let value_w = ui::text_width(none, fonts.strong, value) + 2 * pad;
            label_w.max(value_w) + 1
        })
        .max()
        .unwrap_or(0)
}

/// The tile grid's columns and tile width in `width`: the most columns that leave every row
/// full and every tile at least `min_w` wide, else one column.
fn tile_grid(count: i32, width: i32, gap: i32, min_w: i32) -> (i32, i32) {
    let tile_w = |columns: i32| (width - (columns - 1) * gap) / columns;
    let columns = (1..=count.max(1))
        .rev()
        .find(|c| count % c == 0 && tile_w(*c) >= min_w)
        .unwrap_or(1);
    (columns, tile_w(columns))
}

fn percent(v: f64) -> String {
    format!("{v:.0} %")
}

/// Memory in use as a share of the total, 0 to 100.
fn in_use_percent(s: &Sample) -> Option<f64> {
    let m = s.memory?;
    (m.total_bytes > 0).then(|| m.in_use_bytes as f64 / m.total_bytes as f64 * 100.0)
}

impl CpuMemView {
    pub fn new(tab: Tab, per_processor: bool) -> Self {
        Self::reading(
            tab,
            per_processor,
            read_details(),
            start_sampler(),
            monitor::logical_processors(),
        )
    }

    /// The window at `tab` as if the details engine had given `found` and the sampler
    /// `events`, reading nothing itself: for the screenshot mode.
    #[cfg(debug_assertions)]
    pub fn read_as(tab: Tab, found: Details, events: Vec<Event>) -> Self {
        let (sender, load) = mpsc::channel();
        let _ = sender.send(found);
        let (sender, sampled) = mpsc::channel();
        let mut processors = 1;
        for event in events {
            if let Event::Started {
                logical_processors, ..
            } = &event
            {
                processors = *logical_processors;
            }
            let _ = sender.send(event);
        }
        let sampler = Sampler {
            cancel: Arc::new(AtomicBool::new(false)),
            events: sampled,
        };
        Self::reading(tab, false, load, sampler, processors)
    }

    fn reading(
        tab: Tab,
        per_processor: bool,
        load: mpsc::Receiver<Details>,
        sampler: Sampler,
        processors: u32,
    ) -> Self {
        Self {
            controls: None,
            load: Load::Reading(load),
            tab,
            lines: Vec::new(),
            sampler,
            history: History::new(monitor::HISTORY),
            frozen: None,
            processors,
            base_mhz: None,
            unavailable: Vec::new(),
            range: 0,
            per_processor,
            hover: None,
            graph_at: Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            notice: None,
            area: (0, 0, 96),
        }
    }

    fn details(&self) -> Option<&Details> {
        match &self.load {
            Load::Ready(d) => Some(d),
            Load::Reading(_) => None,
        }
    }

    fn shown(&self) -> &History {
        self.frozen.as_ref().unwrap_or(&self.history)
    }

    fn slots(&self) -> usize {
        RANGES[self.range]
    }

    fn graphing(&self) -> bool {
        matches!(self.tab, Tab::Cpu | Tab::MemoryGraph)
    }

    fn fill_list(&mut self) {
        self.lines = match (self.details(), self.tab.section()) {
            (Some(d), Some(section)) => details::lines(d, section),
            _ => Vec::new(),
        };
        let texts: Vec<String> = self
            .lines
            .iter()
            .map(|l| match l {
                Line::Heading(h) => h.clone(),
                Line::Fact(name, value) => format!("{name}: {value}"),
                Line::Note(note) => note.clone(),
            })
            .collect();
        if let Some(c) = &self.controls {
            toolwin::set_items(c.list, &texts, false);
            toolwin::set_empty(
                c.list,
                if self.details().is_some() {
                    "Nothing was read for this part."
                } else {
                    "Reading the processor, memory and firmware tables…"
                },
            );
        }
    }

    fn relayout(&mut self) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            if let Some(hwnd) = self.controls.as_ref().map(|c| c.title) {
                let parent = unsafe { GetParent(hwnd) };
                self.layout(parent, w, h, dpi);
            }
        }
    }

    fn subtitle(&self) -> String {
        let Some(d) = self.details() else {
            return "Reading…".into();
        };
        let mut parts = Vec::new();
        if let Some(p) = &d.processor {
            if !p.brand.is_empty() {
                parts.push(p.brand.clone());
            }
        }
        if let Some(m) = &d.memory {
            let total = m.installed_bytes.unwrap_or(m.usable_bytes);
            parts.push(format!("{} memory", details::memory_size(total)));
        }
        parts.join("  ·  ")
    }

    fn base(&self) -> Option<f64> {
        self.details()
            .and_then(|d| d.processor.as_ref())
            .and_then(details::base_clock)
            .map(f64::from)
            .or(self.base_mhz)
    }

    fn cpu_tiles(&self) -> Vec<(String, String)> {
        let last = self.shown().last();
        let or_dash = |v: Option<String>| v.unwrap_or_else(|| "not read".into());
        let max = self
            .details()
            .and_then(|d| d.processor.as_ref())
            .and_then(details::max_clock)
            .map(|(v, _)| ghz(f64::from(v)));
        vec![
            (
                "Use".into(),
                or_dash(last.and_then(|s| s.cpu_percent).map(percent)),
            ),
            (
                "Speed now".into(),
                or_dash(last.and_then(|s| s.clock_mhz).map(ghz)),
            ),
            ("Base speed".into(), or_dash(self.base().map(ghz))),
            ("Maximum speed".into(), or_dash(max)),
            (
                "Processes".into(),
                or_dash(last.and_then(|s| s.processes).map(|v| grouped(v.into()))),
            ),
            (
                "Threads".into(),
                or_dash(last.and_then(|s| s.threads).map(|v| grouped(v.into()))),
            ),
            (
                "Handles".into(),
                or_dash(last.and_then(|s| s.handles).map(|v| grouped(v.into()))),
            ),
            (
                "Up time".into(),
                or_dash(last.and_then(|s| s.uptime_s).map(uptime_text)),
            ),
        ]
    }

    fn memory_tiles(&self) -> Vec<(String, String)> {
        let m = self.shown().last().and_then(|s| s.memory);
        let or_dash = |v: Option<String>| v.unwrap_or_else(|| "not read".into());
        vec![
            (
                "In use".into(),
                or_dash(m.map(|m| {
                    let share = m.in_use_bytes as f64 / m.total_bytes.max(1) as f64 * 100.0;
                    format!("{} ({share:.0} %)", bytes(m.in_use_bytes))
                })),
            ),
            (
                "Available".into(),
                or_dash(m.map(|m| bytes(m.available_bytes))),
            ),
            (
                "Committed".into(),
                or_dash(m.map(|m| share_of(m.committed_bytes, m.commit_limit_bytes))),
            ),
            (
                "Cached".into(),
                or_dash(m.and_then(|m| m.cached_bytes).map(bytes)),
            ),
            (
                "Paged pool".into(),
                or_dash(m.map(|m| bytes(m.paged_pool_bytes))),
            ),
            (
                "Non-paged pool".into(),
                or_dash(m.map(|m| bytes(m.nonpaged_pool_bytes))),
            ),
        ]
    }

    /// The line under a graph: the window's lowest, average and highest, and what is missing.
    fn graph_status(&self) -> String {
        let n = self.slots();
        let history = self.shown();
        let stat = match self.tab {
            Tab::Cpu => history.stat(n, |s| s.cpu_percent),
            _ => history.stat(n, in_use_percent),
        };
        let what = if self.tab == Tab::Cpu {
            "Processor use"
        } else {
            "Memory in use"
        };
        let mut text = match stat {
            Some(s) => format!(
                "{what} over the {}: lowest {}, average {}, highest {}.",
                range_caption(n).to_lowercase(),
                percent(s.min),
                percent(s.avg),
                percent(s.max)
            ),
            None => "Waiting for the first reading…".into(),
        };
        if self.frozen.is_some() {
            text.push_str(" Paused; readings continue in the background.");
        }
        for u in &self.unavailable {
            text.push_str(&format!(" Not read: {u}."));
        }
        text
    }

    fn render(&mut self) {
        let subtitle = self.subtitle();
        let graphing = self.graphing();
        let status = if graphing {
            self.graph_status()
        } else {
            self.notice.clone().unwrap_or_default()
        };
        let tiles = match self.tab {
            Tab::Cpu => self.cpu_tiles(),
            Tab::MemoryGraph => self.memory_tiles(),
            _ => Vec::new(),
        };
        let graph_name = self.graph_name();
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_text(c.subtitle, &subtitle);
        for (tab, hwnd) in &c.tabs {
            ui::set_kind(
                *hwnd,
                if *tab == self.tab {
                    Kind::Secondary
                } else {
                    Kind::Ghost
                },
            );
        }
        for (i, tile) in c.tiles.iter().enumerate() {
            match tiles.get(i) {
                Some((label, value)) => {
                    ui::set_text(*tile, &format!("{label}\n{value}"));
                    ui::set_tone(
                        *tile,
                        if value == "not read" {
                            Tone::Unavailable
                        } else {
                            Tone::Neutral
                        },
                    );
                }
                None => ui::set_text(*tile, ""),
            }
        }
        ui::set_text(c.status, &status);
        ui::set_text(c.graph, &graph_name);
        ui::set_text(
            c.action,
            if graphing {
                if self.frozen.is_some() {
                    "Resume"
                } else {
                    "Pause"
                }
            } else {
                "Copy details"
            },
        );
        ui::enable(c.action, graphing || self.details().is_some());
        ui::set_text(c.range, &range_caption(self.slots()));
        ui::set_text(
            c.view,
            if self.per_processor {
                "One graph"
            } else {
                "Per processor"
            },
        );
        ui::enable(c.reread, self.details().is_some());
    }

    /// The canvas's accessible name: what the graph shows and its value now.
    fn graph_name(&self) -> String {
        let last = self.shown().last();
        match self.tab {
            Tab::Cpu => format!(
                "Processor use graph, {}",
                last.and_then(|s| s.cpu_percent)
                    .map_or("no reading yet".into(), percent)
            ),
            Tab::MemoryGraph => format!(
                "Memory in use graph, {}",
                last.and_then(in_use_percent)
                    .map_or("no reading yet".into(), percent)
            ),
            _ => String::new(),
        }
    }

    fn copy(&mut self, hwnd: HWND) {
        if let Some(d) = self.details() {
            let text = details::copy_text(d);
            self.notice = Some(if ui::copy_to_clipboard(hwnd, &text) {
                "Copied the processor, memory and board details to the clipboard.".into()
            } else {
                "Windows did not let the details be copied.".into()
            });
        }
    }

    // ---- drawing ------------------------------------------------------------------------

    fn draw_line(&self, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        ui::fill_rect(dc, rect, colors.card);
        let Some(line) = self.lines.get(index) else {
            return;
        };
        let pad = s(8);
        let split = name_width(state.dpi);
        match line {
            Line::Heading(text) => {
                let r = RECT {
                    left: rect.left + pad,
                    top: rect.top + s(8),
                    right: rect.right - pad,
                    bottom: rect.bottom,
                };
                ui::draw_text(
                    dc,
                    text,
                    &r,
                    fonts.strong,
                    colors.text,
                    DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
                );
            }
            Line::Fact(name, value) => {
                let name_r = RECT {
                    left: rect.left + pad,
                    top: rect.top + s(4),
                    right: rect.left + split - pad,
                    bottom: rect.bottom,
                };
                ui::draw_text(
                    dc,
                    name,
                    &name_r,
                    fonts.body,
                    colors.muted,
                    DT_END_ELLIPSIS | DT_SINGLELINE,
                );
                let value_r = RECT {
                    left: rect.left + split,
                    top: rect.top + s(4),
                    right: rect.right - pad,
                    bottom: rect.bottom,
                };
                ui::draw_text(dc, value, &value_r, fonts.body, colors.text, DT_WORDBREAK);
            }
            Line::Note(text) => {
                let r = RECT {
                    left: rect.left + pad,
                    top: rect.top + s(6),
                    right: rect.right - pad,
                    bottom: rect.bottom,
                };
                ui::draw_text(dc, text, &r, fonts.caption, colors.muted, DT_WORDBREAK);
            }
        }
    }

    /// The hover label and sample index for a trace of `values` drawn in `area`.
    fn hover_for(
        &self,
        local: (i32, i32),
        area: (f32, f32, f32, f32),
        values: &[Option<f64>],
        samples: &[&Sample],
        show: impl Fn(&Sample) -> String,
    ) -> Option<(usize, String)> {
        let (x, y, w, h) = area;
        let (px, py) = (local.0 as f32, local.1 as f32);
        if py < y - 4.0 || py > y + h + 4.0 {
            return None;
        }
        let index = graph::sample_at(px, x, w, self.slots(), values.len())?;
        let sample = samples.get(index)?;
        Some((index, format!("{}   {}", time_of(sample), show(sample))))
    }

    fn draw_graph(&self, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        ui::fill_rect(dc, rect, colors.card);
        let canvas = ui::Canvas::new(dc);
        let slots = self.slots();
        let samples: Vec<&Sample> = self.shown().newest(slots).collect();
        let to = match self.frozen.as_ref().and_then(History::last) {
            Some(s) => format!("Paused at {}", time_of(s)),
            None => "Now".into(),
        };
        let from = range_words(slots);
        let dpi = state.dpi;
        if self.tab == Tab::MemoryGraph {
            let values: Vec<Option<f64>> = samples.iter().map(|s| in_use_percent(s)).collect();
            let area = graph::plot_area(rect, dpi, false);
            let hover = self.hover.and_then(|p| {
                self.hover_for(p, area, &values, &samples, |s| {
                    s.memory.map_or("not read".into(), |m| {
                        format!("{} in use", bytes(m.in_use_bytes))
                    })
                })
            });
            let total = samples
                .last()
                .and_then(|s| s.memory)
                .map_or(String::new(), |m| {
                    format!("{} usable", bytes(m.total_bytes))
                });
            graph::draw_trace(
                dc,
                canvas.as_ref(),
                rect,
                dpi,
                &colors,
                &values,
                &Look {
                    title: "Memory in use",
                    top_right: &total,
                    from: &from,
                    to: &to,
                    slots,
                    compact: false,
                    hover,
                    ink: graph::Ink::Memory,
                },
            );
            return;
        }
        if !self.per_processor {
            let values: Vec<Option<f64>> = samples.iter().map(|s| s.cpu_percent).collect();
            let area = graph::plot_area(rect, dpi, false);
            let hover = self.hover.and_then(|p| {
                self.hover_for(p, area, &values, &samples, |s| {
                    let mut text = s.cpu_percent.map_or("not read".into(), percent);
                    if let Some(clock) = s.clock_mhz {
                        text.push_str(&format!(" at {}", ghz(clock)));
                    }
                    text
                })
            });
            graph::draw_trace(
                dc,
                canvas.as_ref(),
                rect,
                dpi,
                &colors,
                &values,
                &Look {
                    title: "Processor use, all processors",
                    top_right: "100 %",
                    from: &from,
                    to: &to,
                    slots,
                    compact: false,
                    hover,
                    ink: graph::Ink::Cpu,
                },
            );
            return;
        }
        // One small graph per logical processor.
        let s = |v: i32| scale(dpi, v);
        let n = samples
            .last()
            .map_or(self.processors as usize, |l| l.per_processor_percent.len())
            .max(1);
        let foot = s(20);
        let inner = RECT {
            left: rect.left + s(6),
            top: rect.top + s(4),
            right: rect.right - s(6),
            bottom: rect.bottom - foot,
        };
        let (cols, rows) = graph::grid_shape(n, inner.right - inner.left, inner.bottom - inner.top);
        let gap = s(8);
        let cell_w = (inner.right - inner.left - gap * (cols as i32 - 1)) / cols as i32;
        let cell_h = (inner.bottom - inner.top - gap * (rows as i32 - 1)) / rows as i32;
        for p in 0..n {
            let (row, col) = (p / cols, p % cols);
            let cell = RECT {
                left: inner.left + col as i32 * (cell_w + gap),
                top: inner.top + row as i32 * (cell_h + gap),
                right: inner.left + col as i32 * (cell_w + gap) + cell_w,
                bottom: inner.top + row as i32 * (cell_h + gap) + cell_h,
            };
            let values: Vec<Option<f64>> = samples
                .iter()
                .map(|s| s.per_processor_percent.get(p).copied().flatten())
                .collect();
            let area = graph::plot_area(&cell, dpi, true);
            let inside = self.hover.filter(|(hx, hy)| {
                *hx >= cell.left && *hx < cell.right && *hy >= cell.top && *hy < cell.bottom
            });
            let hover = inside.and_then(|pt| {
                self.hover_for(pt, area, &values, &samples, |s| {
                    s.per_processor_percent
                        .get(p)
                        .copied()
                        .flatten()
                        .map_or("not read".into(), percent)
                })
            });
            let now = values
                .last()
                .copied()
                .flatten()
                .map_or(String::new(), percent);
            let title = format!("CPU {p}");
            graph::draw_trace(
                dc,
                canvas.as_ref(),
                &cell,
                dpi,
                &colors,
                &values,
                &Look {
                    title: &title,
                    top_right: &now,
                    from: "",
                    to: "",
                    slots,
                    compact: true,
                    hover,
                    ink: graph::Ink::Cpu,
                },
            );
        }
        let foot_r = RECT {
            left: inner.left + s(4),
            top: rect.bottom - foot,
            right: inner.right - s(4),
            bottom: rect.bottom - s(2),
        };
        let fonts = ui::fonts(dpi);
        let flags = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
        ui::draw_text(
            dc,
            &format!(
                "Each graph covers the {}, newest at the right",
                range_caption(slots).to_lowercase()
            ),
            &foot_r,
            fonts.caption,
            colors.subtle,
            flags,
        );
        ui::draw_text(
            dc,
            &to,
            &foot_r,
            fonts.caption,
            colors.subtle,
            flags | windows_sys::Win32::Graphics::Gdi::DT_RIGHT,
        );
    }

    fn bar_parts(&self) -> Option<(Vec<Part>, Vec<String>)> {
        let m = self.shown().last()?.memory?;
        let [in_use, modified_ink, standby_ink, free_ink] = graph::composition(&ui::current());
        let mut parts = vec![Part {
            name: "In use",
            bytes: m.in_use_bytes,
            color: in_use,
        }];
        if let (Some(modified), Some(standby), Some(free)) =
            (m.modified_bytes, m.standby_bytes, m.free_bytes)
        {
            parts.push(Part {
                name: "Modified",
                bytes: modified,
                color: modified_ink,
            });
            parts.push(Part {
                name: "Standby",
                bytes: standby,
                color: standby_ink,
            });
            parts.push(Part {
                name: "Free",
                bytes: free,
                color: free_ink,
            });
        } else {
            parts.push(Part {
                name: "Available",
                bytes: m.available_bytes,
                color: free_ink,
            });
        }
        let legend = parts
            .iter()
            .map(|p| format!("{} {}", p.name, bytes(p.bytes)))
            .collect();
        Some((parts, legend))
    }

    fn draw_bar(&self, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        ui::fill_rect(dc, rect, colors.card);
        let canvas = ui::Canvas::new(dc);
        match self.bar_parts() {
            Some((parts, legend)) => graph::draw_split_bar(
                dc,
                canvas.as_ref(),
                rect,
                state.dpi,
                &colors,
                &parts,
                &legend,
            ),
            None => {
                let r = RECT {
                    left: rect.left + scale(state.dpi, 10),
                    ..*rect
                };
                ui::draw_text(
                    dc,
                    "Waiting for the first reading…",
                    &r,
                    ui::fonts(state.dpi).caption,
                    colors.muted,
                    DT_SINGLELINE | DT_VCENTER,
                );
            }
        }
    }

    fn set_hover(&mut self, hover: Option<(i32, i32)>) {
        if hover != self.hover {
            self.hover = hover;
            if let Some(c) = &self.controls {
                toolwin::redraw(c.graph);
            }
        }
    }
}

/// The status line's height at width `w`: up to three lines, none when it is empty.
fn status_height(status: HWND, dpi: u32, w: i32) -> i32 {
    let text = ui::window_text(status);
    if text.is_empty() {
        return 0;
    }
    ui::text_height(status, ui::fonts(dpi).body, &text, w)
        .max(scale(dpi, grid::BODY_H))
        .min(scale(dpi, grid::BODY_H) * 3)
}

/// The width of a fact's name column.
fn name_width(dpi: u32) -> i32 {
    scale(dpi, 200)
}

impl Page for CpuMemView {
    fn title(&self) -> String {
        TITLE.into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((900, 740), (680, 580))
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::CPU_MEMORY)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let controls = Controls {
            title: text(Kind::Title, TITLE),
            subtitle: text(Kind::Muted, ""),
            tabs: Tab::ALL
                .iter()
                .map(|(tab, id, caption)| (*tab, ui::button(hwnd, *id, Kind::Ghost, caption)))
                .collect(),
            list: toolwin::list_wrapping(hwnd, LIST, 30),
            graph: toolwin::canvas(hwnd, GRAPH),
            bar: toolwin::canvas(hwnd, BAR),
            tiles: (0..TILES).map(|_| text(Kind::Tile, "")).collect(),
            status: text(Kind::Muted, ""),
            action: ui::button(hwnd, ACTION, Kind::Primary, "Copy details"),
            range: ui::button(hwnd, RANGE, Kind::Secondary, "Last 60 s"),
            view: ui::button(hwnd, VIEW, Kind::Secondary, "Per processor"),
            reread: ui::button(hwnd, REREAD, Kind::Secondary, "Read again"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        ui::set_font(controls.list, ui::fonts(ui::dpi_of(hwnd)).body);
        self.controls = Some(controls);
        self.fill_list();
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let tab = self.tab;
        let graphing = self.graphing();
        let tile_count = match tab {
            Tab::Cpu => 8,
            Tab::MemoryGraph => 6,
            _ => 0,
        };
        let heights = self.line_heights(dpi, w);
        let mut tile_texts = match tab {
            Tab::Cpu => self.cpu_tiles(),
            Tab::MemoryGraph => self.memory_tiles(),
            _ => Vec::new(),
        };
        tile_texts.extend(widest_tiles(tab));
        let tile_min = tile_min_width(dpi, &tile_texts);
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_font(c.list, ui::fonts(dpi).body);
        let s = |v: i32| scale(dpi, v);
        let place = |hwnd, x, y, w, h| ui::place(hwnd, Rect { x, y, w, h });
        let m = s(grid::OUTER);
        let (bh, gap) = (s(grid::BUTTON_H), s(grid::BUTTON_GAP));
        let cw = w - 2 * m;
        let mut y = s(16);
        place(c.title, m, y, cw, s(grid::TITLE_H));
        y += s(grid::TITLE_H) + s(2);
        place(c.subtitle, m, y, cw, s(grid::BODY_H));
        y += s(grid::BODY_H) + s(12);
        let mut x = m;
        for (_, hwnd) in &c.tabs {
            let bw = ui::button_width(*hwnd, &ui::window_text(*hwnd));
            place(*hwnd, x, y, bw, bh);
            x += bw + gap;
        }
        y += bh + s(12);
        // The footer and the status line above it.
        ui::show(c.range, graphing);
        ui::show(c.view, tab == Tab::Cpu);
        ui::show(c.reread, !graphing);
        let action_w = ui::button_width(c.action, "Copy details");
        let range_w = ui::button_width(c.range, "Last 30 min");
        let view_w = ui::button_width(c.view, "Per processor");
        let bottom = h - m - bh;
        place(c.action, m, bottom, action_w, bh);
        place(c.range, m + action_w + gap, bottom, range_w, bh);
        place(
            c.view,
            m + action_w + gap + range_w + gap,
            bottom,
            view_w,
            bh,
        );
        let mut rx = w - m;
        for hwnd in [c.close, c.reread] {
            if ui::visible(hwnd) {
                let bw = ui::button_width(hwnd, &ui::window_text(hwnd));
                rx -= bw;
                place(hwnd, rx, bottom, bw, bh);
                rx -= gap;
            }
        }
        let status_h = status_height(c.status, dpi, cw);
        let status_y = bottom - s(12) - status_h;
        place(c.status, m, status_y, cw, status_h);
        let content_bottom = if status_h > 0 {
            status_y - s(10)
        } else {
            bottom - s(16)
        };
        let mut cards = Vec::new();
        ui::show(c.list, !graphing);
        ui::show(c.graph, graphing);
        ui::show(c.bar, tab == Tab::MemoryGraph);
        // Tiles: the most columns that keep every row full and every value whole.
        let tile_gap = s(8);
        let tile_h = s(58);
        let (columns, tile_w) = tile_grid(tile_count, cw, tile_gap, tile_min);
        let tile_rows = if tile_count == 0 {
            0
        } else {
            (tile_count + columns - 1) / columns
        };
        let tiles_h = tile_rows * (tile_h + tile_gap);
        let tiles_y = content_bottom - tiles_h + tile_gap;
        for (i, tile) in c.tiles.iter().enumerate() {
            let shown = (i as i32) < tile_count;
            ui::show(*tile, shown);
            if shown {
                let (row, col) = (i as i32 / columns, i as i32 % columns);
                place(
                    *tile,
                    m + col * (tile_w + tile_gap),
                    tiles_y + row * (tile_h + tile_gap),
                    tile_w,
                    tile_h,
                );
            }
        }
        let mut area_bottom = if tile_count > 0 {
            tiles_y - s(12)
        } else {
            content_bottom
        };
        if tab == Tab::MemoryGraph {
            let bar_h = graph::split_bar_height(dpi, 4);
            let card = Rect {
                x: m,
                y: area_bottom - bar_h,
                w: cw,
                h: bar_h,
            };
            ui::place(
                c.bar,
                Rect {
                    x: card.x + s(6),
                    y: card.y + s(4),
                    w: card.w - s(12),
                    h: card.h - s(8),
                },
            );
            cards.push(card);
            area_bottom = card.y - s(12);
        }
        let card = Rect {
            x: m,
            y,
            w: cw,
            h: (area_bottom - y).max(s(120)),
        };
        let inner = Rect {
            x: card.x + s(6),
            y: card.y + s(6),
            w: card.w - s(12),
            h: card.h - s(12),
        };
        ui::place(c.list, inner);
        ui::place(c.graph, inner);
        self.graph_at = inner;
        cards.push(card);
        ui::set_cards(hwnd, cards);
        toolwin::set_heights(c.list, &heights);
        toolwin::redraw(c.graph);
        toolwin::redraw(c.bar);
    }

    fn command(&mut self, hwnd: HWND, id: usize, _code: u16) -> Option<Ask> {
        match id {
            TAB_PROCESSOR | TAB_MEMORY | TAB_BOARD | TAB_CPU | TAB_MEM_GRAPH => {
                if let Some((tab, _, _)) = Tab::ALL.iter().find(|(_, i, _)| *i == id) {
                    self.tab = *tab;
                    self.notice = None;
                    self.hover = None;
                    self.fill_list();
                    self.render();
                    self.relayout();
                }
            }
            ACTION if self.graphing() => {
                self.frozen = match self.frozen {
                    Some(_) => None,
                    None => Some(self.history.clone()),
                };
                if let Some(c) = &self.controls {
                    toolwin::redraw(c.graph);
                    toolwin::redraw(c.bar);
                }
            }
            ACTION => self.copy(hwnd),
            RANGE => {
                self.range = (self.range + 1) % RANGES.len();
                if let Some(c) = &self.controls {
                    toolwin::redraw(c.graph);
                }
            }
            VIEW => {
                self.per_processor = !self.per_processor;
                self.hover = None;
                if let Some(c) = &self.controls {
                    toolwin::redraw(c.graph);
                }
            }
            REREAD => {
                self.notice = None;
                self.load = Load::Reading(read_details());
                self.fill_list();
            }
            // Posted, so the window closes after this call and the page, with its sampler,
            // is dropped.
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        self.relayout_status();
        None
    }

    fn tick(&mut self, hwnd: HWND) {
        let mut changed = false;
        if let Load::Reading(receiver) = &self.load {
            if let Ok(found) = receiver.try_recv() {
                self.load = Load::Ready(Box::new(found));
                self.fill_list();
                changed = true;
            }
        }
        let mut sampled = false;
        while let Ok(event) = self.sampler.events.try_recv() {
            match event {
                Event::Started {
                    logical_processors,
                    base_mhz,
                    unavailable,
                } => {
                    self.processors = logical_processors;
                    self.base_mhz = base_mhz;
                    self.unavailable = unavailable;
                }
                Event::Sample(sample) => {
                    self.history.push(sample);
                    sampled = true;
                }
            }
        }
        // The pointer left the graph without a move over it: drop the hover line.
        if self.hover.is_some() {
            let mut point = POINT { x: 0, y: 0 };
            unsafe {
                GetCursorPos(&mut point);
                ScreenToClient(hwnd, &mut point);
            }
            let g = self.graph_at;
            if point.x < g.x || point.y < g.y || point.x >= g.x + g.w || point.y >= g.y + g.h {
                self.set_hover(None);
            }
        }
        self.render();
        if changed {
            self.relayout();
        } else {
            self.relayout_status();
        }
        if sampled && self.frozen.is_none() && self.graphing() {
            if let Some(c) = &self.controls {
                toolwin::redraw(c.graph);
                toolwin::redraw(c.bar);
            }
        }
    }

    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        match list {
            LIST => self.draw_line(index, dc, rect, state),
            GRAPH => self.draw_graph(dc, rect, state),
            BAR => self.draw_bar(dc, rect, state),
            _ => {}
        }
    }

    fn mouse(&mut self, _hwnd: HWND, msg: u32, x: i32, y: i32) -> bool {
        if msg == WM_MOUSEMOVE && self.graphing() {
            let g = self.graph_at;
            let inside = x >= g.x && y >= g.y && x < g.x + g.w && y < g.y + g.h;
            self.set_hover(inside.then_some((x - g.x, y - g.y)));
        }
        false
    }
}

impl CpuMemView {
    /// Each line's height at a client width `w`: facts and notes wrap to their column.
    fn line_heights(&self, dpi: u32, w: i32) -> Vec<i32> {
        let Some(c) = &self.controls else {
            return Vec::new();
        };
        let s = |v: i32| scale(dpi, v);
        let fonts = ui::fonts(dpi);
        // The list's width: the card inset and the scroll bar.
        let list_w = w - 2 * s(grid::OUTER) - s(12) - s(20);
        let pad = s(8);
        self.lines
            .iter()
            .map(|line| match line {
                Line::Heading(_) => s(36),
                Line::Fact(_, value) => {
                    let value_w = (list_w - name_width(dpi) - pad).max(s(60));
                    (ui::text_height(c.list, fonts.body, value, value_w) + s(10)).max(s(28))
                }
                Line::Note(text) => {
                    ui::text_height(c.list, fonts.caption, text, list_w - 2 * pad) + s(12)
                }
            })
            .collect()
    }

    /// Lays out again when the status line's height changes, so the graph keeps its room.
    fn relayout_status(&mut self) {
        let (w, _, dpi) = self.area;
        let Some(c) = &self.controls else {
            return;
        };
        if w == 0 {
            return;
        }
        let cw = w - 2 * scale(dpi, grid::OUTER);
        let want = status_height(c.status, dpi, cw);
        let mut r = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetClientRect(c.status, &mut r) };
        if r.bottom != want {
            self.relayout();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tile_value_fits_whole_at_96_and_144_dpi() {
        for dpi in [96, 144] {
            let s = |v: i32| scale(dpi, v);
            let fonts = ui::fonts(dpi);
            let pad = s(12);
            for (tab, count) in [(Tab::Cpu, 8), (Tab::MemoryGraph, 6)] {
                let widest = widest_tiles(tab);
                let min_w = tile_min_width(dpi, &widest);
                // The window's default width and its minimum.
                for width in [900, 680] {
                    let cw = s(width) - 2 * s(grid::OUTER);
                    let (columns, tile_w) = tile_grid(count, cw, s(8), min_w);
                    assert_eq!(count % columns, 0, "rows stay full");
                    for (label, value) in &widest {
                        let value_w =
                            ui::text_width(std::ptr::null_mut(), fonts.strong, value) + 2 * pad;
                        let label_w = ui::text_width(std::ptr::null_mut(), fonts.caption, label)
                            + 2 * pad
                            + s(10);
                        assert!(
                            value_w <= tile_w && label_w <= tile_w,
                            "{value:?} needs {value_w}, {label:?} needs {label_w}, tile is \
                             {tile_w} in {columns} columns at {dpi} dpi, width {width}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_tile_grid_keeps_rows_full_and_drops_columns_for_wide_values() {
        assert_eq!(tile_grid(6, 852, 8, 100), (6, 135));
        assert_eq!(tile_grid(6, 852, 8, 140), (3, 278));
        assert_eq!(tile_grid(8, 852, 8, 200), (4, 207));
        assert_eq!(tile_grid(8, 852, 8, 5000), (1, 852));
        assert_eq!(tile_grid(0, 852, 8, 100), (1, 852));
    }

    #[test]
    fn captions_name_the_window_plainly() {
        assert_eq!(range_caption(60), "Last 60 s");
        assert_eq!(range_caption(300), "Last 5 min");
        assert_eq!(range_caption(1800), "Last 30 min");
        assert_eq!(range_words(300), "5 minutes ago");
        assert_eq!(uptime_text(59), "00:00:59");
        assert_eq!(
            uptime_text(2 * 86_400 + 3 * 3600 + 4 * 60 + 5),
            "2 d 03:04:05"
        );
        assert_eq!(ghz(4681.2), "4.68 GHz");
        assert_eq!(share_of(67_900_000_000, 91_900_000_000), "67.9 of 91.9 GB");
        assert_eq!(share_of(900_000_000, 91_900_000_000), "900.0 MB of 91.9 GB");
    }

    #[test]
    fn every_demo_tab_name_opens_a_tab() {
        for (tab, _, _) in Tab::ALL {
            let name = match tab {
                Tab::Processor => "processor",
                Tab::Memory => "memory",
                Tab::Board => "board",
                Tab::Cpu => "cpu",
                Tab::MemoryGraph => "memory-graph",
            };
            assert_eq!(Tab::named(name), Some(tab));
        }
        assert_eq!(Tab::named("other"), None);
    }
}
