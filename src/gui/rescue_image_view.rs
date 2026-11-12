//! The rescue image window: copies a failing disk to an image file and a GNU ddrescue map on
//! another drive, shows rescued, bad and untried bytes with rates and time left, and draws
//! the map as blocks. Stopping keeps the map, and starting again resumes from it. Photos
//! first, the drive's read limit and Fill the gaps are engine functions (`image`,
//! `read_limit`, `fill`); this window only sets their options and shows what they say.
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use diagnostics::recovery::condition::Speed;
use diagnostics::recovery::edges::{self, EdgeEnd, EdgeOptions, EdgeResult, EdgeStatus};
use diagnostics::recovery::fill::{self, FillEnd, FillEvent, FillOptions, FillResult};
use diagnostics::recovery::image::{
    self, Cell, Ended, Map, Outcome, Plan, Progress, Settings, Status, WearRate,
};
use diagnostics::recovery::photos::PhotosFirst;
use diagnostics::recovery::place;
use diagnostics::recovery::read_limit::{QuickGiveUp, ReadLimit};
use diagnostics::recovery::timed::{self, HealthWatch, Throttle};
use diagnostics::recovery::wait::Waiter;
use diagnostics::recovery::{BlockSource, SourceChoice};
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::condition_strip::{self, Strip};
use crate::dialog::{Dialog, Item, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const FOLDER: usize = 10;
const RETRIES: usize = 11;
const ACTION: usize = 12;
const OPEN_FOLDER: usize = 13;
const CLOSE: usize = 14;
const PHOTOS: usize = 15;
const FILL: usize = 16;
const FILL_PASSES: usize = 17;
const REST: usize = 18;
const STRIP: usize = 20;
const LEGEND: usize = 40;
const COUNTS: usize = 41;
const STEPS: usize = 42;
const HEAT: usize = 21;
const COOL: usize = 22;
const ERRORS: usize = 23;
const RESUME_NOW: usize = 24;
const UNDO_FILL: usize = 25;
const EDGES: usize = 26;
/// Accepting the start confirmation.
const DO_START: usize = 30;
/// Accepting the Fill the gaps confirmation.
const DO_FILL: usize = 31;
/// Accepting the undo of Fill the gaps.
const DO_UNDO: usize = 32;
/// Accepting the edge check's confirmation.
const DO_EDGES: usize = 33;
/// The settings table's labels, row by row, two to a row; the values are the buttons.
const TABLE_LABELS: [&str; 7] = [
    "Save in",
    "Retry passes",
    "Photos first",
    "Fill passes",
    "Rest between",
    "Heat pause",
    "Error pause",
];
/// The rests offered between fill passes, in minutes.
const RESTS: [u64; 5] = [0, 1, 2, 5, 10];
/// The heat pause's thresholds offered, in degrees C; after the last, the heat pause is off.
const HEATS: [i32; 6] = [35, 38, 40, 42, 45, 50];
const COOLS: [i32; 7] = [25, 28, 30, 32, 35, 38, 40];
/// The error pause's limits offered, per 30 minutes; after the last, it is off.
const ERROR_LIMITS: [u64; 5] = [250, 500, 1000, 2000, 5000];

pub fn open(owner: HWND, disk: u32) {
    toolwin::open(owner, "rescue-image", || Box::new(ImageView::new(disk)));
}

/// Debug builds only: a run partway through, as `ImageView::mid_run` shows it.
#[cfg(debug_assertions)]
pub struct MidRun {
    /// The source's description, as an opened disk gives it.
    pub about: String,
    pub folder: PathBuf,
    /// The map as the run began, and as it is now.
    pub before: Map,
    pub map: Map,
    /// The latest health reading in words, and its figures for the condition strip.
    pub health: String,
    pub drive: Option<diagnostics::recovery::health_log::Reading>,
    /// Bytes a second over the last seconds, and on average since the run started.
    pub rate: f64,
    pub average: f64,
    pub running_for: Duration,
}

type Opened = Result<Box<dyn BlockSource>, String>;

enum Source {
    Opening(mpsc::Receiver<Opened>),
    Ready(Box<dyn BlockSource>),
    /// Lent to the running rescue.
    Busy,
    Failed(String),
}

/// How a run ended: a rescue (and what its health log says), or Fill the gaps.
enum Done {
    Rescue(Ended, Option<String>),
    Fill(FillResult),
}

/// The edge check under way (`edges::check_edges`), holding the source.
struct EdgeRun {
    stop: Arc<AtomicBool>,
    status: Arc<EdgeStatus>,
    result: mpsc::Receiver<(Box<dyn BlockSource>, EdgeResult)>,
    worker: Option<JoinHandle<()>>,
}

struct Running {
    stop: Arc<AtomicBool>,
    /// Resume now, while the drive cools.
    resume_now: Arc<AtomicBool>,
    progress: Arc<Progress>,
    /// The source back, and how the run ended.
    result: mpsc::Receiver<(Box<dyn BlockSource>, Done)>,
    /// Fill the gaps' events; None for a rescue.
    fill: Option<mpsc::Receiver<FillEvent>>,
    worker: Option<JoinHandle<()>>,
    started: Instant,
    start_rescued: u64,
    samples: VecDeque<(Instant, u64)>,
    estimate: image::Estimate,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    about: HWND,
    strip: Strip,
    labels: Vec<HWND>,
    folder: HWND,
    retries: HWND,
    photos: HWND,
    fill_passes: HWND,
    rest: HWND,
    heat: HWND,
    cool: HWND,
    errors: HWND,
    phase: HWND,
    steps: HWND,
    counts: HWND,
    rates: HWND,
    health: HWND,
    photos_line: HWND,
    limit_line: HWND,
    fill_line: HWND,
    resumed_line: HWND,
    gained_line: HWND,
    map_strip: HWND,
    legend: HWND,
    notice: HWND,
    action: HWND,
    resume_now: HWND,
    open_folder: HWND,
    fill: HWND,
    undo: HWND,
    edges: HWND,
    close: HWND,
}

pub struct ImageView {
    disk: u32,
    source: Source,
    folder: Option<PathBuf>,
    retries: u32,
    /// Photos first for the next start; on unless the technician turns it off.
    photos_first: bool,
    /// Fill the gaps' passes and rest, as the technician picked them.
    fill_passes: u32,
    rest_minutes: u64,
    /// The heat pause and the error pause for the next start.
    throttle: Throttle,
    wear_rate: WearRate,
    /// The last lines photos first, the read limit and Fill the gaps gave, and the last
    /// time a run carried on after waiting.
    photos_text: String,
    limit_text: String,
    fill_text: String,
    resumed_text: String,
    /// The notice shows the run's waiting, to be cleared when it carries on.
    notice_waiting: bool,
    /// A person was told of the run's waiting for the drive (`notify::waiting_news`).
    told_waiting: bool,
    /// The window a person was told from, whose notification-area icon goes with it.
    told_from: Option<isize>,
    plan: Option<Plan>,
    /// The map as it was before the last Fill the gaps here, for its undo.
    map_copy: Option<PathBuf>,
    /// A directed read for the next Fill the gaps, asked from the inspector.
    directed: Option<image::Directed>,
    /// The map as the last run here began, or as the newest copy kept before Fill the gaps
    /// holds it: what was recovered since is marked (manual step 27).
    before: Option<Map>,
    running: Option<Running>,
    /// The edge check under way, and the plan its confirmation showed.
    edges: Option<EdgeRun>,
    edge_plan: Option<Plan>,
    /// The map in the folder is this drive's: it names the drive, or a start here confirmed
    /// it. The edge check reads only then.
    confirmed: bool,
    /// The latest map, for the strip and the counts when nothing runs.
    map: Option<Map>,
    /// Where the running run reads, as it last said (`Progress::reading`).
    reading: Option<u64>,
    /// What the inspector shows, kept current while it is open (`inspect_view`).
    inspect: std::rc::Rc<std::cell::RefCell<crate::inspect_view::Live>>,
    image: Option<PathBuf>,
    notice: Option<(String, Tone)>,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
    /// The source's description, kept while the run holds the source.
    about: Option<String>,
}

impl Drop for ImageView {
    fn drop(&mut self) {
        if let Some(hwnd) = self.told_from {
            crate::notify::forget(hwnd as HWND);
        }
        condition_strip::speed(self.disk, None);
        if let Some(edges) = &mut self.edges {
            edges.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = edges.worker.take() {
                let _ = worker.join();
            }
        }
        // The run stops at its next read and saves the map before the window goes.
        if let Some(running) = &mut self.running {
            running.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = running.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// Which run ended, for telling a person.
enum DoneKind {
    Rescue,
    Fill,
}

/// The rate line, from the run's figures and its time left (`image::Estimate`).
pub fn rates_line(current: f64, average: f64, left: Option<String>) -> String {
    let left = left.unwrap_or_else(|| "time left not known yet".into());
    format!(
        "Now {}  ·  Average {}  ·  {left}",
        image::rate_text(current),
        image::rate_text(average)
    )
}

/// What a run's end says, built from how it ended and whether it saved a map.
pub fn outcome_text(ended: &Ended, map: Option<&Map>) -> (String, Tone) {
    let tone = match ended.outcome {
        Outcome::Finished => Tone::Ok,
        Outcome::Stopped => Tone::Neutral,
        _ => Tone::Warn,
    };
    (image::end_text(ended, map), tone)
}

/// The tone of a fill's end: a problem beside the passes (the log or the place) warns
/// even when the passes finished.
fn fill_tone(result: &FillResult) -> Tone {
    match result.end {
        FillEnd::Finished | FillEnd::NothingToDo if result.problems.is_empty() => Tone::Ok,
        FillEnd::Stopped if result.problems.is_empty() => Tone::Neutral,
        _ => Tone::Warn,
    }
}

/// The heat pause's value in the settings table: "38 C", or off.
pub fn heat_caption(throttle: &Throttle) -> String {
    if throttle.on {
        format!("{} C", throttle.pause_at)
    } else {
        "off".into()
    }
}

/// The error pause's value in the settings table: "1000 in 30 min", or off.
pub fn errors_caption(rate: &WearRate) -> String {
    if rate.on {
        format!("{} in {} min", rate.limit, rate.minutes)
    } else {
        "off".into()
    }
}

/// The next heat pause offered: each threshold in turn, then off. The carry-on threshold
/// drops below a new pause threshold when it is not below it.
pub fn next_heat(throttle: Throttle) -> Throttle {
    let next = if throttle.on {
        HEATS.iter().copied().find(|t| *t > throttle.pause_at)
    } else {
        Some(HEATS[0])
    };
    match next {
        Some(pause_at) => {
            let resume_at = if throttle.resume_at < pause_at {
                throttle.resume_at
            } else {
                COOLS
                    .iter()
                    .copied()
                    .rfind(|t| *t < pause_at)
                    .unwrap_or(COOLS[0])
            };
            Throttle {
                on: true,
                pause_at,
                resume_at,
            }
        }
        None => Throttle {
            on: false,
            ..throttle
        },
    }
}

/// The next carry-on threshold offered, each below the pause threshold in turn.
pub fn next_cool(throttle: Throttle) -> Throttle {
    let below: Vec<i32> = COOLS
        .iter()
        .copied()
        .filter(|t| *t < throttle.pause_at)
        .collect();
    let resume_at = below
        .iter()
        .copied()
        .find(|t| *t > throttle.resume_at)
        .or_else(|| below.first().copied())
        .unwrap_or(throttle.resume_at);
    Throttle {
        resume_at,
        ..throttle
    }
}

/// The next error pause offered: each limit in turn, then off.
pub fn next_errors(rate: WearRate) -> WearRate {
    let next = if rate.on {
        ERROR_LIMITS.iter().copied().find(|l| *l > rate.limit)
    } else {
        Some(ERROR_LIMITS[0])
    };
    match next {
        Some(limit) => WearRate {
            on: true,
            limit,
            ..rate
        },
        None => WearRate { on: false, ..rate },
    }
}

impl ImageView {
    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    pub fn new(disk: u32) -> Self {
        Self::with_source(
            disk,
            Source::Opening(timed::open_in_background(SourceChoice::Disk(disk))),
        )
    }

    fn with_source(disk: u32, source: Source) -> Self {
        Self {
            disk,
            source,
            folder: None,
            retries: 1,
            photos_first: true,
            fill_passes: FillOptions::default().passes,
            rest_minutes: FillOptions::default().rest_secs / 60,
            throttle: Throttle::default(),
            wear_rate: WearRate::default(),
            photos_text: String::new(),
            limit_text: String::new(),
            fill_text: String::new(),
            reading: None,
            inspect: Default::default(),
            resumed_text: String::new(),
            notice_waiting: false,
            told_waiting: false,
            told_from: None,
            plan: None,
            map_copy: None,
            before: None,
            directed: None,
            running: None,
            edges: None,
            edge_plan: None,
            confirmed: false,
            map: None,
            image: None,
            notice: None,
            controls: None,
            area: (0, 0, 96),
            natural: None,
            about: None,
        }
    }

    /// Debug builds only: the window partway through a run, from `run` alone, for the
    /// screenshots. No source is opened and no worker runs; the run's figures are fixed.
    #[cfg(debug_assertions)]
    pub fn mid_run(disk: u32, run: MidRun) -> Self {
        let mut view = Self::with_source(disk, Source::Busy);
        let now = Instant::now();
        let ago = |seconds: f64| {
            now.checked_sub(Duration::from_secs_f64(seconds))
                .unwrap_or(now)
        };
        let map = run.map;
        let rescued = map.count(Status::Rescued);
        let progress = Progress::default();
        progress.rescued.store(rescued, Ordering::Relaxed);
        progress.failed.store(map.failed(), Ordering::Relaxed);
        progress
            .untried
            .store(map.count(Status::Untried), Ordering::Relaxed);
        progress
            .non_trimmed
            .store(map.count(Status::NonTrimmed), Ordering::Relaxed);
        progress
            .non_scraped
            .store(map.count(Status::NonScraped), Ordering::Relaxed);
        progress
            .bad
            .store(map.count(Status::Bad), Ordering::Relaxed);
        progress.pos.store(map.current_pos, Ordering::Relaxed);
        if let Ok(mut health) = progress.health.lock() {
            *health = run.health;
        }
        if let Ok(mut drive) = progress.drive.lock() {
            *drive = run.drive;
        }
        if let Ok(mut reading) = progress.reading.lock() {
            *reading = Some(map.current_pos);
        }
        // The pace of the last ten minutes, as the estimate would have seen it.
        let phase = (map.phase, map.pass);
        let left = image::phase_left(&map);
        let mut estimate = image::Estimate::default();
        for seconds in [600.0, 400.0, 200.0, 0.0] {
            let done_since = (run.rate * seconds) as u64;
            estimate.observe(ago(seconds), phase, left + done_since, true);
        }
        let samples = (0..=4)
            .rev()
            .map(|s| {
                (
                    ago(f64::from(s)),
                    rescued - (run.rate * f64::from(s)) as u64,
                )
            })
            .collect();
        let running_for = run.running_for.as_secs_f64();
        if let Ok(mut state) = progress.state.lock() {
            *state = Some((map.phase, map.pass, map.clone()));
        }
        // No sender is left to drop, so the window reads the run as still going.
        let (sender, result) = mpsc::channel();
        std::mem::forget(sender);
        view.running = Some(Running {
            stop: Arc::new(AtomicBool::new(false)),
            resume_now: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(progress),
            result,
            fill: None,
            worker: None,
            started: ago(running_for),
            start_rescued: rescued.saturating_sub((run.average * running_for) as u64),
            samples,
            estimate,
        });
        view.about = Some(run.about);
        view.folder = Some(run.folder);
        view.before = Some(run.before);
        view.reading = Some(map.current_pos);
        view.map = Some(map);
        view.confirmed = true;
        view
    }

    fn describe(&self) -> String {
        match &self.source {
            Source::Ready(source) => source.describe(),
            Source::Opening(_) => format!("Disk {}: opening…", self.disk),
            // The source is with the run; its description was kept when it opened.
            Source::Busy => self
                .about
                .clone()
                .unwrap_or_else(|| format!("Disk {}", self.disk)),
            Source::Failed(why) => why.clone(),
        }
    }

    fn render(&mut self) {
        let subtitle = self.describe();
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_text(c.title, &format!("Rescue image of disk {}", self.disk));
        ui::set_text(c.subtitle, &subtitle);
        ui::set_text(
            c.folder,
            &match &self.folder {
                Some(folder) => folder.display().to_string(),
                None => "Choose where to save…".into(),
            },
        );
        ui::set_text(c.retries, &self.retries.to_string());
        ui::set_text(c.photos, if self.photos_first { "on" } else { "off" });
        ui::set_text(c.fill_passes, &self.fill_passes.to_string());
        ui::set_text(c.rest, &format!("{} min", self.rest_minutes));
        ui::set_text(c.heat, &heat_caption(&self.throttle));
        ui::set_text(
            c.cool,
            &format!("carry on at {} C", self.throttle.resume_at),
        );
        ui::show(c.cool, self.throttle.on);
        ui::set_text(c.errors, &errors_caption(&self.wear_rate));
        let running = self.running.is_some();
        let filling = self.running.as_ref().is_some_and(|run| run.fill.is_some());
        for hwnd in [
            c.folder,
            c.retries,
            c.photos,
            c.fill_passes,
            c.rest,
            c.heat,
            c.cool,
            c.errors,
        ] {
            ui::enable(hwnd, !running);
        }
        let phase = match (&self.running, &self.map) {
            (_, Some(map)) => {
                if filling {
                    "Filling the gaps".into()
                } else if running {
                    map.phase.name(map.pass)
                } else if map.phase == image::Phase::Finished {
                    "Finished".into()
                } else {
                    format!("Not running. Next: {}", map.phase.name(map.pass))
                }
            }
            (Some(_), None) => "Starting…".into(),
            (None, None) => "Not started. Choose where to save, then Start.".into(),
        };
        ui::set_text(c.phase, &phase);
        let rates = match &self.running {
            Some(run) => {
                let rescued = run.progress.rescued.load(Ordering::Relaxed);
                let current = image::window_rate(&run.samples.iter().copied().collect::<Vec<_>>());
                let elapsed = run.started.elapsed().as_secs_f64().max(0.001);
                let average = rescued.saturating_sub(run.start_rescued) as f64 / elapsed;
                rates_line(current, average, run.estimate.text(Instant::now()))
            }
            None => String::new(),
        };
        ui::set_text(c.rates, if filling { "" } else { &rates });
        if let Some(run) = &self.running {
            if let Ok(health) = run.progress.health.lock() {
                ui::set_text(c.health, &health);
            }
        }
        ui::set_text(c.photos_line, &self.photos_text);
        ui::set_text(c.limit_line, &self.limit_text);
        ui::set_text(c.fill_line, &self.fill_text);
        ui::set_text(c.resumed_line, &self.resumed_text);
        let gained = self
            .map
            .as_ref()
            .zip(self.before.as_ref())
            .and_then(|(map, before)| map.gains_text(before))
            .unwrap_or_default();
        ui::set_text(c.gained_line, &gained);
        let cooling = self
            .running
            .as_ref()
            .is_some_and(|run| Progress::read(&run.progress.cooling).is_some());
        ui::show(c.resume_now, cooling);
        let (notice, notice_tone) = self
            .notice
            .clone()
            .unwrap_or((String::new(), Tone::Neutral));
        ui::set_text(c.notice, &notice);
        ui::set_tone(c.notice, notice_tone);
        let ready = matches!(self.source, Source::Ready(_));
        let (caption, enabled) = match (&self.running, &self.map) {
            (Some(run), _) if run.stop.load(Ordering::Relaxed) => ("Stopping…", false),
            (Some(_), _) => ("Stop", true),
            (None, Some(map)) if map.phase != image::Phase::Finished => ("Resume…", ready),
            (None, _) => ("Start…", ready),
        };
        ui::set_text(c.action, caption);
        ui::enable(c.action, enabled);
        ui::enable(c.open_folder, self.image.is_some());
        // Fill the gaps is for an image whose map shows areas not read yet.
        let gaps = self
            .map
            .as_ref()
            .is_some_and(|map| map.count(Status::Rescued) < map.len());
        ui::enable(
            c.fill,
            !running && ready && gaps && self.image.is_some() && self.folder.is_some(),
        );
        ui::show(c.undo, !running && self.map_copy.is_some());
        let (caption, enabled) = self.edges_button();
        ui::set_text(c.edges, caption);
        ui::enable(c.edges, enabled);
        toolwin::redraw(c.map_strip);
        toolwin::redraw(c.counts);
        toolwin::redraw(c.steps);
    }

    /// The image and map already in the chosen folder, shown so Fill the gaps can start on
    /// them; nothing is read from the drive.
    /// The image's name in `folder`: the image this window already has there, which a
    /// drive that came back under another disk number keeps; else one from the drive.
    fn stem_in(&self, folder: &std::path::Path, source: &dyn BlockSource) -> String {
        match &self.image {
            Some(image) if image.parent() == Some(folder) => image
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_else(|| image::stem_for(&source.describe())),
            _ => image::stem_for(&source.describe()),
        }
    }

    fn look_in_folder(&mut self) {
        let (Some(folder), Source::Ready(source)) = (&self.folder, &self.source) else {
            return;
        };
        let stem = self.stem_in(folder, source.as_ref());
        // A folder whose earlier image or map cannot be read is said, not taken for a folder
        // with no earlier image.
        self.confirmed = false;
        match image::plan(source.as_ref(), folder, &stem) {
            Ok(plan) if plan.resumed => {
                self.confirmed = plan.unconfirmed.is_none();
                self.map = Some(plan.map.clone());
                self.image = Some(plan.image.clone());
                if self.before.is_none() {
                    self.before = image::latest_map_copy(&plan.map_path, &plan.map);
                }
            }
            Ok(_) => {}
            Err(why) => self.notice = Some((why, Tone::Warn)),
        }
    }

    fn ask_fill(&mut self) -> Option<Ask> {
        let folder = self.folder.clone()?;
        let Source::Ready(source) = &self.source else {
            return None;
        };
        let stem = self.stem_in(&folder, source.as_ref());
        let plan = match image::plan(source.as_ref(), &folder, &stem) {
            Ok(plan) if plan.resumed => plan,
            Ok(_) => {
                self.notice = Some((
                    "There is no image and map of this drive in that folder to fill.".into(),
                    Tone::Warn,
                ));
                return None;
            }
            Err(why) => {
                self.notice = Some((why, Tone::Warn));
                return None;
            }
        };
        let options = self.fill_options();
        let unread = plan.map.len() - plan.map.count(Status::Rescued);
        let items = vec![
            Item::Pair("Drive".into(), source.describe()),
            Item::Pair("Image".into(), plan.image.display().to_string()),
            Item::Pair("Not read yet".into(), bytes_text(unread)),
            Item::Pair("Passes".into(), options.passes.to_string()),
            Item::Pair(
                "Directed".into(),
                match &options.directed {
                    Some(directed) => {
                        let range = directed.range();
                        format!(
                            "{}: bytes {} to {} ({})",
                            directed.how(),
                            range.start,
                            range.end,
                            bytes_text(range.end - range.start)
                        )
                    }
                    None => "no: the whole drive".into(),
                },
            ),
            Item::Pair(
                "Starts at".into(),
                match place::held(&plan.image, source.as_ref()).ok().and_then(|(guard, folder)| {
                    image::fill_place_for(&guard, &folder, &plan.image, &plan.map)
                }) {
                    Some(place) if place.pass <= options.passes => match place.at {
                        Some(at) => format!(
                            "pass {}, {}, at {}: where the last run stopped",
                            place.pass,
                            if place.backwards { "backwards" } else { "forwards" },
                            bytes_text(at)
                        ),
                        None => format!("pass {}: the pass after the last run's", place.pass),
                    },
                    Some(_) => format!("pass {}, from its start", options.passes),
                    None => "pass 1".into(),
                },
            ),
            Item::Pair(
                "Rest between passes".into(),
                format!("{} min, nothing read", self.rest_minutes),
            ),
            Item::Pair(
                "Stops if".into(),
                format!(
                    "a pass recovers nothing while reallocated or pending sectors have risen by more than {}",
                    options.rise_limit
                ),
            ),
        ];
        let mut intro = "Reads every part of the drive the image does not have yet, one sector at a time and each sector once per pass, alternating direction, letting the drive try each one for up to 10 seconds. The drive's health is read after each pass. Everything that comes back goes into the image and its map at once, so Stop keeps it.".to_string();
        if let Some(why) = &plan.unconfirmed {
            intro = format!("{why} Go on only if this map was made from this drive.");
        }
        self.plan = Some(plan);
        Some(Ask {
            dialog: Dialog {
                window_title: "Fill the gaps".into(),
                heading: "Fill the gaps in the image?".into(),
                intro,
                sections: vec![Section {
                    heading: None,
                    items,
                }],
                accept: "Fill the gaps".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_FILL,
        })
    }

    /// Asks before putting back the map from before the last Fill the gaps.
    fn ask_undo(&mut self) -> Option<Ask> {
        let copy = self.map_copy.clone()?;
        let map_path = image::map_of_copy(&copy)?;
        let rescued = |path: &std::path::Path| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| image::Map::parse(&text).ok())
                .map(|map| bytes_text(map.count(Status::Rescued)))
                .unwrap_or_else(|| "unreadable".into())
        };
        let items = vec![
            Item::Pair(
                "Map from before".into(),
                copy.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            ),
            Item::Pair("Rescued then".into(), rescued(&copy)),
            Item::Pair("Rescued now".into(), rescued(&map_path)),
        ];
        Some(Ask {
            dialog: Dialog {
                window_title: "Undo Fill the gaps".into(),
                heading: "Put back the map from before Fill the gaps?".into(),
                intro: "The map goes back to what it was before the last Fill the gaps here. The map as it is now is kept beside it first, so this can be undone too. The image keeps every byte the fill read; they are only no longer marked rescued, and a later pass reads them again.".into(),
                sections: vec![Section {
                    heading: None,
                    items,
                }],
                accept: "Put it back".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_UNDO,
        })
    }

    fn undo_fill(&mut self) {
        let Some(copy) = self.map_copy.clone() else {
            return;
        };
        let Some(map_path) = image::map_of_copy(&copy) else {
            return;
        };
        if self.running.is_some() {
            return;
        }
        self.notice = Some(match image::put_back_map(&copy, &map_path) {
            Ok(kept) => {
                self.map_copy = None;
                if let Some(map) = std::fs::read_to_string(&map_path)
                    .ok()
                    .and_then(|text| image::Map::parse(&text).ok())
                {
                    self.map = Some(map);
                }
                (
                    format!(
                        "The map from before Fill the gaps is back. The map it replaced is kept as {}.",
                        kept.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    Tone::Ok,
                )
            }
            Err(why) => (why, Tone::Warn),
        });
    }

    fn fill_options(&self) -> FillOptions {
        FillOptions {
            passes: match self.directed {
                Some(image::Directed::Block { .. }) => 1,
                _ => self.fill_passes,
            },
            rest_secs: self.rest_minutes * 60,
            directed: self.directed.clone(),
            ..FillOptions::default()
        }
    }

    /// A directed read from the inspector: handed to a running Fill the gaps, or asked
    /// before one starts with it; not during a rescue's own phases.
    fn directed(&mut self, asked: image::Directed) -> Option<Ask> {
        let range = asked.range();
        let said = format!(
            "{} at {} ({})",
            asked.how(),
            bytes_text(range.start),
            bytes_text(range.end - range.start)
        );
        match &self.running {
            Some(run) if run.fill.is_some() => {
                if let Ok(mut directed) = run.progress.directed.lock() {
                    *directed = Some(asked.clone());
                }
                let then = match asked {
                    image::Directed::Block { .. } => "then the pass goes on from where it was",
                    image::Directed::From { .. } => "the pass goes on from there",
                };
                self.notice = Some((
                    format!("Fill the gaps: {said} at its next read; {then}."),
                    Tone::Neutral,
                ));
                None
            }
            Some(_) => {
                self.notice = Some((
                    format!("{said}: a directed read runs in Fill the gaps, after the rescue."),
                    Tone::Warn,
                ));
                None
            }
            None => {
                self.directed = Some(asked);
                self.ask_fill()
            }
        }
    }

    fn start_fill(&mut self) {
        let Some(mut plan) = self.plan.take() else {
            return;
        };
        // Runs only from the dialog's accept, which showed any doubt about the map.
        plan.confirm();
        self.confirmed = true;
        let Source::Ready(mut source) = std::mem::replace(&mut self.source, Source::Busy) else {
            return;
        };
        let disk = self.disk;
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let (sender, result) = mpsc::channel();
        let (tell, events) = mpsc::channel();
        let options = self.fill_options();
        let start_rescued = plan.map.count(Status::Rescued);
        self.before = Some(plan.map.clone());
        self.map = Some(plan.map.clone());
        self.image = Some(plan.image.clone());
        let resume_now = Arc::new(AtomicBool::new(false));
        let (s, p, r, throttle) = (
            stop.clone(),
            progress.clone(),
            resume_now.clone(),
            self.throttle,
        );
        let worker = thread::spawn(move || {
            let mut health = HealthWatch::for_disk(disk, s.clone()).with_throttle(throttle, r);
            let mut limit = ReadLimit::for_source(source.as_ref(), QuickGiveUp::default());
            let mut waiter = Waiter::disks();
            let done = fill::fill_gaps(
                plan,
                source.as_mut(),
                &options,
                &mut health,
                &mut limit,
                &mut waiter,
                &s,
                &p,
                &mut |event| {
                    let _ = tell.send(event);
                },
            );
            drop(limit);
            // The drive it ended with, when it came back under another number.
            let source = waiter.take_source().unwrap_or(source);
            let _ = sender.send((source, Done::Fill(done)));
        });
        self.running = Some(Running {
            stop,
            resume_now,
            progress,
            result,
            fill: Some(events),
            worker: Some(worker),
            started: Instant::now(),
            start_rescued,
            samples: VecDeque::new(),
            estimate: image::Estimate::default(),
        });
        self.fill_text = String::new();
        self.resumed_text = String::new();
        self.notice = None;
    }

    fn ask_start(&mut self, hwnd: HWND) -> Option<Ask> {
        if self.folder.is_none() {
            self.folder = toolwin::pick_folder(
                hwnd,
                "Choose a folder on another drive for the image and its map",
            );
        }
        let folder = self.folder.clone()?;
        let Source::Ready(source) = &self.source else {
            return None;
        };
        let stem = self.stem_in(&folder, source.as_ref());
        let plan = match image::plan(source.as_ref(), &folder, &stem) {
            Ok(plan) => plan,
            Err(why) => {
                self.notice = Some((why, Tone::Warn));
                return None;
            }
        };
        let rescued = plan.map.count(Status::Rescued);
        let mut items = vec![
            Item::Pair("Drive".into(), source.describe()),
            Item::Pair("Image".into(), plan.image.display().to_string()),
            Item::Pair("Map".into(), plan.map_path.display().to_string()),
            Item::Pair(
                "Health log".into(),
                diagnostics::recovery::health_log::path_for(&plan.image)
                    .display()
                    .to_string(),
            ),
            Item::Pair("Free there".into(), bytes_text(plan.free)),
            Item::Pair("Retry passes".into(), self.retries.to_string()),
        ];
        if plan.resumed {
            items.push(Item::Pair(
                "Already rescued".into(),
                format!("{} of {}", bytes_text(rescued), bytes_text(plan.map.len())),
            ));
        }
        let heading = match (&plan.unconfirmed, plan.resumed) {
            (Some(_), _) => "Resume from a map that does not name this drive?",
            (None, true) => "Resume the rescue image?",
            (None, false) => "Start a rescue image?",
        };
        let mut intro = "The drive is only read. The image is written to the folder above, and the map beside it is saved as the rescue goes, so it can be stopped at any time and resumed later, here or with GNU ddrescue.".to_string();
        if let Some(why) = &plan.unconfirmed {
            // Resuming another drive's map would keep its data marked as rescued.
            intro = format!("{why} Resume only if this map was made from this drive: blocks it marks as rescued are not read again, so another drive's map would leave that drive's data in this image.");
        }
        self.plan = Some(plan);
        Some(Ask {
            dialog: Dialog {
                window_title: "Rescue image".into(),
                heading: heading.into(),
                intro,
                sections: vec![Section {
                    heading: None,
                    items,
                }],
                accept: if heading.starts_with("Resume") {
                    "Resume".into()
                } else {
                    "Start".into()
                },
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_START,
        })
    }

    fn start(&mut self) {
        let Some(mut plan) = self.plan.take() else {
            return;
        };
        // Start runs only from the dialog's accept, which showed any doubt about the map.
        plan.confirm();
        self.confirmed = true;
        let Source::Ready(mut source) = std::mem::replace(&mut self.source, Source::Busy) else {
            return;
        };
        let disk = self.disk;
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let (sender, result) = mpsc::channel();
        let settings = Settings {
            retries: self.retries,
            photos_first: if self.photos_first {
                PhotosFirst::default()
            } else {
                PhotosFirst::off()
            },
            ..Settings::for_len(source.len())
        };
        let start_rescued = plan.map.count(Status::Rescued);
        self.before = Some(plan.map.clone());
        self.map = Some(plan.map.clone());
        self.image = Some(plan.image.clone());
        let resume_now = Arc::new(AtomicBool::new(false));
        let (s, p, r, throttle, wear_rate) = (
            stop.clone(),
            progress.clone(),
            resume_now.clone(),
            self.throttle,
            self.wear_rate,
        );
        let worker = thread::spawn(move || {
            // Every health reading is timed, and judged by the heat and error pauses.
            let mut health = HealthWatch::for_disk(disk, s.clone()).with_throttle(throttle, r);
            health.wear_rate = wear_rate;
            let mut limit = ReadLimit::for_source(source.as_ref(), QuickGiveUp::default());
            let mut waiter = Waiter::disks();
            let ended = timed::rescue(
                plan,
                source.as_mut(),
                &settings,
                &s,
                &p,
                &mut health,
                &mut limit,
                &mut waiter,
            );
            drop(limit);
            // The drive it ended with, when it came back under another number.
            let source = waiter.take_source().unwrap_or(source);
            let _ = sender.send((source, Done::Rescue(ended, health.finish_log())));
        });
        self.running = Some(Running {
            stop,
            resume_now,
            progress,
            result,
            fill: None,
            worker: Some(worker),
            started: Instant::now(),
            start_rescued,
            samples: VecDeque::new(),
            estimate: image::Estimate::default(),
        });
        self.photos_text = String::new();
        self.resumed_text = String::new();
        self.notice = None;
    }

    /// The edge check's button: its caption, and whether it can be pressed. It checks only
    /// an image whose map is this drive's, with the drive here and nothing else reading it
    /// or writing the image; while it runs, the button stops it.
    fn edges_button(&self) -> (&'static str, bool) {
        match &self.edges {
            Some(run) => ("Stop edge check", !run.stop.load(Ordering::Relaxed)),
            None => (
                "Check edges…",
                self.running.is_none()
                    && matches!(self.source, Source::Ready(_))
                    && self.confirmed
                    && self.image.is_some()
                    && self.folder.is_some(),
            ),
        }
    }

    /// Says what the edge check reads and about how long, before it starts.
    fn ask_edges(&mut self) -> Option<Ask> {
        if !self.edges_button().1 || self.edges.is_some() {
            return None;
        }
        let folder = self.folder.clone()?;
        let Source::Ready(source) = &self.source else {
            return None;
        };
        let stem = self.stem_in(&folder, source.as_ref());
        let mut plan = match image::plan(source.as_ref(), &folder, &stem) {
            Ok(plan) if plan.resumed => plan,
            Ok(_) => {
                self.notice = Some((
                    "There is no image and map of this drive in that folder to check.".into(),
                    Tone::Warn,
                ));
                return None;
            }
            Err(why) => {
                self.notice = Some((why, Tone::Warn));
                return None;
            }
        };
        // Confirmed already: by the map naming the drive, or by a start here.
        plan.confirm();
        let edge = edges::edge_plan(&plan, source.as_ref(), &EdgeOptions::default());
        self.edge_plan = Some(plan);
        Some(Ask {
            dialog: Dialog {
                window_title: "Check edges".into(),
                heading: "Check the rescued sectors beside the gaps?".into(),
                intro: edge.text(),
                sections: Vec::new(),
                accept: "Check edges".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_EDGES,
        })
    }

    /// Starts the edge check on its own thread with the drive's source, which it gives back.
    fn start_edges(&mut self) {
        let Some(plan) = self.edge_plan.take() else {
            return;
        };
        if self.running.is_some() {
            return;
        }
        let Source::Ready(mut source) = std::mem::replace(&mut self.source, Source::Busy) else {
            return;
        };
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(EdgeStatus::default());
        let (sender, result) = mpsc::channel();
        let (s, st) = (stop.clone(), status.clone());
        let worker = thread::spawn(move || {
            let done = edges::check_edges(&plan, source.as_mut(), &EdgeOptions::default(), &s, &st);
            let _ = sender.send((source, done));
        });
        self.edges = Some(EdgeRun {
            stop,
            status,
            result,
            worker: Some(worker),
        });
        self.notice = None;
    }

    /// Picks up the edge check's progress and its end.
    fn tick_edges(&mut self) {
        let Some(run) = &mut self.edges else {
            return;
        };
        match toolwin::poll_result(&run.result) {
            None => self.notice = Some((run.status.text(), Tone::Neutral)),
            Some(Ok((source, done))) => {
                if let Some(worker) = run.worker.take() {
                    let _ = worker.join();
                }
                let clean = matches!(done.end, EdgeEnd::Finished | EdgeEnd::NothingToDo)
                    && done.found.is_empty();
                self.notice = Some((done.text(), if clean { Tone::Ok } else { Tone::Warn }));
                self.source = Source::Ready(source);
                self.edges = None;
            }
            Some(Err(why)) => {
                let worker = run.worker.take();
                let why = toolwin::without_result(why, worker);
                self.source =
                    Source::Failed(format!("{why} Open this window again to read the drive."));
                self.notice = Some((why, Tone::Warn));
                self.edges = None;
            }
        }
    }

    /// Hands the condition strip what this window knows of the drive: its event log, the
    /// run's latest reading, the speed and the pauses set here.
    fn share_condition(&mut self) {
        let disk = self.disk;
        if let Some(image) = &self.image {
            condition_strip::follow(disk, &diagnostics::recovery::events::path_for(image));
        }
        condition_strip::pauses(disk, self.throttle, self.wear_rate);
        let speed = self.running.as_ref().map(|run| {
            let filling = run.fill.is_some();
            let waiting = Progress::read(&run.progress.waiting).is_some()
                || Progress::read(&run.progress.cooling).is_some();
            let left = self.map.as_ref().map(|map| {
                if !filling {
                    format!("{} left in this pass", bytes_text(image::phase_left(map)))
                } else if map.reads_before_bad() {
                    let purple = map.count(Status::NonTrimmed)
                        + map.count(Status::NonScraped)
                        + map.count(Status::Untried);
                    format!("{} purple left", bytes_text(purple))
                } else {
                    format!("{} red left", bytes_text(map.count(Status::Bad)))
                }
            });
            Speed {
                bytes_per_second: image::window_rate(
                    &run.samples.iter().copied().collect::<Vec<_>>(),
                ),
                left,
                waiting,
            }
        });
        if let Some(run) = &self.running {
            let latest = run.progress.drive.lock().ok().and_then(|d| d.clone());
            if let Some(reading) = latest {
                let every = if run.fill.is_some() {
                    if self.throttle.on {
                        "every 1 min while reading, and after each pass".to_string()
                    } else {
                        "after each pass".to_string()
                    }
                } else {
                    let every = timed::reading_every(
                        &self.throttle,
                        Settings::for_len(0).health_every,
                        timed::THROTTLE_EVERY,
                    );
                    format!("every {} min", every.as_secs().div_ceil(60))
                };
                condition_strip::reading(disk, &reading, &every);
            }
        }
        condition_strip::speed(disk, speed);
        if let Some(c) = &mut self.controls {
            c.strip.set_disk(Some(disk));
            c.strip.refresh();
        }
    }

    /// The strip's legend: a dot in each color the strip uses, and what it means, instead of a color's name.
    fn draw_legend(&self, dc: HDC, rect: &RECT, dpi: u32) {
        let Some(c) = &self.controls else {
            return;
        };
        let colors = ui::current();
        let items: Vec<(usize, &str)> = LEGEND_ITEMS.iter().copied().enumerate().collect();
        draw_dots(
            dc,
            rect,
            dpi,
            c.legend,
            ui::fonts(dpi).caption,
            colors.muted,
            &items,
        );
    }

    /// The map's amounts above the strip, each with its legend dot, every legend color but white.
    fn draw_counts(&self, dc: HDC, rect: &RECT, dpi: u32) {
        let (Some(c), Some(map)) = (&self.controls, &self.map) else {
            return;
        };
        let colors = ui::current();
        let figures = figures(map);
        let items: Vec<(usize, &str)> = figures.iter().map(|(i, s)| (*i, s.as_str())).collect();
        draw_dots(
            dc,
            rect,
            dpi,
            c.counts,
            ui::fonts(dpi).body,
            colors.text,
            &items,
        );
    }

    /// The phases as steps (`phase_steps`) for this window as it is now.
    fn steps(&self) -> (Vec<String>, Option<usize>) {
        let filling = self.running.as_ref().is_some_and(|run| run.fill.is_some());
        let at = self.map.as_ref().map(|map| (map.phase, map.pass));
        phase_steps(at, self.retries, filling)
    }

    /// The steps, right-aligned: done ones in the text color, the current one in a bubble,
    /// the ones still to run muted, a chevron between each.
    fn draw_steps(&self, dc: HDC, rect: &RECT, dpi: u32) {
        let colors = ui::current();
        ui::fill_rect(dc, rect, colors.page);
        let Some(c) = &self.controls else {
            return;
        };
        let (labels, current) = self.steps();
        let font = ui::fonts(dpi).body;
        let widths: Vec<i32> = labels
            .iter()
            .map(|l| ui::text_width(c.steps, font, l))
            .collect();
        let total = steps_width(&labels, dpi, |l| ui::text_width(c.steps, font, l));
        let (pad, gap) = (scale(dpi, STEP_PAD), scale(dpi, STEP_GAP));
        let mut x = rect.right - total;
        let mut spans = Vec::new();
        for w in &widths {
            spans.push((x, x + w + 2 * pad));
            x += w + 2 * pad + gap;
        }
        let (top, bottom) = (rect.top, rect.bottom);
        let bubble_h = (bottom - top).min(scale(dpi, 26));
        let bubble_top = top + (bottom - top - bubble_h) / 2;
        // GDI+ shapes first, then the GDI text (see `draw_dots`).
        if let Some(canvas) = ui::Canvas::new(dc) {
            if let Some(i) = current {
                let (l, r) = spans[i];
                canvas.fill_round(
                    (l as f32, bubble_top as f32, (r - l) as f32, bubble_h as f32),
                    bubble_h as f32 / 2.0,
                    colors.primary,
                );
            }
            let mid = (top + bottom) as f32 / 2.0;
            let arm = scale(dpi, 4) as f32;
            for pair in spans.windows(2) {
                let cx = (pair[0].1 + pair[1].0) as f32 / 2.0;
                canvas.polyline(
                    &[
                        (cx - arm / 2.0, mid - arm),
                        (cx + arm / 2.0, mid),
                        (cx - arm / 2.0, mid + arm),
                    ],
                    colors.muted,
                    scale(dpi, 2) as f32,
                );
            }
        }
        for (i, label) in labels.iter().enumerate() {
            let color = match current {
                Some(at) if at == i => colors.primary_text,
                Some(at) if i < at => colors.text,
                _ => colors.muted,
            };
            let (l, r) = spans[i];
            ui::draw_text(
                dc,
                label,
                &RECT {
                    left: l,
                    top,
                    right: r,
                    bottom,
                },
                font,
                color,
                windows_sys::Win32::Graphics::Gdi::DT_SINGLELINE
                    | windows_sys::Win32::Graphics::Gdi::DT_VCENTER
                    | windows_sys::Win32::Graphics::Gdi::DT_CENTER,
            );
        }
    }

    /// The map as blocks, row by row from the top left, each in the color of most of its
    /// bytes, the one being read in the reading color, like a disk
    /// defragmenter's map.
    fn draw_strip(&self, dc: HDC, rect: &RECT, dpi: u32) {
        let blocks = Blocks::new(rect.right - rect.left, dpi);
        let count = blocks.count();
        let (cells, shares, gained, reading) = match self.map.as_ref().filter(|map| !map.is_empty())
        {
            Some(map) => (
                map.strip(count),
                map.strip_rescued(count),
                self.before.as_ref().map_or_else(Vec::new, |before| {
                    map.strip_gained_in(before, &(0..map.len()), count)
                }),
                ring_at(map, self.running.is_some(), self.reading)
                    .map(|pos| map.strip_cell(pos, count)),
            ),
            None => (
                vec![Cell::Untried; count],
                vec![0.0; count],
                Vec::new(),
                None,
            ),
        };
        draw_grid(
            dc,
            rect,
            dpi,
            &blocks,
            &Shown {
                cells: &cells,
                shares: &shares,
                gained: &gained,
                reading,
                picked: None,
            },
        );
    }
}

impl ImageView {
    /// The bytes of the strip's square under `x`, `y` in the window, when a map is shown.
    fn square_at(&self, x: i32, y: i32) -> Option<std::ops::Range<u64>> {
        let c = self.controls.as_ref()?;
        let map = self.map.as_ref().filter(|map| !map.is_empty())?;
        let rect = ui::rect_in_parent(c.map_strip)?;
        let blocks = Blocks::new(rect.right - rect.left, self.area.2);
        let i = blocks.at(x - rect.left, y - rect.top)?;
        let whole = 0..map.len();
        let cells = blocks.count();
        Some(Map::strip_edge_in(&whole, i, cells)..Map::strip_edge_in(&whole, i + 1, cells))
    }

    /// Hands the inspector the map and where the run reads, while it is open, or now when
    /// `opening` it.
    fn share_live(&self, opening: bool) {
        if !opening && std::rc::Rc::strong_count(&self.inspect) < 2 {
            return;
        }
        let mut live = self.inspect.borrow_mut();
        live.map = self.map.clone();
        live.before = self.before.clone();
        live.running = self.running.is_some();
        live.filling = self.running.as_ref().is_some_and(|run| run.fill.is_some());
        live.reading = self.reading;
        live.disk = self.disk;
        live.sector = match &self.source {
            Source::Ready(source) => u64::from(source.sector_size()).max(512),
            _ => live.sector.max(512),
        };
    }
}

/// A value in the settings table: a button on the table's card, its caption the value.
fn value_button(hwnd: HWND, id: usize, caption: &str) -> HWND {
    let button = ui::button(hwnd, id, Kind::Secondary, caption);
    ui::mark_on_card(button);
    button
}

/// The settings as a small fixed table: each label beside the button showing its value, a
/// click on the value changing it. Returns the table's card.
fn settings_table(f: &mut toolwin::Flow, c: &Controls) -> Rect {
    let rows = diagnostics::ui_layout::table_rows(f.x, f.y, f.w, f.dpi, 4);
    let inset = |r: Rect| Rect {
        x: r.x + f.s(6),
        y: r.y + f.s(2),
        w: r.w - f.s(12),
        h: r.h - f.s(4),
    };
    let label = |r: Rect, hwnd: HWND| {
        let h = f.s(grid::BODY_H);
        ui::place(
            hwnd,
            Rect {
                x: r.x + f.s(10),
                y: r.y + (r.h - h) / 2,
                w: r.w - f.s(12),
                h,
            },
        );
    };
    // Save in takes the whole first row.
    label(rows[0][0], c.labels[0]);
    ui::place(
        c.folder,
        inset(Rect {
            w: rows[0][3].right() - rows[0][1].x,
            ..rows[0][1]
        }),
    );
    let pairs = [
        (rows[1][0], c.labels[1], rows[1][1], c.retries),
        (rows[1][2], c.labels[2], rows[1][3], c.photos),
        (rows[2][0], c.labels[3], rows[2][1], c.fill_passes),
        (rows[2][2], c.labels[4], rows[2][3], c.rest),
        (rows[3][2], c.labels[6], rows[3][3], c.errors),
    ];
    for (at, name, value_at, value) in pairs {
        label(at, name);
        ui::place(value, inset(value_at));
    }
    // The heat pause's value is two: where it pauses and where it carries on.
    label(rows[3][0], c.labels[5]);
    let heat = inset(rows[3][1]);
    let heat_w = ui::button_width(c.heat, &ui::window_text(c.heat)).min(heat.w / 3);
    ui::place(c.heat, Rect { w: heat_w, ..heat });
    ui::place(
        c.cool,
        Rect {
            x: heat.x + heat_w + f.s(4),
            w: heat.w - heat_w - f.s(4),
            ..heat
        },
    );
    let card = Rect {
        x: f.x,
        y: f.y,
        w: f.w,
        h: rows[3][0].bottom() - f.y,
    };
    f.y = card.bottom();
    card
}

/// Draws `cells` into the grid `blocks` within `rect`: each block in its color, filled with
/// green to its rescued share, the one being read ringed. The strip and the inspector both
/// draw with it, so a square looks the same in each.
pub(crate) fn draw_grid(dc: HDC, rect: &RECT, dpi: u32, blocks: &Blocks, shown: &Shown) {
    let Shown {
        cells,
        shares,
        gained,
        reading,
        picked,
    } = *shown;
    let colors = ui::current();
    ui::fill_rect(dc, rect, colors.card);
    let color = |cell: Cell| match cell {
        Cell::Rescued => legend_color(0, &colors),
        Cell::Partly => legend_color(1, &colors),
        Cell::ToRetry => legend_color(2, &colors),
        Cell::Failed => legend_color(3, &colors),
        Cell::Untried => legend_color(4, &colors),
    };
    let canvas = ui::Canvas::new(dc);
    let radius = blocks.cell as f32 * 0.22;
    let green = legend_color(0, &colors);
    // A cell with anything left to read keeps a sliver of its color on top.
    let cap = scale(dpi, 2);
    for (i, &cell) in cells.iter().enumerate().take(blocks.count()) {
        let (x, y, w, h) = blocks.place(i);
        let (x, y) = (rect.left + x, rect.top + y);
        let base = color(cell);
        let share = shares.get(i).copied().unwrap_or(0.0);
        let level = if base == green {
            0
        } else {
            ((h as f32 * share).round() as i32).min(h - cap).max(0)
        };
        match &canvas {
            Some(canvas) => {
                canvas.fill_round((x as f32, y as f32, w as f32, h as f32), radius, base);
                if level > 0 {
                    let r = radius.min(level as f32 / 2.0);
                    canvas.fill_round(
                        (x as f32, (y + h - level) as f32, w as f32, level as f32),
                        r,
                        green,
                    );
                }
                if gained.get(i).is_some_and(|g| *g > 0) {
                    // A dark ring keeps the mark apart from the green it mostly sits on.
                    let (cx, cy) = (x as f32 + w as f32 / 2.0, y as f32 + h as f32 / 2.0);
                    let r = (w.min(h) as f32 * 0.2).max(1.5);
                    canvas.circle(cx, cy, r + (w.min(h) as f32 * 0.1).max(1.0), colors.card);
                    canvas.circle(cx, cy, r, legend_color(GAINED, &colors));
                }
                if picked == Some(i) {
                    canvas.stroke_round(
                        (x as f32, y as f32, w as f32, h as f32),
                        radius,
                        legend_color(PICKED, &colors),
                        scale(dpi, 3) as f32,
                    );
                }
                if reading == Some(i) {
                    canvas.stroke_round(
                        (x as f32, y as f32, w as f32, h as f32),
                        radius,
                        legend_color(5, &colors),
                        scale(dpi, 2) as f32,
                    );
                }
            }
            None => {
                let square = |top: i32, color: u32| {
                    ui::fill_rect(
                        dc,
                        &RECT {
                            left: x,
                            top,
                            right: x + w,
                            bottom: y + h,
                        },
                        color,
                    )
                };
                square(
                    y,
                    if reading == Some(i) {
                        legend_color(5, &colors)
                    } else {
                        base
                    },
                );
                if level > 0 && reading != Some(i) {
                    square(y + h - level, green);
                }
                if gained.get(i).is_some_and(|g| *g > 0) && reading != Some(i) {
                    let d = (w.min(h) / 3).max(1);
                    ui::fill_rect(
                        dc,
                        &RECT {
                            left: x + (w - d) / 2,
                            top: y + (h - d) / 2,
                            right: x + (w + d) / 2,
                            bottom: y + (h + d) / 2,
                        },
                        legend_color(GAINED, &colors),
                    );
                }
            }
        }
    }
}

/// What each square of a grid shows: its color, its rescued share, what this run recovered
/// in it, and which one is being read.
#[derive(Clone, Copy)]
pub(crate) struct Shown<'a> {
    pub cells: &'a [Cell],
    pub shares: &'a [f32],
    pub gained: &'a [u64],
    pub reading: Option<usize>,
    /// The square picked for a directed read (the inspector's).
    pub picked: Option<usize>,
}

/// Where the strip rings the cell being read: where a running run says it reads (Fill the
/// gaps reads with its map finished), and with no run, where an unfinished map stopped.
pub(crate) fn ring_at(map: &Map, running: bool, reading: Option<u64>) -> Option<u64> {
    if running {
        reading
    } else {
        (map.phase != image::Phase::Finished).then_some(map.current_pos)
    }
}

/// The phases a rescue goes through, as the steps at the top right: each step's label, the
/// current one with its pass, and which is current, so the
/// user knows there is more to run. Retrying is a step when retry passes are set or the map is in one; Fill the gaps
/// is one while it runs.
fn phase_steps(
    at: Option<(image::Phase, u32)>,
    retries: u32,
    filling: bool,
) -> (Vec<String>, Option<usize>) {
    use image::Phase;
    let mut phases = vec![Phase::Copying, Phase::Trimming, Phase::Scraping];
    if retries > 0 || at.is_some_and(|(phase, _)| phase == Phase::Retrying) {
        phases.push(Phase::Retrying);
    }
    phases.push(Phase::Finished);
    let mut labels: Vec<String> = phases
        .iter()
        .map(|phase| match phase {
            Phase::Copying => "Copy",
            Phase::Trimming => "Trim",
            Phase::Scraping => "Scrape",
            Phase::Retrying => "Retry",
            Phase::Finished => "Done",
        })
        .map(String::from)
        .collect();
    if filling {
        labels.push("Fill the gaps".into());
        return (labels, Some(phases.len()));
    }
    let Some((phase, pass)) = at else {
        return (labels, None);
    };
    let current = phases.iter().position(|p| *p == phase);
    if let Some(i) = current {
        match phase {
            Phase::Copying => labels[i] = format!("Copy, pass {pass}"),
            Phase::Retrying => labels[i] = format!("Retry {pass} of {}", retries.max(pass)),
            _ => {}
        }
    }
    (labels, current)
}

/// A step's bubble padding and the gap the chevron between steps takes, at 96 dpi.
const STEP_PAD: i32 = 10;
const STEP_GAP: i32 = 18;

/// The steps' width at `dpi`, each label measured by `measure`.
fn steps_width(labels: &[String], dpi: u32, measure: impl Fn(&str) -> i32) -> i32 {
    let pads = scale(dpi, 2 * STEP_PAD) * labels.len() as i32;
    let gaps = scale(dpi, STEP_GAP) * (labels.len() as i32 - 1).max(0);
    labels.iter().map(|l| measure(l)).sum::<i32>() + pads + gaps
}

/// The block map's rows; its columns follow the window's width.
const BLOCK_ROWS: i32 = 14;

/// Where the map's blocks go, in whole pixels: every block the same size, every gap the same,
/// the grid centred in its width. Blocks placed at fractions of the width came out a pixel apart
/// in size.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Blocks {
    cols: i32,
    rows: i32,
    cell: i32,
    gap: i32,
    left: i32,
}

impl Blocks {
    fn cell_gap(dpi: u32) -> (i32, i32) {
        (scale(dpi, 7).max(2), scale(dpi, 2).max(1))
    }

    fn new(width: i32, dpi: u32) -> Self {
        Self::with_rows(width, dpi, BLOCK_ROWS)
    }

    /// The strip's grid with `rows` rows, as many columns as fit `width`.
    pub(crate) fn with_rows(width: i32, dpi: u32, rows: i32) -> Self {
        let (cell, gap) = Self::cell_gap(dpi);
        let cols = ((width + gap) / (cell + gap)).max(1);
        let used = cols * (cell + gap) - gap;
        Self {
            cols,
            rows: rows.max(1),
            cell,
            gap,
            left: ((width - used) / 2).max(0),
        }
    }

    /// The grid's height, which does not depend on its width.
    fn height(dpi: u32) -> i32 {
        Self::rows_height(dpi, BLOCK_ROWS)
    }

    /// The height of a grid of `rows` rows.
    pub(crate) fn rows_height(dpi: u32, rows: i32) -> i32 {
        let (cell, gap) = Self::cell_gap(dpi);
        rows * (cell + gap) - gap
    }

    pub(crate) fn count(&self) -> usize {
        (self.cols * self.rows) as usize
    }

    /// The block at `x`, `y` within the grid's rectangle; a gap counts with the block before
    /// it, so a click between two blocks is not lost.
    pub(crate) fn at(&self, x: i32, y: i32) -> Option<usize> {
        let x = x - self.left;
        let pitch = self.cell + self.gap;
        if x < 0 || y < 0 {
            return None;
        }
        let (col, row) = (x / pitch, y / pitch);
        (col < self.cols && row < self.rows).then(|| (row * self.cols + col) as usize)
    }

    /// Block `i`'s x, y, width and height within the grid's rectangle.
    fn place(&self, i: usize) -> (i32, i32, i32, i32) {
        let i = i as i32;
        let pitch = self.cell + self.gap;
        (
            self.left + (i % self.cols) * pitch,
            (i / self.cols) * pitch,
            self.cell,
            self.cell,
        )
    }
}

/// What each color of the map strip means, in the strip's order of states.
pub(crate) const LEGEND_ITEMS: [&str; 7] = [
    "Rescued",
    "Rescued, some failed",
    "Failed, to be read again",
    "Bad",
    "Not read yet",
    "Reading here",
    "Recovered this run",
];
/// The legend item marking what this run recovered.
pub(crate) const GAINED: usize = 6;
/// The ring of the square picked in the inspector (not a legend item).
pub(crate) const PICKED: usize = 7;
/// One legend line's height, in 96-dpi pixels.
pub(crate) const LEGEND_LINE: i32 = 18;

pub(crate) fn legend_color(item: usize, colors: &ui::Palette) -> u32 {
    match item {
        0 => colors.ok,
        1 if colors.high_contrast => colors.warn,
        1 => ui::rgb(0xFB923C),
        2 if colors.high_contrast => colors.warn,
        2 => ui::rgb(0xA78BFA),
        3 => colors.serious,
        4 => colors.raised_hover,
        GAINED if colors.high_contrast => colors.text,
        GAINED => ui::rgb(0x22D3EE),
        PICKED if colors.high_contrast => colors.warn,
        PICKED => ui::rgb(0xFACC15),
        _ => colors.text,
    }
}

/// The legend items shown with an amount above the strip: all but the partly rescued parts,
/// whose bytes are counted as rescued and failed already, and the reading mark.
pub(crate) const FIGURES: [usize; 4] = [0, 2, 3, 4];

/// The map's amounts by the legend's names: rescued, failed and to be read again (not
/// trimmed or not scraped), bad, and not read yet; together they are the whole map.
fn figures(map: &Map) -> Vec<(usize, String)> {
    let amount = |item: usize| match item {
        0 => map.count(Status::Rescued),
        2 => map.count(Status::NonTrimmed) + map.count(Status::NonScraped),
        3 => map.count(Status::Bad),
        _ => map.count(Status::Untried),
    };
    FIGURES
        .iter()
        .map(|&item| {
            (
                item,
                format!("{} {}", LEGEND_ITEMS[item], bytes_text(amount(item))),
            )
        })
        .collect()
}

/// Where each labelled dot goes within `width`: its x and its line; one that would run past
/// the edge starts the next line.
pub(crate) fn dot_spots<'a>(
    labels: impl IntoIterator<Item = &'a str>,
    width: i32,
    dpi: u32,
    measure: impl Fn(&str) -> i32,
) -> Vec<(i32, i32)> {
    let dot = scale(dpi, 8) + scale(dpi, 6);
    let gap = scale(dpi, 16);
    let (mut x, mut row) = (0, 0);
    let mut spots = Vec::new();
    for label in labels {
        let w = dot + measure(label);
        if x > 0 && x + w > width {
            x = 0;
            row += 1;
        }
        spots.push((x, row));
        x += w + gap;
    }
    spots
}

/// Draws `items`, each a dot in its legend color and its label, laid out by `dot_spots`.
pub(crate) fn draw_dots(
    dc: HDC,
    rect: &RECT,
    dpi: u32,
    hwnd: HWND,
    font: windows_sys::Win32::Graphics::Gdi::HFONT,
    text: u32,
    items: &[(usize, &str)],
) {
    let colors = ui::current();
    ui::fill_rect(dc, rect, colors.page);
    let width = rect.right - rect.left;
    let spots = dot_spots(items.iter().map(|(_, s)| *s), width, dpi, |s| {
        ui::text_width(hwnd, font, s)
    });
    let line = scale(dpi, LEGEND_LINE);
    let r = scale(dpi, 4) as f32;
    // GDI+ first and let go of the DC, then the GDI text (GDI+ ignores the DC's offset for
    // GDI text drawn while it holds the DC).
    if let Some(canvas) = ui::Canvas::new(dc) {
        for (&(x, row), &(item, _)) in spots.iter().zip(items) {
            let cy = (rect.top + row * line + line / 2) as f32;
            canvas.circle(
                (rect.left + x) as f32 + r,
                cy,
                r,
                legend_color(item, &colors),
            );
        }
    }
    for (&(x, row), &(_, label)) in spots.iter().zip(items) {
        let text_x = rect.left + x + 2 * r as i32 + scale(dpi, 6);
        ui::draw_text(
            dc,
            label,
            &RECT {
                left: text_x,
                top: rect.top + row * line,
                right: rect.right,
                bottom: rect.top + (row + 1) * line,
            },
            font,
            text,
            windows_sys::Win32::Graphics::Gdi::DT_SINGLELINE
                | windows_sys::Win32::Graphics::Gdi::DT_VCENTER
                | windows_sys::Win32::Graphics::Gdi::DT_LEFT,
        );
    }
}

impl Page for ImageView {
    fn title(&self) -> String {
        "Rescue image".into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((780, 760), (620, 640))
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::RESCUE_IMAGE)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        self.controls = Some(Controls {
            title: text(Kind::Title, &format!("Rescue image of disk {}", self.disk)),
            subtitle: text(Kind::Muted, ""),
            about: text(Kind::Muted, "Reads the whole drive once into an image file on another drive, easy areas first, with a map so it can stop and pick up again. The ? button explains each step."),
            strip: Strip::new(hwnd, Some(self.disk)),
            labels: TABLE_LABELS
                .iter()
                .map(|l| ui::text(hwnd, Kind::Muted, Tone::Neutral, true, l))
                .collect(),
            folder: value_button(hwnd, FOLDER, "Choose where to save…"),
            retries: value_button(hwnd, RETRIES, "1"),
            photos: value_button(hwnd, PHOTOS, "on"),
            fill_passes: value_button(hwnd, FILL_PASSES, "3"),
            rest: value_button(hwnd, REST, "2 min"),
            heat: value_button(hwnd, HEAT, &heat_caption(&self.throttle)),
            cool: value_button(hwnd, COOL, "carry on at 30 C"),
            errors: value_button(hwnd, ERRORS, &errors_caption(&self.wear_rate)),
            phase: text(Kind::Body, ""),
            steps: toolwin::canvas(hwnd, STEPS),
            counts: toolwin::canvas(hwnd, COUNTS),
            rates: text(Kind::Muted, ""),
            health: text(Kind::Muted, ""),
            photos_line: text(Kind::Muted, ""),
            limit_line: text(Kind::Muted, ""),
            fill_line: text(Kind::Muted, ""),
            resumed_line: text(Kind::Muted, ""),
            gained_line: text(Kind::Muted, ""),
            map_strip: toolwin::canvas(hwnd, STRIP),
            legend: toolwin::canvas(hwnd, LEGEND),
            notice: text(Kind::Body, ""),
            action: ui::button(hwnd, ACTION, Kind::Primary, "Start…"),
            resume_now: ui::button(hwnd, RESUME_NOW, Kind::Secondary, "Resume now"),
            open_folder: ui::button(hwnd, OPEN_FOLDER, Kind::Secondary, "Show image"),
            fill: ui::button(hwnd, FILL, Kind::Secondary, "Fill the gaps…"),
            undo: ui::button(hwnd, UNDO_FILL, Kind::Secondary, "Undo Fill the gaps…"),
            edges: ui::button(hwnd, EDGES, Kind::Secondary, "Check edges…"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        });
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        let top = f.y;
        f.header(c.title, c.subtitle);
        // The phases at the top right, beside the title when there is room, else under it.
        let font = ui::fonts(dpi).body;
        let (labels, _) = self.steps();
        let steps_w = steps_width(&labels, dpi, |s| ui::text_width(c.steps, font, s));
        let title_w = ui::text_width(c.title, ui::fonts(dpi).title, &ui::window_text(c.title));
        let row = f.s(grid::TITLE_H);
        // The help button keeps the right end of the title row.
        let row_w = f.w - diagnostics::ui_layout::help_room(dpi);
        if row_w - steps_w - f.s(16) >= title_w {
            ui::place(
                c.title,
                Rect {
                    x: f.x,
                    y: top,
                    w: row_w - steps_w - f.s(16),
                    h: row,
                },
            );
            ui::place(
                c.steps,
                Rect {
                    x: f.x + row_w - steps_w,
                    y: top,
                    w: steps_w,
                    h: row,
                },
            );
        } else {
            ui::place(
                c.steps,
                Rect {
                    x: f.x,
                    y: f.y,
                    w: f.w,
                    h: row,
                },
            );
            f.y += row;
            f.space(8);
        }
        f.text(c.about, 10);
        c.strip.place(&mut f);
        let table = settings_table(&mut f, c);
        f.space(12);
        // Progress lines take room only while they say something, so the map follows them.
        f.text(c.phase, 4);
        // The map's amounts, each by its strip color; room is kept for the widest amounts, so
        // the row does not move as they change.
        let counts_h = if self.map.is_some() {
            let font = ui::fonts(dpi).body;
            let widest: Vec<String> = FIGURES
                .iter()
                .map(|&item| format!("{} 999.9 GB", LEGEND_ITEMS[item]))
                .collect();
            dot_spots(widest.iter().map(String::as_str), f.w, dpi, |s| {
                ui::text_width(c.counts, font, s)
            })
            .last()
            .map_or(0, |spot| spot.1 + 1)
                * f.s(LEGEND_LINE)
        } else {
            0
        };
        ui::show(c.counts, counts_h > 0);
        ui::place(
            c.counts,
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h: counts_h,
            },
        );
        if counts_h > 0 {
            f.y += counts_h;
            f.space(4);
        }
        for hwnd in [
            c.rates,
            c.health,
            c.photos_line,
            c.limit_line,
            c.fill_line,
            c.resumed_line,
            c.gained_line,
        ] {
            f.text(hwnd, 4);
        }
        f.space(8);
        let pad = f.s(8);
        let card = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: Blocks::height(dpi) + 2 * pad,
        };
        ui::place(
            c.map_strip,
            Rect {
                x: f.x + pad,
                y: f.y + pad,
                w: f.w - 2 * pad,
                h: Blocks::height(dpi),
            },
        );
        f.y += card.h;
        f.space(6);
        let legend_h = dot_spots(LEGEND_ITEMS, f.w, dpi, |s| {
            ui::text_width(c.legend, ui::fonts(dpi).caption, s)
        })
        .last()
        .map_or(0, |spot| spot.1 + 1)
            * f.s(LEGEND_LINE);
        ui::place(
            c.legend,
            Rect {
                x: f.x,
                y: f.y,
                w: f.w,
                h: legend_h,
            },
        );
        f.y += legend_h;
        f.space(10);
        f.text(c.notice, 0);
        self.natural = Some(f.y + toolwin::footer_h(dpi));
        toolwin::footer(
            w,
            h,
            dpi,
            &[
                c.action,
                c.resume_now,
                c.open_folder,
                c.fill,
                c.undo,
                c.edges,
            ],
            &[c.close],
        );
        ui::set_cards(hwnd, vec![table, card]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, _code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            FOLDER => {
                if let Some(folder) = toolwin::pick_folder(
                    hwnd,
                    "Choose a folder on another drive for the image and its map",
                ) {
                    self.folder = Some(folder);
                    self.notice = None;
                    self.look_in_folder();
                }
            }
            RETRIES => self.retries = (self.retries + 1) % 4,
            PHOTOS => self.photos_first = !self.photos_first,
            FILL_PASSES => self.fill_passes = self.fill_passes % 5 + 1,
            HEAT => self.throttle = next_heat(self.throttle),
            COOL => self.throttle = next_cool(self.throttle),
            ERRORS => self.wear_rate = next_errors(self.wear_rate),
            RESUME_NOW => {
                if let Some(run) = &self.running {
                    run.resume_now.store(true, Ordering::Relaxed);
                }
            }
            REST => {
                let at = RESTS
                    .iter()
                    .position(|m| *m == self.rest_minutes)
                    .unwrap_or(0);
                self.rest_minutes = RESTS[(at + 1) % RESTS.len()];
            }
            FILL => {
                if self.running.is_none() {
                    self.directed = None;
                    ask = self.ask_fill();
                }
            }
            DO_FILL => self.start_fill(),
            crate::inspect_view::DIRECTED => {
                let asked = self.inspect.borrow_mut().directed.take();
                if let Some(asked) = asked {
                    ask = self.directed(asked);
                }
            }
            UNDO_FILL => {
                if self.running.is_none() {
                    ask = self.ask_undo();
                }
            }
            DO_UNDO => self.undo_fill(),
            EDGES => match &self.edges {
                Some(run) => run.stop.store(true, Ordering::Relaxed),
                None => ask = self.ask_edges(),
            },
            DO_EDGES => self.start_edges(),
            ACTION => match &self.running {
                Some(run) => {
                    run.stop.store(true, Ordering::Relaxed);
                }
                None => ask = self.ask_start(hwnd),
            },
            DO_START => self.start(),
            OPEN_FOLDER => {
                if let Some(image) = &self.image {
                    toolwin::reveal(hwnd, image);
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
        if let Source::Opening(receiver) = &self.source {
            match receiver.try_recv() {
                Ok(Ok(source)) => {
                    self.about = Some(source.describe());
                    self.source = Source::Ready(source);
                    self.look_in_folder();
                }
                Ok(Err(why)) => self.source = Source::Failed(why),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.source = Source::Failed("The disk could not be opened.".into())
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let mut finished = None;
        let mut lost = None;
        if let Some(run) = &mut self.running {
            let rescued = run.progress.rescued.load(Ordering::Relaxed);
            run.samples.push_back((Instant::now(), rescued));
            while run
                .samples
                .front()
                .is_some_and(|(at, _)| at.elapsed() > Duration::from_secs(5))
            {
                run.samples.pop_front();
            }
            let reading = Progress::read(&run.progress.waiting).is_none()
                && Progress::read(&run.progress.cooling).is_none();
            if let Ok(state) = run.progress.state.lock() {
                if let Some((phase, pass, map)) = state.as_ref() {
                    run.estimate.observe(
                        Instant::now(),
                        (*phase, *pass),
                        image::phase_left(map),
                        reading,
                    );
                    self.map = Some(map.clone());
                }
            }
            if let Ok(at) = run.progress.reading.lock() {
                self.reading = *at;
            }
            if let Some(events) = &run.fill {
                while let Ok(event) = events.try_recv() {
                    if let FillEvent::Warning(text) = &event {
                        self.notice = Some((text.clone(), Tone::Warn));
                    } else if let Some(text) = event.text() {
                        self.fill_text = text;
                    }
                }
            }
            if let Ok(photos) = run.progress.photos.lock() {
                if let Some(photos) = photos.as_ref() {
                    self.photos_text = photos.text();
                }
            }
            if let Ok(limit) = run.progress.read_limit.lock() {
                if let Some(limit) = limit.as_ref() {
                    self.limit_text = limit.text();
                }
            }
            // Waiting for the drive needs a person outside the window too.
            let waiting = Progress::read(&run.progress.waiting);
            if let Some(text) =
                crate::notify::waiting_news(&mut self.told_waiting, waiting.as_deref())
            {
                crate::notify::tell(hwnd, "The rescue needs you", &text, true);
                self.told_from = Some(hwnd as isize);
            }
            // Waiting for the drive, or for it to cool, shows in the notice until it ends.
            let live = Progress::read(&run.progress.waiting)
                .or_else(|| Progress::read(&run.progress.cooling));
            match live {
                Some(text) => {
                    self.notice = Some((text, Tone::Warn));
                    self.notice_waiting = true;
                }
                None if self.notice_waiting => {
                    self.notice = None;
                    self.notice_waiting = false;
                }
                None => {}
            }
            if let Some(resumed) = Progress::read(&run.progress.resumed) {
                self.resumed_text = resumed;
            }
            if let Some(about) = Progress::read(&run.progress.source) {
                self.about = Some(about);
            }
            match toolwin::poll_result(&run.result) {
                Some(Ok(done)) => finished = Some(done),
                Some(Err(why)) => lost = Some(why),
                None => {}
            }
        }
        if let Some(why) = lost {
            // The worker took the source with it: open the disk again before anything else.
            let worker = self.running.take().and_then(|mut run| run.worker.take());
            let why = toolwin::without_result(why, worker);
            self.source = Source::Failed(format!(
                "{why} The map holds what was saved before then; open this window again to resume."
            ));
            self.notice = Some((why, Tone::Warn));
        }
        if let Some((source, done)) = finished {
            // The end message as the run's last event gave it, so the window and the event
            // log say the same.
            let mut said = None;
            if let Some(mut run) = self.running.take() {
                if let Some(worker) = run.worker.take() {
                    let _ = worker.join();
                }
                said = Progress::read(&run.progress.ended);
                if let Ok(state) = run.progress.state.lock() {
                    if let Some((_, _, map)) = state.as_ref() {
                        self.map = Some(map.clone());
                    }
                }
            }
            // The drive may have come back under another number.
            if let Some(number) = source.disk_number() {
                self.disk = number;
            }
            self.about = Some(source.describe());
            self.notice_waiting = false;
            self.source = Source::Ready(source);
            let done_kind = match &done {
                Done::Rescue(..) => DoneKind::Rescue,
                Done::Fill(_) => DoneKind::Fill,
            };
            let (map_saved, (mut text, tone), health) = match done {
                Done::Rescue(ended, health) => {
                    let (text, tone) = outcome_text(&ended, self.map.as_ref());
                    (ended.map_saved, (said.unwrap_or(text), tone), health)
                }
                Done::Fill(result) => {
                    let tone = fill_tone(&result);
                    let text = said.unwrap_or_else(|| result.text());
                    if result.map_copy.is_some() {
                        self.map_copy = result.map_copy.clone();
                    }
                    (result.map_saved, (text, tone), result.health)
                }
            };
            let ended = match &done_kind {
                DoneKind::Rescue => "The rescue has ended",
                DoneKind::Fill => "Fill the gaps has ended",
            };
            crate::notify::tell(hwnd, ended, &text, tone == Tone::Warn);
            self.told_from = Some(hwnd as isize);
            self.told_waiting = false;
            if let Some(health) = health {
                text = format!("{text}\n{health}");
            }
            self.notice = Some((text, tone));
            if let Some(image) = &self.image {
                if map_saved {
                    crate::recovery_view::image_made(image.clone());
                }
            }
        }
        self.tick_edges();
        self.share_live(false);
        self.share_condition();
        self.render();
        self.relayout(hwnd);
    }

    fn cursor_at(&self, x: i32, y: i32) -> Option<windows_sys::core::PCWSTR> {
        self.square_at(x, y)
            .map(|_| windows_sys::Win32::UI::WindowsAndMessaging::IDC_HAND)
    }

    fn mouse(&mut self, hwnd: HWND, msg: u32, x: i32, y: i32) -> bool {
        if msg == windows_sys::Win32::UI::WindowsAndMessaging::WM_LBUTTONDOWN {
            if let Some(square) = self.square_at(x, y) {
                self.share_live(true);
                crate::inspect_view::open(hwnd, self.inspect.clone(), square);
            }
        }
        false
    }

    fn draw_item(&self, list: usize, _index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        if self
            .controls
            .as_ref()
            .is_some_and(|c| c.strip.draw(list, dc, rect, state.dpi))
        {
            return;
        }
        if list == STRIP {
            self.draw_strip(dc, rect, state.dpi);
        } else if list == LEGEND {
            self.draw_legend(dc, rect, state.dpi);
        } else if list == COUNTS {
            self.draw_counts(dc, rect, state.dpi);
        } else if list == STEPS {
            self.draw_steps(dc, rect, state.dpi);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A drive that reads zeros, for the window's state without a disk.
    struct Blank;

    impl BlockSource for Blank {
        fn len(&self) -> u64 {
            1 << 20
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(
            &mut self,
            _offset: u64,
            buf: &mut [u8],
        ) -> Result<(), diagnostics::recovery::ReadError> {
            buf.fill(0);
            Ok(())
        }
        fn describe(&self) -> String {
            "Blank".into()
        }
    }

    /// The guard: Check edges is offered only for an image whose map is this drive's, with
    /// the drive here and no rescue or Fill the gaps running, which would be writing that
    /// image; while the check runs, the button stops it.
    #[test]
    fn the_edge_check_waits_for_no_run() {
        let mut view = ImageView::with_source(3, Source::Ready(Box::new(Blank)));
        assert!(!view.edges_button().1, "no image yet");
        view.folder = Some(std::env::temp_dir());
        view.image = Some(std::env::temp_dir().join("Disk 3 Blank.img"));
        assert!(
            !view.edges_button().1,
            "a map not confirmed as this drive's"
        );
        view.confirmed = true;
        assert_eq!(view.edges_button(), ("Check edges…", true));
        let (_sender, result) = mpsc::channel();
        view.running = Some(Running {
            stop: Arc::new(AtomicBool::new(false)),
            resume_now: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Progress::default()),
            result,
            fill: None,
            worker: None,
            started: Instant::now(),
            start_rescued: 0,
            samples: VecDeque::new(),
            estimate: image::Estimate::default(),
        });
        assert!(!view.edges_button().1, "a rescue is running");
        let (_tell, events) = mpsc::channel();
        if let Some(run) = &mut view.running {
            run.fill = Some(events);
        }
        assert!(!view.edges_button().1, "Fill the gaps is running");
        view.running = None;
        assert!(view.edges_button().1);
        view.source = Source::Failed("The disk could not be opened.".into());
        assert!(!view.edges_button().1, "the drive is not here");
        let (_sender, result) = mpsc::channel();
        view.edges = Some(EdgeRun {
            stop: Arc::new(AtomicBool::new(false)),
            status: Arc::new(EdgeStatus::default()),
            result,
            worker: None,
        });
        assert_eq!(view.edges_button(), ("Stop edge check", true));
    }

    /// The guard: the steps show every phase still to run, the current one with its pass,
    /// a retry step only with retry passes, and Fill the gaps while it runs.
    /// The guard: a click lands on the block drawn there, gaps with the block before them,
    /// and nothing outside the grid; the inspector opens the clicked square by it.
    #[test]
    fn a_click_finds_the_block_drawn_under_it() {
        let blocks = Blocks::with_rows(300, 96, 5);
        for i in 0..blocks.count() {
            let (x, y, w, h) = blocks.place(i);
            assert_eq!(blocks.at(x + w / 2, y + h / 2), Some(i), "center of {i}");
            assert_eq!(blocks.at(x, y), Some(i), "corner of {i}");
            assert_eq!(blocks.at(x + w, y + h), Some(i), "gap after {i}");
        }
        let (x, y, _, _) = blocks.place(blocks.count() - 1);
        assert_eq!(blocks.at(x + 40, y), None, "past the last column");
        assert_eq!(blocks.at(x, y + 40), None, "past the last row");
        assert_eq!(blocks.at(-1, 0), None);
    }

    #[test]
    fn the_ring_follows_what_the_run_reads() {
        let mut map = Map::new(1000);
        map.phase = image::Phase::Finished;
        map.current_pos = 1000;
        assert_eq!(
            ring_at(&map, true, Some(96)),
            Some(96),
            "Fill the gaps on a finished map"
        );
        assert_eq!(ring_at(&map, true, None), None, "resting between passes");
        assert_eq!(
            ring_at(&map, false, Some(96)),
            None,
            "a finished map with no run"
        );
        map.phase = image::Phase::Scraping;
        map.current_pos = 400;
        assert_eq!(
            ring_at(&map, false, None),
            Some(400),
            "where a stopped rescue resumes"
        );
    }

    #[test]
    fn the_steps_show_the_phases_still_to_run() {
        use image::Phase;
        let (labels, at) = phase_steps(None, 1, false);
        assert_eq!(labels, ["Copy", "Trim", "Scrape", "Retry", "Done"]);
        assert_eq!(at, None);
        let (labels, at) = phase_steps(Some((Phase::Copying, 2)), 1, false);
        assert_eq!(labels[0], "Copy, pass 2");
        assert_eq!(at, Some(0));
        let (labels, at) = phase_steps(Some((Phase::Scraping, 1)), 0, false);
        assert_eq!(labels, ["Copy", "Trim", "Scrape", "Done"]);
        assert_eq!(at, Some(2));
        let (labels, at) = phase_steps(Some((Phase::Retrying, 1)), 2, false);
        assert_eq!(labels[3], "Retry 1 of 2");
        assert_eq!(at, Some(3));
        // A map already retrying shows its step even with no retry passes set now.
        let (labels, at) = phase_steps(Some((Phase::Retrying, 1)), 0, false);
        assert_eq!(labels[3], "Retry 1 of 1");
        assert_eq!(at, Some(3));
        let (_, at) = phase_steps(Some((Phase::Finished, 1)), 1, false);
        assert_eq!(at, Some(4));
        let (labels, at) = phase_steps(Some((Phase::Finished, 1)), 1, true);
        assert_eq!(labels.last().map(String::as_str), Some("Fill the gaps"));
        assert_eq!(at, Some(5));
        assert!(steps_width(&labels, 96, |s| s.len() as i32) > 0);
    }

    /// The guard: the amounts above the strip go by the legend's names and colors, each byte
    /// of the map in one of them; the line there called everything that failed "Bad", the 7.3
    /// GB still to be trimmed with the 540 kB of bad sectors (2026-11-09).
    #[test]
    fn the_amounts_follow_the_legend() {
        let mut map = Map::new(10_000);
        map.set(0, 4000, Status::Rescued);
        map.set(4000, 1000, Status::NonTrimmed);
        map.set(5000, 500, Status::NonScraped);
        map.set(5500, 300, Status::Bad);
        let figures = figures(&map);
        let expect = [(0, 4000), (2, 1500), (3, 300), (4, 4200)];
        assert_eq!(figures.len(), expect.len());
        for ((item, label), (want, bytes)) in figures.iter().zip(expect) {
            assert_eq!(*item, want);
            assert_eq!(
                label,
                &format!("{} {}", LEGEND_ITEMS[want], bytes_text(bytes)),
                "{label}"
            );
        }
        assert_eq!(expect.iter().map(|e| e.1).sum::<u64>(), map.len());
    }

    /// The guard: every block of the map is the same size with the same gap, inside its width,
    /// centred, as many as fit, and the rows fill the grid's height, at every width and scale.
    /// Blocks placed at fractions of the width came out a pixel apart in size (2026-11-09).
    #[test]
    fn every_block_is_the_same_size() {
        for dpi in [96, 120, 144, 168, 192, 288] {
            let (cell, gap) = Blocks::cell_gap(dpi);
            for width in (cell..=2600).step_by(7) {
                let b = Blocks::new(width, dpi);
                assert_eq!(b.count(), (b.cols * BLOCK_ROWS) as usize);
                let mut right = None;
                for i in 0..b.count() {
                    let (x, y, w, h) = b.place(i);
                    assert_eq!((w, h), (cell, cell), "dpi {dpi} width {width} block {i}");
                    let col = i as i32 % b.cols;
                    assert_eq!(y, (i as i32 / b.cols) * (cell + gap));
                    if col > 0 {
                        assert_eq!(x - right.unwrap(), gap, "dpi {dpi} width {width} block {i}");
                    } else {
                        assert_eq!(x, b.left);
                    }
                    right = Some(x + w);
                    if col == b.cols - 1 {
                        let spare = width - (x + w);
                        assert!(spare >= 0 && spare < cell + gap, "dpi {dpi} width {width}");
                        assert!((spare - b.left).abs() <= 1, "dpi {dpi} width {width}");
                    }
                }
                let (_, y, _, h) = b.place(b.count() - 1);
                assert_eq!(y + h, Blocks::height(dpi));
            }
        }
    }

    #[test]
    fn end_texts_say_what_happened_and_how_to_go_on() {
        let mut map = Map::new(1 << 30);
        map.set(0, 1 << 29, Status::Rescued);
        map.set(1 << 29, 4096, Status::Bad);
        let saved = |outcome| Ended {
            outcome,
            map_saved: true,
            zones_left: 0,
        };
        let (text, tone) = outcome_text(&saved(Outcome::Stopped), Some(&map));
        assert!(text.contains("Resume carries on"), "{text}");
        assert!(
            text.contains("Rescued 536.9 MB of 1.1 GB; 4.1 kB unreadable."),
            "{text}"
        );
        assert_eq!(tone, Tone::Neutral);
        let (text, tone) = outcome_text(&saved(Outcome::Paused("Paused: it is hot.".into())), None);
        assert!(
            text.starts_with("Paused: it is hot. The map is saved"),
            "{text}"
        );
        assert_eq!(tone, Tone::Warn);
        assert_eq!(
            rates_line(
                2_000_000.0,
                1_000_000.0,
                Some("about 1 min left in this phase".into())
            ),
            "Now 2.0 MB/s  ·  Average 1.0 MB/s  ·  about 1 min left in this phase"
        );
        assert_eq!(
            rates_line(0.0, 0.0, None),
            "Now 0 MB/s  ·  Average 0 MB/s  ·  time left not known yet"
        );
    }

    /// The guard: the window's threshold buttons step through their values and then off, and
    /// the carry-on threshold is always below the pause threshold.
    #[test]
    fn the_threshold_buttons_keep_carry_on_below_pause() {
        let mut throttle = Throttle::default();
        assert_eq!(heat_caption(&throttle), "38 C");
        let mut seen = Vec::new();
        for _ in 0..HEATS.len() + 2 {
            throttle = next_heat(throttle);
            for _ in 0..COOLS.len() + 1 {
                assert!(
                    !throttle.on || throttle.resume_at < throttle.pause_at,
                    "{throttle:?}"
                );
                throttle = next_cool(throttle);
            }
            seen.push(throttle.on.then_some(throttle.pause_at));
        }
        assert_eq!(
            seen,
            [
                Some(40),
                Some(42),
                Some(45),
                Some(50),
                None,
                Some(35),
                Some(38),
                Some(40)
            ]
        );
        let low = Throttle {
            on: true,
            pause_at: 35,
            resume_at: 32,
        };
        assert_eq!(next_cool(low).resume_at, 25);
        // From the highest pause value round to the lowest: the carry-on value drops below it.
        let high = Throttle {
            on: true,
            pause_at: 50,
            resume_at: 40,
        };
        assert!(!next_heat(high).on);
        assert_eq!(
            next_heat(next_heat(high)),
            Throttle {
                on: true,
                pause_at: 35,
                resume_at: 32,
            }
        );
        let mut rate = WearRate::default();
        let mut limits = Vec::new();
        for _ in 0..4 {
            rate = next_errors(rate);
            limits.push(rate.on.then_some(rate.limit));
        }
        assert_eq!(limits, [Some(2000), Some(5000), None, Some(250)]);
        assert_eq!(errors_caption(&rate), "250 in 30 min");
    }

    /// A fill whose passes finished but whose log or place went wrong warns.
    #[test]
    fn a_fill_with_a_problem_beside_its_passes_warns() {
        let result = |end, problems: Vec<String>| FillResult {
            end,
            passes: Vec::new(),
            recovered: 0,
            unread_before: 0,
            unread_after: 0,
            map_saved: true,
            map_copy: None,
            health: None,
            read_limit: Vec::new(),
            problems,
        };
        assert_eq!(fill_tone(&result(FillEnd::Finished, vec![])), Tone::Ok);
        assert_eq!(fill_tone(&result(FillEnd::NothingToDo, vec![])), Tone::Ok);
        assert_eq!(fill_tone(&result(FillEnd::Stopped, vec![])), Tone::Neutral);
        let problem = || vec!["the event log could not be saved".to_string()];
        assert_eq!(fill_tone(&result(FillEnd::Finished, problem())), Tone::Warn);
        assert_eq!(
            fill_tone(&result(FillEnd::NothingToDo, problem())),
            Tone::Warn
        );
        assert_eq!(fill_tone(&result(FillEnd::Stopped, problem())), Tone::Warn);
    }
}
