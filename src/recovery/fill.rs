//! Fill the gaps: bounded passes over what a finished or stopped rescue image could not
//! read, started by the technician, or by an agent the technician directs, never by the
//! rescue itself. Recovering as much data as possible is the goal, and several tries give
//! the best chance of it.
//!
//! Each pass reads every sector not rescued yet once, one sector at a time, alternating
//! direction; the drive rests between passes with nothing read; the drive is allowed its
//! longer read limit; and its health is read after each pass. When a pass recovered nothing
//! and its reallocated or pending sectors (an NVMe drive's media errors) have risen by more
//! than `rise_limit` since the step began, it stops: the drive is getting worse and gives no
//! data back. A pass that recovers anything goes on whatever the counts did: wear matters
//! less than the data, and not recovering it is no better than the drive dying.
//! Every sector that comes back goes into the image and the map at once.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::events::{Event, Figures, PauseKind};
use super::health_log::{self, HealthLog};
use super::image::{Directed, Outcome, Plan, Progress, Rescue, Settings, SweepCount};
use super::read_limit::{LimitEvent, ReadLimit};
use super::timed::{HealthWatch, Wear, WearReading};
use super::wait::Waiter;
use super::BlockSource;
use crate::tools::drives::bytes_text;

/// Fill the gaps' options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillOptions {
    /// Passes, 1 to 5. Default 3.
    pub passes: u32,
    /// Seconds the drive rests between passes, nothing read, 0 to 3600. Default 120.
    pub rest_secs: u64,
    /// How far reallocated or pending sectors (an NVMe drive's media errors) may rise
    /// since the step began before a pass that recovered nothing stops it, 0 to 1000.
    /// Default 16.
    pub rise_limit: u64,
    /// The drive's read limit for these passes, tenths of a second, 1 to 600. Default 100.
    pub read_limit_tenths: u16,
    /// Where the technician pointed the step from the inspector: one block read once, or
    /// the first pass from a block. None: every pass over the whole drive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directed: Option<Directed>,
}

impl Default for FillOptions {
    fn default() -> Self {
        Self {
            passes: 3,
            rest_secs: 120,
            rise_limit: 16,
            read_limit_tenths: 100,
            directed: None,
        }
    }
}

impl FillOptions {
    /// Refuses values outside their bounds.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=5).contains(&self.passes) {
            return Err(format!("passes must be 1 to 5, not {}", self.passes));
        }
        if self.rest_secs > 3600 {
            return Err(format!(
                "rest_secs must be 0 to 3600, not {}",
                self.rest_secs
            ));
        }
        if self.rise_limit > 1000 {
            return Err(format!(
                "rise_limit must be 0 to 1000, not {}",
                self.rise_limit
            ));
        }
        if let Some(directed) = &self.directed {
            if directed.range().is_empty() {
                return Err("the block pointed at holds no bytes".into());
            }
        }
        if !(1..=600).contains(&self.read_limit_tenths) {
            return Err(format!(
                "read_limit_tenths must be 1 to 600, not {}",
                self.read_limit_tenths
            ));
        }
        Ok(())
    }
}

/// What the step is doing, as it happens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FillEvent {
    /// A pass begins over `unread` bytes; `from` where it carries on from a run before.
    PassStarted {
        pass: u32,
        of: u32,
        backwards: bool,
        unread: u64,
        #[serde(default)]
        from: Option<u64>,
    },
    /// Within a pass: bytes read of `unread`, and of them recovered; what is ahead.
    Progress {
        pass: u32,
        read: u64,
        unread: u64,
        recovered: u64,
        #[serde(default)]
        ahead: Option<Ahead>,
    },
    PassEnded {
        pass: u32,
        read: u64,
        recovered: u64,
    },
    /// A health reading: the counts, or why there are none.
    Health {
        text: String,
    },
    /// Resting before the next pass.
    Resting {
        seconds_left: u64,
    },
    ReadLimit(LimitEvent),
    /// Something the technician should know.
    Warning(String),
}

impl FillEvent {
    /// The window's line for it; None for what another line shows (health, read limit).
    pub fn text(&self) -> Option<String> {
        let way = |backwards: bool| if backwards { "backwards" } else { "forwards" };
        Some(match self {
            FillEvent::PassStarted {
                pass,
                of,
                backwards,
                unread,
                from,
            } => {
                let from = match from {
                    Some(at) => format!(
                        ", carrying on from {} where the last run stopped",
                        bytes_text(*at)
                    ),
                    None => String::new(),
                };
                format!(
                    "Fill the gaps: pass {pass} of {of}, {}, over {} not read yet{from}.",
                    way(*backwards),
                    bytes_text(*unread)
                )
            }
            FillEvent::Progress {
                pass,
                read,
                unread,
                recovered,
                ahead,
            } => {
                let mut text = format!(
                    "Fill the gaps: pass {pass}: {} of {} tried, {} recovered.",
                    bytes_text(*read),
                    bytes_text(*unread),
                    bytes_text(*recovered)
                );
                if let Some(ahead) = ahead {
                    text.push(' ');
                    text.push_str(&ahead.text());
                }
                text
            }
            FillEvent::PassEnded {
                pass, recovered, ..
            } => format!(
                "Fill the gaps: pass {pass} recovered {}.",
                bytes_text(*recovered)
            ),
            FillEvent::Resting { seconds_left } => format!(
                "Fill the gaps: the drive rests with nothing read; the next pass starts in {}.",
                if *seconds_left >= 60 {
                    format!("about {} min", seconds_left.div_ceil(60))
                } else {
                    format!("{seconds_left} s")
                }
            ),
            FillEvent::Warning(text) => text.clone(),
            FillEvent::Health { .. } | FillEvent::ReadLimit(_) => return None,
        })
    }
}

/// What a pass has ahead of the sector it reads, that one included (manual step 29: a pass
/// spent an hour on sectors that failed before and looked stalled).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ahead {
    /// The sector being read failed before.
    pub on_bad: bool,
    /// Sectors that failed before, ahead: retried one by one.
    pub bad_sectors: u64,
    /// Bytes ahead not read yet that never failed: areas the rescue skipped, or a drop
    /// skipped.
    pub skipped: u64,
    /// About how long the sectors that failed before take, at this step's time per failed
    /// read; None before one is timed.
    pub bad_secs: Option<u64>,
}

impl Ahead {
    /// Where the pass reading `sector`-byte sectors at `at` stands in `map`, going
    /// `backwards` or forwards; `fail_secs` is the time a failed read takes.
    pub fn of(
        map: &super::image::Map,
        at: u64,
        sector: u64,
        backwards: bool,
        fail_secs: Option<f64>,
    ) -> Self {
        use super::image::Status;
        let sector = sector.max(1);
        let range = if backwards {
            0..at.saturating_add(sector).min(map.len())
        } else {
            at..map.len()
        };
        // A pass with anything else to read passes over the bad sectors and splits all of
        // what is left, whichever way it reads (`Map::largest_unfailed`).
        let splitting = map.reads_before_bad();
        let range = if splitting { 0..map.len() } else { range };
        let [_, untried, retry, bad] = map.amounts_in(&range);
        let bad = if splitting { 0 } else { bad };
        let bad_sectors = bad.div_ceil(sector);
        Self {
            on_bad: map
                .find_where(|_| true, at)
                .is_some_and(|block| block.pos <= at && block.status == Status::Bad),
            bad_sectors,
            skipped: untried + retry,
            bad_secs: fail_secs.map(|secs| (secs * bad_sectors as f64).round() as u64),
        }
    }

    /// For the fill line: what is being read, and what is left of the pass.
    pub fn text(&self) -> String {
        let bad = match self.bad_secs {
            Some(secs) => format!(
                "{} {} that failed before, about {}",
                self.bad_sectors,
                if self.bad_sectors == 1 {
                    "sector"
                } else {
                    "sectors"
                },
                minutes_text(secs)
            ),
            None => format!(
                "{} {} that failed before",
                self.bad_sectors,
                if self.bad_sectors == 1 {
                    "sector"
                } else {
                    "sectors"
                }
            ),
        };
        let skipped = format!("{} skipped earlier", bytes_text(self.skipped));
        match (self.on_bad, self.bad_sectors > 0, self.skipped > 0) {
            (true, _, true) => format!("Retrying {bad}; then {skipped}."),
            (true, _, false) => format!("Retrying {bad}; then the pass ends."),
            (false, true, _) => format!("Reading {skipped}; {bad} still ahead."),
            (false, false, _) => format!("Reading {skipped}; the pass ends after it."),
        }
    }
}

fn minutes_text(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs} s"),
        90..=5399 => format!("{} min", (secs + 30) / 60),
        _ => format!("{:.1} h", secs as f64 / 3600.0),
    }
}

/// One pass's figures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillPass {
    pub pass: u32,
    pub backwards: bool,
    /// Bytes asked of the drive, and of them recovered.
    pub read: u64,
    pub recovered: u64,
    /// The step ended during the pass (Stop, the drive gone, a failure); its figures are
    /// what it did up to then, which the map holds.
    #[serde(default)]
    pub ended_early: bool,
}

/// How the step ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FillEnd {
    /// Every pass ran.
    Finished,
    /// The map shows nothing unread: nothing was read.
    NothingToDo,
    Stopped,
    /// The drive's counts rose past the limit; says which and by how much.
    Worsening(String),
    /// The drive stopped answering.
    Gone(String),
    /// The options were refused, or the image or map could not be opened or written.
    Failed(String),
}

/// What the step did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillResult {
    pub end: FillEnd,
    pub passes: Vec<FillPass>,
    /// Bytes recovered by all passes.
    pub recovered: u64,
    /// Bytes not rescued before the step and after it.
    pub unread_before: u64,
    pub unread_after: u64,
    /// A map was saved in this step.
    pub map_saved: bool,
    /// The map as it was before the passes, kept beside it for an undo.
    #[serde(default)]
    pub map_copy: Option<std::path::PathBuf>,
    /// The health log's account of the drive over the step.
    pub health: Option<String>,
    pub read_limit: Vec<LimitEvent>,
    /// What went wrong beside the passes (the event log not saved, the place not removed).
    #[serde(default)]
    pub problems: Vec<String>,
}

impl FillResult {
    fn ended(end: FillEnd, unread: u64) -> Self {
        Self {
            end,
            passes: Vec::new(),
            recovered: 0,
            unread_before: unread,
            unread_after: unread,
            map_saved: false,
            map_copy: None,
            health: None,
            read_limit: Vec::new(),
            problems: Vec::new(),
        }
    }

    /// For the window: how it ended, what each pass recovered and what is left.
    pub fn text(&self) -> String {
        let head = match &self.end {
            FillEnd::Finished => "Fill the gaps finished.".to_string(),
            FillEnd::NothingToDo => "Nothing to fill: every area of the image is read.".into(),
            FillEnd::Stopped => "Fill the gaps stopped.".into(),
            FillEnd::Worsening(why) => format!("Fill the gaps stopped: {why}"),
            FillEnd::Gone(why) => format!("Fill the gaps stopped: {why}"),
            FillEnd::Failed(why) => format!("Fill the gaps could not go on: {why}"),
        };
        let passes: Vec<String> = self
            .passes
            .iter()
            .map(|p| {
                let early = if p.ended_early {
                    " before it ended"
                } else {
                    ""
                };
                format!(
                    "pass {} recovered {}{early}",
                    p.pass,
                    bytes_text(p.recovered)
                )
            })
            .collect();
        let mut text = head;
        if !passes.is_empty() {
            text.push_str(&format!(
                " {}. {} still unreadable.",
                capitalize(&passes.join(", ")),
                bytes_text(self.unread_after)
            ));
        }
        if self.map_saved {
            text.push_str(" The map is saved.");
        }
        if let Some(name) = self.map_copy.as_ref().and_then(|p| p.file_name()) {
            text.push_str(&format!(
                " The map from before is kept as {}.",
                name.to_string_lossy()
            ));
        }
        for problem in &self.problems {
            text.push(' ');
            text.push_str(problem);
        }
        text
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Why the counts say to stop: any count that rose by more than `limit` since `start`,
/// after a pass that recovered nothing (`pass_recovered`); `recovered` is the step's.
pub fn worsening(
    start: &Wear,
    now: &Wear,
    limit: u64,
    pass_recovered: u64,
    recovered: u64,
) -> Option<String> {
    if pass_recovered > 0 {
        return None;
    }
    let rises: Vec<String> = [
        ("reallocated sectors", start.reallocated, now.reallocated),
        ("pending sectors", start.pending, now.pending),
        ("media errors", start.media_errors, now.media_errors),
    ]
    .into_iter()
    .filter_map(|(name, before, after)| match (before, after) {
        (Some(before), Some(after)) if after > before.saturating_add(limit) => {
            Some(format!("{name} rose from {before} to {after}"))
        }
        _ => None,
    })
    .collect();
    (!rises.is_empty()).then(|| {
        format!(
            "the drive is getting worse and the last pass gave no data back: {} since the passes began, while they recovered {}.",
            rises.join(" and "),
            bytes_text(recovered)
        )
    })
}

/// The longest a single read is taken to last when timing failed reads: the longest read
/// limit offered. Longer, the time held a wait for the drive.
const MAX_READ_TIME: Duration = Duration::from_secs(60);

/// Times failed reads from a sweep's counts, for the time ahead (`Ahead`).
#[derive(Default)]
struct FailTimer {
    secs: f64,
    fails: u64,
    /// When the last read ended and the sweep's count then.
    last: Option<(Instant, SweepCount)>,
}

impl FailTimer {
    /// A sweep starts at `now`, its count at nothing.
    fn start(&mut self, now: Instant) {
        self.last = Some((now, SweepCount::default()));
    }

    /// The sweep's count after a read that ended at `now`: one that read and recovered
    /// nothing failed, and took the time since the read before.
    fn note(&mut self, count: &SweepCount, now: Instant) {
        if let Some((then, before)) = self.last {
            let took = now.saturating_duration_since(then);
            if count.read > before.read
                && count.recovered == before.recovered
                && took <= MAX_READ_TIME
            {
                self.secs += took.as_secs_f64();
                self.fails += 1;
            }
        }
        self.last = Some((now, *count));
    }

    /// Seconds a failed read takes, on average; None before one is timed.
    fn mean(&self) -> Option<f64> {
        (self.fails > 0).then(|| self.secs / self.fails as f64)
    }
}

/// Rests `seconds` with nothing read, telling `events` every 10 s; false on Stop.
fn rest(seconds: u64, stop: &AtomicBool, events: &mut dyn FnMut(FillEvent)) -> bool {
    let until = Instant::now() + Duration::from_secs(seconds);
    let mut told = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        let secs = left.as_secs() + 1;
        if told.is_none_or(|t: u64| t >= secs + 10) {
            told = Some(secs);
            events(FillEvent::Resting { seconds_left: secs });
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

/// Fill the gaps on the image and map `plan` names, reading `source`. `health` reads the
/// drive (and logs each reading beside the image), `limit` sets its read limit, `stop`
/// ends the step at the next sector, and `events` hears what happens. `progress` carries
/// the map for the window's strip, and the waiting. The heat pause (`health.throttle`)
/// pauses a pass with the map saved until the drive cools; a drive that stops answering
/// pauses it until the same drive is back (`waiter`), and the pass carries on past a skip.
/// The source the step ended with is left in `waiter.source` when it changed.
#[allow(clippy::too_many_arguments)]
pub fn fill_gaps(
    plan: Plan,
    source: &mut dyn BlockSource,
    options: &FillOptions,
    health: &mut HealthWatch,
    limit: &mut ReadLimit,
    waiter: &mut Waiter,
    stop: &AtomicBool,
    progress: &Progress,
    events: &mut dyn FnMut(FillEvent),
) -> FillResult {
    let unread = plan.map.len() - plan.map.count(super::image::Status::Rescued);
    if let Err(why) = options.check().and_then(|()| health.throttle.check()) {
        return FillResult::ended(FillEnd::Failed(why), unread);
    }
    let place_path = super::image::fill_place_path(&plan.image);
    let place_name = place_path.file_name().unwrap_or_default().to_os_string();
    // The place is read and removed through the image's folder, never by its path.
    let held = super::place::held(&plan.image, &*source);
    let events_path = super::events::path_for(&plan.image);
    if unread == 0 {
        // A run with nothing to fill ends as any other: its event line saved, then the place
        // a failed earlier save kept removed.
        let mut result = FillResult::ended(FillEnd::NothingToDo, 0);
        if let Ok((guard, folder)) = &held {
            let name = events_path.file_name().unwrap_or_default().to_os_string();
            let opened = super::writer::open_beside(guard, folder, &name);
            progress.events.start(events_path, opened);
            let event = Event::Finished {
                reason: result.text(),
            };
            progress.events.write(&event, Figures::of(&plan.map));
        }
        result
            .problems
            .extend(super::place::finish(&held, &place_name, true, || {
                progress.events.finish()
            }));
        return result;
    }
    // Where a run before this one stopped, when the map is still as it left it.
    let carried = held.as_ref().ok().and_then(|(guard, folder)| {
        super::image::fill_place_for(guard, folder, &plan.image, &plan.map)
    });
    let first = carried.map_or(1, |place| place.pass.min(options.passes));
    // A block pointed at: read once, alone, and the place kept for the passes stays as it is.
    let only = match &options.directed {
        Some(Directed::Block { .. }) => options.directed.as_ref().map(Directed::range),
        _ => None,
    };
    let first = if only.is_some() { 1 } else { first };
    let last = if only.is_some() { 1 } else { options.passes };
    let carry_from = match &options.directed {
        Some(Directed::From { start, end }) => Some(if first % 2 == 0 { *end } else { *start }),
        // A block read alone starts nowhere else.
        Some(Directed::Block { .. }) => None,
        // A place kept while reading what never failed is not one: that is split from the
        // middle of its longest run each time (on 2026-11-10 a place kept by a build before
        // splitting sent the first read to a run's hanging edge).
        None => carried
            .filter(|place| place.pass == first && !plan.map.reads_before_bad())
            .and_then(|place| place.at),
    };
    health.then = "Fill the gaps".into();
    // Within a pass the drive is read only for the heat pause.
    let every = health.every(Duration::MAX);
    let meant = source.identity();
    let sector = u64::from(source.sector_size().max(1));
    let mut current: Option<Box<dyn BlockSource>> = None;
    let drop_skip = Settings::for_len(plan.map.len()).drop_skip;
    // The reading the rises are counted from.
    let start = match health.wear() {
        WearReading::Stop => return FillResult::ended(FillEnd::Stopped, unread),
        WearReading::Gone(why) => return FillResult::ended(FillEnd::Gone(why), unread),
        WearReading::Counts(wear) => Some(wear),
        WearReading::NoCounts(why) => {
            events(FillEvent::Warning(format!(
                "The drive gives no sector counts ({why}), so the passes cannot stop on a drive getting worse; they stop after {} passes or on Stop.",
                options.passes
            )));
            None
        }
    };
    let log_path = health_log::path_for(&plan.image);
    let disk_number = source.disk_number();
    let mut rescue = match Rescue::open(plan, source) {
        Ok(rescue) => rescue,
        Err(why) => return FillResult::ended(FillEnd::Failed(why), unread),
    };
    let opened = rescue.beside(events_path.file_name().unwrap_or_default());
    progress.events.start(events_path, opened);
    rescue.events = progress.events.clone();
    rescue.publish(progress);
    progress.events.write(
        &super::events::started(
            "fill the gaps",
            disk_number,
            meant.as_ref(),
            serde_json::json!({
                "options": options,
                "heat_pause": health.throttle,
                "carried_on": carried.map(|_| serde_json::json!({
                    "pass": first,
                    "from": carry_from,
                })),
            }),
        ),
        Figures::of(&rescue.map),
    );
    // The map as it is before any pass, for an undo (manual step 24); not for a block read
    // alone, one a click, whose undo is the last whole run's.
    let kept = match only {
        Some(_) => Ok(None),
        None => rescue.keep_map_copy("before-fill").map(Some),
    };
    let map_copy = match kept {
        Ok(path) => path,
        Err(why) => {
            events(FillEvent::Warning(format!(
                "{why}; Fill the gaps goes on without one."
            )));
            None
        }
    };
    let opened = rescue.beside(log_path.file_name().unwrap_or_default());
    // Unchanged readings are written on the rescue's own health schedule.
    let quiet = super::image::Settings::for_len(0).health_every;
    health.log = Some(HealthLog::start(log_path, opened).quiet(quiet));
    health.note(rescue.map.current_pos, rescue.map.failed(), progress);
    if let Some(text) = health.shown(progress) {
        events(FillEvent::Health { text });
    }
    let mut result = FillResult::ended(FillEnd::Finished, unread);
    result.map_copy = map_copy;
    // Failed reads timed over the step, for the time ahead.
    let mut fails = FailTimer::default();
    limit.options.retry_tenths = options.read_limit_tenths;
    if let Some(event) = limit.apply(options.read_limit_tenths) {
        if let Some(text) = event.not_set() {
            health.log_note("read limit", None, text);
            health.note(rescue.map.current_pos, rescue.map.failed(), progress);
        }
        events(FillEvent::ReadLimit(event));
    }
    if let Some(block) = &only {
        rescue.fill_only(block.clone());
    }
    if let Some(directed) = &options.directed {
        let range = directed.range();
        progress.events.write(
            &Event::Directed {
                how: directed.how().into(),
                start: range.start,
                end: range.end,
            },
            Figures::of(&rescue.map),
        );
    }
    for pass in first..=last {
        let backwards = pass % 2 == 0 && only.is_none();
        let unread = match &only {
            Some(block) => {
                let [_, untried, retry, bad] = rescue.map.amounts_in(block);
                untried + retry + bad
            }
            None => rescue.unread(),
        };
        if unread == 0 {
            break;
        }
        if only.is_none() {
            rescue.keep_fill_places(place_path.clone(), pass, backwards);
        }
        let from = carry_from.filter(|_| pass == first);
        if let Some(at) = from {
            rescue.carry_on_fill(at);
        }
        events(FillEvent::PassStarted {
            pass,
            of: last,
            backwards,
            unread,
            from,
        });
        rescue.say_fill_pass(pass);
        let mut told = Instant::now();
        // What the pass read before any drop it carried on from.
        let mut before = SweepCount::default();
        let swept = loop {
            let mut so_far = SweepCount::default();
            fails.start(Instant::now());
            let reading: &mut dyn BlockSource = match current.as_mut() {
                Some(back) => back.as_mut(),
                None => &mut *source,
            };
            let swept = {
                let watch_health = &mut *health;
                let mut watch = || {
                    let watch = watch_health.heat();
                    let (pos, bad) = (
                        progress.pos.load(Ordering::Relaxed),
                        progress.failed.load(Ordering::Relaxed),
                    );
                    if watch != super::image::Watch::Stop {
                        watch_health.note(pos, bad, progress);
                    }
                    watch
                };
                rescue.fill_pass(
                    reading,
                    backwards,
                    stop,
                    progress,
                    every,
                    &mut watch,
                    &mut |count| {
                        so_far = *count;
                        fails.note(count, Instant::now());
                        if told.elapsed() >= Duration::from_millis(500) {
                            told = Instant::now();
                            let fail_secs = fails.mean();
                            let ahead = progress
                                .reading
                                .lock()
                                .ok()
                                .and_then(|at| *at)
                                .zip(progress.state.lock().ok().and_then(|state| {
                                    state.as_ref().map(|(_, _, map)| map.clone())
                                }))
                                .map(|(at, map)| Ahead::of(&map, at, sector, backwards, fail_secs));
                            events(FillEvent::Progress {
                                pass,
                                read: before.read + count.read,
                                unread,
                                recovered: before.recovered + count.recovered,
                                ahead,
                            });
                        }
                    },
                )
            };
            before.read += so_far.read;
            before.recovered += so_far.recovered;
            let why = match swept {
                Err(Outcome::Gone(why)) => why,
                Ok(_) => break Ok(before),
                Err(other) => break Err(other),
            };
            let went = super::wait::pause(
                &mut rescue,
                meant.as_ref(),
                why,
                sector,
                drop_skip,
                waiter,
                stop,
                progress,
                &mut |kind, text| health.log_note(kind, None, text),
                "Fill the gaps",
            );
            health.note(rescue.map.current_pos, rescue.map.failed(), progress);
            match went {
                super::wait::Went::Back(back) => {
                    limit.reconnect(back.as_ref());
                    health.moved_to(back.disk_number());
                    if let Some(event) = limit.apply(options.read_limit_tenths) {
                        if let Some(text) = event.not_set() {
                            health.log_note("read limit", None, text);
                        }
                        events(FillEvent::ReadLimit(event));
                    }
                    current = Some(back);
                }
                super::wait::Went::End(outcome) => {
                    rescue.end_filling();
                    break Err(outcome);
                }
            }
        };
        let count = match &swept {
            Ok(count) => *count,
            Err(_) => before,
        };
        // Every pass that read anything is counted, however it ended, so the result and its
        // end text agree with the map.
        if swept.is_ok() || count.read > 0 {
            result.recovered += count.recovered;
            result.passes.push(FillPass {
                pass,
                backwards,
                read: count.read,
                recovered: count.recovered,
                ended_early: swept.is_err(),
            });
        }
        if let Err(outcome) = swept {
            // The pass's figures up to the stop are in the map; the step ends here.
            result.end = match outcome {
                Outcome::Stopped => FillEnd::Stopped,
                Outcome::Gone(why) | Outcome::Unconfirmed(why) => FillEnd::Gone(why),
                Outcome::Failed(why) => FillEnd::Failed(why),
                Outcome::Paused(why) => FillEnd::Worsening(why),
                Outcome::Finished => FillEnd::Finished,
            };
            break;
        }
        events(FillEvent::PassEnded {
            pass,
            read: count.read,
            recovered: count.recovered,
        });
        // A restart from here on starts the next pass.
        if only.is_none() {
            rescue.keep_fill_places(place_path.clone(), pass + 1, !backwards);
        }
        // A health reading each pass, logged, and compared with the step's first.
        match health.wear() {
            WearReading::Stop => {
                result.end = FillEnd::Stopped;
                break;
            }
            WearReading::Gone(why) => {
                result.end = FillEnd::Gone(why);
                break;
            }
            WearReading::NoCounts(_) => {}
            WearReading::Counts(now) => {
                if let Some(why) = start.as_ref().and_then(|start| {
                    worsening(
                        start,
                        &now,
                        options.rise_limit,
                        count.recovered,
                        result.recovered,
                    )
                }) {
                    health.keep_latest();
                    health.note(rescue.map.current_pos, rescue.map.failed(), progress);
                    result.end = FillEnd::Worsening(why);
                    break;
                }
            }
        }
        health.note(rescue.map.current_pos, rescue.map.failed(), progress);
        if let Some(text) = health.shown(progress) {
            events(FillEvent::Health { text });
        }
        if pass < last && rescue.unread() > 0 && !rest(options.rest_secs, stop, events) {
            result.end = FillEnd::Stopped;
            break;
        }
    }
    if let Some(event) = limit.restore() {
        events(FillEvent::ReadLimit(event));
    }
    if let Err(why) = rescue.save_now() {
        result.end = FillEnd::Failed(why);
    }
    result.map_saved = rescue.map_saved();
    result.unread_after = rescue.unread();
    health.note(rescue.map.current_pos, rescue.map.failed(), progress);
    rescue.publish(progress);
    let said = result.text();
    let event = match &result.end {
        FillEnd::Finished | FillEnd::NothingToDo => Some(Event::Finished {
            reason: said.clone(),
        }),
        FillEnd::Stopped => Some(Event::Stopped {
            reason: said.clone(),
        }),
        FillEnd::Worsening(_) => Some(Event::Paused {
            kind: PauseKind::ErrorRate,
            reason: said.clone(),
            values: serde_json::json!({ "rise_limit": options.rise_limit }),
        }),
        // Not when the wait for the drive already said so and the step ended waiting.
        FillEnd::Gone(_) if progress.events.state() == Some("paused") => None,
        FillEnd::Gone(_) => Some(Event::Paused {
            kind: PauseKind::DriveGone,
            reason: said.clone(),
            values: serde_json::json!({ "waiting": false }),
        }),
        FillEnd::Failed(_) => Some(Event::AppError {
            reason: said.clone(),
        }),
    };
    if let Some(event) = event {
        progress.events.write(&event, Figures::of(&rescue.map));
    }
    // Every pass ran and the event log is saved: a restart starts afresh. A log that did not
    // save keeps the place, which the run would be made again from.
    let complete = result.end == FillEnd::Finished && only.is_none();
    result
        .problems
        .extend(super::place::finish(&held, &place_name, complete, || {
            progress.events.finish()
        }));
    Progress::say(&progress.ended, Some(result.text()));
    result.health = health.finish_log();
    result.read_limit = limit.events.clone();
    if let Some(back) = current {
        waiter.source.get_or_insert(back);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::dest::Guard;
    use crate::recovery::image::{plan_with, Directed, Map, Phase, Settings, Status, Watch};
    use crate::recovery::read_limit::{FakeLimit, QuickGiveUp};
    use crate::recovery::{MemDisk, ReadError};
    use crate::tools::drives::health::{fixtures, parse_smart_attributes, Health};
    use crate::tools::drives::sct::Request;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn folder(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("diagtool-fill-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 / 512 + i) as u8).collect()
    }

    /// The place kept beside `dir`'s image, read through the folder as the code reads it.
    fn place_for(dir: &std::path::Path, map: &Map) -> Option<crate::recovery::image::FillPlace> {
        let guard = Guard::new([]);
        let folder = guard.base(dir).unwrap();
        crate::recovery::image::fill_place_for(&guard, &folder, &dir.join("image.img"), map)
    }

    /// A disk whose listed sectors fail a set number of times more, then read.
    struct Flaky {
        disk: MemDisk,
        fails: HashMap<u64, u32>,
    }

    impl BlockSource for Flaky {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            let result = self.disk.read_at(offset, buf);
            let mut failed = false;
            for sector in (offset..offset + buf.len() as u64).step_by(512) {
                if let Some(left) = self.fails.get_mut(&sector) {
                    if *left > 0 {
                        *left -= 1;
                        failed = true;
                    }
                }
            }
            if failed {
                return Err(ReadError::Bad(23));
            }
            result
        }
        fn describe(&self) -> String {
            self.disk.describe()
        }
        fn identity(&self) -> Option<crate::recovery::SourceId> {
            self.disk.identity()
        }
    }

    fn ata(pending: u64) -> crate::tools::drives::health::Disk {
        let table = fixtures::smart_table(&[(5, 100, 100, 0), (197, 100, 100, pending)]);
        fixtures::disk(Health::Ata(parse_smart_attributes(&table).unwrap()))
    }

    /// A health reading that gives these pending counts in turn, then the last again.
    fn readings(pending: Vec<u64>) -> HealthWatch {
        let left = Arc::new(Mutex::new(pending));
        let read: Arc<dyn Fn() -> Option<crate::tools::drives::health::Disk> + Send + Sync> =
            Arc::new(move || {
                let mut left = left.lock().unwrap();
                let value = if left.len() > 1 {
                    left.remove(0)
                } else {
                    left[0]
                };
                Some(ata(value))
            });
        HealthWatch::with_reader(
            read,
            Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// A finished image of `len` bytes whose sectors `bad` could not be read.
    fn finished_image(dir: &std::path::Path, len: usize, bad: std::ops::Range<u64>) -> MemDisk {
        let mut disk = MemDisk::new(data(len));
        disk.bad.push(bad);
        let plan = plan_with(&disk, dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        let settings = Settings {
            cluster: 4096,
            skip: 4096,
            ..Settings::for_len(len as u64)
        };
        let outcome = run.run(
            &mut disk,
            &settings,
            &AtomicBool::new(false),
            &Progress::default(),
            &mut || Watch::Fine,
        );
        assert_eq!(outcome, Outcome::Finished);
        disk.bad.clear();
        disk.reads.clear();
        disk
    }

    /// The guard: each pass reads every sector not rescued once, one sector at a time,
    /// alternating direction; what comes back is in the image and the map at once; the
    /// map's phase is left as it was; each pass's recovered bytes are reported; and the
    /// drive's read limit is the longer one and is put back.
    #[test]
    fn fill_passes_read_each_gap_once_per_pass_and_alternate() {
        let dir = folder("passes");
        let len = 256 << 10;
        let bad = 65_536..69_632; // 8 sectors
        let disk = finished_image(&dir, len, bad.clone());
        // Sector k fails k % 3 more times: three are read by pass 1, three by 2, two by 3.
        let fails = (0..8u64)
            .map(|k| (bad.start + k * 512, (k % 3) as u32))
            .collect();
        let mut source = Flaky { disk, fails };
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let fake = FakeLimit::default();
        *fake.value.lock().unwrap() = 70;
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        let mut events = Vec::new();
        let options = FillOptions {
            rest_secs: 0,
            ..FillOptions::default()
        };
        let result = fill_gaps(
            plan,
            &mut source,
            &options,
            &mut readings(vec![0]),
            &mut limit,
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |event| events.push(event),
        );
        assert_eq!(result.end, FillEnd::Finished, "{result:?}");
        let recovered: Vec<u64> = result.passes.iter().map(|p| p.recovered).collect();
        assert_eq!(recovered, vec![3 * 512, 3 * 512, 2 * 512]);
        assert_eq!(result.unread_after, 0);
        assert!(result.map_saved);
        assert!(
            result.text().contains("Pass 1 recovered 1.5 kB"),
            "{}",
            result.text()
        );
        // Pass 1 forwards over all 8, pass 2 backwards over the 5 left, pass 3 forwards.
        let reads: Vec<u64> = source.disk.reads.iter().map(|r| r.0).collect();
        let sectors: Vec<u64> = (0..8u64).map(|k| bad.start + k * 512).collect();
        assert!(source.disk.reads.iter().all(|r| r.1 == 512));
        assert_eq!(reads[..8], sectors[..]);
        let second: Vec<u64> = [7u64, 5, 4, 2, 1]
            .iter()
            .map(|k| bad.start + k * 512)
            .collect();
        assert_eq!(reads[8..13], second[..]);
        let third: Vec<u64> = [2u64, 5].iter().map(|k| bad.start + k * 512).collect();
        assert_eq!(reads[13..], third[..]);
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        let map = Map::parse(&text).unwrap();
        assert_eq!(
            map.phase,
            Phase::Finished,
            "the fill changed the map's phase"
        );
        assert_eq!(map.count(Status::Rescued), len as u64);
        assert_eq!(
            std::fs::read(dir.join("image.img")).unwrap(),
            source.disk.data
        );
        assert_eq!(
            *fake.sent.lock().unwrap(),
            vec![
                Request::Read,
                Request::Set(100),
                Request::Read,
                Request::Set(70)
            ]
        );
        assert!(events.iter().any(|e| matches!(
            e,
            FillEvent::PassStarted {
                pass: 2,
                backwards: true,
                ..
            }
        )));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A source that sets `stop` once it has been read `left` more times.
    struct StopAfter {
        inner: Flaky,
        left: u32,
        stop: Arc<AtomicBool>,
    }

    impl BlockSource for StopAfter {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.left = self.left.saturating_sub(1);
            if self.left == 0 {
                self.stop.store(true, Ordering::Relaxed);
            }
            self.inner.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
        fn identity(&self) -> Option<crate::recovery::SourceId> {
            self.inner.identity()
        }
    }

    /// The guard for manual steps 28 and 24: a run stopped mid-pass keeps its pass and place
    /// beside the map, and the next run carries on there rather than at pass 1; stopped
    /// between passes, the next run starts the next pass; a map changed since is not carried
    /// on; every pass done, the place is gone. Each run keeps the map from before it.
    #[test]
    fn fill_carries_on_where_a_stopped_run_left_off() {
        let dir = folder("carry");
        let len = 256 << 10;
        let bad = 65_536..69_632; // 8 sectors
        let mut disk = finished_image(&dir, len, bad.clone());
        let sector = |k: u64| bad.start + k * 512;
        let place_path = dir.join("image.fill.json");
        let options = FillOptions {
            rest_secs: 0,
            ..FillOptions::default()
        };
        let run = |disk: MemDisk, fails: u32, reads: u32, stop_on_pass_end: bool| {
            let stop = Arc::new(AtomicBool::new(false));
            let fails = (0..8u64).map(|k| (sector(k), fails)).collect();
            let mut source = StopAfter {
                inner: Flaky { disk, fails },
                left: reads,
                stop: stop.clone(),
            };
            let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let mut events = Vec::new();
            let result = fill_gaps(
                plan,
                &mut source,
                &options,
                &mut readings(vec![0]),
                &mut ReadLimit::new(Box::new(FakeLimit::default()), QuickGiveUp::default()),
                &mut Waiter::none(),
                &stop,
                &Progress::default(),
                &mut |event| {
                    if stop_on_pass_end && matches!(event, FillEvent::PassEnded { .. }) {
                        stop.store(true, Ordering::Relaxed);
                    }
                    events.push(event);
                },
            );
            let mut disk = source.inner.disk;
            let reads = std::mem::take(&mut disk.reads);
            (result, events, reads, disk)
        };
        let place = || {
            let map = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
            place_for(&dir, &map)
        };
        let before = std::fs::read_to_string(dir.join("image.map")).unwrap();

        // Stopped after 3 failed reads of pass 1: the place is pass 1 past them.
        let (result, _, reads, back) = run(disk, u32::MAX, 3, false);
        disk = back;
        assert_eq!(result.end, FillEnd::Stopped, "{result:?}");
        assert_eq!(reads.len(), 3);
        let kept = place().expect("no place kept");
        assert_eq!(
            (kept.pass, kept.backwards, kept.at),
            (1, false, Some(sector(3)))
        );
        // The map from before the run, kept beside it.
        let copy = result.map_copy.clone().expect("no map copy");
        let copied = Map::parse(&std::fs::read_to_string(&copy).unwrap()).unwrap();
        assert_eq!(
            copied.count(Status::Rescued),
            Map::parse(&before).unwrap().count(Status::Rescued)
        );
        assert!(
            result
                .text()
                .contains("The map from before is kept as image.map.before-fill-"),
            "{}",
            result.text()
        );

        // The next run carries on at sector 3, not at the start of pass 1.
        let (result, events, reads, back) = run(disk, u32::MAX, 1, false);
        disk = back;
        assert_eq!(reads[0].0, sector(3), "{reads:?}");
        assert!(events.iter().any(|e| matches!(
            e,
            FillEvent::PassStarted { pass: 1, from: Some(at), .. } if *at == sector(3)
        )));
        assert!(result.text().starts_with("Fill the gaps stopped."));
        assert_eq!(place().map(|p| p.at), Some(Some(sector(4))));

        // A map changed since is carried on all the same; a place that does not fit is not.
        let mut map = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        map.set(sector(0), 512, Status::Rescued);
        assert!(place_for(&dir, &map).is_some());
        assert_eq!(place_for(&dir, &Map::new(sector(3))), None);
        // Nor one whose way is not its pass's (pass 2 reads backwards).
        let kept = std::fs::read(&place_path).unwrap();
        std::fs::write(&place_path, br#"{"pass":2,"backwards":false,"at":null}"#).unwrap();
        assert_eq!(place_for(&dir, &map), None);
        std::fs::write(&place_path, kept).unwrap();

        // Stopped after pass 1 ends: the place is pass 2 from its start.
        let (result, _, reads, back) = run(disk, 0, u32::MAX, true);
        disk = back;
        assert_eq!(result.end, FillEnd::Stopped, "{result:?}");
        let firsts: Vec<u64> = reads.iter().map(|r| r.0).collect();
        assert_eq!(firsts, (4..8).map(sector).collect::<Vec<_>>());
        let kept = place().expect("no place kept between passes");
        assert_eq!((kept.pass, kept.backwards, kept.at), (2, true, None));

        // The next run starts pass 2, finishes, and leaves no place.
        let (result, events, reads, disk) = run(disk, 0, u32::MAX, false);
        assert_eq!(result.end, FillEnd::Finished, "{result:?}");
        assert!(matches!(
            events
                .iter()
                .find(|e| matches!(e, FillEvent::PassStarted { .. })),
            Some(FillEvent::PassStarted {
                pass: 2,
                backwards: true,
                from: None,
                ..
            })
        ));
        assert_eq!(reads[0].0, sector(3));
        assert_eq!(result.unread_after, 0);
        assert!(!place_path.exists(), "the place outlived a finished run");

        // With a run never failed to read, a kept place is not carried on: the run is split
        // from its middle.
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        let mut map = Map::parse(&text).unwrap();
        map.set(sector(0), 4096, Status::NonScraped);
        let heading: String = text
            .lines()
            .filter(|l| l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        let body: String = map
            .to_text(&[])
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        std::fs::write(dir.join("image.map"), heading + &body).unwrap();
        let kept = crate::recovery::image::FillPlace {
            pass: 1,
            backwards: false,
            at: Some(sector(6)),
        };
        std::fs::write(&place_path, serde_json::to_vec(&kept).unwrap()).unwrap();
        let (_, _, reads, _) = run(disk, 0, 1, false);
        assert_eq!(reads[0].0, sector(4), "{reads:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: Fill the gaps reads and removes its place through the folder it opened and
    /// checked (`place`), never by a path that can lead elsewhere by then.
    #[test]
    fn the_place_is_reached_only_through_the_held_folder() {
        let code = include_str!("fill.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for by_path in [
            "fs::remove_file(",
            "fs::read(",
            "fs::read_to_string(",
            "fs::write(",
        ] {
            assert!(!code.contains(by_path), "fill.rs uses {by_path}");
        }
        assert!(code.contains("place::finish(") && code.contains("place::held("));
        assert!(
            !code.contains("place::remove("),
            "fill.rs removes a place outside place::finish"
        );
    }

    /// The guard for the undo of manual step 24: the map from before a fill is put back over
    /// the map, the map it replaces kept first; a copy of another map, or of another size,
    /// is refused and changes nothing.
    #[test]
    fn the_map_from_before_a_fill_is_put_back_and_the_one_it_replaces_kept() {
        use crate::recovery::image::{map_of_copy, put_back_map};
        let dir = folder("undo");
        let len = 128 << 10;
        let mut source = finished_image(&dir, len, 16_384..20_480);
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let result = fill_gaps(
            plan,
            &mut source,
            &FillOptions {
                passes: 1,
                ..FillOptions::default()
            },
            &mut readings(vec![0]),
            &mut ReadLimit::new(Box::new(FakeLimit::default()), QuickGiveUp::default()),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.unread_after, 0, "{result:?}");
        let map_path = dir.join("image.map");
        let copy = result.map_copy.expect("no map copy");
        assert_eq!(map_of_copy(&copy).as_deref(), Some(map_path.as_path()));
        let after = std::fs::read_to_string(&map_path).unwrap();
        let rescued = |text: &str| Map::parse(text).unwrap().count(Status::Rescued);

        // Not a copy of this map, or of another size: refused, nothing changed.
        let stranger = dir.join("other.map.before-fill-20260101-000000");
        std::fs::copy(&copy, &stranger).unwrap();
        assert!(put_back_map(&stranger, &map_path).is_err());
        let small = dir.join("image.map.before-fill-20260101-000000");
        std::fs::write(&small, "# small\n0x00000000 ?\n0x00000000 0x00000200 +\n").unwrap();
        assert!(put_back_map(&small, &map_path)
            .unwrap_err()
            .contains("not put back"));
        assert_eq!(std::fs::read_to_string(&map_path).unwrap(), after);

        let kept = put_back_map(&copy, &map_path).unwrap();
        let now = std::fs::read_to_string(&map_path).unwrap();
        assert_eq!(rescued(&now), len as u64 - 4096);
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), after);
        assert_eq!(rescued(&after), len as u64);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard for manual step 29: the fill line says whether the pass is retrying
    /// sectors that failed before or reading areas skipped earlier, how many of each are
    /// ahead in its direction, and about how long the failed ones take.
    #[test]
    fn the_fill_line_says_what_is_ahead_of_the_pass() {
        // 0-4096 rescued, 4096-6144 bad (4 sectors), 6144-8192 skipped, 8192-10240 rescued,
        // 10240-11264 bad (2), 11264-12288 not tried.
        let map = Map::parse(
            "# test\n0x00000000 ?\n0x00000000 0x00001000 +\n0x00001000 0x00000800 -\n0x00001800 0x00000800 /\n0x00002000 0x00000800 +\n0x00002800 0x00000400 -\n0x00002C00 0x00000400 ?\n",
        )
        .unwrap();
        // While anything else is left, the pass passes over the bad sectors.
        let ahead = Ahead::of(&map, 6144, 512, false, Some(4.0));
        assert_eq!(
            (ahead.bad_sectors, ahead.skipped, ahead.bad_secs),
            (0, 3072, Some(0))
        );
        assert_eq!(
            ahead.text(),
            "Reading 3.1 kB skipped earlier; the pass ends after it."
        );
        let ahead = Ahead::of(&map, 11264, 512, true, None);
        assert_eq!(
            ahead.text(),
            "Reading 3.1 kB skipped earlier; the pass ends after it."
        );
        // The same map with only its bad sectors left.
        let map = Map::parse(
            "# test\n0x00000000 ?\n0x00000000 0x00001000 +\n0x00001000 0x00000800 -\n0x00001800 0x00000800 +\n0x00002000 0x00000800 +\n0x00002800 0x00000400 -\n0x00002C00 0x00000400 +\n",
        )
        .unwrap();
        let ahead = Ahead::of(&map, 4096, 512, false, Some(4.0));
        assert_eq!(
            ahead,
            Ahead {
                on_bad: true,
                bad_sectors: 6,
                skipped: 0,
                bad_secs: Some(24),
            }
        );
        assert_eq!(
            ahead.text(),
            "Retrying 6 sectors that failed before, about 24 s; then the pass ends."
        );
        let ahead = Ahead::of(&map, 6144, 512, false, None);
        assert_eq!(
            (
                ahead.on_bad,
                ahead.bad_sectors,
                ahead.skipped,
                ahead.bad_secs
            ),
            (false, 2, 0, None)
        );
        // Backwards: what lies before the sector, that one included.
        let ahead = Ahead::of(&map, 10240, 512, true, Some(285.0));
        assert_eq!(
            (ahead.on_bad, ahead.bad_sectors, ahead.skipped),
            (true, 5, 0)
        );
        assert!(ahead.text().contains("about 24 min"), "{}", ahead.text());
        let ahead = Ahead::of(&map, 6144, 512, true, None);
        assert_eq!(
            (ahead.on_bad, ahead.bad_sectors, ahead.skipped),
            (false, 4, 0)
        );
        let event = FillEvent::Progress {
            pass: 3,
            read: 0,
            unread: 1,
            recovered: 0,
            ahead: Some(Ahead::of(&map, 4096, 512, false, Some(4.0))),
        };
        assert!(event
            .text()
            .unwrap()
            .contains("recovered. Retrying 6 sectors"));
    }

    /// The guard: a failed read is timed from the read before it; reads that came back, a
    /// wait longer than any read, and a sweep that starts again after a drop (its count
    /// back at nothing) do not count.
    #[test]
    fn failed_reads_are_timed_from_the_read_before() {
        let at = Instant::now();
        let s = |secs: u64| at + Duration::from_secs(secs);
        let count = |read: u64, recovered: u64| SweepCount { read, recovered };
        let mut timer = FailTimer::default();
        assert_eq!(timer.mean(), None);
        timer.start(s(0));
        timer.note(&count(512, 512), s(1)); // came back
        timer.note(&count(1024, 512), s(5)); // failed, 4 s
        timer.note(&count(1536, 512), s(11)); // failed, 6 s
        assert_eq!(timer.mean(), Some(5.0));
        timer.note(&count(2048, 512), s(200)); // a wait for the drive
        assert_eq!(timer.mean(), Some(5.0));
        // After a drop the sweep starts again, its count at nothing.
        timer.start(s(300));
        timer.note(&count(512, 0), s(302));
        assert_eq!(timer.mean(), Some(4.0));
    }

    /// A source that asks a directed read of the running step once it has been read `left`
    /// more times.
    struct AskAfter {
        inner: Flaky,
        left: u32,
        progress: Arc<Progress>,
        ask: Option<Directed>,
    }

    impl BlockSource for AskAfter {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.left = self.left.saturating_sub(1);
            if self.left == 0 {
                if let Some(ask) = self.ask.take() {
                    *self.progress.directed.lock().unwrap() = Some(ask);
                }
            }
            self.inner.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
        fn identity(&self) -> Option<crate::recovery::SourceId> {
            self.inner.identity()
        }
    }

    /// The guard for the directed read: asked of a running pass, "read this block"
    /// reads the block's sectors once and the pass goes on from where it was, passing over
    /// the block; "continue scan from here" moves the pass to the block. With no pass
    /// running, a block is read alone, once, and the place kept for the passes stays.
    #[test]
    fn a_directed_read_reads_the_block_or_moves_the_pass() {
        let dir = folder("directed");
        let len = 256 << 10;
        let mut disk = finished_image(&dir, len, 65_536..67_584); // A: 4 sectors at 64 kB
                                                                  // B: 4 more sectors at 128 kB, not read in the rescue either.
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        let mut map = Map::parse(&text).unwrap();
        map.set(131_072, 2048, Status::Bad);
        // The map keeps its heading, which names the drive.
        let heading: String = text
            .lines()
            .filter(|l| l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        let body: String = map
            .to_text(&[])
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        std::fs::write(dir.join("image.map"), heading + &body).unwrap();
        let a = |k: u64| 65_536 + k * 512;
        let b = |k: u64| 131_072 + k * 512;
        let block_b = (b(0), b(4));
        let options = FillOptions {
            passes: 1,
            rest_secs: 0,
            ..FillOptions::default()
        };
        let run =
            |disk: MemDisk, options: &FillOptions, left: u32, ask: Option<Directed>, fail: u32| {
                let progress = Arc::new(Progress::default());
                let fails = (0..4u64)
                    .flat_map(|k| [(a(k), fail), (b(k), fail)])
                    .collect();
                let mut source = AskAfter {
                    inner: Flaky { disk, fails },
                    left,
                    progress: progress.clone(),
                    ask,
                };
                let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
                let result = fill_gaps(
                    plan,
                    &mut source,
                    options,
                    &mut readings(vec![0]),
                    &mut ReadLimit::new(Box::new(FakeLimit::default()), QuickGiveUp::default()),
                    &mut Waiter::none(),
                    &AtomicBool::new(false),
                    &progress,
                    &mut |_| {},
                );
                let mut disk = source.inner.disk;
                let reads: Vec<u64> = std::mem::take(&mut disk.reads)
                    .iter()
                    .map(|r| r.0)
                    .collect();
                (result, reads, disk)
            };

        // Read this block, asked after two reads of pass 1: B, then the rest of A, and B
        // is not read again.
        let ask = Directed::Block {
            start: block_b.0,
            end: block_b.1,
        };
        let (result, reads, back) = run(disk, &options, 2, Some(ask), u32::MAX);
        disk = back;
        assert_eq!(result.end, FillEnd::Finished, "{result:?}");
        assert_eq!(reads, vec![a(0), a(1), b(0), b(1), b(2), b(3), a(2), a(3)]);
        let log = std::fs::read_to_string(dir.join("image.events.jsonl")).unwrap();
        assert!(
            log.contains(r#""event":"directed","how":"read this block""#),
            "{log}"
        );

        // Continue scan from here, asked after one read: the pass goes on at B.
        let ask = Directed::From {
            start: block_b.0,
            end: block_b.1,
        };
        let (_, reads, back) = run(disk, &options, 1, Some(ask), u32::MAX);
        disk = back;
        assert_eq!(reads, vec![a(0), b(0), b(1), b(2), b(3)]);

        // With no pass running, a block alone; the place kept for the passes is kept, though
        // the block read changes the map.
        let place = crate::recovery::image::fill_place_path(&dir.join("image.img"));
        let kept = crate::recovery::image::FillPlace {
            pass: 1,
            backwards: false,
            at: Some(a(3)),
        };
        std::fs::write(&place, serde_json::to_vec(&kept).unwrap()).unwrap();
        let alone = FillOptions {
            passes: 3,
            directed: Some(Directed::Block {
                start: b(1),
                end: b(3),
            }),
            ..options.clone()
        };
        let (result, reads, back) = run(disk, &alone, 0, None, 0);
        disk = back;
        assert_eq!(result.end, FillEnd::Finished, "{result:?}");
        assert_eq!(reads, vec![b(1), b(2)]);
        assert_eq!(result.passes.len(), 1);
        assert_eq!(result.recovered, 1024, "the block read changed nothing");
        assert_eq!(result.map_copy, None, "a block read alone kept a map copy");
        let map = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        assert_eq!(
            place_for(&dir, &map).map(|p| (p.pass, p.at)),
            Some((1, Some(a(3))))
        );

        // And the first pass from a block, with no pass running.
        let from = FillOptions {
            directed: Some(Directed::From {
                start: b(2),
                end: b(4),
            }),
            ..options.clone()
        };
        let (_, reads, _) = run(disk, &from, 0, None, u32::MAX);
        // b(1) and b(2) came back in the block read.
        assert_eq!(reads, vec![b(3)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: when pending sectors rise past the limit after a pass that gave nothing,
    /// the step stops there and says so.
    #[test]
    fn fill_passes_stop_on_a_rising_health_count() {
        let dir = folder("worse");
        let len = 128 << 10;
        let bad = 32_768..36_864;
        let disk = finished_image(&dir, len, bad.clone());
        let fails = (0..8u64).map(|k| (bad.start + k * 512, 99)).collect();
        let mut source = Flaky { disk, fails };
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let result = fill_gaps(
            plan,
            &mut source,
            &FillOptions {
                rest_secs: 0,
                ..FillOptions::default()
            },
            &mut readings(vec![4, 30]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.passes.len(), 1, "{result:?}");
        assert!(
            matches!(&result.end, FillEnd::Worsening(why)
                if why.contains("getting worse and the last pass gave no data back")
                && why.contains("pending sectors rose from 4 to 30")),
            "{result:?}"
        );
        assert_eq!(source.disk.reads.len(), 8, "a second pass ran");
        // A rise within the limit does not stop it.
        let start = Wear {
            pending: Some(4),
            ..Wear::default()
        };
        let now = Wear {
            pending: Some(20),
            ..Wear::default()
        };
        assert_eq!(worsening(&start, &now, 16, 0, 0), None);
        assert!(worsening(&start, &now, 15, 0, 0).is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a pass that recovered data goes on however far the counts rose; the
    /// step stopped after a pass that recovered 218 MB of disk 3 (2026-11-10).
    #[test]
    fn a_pass_that_recovers_data_goes_on_whatever_the_counts() {
        let dir = folder("worse-but-giving");
        let len = 128 << 10;
        let bad = 32_768..36_864;
        let disk = finished_image(&dir, len, bad.clone());
        // Seven sectors never read; the eighth reads in pass 1.
        let fails = (0..7u64).map(|k| (bad.start + k * 512, 99)).collect();
        let mut source = Flaky { disk, fails };
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let result = fill_gaps(
            plan,
            &mut source,
            &FillOptions {
                rest_secs: 0,
                ..FillOptions::default()
            },
            &mut readings(vec![4, 300, 600, 900]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.passes[0].recovered, 512, "{result:?}");
        assert!(
            result.passes.len() >= 2,
            "pass 1 recovered data: {result:?}"
        );
        // Pass 2 gave nothing while the counts rose: that stops it.
        assert!(matches!(&result.end, FillEnd::Worsening(_)), "{result:?}");
        assert_eq!(result.passes.len(), 2, "{result:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn options_out_of_bounds_and_nothing_to_fill_are_said() {
        for bad in [
            FillOptions {
                passes: 0,
                ..FillOptions::default()
            },
            FillOptions {
                passes: 6,
                ..FillOptions::default()
            },
            FillOptions {
                rest_secs: 3601,
                ..FillOptions::default()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        let dir = folder("whole");
        let mut disk = finished_image(&dir, 64 << 10, 0..0);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let result = fill_gaps(
            plan,
            &mut disk,
            &FillOptions::default(),
            &mut readings(vec![0]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.end, FillEnd::NothingToDo);
        assert!(disk.reads.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a finished run's place goes only once its event log is saved; a log that
    /// cannot be written keeps the place and says so in the result.
    #[test]
    fn the_place_stays_until_the_event_log_is_saved() {
        let dir = folder("log-fails");
        let mut disk = finished_image(&dir, 128 << 10, 16_384..20_480);
        // A folder where the log goes: it cannot be opened.
        std::fs::create_dir(dir.join("image.events.jsonl")).unwrap();
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let result = fill_gaps(
            plan,
            &mut disk,
            &FillOptions {
                passes: 1,
                ..FillOptions::default()
            },
            &mut readings(vec![0]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.end, FillEnd::Finished, "{result:?}");
        assert!(result.text().contains("event log"), "{}", result.text());
        assert!(
            dir.join("image.fill.json").exists(),
            "the place went before the event log was saved"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a place that cannot be removed is in the result of a run with nothing to
    /// fill, as of any run.
    // Windows only: clearing the attribute is the Unix warning's world-writable concern.
    #[allow(clippy::permissions_set_readonly_false)]
    #[test]
    fn a_place_that_cannot_be_removed_is_said_when_nothing_is_to_fill() {
        let dir = folder("whole-place");
        let mut disk = finished_image(&dir, 64 << 10, 0..0);
        let place = dir.join("image.fill.json");
        std::fs::write(&place, b"{}").unwrap();
        let mut mode = std::fs::metadata(&place).unwrap().permissions();
        mode.set_readonly(true);
        std::fs::set_permissions(&place, mode).unwrap();
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let result = fill_gaps(
            plan,
            &mut disk,
            &FillOptions::default(),
            &mut readings(vec![0]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.end, FillEnd::NothingToDo);
        assert!(
            result.text().contains("could not be removed"),
            "{}",
            result.text()
        );
        let mut mode = std::fs::metadata(&place).unwrap().permissions();
        mode.set_readonly(false);
        std::fs::set_permissions(&place, mode).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Runs `fill_gaps` on a whole image (nothing to fill) in `dir`, with nothing else asked.
    fn run_on_whole_image(dir: &std::path::Path) -> FillResult {
        let mut disk = finished_image(dir, 64 << 10, 0..0);
        let plan = plan_with(&disk, dir, "image", u64::MAX / 2, "NTFS").unwrap();
        fill_gaps(
            plan,
            &mut disk,
            &FillOptions::default(),
            &mut readings(vec![0]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        )
    }

    /// The guard: a run with nothing to fill saves its event line before it removes the place
    /// an earlier run kept after its own log failed; a log that cannot be saved keeps the
    /// place and says so.
    #[test]
    fn the_place_stays_when_a_run_with_nothing_to_fill_cannot_save_its_event_log() {
        let dir = folder("whole-log-fails");
        std::fs::write(dir.join("image.fill.json"), b"{}").unwrap();
        // A folder where the log goes: it cannot be opened.
        std::fs::create_dir(dir.join("image.events.jsonl")).unwrap();
        let result = run_on_whole_image(&dir);
        assert_eq!(result.end, FillEnd::NothingToDo);
        assert!(result.text().contains("event log"), "{}", result.text());
        assert!(
            dir.join("image.fill.json").exists(),
            "the place went with no event saved"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        // With the log savable, the line is written and the place goes.
        let dir = folder("whole-log-saves");
        std::fs::write(dir.join("image.fill.json"), b"{}").unwrap();
        let result = run_on_whole_image(&dir);
        assert!(result.problems.is_empty(), "{result:?}");
        assert!(!dir.join("image.fill.json").exists());
        let log = std::fs::read_to_string(dir.join("image.events.jsonl")).unwrap();
        assert!(log.contains(r#""event":"finished""#), "{log}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a run with nothing to fill whose folder cannot be opened says so, not an
    /// empty success.
    #[test]
    fn a_run_with_nothing_to_fill_says_when_the_folder_cannot_be_opened() {
        let dir = folder("whole-no-folder");
        let mut disk = finished_image(&dir, 64 << 10, 0..0);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let result = fill_gaps(
            plan,
            &mut disk,
            &FillOptions::default(),
            &mut readings(vec![0]),
            &mut ReadLimit::none(),
            &mut Waiter::none(),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut |_| {},
        );
        assert_eq!(result.end, FillEnd::NothingToDo);
        assert!(
            result.text().contains("could not be opened"),
            "{}",
            result.text()
        );
    }
}
