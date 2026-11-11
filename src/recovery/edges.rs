//! The edge check (manual step 42): two whole copies of damaged photos matched the damaged
//! file on every readable byte but one 512-byte sector right beside an unread area, a sector
//! the map held as rescued. A sector next to a failing one may have come back wrong without an
//! error. Started by the technician, the check reads again the rescued sectors within a few
//! sectors of every area not rescued, compares each with the image, and reports every one
//! that reads differently and every one that now fails to read.
//!
//! It reads only those sectors, each once, one at a time, through the rescue's own source,
//! whose reads are timed and ask the drive whether it is still there before a failure counts.
//! It never writes the source, never writes or changes the map, and never writes the image: a
//! sector that differs is reported, not repaired. `take_sector` is the separate step that
//! takes a sector the drive now returns alike on two reads into the image. The findings go to
//! a dated text file beside the image and one line in the image's event log. A drop or Stop
//! ends the check with its place kept beside the image; started again on the same map, it
//! carries on from there.
use std::ffi::OsStr;
use std::fs::File;
use std::ops::Range;
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::dest::{Folder, Guard};
use super::events::{Event, EventLog, Figures};
use super::image::{Map, Plan, Status};
use super::place;
use super::{write_all_at, BlockSource, ReadError};
use crate::tools::drives::bytes_text;
use crate::tools::drives::details::grouped;

/// The edge check's options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeOptions {
    /// Sectors read on each side of every area not rescued, 1 to 64. Default 8: 4 KiB of
    /// 512-byte sectors.
    pub distance: u32,
}

impl Default for EdgeOptions {
    fn default() -> Self {
        Self { distance: 8 }
    }
}

impl EdgeOptions {
    /// Refuses values outside their bounds.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=64).contains(&self.distance) {
            return Err(format!("distance must be 1 to 64, not {}", self.distance));
        }
        Ok(())
    }
}

/// The time the first read of a stretch is taken to need: a seek, as on a hard drive.
const STRETCH_SECS: f64 = 0.02;
/// The time each sector read is taken to need: trimming's sector reads ran at about 1 MB/s
/// on a failing drive, half a millisecond a sector; twice that.
const SECTOR_SECS: f64 = 0.001;
/// How often the place is kept while the check reads, for a check the process did not end.
const KEEP_EVERY: Duration = Duration::from_secs(30);

/// What the check reads, said before it starts: how many sectors, and about how long.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePlan {
    pub distance: u32,
    pub sector: u32,
    /// Areas not rescued: each run of blocks the map does not hold as rescued, once.
    pub areas: u64,
    /// The rescued sectors beside them, all read by a whole check.
    pub sectors: u64,
    /// Of them, still to read from where a stopped check on this map left off.
    pub left: u64,
    /// Where that check stopped; None when the check starts from the beginning.
    pub from: Option<u64>,
    /// About how long reading what is left takes while the sectors read back.
    pub estimate_secs: u64,
    /// The stretches of rescued sectors read, in order.
    #[serde(skip)]
    stretches: Vec<Range<u64>>,
}

impl EdgePlan {
    /// The check of `map` read in `sector`-byte sectors, from byte `from` on.
    fn of(map: &Map, sector: u32, distance: u32, from: Option<u64>) -> Self {
        let size = u64::from(sector.max(1));
        let (areas, stretches) = edges(map, size, u64::from(distance));
        let at = from.unwrap_or(0);
        let (mut sectors, mut left, mut parts) = (0, 0, 0);
        for stretch in &stretches {
            sectors += (stretch.end - stretch.start) / size;
            let start = stretch.start.max(at);
            if start < stretch.end {
                left += (stretch.end - start) / size;
                parts += 1;
            }
        }
        let estimate = parts as f64 * STRETCH_SECS + left as f64 * SECTOR_SECS;
        Self {
            distance,
            sector,
            areas,
            sectors,
            left,
            from,
            estimate_secs: estimate.ceil() as u64,
            stretches,
        }
    }

    /// For the window before it starts: what is read and about how long it takes.
    pub fn text(&self) -> String {
        if self.sectors == 0 {
            return "Nothing to read: the map shows no rescued sector beside an area not rescued."
                .into();
        }
        let reach = u64::from(self.distance) * u64::from(self.sector);
        let mut text = format!(
            "The edge check reads again {} {} ({}): the rescued sectors within {} {} ({}) of each of the {} {} not rescued, and compares each with the image.",
            grouped(u128::from(self.sectors)),
            plural(self.sectors, "sector", "sectors"),
            bytes_text(self.sectors * u64::from(self.sector)),
            self.distance,
            plural(u64::from(self.distance), "sector", "sectors"),
            bytes_text(reach),
            grouped(u128::from(self.areas)),
            plural(self.areas, "area", "areas"),
        );
        if let Some(at) = self.from {
            text.push_str(&format!(
                " It carries on from {}, where the last check stopped: {} left.",
                bytes_text(at),
                grouped(u128::from(self.left))
            ));
        }
        text.push_str(&format!(
            " About {}; a sector that fails to read can take up to {} s more. Nothing is written to the drive, the map or the image.",
            time_text(self.estimate_secs),
            super::disk::READ_LIMIT.as_secs()
        ));
        text
    }
}

/// The areas `map` does not hold as rescued, and the stretches of whole rescued `sector`-byte
/// sectors within `distance` sectors of them, in order and joined where they meet. An area is
/// each run of blocks not rescued, so the rescued bytes between two areas are all rescued.
fn edges(map: &Map, sector: u64, distance: u64) -> (u64, Vec<Range<u64>>) {
    let reach = distance * sector;
    let mut areas: Vec<Range<u64>> = Vec::new();
    for block in map.blocks.iter().filter(|b| b.status != Status::Rescued) {
        match areas.last_mut() {
            Some(last) if last.end == block.pos => last.end = block.end(),
            _ => areas.push(block.pos..block.end()),
        }
    }
    let mut stretches: Vec<Range<u64>> = Vec::new();
    for (i, area) in areas.iter().enumerate() {
        let floor = if i == 0 { 0 } else { areas[i - 1].end };
        let ceiling = areas.get(i + 1).map_or(map.len(), |next| next.start);
        let before = area.start.saturating_sub(reach).max(floor)..area.start;
        let after = area.end..area.end.saturating_add(reach).min(ceiling);
        for side in [before, after] {
            // Whole sectors only: a sector part of an area is the area's. A first sector
            // boundary past u64::MAX leaves no whole sector in the side.
            let Some(lo) = side.start.div_ceil(sector).checked_mul(sector) else {
                continue;
            };
            let hi = side.end / sector * sector;
            if lo >= hi {
                continue;
            }
            match stretches.last_mut() {
                Some(last) if last.end >= lo => last.end = last.end.max(hi),
                _ => stretches.push(lo..hi),
            }
        }
    }
    (areas.len() as u64, stretches)
}

/// The edge check of the image and map `plan` names, read in `source`'s sectors, as a check
/// started now would read it: from where a stopped check on this map left off.
pub fn edge_plan(plan: &Plan, source: &dyn BlockSource, options: &EdgeOptions) -> EdgePlan {
    let id = PlanId::of(&plan.map, options, source);
    let place = place::held(&plan.image, source)
        .ok()
        .and_then(|(guard, folder)| place_for(&guard, &folder, plan, &id));
    EdgePlan::of(&plan.map, id.sector, id.distance, place.map(|p| p.at))
}

/// How a sector read now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reread {
    /// It read, with these bytes' SHA-256, other than the image's.
    Differs { drive: String },
    /// It failed: the read error, or that it timed out.
    Failed { error: String },
}

/// A sector that read differently from the image, or failed to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The sector's number on the drive, and its first byte.
    pub sector: u64,
    pub at: u64,
    /// The SHA-256 of the image's bytes for it.
    pub image: String,
    pub now: Reread,
}

impl Finding {
    /// The findings file's row: sector, byte, the image's hash, and the drive's or its error.
    fn row(&self) -> String {
        let now = match &self.now {
            Reread::Differs { drive } => drive.clone(),
            Reread::Failed { error } => error.clone(),
        };
        format!("{}\t{}\t{}\t{now}", self.sector, self.at, self.image)
    }
}

/// How the check ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeEnd {
    /// Every sector planned was read.
    Finished,
    /// No rescued sector lies beside an area not rescued: nothing was read.
    NothingToDo,
    /// Stop, at this byte; started again on this map, the check carries on from it.
    Stopped(u64),
    /// The drive stopped answering; says where. Started again, the check carries on there.
    Gone(String),
    /// The options were refused, or the image or its folder could not be read or written.
    Failed(String),
}

/// What the check did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeResult {
    pub end: EdgeEnd,
    pub plan: EdgePlan,
    /// Sectors read, a stopped check's before this one included.
    pub read: u64,
    /// Every sector that read differently or failed, a stopped check's included.
    pub found: Vec<Finding>,
    /// The findings file beside the image.
    pub findings: Option<PathBuf>,
    /// What could not be written: the findings file, the event log line, the place.
    pub problems: Vec<String>,
}

impl EdgeResult {
    fn ended(end: EdgeEnd, plan: EdgePlan) -> Self {
        Self {
            end,
            plan,
            read: 0,
            found: Vec::new(),
            findings: None,
            problems: Vec::new(),
        }
    }

    /// Sectors that read differently from the image.
    pub fn differ(&self) -> u64 {
        self.found
            .iter()
            .filter(|f| matches!(f.now, Reread::Differs { .. }))
            .count() as u64
    }

    /// Sectors that failed to read now.
    pub fn failed(&self) -> u64 {
        self.found.len() as u64 - self.differ()
    }

    /// For the window and the command line: how it ended, what it found, and where.
    pub fn text(&self) -> String {
        let counts = format!(
            "{} of {} {} read: {} read differently from the image, {} failed to read now.",
            grouped(u128::from(self.read)),
            grouped(u128::from(self.plan.sectors)),
            plural(self.plan.sectors, "sector", "sectors"),
            grouped(u128::from(self.differ())),
            grouped(u128::from(self.failed())),
        );
        let mut text = match &self.end {
            EdgeEnd::Finished => format!("The edge check finished. {counts}"),
            EdgeEnd::NothingToDo => {
                "Nothing to check: the map shows no rescued sector beside an area not rescued."
                    .into()
            }
            EdgeEnd::Stopped(at) => format!(
                "The edge check stopped at {}; started again on this map it carries on from there. {counts}",
                bytes_text(*at)
            ),
            EdgeEnd::Gone(why) => format!("The edge check stopped: {why} {counts}"),
            EdgeEnd::Failed(why) => format!("The edge check could not go on: {why}"),
        };
        if self.differ() > 0 {
            text.push_str(" A sector that reads differently is reported, not repaired.");
        }
        if let Some(name) = self.findings.as_ref().and_then(|p| p.file_name()) {
            text.push_str(&format!(" Findings: {}.", name.to_string_lossy()));
        }
        for problem in &self.problems {
            text.push(' ');
            text.push_str(problem);
        }
        text
    }
}

/// The check as it goes, for the window: set by the check, read by the window.
#[derive(Default)]
pub struct EdgeStatus {
    /// Sectors planned in all, and read so far, a stopped check's included.
    pub planned: AtomicU64,
    pub read: AtomicU64,
    pub differ: AtomicU64,
    pub failed: AtomicU64,
    /// The byte being read.
    pub at: AtomicU64,
    /// The end text, once it ended.
    pub ended: Mutex<Option<String>>,
}

impl EdgeStatus {
    /// "Edge check: 120 of 4,000 sectors read; 1 read differently, 0 failed to read now."
    pub fn text(&self) -> String {
        if let Some(ended) = self.ended.lock().ok().and_then(|e| e.clone()) {
            return ended;
        }
        let planned = self.planned.load(Ordering::Relaxed);
        format!(
            "Edge check: {} of {} {} read; {} read differently, {} failed to read now.",
            grouped(u128::from(self.read.load(Ordering::Relaxed))),
            grouped(u128::from(planned)),
            plural(planned, "sector", "sectors"),
            grouped(u128::from(self.differ.load(Ordering::Relaxed))),
            grouped(u128::from(self.failed.load(Ordering::Relaxed))),
        )
    }

    fn end(&self, result: &EdgeResult) {
        if let Ok(mut ended) = self.ended.lock() {
            *ended = Some(result.text());
        }
    }
}

/// What a check's plan is made from: the map, by its blocks' print, the distance and the
/// sector size it is read in. A place is kept with it and taken only for the same, whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PlanId {
    map: String,
    distance: u32,
    sector: u32,
}

impl PlanId {
    fn of(map: &Map, options: &EdgeOptions, source: &dyn BlockSource) -> Self {
        Self {
            map: map_print(map),
            distance: options.distance,
            sector: source.sector_size().max(1),
        }
    }
}

/// Where a stopped check left off, kept beside the image with its plan's identity, so a map
/// changed since (Fill the gaps, a resumed rescue), another distance or another sector size
/// starts the check afresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EdgePlace {
    plan: PlanId,
    /// The first sector not read yet.
    at: u64,
    read: u64,
    found: Vec<Finding>,
}

/// The file beside the image that keeps a stopped check's place.
pub fn place_path(image: &Path) -> PathBuf {
    image.with_extension("edges.json")
}

/// A print of the map's blocks: what the check reads depends on nothing else.
fn map_print(map: &Map) -> String {
    let blocks: String = map
        .blocks
        .iter()
        .map(|b| format!("{} {} {}\n", b.pos, b.size, b.status.symbol()))
        .collect();
    sha256_hex(blocks.as_bytes())
}

/// The place kept beside `plan`'s image when it is of the plan `id` names.
fn place_for(guard: &Guard, folder: &Folder, plan: &Plan, id: &PlanId) -> Option<EdgePlace> {
    let path = place_path(&plan.image);
    let place: EdgePlace = place::read(guard, folder, path.file_name()?)?;
    (place.plan == *id && place.at <= plan.map.len()).then_some(place)
}

fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Refuses what the check and `take_sector` are not to read: no image and map yet, a map not
/// confirmed as this drive's, or a drive of another size than the map.
fn ready(plan: &Plan, source: &dyn BlockSource) -> Result<(), String> {
    if !plan.resumed {
        return Err(format!(
            "{} has no image and map to check yet",
            plan.image.parent().unwrap_or(Path::new("")).display()
        ));
    }
    if let Some(why) = &plan.unconfirmed {
        return Err(format!(
            "{why} The edge check reads it only once you confirm it is this drive's."
        ));
    }
    if source.len() != plan.map.len() {
        return Err(format!(
            "the drive holds {} and the map {}; the map is not this drive's",
            bytes_text(source.len()),
            bytes_text(plan.map.len())
        ));
    }
    Ok(())
}

/// Reads `buf.len()` bytes of the image at `at`.
fn read_image(file: &File, at: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match file.seek_read(&mut buf[done..], at + done as u64)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => done += n,
        }
    }
    Ok(())
}

/// Writes one line to the image's event log, opened and closed for it; why not, when not.
fn log_line(guard: &Guard, folder: &Folder, plan: &Plan, event: &Event) -> Option<String> {
    let path = super::events::path_for(&plan.image);
    let opened = super::writer::open_beside(guard, folder, path.file_name().unwrap_or_default());
    let log = EventLog::default();
    log.start(path, opened);
    log.write(event, Figures::of(&plan.map));
    log.finish()
}

fn stamp(time: SystemTime) -> String {
    let s = crate::clock::local(time);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        s.year, s.month, s.day, s.hour, s.minute, s.second
    )
}

/// The edge check of the image and map `plan` names, reading `source`, the rescue's own
/// source for the drive. `stop` ends it at the next sector with its place kept, and `status`
/// shows it as it goes. Before starting, `edge_plan` says what it reads and about how long.
pub fn check_edges(
    plan: &Plan,
    source: &mut dyn BlockSource,
    options: &EdgeOptions,
    stop: &AtomicBool,
    status: &EdgeStatus,
) -> EdgeResult {
    let id = PlanId::of(&plan.map, options, source);
    let beside = options
        .check()
        .and_then(|()| ready(plan, source))
        .and_then(|()| place::held(&plan.image, source));
    let place = beside
        .as_ref()
        .ok()
        .and_then(|(guard, folder)| place_for(guard, folder, plan, &id));
    let edge = EdgePlan::of(
        &plan.map,
        id.sector,
        id.distance,
        place.as_ref().map(|p| p.at),
    );
    status.planned.store(edge.sectors, Ordering::Relaxed);
    let (guard, folder) = match &beside {
        Ok(held) => held,
        // Refused before the folder is held: no place is read, kept or removed.
        Err(why) => {
            let result = EdgeResult::ended(EdgeEnd::Failed(why.clone()), edge);
            status.end(&result);
            return result;
        }
    };
    let place_name = place_path(&plan.image);
    let place_name = place_name.file_name().unwrap_or_default();
    let mut result = EdgeResult::ended(EdgeEnd::Finished, edge);
    // Every way the check ends from here goes through `place::finish`.
    let complete = match File::open(&plan.image) {
        Err(e) => {
            result.end =
                EdgeEnd::Failed(format!("{} could not be opened: {e}", plan.image.display()));
            false
        }
        Ok(_) if result.plan.sectors == 0 => {
            result.end = EdgeEnd::NothingToDo;
            true
        }
        Ok(image) => Check {
            plan,
            id: &id,
            guard,
            folder,
            place_name,
            stop,
            status,
        }
        .read(source, image, place, &mut result),
    };
    let event = Event::EdgesChecked {
        distance: options.distance,
        planned: result.plan.sectors,
        read: result.read,
        differ: result.differ(),
        failed: result.failed(),
        ended: result.text(),
        findings: result.findings.as_ref().map(|p| p.display().to_string()),
    };
    // A finished check's place goes only once its findings and its log line are written and
    // synced: either one that failed is made again from the place.
    result
        .problems
        .extend(place::finish(&beside, place_name, complete, || {
            log_line(guard, folder, plan, &event)
        }));
    status.end(&result);
    result
}

/// A check with its image's folder held and its image open, reading by the plan `id` names.
struct Check<'a> {
    plan: &'a Plan,
    id: &'a PlanId,
    guard: &'a Guard,
    folder: &'a Folder,
    place_name: &'a OsStr,
    stop: &'a AtomicBool,
    status: &'a EdgeStatus,
}

impl Check<'_> {
    /// Keeps the place a later check carries on from; why not, when not.
    fn keep(&self, at: u64, read: u64, found: &[Finding]) -> Option<String> {
        let place = EdgePlace {
            plan: self.id.clone(),
            at,
            read,
            found: found.to_vec(),
        };
        let json = serde_json::to_vec(&place).ok()?;
        super::writer::save_map(self.guard, self.folder, self.place_name, &json, false)
            .err()
            .map(|e| {
                format!(
                    "The place could not be kept for a later check: {}.",
                    e.error
                )
            })
    }

    /// Reads the planned sectors from where `place` left off into `result`, keeping the
    /// place as it goes and where it stops, then writes the findings; true when every
    /// sector was read and the findings were saved.
    fn read(
        &self,
        source: &mut dyn BlockSource,
        image: File,
        place: Option<EdgePlace>,
        result: &mut EdgeResult,
    ) -> bool {
        let started = SystemTime::now();
        let size = u64::from(self.id.sector);
        let status = self.status;
        let (from, carried) = match place {
            Some(place) => {
                result.read = place.read;
                result.found = place.found;
                (place.at, true)
            }
            None => (0, false),
        };
        status.read.store(result.read, Ordering::Relaxed);
        status.differ.store(result.differ(), Ordering::Relaxed);
        status.failed.store(result.failed(), Ordering::Relaxed);
        let mut drive = vec![0u8; self.id.sector as usize];
        let mut held = vec![0u8; self.id.sector as usize];
        let mut kept = Instant::now();
        let mut left_at = None;
        'stretches: for stretch in result.plan.stretches.clone() {
            let mut at = stretch.start.max(from);
            while at < stretch.end {
                if self.stop.load(Ordering::Relaxed) {
                    result.end = EdgeEnd::Stopped(at);
                    left_at = Some(at);
                    break 'stretches;
                }
                status.at.store(at, Ordering::Relaxed);
                if let Err(e) = read_image(&image, at, &mut held) {
                    result.end = EdgeEnd::Failed(format!(
                        "{} could not be read at byte {at}: {e}",
                        self.plan.image.display()
                    ));
                    left_at = Some(at);
                    break 'stretches;
                }
                let now = match source.read_at(at, &mut drive) {
                    Ok(()) if drive == held => None,
                    Ok(()) => Some(Reread::Differs {
                        drive: sha256_hex(&drive),
                    }),
                    Err(failed @ (ReadError::Bad(_) | ReadError::TimedOut)) => {
                        Some(Reread::Failed {
                            error: error_text(&failed),
                        })
                    }
                    // The sector in flight is read again when the check carries on.
                    Err(ReadError::Gone(code)) => {
                        result.end = EdgeEnd::Gone(format!(
                            "the drive stopped answering (error {code}) at byte {at}: it was unplugged or has failed. Plug it back in and start the edge check again; it carries on from there."
                        ));
                        left_at = Some(at);
                        break 'stretches;
                    }
                };
                result.read += 1;
                status.read.store(result.read, Ordering::Relaxed);
                if let Some(now) = now {
                    let counter = match now {
                        Reread::Differs { .. } => &status.differ,
                        Reread::Failed { .. } => &status.failed,
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                    result.found.push(Finding {
                        sector: at / size,
                        at,
                        image: sha256_hex(&held),
                        now,
                    });
                }
                at += size;
                if kept.elapsed() >= KEEP_EVERY {
                    kept = Instant::now();
                    if let Some(problem) = self.keep(at, result.read, &result.found) {
                        result.problems.push(problem);
                    }
                }
            }
        }
        drop(image);
        if let Some(at) = left_at {
            if let Some(problem) = self.keep(at, result.read, &result.found) {
                result.problems.push(problem);
            }
        }
        let (report, problem) = write_findings(
            self.guard,
            self.folder,
            self.plan,
            source.describe(),
            result,
            carried.then_some(from),
            started,
        );
        result.findings = report;
        let findings_saved = problem.is_none();
        result.problems.extend(problem);
        left_at.is_none() && findings_saved
    }
}

/// Writes the findings beside the image as `<image name>.edges-<date and time>.txt`; its
/// path, and why it is missing or incomplete.
fn write_findings(
    guard: &Guard,
    folder: &Folder,
    plan: &Plan,
    drive: String,
    result: &EdgeResult,
    carried_from: Option<u64>,
    started: SystemTime,
) -> (Option<PathBuf>, Option<String>) {
    let s = crate::clock::local(started);
    let name = format!(
        "{}.edges-{:04}{:02}{:02}-{:02}{:02}{:02}.txt",
        plan.image.file_name().unwrap_or_default().to_string_lossy(),
        s.year,
        s.month,
        s.day,
        s.hour,
        s.minute,
        s.second
    );
    let edge = &result.plan;
    let mut text = String::new();
    text.push_str("Edge check: the rescued sectors beside the areas not rescued, read again\r\n");
    text.push_str(&format!("Image: {}\r\n", plan.image.display()));
    text.push_str(&format!("Map: {}\r\n", plan.map_path.display()));
    text.push_str(&format!("Drive: {drive}\r\n"));
    text.push_str(&format!(
        "Started: {}; ended: {}\r\n",
        stamp(started),
        stamp(SystemTime::now())
    ));
    text.push_str(&format!(
        "Read: the rescued sectors within {} {} of each of the {} {} not rescued, {} {} of {} bytes.\r\n",
        edge.distance,
        plural(u64::from(edge.distance), "sector", "sectors"),
        grouped(u128::from(edge.areas)),
        plural(edge.areas, "area", "areas"),
        grouped(u128::from(edge.sectors)),
        plural(edge.sectors, "sector", "sectors"),
        edge.sector
    ));
    if let Some(at) = carried_from {
        text.push_str(&format!(
            "Carried on from byte {at}, where the check before stopped; its findings are included.\r\n"
        ));
    }
    text.push_str(&format!("{}\r\n", result.text()));
    text.push_str(
        "The map and the image were not changed: a sector that reads differently is reported, not repaired.\r\n\r\n",
    );
    text.push_str("Sector\tByte\tImage SHA-256\tDrive SHA-256 or read error\r\n");
    for finding in &result.found {
        text.push_str(&finding.row());
        text.push_str("\r\n");
    }
    if result.found.is_empty() {
        text.push_str("None.\r\n");
    }
    text.push_str("\r\nEnd of report.\r\n");
    let (made, ended) = super::writer::write_lone_report(guard, folder, &name, text.as_bytes());
    let problem = made
        .error
        .map(|why| format!("The findings file {name} is incomplete: {why}."))
        .or_else(|| ended.filter(|e| e.contains("PARTIAL")));
    (made.path, problem)
}

/// What `take_sector` did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Taken {
    pub at: u64,
    pub length: u64,
    /// The SHA-256 of the image's bytes before, and of the drive's bytes now.
    pub image_was: String,
    pub now: String,
    /// The image held other bytes and now holds the drive's; false when it held them.
    pub written: bool,
}

/// Takes the rescued sector at byte `at` from the drive into the image, asked for on its
/// own after the edge check: only when the drive returns it alike on two reads in a row, so
/// the image then holds what the drive reads now. The map is not changed (the sector stays
/// rescued) and the event log says what was replaced. A sector not held as rescued is Fill
/// the gaps' to read.
pub fn take_sector(plan: &Plan, source: &mut dyn BlockSource, at: u64) -> Result<Taken, String> {
    ready(plan, source)?;
    let size = u64::from(source.sector_size().max(1));
    if !at.is_multiple_of(size) || at.saturating_add(size) > plan.map.len() {
        return Err(format!(
            "byte {at} does not start a {size}-byte sector of the drive"
        ));
    }
    if !plan.map.all(at, size, Status::Rescued) {
        return Err(format!(
            "the sector at byte {at} is not held as rescued in the map; Fill the gaps reads what is not rescued"
        ));
    }
    let read = |source: &mut dyn BlockSource| {
        let mut buf = vec![0u8; size as usize];
        source.read_at(at, &mut buf).map(|()| buf).map_err(|e| {
            format!(
                "the sector at byte {at} did not read ({}); the image is left as it was",
                error_text(&e)
            )
        })
    };
    let first = read(source)?;
    let second = read(source)?;
    if first != second {
        return Err(format!(
            "the drive returned different bytes on two reads in a row at byte {at}; the image is left as it was"
        ));
    }
    let (guard, folder) = place::held(&plan.image, source)?;
    let name = plan.image.file_name().unwrap_or_default();
    let mut image = super::writer::open_image(&guard, &folder, name, true)
        .map_err(|e| format!("{} could not be opened: {e}", plan.image.display()))?;
    let mut held = vec![0u8; size as usize];
    read_image(&image, at, &mut held)
        .map_err(|e| format!("{} could not be read: {e}", plan.image.display()))?;
    let taken = Taken {
        at,
        length: size,
        image_was: sha256_hex(&held),
        now: sha256_hex(&first),
        written: held != first,
    };
    if taken.written {
        write_all_at(&mut image, &first, at)
            .and_then(|()| image.sync_data())
            .map_err(|e| format!("{} could not be written: {e}", plan.image.display()))?;
        let event = Event::SectorTaken {
            at,
            length: size,
            image_was: taken.image_was.clone(),
            now: taken.now.clone(),
        };
        if let Some(problem) = log_line(&guard, &folder, plan, &event) {
            return Err(format!(
                "the sector was written into the image, but not logged: {problem}"
            ));
        }
    }
    Ok(taken)
}

/// A failed read, for people and the findings file.
fn error_text(error: &ReadError) -> String {
    match error {
        ReadError::Bad(code) => format!("read error {code}"),
        ReadError::TimedOut => "the read timed out".into(),
        ReadError::Gone(code) => format!("the drive stopped answering (error {code})"),
    }
}

fn plural<'a>(n: u64, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 {
        one
    } else {
        many
    }
}

fn time_text(secs: u64) -> String {
    match secs {
        0..=89 => format!("{} s", secs.max(1)),
        90..=5399 => format!("{} min", (secs + 30) / 60),
        _ => format!("{:.1} h", secs as f64 / 3600.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::image::plan_with;
    use crate::recovery::MemDisk;

    const LEN: usize = 256 << 10;

    fn folder(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("diagtool-edges-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 / 512 + i) as u8).collect()
    }

    /// The areas not rescued: a bad first sector, a bad area, a non-trimmed area and an
    /// untried sector two sectors past it, and a bad last sector.
    fn unread() -> Vec<(u64, u64, Status)> {
        vec![
            (0, 512, Status::Bad),
            (65_536, 4096, Status::Bad),
            (102_400, 2048, Status::NonTrimmed),
            (105_472, 512, Status::Untried),
            (LEN as u64 - 512, 512, Status::Bad),
        ]
    }

    /// The rescued sectors within 8 sectors of them, in order: 50.
    fn neighbours() -> Vec<u64> {
        [
            512..4608,
            61_440..65_536,
            69_632..73_728,
            98_304..102_400,
            104_448..105_472,
            105_984..110_080,
            257_536..261_632,
        ]
        .into_iter()
        .flat_map(|r| r.step_by(512))
        .collect()
    }

    fn map() -> Map {
        let mut map = Map::new(LEN as u64);
        map.set(0, LEN as u64, Status::Rescued);
        for (pos, size, status) in unread() {
            map.set(pos, size, status);
        }
        map
    }

    /// An image in `dir` holding `disk`'s bytes, with the map above beside it, as a finished
    /// rescue leaves them; the drive then fails where the map says, and the plan to read it.
    fn imaged(dir: &Path, disk: &mut MemDisk) -> Plan {
        imaged_as(dir, "image", disk)
    }

    fn imaged_as(dir: &Path, stem: &str, disk: &mut MemDisk) -> Plan {
        std::fs::write(dir.join(format!("{stem}.img")), &disk.data).unwrap();
        std::fs::write(dir.join(format!("{stem}.map")), map().to_text(&[])).unwrap();
        disk.bad = unread()
            .iter()
            .map(|(pos, size, _)| *pos..pos + size)
            .collect();
        let mut plan = plan_with(&*disk, dir, stem, u64::MAX / 2, "NTFS").unwrap();
        plan.confirm();
        assert!(plan.resumed);
        plan
    }

    fn events(dir: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.join("image.events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn findings_text(result: &EdgeResult) -> String {
        std::fs::read_to_string(result.findings.as_ref().expect("a findings file")).unwrap()
    }

    #[test]
    fn the_plan_reads_whole_rescued_sectors_beside_each_area_and_says_so() {
        let plan = EdgePlan::of(&map(), 512, 8, None);
        assert_eq!(plan.areas, 5);
        assert_eq!(plan.sectors, 50);
        assert_eq!(plan.left, 50);
        let read: Vec<u64> = plan
            .stretches
            .iter()
            .flat_map(|r| r.clone().step_by(512))
            .collect();
        assert_eq!(read, neighbours());
        // 7 stretches at 20 ms and 50 sectors at 1 ms.
        assert_eq!(plan.estimate_secs, 1);
        let text = plan.text();
        assert!(
            text.contains("50 sectors (25.6 kB)") && text.contains("5 areas not rescued"),
            "{text}"
        );
        // Carried on from a place: only what lies at or after it is left.
        let later = EdgePlan::of(&map(), 512, 8, Some(69_632));
        assert_eq!((later.sectors, later.left), (50, 34));
        assert!(later.text().contains("carries on from"), "{}", later.text());
        // An area's edge inside a sector leaves that sector to the area.
        let mut odd = Map::new(16_384);
        odd.set(0, 16_384, Status::Rescued);
        odd.set(1000, 2000, Status::Bad);
        let (_, stretches) = edges(&odd, 512, 8);
        assert_eq!(stretches, vec![0..512, 3072..7096 / 512 * 512]);
        // Nothing rescued, nothing to read.
        assert_eq!(EdgePlan::of(&Map::new(16_384), 512, 8, None).sectors, 0);
    }

    /// The guard: a rescued sector beside a bad area that the drive now returns otherwise
    /// is reported, with the image's hash and the drive's; the sectors that match are not.
    #[test]
    fn a_sector_beside_a_bad_area_that_reads_differently_is_reported() {
        let dir = folder("differs");
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged(&dir, &mut disk);
        let was = disk.data[69_632..70_144].to_vec();
        disk.data[69_700] ^= 0x5a;
        let status = EdgeStatus::default();
        let result = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &status,
        );
        assert_eq!(result.end, EdgeEnd::Finished, "{result:?}");
        assert_eq!(result.read, 50);
        assert_eq!(
            result.found,
            vec![Finding {
                sector: 136,
                at: 69_632,
                image: sha256_hex(&was),
                now: Reread::Differs {
                    drive: sha256_hex(&disk.data[69_632..70_144]),
                },
            }]
        );
        assert_eq!((result.differ(), result.failed()), (1, 0));
        assert!(
            result.text().contains("1 read differently") && result.text().contains("Findings:"),
            "{}",
            result.text()
        );
        assert_eq!(status.text(), result.text());
        let text = findings_text(&result);
        assert!(
            text.contains(&format!("136\t69632\t{}\t", sha256_hex(&was)))
                && text.ends_with("End of report.\r\n"),
            "{text}"
        );
        let name = result.findings.as_ref().unwrap().file_name().unwrap();
        assert!(name.to_string_lossy().starts_with("image.img.edges-"));
        let lines = events(&dir);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["event"], "edges_checked");
        assert_eq!(lines[0]["differ"], 1);
        assert_eq!(lines[0]["read"], 50);
        // A whole check keeps no place.
        assert!(!place_path(&plan.image).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A rescued sector that fails to read now is reported as such, with its error.
    #[test]
    fn a_sector_that_now_fails_to_read_is_reported_as_failing() {
        let dir = folder("fails");
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged(&dir, &mut disk);
        disk.bad.push(61_440..61_952);
        disk.slow.push(104_448..104_960);
        let result = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert_eq!(result.end, EdgeEnd::Finished);
        let found: Vec<(u64, Reread)> =
            result.found.iter().map(|f| (f.at, f.now.clone())).collect();
        assert_eq!(
            found,
            vec![
                (
                    61_440,
                    Reread::Failed {
                        error: "read error 23".into()
                    }
                ),
                (
                    104_448,
                    Reread::Failed {
                        error: "the read timed out".into()
                    }
                ),
            ]
        );
        assert_eq!((result.differ(), result.failed()), (0, 2));
        assert!(findings_text(&result).contains("61440\t"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the check reads only the rescued sectors beside the areas not rescued,
    /// each once, one at a time, and changes nothing: the map file, the image and the drive
    /// are as they were, a sector that differs included.
    #[test]
    fn the_check_reads_only_the_neighbours_and_changes_nothing() {
        let dir = folder("unchanged");
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged(&dir, &mut disk);
        disk.data[4096] ^= 1;
        let drive = disk.data.clone();
        let map_before = std::fs::read(&plan.map_path).unwrap();
        let image_before = std::fs::read(&plan.image).unwrap();
        let result = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert_eq!(result.end, EdgeEnd::Finished);
        assert_eq!(result.differ(), 1);
        let reads: Vec<(u64, usize)> = neighbours().into_iter().map(|at| (at, 512)).collect();
        assert_eq!(disk.reads.len(), 50);
        assert_eq!(disk.reads, reads);
        assert_eq!(std::fs::read(&plan.map_path).unwrap(), map_before);
        assert_eq!(plan.map, map());
        assert_eq!(std::fs::read(&plan.image).unwrap(), image_before);
        assert_eq!(disk.data, drive);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A drop ends the check with its place kept; started again on the same map it carries
    /// on from the sector in flight, with what it found before; Stop keeps the place too.
    #[test]
    fn a_drop_stops_the_check_and_it_carries_on_from_there() {
        let dir = folder("drop");
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged(&dir, &mut disk);
        disk.data[69_632] ^= 1;
        // Stop before the first read: nothing read, the place at the first sector.
        let stopped = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(true),
            &EdgeStatus::default(),
        );
        assert_eq!(stopped.end, EdgeEnd::Stopped(512));
        assert!(disk.reads.is_empty());
        disk.dies_after = Some(20);
        let first = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert!(
            matches!(&first.end, EdgeEnd::Gone(why) if why.contains("carries on from there")),
            "{first:?}"
        );
        assert_eq!(first.read, 20);
        assert_eq!(first.differ(), 1);
        let in_flight = neighbours()[20];
        assert_eq!(disk.reads.last().map(|r| r.0), Some(in_flight));
        let ahead = edge_plan(&plan, &disk, &EdgeOptions::default());
        assert_eq!((ahead.from, ahead.left), (Some(in_flight), 30));
        // Another distance is another check: it starts afresh.
        let wider = edge_plan(&plan, &disk, &EdgeOptions { distance: 4 });
        assert_eq!(wider.from, None);
        let mut back = disk.again();
        let status = EdgeStatus::default();
        let second = check_edges(
            &plan,
            &mut back,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &status,
        );
        assert_eq!(second.end, EdgeEnd::Finished, "{second:?}");
        assert_eq!(second.read, 50);
        assert_eq!(back.reads.len(), 30);
        assert_eq!(back.reads[0].0, in_flight);
        assert_eq!(second.found.len(), 1);
        assert_eq!(second.found[0].at, 69_632);
        assert!(findings_text(&second).contains("Carried on from byte"));
        assert!(!place_path(&plan.image).exists());
        // One event line for each check: stopped, dropped, finished.
        assert_eq!(events(&dir).len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The map unconfirmed, or no image yet: the drive is not read.
    #[test]
    fn a_map_not_confirmed_is_not_checked() {
        let dir = folder("unconfirmed");
        let mut disk = MemDisk::new(data(LEN));
        let mut plan = imaged(&dir, &mut disk);
        plan.unconfirmed = Some("The map names no drive.".into());
        let result = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert!(matches!(result.end, EdgeEnd::Failed(_)), "{result:?}");
        assert!(disk.reads.is_empty());
        assert!(take_sector(&plan, &mut disk, 512).is_err());
        assert!(disk.reads.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a finished check's place is removed only after its findings are written;
    /// a report that cannot be made leaves it, so the check can be run again from it. The
    /// image's name is too long for the report's name and not for the place's.
    #[test]
    fn the_place_stays_until_the_findings_are_written() {
        let dir = folder("report-fails");
        let stem = "n".repeat(236);
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged_as(&dir, &stem, &mut disk);
        let stopped = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(true),
            &EdgeStatus::default(),
        );
        assert_eq!(stopped.end, EdgeEnd::Stopped(512));
        assert!(place_path(&plan.image).exists());
        let result = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert_eq!(result.end, EdgeEnd::Finished, "{result:?}");
        assert!(result.findings.is_none(), "{result:?}");
        assert!(
            result.problems.iter().any(|p| p.contains("findings file")),
            "{result:?}"
        );
        assert!(
            place_path(&plan.image).exists(),
            "the place went before the findings were written"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a finished check's place goes only once its log line is saved too; a log
    /// that cannot be written leaves it and says so.
    #[test]
    fn the_place_stays_until_the_log_line_is_written() {
        let dir = folder("log-fails");
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged(&dir, &mut disk);
        let stopped = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(true),
            &EdgeStatus::default(),
        );
        assert_eq!(stopped.end, EdgeEnd::Stopped(512));
        // A folder where the log goes: it cannot be opened.
        std::fs::remove_file(dir.join("image.events.jsonl")).unwrap();
        std::fs::create_dir(dir.join("image.events.jsonl")).unwrap();
        let result = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert_eq!(result.end, EdgeEnd::Finished, "{result:?}");
        assert!(
            result.problems.iter().any(|p| p.contains("event log")),
            "{result:?}"
        );
        assert!(
            place_path(&plan.image).exists(),
            "the place went before the log line was written"
        );
        // Run again with the log writable: the kept place ends the way any run ends, its log
        // line saved and then the place removed, whatever is left to read.
        std::fs::remove_dir(dir.join("image.events.jsonl")).unwrap();
        let again = check_edges(
            &plan,
            &mut disk,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert!(again.problems.is_empty(), "{again:?}");
        assert!(
            !place_path(&plan.image).exists(),
            "the kept place outlived a run that ended clean: {again:?}"
        );
        let log = std::fs::read_to_string(dir.join("image.events.jsonl")).unwrap();
        assert!(
            log.contains("EdgesChecked") || log.contains("edges_checked"),
            "{log}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (review F7): a place kept by a check read in 512-byte sectors is not taken
    /// by one read in 4096-byte sectors on the same map and distance, and a check with
    /// nothing to read ends as any other: its log line saved, then the place removed.
    #[test]
    fn a_place_of_another_sector_size_is_not_taken_and_nothing_to_read_ends_the_same() {
        let dir = folder("sector-size");
        // A bad first sector in every 4 KiB: no whole 4 KiB sector lies beside an area.
        let mut map = Map::new(LEN as u64);
        map.set(0, LEN as u64, Status::Rescued);
        for at in (0..LEN as u64).step_by(4096) {
            map.set(at, 512, Status::Bad);
        }
        std::fs::write(dir.join("image.img"), data(LEN)).unwrap();
        std::fs::write(dir.join("image.map"), map.to_text(&[])).unwrap();
        let mut small = MemDisk::new(data(LEN));
        let mut plan = plan_with(&small, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        plan.confirm();
        let stopped = check_edges(
            &plan,
            &mut small,
            &EdgeOptions::default(),
            &AtomicBool::new(true),
            &EdgeStatus::default(),
        );
        assert_eq!(stopped.end, EdgeEnd::Stopped(512), "{stopped:?}");
        assert_eq!(stopped.plan.sectors, 64 * 7);
        assert!(place_path(&plan.image).exists());
        let mut large = MemDisk::new(data(LEN));
        large.sector = 4096;
        let ahead = edge_plan(&plan, &large, &EdgeOptions::default());
        assert_eq!((ahead.sectors, ahead.from), (0, None));
        let result = check_edges(
            &plan,
            &mut large,
            &EdgeOptions::default(),
            &AtomicBool::new(false),
            &EdgeStatus::default(),
        );
        assert_eq!(result.end, EdgeEnd::NothingToDo, "{result:?}");
        assert!(result.problems.is_empty(), "{result:?}");
        assert!(large.reads.is_empty());
        assert!(
            !place_path(&plan.image).exists(),
            "a check with nothing to read left the place"
        );
        // One event line for each check: stopped, nothing to read.
        assert_eq!(events(&dir).len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the check reads, keeps and removes its place through the folder it
    /// opened and checked, never by a path that can lead elsewhere by then.
    #[test]
    fn the_place_is_reached_only_through_the_held_folder() {
        let code = include_str!("edges.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(
            !code.contains("place::remove("),
            "edges.rs removes a place outside place::finish"
        );
        for by_path in [
            "fs::remove_file(",
            "fs::read(",
            "fs::read_to_string(",
            "fs::write(",
        ] {
            assert!(!code.contains(by_path), "edges.rs uses {by_path}");
        }
    }

    /// The guard: a map whose last area ends at the top of the address space is planned
    /// without a sector boundary past u64::MAX wrapping to a low offset.
    #[test]
    fn a_map_ending_at_the_top_of_the_address_space_wraps_to_no_low_sector() {
        let mut top = Map::new(u64::MAX);
        top.set(0, u64::MAX, Status::Rescued);
        top.set(u64::MAX - 1000, 1000, Status::Bad);
        let (areas, stretches) = edges(&top, 512, 8);
        assert_eq!(areas, 1);
        assert_eq!(stretches, vec![u64::MAX - 4607..u64::MAX - 1023]);
        assert_eq!(EdgePlan::of(&top, 512, 8, None).sectors, 7);
    }

    /// A drive that returns a set sector otherwise on every other read.
    struct Wobbly {
        disk: MemDisk,
        at: u64,
        reads: u32,
    }

    impl BlockSource for Wobbly {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.disk.read_at(offset, buf)?;
            if offset == self.at {
                self.reads += 1;
                buf[0] ^= (self.reads % 2) as u8;
            }
            Ok(())
        }
        fn describe(&self) -> String {
            self.disk.describe()
        }
    }

    /// Taking a sector into the image is its own step: only a rescued sector the drive
    /// returns alike on two reads in a row is written, the map is left as it is, and the
    /// event log says what was replaced.
    #[test]
    fn a_sector_read_alike_twice_is_taken_into_the_image_and_logged() {
        let dir = folder("take");
        let mut disk = MemDisk::new(data(LEN));
        let plan = imaged(&dir, &mut disk);
        let map_before = std::fs::read(&plan.map_path).unwrap();
        let was = disk.data[69_632..70_144].to_vec();
        disk.data[69_632] ^= 0xff;
        let now = disk.data[69_632..70_144].to_vec();
        let taken = take_sector(&plan, &mut disk, 69_632).unwrap();
        assert_eq!(
            taken,
            Taken {
                at: 69_632,
                length: 512,
                image_was: sha256_hex(&was),
                now: sha256_hex(&now),
                written: true,
            }
        );
        assert_eq!(disk.reads, vec![(69_632, 512), (69_632, 512)]);
        let image = std::fs::read(&plan.image).unwrap();
        assert_eq!(&image[69_632..70_144], &now[..]);
        assert_eq!(image[..69_632], disk.data[..69_632]);
        assert_eq!(std::fs::read(&plan.map_path).unwrap(), map_before);
        let lines = events(&dir);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["event"], "sector_taken");
        assert_eq!(lines[0]["at"], 69_632);
        // The image now holds what the drive reads: nothing to write, nothing logged.
        let again = take_sector(&plan, &mut disk, 69_632).unwrap();
        assert!(!again.written);
        assert_eq!(events(&dir).len(), 1);
        // A sector not rescued, or not a sector's start, is not taken.
        assert!(take_sector(&plan, &mut disk, 65_536).is_err());
        assert!(take_sector(&plan, &mut disk, 69_633).is_err());
        // Two reads that differ: the image is left as it was.
        let mut wobbly = Wobbly {
            disk: disk.again(),
            at: 4096,
            reads: 0,
        };
        let why = take_sector(&plan, &mut wobbly, 4096).unwrap_err();
        assert!(why.contains("different bytes"), "{why}");
        assert_eq!(std::fs::read(&plan.image).unwrap(), image);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
