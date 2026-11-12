//! The drive's condition at a glance, for the strip under a recovery window's title, in a constant
//! stable location. It is built only from what the
//! rescue already records: the health readings and drops in its event log beside the image,
//! the readings it takes as it runs, and its reading speed. Nothing here asks the drive.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::health_log::{Counts, Reading};
use super::image::{rate_text, WearRate};
use super::timed::Throttle;
use crate::clock::local_seconds;
use crate::tools::drives::details::grouped;

/// How far back the trend lines reach, in seconds.
pub const TREND_SECS: i64 = 2 * 3600;
/// The span each change is measured over, in seconds.
pub const CHANGE_SECS: i64 = 30 * 60;
/// The most of an event log read when it is first followed: hours of readings and drops.
const TAIL_START: u64 = 4 << 20;

/// A cell's state color: ok, warn or bad by the app's thresholds, or unknown (gray).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unknown,
    Ok,
    Warn,
    Bad,
}

/// One answered health reading at a wall-clock second (`clock::local_seconds`).
#[derive(Clone, Debug, PartialEq)]
struct Sample {
    at: i64,
    nvme: bool,
    reallocated: Option<u64>,
    pending: Option<u64>,
    uncorrectable: Option<u64>,
    media_errors: Option<u64>,
    spare: Option<u64>,
    celsius: Option<i32>,
}

/// What the rescue recorded about one drive, kept for the trend lines' two hours.
#[derive(Clone, Debug, Default)]
pub struct History {
    samples: Vec<Sample>,
    /// When the latest run started, and the drops since.
    run_start: Option<i64>,
    drops: Vec<i64>,
    /// Bytes a second, from the run's progress events.
    rates: Vec<(i64, f64)>,
    /// The heat and error pauses the latest run started with.
    heat: Option<Throttle>,
    wear: Option<WearRate>,
    /// The last time the drive was asked for a reading, and whether it answered.
    asked: Option<(i64, bool)>,
}

impl History {
    /// Takes one line of a rescue's event log (`events.rs`); other lines are passed over.
    pub fn line(&mut self, line: &str) {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let Some(at) = value["time"].as_str().and_then(local_seconds) else {
            return;
        };
        let count = |key: &str| value[key].as_u64();
        match value["event"].as_str() {
            Some("started") => {
                self.run_start = Some(at);
                self.drops.clear();
                let settings = &value["settings"];
                self.heat = serde_json::from_value(settings["heat_pause"].clone()).ok();
                self.wear = serde_json::from_value(settings["error_pause"].clone()).ok();
            }
            Some("drive_gone") => self.drops.push(at),
            Some("progress") => {
                if let Some(rate) = value["bytes_per_second"].as_f64() {
                    self.rates.push((at, rate));
                }
            }
            Some("health") => match value["kind"].as_str() {
                Some(kind @ ("ATA" | "NVMe" | "temperature only")) => self.add(Sample {
                    at,
                    nvme: kind == "NVMe",
                    reallocated: count("reallocated"),
                    pending: count("pending"),
                    uncorrectable: count("uncorrectable"),
                    media_errors: count("media_errors"),
                    spare: count("available_spare"),
                    celsius: value["temperature_c"].as_i64().map(|c| c as i32),
                }),
                _ => self.asked(at, false),
            },
            _ => {}
        }
    }

    /// Takes a reading the run or the window just made (`health_log::Reading`).
    pub fn reading(&mut self, reading: &Reading) {
        let Some(at) = local_seconds(&reading.time) else {
            return;
        };
        let mut sample = Sample {
            at,
            nvme: false,
            reallocated: None,
            pending: None,
            uncorrectable: None,
            media_errors: None,
            spare: None,
            celsius: reading.celsius,
        };
        match &reading.counts {
            Counts::Ata {
                reallocated,
                pending,
                uncorrectable,
            } => {
                (sample.reallocated, sample.pending, sample.uncorrectable) =
                    (*reallocated, *pending, *uncorrectable);
            }
            Counts::Nvme {
                media_errors,
                spare,
            } => {
                sample.nvme = true;
                sample.media_errors = Some(u64::try_from(*media_errors).unwrap_or(u64::MAX));
                sample.spare = Some(u64::from(*spare));
            }
            Counts::TemperatureOnly(_) => {}
            Counts::Nothing(_) | Counts::NoAnswer(_) => return self.asked(at, false),
        }
        self.add(sample);
    }

    /// A reading in time order; the same reading from the log and from the run is kept once.
    fn add(&mut self, sample: Sample) {
        self.asked(sample.at, true);
        if self.samples.iter().any(|s| s.at == sample.at) {
            return;
        }
        let at = self.samples.partition_point(|s| s.at < sample.at);
        self.samples.insert(at, sample);
    }

    fn asked(&mut self, at: i64, answered: bool) {
        if self.asked.is_none_or(|(last, _)| at >= last) {
            self.asked = Some((at, answered));
        }
    }

    /// Lets go of what is older than the trend lines reach, keeping the reading before them.
    pub fn trim(&mut self, now: i64) {
        let cutoff = now - TREND_SECS;
        let first = self.samples.partition_point(|s| s.at < cutoff);
        self.samples.drain(..first.saturating_sub(1));
        let first = self.rates.partition_point(|r| r.0 < cutoff);
        self.rates.drain(..first.saturating_sub(1));
    }

    fn series(&self, pick: impl Fn(&Sample) -> Option<f64>) -> Vec<(i64, f64)> {
        self.samples
            .iter()
            .filter_map(|s| pick(s).map(|v| (s.at, v)))
            .collect()
    }
}

/// How fast the drive reads now, from the window that reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Speed {
    pub bytes_per_second: f64,
    /// What is left in the current pass, said ("0.45 GB left in this pass").
    pub left: Option<String>,
    /// The run is waiting (for the drive to cool or come back), not reading.
    pub waiting: bool,
}

/// What the window knows besides the history: the time, its own pauses, and the speed.
#[derive(Clone, Debug)]
pub struct Live {
    /// Now, in wall-clock seconds (`clock::Stamp::seconds`).
    pub now: i64,
    /// The heat and error pauses set in the window, for a drive no run has logged yet.
    pub heat: Throttle,
    pub wear: WearRate,
    /// None when nothing reads the drive.
    pub speed: Option<Speed>,
    /// How often the drive is read: "every 1 min", "once, when this window opened".
    pub every: String,
}

/// One cell of the strip.
#[derive(Clone, Debug, PartialEq)]
pub struct Cell {
    pub label: String,
    pub value: String,
    /// The change over the last 30 minutes.
    pub change: String,
    pub note: String,
    pub state: State,
    /// The last two hours: x from 0 (two hours ago) to 1 (now), and the value.
    pub trend: Vec<(f32, f64)>,
}

/// The strip: six cells, always in the same order, and the line under it.
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    pub cells: [Cell; 6],
    pub stamp: String,
}

fn clock_text(at: i64) -> String {
    let day = at.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", day / 3600, (day % 3600) / 60, day % 60)
}

fn short_clock(at: i64) -> String {
    clock_text(at)[..5].to_string()
}

/// The last value, and what it was 30 minutes ago (or at the first reading since, with
/// that reading's time when it is under 30 minutes old).
fn change_of(series: &[(i64, f64)], now: i64) -> Option<(f64, f64, Option<i64>)> {
    let last = series.last()?.1;
    let span = now - CHANGE_SECS;
    match series.iter().rev().find(|p| p.0 <= span) {
        Some(then) => Some((last, then.1, None)),
        None => series.first().map(|first| (last, first.1, Some(first.0))),
    }
}

/// "+72 in 30 min", "-8 since 15:41", "no change in 30 min"; `unit` follows the number.
fn change_text(series: &[(i64, f64)], now: i64, unit: &str) -> String {
    let Some((last, then, since)) = change_of(series, now) else {
        return String::new();
    };
    let span = match since {
        Some(at) if series.len() < 2 => return format!("first read at {}", short_clock(at)),
        Some(at) => format!("since {}", short_clock(at)),
        None => "in 30 min".into(),
    };
    let delta = last - then;
    if delta == 0.0 {
        return format!("no change {span}");
    }
    let sign = if delta > 0.0 { '+' } else { '-' };
    format!(
        "{sign}{}{unit} {span}",
        grouped(delta.abs().round() as u128)
    )
}

fn rise(series: &[(i64, f64)], now: i64) -> f64 {
    change_of(series, now).map_or(0.0, |(last, then, _)| last - then)
}

fn trend(series: &[(i64, f64)], now: i64) -> Vec<(f32, f64)> {
    let start = now - TREND_SECS;
    let first = series.partition_point(|p| p.0 < start).saturating_sub(1);
    series[first..]
        .iter()
        .map(|&(at, v)| {
            let x = ((at - start) as f32 / TREND_SECS as f32).clamp(0.0, 1.0);
            (x, v)
        })
        .collect()
}

fn unknown(label: &str, value: &str) -> Cell {
    Cell {
        label: label.into(),
        value: value.into(),
        change: String::new(),
        note: String::new(),
        state: State::Unknown,
        trend: Vec::new(),
    }
}

/// A sector count: ok at 0, warn above it, bad once it rose by the error pause's limit in its
/// window (the rate that pauses a rescue).
fn count_cell(
    label: &str,
    series: &[(i64, f64)],
    run_start: Option<i64>,
    wear: &WearRate,
    now: i64,
) -> Cell {
    let Some(&(_, last)) = series.last() else {
        return unknown(label, "not read");
    };
    let fast = wear.on && rise(series, now) >= wear.limit as f64;
    let state = if fast {
        State::Bad
    } else if last > 0.0 {
        State::Warn
    } else {
        State::Ok
    };
    let note = run_start
        .and_then(|start| series.iter().find(|p| p.0 >= start))
        .map(|first| last - first.1)
        .filter(|d| *d != 0.0)
        .map(|d| {
            let sign = if d > 0.0 { '+' } else { '-' };
            format!("{sign}{} this run", grouped(d.abs().round() as u128))
        })
        .unwrap_or_default();
    Cell {
        label: label.into(),
        value: grouped(last.round() as u128),
        change: change_text(series, now, ""),
        note,
        state,
        trend: trend(series, now),
    }
}

/// The strip's cells and line from `history` and what the window knows now.
pub fn condition(history: &History, live: &Live) -> Condition {
    let now = live.now;
    let heat = history.heat.unwrap_or(live.heat);
    let wear = history.wear.unwrap_or(live.wear);
    let nvme = history.samples.last().is_some_and(|s| s.nvme);

    let temps = history.series(|s| s.celsius.map(f64::from));
    let temperature = match temps.last() {
        Some(&(_, c)) => Cell {
            label: "Temperature".into(),
            value: format!("{c} C"),
            change: change_text(&temps, now, " C"),
            note: if heat.on {
                format!("pause at {}, resume {}", heat.pause_at, heat.resume_at)
            } else {
                "heat pause off".into()
            },
            state: match c as i32 {
                _ if !heat.on => State::Unknown,
                c if c >= heat.pause_at => State::Bad,
                c if c + 5 >= heat.pause_at => State::Warn,
                _ => State::Ok,
            },
            trend: trend(&temps, now),
        },
        None => unknown("Temperature", "not read"),
    };
    let as_f64 = |v: Option<u64>| v.map(|v| v as f64);
    let (second, third, fourth) = if nvme {
        let spare = history.series(|s| as_f64(s.spare));
        let errors = history.series(|s| as_f64(s.media_errors));
        let spare_cell = match spare.last() {
            Some(&(_, left)) => Cell {
                label: "Spare".into(),
                value: format!("{left} %"),
                change: change_text(&spare, now, " %"),
                note: "available spare".into(),
                state: if rise(&spare, now) < 0.0 {
                    State::Warn
                } else {
                    State::Ok
                },
                trend: trend(&spare, now),
            },
            None => unknown("Spare", "not read"),
        };
        let mut media = count_cell("Media errors", &errors, history.run_start, &wear, now);
        if errors.last().is_some_and(|e| e.1 > 0.0) {
            media.state = State::Bad;
        }
        (spare_cell, unknown("Pending", "not kept"), media)
    } else {
        let reallocated = history.series(|s| as_f64(s.reallocated));
        let pending = history.series(|s| as_f64(s.pending));
        let uncorrectable = history.series(|s| as_f64(s.uncorrectable));
        let mut bad = count_cell(
            "Uncorrectable",
            &uncorrectable,
            history.run_start,
            &wear,
            now,
        );
        if uncorrectable.last().is_some_and(|u| u.1 > 0.0) {
            bad.state = State::Bad;
        }
        if bad.note.is_empty() && !uncorrectable.is_empty() {
            bad.note = "reported by the drive".into();
        }
        (
            count_cell("Reallocated", &reallocated, history.run_start, &wear, now),
            count_cell("Pending", &pending, history.run_start, &wear, now),
            bad,
        )
    };
    let drops = {
        let mut total = 0.0;
        let series: Vec<(i64, f64)> = history
            .drops
            .iter()
            .map(|&at| {
                total += 1.0;
                (at, total)
            })
            .collect();
        let recent = history
            .drops
            .iter()
            .filter(|&&at| at > now - CHANGE_SECS)
            .count();
        let mut line = series.clone();
        if let Some(&(_, n)) = line.last() {
            line.push((now, n));
        }
        Cell {
            label: "Drops this run".into(),
            value: history.drops.len().to_string(),
            change: if history.run_start.is_some() {
                format!("+{recent} in 30 min")
            } else {
                String::new()
            },
            note: match history.drops.last() {
                Some(&at) => format!(
                    "last at {}, {} min ago",
                    short_clock(at),
                    (now - at).max(0) / 60
                ),
                None if history.run_start.is_some() => "none this run".into(),
                None => "no run logged".into(),
            },
            state: match (history.run_start, history.drops.len()) {
                (None, _) => State::Unknown,
                (_, 0) => State::Ok,
                _ => State::Warn,
            },
            trend: trend(&line, now),
        }
    };
    let rates: Vec<(i64, f64)> = history.rates.clone();
    let average = {
        let recent: Vec<f64> = rates
            .iter()
            .filter(|r| r.0 > now - CHANGE_SECS)
            .map(|r| r.1)
            .collect();
        (!recent.is_empty()).then(|| recent.iter().sum::<f64>() / recent.len() as f64)
    };
    let reading = match &live.speed {
        Some(speed) => Cell {
            label: "Reading".into(),
            value: if speed.waiting {
                "waiting".into()
            } else {
                rate_text(speed.bytes_per_second)
            },
            change: average
                .map(|a| format!("{} avg, 30 min", rate_text(a)))
                .unwrap_or_default(),
            note: speed.left.clone().unwrap_or_default(),
            state: if speed.waiting || speed.bytes_per_second <= 0.0 {
                State::Warn
            } else {
                State::Ok
            },
            trend: trend(&rates, now),
        },
        None => Cell {
            change: average
                .map(|a| format!("{} avg, 30 min", rate_text(a)))
                .unwrap_or_default(),
            note: "nothing reads the drive now".into(),
            trend: trend(&rates, now),
            ..unknown("Reading", "idle")
        },
    };
    let stamp = match history.asked {
        None => "No reading of this drive yet.".into(),
        Some((at, true)) => format!(
            "Drive read at {}, {}. Lines show the last 2 hours.",
            clock_text(at),
            live.every
        ),
        Some((at, false)) => format!(
            "The drive did not answer at {}; it is read {}. Lines show the last 2 hours.",
            clock_text(at),
            live.every
        ),
    };
    Condition {
        cells: [temperature, second, third, fourth, drops, reading],
        stamp,
    }
}

/// Follows a rescue's event log as it grows: each call gives the whole lines added since the
/// last. It reads only, and a log it cannot open gives nothing until it can.
#[derive(Debug)]
pub struct Tail {
    path: PathBuf,
    offset: u64,
    rest: Vec<u8>,
}

impl Tail {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            rest: Vec::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The whole lines added since the last call; a log first read starts at most
    /// `TAIL_START` before its end, from a whole line.
    pub fn read(&mut self) -> Vec<String> {
        crate::live::reading("a rescue's event log");
        let Ok(mut file) = File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(len) = file.seek(SeekFrom::End(0)) else {
            return Vec::new();
        };
        // A log made anew is followed from its start.
        if len < self.offset {
            self.offset = 0;
            self.rest.clear();
        }
        let skip_partial = self.offset == 0 && len > TAIL_START;
        if skip_partial {
            self.offset = len - TAIL_START;
        }
        let mut added = Vec::new();
        if file.seek(SeekFrom::Start(self.offset)).is_err() || file.read_to_end(&mut added).is_err()
        {
            return Vec::new();
        }
        self.offset += added.len() as u64;
        if skip_partial {
            let start = added
                .iter()
                .position(|b| *b == b'\n')
                .map_or(added.len(), |i| i + 1);
            added.drain(..start);
        }
        self.rest.extend_from_slice(&added);
        let Some(end) = self.rest.iter().rposition(|b| *b == b'\n') else {
            return Vec::new();
        };
        let whole: Vec<u8> = self.rest.drain(..=end).collect();
        String::from_utf8_lossy(&whole)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(String::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(now: i64) -> Live {
        Live {
            now,
            heat: Throttle::default(),
            wear: WearRate::default(),
            speed: None,
            every: "every 1 min".into(),
        }
    }

    fn health(time: &str, reallocated: u64, pending: u64, celsius: i32) -> String {
        format!(
            r#"{{"time":"{time}","event":"health","kind":"ATA","reallocated":{reallocated},"pending":{pending},"uncorrectable":1112,"media_errors":null,"available_spare":null,"temperature_c":{celsius},"note":"","state":"running"}}"#
        )
    }

    /// The guard: the strip reads the rescue's own log; each count's change is over the last
    /// 30 minutes, the drops are this run's with the time of the last, and the states follow
    /// the heat pause and the error pause the run started with.
    #[test]
    fn the_strip_follows_the_rescues_log() {
        let mut history = History::default();
        history.line(r#"{"time":"2026-11-10 14:00:00","event":"started","run":"rescue image","settings":{"heat_pause":{"on":true,"pause_at":38,"resume_at":30},"error_pause":{"on":true,"limit":1000,"minutes":30}},"state":"running"}"#);
        history.line(&health("2026-11-10 14:00:10", 15_000, 1_200, 30));
        history.line(&health("2026-11-10 15:30:00", 15_585, 1_120, 31));
        history.line(r#"{"time":"2026-11-10 15:41:00","event":"drive_gone","seen":"x","code":null,"state":"paused"}"#);
        history.line(r#"{"time":"2026-11-10 15:50:00","event":"progress","bytes_per_second":1200000,"state":"running"}"#);
        history.line(&health("2026-11-10 16:03:00", 15_657, 1_112, 32));
        history.line("not json");
        let now = local_seconds("2026-11-10 16:03:20").unwrap();
        let shown = condition(&history, &live(now));
        let [temp, realloc, pending, bad, drops, reading] = &shown.cells;
        assert_eq!(temp.value, "32 C");
        assert_eq!(temp.note, "pause at 38, resume 30");
        assert_eq!(temp.state, State::Ok);
        assert_eq!(realloc.value, "15,657");
        assert_eq!(realloc.change, "+72 in 30 min");
        assert_eq!(realloc.note, "+657 this run");
        assert_eq!(realloc.state, State::Warn);
        assert_eq!(pending.change, "-8 in 30 min");
        assert_eq!(bad.state, State::Bad);
        assert_eq!(bad.note, "reported by the drive");
        assert_eq!(drops.value, "1");
        assert_eq!(drops.note, "last at 15:41, 22 min ago");
        assert_eq!(drops.state, State::Warn);
        assert_eq!(reading.value, "idle");
        assert_eq!(reading.change, "1.2 MB/s avg, 30 min");
        assert_eq!(
            shown.stamp,
            "Drive read at 16:03:00, every 1 min. Lines show the last 2 hours."
        );
        // The trend lines start two hours back and end now.
        assert!(realloc.trend.iter().all(|p| (0.0..=1.0).contains(&p.0)));
        assert!(realloc.trend.last().unwrap().0 > 0.99);
        // Rising by the error pause's limit within its window is bad.
        history.line(&health("2026-11-10 16:10:00", 16_700, 1_112, 37));
        let now = local_seconds("2026-11-10 16:10:05").unwrap();
        let shown = condition(&history, &live(now));
        assert_eq!(shown.cells[1].state, State::Bad);
        assert_eq!(shown.cells[0].state, State::Warn, "within 5 C of the pause");
        // A new run counts its own drops.
        history.line(r#"{"time":"2026-11-10 16:20:00","event":"started","run":"fill the gaps","settings":{"heat_pause":{"on":true,"pause_at":38,"resume_at":30}},"state":"running"}"#);
        let shown = condition(&history, &live(now + 900));
        assert_eq!(shown.cells[4].value, "0");
        assert_eq!(shown.cells[4].note, "none this run");
    }

    #[test]
    fn a_drive_never_read_says_so_and_a_live_reading_counts_once() {
        let history = History::default();
        let shown = condition(&history, &live(0));
        assert_eq!(shown.stamp, "No reading of this drive yet.");
        assert!(shown.cells.iter().all(|c| c.state == State::Unknown));
        let mut history = History::default();
        let reading = Reading {
            time: "2026-11-10 16:03:00".into(),
            counts: Counts::Ata {
                reallocated: Some(0),
                pending: Some(0),
                uncorrectable: Some(0),
            },
            celsius: Some(29),
            pos: 0,
            bad: 0,
        };
        history.reading(&reading);
        history.line(&health("2026-11-10 16:03:00", 0, 0, 29));
        assert_eq!(history.samples.len(), 1);
        let now = local_seconds("2026-11-10 16:03:30").unwrap();
        let mut at = live(now);
        at.speed = Some(Speed {
            bytes_per_second: 45e6,
            left: Some("0.45 GB left in this pass".into()),
            waiting: false,
        });
        let shown = condition(&history, &at);
        assert_eq!(shown.cells[1].state, State::Ok);
        assert_eq!(shown.cells[1].change, "first read at 16:03");
        assert_eq!(shown.cells[5].value, "45.0 MB/s");
        assert_eq!(shown.cells[5].note, "0.45 GB left in this pass");
        assert_eq!(shown.cells[5].state, State::Ok);
        history.reading(&Reading {
            time: "2026-11-10 16:04:00".into(),
            counts: Counts::NoAnswer("no answer within 30 s".into()),
            celsius: None,
            pos: 0,
            bad: 0,
        });
        let shown = condition(&history, &at);
        assert!(shown
            .stamp
            .starts_with("The drive did not answer at 16:04:00"));
        history.trim(now + 3 * 3600);
        assert_eq!(
            history.samples.len(),
            1,
            "the reading before the window is kept"
        );
    }

    #[test]
    fn the_tail_gives_whole_lines_as_the_log_grows() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("diagtool-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image.events.jsonl");
        let mut tail = Tail::new(path.clone());
        assert!(tail.read().is_empty(), "no log yet");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"one\ntwo\nthr").unwrap();
        assert_eq!(tail.read(), ["one", "two"]);
        file.write_all(b"ee\n").unwrap();
        assert_eq!(tail.read(), ["three"]);
        assert!(tail.read().is_empty());
        drop(file);
        std::fs::write(&path, b"new\n").unwrap();
        assert_eq!(
            tail.read(),
            ["new"],
            "a log made anew is read from its start"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
