//! The drive's health over a rescue image. Each health reading the run takes (at the start,
//! between passes, every few minutes and at the end) is added as one line to
//! `<image name>.health.csv` beside the image, with the rescue's position and bad bytes at
//! that moment, so the technician can show the customer how the drive changed while it was
//! read. A drive that answers no health query, or a reading that does not come back, gets one
//! line saying so; the drive is still asked at every reading, and the next line comes once it
//! answers. Pauses for heat, a drive that stopped answering and came back, and a read limit
//! that could not be set get a line of their own.
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::events::Event;
use super::ledger::Ledger;
use crate::tools::drives::bytes_text;
use crate::tools::drives::health::{Disk, Health};

/// The first line of a new log.
pub const HEADER: &str = "time,kind,reallocated sectors,pending sectors,uncorrectable sectors,media errors,available spare %,temperature C,position bytes,bad bytes,note\r\n";

/// The log's file name for an image: `Disk 3 Samsung.img` gives `Disk 3 Samsung.health.csv`.
pub fn path_for(image: &Path) -> PathBuf {
    image.with_extension("health.csv")
}

/// The counts one reading gave.
#[derive(Clone, Debug, PartialEq)]
pub enum Counts {
    /// SMART attributes 5, 197 and 198; None where the drive does not keep one.
    Ata {
        reallocated: Option<u64>,
        pending: Option<u64>,
        uncorrectable: Option<u64>,
    },
    /// The NVMe health log's media errors and available spare.
    Nvme { media_errors: u128, spare: u8 },
    /// No counts, only the temperature Windows reports; says why.
    TemperatureOnly(String),
    /// The drive answered no health query; says why.
    Nothing(String),
    /// The reading did not come back; says why.
    NoAnswer(String),
}

/// A row's columns.
#[derive(Default)]
struct Row {
    kind: &'static str,
    reallocated: Option<u64>,
    pending: Option<u64>,
    uncorrectable: Option<u64>,
    media_errors: Option<u128>,
    spare: Option<u8>,
    note: String,
}

/// One line of the log.
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    pub time: String,
    pub counts: Counts,
    pub celsius: Option<i32>,
    pub pos: u64,
    pub bad: u64,
}

fn now() -> String {
    let s = crate::clock::local(SystemTime::now());
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        s.year, s.month, s.day, s.hour, s.minute, s.second
    )
}

/// A CSV field: quoted, with quotes doubled, when it holds a comma, quote or line break.
fn field(text: &str) -> String {
    if text.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

fn cell<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

impl Reading {
    /// What `disk` says, or why there is no reading, at the rescue's `pos` with `bad` bytes.
    pub fn of(disk: Result<&Disk, &str>, pos: u64, bad: u64) -> Self {
        let (counts, celsius) = match disk {
            Err(why) => (Counts::NoAnswer(why.to_string()), None),
            Ok(disk) => {
                let celsius = super::image::temperature(disk);
                let counts = match &disk.health {
                    Health::Ata(list) => {
                        let raw = |id: u8| list.iter().find(|a| a.id == id).map(|a| a.raw_value());
                        Counts::Ata {
                            reallocated: raw(5),
                            pending: raw(197),
                            uncorrectable: raw(198),
                        }
                    }
                    Health::Nvme(log) => Counts::Nvme {
                        media_errors: log.media_errors,
                        spare: log.available_spare,
                    },
                    Health::Unread(why) if celsius.is_some() => {
                        Counts::TemperatureOnly(why.clone())
                    }
                    Health::Unread(why) => Counts::Nothing(why.clone()),
                };
                (counts, celsius)
            }
        };
        Self {
            time: now(),
            counts,
            celsius,
            pos,
            bad,
        }
    }

    /// The row's kind, counts and note: what the line and the event both carry.
    fn row(&self) -> Row {
        let mut row = Row::default();
        match &self.counts {
            Counts::Ata {
                reallocated,
                pending,
                uncorrectable,
            } => {
                row.kind = "ATA";
                (row.reallocated, row.pending, row.uncorrectable) =
                    (*reallocated, *pending, *uncorrectable);
            }
            Counts::Nvme {
                media_errors,
                spare,
            } => {
                row.kind = "NVMe";
                (row.media_errors, row.spare) = (Some(*media_errors), Some(*spare));
            }
            Counts::TemperatureOnly(why) => {
                row.kind = "temperature only";
                row.note = format!("no error counts: {why}");
            }
            Counts::Nothing(why) => {
                row.kind = "none";
                row.note = format!("the drive answered no health query ({why}); it is still asked at every reading, and the next line comes when it answers");
            }
            Counts::NoAnswer(why) => {
                row.kind = "no answer";
                row.note = why.clone();
            }
        }
        row
    }

    /// The reading as a line of the log, ending in CRLF.
    pub fn line(&self) -> String {
        let row = self.row();
        format!(
            "{},{},{},{},{},{},{},{},{},{},{}\r\n",
            self.time,
            row.kind,
            cell(row.reallocated),
            cell(row.pending),
            cell(row.uncorrectable),
            cell(row.media_errors),
            cell(row.spare),
            cell(self.celsius),
            self.pos,
            self.bad,
            field(&row.note)
        )
    }

    /// The reading as an event for the run's event log: the same fields as its row.
    pub fn event(&self) -> Event {
        let row = self.row();
        Event::Health {
            kind: row.kind.into(),
            reallocated: row.reallocated,
            pending: row.pending,
            uncorrectable: row.uncorrectable,
            media_errors: row.media_errors,
            available_spare: row.spare,
            temperature_c: self.celsius,
            note: row.note,
        }
    }

    /// The figures in words, each with its change since `start` when that is known.
    fn figures(&self, start: Option<&Reading>) -> Vec<String> {
        let change = |now: u128, then: Option<u128>| match then {
            Some(then) if now != then => {
                let sign = if now > then { "+" } else { "-" };
                format!(" ({sign}{} since the start)", now.abs_diff(then))
            }
            _ => String::new(),
        };
        let mut words = Vec::new();
        match (&self.counts, start.map(|s| &s.counts)) {
            (
                Counts::Ata {
                    reallocated,
                    pending,
                    uncorrectable,
                },
                then,
            ) => {
                let before = |pick: fn(&Counts) -> Option<u64>| then.and_then(pick);
                let rows: [(&str, Option<u64>, Option<u64>); 3] = [
                    (
                        "reallocated sectors",
                        *reallocated,
                        before(|c| match c {
                            Counts::Ata { reallocated, .. } => *reallocated,
                            _ => None,
                        }),
                    ),
                    (
                        "pending sectors",
                        *pending,
                        before(|c| match c {
                            Counts::Ata { pending, .. } => *pending,
                            _ => None,
                        }),
                    ),
                    (
                        "uncorrectable sectors",
                        *uncorrectable,
                        before(|c| match c {
                            Counts::Ata { uncorrectable, .. } => *uncorrectable,
                            _ => None,
                        }),
                    ),
                ];
                for (name, now, then) in rows {
                    if let Some(now) = now {
                        let shift = change(u128::from(now), then.map(u128::from));
                        words.push(format!("{name} {now}{shift}"));
                    }
                }
            }
            (
                Counts::Nvme {
                    media_errors,
                    spare,
                },
                then,
            ) => {
                let (errors_then, spare_then) = match then {
                    Some(Counts::Nvme {
                        media_errors,
                        spare,
                    }) => (Some(*media_errors), Some(u128::from(*spare))),
                    _ => (None, None),
                };
                words.push(format!(
                    "media errors {media_errors}{}",
                    change(*media_errors, errors_then)
                ));
                words.push(format!(
                    "spare {spare} %{}",
                    change(u128::from(*spare), spare_then)
                ));
            }
            _ => {}
        }
        if let Some(c) = self.celsius {
            let then = start.and_then(|s| s.celsius);
            let shift = match then {
                Some(t) if t != c => format!(" ({:+} since the start)", c - t),
                _ => String::new(),
            };
            words.push(format!("{c} C{shift}"));
        }
        words
    }
}

/// How a reading offered to the log is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// Written whatever came before: the reading that paused the run, and the end's.
    Always,
    /// On the run's own schedule: written, except a failed reading in a run of failed ones.
    Scheduled,
    /// The heat pause's extra reading: written under `quiet` only when it says something new.
    Extra,
}

/// The health log of one run: its file, its ledger entry, and the first and latest readings.
pub struct HealthLog {
    path: PathBuf,
    file: Option<File>,
    ledger: Ledger,
    id: usize,
    /// Bytes the file holds, all of them written.
    size: u64,
    /// Why the file could not be opened or written; it is not written again after.
    error: Option<String>,
    first: Option<Reading>,
    latest: Option<Reading>,
    /// The latest reading that answered, for the end text.
    answered: Option<Reading>,
    /// Readings that did not answer are being skipped: the first of the streak is written.
    failing: bool,
    /// How long an unchanged reading goes unwritten (`quiet`); None writes every one.
    quiet: Option<Duration>,
    /// The last answered reading written as a row, and when.
    last_row: Option<(Instant, Counts, Option<i32>)>,
}

impl HealthLog {
    /// Starts the log at `path` in `opened`, a file made new or one a stopped run left, which
    /// is added to. The file is entered in the ledger now, whether it opened or not.
    pub fn start(path: PathBuf, opened: std::io::Result<File>) -> Self {
        let mut ledger = Ledger::default();
        let id = ledger.made(
            0,
            path.clone(),
            PathBuf::from("drive health readings"),
            String::new(),
            0,
        );
        let mut log = Self {
            path,
            file: None,
            ledger,
            id,
            size: 0,
            error: None,
            first: None,
            latest: None,
            answered: None,
            failing: false,
            quiet: None,
            last_row: None,
        };
        match opened.and_then(|mut file| file.seek(SeekFrom::End(0)).map(|end| (file, end))) {
            Ok((file, end)) => {
                log.file = Some(file);
                log.size = end;
                log.ledger.grew(id, end);
                if end == 0 {
                    log.put(HEADER);
                }
            }
            Err(e) => log.error = Some(format!("it could not be opened: {e}")),
        }
        log
    }

    fn put(&mut self, text: &str) {
        if self.error.is_some() {
            return;
        }
        let Some(file) = &mut self.file else {
            return;
        };
        let (base, ledger, id) = (self.size, &mut self.ledger, self.id);
        let mut size = base;
        let written = super::ledger::write_counted(file, text.as_bytes(), &mut |n| {
            size = base + n;
            ledger.grew(id, size);
        });
        self.size = size;
        if let Err(e) = written.and_then(|()| file.flush()) {
            self.error = Some(format!("a line could not be written: {e}"));
        }
    }

    /// Adds a reading, and says whether it was written as a row. Of readings in a row that
    /// got no answer from the drive, only the first is written; the next that answers is
    /// written again.
    pub fn add(&mut self, reading: Reading) -> bool {
        self.offer(reading, Keep::Scheduled)
    }

    /// Writes an unchanged reading at most once every `every`: the heat pause reads the
    /// drive every minute, and a row each time would bury the changes (and the health log's
    /// own schedule) in repeats.
    pub fn quiet(mut self, every: Duration) -> Self {
        self.quiet = Some(every);
        self
    }

    /// Adds a reading by `keep`, and says whether it was written as a row: `Always` is
    /// written; `Scheduled` as `add` writes it; `Extra`, under `quiet`, only when it is the
    /// first, follows a failed one, changes a count, moves the temperature by 2 C or more
    /// since the last row, or comes `every` after it.
    pub fn offer(&mut self, reading: Reading, keep: Keep) -> bool {
        let failed = matches!(reading.counts, Counts::Nothing(_) | Counts::NoAnswer(_));
        let mut row = keep == Keep::Always || !(failed && self.failing);
        if row && !failed && keep == Keep::Extra && !self.failing {
            if let (Some(every), Some((at, counts, celsius))) = (self.quiet, &self.last_row) {
                let warmer = match (reading.celsius, celsius) {
                    (Some(now), Some(then)) => (now - then).abs() >= 2,
                    (now, then) => now != *then,
                };
                row = at.elapsed() >= every || reading.counts != *counts || warmer;
            }
        }
        if row {
            self.put(&reading.line());
            if !failed {
                self.last_row = Some((Instant::now(), reading.counts.clone(), reading.celsius));
            }
        }
        self.failing = failed;
        if !failed {
            if self.first.is_none() {
                self.first = Some(reading.clone());
            }
            self.answered = Some(reading.clone());
        }
        self.latest = Some(reading);
        row
    }

    /// Adds a line that is not a reading: `kind` ("heat pause", "drive back", "read limit")
    /// with `text`, the temperature when it is known, and the rescue's figures.
    pub fn note(&mut self, kind: &str, celsius: Option<i32>, pos: u64, bad: u64, text: &str) {
        let line = format!(
            "{},{},,,,,,{},{pos},{bad},{}\r\n",
            now(),
            field(kind),
            cell(celsius),
            field(text)
        );
        self.put(&line);
    }

    fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// The latest reading offered, answered or not.
    pub fn latest(&self) -> Option<&Reading> {
        self.latest.as_ref()
    }

    /// The window's line: the latest reading and its change since the start.
    pub fn live_text(&self) -> String {
        let Some(latest) = &self.latest else {
            return String::new();
        };
        let at = latest.time.get(11..).unwrap_or(&latest.time);
        match &latest.counts {
            Counts::Nothing(_) => format!(
                "Drive health at {at}: the drive answered no health query; it is asked again at each reading."
            ),
            Counts::NoAnswer(why) => format!("Drive health at {at}: no reading ({why})."),
            _ => format!(
                "Drive health at {at}: {}.",
                latest.figures(self.first.as_ref()).join(", ")
            ),
        }
    }

    /// Ends the log and says, for the end text, how the drive's health went from the start
    /// to the end and where the readings are.
    pub fn finish(&mut self) -> String {
        if let Some(file) = &self.file {
            if let Err(e) = file.sync_all() {
                self.error
                    .get_or_insert(format!("it could not be saved: {e}"));
            }
        }
        match self.error.clone() {
            Some(why) => self.ledger.partial(self.id, why),
            None => self.ledger.whole(self.id),
        }
        let output = self.ledger.get(self.id);
        let name = self.name();
        let where_ = if output.complete() {
            format!(
                "The readings are in {name} beside the image ({}).",
                bytes_text(output.size)
            )
        } else {
            format!("{name} is incomplete: {}.", output.condition())
        };
        let said = match (&self.first, &self.answered) {
            (None, _)
                if self
                    .latest
                    .as_ref()
                    .is_some_and(|l| matches!(l.counts, Counts::Nothing(_))) =>
            {
                "The drive answered no health query, so its health could not be followed."
                    .to_string()
            }
            (Some(first), Some(last)) if first != last => {
                let start = first.figures(None);
                let end = last.figures(None);
                if start.is_empty() {
                    "The drive gave no health figures.".into()
                } else {
                    format!(
                        "Drive health at the start: {}. At the end: {}.",
                        start.join(", "),
                        end.join(", ")
                    )
                }
            }
            (Some(first), _) if !first.figures(None).is_empty() => format!(
                "Drive health: {} (one reading).",
                first.figures(None).join(", ")
            ),
            _ => "The drive gave no health figures.".into(),
        };
        format!("{said} {where_}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::drives::health::{fixtures, parse_nvme_health, parse_smart_attributes};

    fn ata(raw: &[u8]) -> Disk {
        fixtures::disk(Health::Ata(parse_smart_attributes(raw).unwrap()))
    }

    fn temp_file(name: &str) -> (PathBuf, File) {
        let path =
            std::env::temp_dir().join(format!("diagtool-health-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        (path, file)
    }

    #[test]
    fn readings_become_lines_with_the_rescue_figures() {
        let healthy = Reading::of(Ok(&ata(&fixtures::healthy_smart())), 4096, 0);
        let line = healthy.line();
        let cells: Vec<&str> = line.trim_end().split(',').collect();
        assert_eq!(cells.len(), HEADER.trim_end().split(',').count(), "{line}");
        assert_eq!(cells[1], "ATA");
        assert_eq!(&cells[8..10], &["4096", "0"]);
        let pending = Reading::of(Ok(&ata(&fixtures::pending_smart())), 8192, 512);
        let text = pending.figures(Some(&healthy)).join(", ");
        assert!(text.contains("since the start"), "{text}");
        let nvme = fixtures::disk(Health::Nvme(
            parse_nvme_health(&fixtures::worn_nvme()).unwrap(),
        ));
        let line = Reading::of(Ok(&nvme), 0, 0).line();
        assert!(line.contains(",NVMe,,,,"), "{line}");
        let line = Reading::of(Err("no answer within 30 s, the drive, \"x\""), 0, 0).line();
        assert!(
            line.ends_with("\"no answer within 30 s, the drive, \"\"x\"\"\"\r\n"),
            "{line}"
        );
    }

    /// The guard: readings that get no answer are written once per streak, and the drive is
    /// still read: the next reading that answers is written, and a later failure is written
    /// again. The file is in the ledger, whole.
    #[test]
    fn failed_readings_are_logged_once_per_streak_and_readings_resume() {
        let mut silent = fixtures::disk(Health::Unread("SMART is not supported".into()));
        silent.temperature = Err("not supported".into());
        let (path, file) = temp_file("silent.health.csv");
        let mut log = HealthLog::start(path.clone(), Ok(file));
        log.add(Reading::of(Ok(&silent), 0, 0));
        log.add(Reading::of(Ok(&silent), 512, 0));
        assert!(
            log.live_text().contains("asked again"),
            "{}",
            log.live_text()
        );
        log.add(Reading::of(Err("no answer within 30 s"), 1024, 0));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.contains("answered no health query"), "{text}");
        log.add(Reading::of(Ok(&ata(&fixtures::healthy_smart())), 2048, 0));
        log.add(Reading::of(Err("no answer within 30 s"), 4096, 0));
        log.add(Reading::of(Err("no answer within 30 s"), 8192, 0));
        log.note("heat pause", Some(39), 8192, 0, "Paused at 39 C.");
        let end = log.finish();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5, "{text}");
        assert!(lines[2].contains(",ATA,"), "{text}");
        assert!(lines[3].contains(",no answer,"), "{text}");
        let cells: Vec<&str> = lines[4].split(',').collect();
        assert_eq!(cells.len(), HEADER.trim_end().split(',').count(), "{text}");
        assert_eq!((cells[1], cells[7], cells[8]), ("heat pause", "39", "8192"));
        assert!(end.contains("Drive health"), "{end}");
        assert!(end.contains("The readings are in"), "{end}");
        assert_eq!(log.ledger.get(log.id).size, text.len() as u64);
        assert!(log.ledger.get(log.id).complete());
        std::fs::remove_file(&path).unwrap();
    }

    /// The guard for the heat pause's minute readings: under `quiet` an unchanged reading is
    /// not written again until the span has passed, while a change of count, a 2 C move, the
    /// reading that paused the run, and the first answer after a failure always are.
    /// The guard: a reading that must be written (the end's, the one that paused the run)
    /// is written though it repeats a run of failed readings; a scheduled one is folded in.
    #[test]
    fn a_reading_that_must_be_written_is_written_in_a_failing_streak() {
        let dir = std::env::temp_dir().join(format!("diagtool-mustlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("must.health.csv");
        let opened = std::fs::File::create(&path);
        let mut log = HealthLog::start(path.clone(), opened);
        let silent = || Reading::of(Err("no answer within 30 s"), 0, 0);
        assert!(log.offer(silent(), Keep::Scheduled), "the streak's first");
        assert!(
            !log.offer(silent(), Keep::Scheduled),
            "folded into the streak"
        );
        assert!(!log.offer(silent(), Keep::Extra), "folded into the streak");
        assert!(log.offer(silent(), Keep::Always), "the end's is written");
        drop(log);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_quiet_log_writes_changes_and_skips_repeats() {
        let at = |smart: Vec<u8>, celsius: i32| {
            let mut reading = Reading::of(Ok(&ata(&smart)), 0, 0);
            reading.celsius = Some(celsius);
            reading
        };
        let (path, file) = temp_file("quiet.health.csv");
        let mut log = HealthLog::start(path.clone(), Ok(file)).quiet(Duration::from_millis(400));
        let healthy = fixtures::healthy_smart();
        let pending = fixtures::pending_smart();
        assert!(
            log.offer(at(healthy.clone(), 30), Keep::Extra),
            "the first reading"
        );
        assert!(!log.offer(at(healthy.clone(), 30), Keep::Extra), "a repeat");
        assert!(
            !log.offer(at(healthy.clone(), 31), Keep::Extra),
            "a 1 C move"
        );
        assert!(
            log.offer(at(healthy.clone(), 32), Keep::Extra),
            "a 2 C move"
        );
        assert!(
            log.offer(at(pending.clone(), 32), Keep::Extra),
            "a count changed"
        );
        assert!(
            log.offer(at(pending.clone(), 32), Keep::Always),
            "the reading that paused"
        );
        assert!(
            !log.offer(at(pending.clone(), 32), Keep::Extra),
            "a repeat again"
        );
        std::thread::sleep(Duration::from_millis(450));
        assert!(
            log.offer(at(pending.clone(), 32), Keep::Extra),
            "the span passed"
        );
        assert!(log.offer(Reading::of(Err("no answer within 30 s"), 0, 0), Keep::Extra));
        assert!(
            log.offer(at(pending.clone(), 32), Keep::Extra),
            "the answer after a failure"
        );
        // Unquiet, every reading is written, as before.
        let (path2, file2) = temp_file("loud.health.csv");
        let mut loud = HealthLog::start(path2.clone(), Ok(file2));
        assert!(loud.offer(at(healthy.clone(), 30), Keep::Extra));
        assert!(loud.offer(at(healthy, 30), Keep::Extra));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 8, "{text}");
        drop((log, loud));
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&path2).unwrap();
    }

    #[test]
    fn the_end_text_compares_the_start_with_the_end_and_a_resumed_log_is_added_to() {
        let (path, file) = temp_file("worse.health.csv");
        let mut log = HealthLog::start(path.clone(), Ok(file));
        log.add(Reading::of(Ok(&ata(&fixtures::healthy_smart())), 0, 0));
        log.add(Reading::of(Err("Windows no longer lists the drive"), 1, 0));
        log.add(Reading::of(
            Ok(&ata(&fixtures::pending_smart())),
            1 << 20,
            4096,
        ));
        let live = log.live_text();
        assert!(live.starts_with("Drive health at ") && live.contains("since the start"));
        let end = log.finish();
        assert!(end.contains("Drive health at the start:"), "{end}");
        assert!(end.contains("At the end:"), "{end}");
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        assert_eq!(lines, 4);
        // A resumed run adds to the same file, with no second header.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut log = HealthLog::start(path.clone(), Ok(file));
        log.add(Reading::of(
            Ok(&ata(&fixtures::pending_smart())),
            2 << 20,
            4096,
        ));
        log.finish();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 5);
        assert_eq!(text.matches("time,kind").count(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_log_that_cannot_be_written_is_entered_as_partial() {
        let mut log = HealthLog::start(
            PathBuf::from("x.health.csv"),
            Err(std::io::Error::other("denied")),
        );
        log.add(Reading::of(Ok(&ata(&fixtures::healthy_smart())), 0, 0));
        let end = log.finish();
        assert!(end.contains("x.health.csv is incomplete"), "{end}");
        assert!(log.ledger.get(log.id).partial());
    }
}
