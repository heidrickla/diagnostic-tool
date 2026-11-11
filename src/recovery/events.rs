//! The run's events for a program watching it: `<image name>.events.jsonl` beside the image
//! and its map, one JSON object per line, only ever added to, so a watcher tailing the file
//! knows the run's state without polling the map and the health log and guessing. Each line
//! carries the local time, the event, the run's state after it (running, paused, stopped,
//! finished or failed) and the map's figures then: the position and the rescued,
//! non-trimmed, non-scraped and bad bytes. A line is made whole in memory, written with one
//! write and flushed, so a reader never sees part of one; a line a killed process left part
//! written is cut off when the next run opens the file, so every line is whole JSON. The
//! window's pause and end messages are the `reason` of the event written for them.
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::Value;

use super::image::{Map, Status};
use super::ledger::Ledger;
use super::SourceId;

/// The log's file name for an image: `Disk 3 Samsung.img` gives `Disk 3 Samsung.events.jsonl`.
pub fn path_for(image: &Path) -> PathBuf {
    image.with_extension("events.jsonl")
}

/// The map's figures a line carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Figures {
    pub position: u64,
    pub rescued: u64,
    pub non_trimmed: u64,
    pub non_scraped: u64,
    pub bad: u64,
}

impl Figures {
    pub fn of(map: &Map) -> Self {
        Self {
            position: map.current_pos,
            rescued: map.count(Status::Rescued),
            non_trimmed: map.count(Status::NonTrimmed),
            non_scraped: map.count(Status::NonScraped),
            bad: map.count(Status::Bad),
        }
    }
}

/// Why a run paused, for a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PauseKind {
    /// The drive's error counts grew too fast (`image::WearRate`), or rose past Fill the
    /// gaps' limit. The run ends; Resume carries on.
    ErrorRate,
    /// The drive reached its own critical temperature. The run ends; Resume carries on.
    CriticalTemperature,
    /// The heat pause; the run carries on by itself once the drive has cooled.
    Heat,
    /// The drive stopped answering; the run carries on by itself when it is back, or ends
    /// when it is not waited for.
    DriveGone,
    /// A drive came back that cannot be told from the one being read: the run ends, and
    /// Resume asks the technician to confirm it.
    User,
}

/// One event. The state events (started, paused, resumed, stopped, finished, app error)
/// are written once for each change of the run's state; the others are what was seen.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Started {
        app_version: String,
        /// "rescue image" or "fill the gaps".
        run: String,
        disk_number: Option<u32>,
        /// What Windows reports, and the drive's own from IDENTIFY when it gave them.
        model: Option<String>,
        serial: Option<String>,
        drive_model: Option<String>,
        drive_serial: Option<String>,
        settings: Value,
    },
    Phase {
        phase: String,
        pass: u32,
    },
    /// Every 30 s while reading: rescued bytes per second over the last 30 s.
    Progress {
        bytes_per_second: u64,
    },
    /// A failed read that was recorded; `code` is the Windows error, None when it timed out.
    ReadError {
        at: u64,
        length: u64,
        code: Option<u32>,
    },
    /// A health reading, as its health log row.
    Health {
        kind: String,
        reallocated: Option<u64>,
        pending: Option<u64>,
        uncorrectable: Option<u64>,
        media_errors: Option<u128>,
        available_spare: Option<u8>,
        temperature_c: Option<i32>,
        note: String,
    },
    Paused {
        kind: PauseKind,
        reason: String,
        /// The values that paused it.
        values: Value,
    },
    Resumed {
        kind: PauseKind,
        reason: String,
    },
    /// What showed the drive had stopped answering; `code` is the failed read's Windows
    /// error when a read showed it.
    DriveGone {
        seen: String,
        code: Option<u32>,
    },
    DriveBack {
        disk_number: Option<u32>,
        serial: Option<String>,
        drive_serial: Option<String>,
        source: String,
    },
    /// Another program held the map, so a timed save was refused; the map on disk is the
    /// last one saved, and the run carries on and tries again.
    MapNotSaved {
        reason: String,
    },
    /// A timed save went through again after `after_seconds` of refusals.
    MapSaved {
        after_seconds: u64,
    },
    Stopped {
        reason: String,
    },
    Finished {
        reason: String,
    },
    AppError {
        reason: String,
    },
    /// The technician pointed Fill the gaps at bytes `start` to `end`: `how` is "read this
    /// block" or "continue scan from here".
    Directed {
        how: String,
        start: u64,
        end: u64,
    },
    /// The rescued sectors within `distance` sectors of every area not rescued were read
    /// again and compared with the image (`edges.rs`): of `planned`, `read`, and of them
    /// `differ` read otherwise and `failed` failed now. The map and the image are unchanged.
    EdgesChecked {
        distance: u32,
        planned: u64,
        read: u64,
        differ: u64,
        failed: u64,
        ended: String,
        findings: Option<String>,
    },
    /// A rescued sector the drive returned alike on two reads in a row was written into the
    /// image over what it held (`edges::take_sector`); the SHA-256 of both.
    SectorTaken {
        at: u64,
        length: u64,
        image_was: String,
        now: String,
    },
}

/// The first event of a run: what reads which drive, with which settings.
pub fn started(
    run: &str,
    disk_number: Option<u32>,
    id: Option<&SourceId>,
    settings: Value,
) -> Event {
    let drive = id.and_then(|id| id.drive.as_ref());
    Event::Started {
        app_version: env!("CARGO_PKG_VERSION").into(),
        run: run.into(),
        disk_number,
        model: id.map(|id| id.model.clone()),
        serial: id.map(|id| id.serial.clone()),
        drive_model: drive.map(|d| d.model.clone()),
        drive_serial: drive.map(|d| d.serial.clone()),
        settings,
    }
}

impl Event {
    /// The run's state after this event, or None when it does not change it.
    fn state(&self) -> Option<&'static str> {
        match self {
            Event::Started { .. } | Event::Resumed { .. } => Some("running"),
            Event::Paused { .. } => Some("paused"),
            Event::Stopped { .. } => Some("stopped"),
            Event::Finished { .. } => Some("finished"),
            Event::AppError { .. } => Some("failed"),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct Line<'a> {
    time: String,
    #[serde(flatten)]
    event: &'a Event,
    state: &'static str,
    #[serde(flatten)]
    figures: Figures,
}

/// The run's event log; a clone writes to the same file. Until `start`, and after it
/// failed, nothing is written.
#[derive(Clone, Default)]
pub struct EventLog(Arc<Mutex<Option<Inner>>>);

struct Inner {
    path: PathBuf,
    file: Option<File>,
    ledger: Ledger,
    id: usize,
    /// Bytes the file holds, all of them whole lines.
    size: u64,
    /// Why the file could not be opened or written; it is not written again after.
    error: Option<String>,
    state: &'static str,
}

impl EventLog {
    /// Starts the log at `path` in `opened`, a file made new or one an earlier run left,
    /// which is added to after any line left part written is cut off. The file is entered
    /// in the ledger now, whether it opened or not.
    pub fn start(&self, path: PathBuf, opened: io::Result<File>) {
        let mut ledger = Ledger::default();
        let id = ledger.made(
            0,
            path.clone(),
            PathBuf::from("run events"),
            String::new(),
            0,
        );
        let mut inner = Inner {
            path,
            file: None,
            ledger,
            id,
            size: 0,
            error: None,
            state: "running",
        };
        match opened.and_then(|mut file| whole_lines(&mut file).map(|end| (file, end))) {
            Ok((file, (end, state))) => {
                inner.file = Some(file);
                inner.size = end;
                inner.ledger.grew(id, end);
                // A line that changes no state (a check after the run) carries the run's.
                if let Some(state) = state {
                    inner.state = state;
                }
            }
            Err(e) => inner.error = Some(format!("it could not be opened: {e}")),
        }
        if let Ok(mut log) = self.0.lock() {
            *log = Some(inner);
        }
    }

    /// Writes one line: the event with the time, the run's state after it and `figures`.
    pub fn write(&self, event: &Event, figures: Figures) {
        let Ok(mut log) = self.0.lock() else {
            return;
        };
        let Some(inner) = log.as_mut() else {
            return;
        };
        if let Some(state) = event.state() {
            inner.state = state;
        }
        if inner.error.is_some() {
            return;
        }
        let Some(file) = &mut inner.file else {
            return;
        };
        let line = Line {
            time: now(),
            event,
            state: inner.state,
            figures,
        };
        let mut text = match serde_json::to_string(&line) {
            Ok(text) => text,
            Err(e) => {
                inner.error = Some(format!("a line could not be made: {e}"));
                return;
            }
        };
        text.push('\n');
        let (base, ledger, id) = (inner.size, &mut inner.ledger, inner.id);
        let mut size = base;
        let written = super::ledger::write_counted(file, text.as_bytes(), &mut |n| {
            size = base + n;
            ledger.grew(id, size);
        });
        inner.size = size;
        if let Err(e) = written.and_then(|()| file.flush()) {
            inner.error = Some(format!("a line could not be written: {e}"));
        }
    }

    /// The run's state as the log last said it; None before `start`.
    pub fn state(&self) -> Option<&'static str> {
        self.0.lock().ok()?.as_ref().map(|inner| inner.state)
    }

    /// Ends the log: saved to the disk and its ledger entry closed. Says why when it is
    /// incomplete, for the end text.
    pub fn finish(&self) -> Option<String> {
        let mut log = self.0.lock().ok()?;
        let inner = log.as_mut()?;
        if let Some(file) = &inner.file {
            if let Err(e) = file.sync_all() {
                inner
                    .error
                    .get_or_insert(format!("it could not be saved: {e}"));
            }
        }
        let name = inner
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match inner.error.clone() {
            Some(why) => {
                inner.ledger.partial(inner.id, why.clone());
                Some(format!("The event log {name} is incomplete: {why}."))
            }
            None => {
                inner.ledger.whole(inner.id);
                None
            }
        }
    }
}

/// The states a line can carry.
const STATES: [&str; 5] = ["running", "paused", "stopped", "finished", "failed"];

/// Positions `file` after its last whole line, cutting off a line a killed process left part
/// written, and returns that length and the state the last whole line says. The last line is
/// looked for in the file's last 64 KiB, far more than any line this log writes.
fn whole_lines(file: &mut File) -> io::Result<(u64, Option<&'static str>)> {
    const TAIL: u64 = 64 * 1024;
    let end = file.seek(SeekFrom::End(0))?;
    if end == 0 {
        return Ok((0, None));
    }
    let back = end.min(TAIL);
    file.seek(SeekFrom::Start(end - back))?;
    let mut tail = vec![0u8; back as usize];
    file.read_exact(&mut tail)?;
    let keep = match tail.iter().rposition(|b| *b == b'\n') {
        Some(at) => end - back + at as u64 + 1,
        None if back == end => 0,
        None => {
            return Err(io::Error::other(
                "its last line is longer than 64 KiB, so it is not this log",
            ))
        }
    };
    if keep < end {
        file.set_len(keep)?;
    }
    file.seek(SeekFrom::Start(keep))?;
    let whole = &tail[..(keep - (end - back)) as usize];
    let state = whole
        .strip_suffix(b"\n")
        .and_then(|lines| lines.rsplit(|b| *b == b'\n').next())
        .and_then(|line| serde_json::from_slice::<Value>(line).ok())
        .and_then(|line| STATES.into_iter().find(|s| line["state"] == *s));
    Ok((keep, state))
}

fn now() -> String {
    let s = crate::clock::local(SystemTime::now());
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        s.year, s.month, s.day, s.hour, s.minute, s.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(path: &Path) -> Vec<Value> {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.is_empty() || text.ends_with('\n'), "{text}");
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
            .collect()
    }

    /// The guard: each line is whole JSON with the time, the event, the state after it and
    /// the figures; a line a killed process left part written is cut off when the next run
    /// opens the file, and what was whole before it is kept.
    #[test]
    fn every_line_is_whole_json_even_after_a_killed_run() {
        let dir = std::env::temp_dir().join(format!("diagtool-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image.events.jsonl");
        let log = EventLog::default();
        log.write(&Event::Finished { reason: "x".into() }, Figures::default());
        assert!(!path.exists(), "written before start");
        log.start(
            path.clone(),
            File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path),
        );
        let figures = Figures {
            position: 4096,
            rescued: 4096,
            non_trimmed: 512,
            non_scraped: 0,
            bad: 512,
        };
        log.write(
            &Event::ReadError {
                at: 4096,
                length: 512,
                code: Some(23),
            },
            figures,
        );
        log.write(
            &Event::Paused {
                kind: PauseKind::DriveGone,
                reason: "The drive stopped answering.".into(),
                values: serde_json::json!({ "code": 1117 }),
            },
            figures,
        );
        assert_eq!(log.state(), Some("paused"));
        assert_eq!(log.finish(), None);
        let written = lines(&path);
        assert_eq!(written.len(), 2);
        assert_eq!(written[0]["event"], "read_error");
        assert_eq!(written[0]["state"], "running");
        assert_eq!(written[0]["code"], 23);
        assert_eq!(written[1]["event"], "paused");
        assert_eq!(written[1]["kind"], "drive-gone");
        assert_eq!(written[1]["state"], "paused");
        assert_eq!(written[1]["values"]["code"], 1117);
        assert_eq!(written[1]["non_trimmed"], 512);
        assert!(written[1]["time"].as_str().unwrap().len() == 19);
        // A run killed part way through a line.
        let mut file = File::options().append(true).open(&path).unwrap();
        file.write_all(br#"{"time":"2026-11-09 16:40:01","event":"heal"#)
            .unwrap();
        drop(file);
        let again = EventLog::default();
        again.start(
            path.clone(),
            File::options().read(true).write(true).open(&path),
        );
        again.write(
            &Event::Resumed {
                kind: PauseKind::DriveGone,
                reason: "back".into(),
            },
            figures,
        );
        assert_eq!(again.finish(), None);
        let written = lines(&path);
        assert_eq!(written.len(), 3);
        assert_eq!(written[2]["event"], "resumed");
        assert_eq!(written[2]["state"], "running");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A log opened again carries the state its last line said, so a line that changes no
    /// state, written after the run ended (a check of the edges), does not call it running.
    #[test]
    fn a_reopened_log_keeps_the_state_its_last_line_said() {
        let dir =
            std::env::temp_dir().join(format!("diagtool-events-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image.events.jsonl");
        let open = || {
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
        };
        let log = EventLog::default();
        log.start(path.clone(), open());
        log.write(
            &Event::Finished {
                reason: "Finished.".into(),
            },
            Figures::default(),
        );
        assert_eq!(log.finish(), None);
        let again = EventLog::default();
        again.start(path.clone(), open());
        assert_eq!(again.state(), Some("finished"));
        again.write(
            &Event::SectorTaken {
                at: 512,
                length: 512,
                image_was: "a".into(),
                now: "b".into(),
            },
            Figures::default(),
        );
        assert_eq!(again.finish(), None);
        let written = lines(&path);
        assert_eq!(written[1]["event"], "sector_taken");
        assert_eq!(written[1]["state"], "finished");
        // A new log starts running.
        std::fs::remove_file(&path).unwrap();
        let fresh = EventLog::default();
        fresh.start(path.clone(), open());
        assert_eq!(fresh.state(), Some("running"));
        assert_eq!(fresh.finish(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
