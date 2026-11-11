//! The file recover from a command line, for an agent that cannot reach the window:
//! `DiagnosticTool.exe --recover-files --image IMG --to FOLDER [--volume N] [--all |
//! --deleted-only] [--deleted-folder NAME] [--damaged-folder NAME] [--by-type]`. It opens the
//! image read-only as the window does, lists one volume, selects files and runs
//! `output::recover` with the destination rules unchanged; a destination a person would be
//! asked to confirm is refused here. It prints a progress line every few seconds and ends
//! with an exit value: 0 complete, 1 stopped or incomplete (a rerun into the same folder
//! finishes the rest), 2 usage or open error.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::fs::parts::{self, Search};
use super::fs::{self, Progress, Volume};
use super::ledger::files;
use super::output::{self, Item, Layout, Outcome, RecoverOptions};
use super::reader::Reader;
use super::{BlockSource, SourceChoice};
use crate::tools::drives::bytes_text;

/// How long between progress lines.
pub const EVERY: Duration = Duration::from_secs(5);

/// How a run ended, as the process's exit value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Complete = 0,
    Incomplete = 1,
    Usage = 2,
}

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Recover(Request),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub image: PathBuf,
    pub to: PathBuf,
    /// The volume's number in the list the run prints, from 1; none takes the largest.
    pub volume: Option<usize>,
    pub deleted_only: bool,
    pub layout: Layout,
    pub deleted_folder: Option<String>,
    pub damaged_folder: Option<String>,
}

pub const USAGE: &str = "\
DiagnosticTool.exe --recover-files --image IMAGE --to FOLDER [options]
  Recovers files from a disk image into FOLDER, which must exist, on another drive.
  --volume N          the volume to read, numbered from 1 as the run lists them
                      (default: the largest file-system volume)
  --all               recover every file on the volume (default)
  --deleted-only      recover only the deleted files
  --deleted-folder S  put deleted files under folder S of FOLDER
  --damaged-folder S  put files that end damaged under folder S of FOLDER
  --by-type           one folder per kind of file instead of the source's folders
  Progress goes to standard output every few seconds. Exit 0: complete. Exit 1: stopped
  or incomplete; run it again into the same folder to finish the rest. Exit 2: the command
  line or the image could not be used, with the reason on standard error. Ctrl+C stops
  cleanly. A live disk (--disk) is not recovered here: use the rescue window.
";

/// The command a command line asks for, None when it asks for neither the recover nor help.
pub fn parse(args: &[String]) -> Option<Result<Command, String>> {
    let wants = |flag: &str| args.iter().skip(1).any(|a| a == flag);
    if wants("--help") || wants("-h") {
        return Some(Ok(Command::Help));
    }
    wants("--recover-files").then(|| request(&args[1..]).map(Command::Recover))
}

/// The value after `flag`: present, and not another flag.
fn value(rest: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    rest.next()
        .filter(|v| !v.is_empty() && !v.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// Sets `slot` to `v`, once.
fn once<T>(slot: &mut Option<T>, flag: &str, v: T) -> Result<(), String> {
    match slot.replace(v) {
        None => Ok(()),
        Some(_) => Err(format!("{flag} is given twice")),
    }
}

fn request(args: &[String]) -> Result<Request, String> {
    let mut image = None;
    let mut to = None;
    let mut volume = None;
    let mut all = false;
    let mut deleted_only = false;
    let mut by_type = false;
    let mut deleted_folder = None;
    let mut damaged_folder = None;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--recover-files" => {}
            "--disk" => {
                return Err("--disk is not recovered from the command line: a live drive that may be failing belongs in the rescue window, which reads it with the care it needs. Image it there, then recover from the image with --image".into());
            }
            "--image" => once(&mut image, flag, value(&mut rest, flag)?)?,
            "--to" => once(&mut to, flag, value(&mut rest, flag)?)?,
            "--deleted-folder" => once(&mut deleted_folder, flag, value(&mut rest, flag)?)?,
            "--damaged-folder" => once(&mut damaged_folder, flag, value(&mut rest, flag)?)?,
            "--volume" => {
                let v = value(&mut rest, flag)?;
                let n = v
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("--volume needs a number from 1, not {v:?}"))?;
                once(&mut volume, flag, n)?;
            }
            "--all" => all = true,
            "--deleted-only" => deleted_only = true,
            "--by-type" => by_type = true,
            other => return Err(format!("{other} is not a --recover-files option")),
        }
    }
    if all && deleted_only {
        return Err("--all and --deleted-only cannot both be given".into());
    }
    Ok(Request {
        image: PathBuf::from(image.ok_or("--recover-files needs --image IMAGE")?),
        to: PathBuf::from(to.ok_or("--recover-files needs --to FOLDER")?),
        volume,
        deleted_only,
        layout: if by_type {
            Layout::ByType
        } else {
            Layout::Folders
        },
        deleted_folder,
        damaged_folder,
    })
}

/// Runs `work` while a line from `line` goes to `out` every `every`.
fn watched<T: Send>(
    out: &mut (dyn Write + Send),
    every: Duration,
    line: impl Fn() -> String + Send,
    work: impl FnOnce() -> T,
) -> T {
    let (done, finished) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            while finished.recv_timeout(every) == Err(mpsc::RecvTimeoutError::Timeout) {
                let _ = writeln!(out, "{}", line());
                let _ = out.flush();
            }
        });
        let result = work();
        let _ = done.send(());
        result
    })
}

/// "4 min 05 s", "1 h 02 min", "9 s".
fn span_text(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min {:02} s", secs / 60, secs % 60),
        _ => format!("{} h {:02} min", secs / 3600, secs % 3600 / 60),
    }
}

fn recovering_line(progress: &Progress, started: Instant) -> String {
    let pace = &progress.pace;
    let left = pace
        .time_left()
        .map_or("time left not known yet".to_string(), |d| {
            format!("about {} left", span_text(d.as_secs()))
        });
    format!(
        "Recovering: {} of {} files, {} of {}, {} elapsed, {left}",
        pace.files_done.load(Ordering::Relaxed),
        pace.files_total.load(Ordering::Relaxed),
        bytes_text(progress.done.load(Ordering::Relaxed)),
        bytes_text(progress.total.load(Ordering::Relaxed)),
        span_text(started.elapsed().as_secs()),
    )
}

/// The largest volume that holds a file system, or the numbered one (from 1) of `volumes`
/// in their order on the source.
fn chosen(volumes: &[Volume], number: Option<usize>) -> Result<(usize, &Volume), String> {
    match number {
        Some(n) => volumes.get(n - 1).map(|v| (n, v)).ok_or_else(|| {
            format!(
                "--volume {n}: the image has {} volume{}",
                volumes.len(),
                if volumes.len() == 1 { "" } else { "s" }
            )
        }),
        None => volumes
            .iter()
            .enumerate()
            .max_by_key(|(_, v)| v.len)
            .map(|(i, v)| (i + 1, v))
            .ok_or_else(|| "no volume was found in the image".into()),
    }
}

/// The recover `request` asks for, progress lines to `out`, the reason for a failure to
/// `err`. `cancel` stops it between files and between steps.
pub fn run(
    request: &Request,
    cancel: &AtomicBool,
    every: Duration,
    out: &mut (dyn Write + Send),
    err: &mut dyn Write,
) -> Exit {
    fn refuse(err: &mut dyn Write, why: String) -> Exit {
        let _ = writeln!(err, "{why}");
        Exit::Usage
    }
    if !request.to.is_dir() {
        return refuse(
            err,
            format!("--to {} is not an existing folder", request.to.display()),
        );
    }
    let choice = SourceChoice::Image(request.image.clone());
    let source = match super::open_source(&choice) {
        Ok(source) => source,
        Err(why) => return refuse(err, why),
    };
    let protected = output::source_disk(&choice);
    if let Err(refusal) = super::destination_refusal(&request.to, &protected) {
        return refuse(
            err,
            format!("{}; choose a folder on another drive", refusal.why),
        );
    }
    let mut reader = Reader::new(source as Box<dyn BlockSource>);
    let progress = Progress::default();
    let mut finds = parts::find(&mut reader, Search::Tables, cancel, &progress);
    if finds.volumes.is_empty() && !cancel.load(Ordering::Relaxed) {
        let _ = writeln!(
            out,
            "No volume in the partition tables; searching for lost volumes."
        );
        finds = parts::find(&mut reader, Search::Aligned, cancel, &progress);
    }
    finds.volumes.sort_by_key(|v| v.start);
    for (i, v) in finds.volumes.iter().enumerate() {
        let _ = writeln!(out, "Volume {}: {}", i + 1, v.describe());
    }
    if cancel.load(Ordering::Relaxed) {
        let _ = writeln!(err, "Stopped while looking for volumes.");
        return Exit::Incomplete;
    }
    let (number, volume) = match chosen(&finds.volumes, request.volume) {
        Ok(found) => found,
        Err(why) => {
            for note in &finds.notes {
                let _ = writeln!(err, "{note}");
            }
            return refuse(err, why);
        }
    };
    if request.volume.is_none() {
        let _ = writeln!(
            out,
            "No --volume given: reading the largest, volume {number}."
        );
    }
    let started = Instant::now();
    let scanning = Progress::default();
    let listed = watched(
        out,
        every,
        || {
            format!(
                "Reading the volume's files: {} found",
                scanning.found.load(Ordering::Relaxed)
            )
        },
        || fs::scan(&mut reader, volume, cancel, &scanning),
    );
    let listing = match listed {
        Ok(listing) => listing,
        Err(why) => return refuse(err, format!("The volume could not be read: {why}")),
    };
    let deleted = listing.files.iter().filter(|f| f.deleted).count();
    let _ = writeln!(
        out,
        "{} files on the volume, {deleted} deleted.",
        listing.files.len()
    );
    let mut listed_in_full = true;
    for note in &listing.notes {
        let _ = writeln!(err, "{note}");
    }
    if listing.limit.is_some() || cancel.load(Ordering::Relaxed) {
        listed_in_full = false;
        let _ = writeln!(
            err,
            "The volume's files were not all listed; the files found are recovered."
        );
    }
    let items: Vec<Item> = listing
        .files
        .iter()
        .filter(|f| !request.deleted_only || f.deleted)
        .map(Item::from_found)
        .collect();
    if items.is_empty() && listed_in_full {
        let _ = writeln!(out, "No files to recover.");
        return Exit::Complete;
    }
    let options = RecoverOptions {
        layout: request.layout,
        deleted_folder: request.deleted_folder.clone(),
        damaged_folder: request.damaged_folder.clone(),
        ..RecoverOptions::default()
    };
    let copied = Progress::default();
    let result = watched(
        out,
        every,
        || recovering_line(&copied, started),
        || {
            output::recover(
                &mut reader,
                &items,
                &request.to,
                &options,
                &protected,
                cancel,
                &copied,
            )
        },
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(why) => return refuse(err, why),
    };
    let ended = summary(&outcome, &request.to, started.elapsed());
    let _ = writeln!(out, "{}", ended.0);
    if ended.1 && listed_in_full {
        Exit::Complete
    } else {
        for why in ended.2 {
            let _ = writeln!(err, "{why}");
        }
        Exit::Incomplete
    }
}

/// The closing line, whether everything asked for was written, and what was not.
fn summary(outcome: &Outcome, dest: &Path, took: Duration) -> (String, bool, Vec<String>) {
    let mut line = format!(
        "Recovered {} to {} in {}",
        files(outcome.complete() + outcome.damaged()),
        dest.display(),
        span_text(took.as_secs())
    );
    if outcome.damaged() > 0 {
        line.push_str(&format!(
            "; {} damaged (unreadable parts written as zeros)",
            outcome.damaged()
        ));
    }
    if let Some(report) = &outcome.report {
        line.push_str(&format!("; report {}", report.display()));
    }
    line.push('.');
    let mut why = Vec::new();
    if outcome.stopped {
        why.push(
            "Stopped before the end; run it again into the same folder to finish the rest.".into(),
        );
    }
    if let Some(gone) = &outcome.gone {
        why.push(format!("The source stopped answering: {gone}."));
    }
    if outcome.partial() > 0 {
        why.push(format!(
            "{} incomplete, marked PARTIAL in the report.",
            files(outcome.partial())
        ));
    }
    if let Some((name, reason)) = outcome.failed.first() {
        why.push(format!(
            "{} could not be made, the first {name}: {reason}.",
            files(outcome.failed.len())
        ));
    }
    for (what, error) in [
        ("The report", &outcome.report_error),
        ("The log", &outcome.log_error),
    ] {
        if let Some(error) = error {
            why.push(format!("{what} could not be written in full: {error}."));
        }
    }
    if outcome.report.is_none() && outcome.report_error.is_none() {
        why.push("The report could not be made.".into());
    }
    (line, why.is_empty(), why)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(args: &[&str]) -> Vec<String> {
        std::iter::once("DiagnosticTool.exe")
            .chain(args.iter().copied())
            .map(String::from)
            .collect()
    }

    fn recover_request(args: &[&str]) -> Result<Request, String> {
        match parse(&line(args)) {
            Some(Ok(Command::Recover(request))) => Ok(request),
            Some(Err(why)) => Err(why),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_flag_is_read() {
        let r = recover_request(&[
            "--recover-files",
            "--image",
            "d:\\a b.img",
            "--to",
            "e:\\out",
            "--volume",
            "2",
            "--deleted-only",
            "--deleted-folder",
            "Deleted",
            "--damaged-folder",
            "Damaged",
            "--by-type",
        ])
        .unwrap();
        assert_eq!(
            r,
            Request {
                image: "d:\\a b.img".into(),
                to: "e:\\out".into(),
                volume: Some(2),
                deleted_only: true,
                layout: Layout::ByType,
                deleted_folder: Some("Deleted".into()),
                damaged_folder: Some("Damaged".into()),
            }
        );
        let plain =
            recover_request(&["--recover-files", "--all", "--image", "i", "--to", "t"]).unwrap();
        assert_eq!(plain.volume, None);
        assert!(!plain.deleted_only);
        assert_eq!(plain.layout, Layout::Folders);
    }

    #[test]
    fn other_command_lines_are_not_this_mode() {
        assert!(parse(&line(&[])).is_none());
        assert!(parse(&line(&["--recovery", "--image", "x"])).is_none());
        assert_eq!(parse(&line(&["--help"])), Some(Ok(Command::Help)));
        assert_eq!(parse(&line(&["-h"])), Some(Ok(Command::Help)));
    }

    #[test]
    fn a_disk_source_is_refused_for_the_rescue_window() {
        let why = recover_request(&["--recover-files", "--disk", "3", "--to", "t"]).unwrap_err();
        assert!(
            why.contains("--disk") && why.contains("rescue window"),
            "{why}"
        );
        let both = recover_request(&[
            "--recover-files",
            "--disk",
            "3",
            "--image",
            "i",
            "--to",
            "t",
        ]);
        assert!(both.is_err());
    }

    #[test]
    fn bad_command_lines_are_refused_with_a_reason() {
        for (args, said) in [
            (vec!["--recover-files", "--to", "t"], "--image"),
            (vec!["--recover-files", "--image", "i"], "--to"),
            (
                vec!["--recover-files", "--image", "--to", "t"],
                "--image needs a value",
            ),
            (
                vec![
                    "--recover-files",
                    "--image",
                    "i",
                    "--to",
                    "t",
                    "--volume",
                    "0",
                ],
                "from 1",
            ),
            (
                vec![
                    "--recover-files",
                    "--image",
                    "i",
                    "--to",
                    "t",
                    "--volume",
                    "x",
                ],
                "from 1",
            ),
            (
                vec![
                    "--recover-files",
                    "--image",
                    "i",
                    "--to",
                    "t",
                    "--all",
                    "--deleted-only",
                ],
                "cannot both",
            ),
            (
                vec!["--recover-files", "--image", "i", "--to", "t", "--bogus"],
                "--bogus",
            ),
            (
                vec![
                    "--recover-files",
                    "--image",
                    "i",
                    "--image",
                    "j",
                    "--to",
                    "t",
                ],
                "twice",
            ),
            (
                vec![
                    "--recover-files",
                    "--image",
                    "i",
                    "--to",
                    "t",
                    "--deleted-folder",
                ],
                "needs a value",
            ),
        ] {
            let why = recover_request(&args).unwrap_err();
            assert!(why.contains(said), "{args:?}: {why}");
        }
    }

    /// A run cut short is not a complete one: it exits 1, and says why.
    #[test]
    fn a_stopped_run_is_incomplete_and_says_so() {
        let stopped = Outcome {
            stopped: true,
            ..Outcome::default()
        };
        let (_, complete, why) = summary(&stopped, Path::new("t"), Duration::ZERO);
        assert!(!complete);
        assert!(why[0].starts_with("Stopped"), "{why:?}");
    }

    #[test]
    fn the_exit_values_are_0_1_and_2() {
        assert_eq!(
            [Exit::Complete, Exit::Incomplete, Exit::Usage].map(|e| e as i32),
            [0, 1, 2]
        );
    }

    #[test]
    fn the_largest_volume_is_taken_when_none_is_named() {
        let volume = |len| Volume {
            kind: fs::FsKind::Fat32,
            start: 0,
            len,
            origin: fs::Origin::Whole,
            claims: Vec::new(),
        };
        let volumes = [volume(10), volume(30), volume(20)];
        assert_eq!(chosen(&volumes, None).unwrap().0, 2);
        assert_eq!(chosen(&volumes, Some(3)).unwrap().0, 3);
        assert!(chosen(&volumes, Some(4)).unwrap_err().contains("3 volumes"));
        assert!(chosen(&[], None).is_err());
    }

    #[test]
    fn times_read_as_minutes_and_hours() {
        assert_eq!(span_text(9), "9 s");
        assert_eq!(span_text(245), "4 min 05 s");
        assert_eq!(span_text(3720), "1 h 02 min");
    }
}
