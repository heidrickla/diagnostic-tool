//! The output ledger: every file a recovery makes is entered the moment it is made, before
//! a byte is written, and ends in one state. Reports and notices are built from it alone,
//! and a run closes it before reporting, so no error path can leave a made file unlisted or
//! listed as whole when it is not. A rescue copy's ledger is its log: each file's row is
//! written there the moment the file ends, so memory holds only open entries and counts. A
//! recovery of listed items keeps its ledger in memory and writes the same rows to a log as
//! files end, so a run cut short leaves a list of what it finished.
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::tools::drives::bytes_text;

/// How an output file ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Made and being written; a closed ledger holds none.
    Open,
    /// Written to its full size; `zeroed` says which parts are zeros for want of a read.
    Whole,
    /// Holds only its first `at` bytes as far as is known: stopped, or a write failed.
    Partial(String),
    /// Made and then removed again, as chosen.
    Removed(String),
}

/// One file made in the destination.
#[derive(Clone, Debug)]
pub struct Output {
    /// The caller's own index for it, such as the item it was copied from.
    pub tag: usize,
    pub path: PathBuf,
    /// What it was copied from, for people.
    pub source: PathBuf,
    /// What the source said of it, such as "deleted, intact".
    pub note: String,
    pub size: u64,
    /// How far it was written in order; the end for a whole file.
    pub at: u64,
    /// Ranges written as zeros because the source could not be read there.
    pub zeroed: Vec<Range<u64>>,
    /// What the source's own records say is wrong with it, read in full or not: a file with
    /// one is never complete.
    pub flaw: Option<String>,
    /// What the run was asked to do with it and could not, such as move it into the damaged
    /// folder; its condition says so, so the report and log name where it really is.
    pub remark: Option<String>,
    pub state: State,
}

impl Output {
    pub fn complete(&self) -> bool {
        self.state == State::Whole && self.zeroed.is_empty() && self.flaw.is_none()
    }

    pub fn damaged(&self) -> bool {
        self.state == State::Whole && (!self.zeroed.is_empty() || self.flaw.is_some())
    }

    pub fn partial(&self) -> bool {
        matches!(self.state, State::Partial(_) | State::Open)
    }

    pub fn zeroed_bytes(&self) -> u64 {
        self.zeroed.iter().map(|r| r.end - r.start).sum()
    }

    /// The size column of a report row: what it holds against what it should.
    pub fn size_text(&self) -> String {
        if self.partial() {
            format!(
                "{} of {} ({} of {} bytes)",
                bytes_text(self.at),
                bytes_text(self.size),
                self.at,
                self.size
            )
        } else {
            format!("{} bytes", self.size)
        }
    }

    /// The condition column of a report row, with its remark after it.
    pub fn condition(&self) -> String {
        let state = self.state_text();
        match &self.remark {
            Some(remark) => format!("{state}; {remark}"),
            None => state,
        }
    }

    fn state_text(&self) -> String {
        let zeroed = || {
            let ranges: Vec<String> = self
                .zeroed
                .iter()
                .take(8)
                .map(|r| format!("{}-{}", r.start, r.end))
                .collect();
            let more = if self.zeroed.len() > 8 { ", ..." } else { "" };
            format!(
                "{} bytes unreadable, written as zeros (bytes {}{more})",
                self.zeroed_bytes(),
                ranges.join(", ")
            )
        };
        match &self.state {
            State::Whole if self.zeroed.is_empty() && self.flaw.is_none() => "read in full".into(),
            State::Whole => {
                let mut why = Vec::new();
                if !self.zeroed.is_empty() {
                    why.push(zeroed());
                }
                why.extend(self.flaw.clone());
                format!("DAMAGED: {}", why.join("; "))
            }
            State::Partial(why) => format!("PARTIAL: {why}"),
            State::Open => "PARTIAL: it was never finished".into(),
            State::Removed(why) => format!("REMOVED: {why}"),
        }
    }
}

/// What has ended so far, counted as each entry ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    complete: usize,
    damaged: usize,
    partial: usize,
    complete_bytes: u64,
}

/// A rescue copy's log, which is its ledger: each entry's row is written to it the moment
/// the entry ends.
struct Log {
    out: Box<dyn Write + Send>,
    /// The folder the rows' paths are given below.
    base: PathBuf,
    /// Whether each row carries what the source said of the file.
    notes: bool,
    /// The first failed write; a log with one never gets its last line.
    error: Option<String>,
    /// Rows whose write failed, kept to be tried once more at the end; at most
    /// `UNWRITTEN_KEPT`, since writes rarely fail and a full destination fails them all.
    unwritten: Vec<String>,
    /// Files whose row is in the log nowhere: past that bound, or failed again.
    unlisted: usize,
}

/// The most rows whose write failed that are kept for a second try.
const UNWRITTEN_KEPT: usize = 10_000;

impl std::fmt::Debug for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Log")
            .field("base", &self.base)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct Ledger {
    /// Every entry, in the order made, for a ledger kept in memory: a recovery of listed
    /// items, whose list is in memory already.
    outputs: Vec<Output>,
    /// The entries still open, by number, for a ledger that is only a log.
    open: BTreeMap<usize, Output>,
    next: usize,
    /// The log ended entries are written to, if any.
    /// Boxed, so a ledger kept in memory stays small in the outcomes that carry it.
    log: Option<Box<Log>>,
    /// Ended entries are let go once their row is in the log: a ledger that is only a log.
    forgets: bool,
    counts: Counts,
}

impl Ledger {
    /// A ledger that is the log `out`: each entry's row is written to it when the entry
    /// ends, with its path below `base`, and only open entries and counts stay in memory.
    pub fn to_log(out: Box<dyn Write + Send>, base: PathBuf) -> Self {
        Self {
            log: Some(Log::new(out, base, false)),
            forgets: true,
            ..Self::default()
        }
    }

    /// A ledger kept in memory that also writes each entry's row, with what the source said
    /// of it, to the log `out` the moment the entry ends, with its path below `base`.
    pub fn kept_with_log(out: Box<dyn Write + Send>, base: PathBuf) -> Self {
        Self {
            log: Some(Log::new(out, base, true)),
            ..Self::default()
        }
    }

    /// Enters a file just made; returns its number for the calls below.
    pub fn made(
        &mut self,
        tag: usize,
        path: PathBuf,
        source: PathBuf,
        note: String,
        size: u64,
    ) -> usize {
        let id = self.next;
        self.next += 1;
        let output = Output {
            tag,
            path,
            source,
            note,
            size,
            at: 0,
            zeroed: Vec::new(),
            flaw: None,
            remark: None,
            state: State::Open,
        };
        if self.forgets {
            self.open.insert(id, output);
        } else {
            self.outputs.push(output);
        }
        id
    }

    /// An entry still open; in a ledger kept in memory, any entry.
    pub fn get(&self, id: usize) -> &Output {
        if self.forgets {
            &self.open[&id]
        } else {
            &self.outputs[id]
        }
    }

    fn entry(&mut self, id: usize) -> &mut Output {
        if self.forgets {
            self.open.get_mut(&id).expect("an open entry")
        } else {
            &mut self.outputs[id]
        }
    }

    /// It is written in order as far as `at`.
    pub fn wrote(&mut self, id: usize, at: u64) {
        self.entry(id).at = at;
    }

    /// A file written by adding to its end, such as a log, now holds `size` bytes, all
    /// written.
    pub fn grew(&mut self, id: usize, size: u64) {
        let output = self.entry(id);
        output.size = size;
        output.at = size;
    }

    pub fn zeroed(&mut self, id: usize, zeroed: Vec<Range<u64>>) {
        self.entry(id).zeroed = super::reader::merge(zeroed);
    }

    /// The source's own records say it is damaged, for `why`: it ends damaged at best.
    pub fn flawed(&mut self, id: usize, why: impl Into<String>) {
        self.entry(id).flaw = Some(why.into());
    }

    /// The run could not do with it what it was asked, for `why`; it stays as it is.
    pub fn remark(&mut self, id: usize, why: impl Into<String>) {
        self.entry(id).remark = Some(why.into());
    }

    /// It was renamed to `path`; for an open entry, or any entry of a ledger kept in memory.
    pub fn moved(&mut self, id: usize, path: PathBuf) {
        self.entry(id).path = path;
    }

    /// It holds its full size.
    pub fn whole(&mut self, id: usize) {
        let output = self.entry(id);
        output.at = output.size;
        output.state = State::Whole;
        self.end(id);
    }

    pub fn partial(&mut self, id: usize, why: impl Into<String>) {
        self.entry(id).state = State::Partial(why.into());
        self.end(id);
    }

    pub fn removed(&mut self, id: usize, why: impl Into<String>) {
        self.entry(id).state = State::Removed(why.into());
        self.end(id);
    }

    /// Counts an entry that has ended and writes its row to the log, if there is one; a
    /// ledger that is only a log lets it go.
    fn end(&mut self, id: usize) {
        let ended = if self.forgets {
            self.open.remove(&id)
        } else {
            None
        };
        let o = ended.as_ref().unwrap_or_else(|| &self.outputs[id]);
        let counts = &mut self.counts;
        if o.complete() {
            counts.complete += 1;
            counts.complete_bytes += o.size;
        } else if o.damaged() {
            counts.damaged += 1;
        } else if o.partial() {
            counts.partial += 1;
        }
        if let Some(log) = &mut self.log {
            let row = format!("{}\t{}", row(o, &log.base, log.notes), o.source.display());
            let row = format!("{row}\r\n");
            if !log.put(&row) {
                if log.unwritten.len() < UNWRITTEN_KEPT {
                    log.unwritten.push(row);
                } else {
                    log.unlisted += 1;
                }
            }
        }
    }

    /// Ends the run: a file still open was not finished, whatever cut it short.
    pub fn close(&mut self, why: &str) {
        let open: Vec<usize> = if self.forgets {
            self.open.keys().copied().collect()
        } else {
            (0..self.outputs.len())
                .filter(|&id| self.outputs[id].state == State::Open)
                .collect()
        };
        for id in open {
            self.partial(id, why);
        }
    }

    /// Every entry of a ledger kept in memory, in the order made; a ledger that is only a log
    /// holds none here.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Files written in full with every part read.
    pub fn complete(&self) -> usize {
        self.counts.complete
    }

    /// Their bytes.
    pub fn complete_bytes(&self) -> u64 {
        self.counts.complete_bytes
    }

    /// Files written in full with zeros where the source could not be read.
    pub fn damaged(&self) -> usize {
        self.counts.damaged
    }

    /// Files that hold less than their size, open ones included.
    pub fn incomplete(&self) -> usize {
        let open = if self.forgets {
            self.open.len()
        } else {
            self.outputs
                .iter()
                .filter(|o| o.state == State::Open)
                .count()
        };
        self.counts.partial + open
    }

    /// Writes `text` as a line of the log, in one write; a ledger kept in memory has none.
    /// A failed write is kept, and the rest are still tried.
    pub fn line(&mut self, text: &str) {
        if let Some(log) = &mut self.log {
            log.put(&format!("{text}\r\n"));
        }
    }

    /// Writes `text` as the log's last line, with no line break after it, so a log cut
    /// anywhere short of its last byte does not end with it.
    pub fn last_line(&mut self, text: &str) {
        if let Some(log) = &mut self.log {
            log.put(text);
        }
    }

    /// The first failed write to the log, if any.
    pub fn log_error(&self) -> Option<&str> {
        self.log.as_ref().and_then(|log| log.error.as_deref())
    }

    /// Tries once more, under `heading`, every row whose write failed; for a log that will
    /// not be ended, so the files it holds are named however it ends.
    pub fn write_unwritten(&mut self, heading: &str) {
        let Some(log) = &mut self.log else {
            return;
        };
        if log.unwritten.is_empty() {
            return;
        }
        log.put(&format!("{heading}\r\n"));
        for row in std::mem::take(&mut log.unwritten) {
            if !log.put(&row) {
                log.unlisted += 1;
            }
        }
    }

    /// Files made whose row is not in the log, counting those still waiting for a second
    /// try.
    pub fn unlisted(&self) -> usize {
        self.log
            .as_ref()
            .map_or(0, |log| log.unlisted + log.unwritten.len())
    }

    /// Closes the log, once its last line is written or withheld; returns its first failed
    /// write. Nothing more is written to it.
    pub fn close_log(&mut self) -> Option<String> {
        let log = self.log.as_mut()?;
        if let Err(e) = log.out.flush() {
            log.error.get_or_insert(e.to_string());
        }
        log.out = Box::new(io::sink());
        log.error.clone()
    }

    /// Writes one report row per file of a ledger kept in memory to `out`, a row at a time:
    /// its path below `base`, its size, what the source said of it when `notes` is set, and
    /// its condition. Rows go by tag, then in the order made, so files are listed in the
    /// order of the items they came from however they were copied. A ledger that is only a
    /// log wrote its rows as they ended.
    pub fn write_rows(&self, out: &mut dyn Write, base: &Path, notes: bool) -> io::Result<()> {
        if self.forgets {
            return Err(io::Error::other("this ledger's rows are in its log"));
        }
        let mut order: Vec<&Output> = self.outputs.iter().collect();
        order.sort_by_key(|o| o.tag);
        for o in order {
            write!(out, "{}\r\n", row(o, base, notes))?;
        }
        Ok(())
    }
}

/// A row of a log written by `kept_with_log` for a file that ended whole or was cut short,
/// read back by a later run into the same folder to find what an earlier run left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedRow {
    /// Its path below the log's folder.
    pub path: PathBuf,
    /// The size of what it was copied from.
    pub size: u64,
    /// What the source said of it.
    pub note: String,
    /// Whether it ended whole, read in full or damaged; else it was cut short.
    pub whole: bool,
    /// The file it was copied from.
    pub source: String,
}

/// The rows of whole files and of files cut short in a log `kept_with_log` wrote, from every
/// run it holds; a row cut short, a removed file's row and any other line are left out.
pub fn logged_rows(text: &str) -> Vec<LoggedRow> {
    text.split("\r\n")
        .filter_map(|line| {
            let mut fields = line.splitn(5, '\t');
            let path = fields.next()?;
            let size = fields.next()?;
            let note = fields.next()?;
            let condition = fields.next()?;
            let source = fields.next()?;
            let whole = condition == "read in full" || condition.starts_with("DAMAGED: ");
            // A whole file's size reads "N bytes", one cut short's "... (AT of N bytes)".
            let size = if whole {
                size.strip_suffix(" bytes")?
            } else if condition.starts_with("PARTIAL: ") {
                size.strip_suffix(" bytes)")?.rsplit_once(" of ")?.1
            } else {
                return None;
            };
            Some(LoggedRow {
                path: PathBuf::from(path),
                size: size.parse().ok()?,
                note: note.to_string(),
                whole,
                source: source.to_string(),
            })
        })
        .collect()
}

impl Log {
    fn new(out: Box<dyn Write + Send>, base: PathBuf, notes: bool) -> Box<Self> {
        Box::new(Self {
            out,
            base,
            notes,
            error: None,
            unwritten: Vec::new(),
            unlisted: 0,
        })
    }

    /// Writes `text` in one write, then flushes; a failure is kept. Whether it was written.
    fn put(&mut self, text: &str) -> bool {
        let written = self
            .out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.flush());
        if let Err(e) = &written {
            self.error.get_or_insert(e.to_string());
        }
        written.is_ok()
    }
}

/// A row of a table: its path below `base`, its size, what the source said of it when
/// `notes` is set, and its condition, separated by tabs.
fn row(o: &Output, base: &Path, notes: bool) -> String {
    let rel = o.path.strip_prefix(base).unwrap_or(&o.path);
    if notes {
        format!(
            "{}\t{}\t{}\t{}",
            rel.display(),
            o.size_text(),
            o.note,
            o.condition()
        )
    } else {
        format!("{}\t{}\t{}", rel.display(), o.size_text(), o.condition())
    }
}

/// Writes `data` through `out` a piece at a time and calls `took` with the bytes taken so
/// far after each piece the writer takes, so a write that fails part way leaves the ledger
/// saying what the file holds. `write_all` would hide what a failed call took.
pub fn write_counted(
    out: &mut dyn Write,
    data: &[u8],
    took: &mut dyn FnMut(u64),
) -> io::Result<()> {
    let mut at = 0usize;
    while at < data.len() {
        match out.write(&data[at..data.len().min(at + 64 * 1024)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                at += n;
                took(at as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// "1 file", "2 files".
pub fn files(n: usize) -> String {
    if n == 1 {
        "1 file".into()
    } else {
        format!("{n} files")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that takes `left` bytes, then fails as a full drive does.
    struct Full {
        left: usize,
        took: Vec<u8>,
    }

    impl Write for Full {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.left == 0 {
                return Err(io::Error::other("the destination is full"));
            }
            let n = buf.len().min(self.left);
            self.left -= n;
            self.took.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The guard: a write that fails part way leaves the entry holding what the writer
    /// took, never 0, and every file whose writes are entered in a ledger writes through
    /// `write_counted`, not `write_all`, which hides what a failed call took.
    #[test]
    fn a_partly_written_file_is_entered_with_what_it_holds() {
        let mut ledger = Ledger::default();
        let id = ledger.made(0, "t.jpg".into(), "t".into(), String::new(), 5000);
        let mut out = Full {
            left: 1234,
            took: Vec::new(),
        };
        let written = write_counted(&mut out, &[7u8; 5000], &mut |n| ledger.wrote(id, n));
        assert!(written.is_err());
        ledger.partial(id, "the destination is full");
        assert_eq!(ledger.get(id).at, 1234);
        assert_eq!(out.took.len(), 1234);
        // Each writes through the one writer (`writer.rs`), whose writes are counted.
        for (name, code) in [
            ("thumbcache.rs", include_str!("thumbcache.rs")),
            ("verify.rs", include_str!("verify.rs")),
            ("health_log.rs", include_str!("health_log.rs")),
        ] {
            let code = &code[..code.find("#[cfg(test)]").unwrap_or(code.len())];
            assert!(!code.contains("write_all("), "{name} writes with write_all");
            assert!(
                code.contains("write_counted(") || code.contains("writer::write_whole("),
                "{name}"
            );
        }
        let writer = include_str!("writer.rs");
        for f in [
            "pub fn write_report_file(",
            "pub fn write_whole(",
            "pub fn write_pending(",
            "pub fn save_map(",
        ] {
            let body = &writer[writer.find(f).unwrap()..];
            assert!(
                body[..body.find("\n}\n").unwrap()].contains("write_counted("),
                "{f}"
            );
        }
        let output = include_str!("output.rs");
        let preview = &output[output.find("fn write_preview(").unwrap()..];
        let preview = &preview[..preview.find("\n    }\n").unwrap()];
        assert!(preview.contains("writer::write_pending(") && !preview.contains("write_all("));
    }

    /// A log that keeps what it is given, and fails each write whose number is in `fail`.
    struct Lines {
        text: std::sync::Arc<std::sync::Mutex<String>>,
        fail: Vec<usize>,
        writes: usize,
    }

    impl Write for Lines {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail.contains(&self.writes) {
                return Err(io::Error::other("the destination is full"));
            }
            self.text
                .lock()
                .unwrap()
                .push_str(std::str::from_utf8(buf).unwrap());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The guard: a ledger that is a log writes each entry's row the moment it ends and
    /// keeps only the open ones; a failed write is kept, and later rows are still written.
    #[test]
    fn a_log_ledger_writes_each_row_as_it_ends_and_keeps_only_open_entries() {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let log = Lines {
            text: shared.clone(),
            fail: vec![2],
            writes: 0,
        };
        let mut ledger = Ledger::to_log(Box::new(log), r"E:\Rescue".into());
        let a = ledger.made(
            0,
            r"E:\Rescue\src\a".into(),
            r"F:\a".into(),
            String::new(),
            100,
        );
        let b = ledger.made(
            0,
            r"E:\Rescue\src\b".into(),
            r"F:\b".into(),
            String::new(),
            50,
        );
        let c = ledger.made(
            0,
            r"E:\Rescue\src\c".into(),
            r"F:\c".into(),
            String::new(),
            10,
        );
        ledger.zeroed(a, std::iter::once(0..10).collect());
        ledger.whole(a);
        assert_eq!(
            *shared.lock().unwrap(),
            "src\\a\t100 bytes\tDAMAGED: 10 bytes unreadable, written as zeros (bytes 0-10)\tF:\\a\r\n"
        );
        assert_eq!(ledger.open.len(), 2);
        // The second write fails: c's row is kept for one more try, and the error kept.
        ledger.whole(c);
        ledger.wrote(b, 20);
        ledger.close("the drive stopped answering");
        assert!(ledger.open.is_empty() && ledger.outputs().is_empty());
        assert_eq!(ledger.log_error(), Some("the destination is full"));
        let text = shared.lock().unwrap().clone();
        assert!(!text.contains("src\\c"), "{text}");
        assert_eq!(ledger.unlisted(), 1);
        assert!(
            text.ends_with(
                "src\\b\t20 B of 50 B (20 of 50 bytes)\tPARTIAL: the drive stopped answering\tF:\\b\r\n"
            ),
            "{text}"
        );
        assert_eq!(
            (ledger.complete(), ledger.damaged(), ledger.incomplete()),
            (1, 1, 1)
        );
        ledger.write_unwritten("Not written above:");
        assert_eq!(ledger.unlisted(), 0);
        let text = shared.lock().unwrap().clone();
        assert!(
            text.ends_with("Not written above:\r\nsrc\\c\t10 bytes\tread in full\tF:\\c\r\n"),
            "{text}"
        );
        assert_eq!(
            ledger.close_log().as_deref(),
            Some("the destination is full")
        );
        assert!(ledger
            .write_rows(&mut Vec::new(), Path::new("E:"), false)
            .is_err());
    }

    /// A ledger kept in memory with a log keeps every entry and writes each row, with its
    /// note, as the entry ends; the rows of whole files and of files cut short read back,
    /// with the size of what each was copied from, and a row cut short and other lines do not.
    #[test]
    fn a_kept_ledger_logs_rows_that_read_back() {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let log = Lines {
            text: shared.clone(),
            fail: Vec::new(),
            writes: 0,
        };
        let mut ledger = Ledger::kept_with_log(Box::new(log), r"E:\Out".into());
        ledger.line("Recovery log");
        let entries: Vec<usize> = [("a.jpg", 100), ("b.jpg", 50), ("c.jpg", 8192), ("d.jpg", 9)]
            .iter()
            .enumerate()
            .map(|(i, (name, size))| {
                ledger.made(
                    i,
                    PathBuf::from(r"E:\Out\Photos").join(name),
                    PathBuf::from(r"Photos").join(name),
                    "deleted, intact".into(),
                    *size,
                )
            })
            .collect();
        ledger.whole(entries[0]);
        ledger.wrote(entries[1], 20);
        ledger.partial(entries[1], "stopped");
        let many: Vec<Range<u64>> = (0..9).map(|i| i * 512..i * 512 + 10).collect();
        ledger.zeroed(entries[2], many);
        ledger.whole(entries[2]);
        ledger.zeroed(entries[3], std::iter::once(0..4).collect());
        ledger.flawed(entries[3], "the record is damaged");
        ledger.whole(entries[3]);
        assert_eq!(ledger.outputs().len(), 4, "every entry is kept");
        let text = shared.lock().unwrap().clone();
        assert!(
            text.contains(
                "Photos\\a.jpg\t100 bytes\tdeleted, intact\tread in full\tPhotos\\a.jpg\r\n"
            ),
            "{text}"
        );
        let cut = format!("{text}Photos\\e.jpg\t5 bytes\tintact\tread in");
        let rows = logged_rows(&cut);
        let read: Vec<_> = rows
            .iter()
            .map(|r| (r.path.display().to_string(), r.size, r.whole))
            .collect();
        assert_eq!(
            read,
            [
                ("Photos\\a.jpg".to_string(), 100, true),
                ("Photos\\b.jpg".to_string(), 50, false),
                ("Photos\\c.jpg".to_string(), 8192, true),
                ("Photos\\d.jpg".to_string(), 9, true),
            ]
        );
        assert_eq!(
            (rows[0].source.as_str(), rows[0].note.as_str()),
            ("Photos\\a.jpg", "deleted, intact")
        );
    }

    #[test]
    fn closing_marks_every_unfinished_file_partial() {
        let mut ledger = Ledger::default();
        let a = ledger.made(0, "a".into(), "A".into(), String::new(), 10);
        let b = ledger.made(1, "b".into(), "B".into(), String::new(), 10);
        ledger.whole(a);
        ledger.wrote(b, 4);
        ledger.close("the drive stopped answering");
        assert!(ledger.get(a).complete());
        assert!(ledger.get(b).partial());
        assert_eq!(ledger.get(b).size_text(), "4 B of 10 B (4 of 10 bytes)");
        assert!(ledger.outputs().iter().all(|o| o.state != State::Open));
        assert_eq!(files(1), "1 file");
        assert_eq!(files(0), "0 files");
    }
}
