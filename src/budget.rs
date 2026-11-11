//! One budget for every parser of untrusted on-disk or firmware data: a file system's own
//! records, a registry hive, a thumbnail cache, a picture's previews, a recovered file
//! checked, a carve of the whole drive, a crash dump folder, the firmware's SMBIOS table.
//! Their sizes, counts and offsets come from data that may be damaged or forged, so each
//! parser states its limits as a `Limits` constant, takes a `Budget` made from them, charges
//! it at its natural unit, stops when a charge is refused, and says in its result which
//! limit it reached, in words a technician reads (`Budget::said`). Nothing is cut silently.
//!
//! The budget is passed as `&mut Budget`: one parse owns it, recursion and helpers borrow
//! it in turn, and every charge is visible where it is made. No counter is shared between
//! threads; the only shared part is the stop flag a window or an agent sets.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::tools::drives::bytes_text;
use crate::tools::drives::details::grouped;

/// Which limit stopped a parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Limit {
    /// It reached the most items of its unit it takes.
    Count,
    /// It went through the most bytes of the drive's data it reads.
    Bytes,
    /// What it holds reached its memory limit.
    Memory,
    /// It reached its time limit.
    Time,
    /// A person or an agent stopped it.
    Stopped,
}

/// What one parser may spend, stated by the parser as a constant with its numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// What the parse is, for people: "the scan of the file table".
    pub what: &'static str,
    /// What one counted item is, plural, for people: "file table records".
    pub unit: &'static str,
    /// The most items counted.
    pub count: u64,
    /// The most bytes of the drive's data gone through: read from the source, or walked in
    /// a table already read.
    pub bytes: u64,
    /// The most bytes held at once by what the parse keeps.
    pub memory: u64,
    /// The deepest nesting followed (folders, boxes, lists). A deeper part is left out and
    /// counted, and the parse goes on with the rest.
    pub depth: u32,
    /// What nests, plural, for people: "folders".
    pub nested: &'static str,
    /// The longest the parse may take. None for work a person starts and watches with a
    /// Stop button: it still checks the stop flag at every item.
    pub time: Option<Duration>,
}

/// What a parse spent, for tests and results.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Spent {
    pub count: u64,
    pub bytes: u64,
    /// Held now, and the most held at once.
    pub memory: u64,
    pub peak: u64,
    /// Parts left out for being nested too deep.
    pub too_deep: u64,
}

/// A parse's budget: its limits, what it has spent, and the first limit it reached.
pub struct Budget<'c> {
    limits: Limits,
    cancel: Option<&'c AtomicBool>,
    started: Instant,
    spent: Spent,
    hit: Option<Limit>,
}

impl<'c> Budget<'c> {
    /// A budget with `limits`, stopped when `cancel` is set.
    pub fn new(limits: Limits, cancel: Option<&'c AtomicBool>) -> Self {
        Self {
            limits,
            cancel,
            started: Instant::now(),
            spent: Spent::default(),
            hit: None,
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn spent(&self) -> Spent {
        self.spent
    }

    /// The first limit the parse reached, if one: the one its result names. A limit once
    /// reached keeps refusing: the count, bytes and memory spent stay at it, and the stop
    /// flag and the clock do not go back. A parse that stops reading at its count may still
    /// list what it read, within its memory.
    pub fn hit(&self) -> Option<Limit> {
        self.hit
    }

    fn refuse(&mut self, limit: Limit) -> Result<(), Limit> {
        self.hit.get_or_insert(limit);
        Err(limit)
    }

    /// Checks the stop flag and the clock; call it at every item of a loop that charges
    /// nothing else.
    pub fn tick(&mut self) -> Result<(), Limit> {
        if self.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return self.refuse(Limit::Stopped);
        }
        if self.limits.time.is_some_and(|t| self.started.elapsed() > t) {
            return self.refuse(Limit::Time);
        }
        Ok(())
    }

    /// Counts `n` items; refused, and nothing counted, when they would pass the limit or
    /// once the count was refused before.
    pub fn count(&mut self, n: u64) -> Result<(), Limit> {
        self.tick()?;
        if self.hit == Some(Limit::Count) {
            return Err(Limit::Count);
        }
        match self.spent.count.checked_add(n) {
            Some(total) if total <= self.limits.count => {
                self.spent.count = total;
                Ok(())
            }
            _ => self.refuse(Limit::Count),
        }
    }

    /// Counts one item.
    pub fn item(&mut self) -> Result<(), Limit> {
        self.count(1)
    }

    /// Counts `n` bytes of the drive's data gone through; refused as `count` is.
    pub fn read(&mut self, n: u64) -> Result<(), Limit> {
        self.tick()?;
        if self.hit == Some(Limit::Bytes) {
            return Err(Limit::Bytes);
        }
        match self.spent.bytes.checked_add(n) {
            Some(total) if total <= self.limits.bytes => {
                self.spent.bytes = total;
                Ok(())
            }
            _ => self.refuse(Limit::Bytes),
        }
    }

    /// Counts `n` bytes more held; refused, and nothing counted, past the memory limit.
    pub fn hold(&mut self, n: u64) -> Result<(), Limit> {
        self.tick()?;
        match self.spent.memory.checked_add(n) {
            Some(total) if total <= self.limits.memory => {
                self.spent.memory = total;
                self.spent.peak = self.spent.peak.max(total);
                Ok(())
            }
            _ => self.refuse(Limit::Memory),
        }
    }

    /// Counts `n` bytes no longer held.
    pub fn free(&mut self, n: u64) {
        self.spent.memory = self.spent.memory.saturating_sub(n);
    }

    /// Charges the memory of `n` items of `T`; refused past the limit, or when the size
    /// cannot be counted.
    fn charge<T>(&mut self, n: usize) -> Result<u64, Limit> {
        let Some(bytes) = n
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|b| u64::try_from(b).ok())
        else {
            return self.refuse(Limit::Memory).map(|()| 0);
        };
        self.hold(bytes).map(|()| bytes)
    }

    /// `n` zeroed bytes, made only once their memory is charged (`hold`): a buffer whose size
    /// comes from the data is never allocated past the limit. Every size-driven buffer of a
    /// parser comes from here or `filled`, `room` and `grow`; the caller frees the charge
    /// (`free`) when it lets the buffer go.
    pub fn buffer(&mut self, n: usize) -> Result<Vec<u8>, Limit> {
        self.charge::<u8>(n)?;
        Ok(vec![0u8; n])
    }

    /// `n` copies of `value`, made only once their memory is charged.
    pub fn filled<T: Clone>(&mut self, value: T, n: usize) -> Result<Vec<T>, Limit> {
        self.charge::<T>(n)?;
        Ok(vec![value; n])
    }

    /// An empty list with room for `n` items, made only once their memory is charged.
    pub fn room<T>(&mut self, n: usize) -> Result<Vec<T>, Limit> {
        self.charge::<T>(n)?;
        Ok(Vec::with_capacity(n))
    }

    /// Makes `buf` `n` bytes long, charging what it grows by before it grows and freeing
    /// what it shrinks by.
    pub fn grow(&mut self, buf: &mut Vec<u8>, n: usize) -> Result<(), Limit> {
        match n.checked_sub(buf.len()) {
            Some(more) => {
                self.charge::<u8>(more)?;
            }
            None => self.free((buf.len() - n) as u64),
        }
        buf.resize(n, 0);
        Ok(())
    }

    /// Whether a part at nesting `depth` (the top is 0) is followed. A deeper one is
    /// counted as left out and refused; the parse goes on with the rest.
    pub fn within_depth(&mut self, depth: usize) -> bool {
        if depth <= self.limits.depth as usize {
            return true;
        }
        self.spent.too_deep += 1;
        false
    }

    /// Marks the parse stopped at `limit` by a check of its own, such as a table that
    /// states more entries than the parser takes.
    pub fn reach(&mut self, limit: Limit) {
        self.hit.get_or_insert(limit);
    }

    /// Which limit it reached, in plain words, and the parts left out for depth; None when
    /// it reached none.
    pub fn said(&self) -> Option<String> {
        let l = &self.limits;
        let what = upper_first(l.what);
        let stopped = self.hit.map(|hit| match hit {
            Limit::Count => format!(
                "{what} stopped at its limit of {} {}.",
                grouped(u128::from(l.count)),
                l.unit
            ),
            Limit::Bytes => format!(
                "{what} stopped at its limit of {} read.",
                bytes_text(l.bytes)
            ),
            Limit::Memory => format!(
                "{what} stopped at its memory limit of {}.",
                bytes_text(l.memory)
            ),
            Limit::Time => format!(
                "{what} stopped at its time limit of {} seconds.",
                l.time.map_or(0, |t| t.as_secs())
            ),
            Limit::Stopped => format!("{what} was stopped before the end."),
        });
        let deep = (self.spent.too_deep > 0).then(|| {
            format!(
                "{} of its {} lay more than {} deep and {} not followed.",
                grouped(u128::from(self.spent.too_deep)),
                l.nested,
                l.depth,
                if self.spent.too_deep == 1 {
                    "was"
                } else {
                    "were"
                }
            )
        });
        match (stopped, deep) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => Some(format!("{a} {b}")),
        }
    }
}

fn upper_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Source text of the files that hold a parser of untrusted data, cut at their tests, for
/// the guard that every parser's entry function takes a budget.
#[cfg(test)]
pub(crate) fn parser_code(file: &str) -> &'static str {
    let text: &'static str = match file {
        "fs/ntfs.rs" => include_str!("recovery/fs/ntfs.rs"),
        "fs/fat.rs" => include_str!("recovery/fs/fat.rs"),
        "fs/exfat.rs" => include_str!("recovery/fs/exfat.rs"),
        "fs/parts.rs" => include_str!("recovery/fs/parts.rs"),
        "fs/mod.rs" => include_str!("recovery/fs/mod.rs"),
        "copy.rs" => include_str!("recovery/copy.rs"),
        "restore.rs" => include_str!("recovery/restore.rs"),
        "migrate/hive.rs" => include_str!("recovery/migrate/hive.rs"),
        "migrate/mod.rs" => include_str!("recovery/migrate/mod.rs"),
        "thumbcache.rs" => include_str!("recovery/thumbcache.rs"),
        "preview.rs" => include_str!("recovery/preview.rs"),
        "verify.rs" => include_str!("recovery/verify.rs"),
        "verify/pdf.rs" => include_str!("recovery/verify/pdf.rs"),
        "verify/zip.rs" => include_str!("recovery/verify/zip.rs"),
        "verify/media.rs" => include_str!("recovery/verify/media.rs"),
        "carve.rs" => include_str!("recovery/carve.rs"),
        "crashes.rs" => include_str!("tools/crashes.rs"),
        "smbios.rs" => include_str!("tools/cpu_memory/smbios.rs"),
        other => panic!("no parser file {other}"),
    };
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        what: "the test parse",
        unit: "records",
        count: 10,
        bytes: 100,
        memory: 1000,
        depth: 2,
        nested: "folders",
        time: Some(Duration::from_secs(60)),
    };

    #[test]
    fn each_limit_is_refused_said_and_sticks() {
        let mut b = Budget::new(LIMITS, None);
        assert!(b.count(9).is_ok());
        assert_eq!(b.count(2), Err(Limit::Count));
        assert_eq!(b.spent().count, 9);
        // Once reached, the count stays refused, even for what would fit; other kinds of
        // charge go on, so what was read can still be listed.
        assert_eq!(b.item(), Err(Limit::Count));
        assert!(b.read(1).is_ok() && b.hold(1).is_ok());
        assert_eq!(b.hit(), Some(Limit::Count));
        assert_eq!(
            b.said().unwrap(),
            "The test parse stopped at its limit of 10 records."
        );

        let mut b = Budget::new(LIMITS, None);
        assert_eq!(b.read(101), Err(Limit::Bytes));
        assert_eq!(b.spent().bytes, 0);
        assert!(b.said().unwrap().contains("limit of 100 B read"));

        let mut b = Budget::new(LIMITS, None);
        assert!(b.hold(900).is_ok());
        b.free(500);
        assert!(b.hold(600).is_ok());
        assert_eq!(b.hold(1), Err(Limit::Memory));
        assert_eq!((b.spent().memory, b.spent().peak), (1000, 1000));
        assert!(b.said().unwrap().contains("memory limit of 1.0 kB"));

        let stop = AtomicBool::new(true);
        let mut b = Budget::new(LIMITS, Some(&stop));
        assert_eq!(b.tick(), Err(Limit::Stopped));
        assert_eq!(
            b.said().unwrap(),
            "The test parse was stopped before the end."
        );

        let mut b = Budget::new(
            Limits {
                time: Some(Duration::ZERO),
                ..LIMITS
            },
            None,
        );
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(b.item(), Err(Limit::Time));
        assert!(b.said().unwrap().contains("time limit of 0 seconds"));
    }

    /// The text of `file`'s function `f` from its name to the brace that opens its body.
    fn signature(file: &str, f: &str) -> &'static str {
        let code = parser_code(file);
        let at = code.find(f).unwrap_or_else(|| panic!("{file} has no {f}"));
        let rest = &code[at..];
        &rest[..rest.find('{').unwrap_or(rest.len())]
    }

    /// The guard: every parser of untrusted data states its limits as a `Limits` constant
    /// and takes a budget at its entry, so none runs unbounded or cuts silently.
    #[test]
    fn every_parser_states_its_limits_and_takes_a_budget() {
        let parsers: [(&str, &str, &[&str]); 12] = [
            (
                "fs/ntfs.rs",
                "pub const LIMITS: Limits",
                &["pub fn scan(", "pub fn live("],
            ),
            ("fs/fat.rs", "pub const LIMITS: Limits", &["pub fn scan("]),
            ("fs/exfat.rs", "pub const LIMITS: Limits", &["pub fn scan("]),
            (
                "fs/parts.rs",
                "pub const LIMITS: Limits",
                &["pub fn find_within("],
            ),
            (
                "migrate/hive.rs",
                "pub const LIMITS: Limits",
                &["pub fn windows(", "pub fn parse("],
            ),
            (
                "migrate/mod.rs",
                "pub const WALK: Limits",
                &[
                    "\nfn walk(",
                    "\nfn profiles(",
                    "\nfn plan(",
                    "\nfn measure(",
                ],
            ),
            (
                "thumbcache.rs",
                "pub const LIMITS: Limits",
                &["pub fn walk("],
            ),
            (
                "preview.rs",
                "pub const LIMITS: Limits",
                &["pub fn find(", "pub fn best("],
            ),
            (
                "verify.rs",
                "pub const LISTING: Limits",
                &["pub fn check(", "\nfn list("],
            ),
            (
                "carve.rs",
                "pub const LIMITS: Limits",
                &["pub fn carve_within("],
            ),
            (
                "crashes.rs",
                "pub(crate) const LIMITS: budget::Limits",
                &["pub(crate) fn list_within("],
            ),
            ("smbios.rs", "pub const LIMITS: Limits", &["pub fn parse("]),
        ];
        for (file, limits, entries) in parsers {
            assert!(
                parser_code(file).contains(limits),
                "{file} states no limits"
            );
            for f in entries {
                assert!(
                    signature(file, f).contains("Budget"),
                    "{file}: {} takes no budget",
                    f.trim()
                );
            }
        }
        assert!(parser_code("verify.rs").contains("pub const LIMITS: Limits"));
        // The copy follows folders no deeper than its stated depth.
        let copy = parser_code("copy.rs");
        let first = &copy[copy.find("fn first_pass(").unwrap()..];
        assert!(
            first[..first.find("\n    }\n").unwrap()].contains("depth > MAX_DEPTH"),
            "the copy follows folders without a depth limit"
        );
    }

    /// The guard: a value that could not be read is said to be unread, never taken for an
    /// empty length, an unrecognized kind or the start of 1970.
    #[test]
    fn no_failed_read_is_taken_for_a_value() {
        for file in ["verify.rs", "preview.rs", "thumbcache.rs"] {
            assert!(
                !parser_code(file).contains(".map(|m| m.len()).unwrap_or(0)"),
                "{file} takes a length it could not read for 0"
            );
        }
        assert!(
            !parser_code("verify.rs").contains("filter_map(|e| e.ok())"),
            "the folder listing drops entries it could not read"
        );
        assert!(
            !parser_code("restore.rs").contains("Err(_) => FsKind::Other"),
            "an unread file system is taken for an unrecognized one"
        );
        assert!(
            !parser_code("fs/mod.rs").contains("unwrap_or(std::time::UNIX_EPOCH)"),
            "an impossible time is shown as 1970"
        );
    }

    /// Every file holding a parser of untrusted data. `copy.rs` and `restore.rs` are not
    /// parsers: the copy moves bytes in fixed pieces (`CHUNK`, one sector), and the restore
    /// reads back the partition table it wrote, its size checked first (at most 4,096
    /// entries of at most 4,096 bytes).
    const PARSERS: [&str; 16] = [
        "fs/ntfs.rs",
        "fs/fat.rs",
        "fs/exfat.rs",
        "fs/parts.rs",
        "fs/mod.rs",
        "migrate/hive.rs",
        "migrate/mod.rs",
        "thumbcache.rs",
        "preview.rs",
        "verify.rs",
        "verify/pdf.rs",
        "verify/zip.rs",
        "verify/media.rs",
        "carve.rs",
        "crashes.rs",
        "smbios.rs",
    ];

    /// Whether an allocation's size is fixed in the code: a number, a constant, a shift of
    /// numbers, each perhaps cast.
    fn fixed(size: &str) -> bool {
        let size = size.trim().trim_start_matches('(').trim_end_matches(')');
        let size = size.strip_suffix(" as usize").unwrap_or(size).trim();
        let word = |w: &str| {
            !w.is_empty()
                && (w.chars().all(|c| c.is_ascii_digit() || c == '_')
                    || (w.starts_with(|c: char| c.is_ascii_uppercase())
                        && w.chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')))
        };
        word(size) || size.split(" << ").all(|w| word(w.trim()))
    }

    /// The size argument of each allocation of `code` that is driven by a size: `vec![v; n]`,
    /// `Vec::with_capacity(n)` and `.resize(n, v)`.
    fn sized_allocations(code: &str) -> Vec<String> {
        let mut found = Vec::new();
        for (open, close, split) in [
            ("vec![", ']', Some(';')),
            ("with_capacity(", ')', None),
            (".resize(", ')', Some(',')),
        ] {
            for (at, _) in code.match_indices(open) {
                let rest = &code[at + open.len()..];
                let (mut depth, mut end, mut cut) = (0i32, rest.len(), None);
                for (i, c) in rest.char_indices() {
                    match c {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' if depth > 0 => depth -= 1,
                        c if c == close && depth == 0 => {
                            end = i;
                            break;
                        }
                        c if Some(c) == split && depth == 0 && cut.is_none() => cut = Some(i),
                        _ => {}
                    }
                }
                let size = match (split, cut) {
                    (Some(';'), Some(c)) => &rest[c + 1..end],
                    (Some(';'), None) => continue,
                    (Some(_), Some(c)) => &rest[..c],
                    _ => &rest[..end],
                };
                if !fixed(size) {
                    let line = code[..at].matches('\n').count() + 1;
                    found.push(format!("line {line}: {open}..{}", size.trim()));
                }
            }
        }
        found
    }

    /// The guard (cause C): no parser of untrusted data makes a buffer or a list whose size
    /// comes from the data except through its budget (`Budget::buffer`, `filled`, `room`,
    /// `grow`), which charges the memory before it is allocated.
    /// Sized allocations no larger than a list the parser already holds within its budget,
    /// by file and size, with why.
    const NO_LARGER_THAN_HELD: [(&str, &str, &str); 1] = [(
        "crashes.rs",
        "dumps.len()",
        "one flag for each dump file already listed within the listing's budget",
    )];

    #[test]
    fn every_sized_allocation_of_a_parser_is_charged_first() {
        let mut unbudgeted = Vec::new();
        for file in PARSERS {
            for at in sized_allocations(parser_code(file)) {
                let held = NO_LARGER_THAN_HELD
                    .iter()
                    .any(|(f, size, _)| *f == file && at.ends_with(&format!("..{size}")));
                if !held {
                    unbudgeted.push(format!("{file} {at}"));
                }
            }
        }
        assert!(
            unbudgeted.is_empty(),
            "allocated before it is charged:\n{}",
            unbudgeted.join("\n")
        );
        // The rule catches each form, and lets fixed sizes through.
        assert_eq!(sized_allocations("let b = vec![0u8; len];").len(), 1);
        assert_eq!(sized_allocations("Vec::with_capacity(n * 2)").len(), 1);
        assert_eq!(sized_allocations("buf.resize(want, 0);").len(), 1);
        assert!(
            sized_allocations("vec![0u8; 8192]; vec![0u8; CHUNK as usize]; vec![0; 1 << 16]")
                .is_empty()
        );
    }

    /// A buffer is made only once its memory is charged: one past the limit is refused and
    /// never allocated, and what is charged is freed with it.
    #[test]
    fn a_buffer_is_charged_before_it_is_made() {
        let mut b = Budget::new(LIMITS, None);
        assert_eq!(b.buffer(1001), Err(Limit::Memory));
        // Made before the charge, 64 TiB would fail to allocate and end the run.
        assert_eq!(b.buffer(1 << 46), Err(Limit::Memory));
        assert_eq!(b.spent().memory, 0);
        let buf = b.buffer(600).unwrap();
        assert_eq!((buf.len(), b.spent().memory), (600, 600));
        assert_eq!(
            b.room::<u64>(100).map(|v| v.capacity() >= 100),
            Err(Limit::Memory)
        );
        let mut b = Budget::new(LIMITS, None);
        let mut buf = Vec::new();
        b.grow(&mut buf, 300).unwrap();
        b.grow(&mut buf, 100).unwrap();
        assert_eq!((buf.len(), b.spent().memory), (100, 100));
        assert_eq!(b.filled(0u32, usize::MAX), Err(Limit::Memory));
    }

    #[test]
    fn depth_leaves_out_a_part_and_goes_on() {
        let mut b = Budget::new(LIMITS, None);
        assert!(b.within_depth(2));
        assert!(!b.within_depth(3));
        assert!(!b.within_depth(9));
        assert_eq!(b.hit(), None);
        assert!(b.item().is_ok());
        assert_eq!(
            b.said().unwrap(),
            "2 of its folders lay more than 2 deep and were not followed."
        );
        assert_eq!(Budget::new(LIMITS, None).said(), None);
    }
}
