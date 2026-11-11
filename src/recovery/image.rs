//! Rescue imaging in the manner of GNU ddrescue: copy the easy areas in large blocks first,
//! skipping ahead from errors with a growing skip; then trim the edges of the failed areas,
//! scrape what is left sector by sector, and optionally retry the bad sectors. The image is a
//! raw, sparse file and the map is a GNU ddrescue mapfile, so ddrescue and ddrescueview can
//! open both, and a stopped run resumes from the map.
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::dest::{Folder, Guard};
use super::events::{Event, EventLog, Figures};
use super::photos::{self, PhotosFirst};
use super::read_limit::LimitEvent;
use super::reader::Reader;
use super::zones::Zones;
use super::{check_destination, write_all_at, BlockSource, ReadError, Scope, Sink, SourceId};
use crate::tools::drives::ata::DriveId;
use crate::tools::drives::bytes_text;
use crate::tools::drives::health::{Disk, Health};

// ---- the map ---------------------------------------------------------------------------

/// A block's state, as ddrescue writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// `?` not read yet.
    Untried,
    /// `*` a read failed here; its edges are not trimmed yet.
    NonTrimmed,
    /// `/` trimmed; the middle is not read sector by sector yet.
    NonScraped,
    /// `-` bad sectors.
    Bad,
    /// `+` rescued.
    Rescued,
}

impl Status {
    pub fn symbol(self) -> char {
        match self {
            Status::Untried => '?',
            Status::NonTrimmed => '*',
            Status::NonScraped => '/',
            Status::Bad => '-',
            Status::Rescued => '+',
        }
    }

    fn from_symbol(c: char) -> Option<Self> {
        Some(match c {
            '?' => Status::Untried,
            '*' => Status::NonTrimmed,
            '/' => Status::NonScraped,
            '-' => Status::Bad,
            '+' => Status::Rescued,
            _ => return None,
        })
    }

    /// Failed, in any stage.
    pub fn failed(self) -> bool {
        matches!(self, Status::NonTrimmed | Status::NonScraped | Status::Bad)
    }

    /// What a failed read of `len` bytes marks: one sector tried on its own is bad and is
    /// read again only by a retry pass; a larger area is left for trimming and scraping,
    /// which read its sectors on their own for the first time.
    pub fn after_failed_read(len: u64, sector: u64) -> Status {
        if len <= sector {
            Status::Bad
        } else {
            Status::NonTrimmed
        }
    }
}

/// What one cell of the map strip shows: what most of its bytes are, and for a mostly
/// rescued cell whether any of it failed but was recovered (orange).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    Rescued,
    /// Mostly rescued, with failed blocks in it.
    Partly,
    Untried,
    /// Mostly failed, and trimming or scraping will still read it.
    ToRetry,
    /// Mostly bad: trimming and scraping gave up on it; only a retry pass reads it again.
    Failed,
}

/// The phase a run is in, the map's `current_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Copying,
    Trimming,
    Scraping,
    Retrying,
    Finished,
}

impl Phase {
    fn symbol(self) -> char {
        match self {
            Phase::Copying => '?',
            Phase::Trimming => '*',
            Phase::Scraping => '/',
            Phase::Retrying => '-',
            Phase::Finished => '+',
        }
    }

    fn from_symbol(c: char) -> Option<Self> {
        Some(match c {
            '?' => Phase::Copying,
            '*' => Phase::Trimming,
            '/' => Phase::Scraping,
            '-' => Phase::Retrying,
            '+' => Phase::Finished,
            // Sweeping, filling and generating: resume as copying.
            '%' | 'F' | 'G' => Phase::Copying,
            _ => return None,
        })
    }

    /// The comment ddrescue writes above the status line.
    fn comment(self, pass: u32) -> String {
        match self {
            Phase::Copying => format!(
                "Copying non-tried blocks... Pass {pass} ({})",
                if pass == 2 { "backwards" } else { "forwards" }
            ),
            Phase::Trimming => "Trimming failed blocks...".into(),
            Phase::Scraping => "Scraping failed blocks...".into(),
            // Retry 1 is the reverse pass; any further retries asked for follow it.
            Phase::Retrying => format!(
                "Retrying bad sectors... Retry {pass} ({})",
                if pass == 1 { "backwards" } else { "forwards" }
            ),
            Phase::Finished => "Finished".into(),
        }
    }

    /// For people.
    pub fn name(self, pass: u32) -> String {
        match self {
            Phase::Copying => match pass {
                1 => "Copying the easy areas (pass 1, forwards, skipping errors)".into(),
                2 => "Copying skipped areas (pass 2, backwards)".into(),
                3 => "Copying skipped areas (pass 3, forwards)".into(),
                _ => format!("Copying what is left (pass {pass}, no skipping)"),
            },
            Phase::Trimming => "Trimming the edges of failed areas".into(),
            Phase::Scraping => "Scraping failed areas sector by sector".into(),
            Phase::Retrying if pass == 1 => {
                "Retry 1: reading bad areas once more from their far end (reverse pass)".into()
            }
            Phase::Retrying => format!("Retry {pass}: reading bad sectors once more, forwards"),
            Phase::Finished => "Finished".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub pos: u64,
    pub size: u64,
    pub status: Status,
}

impl Block {
    pub fn end(&self) -> u64 {
        self.pos + self.size
    }
}

/// A ddrescue map: contiguous blocks from 0 to the source's length, and where the run is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Map {
    pub blocks: Vec<Block>,
    pub current_pos: u64,
    pub phase: Phase,
    pub pass: u32,
}

impl Map {
    pub fn new(len: u64) -> Self {
        let blocks = if len > 0 {
            vec![Block {
                pos: 0,
                size: len,
                status: Status::Untried,
            }]
        } else {
            Vec::new()
        };
        Self {
            blocks,
            current_pos: 0,
            phase: Phase::Copying,
            pass: 1,
        }
    }

    pub fn len(&self) -> u64 {
        self.blocks.last().map_or(0, Block::end)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes with this status.
    pub fn count(&self, status: Status) -> u64 {
        self.blocks
            .iter()
            .filter(|b| b.status == status)
            .map(|b| b.size)
            .sum()
    }

    /// Bytes that failed in any stage.
    pub fn failed(&self) -> u64 {
        self.blocks
            .iter()
            .filter(|b| b.status.failed())
            .map(|b| b.size)
            .sum()
    }

    /// Marks `pos..pos + size` and merges it with neighbours of the same status.
    pub fn set(&mut self, pos: u64, size: u64, status: Status) {
        let end = pos.saturating_add(size).min(self.len());
        if end <= pos {
            return;
        }
        let first = self.blocks.partition_point(|b| b.end() <= pos);
        let last = self.blocks.partition_point(|b| b.pos < end);
        let mut replacement = Vec::with_capacity(3);
        if first < last {
            let head = self.blocks[first];
            if head.pos < pos {
                replacement.push(Block {
                    pos: head.pos,
                    size: pos - head.pos,
                    status: head.status,
                });
            }
        }
        replacement.push(Block {
            pos,
            size: end - pos,
            status,
        });
        if first < last {
            let tail = self.blocks[last - 1];
            if tail.end() > end {
                replacement.push(Block {
                    pos: end,
                    size: tail.end() - end,
                    status: tail.status,
                });
            }
        }
        let count = replacement.len();
        self.blocks.splice(first..last, replacement);
        // Merge within the changed window and its two neighbours.
        let low = first.saturating_sub(1);
        let mut index = (first + count + 1).min(self.blocks.len()) - 1;
        while index > low {
            if self.blocks[index - 1].status == self.blocks[index].status {
                self.blocks[index - 1].size += self.blocks[index].size;
                self.blocks.remove(index);
            }
            index -= 1;
        }
    }

    /// The first area with `status` that ends after `from`, starting no earlier than `from`.
    pub fn find(&self, status: Status, from: u64) -> Option<Block> {
        self.find_where(|s| s == status, from)
    }

    /// The damaged area around `pos..end`: that span joined with every block whose status
    /// `wanted` accepts that lies within `bridge` bytes of it, and of those in turn, both
    /// ways (`AREA_BRIDGE`).
    pub fn area(
        &self,
        pos: u64,
        end: u64,
        bridge: u64,
        wanted: impl Fn(Status) -> bool,
    ) -> (u64, u64) {
        let (mut lo, mut hi) = (pos, end.max(pos));
        let i = self.blocks.partition_point(|b| b.end() <= pos);
        if let Some(b) = self.blocks.get(i).filter(|b| wanted(b.status)) {
            lo = lo.min(b.pos);
        }
        for b in self.blocks[..i].iter().rev() {
            if b.end().saturating_add(bridge) < lo {
                break;
            }
            if wanted(b.status) {
                lo = lo.min(b.pos);
            }
        }
        for b in &self.blocks[i..] {
            if b.pos > hi.saturating_add(bridge) {
                break;
            }
            if wanted(b.status) {
                hi = hi.max(b.end());
            }
        }
        (lo, hi)
    }

    /// The first area whose status `wanted` accepts that ends after `from`, starting no
    /// earlier than `from`.
    pub fn find_where(&self, wanted: impl Fn(Status) -> bool, from: u64) -> Option<Block> {
        let start = self.blocks.partition_point(|b| b.end() <= from);
        self.blocks[start..]
            .iter()
            .find(|b| wanted(b.status))
            .map(|b| {
                let pos = b.pos.max(from);
                Block {
                    pos,
                    size: b.end() - pos,
                    status: b.status,
                }
            })
    }

    /// The last area with `status` that starts before `before`, ending no later than it.
    pub fn find_back(&self, status: Status, before: u64) -> Option<Block> {
        self.find_back_where(|s| s == status, before)
    }

    /// The last area whose status `wanted` accepts that starts before `before`, ending no
    /// later than it.
    pub fn find_back_where(&self, wanted: impl Fn(Status) -> bool, before: u64) -> Option<Block> {
        let end = self.blocks.partition_point(|b| b.pos < before);
        self.blocks[..end]
            .iter()
            .rev()
            .find(|b| wanted(b.status))
            .map(|b| Block {
                pos: b.pos,
                size: b.end().min(before) - b.pos,
                status: b.status,
            })
    }

    /// Marks the parts of `pos..pos + size` that have status `from` as `to`, and leaves the
    /// rest as it is.
    pub fn set_where(&mut self, pos: u64, size: u64, from: Status, to: Status) {
        let end = pos.saturating_add(size);
        let mut at = pos;
        while let Some(block) = self.find(from, at).filter(|b| b.pos < end) {
            let stop = block.end().min(end);
            self.set(block.pos, stop - block.pos, to);
            at = stop;
        }
    }

    /// Whether every byte of `pos..pos + size` has `status`.
    pub fn all(&self, pos: u64, size: u64, status: Status) -> bool {
        let end = pos.saturating_add(size);
        let first = self.blocks.partition_point(|b| b.end() <= pos);
        let mut at = pos;
        for block in &self.blocks[first..] {
            if at >= end {
                break;
            }
            if block.pos > at || block.status != status {
                return false;
            }
            at = block.end();
        }
        at >= end
    }

    /// Bytes of `areas` (sorted (start, end) offsets) rescued and failed so far.
    pub fn count_in(&self, areas: &[(u64, u64)]) -> (u64, u64) {
        let (mut rescued, mut failed) = (0, 0);
        for &(start, end) in areas {
            let first = self.blocks.partition_point(|b| b.end() <= start);
            for block in self.blocks[first..].iter().take_while(|b| b.pos < end) {
                let bytes = block.end().min(end) - block.pos.max(start);
                match block.status {
                    Status::Rescued => rescued += bytes,
                    s if s.failed() => failed += bytes,
                    _ => {}
                }
            }
        }
        (rescued, failed)
    }

    /// Where strip cell `cell` of `cells` starts. `strip` and `strip_cell` both place bytes
    /// by it, so a position and the cell drawn for it never disagree at an edge.
    #[cfg(test)]
    fn strip_edge(&self, cell: usize, cells: usize) -> u64 {
        Self::strip_edge_in(&(0..self.len()), cell, cells)
    }

    /// Where cell `cell` of `cells` equal parts of `range` starts; cell `cells` starts at its
    /// end. The whole map's strip is the strip of `0..len`.
    pub fn strip_edge_in(range: &Range<u64>, cell: usize, cells: usize) -> u64 {
        if cells == 0 {
            return range.start;
        }
        let span = range.end.saturating_sub(range.start) as u128;
        range.start + ((cell as u128 * span) / cells as u128) as u64
    }

    /// The strip cell of `cells` that holds byte `pos`: the last cell starting at or before
    /// it.
    pub fn strip_cell(&self, pos: u64, cells: usize) -> usize {
        let len = self.len();
        if cells == 0 || len == 0 {
            return 0;
        }
        Self::strip_cell_in(&(0..len), pos.min(len - 1), cells).unwrap_or(0)
    }

    /// The cell of `cells` equal parts of `range` that holds byte `pos`, None outside it.
    pub fn strip_cell_in(range: &Range<u64>, pos: u64, cells: usize) -> Option<usize> {
        if cells == 0 || !range.contains(&pos) {
            return None;
        }
        let span = (range.end - range.start) as u128;
        let pos = (pos - range.start) as u128;
        Some((((pos + 1) * cells as u128 - 1) / span) as usize)
    }

    /// Bytes per cell of `cells` equal parts of `range` that
    /// are rescued, untried, still to be read and bad, in that order; a cell narrower than a
    /// byte (a map smaller than the strip) counts the byte at its place.
    fn strip_bytes_in(&self, range: &Range<u64>, cells: usize) -> Vec<[u64; 4]> {
        // Cells divide the range as given; past the map's end they hold nothing (the
        // inspector's last square at the disk's end).
        let range = range.clone();
        if cells == 0 || range.is_empty() {
            return Vec::new();
        }
        // Bytes per cell that are rescued, untried, still to be read and bad; each cell shows
        // what most of it is. Painting a cell by its worst byte drew a 98 % rescued stretch
        // all red, since small failed fragments lay in nearly every cell (2026-11-09).
        let edge = |cell: usize| Self::strip_edge_in(&range, cell, cells);
        let class = |status: Status| match status {
            Status::Rescued => 0,
            Status::Untried => 1,
            Status::NonTrimmed | Status::NonScraped => 2,
            _ => 3,
        };
        let mut bytes = vec![[0u64; 4]; cells];
        let mut cell = 0;
        // Blocks are in order: start at the first that reaches into the range.
        let first = self.blocks.partition_point(|b| b.end() <= range.start);
        for block in &self.blocks[first..] {
            if block.pos >= range.end {
                break;
            }
            // Cells are in order and so are blocks: walk both once.
            while cell < cells && edge(cell + 1) <= block.pos {
                cell += 1;
            }
            let mut c = cell;
            while c < cells && edge(c) < block.end() {
                let from = block.pos.max(edge(c));
                let to = block.end().min(edge(c + 1));
                bytes[c][class(block.status)] += to.saturating_sub(from);
                c += 1;
            }
        }
        let at = |pos: u64| {
            let i = self.blocks.partition_point(|b| b.end() <= pos);
            self.blocks.get(i).map_or(Status::Untried, |b| b.status)
        };
        bytes
            .iter()
            .enumerate()
            .map(|(c, counts)| {
                // A cell narrower than a byte (a map smaller than the strip) shows the byte at
                // its place.
                if counts.iter().sum::<u64>() == 0 {
                    let mut one = [0u64; 4];
                    one[class(at(edge(c).min(range.end - 1)))] = 1;
                    one
                } else {
                    *counts
                }
            })
            .collect()
    }

    /// The map in `cells` equal parts for the block-map strip, each shown as what most of its
    /// bytes are (`Cell`).
    pub fn strip(&self, cells: usize) -> Vec<Cell> {
        self.strip_in(&(0..self.len()), cells)
    }

    /// `strip` over `range` alone: the inspector's grid of one square of the strip, at the block level.
    pub fn strip_in(&self, range: &Range<u64>, cells: usize) -> Vec<Cell> {
        self.strip_bytes_in(range, cells)
            .iter()
            .map(|counts| {
                let failed = counts[2] + counts[3];
                let most = [counts[0], counts[1], failed];
                match (0..3).max_by_key(|&k| (most[k], k)).unwrap_or(0) {
                    0 if failed > 0 => Cell::Partly,
                    0 => Cell::Rescued,
                    1 => Cell::Untried,
                    _ if counts[2] >= counts[3] => Cell::ToRetry,
                    _ => Cell::Failed,
                }
            })
            .collect()
    }

    /// Each strip cell's share of rescued bytes, 0 to 1, so a cell fills as its blocks are
    /// rescued, so the map shows real progress during a run.
    pub fn strip_rescued(&self, cells: usize) -> Vec<f32> {
        self.strip_rescued_in(&(0..self.len()), cells)
    }

    /// `strip_rescued` over `range` alone.
    /// Bytes rescued in each of `cells` cells over `range` that `before`, an earlier map of
    /// the same drive, did not have rescued: what a run recovered there (manual step 27).
    pub fn strip_gained_in(&self, before: &Map, range: &Range<u64>, cells: usize) -> Vec<u64> {
        if before.len() != self.len() {
            return vec![0; cells];
        }
        let now = self.strip_bytes_in(range, cells);
        let then = before.strip_bytes_in(range, cells);
        now.iter()
            .zip(&then)
            .map(|(now, then)| now[0].saturating_sub(then[0]))
            .collect()
    }

    /// Where this map has rescued what `before`, an earlier map of the same drive, had not:
    /// each area from its first such byte to its last, areas `bridge` bytes apart or closer
    /// joined, with the bytes, largest first.
    pub fn gains(&self, before: &Map, bridge: u64) -> Vec<(Range<u64>, u64)> {
        if before.len() != self.len() {
            return Vec::new();
        }
        let mut areas: Vec<(Range<u64>, u64)> = Vec::new();
        for block in before.blocks.iter().filter(|b| b.status != Status::Rescued) {
            let (start, end) = (block.pos, block.end());
            let got = self.amounts_in(&(start..end))[0];
            if got == 0 {
                continue;
            }
            let rescued = |s: Status| s == Status::Rescued;
            let first = self.find_where(rescued, start).map_or(start, |b| b.pos);
            let last = self.find_back_where(rescued, end).map_or(end, |b| b.end());
            match areas.last_mut() {
                Some((area, bytes)) if first <= area.end.saturating_add(bridge) => {
                    area.end = last;
                    *bytes += got;
                }
                _ => areas.push((first..last, got)),
            }
        }
        areas.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.start.cmp(&b.0.start)));
        areas
    }

    /// What a run recovered since `before`, for the window: the total and the largest areas.
    pub fn gains_text(&self, before: &Map) -> Option<String> {
        const SHOWN: usize = 3;
        let areas = self.gains(before, GAINS_BRIDGE);
        let total: u64 = areas.iter().map(|(_, bytes)| bytes).sum();
        if total == 0 {
            return None;
        }
        let mut parts: Vec<String> = areas
            .iter()
            .take(SHOWN)
            .map(|(area, bytes)| {
                format!(
                    "{} at {} to {}",
                    bytes_text(*bytes),
                    bytes_text(area.start),
                    bytes_text(area.end)
                )
            })
            .collect();
        if areas.len() > SHOWN {
            let more = areas.len() - SHOWN;
            parts.push(format!(
                "{more} more {}",
                if more == 1 { "area" } else { "areas" }
            ));
        }
        Some(format!(
            "Recovered this run: {}, {}.",
            bytes_text(total),
            parts.join(", ")
        ))
    }

    pub fn strip_rescued_in(&self, range: &Range<u64>, cells: usize) -> Vec<f32> {
        self.strip_bytes_in(range, cells)
            .iter()
            .map(|counts| {
                let all: u64 = counts.iter().sum();
                if all == 0 {
                    0.0
                } else {
                    (counts[0] as f64 / all as f64) as f32
                }
            })
            .collect()
    }

    /// Whether any of the drive is still to be read that never failed a read on its own:
    /// untried, not trimmed or not scraped. While some is, Fill the gaps reads only that and
    /// leaves the bad sectors: the red and orange blocks only
    /// hang again once they have been swept, so the purple comes first.
    pub fn reads_before_bad(&self) -> bool {
        self.blocks.iter().any(|b| unfailed(b.status))
    }

    /// The longest run of what never failed (`reads_before_bad`), the first of equal ones:
    /// where Fill the gaps reads next, from its middle (`Map::split_at`).
    pub fn largest_unfailed(&self) -> Option<Range<u64>> {
        let mut best: Option<Range<u64>> = None;
        let mut run: Option<Range<u64>> = None;
        for b in &self.blocks {
            run = match run {
                _ if !unfailed(b.status) => None,
                Some(r) if r.end == b.pos => Some(r.start..b.end()),
                _ => Some(b.pos..b.end()),
            };
            if let Some(r) = &run {
                if best
                    .as_ref()
                    .is_none_or(|x| r.end - r.start > x.end - x.start)
                {
                    best = Some(r.clone());
                }
            }
        }
        best
    }

    /// The run of what never failed that holds `at`, or the next one after it.
    pub fn unfailed_run(&self, at: u64) -> Option<Range<u64>> {
        let first = self.find_where(unfailed, at)?;
        let i = self.blocks.partition_point(|b| b.end() <= first.pos);
        let mut start = self.blocks[i].pos;
        for b in self.blocks[..i].iter().rev() {
            if !unfailed(b.status) || b.end() != start {
                break;
            }
            start = b.pos;
        }
        let mut end = self.blocks[i].end();
        for b in &self.blocks[i + 1..] {
            if !unfailed(b.status) || b.pos != end {
                break;
            }
            end = b.end();
        }
        Some(start..end)
    }

    /// The middle of `run`, on a `sector` boundary: where a split read begins.
    pub fn split_at(run: &Range<u64>, sector: u64) -> u64 {
        let sector = sector.max(1);
        (run.start + (run.end - run.start) / 2 / sector * sector).min(run.end)
    }

    /// The bytes of `range` that are rescued, untried, still to be read (not trimmed or not
    /// scraped) and bad, in that order.
    pub fn amounts_in(&self, range: &Range<u64>) -> [u64; 4] {
        let range = range.start..range.end.min(self.len());
        let first = self.blocks.partition_point(|b| b.end() <= range.start);
        let mut amounts = [0u64; 4];
        for block in &self.blocks[first..] {
            if block.pos >= range.end {
                break;
            }
            let bytes = block.end().min(range.end) - block.pos.max(range.start);
            let class = match block.status {
                Status::Rescued => 0,
                Status::Untried => 1,
                Status::NonTrimmed | Status::NonScraped => 2,
                _ => 3,
            };
            amounts[class] += bytes;
        }
        amounts
    }

    /// The mapfile text, in GNU ddrescue's format.
    pub fn to_text(&self, heading: &[String]) -> String {
        let mut text = String::new();
        for line in heading {
            text.push_str(&format!("# {line}\n"));
        }
        text.push_str(&format!("# {}\n", self.phase.comment(self.pass)));
        text.push_str("# current_pos  current_status  current_pass\n");
        text.push_str(&format!(
            "0x{:08X}     {}               {}\n",
            self.current_pos,
            self.phase.symbol(),
            self.pass
        ));
        text.push_str("#      pos        size  status\n");
        for block in &self.blocks {
            text.push_str(&format!(
                "0x{:08X}  0x{:08X}  {}\n",
                block.pos,
                block.size,
                block.status.symbol()
            ));
        }
        text
    }

    /// Reads a mapfile. Blocks must be contiguous and start at 0; the old two-field status
    /// line (no pass) is accepted.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut status: Option<(u64, Phase, u32)> = None;
        let mut blocks: Vec<Block> = Vec::new();
        for (number, raw) in text.lines().enumerate() {
            let line = strip_comment(raw);
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                continue;
            }
            let bad = || {
                format!(
                    "line {} of the map is not understood: {}",
                    number + 1,
                    quoted(raw)
                )
            };
            if status.is_none() {
                if fields.len() < 2 || fields.len() > 3 {
                    return Err(bad());
                }
                let pos = parse_number(fields[0]).ok_or_else(bad)?;
                let mut chars = fields[1].chars();
                let phase = chars
                    .next()
                    .filter(|_| chars.next().is_none())
                    .and_then(Phase::from_symbol)
                    .ok_or_else(bad)?;
                let pass = match fields.get(2) {
                    Some(text) => text
                        .parse::<u32>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or_else(bad)?,
                    None => 1,
                };
                status = Some((pos, phase, pass));
                continue;
            }
            if fields.len() != 3 {
                return Err(bad());
            }
            let pos = parse_number(fields[0]).ok_or_else(bad)?;
            let size = parse_number(fields[1]).ok_or_else(bad)?;
            let mut chars = fields[2].chars();
            let block_status = chars
                .next()
                .filter(|_| chars.next().is_none())
                .and_then(Status::from_symbol)
                .ok_or_else(bad)?;
            let expected = blocks.last().map_or(0, Block::end);
            if pos != expected {
                return Err(format!(
                    "the map's blocks are not contiguous at line {} (expected 0x{expected:X})",
                    number + 1
                ));
            }
            // Every block's end is representable from here on, so `Block::end` cannot wrap.
            if pos.checked_add(size).is_none() {
                return Err(format!(
                    "the block at line {} of the map runs past the largest byte a drive can have: {}",
                    number + 1,
                    quoted(raw)
                ));
            }
            if size == 0 {
                continue;
            }
            match blocks.last_mut() {
                Some(last) if last.status == block_status => last.size += size,
                _ => blocks.push(Block {
                    pos,
                    size,
                    status: block_status,
                }),
            }
        }
        let (current_pos, phase, pass) = status.ok_or("the map has no status line")?;
        // A position past the blocks is not a place in them.
        let current_pos = current_pos.min(blocks.last().map_or(0, Block::end));
        Ok(Self {
            blocks,
            current_pos,
            phase,
            pass,
        })
    }

    /// Extends the map with untried space up to `len` (a ddrescue map may stop short).
    fn extend_to(&mut self, len: u64) {
        let have = self.len();
        if len > have {
            self.blocks.push(Block {
                pos: have,
                size: len - have,
                status: Status::Untried,
            });
            let n = self.blocks.len();
            if n > 1 && self.blocks[n - 2].status == Status::Untried {
                self.blocks[n - 2].size += len - have;
                self.blocks.pop();
            }
        }
    }
}

const SOURCE_MODEL: &str = "# Source model: ";
const SOURCE_SERIAL: &str = "# Source serial: ";
const SOURCE_SIZE: &str = "# Source size: ";
const SOURCE_SECTOR: &str = "# Source sector size: ";
const SOURCE_DRIVE_MODEL: &str = "# Source drive model: ";
const SOURCE_DRIVE_SERIAL: &str = "# Source drive serial: ";
const SOURCE_SCOPE: &str = "# Source scope: ";
const SOURCE_DISK_SIZE: &str = "# Source disk size: ";

/// A source's scope as its map line says it: "disk", or "volume at byte 1048576".
fn scope_line(scope: Scope) -> String {
    match scope {
        Scope::Disk => "disk".into(),
        Scope::Volume { offset } => format!("volume at byte {offset}"),
    }
}

fn parse_scope(text: &str) -> Option<Scope> {
    match text {
        "disk" => Some(Scope::Disk),
        other => Some(Scope::Volume {
            offset: other.strip_prefix("volume at byte ")?.trim().parse().ok()?,
        }),
    }
}

/// The comment lines that name a map's source drive; ddrescue reads them as comments. The
/// sector size, the part of the drive read and the drive's own model and serial number
/// follow where they are known.
pub(crate) fn identity_lines(id: &SourceId) -> Vec<String> {
    let mut lines = vec![
        (SOURCE_MODEL, id.model.clone()),
        (SOURCE_SERIAL, id.serial.clone()),
        (SOURCE_SIZE, format!("{} bytes", id.size)),
    ];
    if let Some(sector) = id.sector {
        lines.push((SOURCE_SECTOR, format!("{sector} bytes")));
    }
    if let Some(scope) = id.scope {
        lines.push((SOURCE_SCOPE, scope_line(scope)));
    }
    if let Some(size) = id.disk_size {
        lines.push((SOURCE_DISK_SIZE, format!("{size} bytes")));
    }
    if let Some(drive) = &id.drive {
        lines.push((SOURCE_DRIVE_MODEL, drive.model.clone()));
        lines.push((SOURCE_DRIVE_SERIAL, drive.serial.clone()));
    }
    lines
        .into_iter()
        .map(|(key, value)| format!("{}{value}", &key[2..]))
        .collect()
}

/// The source drive a mapfile names, when it names one (a map from ddrescue, or from an
/// older version of this tool, does not); the sector size and the drive's own identity
/// when the map has them.
pub fn map_identity(text: &str) -> Option<SourceId> {
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(|v| v.trim().to_string())
    };
    let bytes = |v: String| -> Option<u64> { v.strip_suffix(" bytes")?.trim().parse().ok() };
    let drive = match (value(SOURCE_DRIVE_MODEL), value(SOURCE_DRIVE_SERIAL)) {
        (Some(model), Some(serial)) if !serial.is_empty() => Some(DriveId { model, serial }),
        _ => None,
    };
    Some(SourceId {
        model: value(SOURCE_MODEL)?,
        serial: value(SOURCE_SERIAL)?,
        size: bytes(value(SOURCE_SIZE)?)?,
        drive,
        sector: value(SOURCE_SECTOR)
            .and_then(bytes)
            .and_then(|b| u32::try_from(b).ok()),
        scope: value(SOURCE_SCOPE).and_then(|v| parse_scope(&v)),
        disk_size: value(SOURCE_DISK_SIZE).and_then(bytes),
    })
}

/// The identity a run writes into its map: the drive's as it gave it, and when it gave no
/// own identity (an IDENTIFY the bridge did not answer), the drive's own model and serial
/// from the map's heading `old`, where the map names the same source by what Windows reports:
/// the same non-blank serial, model, size and part of the drive. The caller passes `old` only
/// when the technician confirmed the map is this drive's, which is what vouches for the drive
/// serial; without this the map would lose the drive's own serial for every later match.
pub fn kept_identity(now: Option<SourceId>, old: Option<SourceId>) -> Option<SourceId> {
    let mut now = now?;
    if now.drive.is_none() {
        if let Some(old) = old {
            let same_scope = match (old.scope, now.scope) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            };
            if !now.serial.trim().is_empty()
                && old.serial.trim() == now.serial.trim()
                && old.model.trim() == now.model.trim()
                && old.size == now.size
                && same_scope
            {
                now.drive = old.drive;
            }
        }
    }
    Some(now)
}

/// A scope for people: "the whole disk", "the volume at byte 1048576".
fn scope_text(scope: Scope) -> String {
    match scope {
        Scope::Disk => "the whole disk".into(),
        Scope::Volume { offset } => format!("the volume at byte {offset}"),
    }
}

/// How the drive a map names compares with the drive being read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    /// The same drive: resume.
    Same,
    /// It cannot be told; resuming needs the technician's yes. Says why.
    Unconfirmed(String),
    /// Another drive, or the same one reporting another size: refused. Says why.
    Other(String),
}

/// Compares the drive the map at `map_path` was made from with the drive being read. Where
/// both say which part of the drive they are (the whole disk, or a volume at its offset),
/// another part is another source. Wherever the map holds the drive's own serial number,
/// that decides, so the move between a USB adapter and a SATA port, which changes what
/// Windows reports, keeps the map: another own serial is another drive, a different sector
/// size or size is refused and said, and a drive that gives no own serial now needs the
/// technician's yes. Otherwise the model, serial number and size Windows reports decide,
/// and a blank serial number or a map or drive that names nothing needs the technician's
/// yes.
pub fn match_drive(
    map_path: &Path,
    made_from: Option<&SourceId>,
    this: Option<&SourceId>,
) -> Match {
    let map = map_path.display();
    let another = |made_from: &SourceId, this: &SourceId| {
        Match::Other(format!(
            "{map} is the map of another drive: it was made from {}, and the drive being read is {}. Choose another folder, or connect the drive it was made from.",
            made_from.text(),
            this.text()
        ))
    };
    // A map from before the part of the drive was kept cannot tell two volumes of one size on
    // one drive apart; a whole disk is matched as it always was.
    let part_unknown = |made_from: &SourceId| {
        Match::Unconfirmed(format!(
            "{map} was made from {} and does not say which part of the drive it was made from (older versions of this tool do not), so it cannot be told from a map of another volume of the same size on this drive.",
            made_from.text()
        ))
    };
    if let (Some(made_from), Some(this)) = (made_from, this) {
        if let (Some(then), Some(now)) = (made_from.scope, this.scope) {
            if then != now {
                return Match::Other(format!(
                    "{map} was made from {} of {}, and the source being read is {} of {}; a map is resumed only on the part of the drive it was made from. Choose another folder.",
                    scope_text(then),
                    made_from.text(),
                    scope_text(now),
                    this.text()
                ));
            }
        }
        // The drive's own serial, wherever the map holds one, decides whatever else the
        // heading carries: what Windows reports is often the USB adapter's, which another
        // drive behind the same adapter reports too. A known difference in shape is refused
        // before anything is left to the technician, since no yes makes such an image fit.
        let own = |id: &SourceId| {
            id.drive
                .as_ref()
                .map(|d| d.serial.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        if let Some(was) = own(made_from) {
            let serial = was.as_str();
            let changed = match (made_from.sector, this.sector) {
                (Some(then), Some(now)) if then != now => Some(format!(
                    "while it reported {then}-byte sectors, and it now reports {now}-byte sectors"
                )),
                _ if made_from.size != this.size => Some(format!(
                    "while it reported {} bytes, and it now reports {} bytes",
                    made_from.size, this.size
                )),
                _ => None,
            };
            let now = own(this);
            if now.as_ref().is_some_and(|now| *now != was) {
                return another(made_from, this);
            }
            if let Some(changed) = changed {
                return Match::Other(if now.is_some() {
                    format!("{map} was made from this drive (serial {serial}) {changed}; a USB adapter and a SATA port can differ in this, and an image is not resumed across the change. Connect the drive the way it was connected when the image was started, or choose another folder to start again.")
                } else {
                    format!("{map} was made from the drive with its own serial number {serial} {changed}; an image is not resumed across the change. Choose another folder, or connect the drive it was made from.")
                });
            }
            // The drive's own serial says which drive, not which part of it.
            if made_from.scope.is_none() && matches!(this.scope, Some(Scope::Volume { .. })) {
                return part_unknown(made_from);
            }
            return match (now, made_from.sector, this.sector) {
                (Some(_), Some(then), Some(now)) if then == now => Match::Same,
                (Some(_), _, _) => Match::Unconfirmed(format!(
                    "{map} was made from this drive (serial {serial}), and the sector size is not known on both sides, so the image cannot be shown to fit the drive as it is connected now."
                )),
                (None, _, _) => Match::Unconfirmed(format!(
                    "{map} was made from the drive with its own serial number {serial}, and the drive being read did not give its own serial number now (its adapter may not have passed the request yet), so it cannot be told from another drive behind the same adapter."
                )),
            };
        }
    }
    match (made_from, this) {
        // A blank serial cannot tell two drives of one model and size apart.
        (Some(made_from), Some(this))
            if (made_from.serial.trim().is_empty() || this.serial.trim().is_empty())
                && made_from.model.trim() == this.model.trim()
                && made_from.size == this.size =>
        {
            Match::Unconfirmed(format!(
                "{map} was made from {}, and the drive being read is {}. Without a serial number on both, two drives of the same model and size cannot be told apart.",
                made_from.text(),
                this.text()
            ))
        }
        (Some(made_from), Some(this))
            if (&made_from.model, &made_from.serial, made_from.size)
                != (&this.model, &this.serial, this.size) =>
        {
            another(made_from, this)
        }
        // A map from before the part of the drive was kept cannot tell two volumes of one
        // size on one drive apart; a whole disk is matched as it always was.
        (Some(made_from), Some(this))
            if made_from.scope.is_none() && matches!(this.scope, Some(Scope::Volume { .. })) =>
        {
            part_unknown(made_from)
        }
        (Some(_), Some(_)) => Match::Same,
        (Some(made_from), None) => Match::Unconfirmed(format!(
            "{map} was made from {}, and this drive did not say what it is, so it cannot be matched.",
            made_from.text()
        )),
        (None, _) => Match::Unconfirmed(format!(
            "{map} does not name the drive it was made from (GNU ddrescue and older versions of this tool do not), so it cannot be matched to this one."
        )),
    }
}

/// The most maps looked at for one moved drive, and the bytes read from each: the lines
/// that name the drive come first.
const MOVED_MAPS: usize = 256;
const MOVED_HEAD: u64 = 16 << 10;

/// What the heading of the map at `path` names, or why it could not be told: it could not
/// be read, is not text, or its heading runs past the first `MOVED_HEAD` bytes.
fn map_heading(path: &Path) -> Result<Option<SourceId>, String> {
    use std::io::Read;
    let name = path.display();
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MOVED_HEAD + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{name} could not be read ({e})"))?;
    let whole = bytes.len() as u64 <= MOVED_HEAD;
    if !whole {
        // Up to the last whole line, so no character is cut.
        let end = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        bytes.truncate(end);
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{name} is not a rescue map"))?;
    let heading: Vec<&str> = text.lines().take_while(|l| l.starts_with('#')).collect();
    if !whole && heading.len() == text.lines().count() {
        return Err(format!(
            "the heading of {name} runs past its first {} KiB",
            MOVED_HEAD >> 10
        ));
    }
    Ok(map_identity(&heading.join("\n")))
}

/// The stem of the image and map in `folder` that were made from the source `this`, by the
/// drive's own serial number and the same part of the drive, when the stem the drive's
/// description gives finds none. That stem names the disk number and the model Windows
/// reports, which change when the drive moves between a USB adapter and a SATA port. None
/// when no map names it or the source gave no identity of its own. A search that cannot
/// tell (too many maps, one that cannot be read or understood) and more than one match are
/// refused, so a second image is never started beside the one to resume.
fn moved_stem(folder: &Path, this: Option<&SourceId>) -> Result<Option<String>, String> {
    let (Some(serial), Some(scope)) = (
        this.and_then(|id| id.drive.as_ref())
            .map(|d| d.serial.trim().to_string()),
        this.and_then(|id| id.scope),
    ) else {
        return Ok(None);
    };
    let unsure = |why: String| {
        format!(
            "{} could not be searched for this drive's image: {why}. Move the image and map to resume into a folder of their own and choose it, or choose another folder.",
            folder.display()
        )
    };
    let entries =
        std::fs::read_dir(folder).map_err(|e| unsure(format!("it could not be listed ({e})")))?;
    let mut maps = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| unsure(format!("it could not be listed ({e})")))?;
        let path = entry.path();
        let (Some(stem), Some("map")) = (
            path.file_stem().and_then(|s| s.to_str()),
            path.extension().and_then(|e| e.to_str()),
        ) else {
            continue;
        };
        if folder.join(format!("{stem}.img")).is_file() {
            maps.push((stem.to_string(), path));
        }
    }
    if maps.len() > MOVED_MAPS {
        return Err(unsure(format!(
            "it holds {} images with maps, more than the {MOVED_MAPS} looked through",
            maps.len()
        )));
    }
    let mut found = Vec::new();
    for (stem, path) in maps {
        let named = map_heading(&path).map_err(unsure)?;
        let names_it = named.is_some_and(|id| {
            id.scope == Some(scope) && id.drive.is_some_and(|drive| drive.serial.trim() == serial)
        });
        if names_it {
            found.push(stem);
        }
    }
    found.sort();
    match found.len() {
        0 | 1 => Ok(found.pop()),
        _ => Err(format!(
            "{} holds more than one image of this drive ({}); move all but the one to resume elsewhere, or choose another folder.",
            folder.display(),
            found
                .iter()
                .map(|stem| format!("{stem}.map"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The most characters of a map line quoted in an error.
const QUOTED: usize = 80;

/// A line of a map, for an error: at most `QUOTED` characters of it, so a map of one
/// 64 MiB line gives a short error, not a copy of the map.
fn quoted(line: &str) -> String {
    match line.char_indices().nth(QUOTED) {
        Some((at, _)) => format!("{}... ({} characters)", &line[..at], line.chars().count()),
        None => line.to_string(),
    }
}

/// '#' at the start of a line or after whitespace starts a comment.
fn strip_comment(line: &str) -> &str {
    let mut previous_space = true;
    for (at, c) in line.char_indices() {
        if c == '#' && previous_space {
            return &line[..at];
        }
        previous_space = c.is_whitespace();
    }
    line
}

/// A C++ integer constant: 0x hex, a leading 0 for octal, else decimal.
fn parse_number(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if text.len() > 1 && text.starts_with('0') {
        u64::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse().ok()
    }
}

// ---- planning --------------------------------------------------------------------------

/// Where an image goes and what it needs, decided before anything is read or written.
#[derive(Debug)]
pub struct Plan {
    pub image: PathBuf,
    pub map_path: PathBuf,
    pub map: Map,
    pub resumed: bool,
    /// Bytes the destination must still take: everything not rescued yet.
    pub needed: u64,
    pub free: u64,
    /// Why a resumed map cannot be matched to this drive (it names no drive, or this drive
    /// did not say what it is). The run starts only once the user has confirmed it.
    pub unconfirmed: Option<String>,
    /// The technician confirmed, over a doubt shown, that the map is this drive's (`confirm`).
    pub confirmed: bool,
}

impl Plan {
    /// The user accepted the start dialog. Where it showed a doubt about the map, the user
    /// confirmed the map is this drive's (`confirmed`).
    pub fn confirm(&mut self) {
        if self.unconfirmed.take().is_some() {
            self.confirmed = true;
        }
    }
}

/// Free bytes and file system name of the volume holding `folder`.
pub fn space_of(folder: &Path) -> Result<(u64, String), String> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetVolumeInformationW, GetVolumePathNameW,
    };
    let target = super::disk::wide(&folder.to_string_lossy());
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: target is NUL-terminated and the out pointers are valid.
    if unsafe { GetDiskFreeSpaceExW(target.as_ptr(), &mut free, &mut total, &mut total_free) } == 0
    {
        return Err(format!(
            "the free space of {} could not be read",
            folder.display()
        ));
    }
    let mut root = vec![0u16; 1024];
    let mut name = vec![0u16; 64];
    // SAFETY: the buffers are writable for the lengths given.
    let named = unsafe {
        GetVolumePathNameW(target.as_ptr(), root.as_mut_ptr(), root.len() as u32) != 0
            && GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                name.as_mut_ptr(),
                name.len() as u32,
            ) != 0
    };
    let end = name.iter().position(|c| *c == 0).unwrap_or(0);
    let file_system = if named {
        String::from_utf16_lossy(&name[..end])
    } else {
        String::new()
    };
    Ok((free, file_system))
}

/// Refuses an image that will not fit: the space still needed must be free, and FAT cannot
/// hold a file of 4 GiB or more.
pub fn check_space(needed: u64, free: u64, file_system: &str, len: u64) -> Result<(), String> {
    if file_system.to_ascii_uppercase().starts_with("FAT") && len > u64::from(u32::MAX) {
        return Err(format!(
            "the destination is {file_system}, which cannot hold a file over 4 GiB; the image needs {}",
            bytes_text(len)
        ));
    }
    // A margin for the map and the file system's own records.
    let margin = 64 << 20;
    if free < needed + margin {
        return Err(format!(
            "the destination has {} free and the image needs up to {} more",
            bytes_text(free),
            bytes_text(needed)
        ));
    }
    Ok(())
}

/// Plans an image of `source` named `stem` in `folder`: refuses a destination on the
/// source's disk, then picks up an earlier run's image and map, then checks the space.
pub fn plan(source: &dyn BlockSource, folder: &Path, stem: &str) -> Result<Plan, String> {
    check_destination(folder, &source.protected())?;
    let (free, file_system) = space_of(folder)?;
    plan_with(source, folder, stem, free, &file_system)
}

/// `plan` after the destination rule, with the space given; for tests.
pub fn plan_with(
    source: &dyn BlockSource,
    folder: &Path,
    stem: &str,
    free: u64,
    file_system: &str,
) -> Result<Plan, String> {
    let this = source.identity();
    let mut image = folder.join(format!("{stem}.img"));
    let mut map_path = folder.join(format!("{stem}.map"));
    if !image.exists() && !map_path.exists() {
        if let Some(moved) = moved_stem(folder, this.as_ref())? {
            image = folder.join(format!("{moved}.img"));
            map_path = folder.join(format!("{moved}.map"));
        }
    }
    let len = source.len();
    let (map, resumed, unconfirmed) = match (image.exists(), map_path.exists()) {
        (true, true) => {
            let text = std::fs::read_to_string(&map_path)
                .map_err(|e| format!("{} could not be read: {e}", map_path.display()))?;
            let mut map = Map::parse(&text)?;
            let unconfirmed =
                match match_drive(&map_path, map_identity(&text).as_ref(), this.as_ref()) {
                    Match::Same => None,
                    Match::Unconfirmed(why) => Some(why),
                    Match::Other(why) => return Err(why),
                };
            if map.len() > len {
                return Err(format!(
                    "{} is for a source of {} and this one has {}; choose another folder",
                    map_path.display(),
                    bytes_text(map.len()),
                    bytes_text(len)
                ));
            }
            check_image_len(&image, &map, len)?;
            map.extend_to(len);
            (map, true, unconfirmed)
        }
        (true, false) => {
            return Err(format!(
                "{} is already there without its map; choose another folder",
                image.display()
            ))
        }
        (false, true) => {
            return Err(format!(
                "{} is already there without its image; choose another folder",
                map_path.display()
            ))
        }
        (false, false) => (Map::new(len), false, None),
    };
    let needed = len - map.count(Status::Rescued);
    check_space(needed, free, file_system, len)?;
    Ok(Plan {
        image,
        map_path,
        map,
        resumed,
        needed,
        free,
        unconfirmed,
        confirmed: false,
    })
}

/// Refuses to resume into an image that cannot hold what its map says was rescued: one
/// shorter than the last rescued byte, or one not the drive's size, which every image made
/// here is from its first save on.
fn check_image_len(image: &Path, map: &Map, len: u64) -> Result<(), String> {
    let have = std::fs::metadata(image)
        .map_err(|e| format!("{} could not be read: {e}", image.display()))?
        .len();
    let rescued_to = map
        .blocks
        .iter()
        .filter(|b| b.status == Status::Rescued)
        .map(Block::end)
        .max()
        .unwrap_or(0);
    if have < rescued_to {
        return Err(format!(
            "{} is {} long, but its map says data was rescued up to {}: the image was cut short or replaced, so resuming would keep holes marked as rescued. Choose another folder to start again.",
            image.display(),
            bytes_text(have),
            bytes_text(rescued_to)
        ));
    }
    // An image left attached by a crash still carries its footer, removed on resume.
    let have = match std::fs::File::open(image).and_then(|f| super::vdisk::data_len(&f)) {
        Ok(data) if data == len => data,
        _ => have,
    };
    if have != len {
        return Err(format!(
            "{} is {} long and the drive is {}; an image made here is always the drive's size, so this one is another drive's or was changed. Choose another folder to start again.",
            image.display(),
            bytes_text(have),
            bytes_text(len)
        ));
    }
    Ok(())
}

/// A file name for a source's image and map from its description, such as
/// "Disk 4 Kingston DataTraveler 3.0 28.9 GB": the same drive gives the same name, so a
/// later run in the same folder resumes.
pub fn stem_for(describe: &str) -> String {
    let cleaned: String = describe
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | ',' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    let stem = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let stem: String = stem.chars().take(100).collect();
    let stem = stem.trim_end_matches(['.', ' ']).to_string();
    if stem.is_empty() {
        "Rescue image".into()
    } else {
        stem
    }
}

// ---- the run ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Settings {
    /// Bytes per read in the copying passes.
    pub cluster: u64,
    /// The first skip after an error; doubled for each further error, up to `max_skip`.
    pub skip: u64,
    pub max_skip: u64,
    /// Retry passes over the bad sectors after scraping, 0 to 3, chosen before the run
    /// starts: the only reads of a sector already tried on its own and failed. Retry 1 is
    /// the reverse pass (each bad area read once more from its far end); retries 2 and 3
    /// read each bad sector once more forwards. 0 reads no failed sector again.
    pub retries: u32,
    /// How often the map is saved while a pass runs.
    pub save_every: Duration,
    /// How often the drive's health is read while a pass runs, besides between passes.
    pub health_every: Duration,
    /// Read the photos' and videos' areas, and the file system records that place them,
    /// before the first pass.
    pub photos_first: PhotosFirst,
    /// How far copying sets aside ahead of the place where the drive stopped answering
    /// (`DROP_SKIP`).
    pub drop_skip: u64,
}

impl Settings {
    /// ddrescue's defaults: 64 KiB reads; the skip starts at the larger of 64 KiB and
    /// 1/32768 of the source and grows to 1 % of it.
    pub fn for_len(len: u64) -> Self {
        let skip = (len / 32_768).max(64 << 10);
        Self {
            cluster: 64 << 10,
            skip,
            max_skip: (len / 100).max(skip),
            retries: 0,
            save_every: Duration::from_secs(30),
            health_every: Duration::from_secs(300),
            // ddrescue's own order; the window turns photos first on.
            photos_first: PhotosFirst::off(),
            drop_skip: DROP_SKIP,
        }
    }
}

/// How far copying sets aside ahead of the place where the drive stopped answering, where
/// nothing is mapped yet. A drive without a read limit of its own can hang inside a bad area
/// until USB resets it, and resuming at the same place walks straight back in. On
/// 2026-11-09 one area ran from 137.4 GB to past 140.0 GB. What is set aside is left untried
/// for copying's last reads, which come at it from the other side, so nothing is given up.
pub const DROP_SKIP: u64 = 1 << 30;
/// What copying sets aside ahead is at most 1/20 (5 %) of the drive.
pub const DROP_SKIP_SHARE: u64 = 20;
/// Unfinished blocks closer together than this are one damaged area (`Map::area`): a zone,
/// or what a retry pass or Fill the gaps skips after a drop, is the area around the drop,
/// never a doubled guess. On a failing drive the areas it hung in were solid runs of 43 MB
/// to 1 GB; 16 MiB joins the three around 264.8 to 266.9 GB, under 16 MB apart, and keeps
/// apart the five from 96.5 to 99.7 GB, 0.1 to 0.6 GB apart, which the doubled skip (to
/// 8.6 GB) had put in one zone with one budget.
pub const AREA_BRIDGE: u64 = 16 << 20;

/// The statuses of bytes read and failed: what a damaged area is made of.
/// Still to be read, and never failed a read of its own: untried, not trimmed, not scraped.
fn unfailed(status: Status) -> bool {
    matches!(
        status,
        Status::Untried | Status::NonTrimmed | Status::NonScraped
    )
}

fn failed(status: Status) -> bool {
    matches!(
        status,
        Status::NonTrimmed | Status::NonScraped | Status::Bad
    )
}

/// What one map's runs remember across a Resume within this app session: the hang zones, so
/// a resumed run reads them last and away from their hangs, with the hangs each has spent in
/// the phase. A Resume after a confirmation starts a new run, and on 2026-11-09 one dropped
/// again 31 s later at the same place.
#[derive(Clone, Debug, Default)]
struct Remembered {
    zones: Zones,
    /// What the map's blocks were when this run last saved it (`body_print`): what is
    /// remembered holds only for a map on disk exactly as this run left it, so another map
    /// put at the same path, or one changed by another program, starts afresh.
    saved: Option<u64>,
}

/// The technician points Fill the gaps at bytes `start` to `end` from the inspector: read this
/// block or continue the scan from there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Directed {
    /// Reads every sector of the block not rescued yet, once, forwards; then the pass goes
    /// on from where it was, or, with no pass running, the step ends.
    Block { start: u64, end: u64 },
    /// The pass goes on from the block: forwards from its start, backwards from its end.
    From { start: u64, end: u64 },
}

impl Directed {
    pub fn range(&self) -> Range<u64> {
        match self {
            Directed::Block { start, end } | Directed::From { start, end } => *start..*end,
        }
    }

    /// As the event log and the window say it.
    pub fn how(&self) -> &'static str {
        match self {
            Directed::Block { .. } => "read this block",
            Directed::From { .. } => "continue scan from here",
        }
    }
}

/// Areas of recovered bytes closer than this are told as one (`Map::gains_text`).
pub const GAINS_BRIDGE: u64 = 1 << 30;

/// The newest map copy kept beside `map_path` before Fill the gaps (`Rescue::keep_map_copy`,
/// or one kept by hand as `<map name>.before-fill`), read; None when there is none that
/// reads as a map of the same size as `map`.
pub fn latest_map_copy(map_path: &Path, map: &Map) -> Option<Map> {
    let folder = map_path.parent()?;
    let name = map_path.file_name()?.to_str()?;
    let prefix = format!("{name}.before-fill");
    let newest = std::fs::read_dir(folder)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max()?;
    let copy = Map::parse(&std::fs::read_to_string(newest.1).ok()?).ok()?;
    (copy.len() == map.len()).then_some(copy)
}

/// Where Fill the gaps was, kept beside the image with each map save it makes, so a restart
/// carries on from there rather than at pass 1 (manual step 28: a restart on a new build
/// went back to pass 1 and spent about an hour on old bad sectors). It holds whatever changed
/// the map since (a block read, an undo, another build): a pass started part way is never
/// harm, the next pass reads the rest, and the Fill the gaps dialog says where it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillPlace {
    pub pass: u32,
    pub backwards: bool,
    /// Where the pass goes on: forwards the first byte not passed yet, backwards the end of
    /// what is left to pass; None from the pass's start.
    pub at: Option<u64>,
}

/// The file beside the image that keeps Fill the gaps' place.
pub fn fill_place_path(image: &Path) -> PathBuf {
    image.with_extension("fill.json")
}

/// The place kept beside `image`, read through its folder `folder`, when it fits `map`; None
/// when there is none, or it does not (a pass's way not its own, a place past the map's end).
pub fn fill_place_for(
    guard: &Guard,
    folder: &Folder,
    image: &Path,
    map: &Map,
) -> Option<FillPlace> {
    let path = fill_place_path(image);
    let place: FillPlace = super::place::read(guard, folder, path.file_name()?)?;
    let fits = place.pass >= 1
        && place.backwards == place.pass.is_multiple_of(2)
        && place.at.is_none_or(|at| at <= map.len());
    fits.then_some(place)
}

/// The map a copy kept by `Rescue::keep_map_copy` was made of: its name without the last
/// `.<what>-<date and time>`.
pub fn map_of_copy(copy: &Path) -> Option<PathBuf> {
    let name = copy.file_name()?.to_str()?;
    let (map, _) = name.rsplit_once('.')?;
    Some(copy.with_file_name(map))
}

/// Puts the map copy `copy` (`Rescue::keep_map_copy`) back over the map at `map_path`, the
/// map there now kept first as `<map name>.before-undo-<date and time>` so the undo can be
/// undone too; the kept map's path, or why not. Only a copy of a map of the same drive size
/// is put back. The image is not touched: what was read since stays in it, no longer marked,
/// and a later pass reads it again. Not while a run is writing the map.
pub fn put_back_map(copy: &Path, map_path: &Path) -> Result<PathBuf, String> {
    if map_of_copy(copy).as_deref() != Some(map_path) {
        return Err(format!(
            "{} is not a copy of {}; it is not put back",
            copy.display(),
            map_path.display()
        ));
    }
    let read = |path: &Path| {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
        let map = Map::parse(&text).map_err(|e| format!("{} is not a map: {e}", path.display()))?;
        Ok::<_, String>((text, map))
    };
    let (text, old) = read(copy)?;
    let (now_text, now) = read(map_path)?;
    if old.len() != now.len() {
        return Err(format!(
            "{} is a map of {} and the map is of {}; it is not put back",
            copy.display(),
            bytes_text(old.len()),
            bytes_text(now.len())
        ));
    }
    let s = crate::clock::local(SystemTime::now());
    let mut name = map_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".before-undo-{:04}{:02}{:02}-{:02}{:02}{:02}",
        s.year, s.month, s.day, s.hour, s.minute, s.second
    ));
    let kept = map_path.with_file_name(name);
    let write_new = |path: &Path, text: &str| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    };
    write_new(&kept, &now_text)
        .map_err(|e| format!("the map could not be kept as {}: {e}", kept.display()))?;
    let mut temp = map_path.as_os_str().to_os_string();
    temp.push(".new");
    let temp = PathBuf::from(temp);
    let _ = std::fs::remove_file(&temp);
    write_new(&temp, &text)
        .and_then(|()| std::fs::rename(&temp, map_path))
        .map_err(|e| format!("{} could not be put back: {e}", copy.display()))?;
    Ok(kept)
}

/// A print of a map's blocks and position, its text without the comment lines (which carry
/// times), the same for the text a run saved and for the map read back from it.
fn body_print(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        line.trim_end().hash(&mut hasher);
    }
    hasher.finish()
}

/// The hang zones a rescue's event log records, for `map`: each drive-gone pause's read the
/// drive hung in (`hang_from`..`hang_to` where the pause gives it; else a sector at the drop
/// event's position before it), in the damaged area the map shows around it, and in copying
/// also the span the pause set aside, which is still untried. An unreadable log or line
/// gives none.
fn zones_from_log(path: &Path, map: &Map, sector: u64) -> Zones {
    let len = map.len();
    let mut zones = Zones::default();
    let Ok(text) = std::fs::read_to_string(path) else {
        return zones;
    };
    let mut gone_at: Option<u64> = None;
    // Whether a drop now makes a zone, for pauses logged before they said so: a rescue's
    // copying, trimming or scraping, never a retry pass or Fill the gaps.
    let mut zoning = true;
    let mut filling = false;
    for line in text.lines() {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match event["event"].as_str() {
            Some("started") => {
                filling = event["run"] == "fill the gaps";
                zoning = !filling;
            }
            Some("phase") => {
                zoning = !filling
                    && matches!(
                        event["phase"].as_str(),
                        Some("copying" | "trimming" | "scraping")
                    );
            }
            Some("drive_gone") => gone_at = event["position"].as_u64(),
            Some("paused")
                if event["kind"] == "drive-gone"
                    && event["values"]["zoned"].as_bool().unwrap_or(zoning) =>
            {
                let values = &event["values"];
                let (Some(from), Some(to)) = (
                    values["skipped_from"].as_u64(),
                    values["skipped_to"].as_u64(),
                ) else {
                    continue;
                };
                let (from, to) = (from.min(len), to.min(len));
                let hang = match (values["hang_from"].as_u64(), values["hang_to"].as_u64()) {
                    (Some(h), Some(e)) => (h, e),
                    _ => match gone_at.take() {
                        // A backward pass's position is its read's end.
                        Some(at) if at >= to => (to.saturating_sub(sector), to),
                        Some(at) => (at, at + sector),
                        None => (from, (from + sector).min(to)),
                    },
                };
                let (lo, hi) = map.area(hang.0, hang.1, AREA_BRIDGE, failed);
                let (lo, hi) = (lo.min(hang.0), hi.max(hang.1).min(len));
                if map.phase == Phase::Copying {
                    zones.seed(lo.min(from), hi.max(to), hang);
                } else {
                    zones.seed(lo, hi, hang);
                }
            }
            _ => {}
        }
    }
    zones
}

fn remembered() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, Remembered>> {
    static MEMORY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, Remembered>>,
    > = std::sync::OnceLock::new();
    MEMORY.get_or_init(Default::default)
}

/// How many failed reads in a row, with no read coming back between, before the drive is
/// asked whether it still answers. Failures the drive gives at once ask on their own (a
/// physical disk asks after every device error and time-out); this catches the rest. 64 bounds
/// what a run records before asking to 4 MiB in the copying passes and 32 KiB sector by
/// sector, and costs one size query per 64 failed sectors when scraping a real bad area.
pub const RUNAWAY_READS: u64 = 64;
/// The span the failed reads in a row may cover before the drive is asked: 1 GiB, far wider
/// than a plausible bad area. Pass 1's skip on a 2 TB drive starts at 61 MB and doubles, so
/// a run that fails everywhere crosses it within six reads.
pub const RUNAWAY_SPAN: u64 = 1 << 30;

/// The failed reads in a row since the last read that came back.
#[derive(Clone, Debug, Default)]
struct Streak {
    reads: u64,
    low: u64,
    high: u64,
}

impl Streak {
    /// Counts one failed read; true when the drive is to be asked whether it still answers
    /// (and the count starts over).
    fn add(&mut self, pos: u64, len: u64) -> bool {
        if self.reads == 0 {
            (self.low, self.high) = (pos, pos + len);
        } else {
            (self.low, self.high) = (self.low.min(pos), self.high.max(pos + len));
        }
        self.reads += 1;
        let ask = self.reads >= RUNAWAY_READS || self.high - self.low >= RUNAWAY_SPAN;
        if ask {
            *self = Self::default();
        }
        ask
    }
}

/// How a run ended. The map is saved in every case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Finished,
    Stopped,
    /// The drive's health changed for the worse; says why.
    Paused(String),
    /// The drive stopped answering.
    Gone(String),
    /// The drive stopped answering, and a drive came back that cannot be told from it; says
    /// why. Resume asks the technician to confirm it.
    Unconfirmed(String),
    /// The image or map could not be written.
    Failed(String),
}

/// How a run ended, and whether it saved a map: what every end text is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended {
    pub outcome: Outcome,
    pub map_saved: bool,
    /// Bytes not rescued in the places the drive hung, which the run left as they were.
    pub zones_left: u64,
}

/// What a run's end says. Only a run that saved its map says so and offers Resume; one
/// that ended before says nothing was read or written.
pub fn end_text(ended: &Ended, map: Option<&Map>) -> String {
    let figures = match map {
        Some(m) if ended.map_saved => format!(
            " Rescued {} of {}; {} unreadable.",
            bytes_text(m.count(Status::Rescued)),
            bytes_text(m.len()),
            bytes_text(m.failed())
        ),
        _ => String::new(),
    };
    let saved = ended.map_saved;
    let nothing = "Nothing was read or written";
    match &ended.outcome {
        Outcome::Finished if ended.zones_left > 0 => format!(
            "Finished.{figures} {} where the drive hung was left as it was, after two hangs there in a phase; Fill the gaps reads it.",
            bytes_text(ended.zones_left)
        ),
        Outcome::Finished => format!("Finished.{figures}"),
        Outcome::Stopped if saved => {
            format!("Stopped; the map is saved, so Resume carries on from here.{figures}")
        }
        Outcome::Stopped => format!("Stopped before the rescue began. {nothing}."),
        Outcome::Paused(why) if saved => {
            format!("{why} The map is saved; Resume carries on when you are ready.{figures}")
        }
        Outcome::Paused(why) => format!("{why} {nothing}; start again when you are ready."),
        Outcome::Gone(why) if saved => format!(
            "{why} The map is saved; unplug the drive and connect it again, then resume.{figures}"
        ),
        Outcome::Gone(why) => {
            format!("{why} {nothing}; unplug the drive and connect it again, then try again.")
        }
        Outcome::Unconfirmed(why) => format!(
            "{why} The map is saved; Resume asks you to confirm it is this drive before it is read.{figures}"
        ),
        Outcome::Failed(why) => format!("The image could not be written: {why}"),
    }
}

/// What the window shows while a run goes on; refreshed a few times a second.
#[derive(Default)]
pub struct Progress {
    pub rescued: AtomicU64,
    pub failed: AtomicU64,
    pub untried: AtomicU64,
    pub pos: AtomicU64,
    /// The phase and pass, and a copy of the map for the strip.
    pub state: Mutex<Option<(Phase, u32, Map)>>,
    /// The latest health reading and its change since the start, from the health log.
    pub health: Mutex<String>,
    /// That reading's figures, for the condition strip (`condition`).
    pub drive: Mutex<Option<super::health_log::Reading>>,
    /// Photos first, once it has begun.
    pub photos: Mutex<Option<PhotosStatus>>,
    /// The drive's read limit, as last set or put back (quick give-up).
    pub read_limit: Mutex<Option<LimitEvent>>,
    /// While the run waits for the drive to come back after it stopped answering: what to
    /// do. None while it reads.
    pub waiting: Mutex<Option<String>>,
    /// While the run waits for the drive to cool: its temperature, when it was read, and the
    /// thresholds. None while it reads.
    pub cooling: Mutex<Option<String>>,
    /// The last time the run carried on after waiting, said.
    pub resumed: Mutex<Option<String>>,
    /// The source's description once the run carries on with the drive under a new number.
    pub source: Mutex<Option<String>>,
    /// The run's event log beside the image (`events`): the window's pause and end messages
    /// are the reasons of the events written there.
    pub events: EventLog,
    /// The end message, as the run's last event gave it.
    pub ended: Mutex<Option<String>>,
    pub non_trimmed: AtomicU64,
    pub non_scraped: AtomicU64,
    pub bad: AtomicU64,
    /// Where the run reads now, for the strip's ring: the map's position in a rescue, the
    /// sector being read in Fill the gaps (whose map stays finished). None when it is not.
    pub reading: Mutex<Option<u64>>,
    /// A directed read the technician asked of a running Fill the gaps, taken at its next
    /// read (`Directed`).
    pub directed: Mutex<Option<Directed>>,
}

impl Progress {
    /// Sets one of the texts above.
    pub fn say(slot: &Mutex<Option<String>>, text: Option<String>) {
        if let Ok(mut shown) = slot.lock() {
            *shown = text;
        }
    }

    /// Reads one of the texts above.
    pub fn read(slot: &Mutex<Option<String>>) -> Option<String> {
        slot.lock().ok().and_then(|shown| shown.clone())
    }

    /// The map's figures as last published, for an event.
    pub fn figures(&self) -> Figures {
        Figures {
            position: self.pos.load(Ordering::Relaxed),
            rescued: self.rescued.load(Ordering::Relaxed),
            non_trimmed: self.non_trimmed.load(Ordering::Relaxed),
            non_scraped: self.non_scraped.load(Ordering::Relaxed),
            bad: self.bad.load(Ordering::Relaxed),
        }
    }
}

/// Where photos first is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhotosState {
    /// Reading the file systems' records.
    Records,
    /// Copying the photos' and videos' areas.
    Copying,
    /// Their areas are read; the rescue goes on with the rest.
    Done,
    /// The records could not be used; the rescue goes on in the usual order. Says why.
    FellBack(String),
}

/// Photos first's figures, for the window and an agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhotosStatus {
    pub state: PhotosState,
    /// Photo and video files listed, deleted ones included, and of them deleted.
    pub files: u64,
    pub deleted: u64,
    /// Their size, and the source bytes of their areas rescued and failed so far.
    pub bytes: u64,
    pub area: u64,
    pub rescued: u64,
    pub failed: u64,
    /// What could not be read in the records.
    pub notes: Vec<String>,
}

impl PhotosStatus {
    /// "Photos first: 1,204 files, 3.2 GB; 1.1 GB of 3.2 GB read, 4.1 kB unreadable."
    pub fn text(&self) -> String {
        match &self.state {
            PhotosState::Records => {
                "Photos first: reading the file system's records to find the photos and videos…"
                    .into()
            }
            PhotosState::FellBack(why) => {
                format!("Photos first: not used, {why}; the drive is read in the usual order.")
            }
            state => {
                let deleted = if self.deleted > 0 {
                    format!(" ({} deleted)", self.deleted)
                } else {
                    String::new()
                };
                let doing = if *state == PhotosState::Done {
                    "done"
                } else {
                    "reading"
                };
                format!(
                    "Photos first: {} files{deleted}, {}; {doing}: {} of {} read, {} unreadable.{}",
                    self.files,
                    bytes_text(self.bytes),
                    bytes_text(self.rescued),
                    bytes_text(self.area),
                    bytes_text(self.failed),
                    self.notes
                        .iter()
                        .take(2)
                        .map(|n| format!(" {n}."))
                        .collect::<String>()
                )
            }
        }
    }
}

impl Progress {
    fn publish(&self, map: &Map) {
        self.rescued
            .store(map.count(Status::Rescued), Ordering::Relaxed);
        self.failed.store(map.failed(), Ordering::Relaxed);
        self.untried
            .store(map.count(Status::Untried), Ordering::Relaxed);
        self.pos.store(map.current_pos, Ordering::Relaxed);
        self.non_trimmed
            .store(map.count(Status::NonTrimmed), Ordering::Relaxed);
        self.non_scraped
            .store(map.count(Status::NonScraped), Ordering::Relaxed);
        self.bad.store(map.count(Status::Bad), Ordering::Relaxed);
        if let Ok(mut state) = self.state.lock() {
            *state = Some((map.phase, map.pass, map.clone()));
        }
    }
}

/// What a health reading says about going on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Watch {
    Fine,
    /// The drive's health changed for the worse; says why.
    Pause(String),
    /// The drive did not answer; says so.
    Gone(String),
    /// Stop was asked for while the reading waited.
    Stop,
    /// The drive is at or above the heat pause: the run saves its map and asks again, and
    /// the watch waits for the next reading before it answers.
    Cooling,
}

fn heed(watch: Watch) -> Result<(), Halt> {
    match watch {
        Watch::Fine | Watch::Cooling => Ok(()),
        Watch::Pause(why) => Err(Halt::Pause(why)),
        Watch::Gone(why) => Err(Halt::Gone(why)),
        Watch::Stop => Err(Halt::Stop),
    }
}

/// Why a pass stopped early.
enum Halt {
    Stop,
    Pause(String),
    Gone(String),
    Write(String),
}

impl Halt {
    fn outcome(self) -> Outcome {
        match self {
            Halt::Stop => Outcome::Stopped,
            Halt::Pause(why) => Outcome::Paused(why),
            Halt::Gone(why) => Outcome::Gone(why),
            Halt::Write(why) => Outcome::Failed(why),
        }
    }
}

/// What one sweep read: bytes asked of the drive, and of them read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepCount {
    pub read: u64,
    pub recovered: u64,
}

/// Which areas a sweep reads, one sector at a time, each once.
#[derive(Clone, Copy)]
struct Sweep {
    backwards: bool,
    /// Every area not rescued (Fill the gaps), or only the bad sectors (the retries).
    any_unread: bool,
    /// Keeps the map's position, so a stopped retry resumes where it was; Fill the gaps
    /// leaves the map's position and phase as they were.
    track_pos: bool,
    /// Reads only what never failed (`Map::reads_before_bad`), split from the middle of its
    /// longest run (`Map::largest_unfailed`); a block pointed at is read whole.
    skip_bad: bool,
}

/// A source read through a rescue while photos first reads the file systems' records:
/// every read goes into the image and the map as it is made, an area already rescued is
/// read back from the image instead of the drive, and a read past the time limit, a Stop,
/// the drive going or a failed write ends the records' reading.
struct Tap<'a> {
    rescue: &'a mut Rescue,
    source: &'a mut dyn BlockSource,
    settings: &'a Settings,
    stop: &'a AtomicBool,
    progress: &'a Progress,
    deadline: Instant,
    halt: &'a mut Option<Halt>,
    late: &'a mut bool,
}

impl BlockSource for Tap<'_> {
    fn len(&self) -> u64 {
        self.source.len()
    }

    fn sector_size(&self) -> u32 {
        self.source.sector_size()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        // Gone ends the reader at once; the reason is kept here.
        const ENDED: ReadError = ReadError::Gone(0);
        if self.halt.is_some() || *self.late {
            return Err(ENDED);
        }
        if Instant::now() >= self.deadline {
            *self.late = true;
            return Err(ENDED);
        }
        if let Err(halt) = self
            .rescue
            .tick_quiet(self.settings, self.stop, self.progress)
        {
            *self.halt = Some(halt);
            return Err(ENDED);
        }
        let len = buf.len() as u64;
        if self.rescue.map.all(offset, len, Status::Rescued)
            && self.rescue.image.read_back(buf, offset)
        {
            return Ok(());
        }
        // A sector that already failed on its own is read again only by a retry pass, and a
        // hang zone only by the phases' last reads; neither is marked for this.
        if self
            .rescue
            .map
            .find(Status::Bad, offset)
            .is_some_and(|b| b.pos < offset + len)
            || self
                .rescue
                .zones
                .first_overlap(offset, offset + len)
                .is_some()
        {
            return Err(ReadError::Bad(0));
        }
        match self.rescue.read_into(self.source, offset, buf) {
            Ok(true) => Ok(()),
            Ok(false) => {
                // A failed copying read, as ddrescue marks one: trimmed and scraped later,
                // or bad when it was one sector.
                let sector = Rescue::sector(self.source);
                let mark = Status::after_failed_read(len, sector);
                self.rescue
                    .map
                    .set_where(offset, len, Status::Untried, mark);
                Err(ReadError::Bad(0))
            }
            Err(halt) => {
                *self.halt = Some(halt);
                Err(ENDED)
            }
        }
    }

    fn describe(&self) -> String {
        self.source.describe()
    }
}

/// How far the map on disk may fall behind the image while another program refuses its
/// timed saves before the run ends.
pub const MAP_LAG_LIMIT: Duration = Duration::from_secs(600);

/// An image being written: the open file, the map, and its saving.
pub struct Rescue {
    image: Box<dyn Sink>,
    /// Checks every file the run writes, the map included.
    guard: Guard,
    /// The image's folder, held open: the map is saved through it, never by path.
    folder: Folder,
    pub map: Map,
    map_path: PathBuf,
    heading: Vec<String>,
    last_save: Instant,
    /// Since when timed saves of the map have been refused by another program holding it.
    refused_since: Option<Instant>,
    /// `MAP_LAG_LIMIT`, shorter in tests.
    map_lag_limit: Duration,
    /// A map was saved in this run; every end text is built from this.
    saved: bool,
    /// The print of the map this run last saved (`body_print`), for `Remembered`.
    saved_print: Option<u64>,
    last_health: Instant,
    last_publish: Instant,
    buffer: Vec<u8>,
    /// Photos first's figures and the areas they count, once listed.
    photos: Option<(PhotosStatus, Vec<(u64, u64)>)>,
    /// The read in flight when the drive stopped answering, which was not recorded.
    dropped: Option<(u64, u64)>,
    /// The drop skip of retry passes and Fill the gaps, which keep their own drop handling.
    /// Where the drive hung in this run, and the spans set aside around those places.
    pub(crate) zones: Zones,
    /// The failed reads in a row, for the runaway guard.
    streak: Streak,
    /// Reads that came back in this run.
    reads_ok: u64,
    /// The source being read, with the drive's own identity kept from the map when the drive
    /// did not give it at the start.
    source_id: Option<SourceId>,
    /// Fill the gaps' pass goes on from here after a drop skip.
    fill_from: Option<u64>,
    /// While a Fill the gaps pass runs: whether it reads backwards.
    filling: Option<bool>,
    /// The sector Fill the gaps reads, for the strip; the map's position stays the run's.
    fill_at: Option<u64>,
    /// Where Fill the gaps' pass goes on from, as far as the map holds its reads.
    fill_edge: Option<u64>,
    /// Where Fill the gaps keeps its place (`FillPlace`), the pass it is on and its way.
    fill_keep: Option<(PathBuf, u32, bool)>,
    /// Fill the gaps reads only this block, once (`Directed::Block` with no pass running).
    fill_only: Option<Range<u64>>,
    /// Photos first is reading; and whether a drop in its areas ended it for this run.
    in_photos: bool,
    /// Whether the read in `dropped` was photos first's: it goes with the drop, since the
    /// pause takes it after photos first has returned.
    dropped_photos: bool,
    photos_ended: bool,
    /// The run's event log; closed unless the caller gives it the progress's.
    pub(crate) events: EventLog,
    /// The Windows error of the read that showed the drive had stopped answering.
    pub(crate) gone_code: Option<u32>,
    /// The phase and pass last written as an event, so a pass carried on after a pause is
    /// not written again.
    phase_said: Option<(Phase, u32)>,
    /// When the last progress event was written, and the rescued bytes then.
    rate_since: Instant,
    rate_rescued: u64,
}

/// How often a progress event is written while the run reads.
pub const PROGRESS_EVERY: Duration = Duration::from_secs(30);

/// Marks a file sparse, so unread areas take no space. Fails quietly where the file system
/// has no sparse files (exFAT, FAT).
fn make_sparse(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut returned = 0u32;
    // SAFETY: a valid file handle; FSCTL_SET_SPARSE takes no buffers.
    unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
}

fn stamp(time: SystemTime) -> String {
    let s = crate::clock::local(time);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        s.year, s.month, s.day, s.hour, s.minute, s.second
    )
}

impl Rescue {
    /// Opens or creates the image and writes the map once before any read.
    pub fn open(plan: Plan, source: &dyn BlockSource) -> Result<Self, String> {
        if let Some(why) = &plan.unconfirmed {
            return Err(format!(
                "{why} It is resumed only once you confirm it is this drive's."
            ));
        }
        // The folder was checked by name when planned; now it is opened and checked through
        // its handle, and the image is made or opened in that handle, never by path.
        let guard = Guard::of(&source.protected());
        let (parent, name) = match (plan.image.parent(), plan.image.file_name()) {
            (Some(parent), Some(name)) => (parent, name),
            _ => {
                return Err(format!(
                    "{} is not a file in a folder",
                    plan.image.display()
                ))
            }
        };
        let folder = guard
            .base(parent)
            .map_err(|e| format!("{} could not be opened: {e}", parent.display()))?;
        let file = super::writer::open_image(&guard, &folder, name, plan.resumed)
            .map_err(|e| format!("{} could not be opened: {e}", plan.image.display()))?;
        if !plan.resumed {
            make_sparse(&file);
        } else if super::vdisk::strip_left_footer(&file, plan.map.len()).is_err() {
            return Err(format!(
                "{} still carries the footer it had while attached, and it could not be removed",
                plan.image.display()
            ));
        }
        let len = plan.map.len();
        if file.metadata().map(|m| m.len()).unwrap_or(0) < len {
            file.set_len(len)
                .map_err(|e| format!("{} could not be sized: {e}", plan.image.display()))?;
        }
        Self::begin(plan, source, guard, folder, Box::new(file))
    }

    /// Starts a run writing its image to `image`; the map is written once before any read.
    fn begin(
        plan: Plan,
        source: &dyn BlockSource,
        guard: Guard,
        folder: Folder,
        image: Box<dyn Sink>,
    ) -> Result<Self, String> {
        let mut heading = vec![
            format!(
                "Mapfile. Created by Diagnostic Tool {} (GNU ddrescue mapfile format)",
                env!("CARGO_PKG_VERSION")
            ),
            format!(
                "Command line: rescue image of {} to {}",
                source.describe(),
                plan.image.display()
            ),
        ];
        // The drive's identity, so a resumed run reads the same drive. A drive that did not
        // give its own identity at the start keeps the one the map already holds for it.
        // Only where the technician confirmed the map is this drive's: what Windows reports
        // is often the USB adapter's, and another drive behind the same adapter reports the
        // same, so a match on it alone never vouches for the map's drive serial.
        let old = if plan.resumed && plan.confirmed {
            map_heading(&plan.map_path).ok().flatten()
        } else {
            None
        };
        let source_id = kept_identity(source.identity(), old);
        heading.extend(source_id.iter().flat_map(identity_lines));
        // Only the map this session's run left at the path, unchanged, is remembered.
        let print = body_print(&plan.map.to_text(&[]));
        let mut memory = remembered()
            .lock()
            .map(|mut m| match m.remove(&plan.map_path) {
                Some(kept) if plan.resumed && kept.saved == Some(print) => kept,
                _ => Remembered::default(),
            })
            .unwrap_or_default();
        // A resume with no zones from this app session takes them from the drops its event
        // log holds.
        if plan.resumed && memory.zones.is_empty() {
            let log = super::events::path_for(&plan.image);
            memory.zones = zones_from_log(&log, &plan.map, u64::from(source.sector_size().max(1)));
        }
        heading.push(format!("Start time:   {}", stamp(SystemTime::now())));
        let mut rescue = Self {
            image,
            guard,
            folder,
            map: plan.map,
            map_path: plan.map_path,
            heading,
            last_save: Instant::now(),
            refused_since: None,
            map_lag_limit: MAP_LAG_LIMIT,
            saved: false,
            saved_print: None,
            last_health: Instant::now(),
            last_publish: Instant::now(),
            buffer: Vec::new(),
            photos: None,
            dropped: None,
            zones: memory.zones,
            streak: Streak::default(),
            reads_ok: 0,
            source_id,
            fill_from: None,
            fill_at: None,
            fill_edge: None,
            fill_keep: None,
            fill_only: None,
            filling: None,
            in_photos: false,
            dropped_photos: false,
            photos_ended: false,
            events: EventLog::default(),
            gone_code: None,
            phase_said: None,
            rate_since: Instant::now(),
            rate_rescued: 0,
        };
        rescue.rate_rescued = rescue.map.count(Status::Rescued);
        rescue.save().map_err(|e| match e {
            Halt::Write(why) => why,
            _ => "the map could not be written".into(),
        })?;
        Ok(rescue)
    }

    /// Writes the image's data to disk, then the map beside it and over the old one, so the
    /// map never claims data the image does not hold.
    fn save(&mut self) -> Result<(), Halt> {
        self.try_save(true).map_err(|(why, held)| {
            Halt::Write(if held {
                format!("{why}; another program is holding the map. The map saved last is whole, and Resume carries on from it once the program lets go of it")
            } else {
                why
            })
        })
    }

    /// `save`, saying with its error whether another program refused the map's rename by
    /// holding it, which passes, rather than a write that failed.
    fn try_save(&mut self, patient: bool) -> Result<(), (String, bool)> {
        self.image
            .flush_data()
            .map_err(|e| (format!("the image could not be flushed: {e}"), false))?;
        let mut heading = self.heading.clone();
        heading.push(format!("Current time: {}", stamp(SystemTime::now())));
        let text = self.map.to_text(&heading);
        let name = self.map_path.file_name().unwrap_or_default();
        super::writer::save_map(&self.guard, &self.folder, name, text.as_bytes(), patient)
            .map_err(|e| {
                let why = format!("{} could not be saved: {e}", self.map_path.display());
                (why, e.held)
            })?;
        self.last_save = Instant::now();
        self.saved = true;
        self.saved_print = Some(body_print(&text));
        self.remember();
        self.keep_fill_place();
        if let Some(since) = self.refused_since.take() {
            self.events.write(
                &Event::MapSaved {
                    after_seconds: since.elapsed().as_secs(),
                },
                Figures::of(&self.map),
            );
        }
        Ok(())
    }

    /// A timed save. One refused because another program holds the map does not end the
    /// run: the map on disk stays the last one saved, whole, and the next timed save tries
    /// again. Only refusals for `MAP_LAG_LIMIT` end it, so the map never falls further
    /// behind the image than that; any other failure ends it at once.
    fn save_timed(&mut self) -> Result<(), Halt> {
        match self.try_save(false) {
            Ok(()) => Ok(()),
            Err((why, false)) => Err(Halt::Write(why)),
            Err((why, true)) => {
                self.last_save = Instant::now();
                let since = match self.refused_since {
                    Some(since) => since,
                    None => {
                        self.events.write(
                            &Event::MapNotSaved {
                                reason: format!(
                                    "{why}; another program is holding the map, so the run carries on and saves it again at the next save"
                                ),
                            },
                            Figures::of(&self.map),
                        );
                        *self.refused_since.insert(Instant::now())
                    }
                };
                if since.elapsed() >= self.map_lag_limit {
                    return Err(Halt::Write(format!(
                        "{why}; another program has held the map for {} minutes. The map saved last is whole, and Resume carries on from it once the program lets go of it",
                        since.elapsed().as_secs() / 60
                    )));
                }
                Ok(())
            }
        }
    }

    /// Opens a file beside the image through the same checks: made new, or, when a stopped
    /// run left one, opened to be added to.
    pub fn beside(&self, name: &std::ffi::OsStr) -> std::io::Result<File> {
        super::writer::open_beside(&self.guard, &self.folder, name)
    }

    /// Whether this run saved its map.
    pub fn map_saved(&self) -> bool {
        self.saved
    }

    /// Where the map is saved.
    pub fn map_path(&self) -> &Path {
        &self.map_path
    }

    /// Reads that came back in this run.
    pub fn reads_ok(&self) -> u64 {
        self.reads_ok
    }

    /// After the drive stopped answering in a read: the read in flight is recorded as a failed
    /// read of its length in its phase, and nothing else changes status. In copying, trimming
    /// and scraping the place joins the hang zones (`Zones::hang`): outside a zone it sets
    /// aside the drop skip in the direction the pass read, which every phase reads last and
    /// from its far side; inside one it is a further hang there, counted against the zone's
    /// budget. A drive that hangs at a place usually hangs there again, and on 2026-11-09 and
    /// 10 each pass that started at a hang place hung again. Retry passes and Fill the gaps
    /// skip past the place by the drop skip. A drop in photos first's areas also ends photos
    /// first for this run. Returns the span set aside; None when the drive did not stop in a
    /// read.
    pub fn skip_drop(&mut self, sector: u64, first: u64) -> Option<(u64, u64)> {
        let (pos, len) = self.dropped.take()?;
        let photos = std::mem::take(&mut self.dropped_photos) || self.in_photos;
        let size = self.map.len();
        // The dropped read counts as a failed read of its length in the phase it was in, by
        // the one rule every failed read follows (`after_failed_read`). Photos first's reads
        // are copying's. Retry passes and Fill the gaps keep their own handling.
        if let Some(reads) = self.zoned() {
            self.map
                .set_where(pos, len, reads, Status::after_failed_read(len, sector));
        }
        if photos {
            self.photos_ended = true;
        }
        if self.zoned().is_some() {
            let inside = self.zones.first_overlap(pos, pos + len.max(1)).is_some();
            let backwards = (self.map.phase, self.map.pass) == (Phase::Copying, 2);
            let area = self.map.area(pos, pos + len, AREA_BRIDGE, failed);
            let ahead = if self.map.phase == Phase::Copying {
                first
            } else {
                0
            };
            let span = self
                .zones
                .hang(pos, len, backwards, size, sector, ahead, Some(area));
            // A copying pass resumed after the drop goes on past the span, as it reads.
            if !inside && self.map.phase == Phase::Copying && !photos {
                self.map.current_pos = if backwards { span.0 } else { span.1 };
            }
            return Some(span);
        }
        // A retry pass or Fill the gaps goes on past the damaged area it dropped in, in the
        // direction it reads, and where the read was untried, with nothing mapped ahead, past
        // the first skip too, as copying does.
        let backwards = self
            .filling
            .unwrap_or((self.map.phase, self.map.pass) == (Phase::Retrying, 1));
        let end = (pos + len).min(size);
        let (lo, hi) = self.map.area(pos, end, AREA_BRIDGE, failed);
        let untried = self
            .map
            .find(Status::Untried, pos)
            .is_some_and(|b| b.pos < end);
        let ahead = if untried {
            super::zones::skip_ahead(first, size, sector)
        } else {
            0
        };
        // Fill the gaps reads a sector at a time: the one the drive hung on failed, and is bad
        // (after the look for untried bytes there, which it was),
        // so a pass that reads what never failed first does not walk back into it (on
        // 2026-11-10 the first sector of a 16.7 MB stretch at 97.27 GB hung the drive at each
        // directed read from there).
        if self.filling.is_some() {
            let splitting = self.map.reads_before_bad();
            let hung = len.min(sector.max(1));
            self.map.set(pos, hung, Status::Bad);
            // Reading what never failed, split from the middle (`Sweep::skip_bad`): nothing is
            // skipped, the next sweep splits what is left around the bad sector.
            if splitting {
                self.fill_from = None;
                self.fill_edge = None;
                return Some((pos, pos + hung));
            }
        }
        let (target, span) = if backwards {
            let lo = lo.min(pos.saturating_sub(ahead) / sector.max(1) * sector.max(1));
            (lo, (lo, end))
        } else {
            let hi = hi.max(pos.saturating_add(ahead).min(size));
            (hi, (pos, hi))
        };
        match self.filling {
            Some(_) => {
                self.fill_from = Some(target);
                self.fill_edge = Some(target);
            }
            None => self.map.current_pos = target,
        }
        Some(span)
    }

    /// Keeps the zones and the drop skip for a Resume of this map (`Remembered`), as they
    /// stood when the map was saved: only `try_save` calls it, after the save, so what is
    /// remembered always goes with the map on disk.
    fn remember(&self) {
        if let Ok(mut memory) = remembered().lock() {
            memory.insert(
                self.map_path.clone(),
                Remembered {
                    zones: self.zones.clone(),
                    saved: self.saved_print,
                },
            );
        }
    }

    /// The source being read, as the map names it (`kept_identity`).
    pub fn source_id(&self) -> Option<&SourceId> {
        self.source_id.as_ref()
    }

    /// The status the phase reads when a drop in it makes a hang zone: copying, trimming and
    /// scraping. Retry passes and Fill the gaps keep their own drop skip and give none.
    pub(crate) fn zoned(&self) -> Option<Status> {
        if self.filling.is_some() {
            return None;
        }
        match self.map.phase {
            Phase::Copying => Some(Status::Untried),
            Phase::Trimming => Some(Status::NonTrimmed),
            Phase::Scraping => Some(Status::NonScraped),
            _ => None,
        }
    }

    /// Whether the zone around `at` still has hangs left in this phase, so its zone stage
    /// reads it; false outside every zone.
    pub(crate) fn zone_open(&self, at: u64) -> bool {
        self.zones
            .first_overlap(at, at + 1)
            .is_some_and(|z| z.spent < super::zones::BUDGET)
    }

    /// The read in flight when the drive stopped answering, until `skip_drop` takes it.
    pub(crate) fn in_flight(&self) -> Option<(u64, u64)> {
        self.dropped
    }

    /// Bytes inside the hang zones no phase has finished reading: untried, non-trimmed or
    /// non-scraped. Bad sectors there were read and failed like any other.
    pub fn zones_left(&self) -> u64 {
        let mut left = 0;
        for zone in self.zones.list() {
            let mut at = zone.from;
            while let Some(b) = self
                .map
                .find_where(
                    |s| matches!(s, Status::Untried | Status::NonTrimmed | Status::NonScraped),
                    at,
                )
                .filter(|b| b.pos < zone.to)
            {
                let end = b.end().min(zone.to);
                left += end - b.pos;
                at = end;
            }
        }
        left
    }

    /// The first area with `status` from `from` that lies outside every hang zone, cut short
    /// where a zone starts: what each phase reads before it comes to the zones.
    fn find_outside(&self, status: Status, from: u64) -> Option<Block> {
        let mut at = from;
        loop {
            let block = self.map.find(status, at)?;
            match self.zones.first_overlap(block.pos, block.end()) {
                None => return Some(block),
                Some(zone) if zone.from <= block.pos => at = zone.to,
                Some(zone) => {
                    return Some(Block {
                        pos: block.pos,
                        size: zone.from - block.pos,
                        status,
                    })
                }
            }
        }
    }

    /// The last area with `status` before `before` that lies outside every hang zone, cut
    /// short where a zone ends.
    fn find_back_outside(&self, status: Status, before: u64) -> Option<Block> {
        let mut at = before;
        loop {
            let block = self.map.find_back(status, at)?;
            match self.zones.last_overlap(block.pos, block.end()) {
                None => return Some(block),
                Some(zone) if zone.to >= block.end() => at = zone.from,
                Some(zone) => {
                    return Some(Block {
                        pos: zone.to,
                        size: block.end() - zone.to,
                        status,
                    })
                }
            }
        }
    }

    /// The next part of a hang zone with `status` to read, and whether it is read downwards:
    /// the first stretch with any (`Zones::stretches`), at the end it is read from.
    fn zone_piece(&self, status: Status, unit: u64) -> Option<(Block, bool)> {
        self.zones.stretches(unit).into_iter().find_map(|stretch| {
            let block = if stretch.down {
                let b = self
                    .map
                    .find_back(status, stretch.to)
                    .filter(|b| b.end() > stretch.from)?;
                let pos = b.pos.max(stretch.from);
                Block {
                    pos,
                    size: b.end() - pos,
                    status,
                }
            } else {
                let b = self
                    .map
                    .find(status, stretch.from)
                    .filter(|b| b.pos < stretch.to)?;
                Block {
                    pos: b.pos,
                    size: b.end().min(stretch.to) - b.pos,
                    status,
                }
            };
            Some((block, stretch.down))
        })
    }

    /// Photos first, ended for this run by the drive stopping in its areas, said.
    fn photos_stopped(&mut self, progress: &Progress) {
        let mut status = match self.photos.take() {
            Some((status, _)) => status,
            None => PhotosStatus {
                state: PhotosState::Records,
                files: 0,
                deleted: 0,
                bytes: 0,
                area: 0,
                rescued: 0,
                failed: 0,
                notes: Vec::new(),
            },
        };
        status.state = PhotosState::FellBack(
            "the drive stopped answering while its photos were read, so it is not asked for them again in this run".into(),
        );
        if let Ok(mut shown) = progress.photos.lock() {
            *shown = Some(status);
        }
    }

    /// One health reading, heeded. While the drive is too hot the map is saved once and the
    /// watch is asked again, which waits for its next reading, until it says to go on.
    fn watch_now(
        &mut self,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        // The figures the reading is logged with are the run's at this moment, not as last
        // published a moment ago.
        self.publish(progress);
        let mut saved = false;
        loop {
            match watch() {
                Watch::Cooling => {
                    if !saved {
                        self.save_timed()?;
                        self.publish(progress);
                        saved = true;
                    }
                }
                other => return heed(other),
            }
        }
    }

    /// Runs the passes from where the map says, until finished, stopped or paused.
    pub fn run(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Outcome {
        self.run_hooked(source, settings, stop, progress, watch, &mut |_| {})
    }

    /// `run`, with `on_pass` told each pass's phase as it begins (photos first is part of
    /// copying), for the drive's read limit.
    pub fn run_hooked(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
        on_pass: &mut dyn FnMut(Phase),
    ) -> Outcome {
        progress.publish(&self.map);
        let result = self.passes(source, settings, stop, progress, watch, on_pass);
        // A drop is not the run's end: it goes on to wait for the drive (`wait::pause`),
        // so its save is a timed one, which a held map does not end.
        let saved = if matches!(result, Err(Halt::Gone(_))) {
            self.save_timed()
        } else {
            self.save()
        };
        self.publish(progress);
        match (result, saved) {
            (_, Err(Halt::Write(why))) | (Err(Halt::Write(why)), _) => Outcome::Failed(why),
            (Ok(()), _) => Outcome::Finished,
            (Err(Halt::Stop), _) => Outcome::Stopped,
            (Err(Halt::Pause(why)), _) => Outcome::Paused(why),
            (Err(Halt::Gone(why)), _) => Outcome::Gone(why),
        }
    }

    /// The phases in order. Every copying pass comes before any failed area is read again,
    /// and a sector that failed on its own is read again only in the retry passes chosen
    /// (`Settings::retries`), the reverse pass first.
    fn passes(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
        on_pass: &mut dyn FnMut(Phase),
    ) -> Result<(), Halt> {
        let mut order: Vec<(Phase, u32)> = vec![
            (Phase::Copying, 1),
            (Phase::Copying, 2),
            (Phase::Copying, 3),
            (Phase::Copying, 4),
            (Phase::Trimming, 1),
            (Phase::Scraping, 1),
        ];
        // Retry 1 is the reverse pass, written as ddrescue's backwards retry.
        order.extend((1..=settings.retries.min(3)).map(|k| (Phase::Retrying, k)));
        // A finished map run again with retries asked for runs just the retries.
        let start = match self.map.phase {
            Phase::Finished => order.len() - settings.retries.min(3) as usize,
            phase => order
                .iter()
                .position(|step| *step == (phase, self.map.pass))
                .unwrap_or(order.len()),
        };
        let resuming = self.map.phase != Phase::Finished;
        for (index, &(phase, pass)) in order.iter().enumerate().skip(start) {
            if index > start || !resuming {
                // A new pass starts from its beginning, after a health reading.
                self.watch_now(progress, watch)?;
                self.last_health = Instant::now();
                let backwards = [(Phase::Copying, 2), (Phase::Retrying, 1)];
                self.map.current_pos = if backwards.contains(&(phase, pass)) {
                    self.map.len()
                } else {
                    0
                };
            }
            self.map.phase = phase;
            self.map.pass = pass;
            if self.zones.start_phase(phase) && phase != Phase::Copying {
                let map = &self.map;
                self.zones
                    .fit(|at, end| map.area(at, end, AREA_BRIDGE, failed));
            }
            self.save_timed()?;
            on_pass(phase);
            self.say_phase();
            if (phase, pass) == (Phase::Copying, 1) && settings.photos_first.enabled {
                if self.photos_ended {
                    self.photos_stopped(progress);
                } else {
                    // Before pass 1, and again when a stopped pass 1 resumes: the records
                    // read back from the image, and only the photos' areas not read yet.
                    self.in_photos = true;
                    let photos = self.photos_first(source, settings, stop, progress, watch);
                    self.in_photos = false;
                    photos?;
                }
            }
            match phase {
                Phase::Copying => self.copy_pass(source, settings, stop, progress, watch, pass)?,
                Phase::Trimming => self.trim(source, settings, stop, progress, watch)?,
                Phase::Scraping => self.scrape(source, settings, stop, progress, watch)?,
                Phase::Retrying if pass == 1 => {
                    self.reverse(source, settings, stop, progress, watch)?
                }
                Phase::Retrying => self.retry(source, settings, stop, progress, watch)?,
                Phase::Finished => {}
            }
        }
        self.map.phase = Phase::Finished;
        self.map.pass = 1;
        self.map.current_pos = self.map.len();
        Ok(())
    }

    /// One read; on success the data goes into the image, and the area is marked rescued
    /// only once every byte of it is written.
    fn read(&mut self, source: &mut dyn BlockSource, pos: u64, len: u64) -> Result<bool, Halt> {
        let mut buffer = std::mem::take(&mut self.buffer);
        if buffer.len() < len as usize {
            buffer.resize(len as usize, 0);
        }
        let read = self.read_into(source, pos, &mut buffer[..len as usize]);
        self.buffer = buffer;
        read
    }

    /// `read` into the caller's buffer.
    fn read_into(
        &mut self,
        source: &mut dyn BlockSource,
        pos: u64,
        buffer: &mut [u8],
    ) -> Result<bool, Halt> {
        let len = buffer.len() as u64;
        match source.read_at(pos, buffer) {
            Ok(()) => {
                write_all_at(self.image.as_mut(), buffer, pos)
                    .map_err(|e| Halt::Write(format!("the image could not be written: {e}")))?;
                self.map.set(pos, len, Status::Rescued);
                self.reads_ok += 1;
                self.streak = Streak::default();
                Ok(true)
            }
            // Not recorded: the read in flight stays as it was in the map.
            Err(ReadError::Gone(code)) => {
                self.dropped = Some((pos, len));
                self.dropped_photos = self.in_photos;
                self.gone_code = Some(code);
                Err(Halt::Gone(format!(
                    "The drive stopped answering (error {code}): it was unplugged or has failed."
                )))
            }
            // The runaway guard: a long run of failures is recorded only while the drive
            // shows it still answers.
            Err(ReadError::Bad(_) | ReadError::TimedOut)
                if self.streak.add(pos, len) && !source.answering() =>
            {
                self.dropped = Some((pos, len));
                self.dropped_photos = self.in_photos;
                Err(Halt::Gone(format!(
                    "The drive stopped answering: reads failed {RUNAWAY_READS} times in a row or across {} with none coming back, and it did not report its size when asked.",
                    bytes_text(RUNAWAY_SPAN)
                )))
            }
            Err(failed @ (ReadError::Bad(_) | ReadError::TimedOut)) => {
                let code = match failed {
                    ReadError::Bad(code) => Some(code),
                    _ => None,
                };
                self.events.write(
                    &Event::ReadError {
                        at: pos,
                        length: len,
                        code,
                    },
                    Figures::of(&self.map),
                );
                Ok(false)
            }
        }
    }

    /// Writes the phase and pass as an event when they changed since the last one written.
    pub(crate) fn say_phase(&mut self) {
        let now = (self.map.phase, self.map.pass);
        if self.phase_said != Some(now) {
            self.phase_said = Some(now);
            self.events.write(
                &Event::Phase {
                    phase: format!("{:?}", now.0).to_lowercase(),
                    pass: now.1,
                },
                Figures::of(&self.map),
            );
        }
    }

    /// A Fill the gaps pass as an event, once.
    pub(crate) fn say_fill_pass(&mut self, pass: u32) {
        if self.phase_said != Some((Phase::Finished, pass)) {
            self.phase_said = Some((Phase::Finished, pass));
            self.events.write(
                &Event::Phase {
                    phase: "fill the gaps".into(),
                    pass,
                },
                Figures::of(&self.map),
            );
        }
    }

    /// Between reads: stop, periodic save, periodic health reading, progress.
    fn tick(
        &mut self,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        self.tick_quiet(settings, stop, progress)?;
        if self.last_health.elapsed() >= settings.health_every {
            self.last_health = Instant::now();
            self.watch_now(progress, watch)?;
        }
        Ok(())
    }

    /// `tick` without the health reading.
    fn tick_quiet(
        &mut self,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
    ) -> Result<(), Halt> {
        if stop.load(Ordering::Relaxed) {
            return Err(Halt::Stop);
        }
        if self.last_save.elapsed() >= settings.save_every {
            self.save_timed()?;
        }
        if self.last_publish.elapsed() >= Duration::from_millis(200) {
            self.last_publish = Instant::now();
            self.publish(progress);
        }
        if self.rate_since.elapsed() >= PROGRESS_EVERY {
            let rescued = self.map.count(Status::Rescued);
            let seconds = self.rate_since.elapsed().as_secs_f64().max(1.0);
            let bytes_per_second =
                (rescued.saturating_sub(self.rate_rescued) as f64 / seconds) as u64;
            self.rate_since = Instant::now();
            self.rate_rescued = rescued;
            self.events.write(
                &Event::Progress { bytes_per_second },
                Figures::of(&self.map),
            );
        }
        Ok(())
    }

    /// The map's figures, and photos first's when it has listed the photos.
    pub(crate) fn publish(&mut self, progress: &Progress) {
        progress.publish(&self.map);
        let reading = match self.filling {
            Some(_) => self.fill_at,
            None => (self.map.phase != Phase::Finished).then_some(self.map.current_pos),
        };
        if let Ok(mut shown) = progress.reading.lock() {
            *shown = reading;
        }
        if let Some((status, areas)) = &mut self.photos {
            (status.rescued, status.failed) = self.map.count_in(areas);
            if let Ok(mut shown) = progress.photos.lock() {
                *shown = Some(status.clone());
            }
        }
    }

    /// Photos first: reads the file systems' records through the rescue (so they are in
    /// the image first of all), lists the photos and videos, deleted ones included, and
    /// reads their areas before pass 1 goes on. A read that fails is marked as pass 1
    /// marks one and skipped past with pass 1's growing skip, within the area. Records that
    /// cannot be read in full, or within the time limit, leave the usual order, said so.
    fn photos_first(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        let mut status = PhotosStatus {
            state: PhotosState::Records,
            files: 0,
            deleted: 0,
            bytes: 0,
            area: 0,
            rescued: 0,
            failed: 0,
            notes: Vec::new(),
        };
        if let Ok(mut shown) = progress.photos.lock() {
            *shown = Some(status.clone());
        }
        let limit = Duration::from_secs(settings.photos_first.records_limit_secs);
        let (mut halt, mut late) = (None, false);
        let listed = {
            let tap = Tap {
                rescue: self,
                source: &mut *source,
                settings,
                stop,
                progress,
                deadline: Instant::now() + limit,
                halt: &mut halt,
                late: &mut late,
            };
            let mut reader = Reader::new(Box::new(tap));
            photos::list(&mut reader, stop)
        };
        if let Some(halt) = halt {
            return Err(halt);
        }
        let fell_back = match listed {
            _ if late => Err(format!(
                "reading the file system's records took longer than {} min",
                limit.as_secs().div_ceil(60)
            )),
            Err(why) => Err(why),
            Ok(list) if list.files == 0 => {
                Err("the file system's records list no photos or videos".into())
            }
            Ok(list) => Ok(list),
        };
        let list = match fell_back {
            Ok(list) => list,
            Err(why) => {
                status.state = PhotosState::FellBack(why);
                if let Ok(mut shown) = progress.photos.lock() {
                    *shown = Some(status);
                }
                return Ok(());
            }
        };
        status.state = PhotosState::Copying;
        status.files = list.files;
        status.deleted = list.deleted;
        status.bytes = list.bytes;
        status.area = list.extents.iter().map(|(s, e)| e - s).sum();
        status.notes = list.notes;
        self.photos = Some((status, list.extents.clone()));
        self.publish(progress);
        let sector = Self::sector(source);
        let cluster = (settings.cluster / sector).max(1) * sector;
        let round = |v: u64| v.div_ceil(sector) * sector;
        let first_skip = round(settings.skip.max(sector));
        for (start, end) in list.extents {
            let end = round(end).min(self.map.len());
            let mut pos = start / sector * sector;
            let mut skip = first_skip;
            while let Some(area) = self
                .find_outside(Status::Untried, pos)
                .filter(|a| a.pos < end)
            {
                self.tick(settings, stop, progress, watch)?;
                let len = cluster.min(area.end().min(end) - area.pos);
                if self.read(source, area.pos, len)? {
                    skip = first_skip;
                    pos = area.pos + len;
                } else {
                    self.map
                        .set(area.pos, len, Status::after_failed_read(len, sector));
                    pos = area.pos + len + skip;
                    skip = round((skip * 2).min(settings.max_skip.max(sector)));
                }
            }
        }
        if let Some((status, _)) = &mut self.photos {
            status.state = PhotosState::Done;
        }
        self.publish(progress);
        self.save_timed()
    }

    fn sector(source: &dyn BlockSource) -> u64 {
        u64::from(source.sector_size().max(1))
    }

    /// Pass 1 skips ahead from each error with a growing skip; passes 2 and 3 read each
    /// untried area from one end until the first error; pass 4 reads all that is left.
    fn copy_pass(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
        pass: u32,
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        let cluster = (settings.cluster / sector).max(1) * sector;
        let round = |v: u64| v.div_ceil(sector) * sector;
        match pass {
            1 => {
                let mut skip = round(settings.skip.max(sector));
                let mut pos = self.map.current_pos;
                while let Some(area) = self.find_outside(Status::Untried, pos) {
                    self.tick(settings, stop, progress, watch)?;
                    pos = area.pos;
                    let len = cluster.min(area.end() - pos);
                    if self.read(source, pos, len)? {
                        skip = round(settings.skip.max(sector));
                        pos += len;
                    } else {
                        self.map
                            .set(pos, len, Status::after_failed_read(len, sector));
                        pos = (pos + len + skip).min(self.map.len());
                        skip = round((skip * 2).min(settings.max_skip.max(sector)));
                    }
                    // Where pass 1 goes on from, so a resumed run skips what this one skipped.
                    self.map.current_pos = pos;
                }
            }
            2 => {
                let mut before = self.map.current_pos;
                while let Some(area) = self.find_back_outside(Status::Untried, before) {
                    let mut end = area.end();
                    while end > area.pos {
                        self.tick(settings, stop, progress, watch)?;
                        self.map.current_pos = end;
                        let len = cluster.min(end - area.pos);
                        let pos = end - len;
                        let ok = self.read(source, pos, len)?;
                        end = pos;
                        if !ok {
                            self.map
                                .set(pos, len, Status::after_failed_read(len, sector));
                            break;
                        }
                    }
                    before = area.pos;
                    self.map.current_pos = before;
                }
            }
            _ => {
                let sweep = pass >= 4;
                let mut from = self.map.current_pos;
                while let Some(area) = self.find_outside(Status::Untried, from) {
                    let mut pos = area.pos;
                    while pos < area.end() {
                        self.tick(settings, stop, progress, watch)?;
                        self.map.current_pos = pos;
                        let len = cluster.min(area.end() - pos);
                        let ok = self.read(source, pos, len)?;
                        if !ok {
                            self.map
                                .set(pos, len, Status::after_failed_read(len, sector));
                        }
                        pos += len;
                        if !ok && !sweep {
                            break;
                        }
                    }
                    from = area.end();
                    self.map.current_pos = from;
                }
                // Pass 4 is the last to read untried areas: the hang zones' come last of all.
                if sweep {
                    self.zone_stage(
                        source,
                        settings,
                        stop,
                        progress,
                        watch,
                        Status::Untried,
                        cluster,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Reads what is left of `status` in the hang zones that have hangs left in this phase,
    /// each part from the side away from its hangs towards them (`Zones::stretches`), `unit`
    /// bytes at a time; a failed read is marked as the phase marks one and the reading goes
    /// on. A further hang there counts against the zone's budget (`skip_drop`).
    #[allow(clippy::too_many_arguments)]
    fn zone_stage(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
        status: Status,
        unit: u64,
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        while let Some((piece, down)) = self.zone_piece(status, sector) {
            self.tick(settings, stop, progress, watch)?;
            let len = unit.min(piece.size);
            let pos = if down { piece.end() - len } else { piece.pos };
            self.map.current_pos = pos;
            if !self.read(source, pos, len)? {
                let failed = match status {
                    Status::NonScraped => Status::Bad,
                    _ => Status::after_failed_read(len, sector),
                };
                self.map.set(pos, len, failed);
            }
        }
        Ok(())
    }

    /// Reads each failed block's edges sector by sector, inwards, up to the first bad sector
    /// from each side; the middle is left for scraping. Blocks outside the hang zones come
    /// first; in a zone each block's edge away from the hangs is read first.
    fn trim(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        while let Some(block) = self.find_outside(Status::NonTrimmed, 0) {
            self.trim_one(source, settings, stop, progress, watch, block, false)?;
        }
        while let Some((block, down)) = self.zone_piece(Status::NonTrimmed, sector) {
            self.trim_one(source, settings, stop, progress, watch, block, down)?;
        }
        Ok(())
    }

    /// Trims one block: each edge sector by sector inwards up to its first failed sector,
    /// the high edge first when `high_first`. The middle goes on to scraping only when both
    /// edges ended on a failed sector.
    #[allow(clippy::too_many_arguments)]
    fn trim_one(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
        block: Block,
        high_first: bool,
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        let (mut low, mut high) = (block.pos, block.end());
        let sides = if high_first {
            [true, false]
        } else {
            [false, true]
        };
        for from_high in sides {
            while low < high {
                self.tick(settings, stop, progress, watch)?;
                let len = sector.min(high - low);
                let at = if from_high { high - len } else { low };
                self.map.current_pos = at;
                let ok = self.read(source, at, len)?;
                if !ok {
                    self.map.set(at, len, Status::Bad);
                }
                if from_high {
                    high -= len;
                } else {
                    low += len;
                }
                if !ok {
                    break;
                }
            }
        }
        if low < high {
            self.map.set(low, high - low, Status::NonScraped);
        }
        Ok(())
    }

    /// Reads every sector of the trimmed failed areas once, those in hang zones last.
    fn scrape(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        while let Some(block) = self.find_outside(Status::NonScraped, 0) {
            self.tick(settings, stop, progress, watch)?;
            self.map.current_pos = block.pos;
            let len = sector.min(block.size);
            if !self.read(source, block.pos, len)? {
                self.map.set(block.pos, len, Status::Bad);
            }
        }
        self.zone_stage(
            source,
            settings,
            stop,
            progress,
            watch,
            Status::NonScraped,
            sector,
        )
    }

    /// The reverse pass: each bad area is read once more from its far end backwards, sector
    /// by sector, because some drives read past damage from the other side. A failed read
    /// is left bad and not read again; after each further failure in a row the pass skips
    /// back a gap that starts at one sector and doubles up to pass 1's first skip, and good
    /// data starts it over.
    fn reverse(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        let cap = (settings.skip / sector).max(1) * sector;
        while let Some(area) = self.map.find_back(Status::Bad, self.map.current_pos) {
            let mut end = area.end();
            let mut gap = 0;
            while end > area.pos {
                self.tick(settings, stop, progress, watch)?;
                let len = sector.min(end - area.pos);
                let pos = end - len;
                if self.read(source, pos, len)? {
                    gap = 0;
                    end = pos;
                } else {
                    end = pos.saturating_sub(gap).max(area.pos);
                    gap = if gap == 0 { sector } else { (gap * 2).min(cap) };
                }
                // Where the pass goes on from, so a resumed run reads nothing twice.
                self.map.current_pos = end;
            }
            self.map.current_pos = area.pos;
        }
        Ok(())
    }

    /// Tries each bad sector once more, from the map's position onwards.
    fn retry(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
    ) -> Result<(), Halt> {
        let how = Sweep {
            backwards: false,
            any_unread: false,
            track_pos: true,
            skip_bad: false,
        };
        let mut count = SweepCount::default();
        self.sweep(
            source,
            settings,
            stop,
            progress,
            watch,
            how,
            &mut count,
            &mut |_| {},
        )
    }

    /// Reads the areas `how` names one sector at a time, each sector once, forwards or
    /// backwards. What reads goes into the image and the map; in Fill the gaps a sector
    /// that fails is marked bad, and the map is saved within a second of a sector coming
    /// back, so a stop loses nothing that was read.
    #[allow(clippy::too_many_arguments)]
    fn sweep(
        &mut self,
        source: &mut dyn BlockSource,
        settings: &Settings,
        stop: &AtomicBool,
        progress: &Progress,
        watch: &mut dyn FnMut() -> Watch,
        how: Sweep,
        count: &mut SweepCount,
        on_count: &mut dyn FnMut(&SweepCount),
    ) -> Result<(), Halt> {
        let sector = Self::sector(source);
        let wanted_in_block = |s: Status| {
            if how.any_unread {
                s != Status::Rescued
            } else {
                s == Status::Bad
            }
        };
        let wanted = |s: Status| wanted_in_block(s) && !(how.skip_bad && s == Status::Bad);
        // Fill the gaps starts at its end, or past a drop skip when it carries on.
        let from = if how.track_pos {
            None
        } else {
            self.fill_from.take()
        };
        let mut edge = match (how.track_pos, how.backwards) {
            (true, _) => self.map.current_pos,
            (false, false) => from.unwrap_or(0),
            (false, true) => from.unwrap_or(self.map.len()),
        };
        // While anything that never failed is left, Fill the gaps reads its longest run from
        // the middle, forwards to its end and then backwards to its start, and a drop splits
        // what is left again, with nothing skipped; the drive hangs mostly in the first and
        // last few blocks of a run, which this leaves for last (the hanging blocks are usually on 2 or 3 blocks at the beginning or end of the
        // big chunks."). The run being read and where it was split; a place asked for splits
        // its own run there.
        let mut split: Option<(Range<u64>, u64)> = None;
        let mut split_from = from.filter(|_| how.skip_bad);
        // A block read while the pass waits at `edge`: the block and how far it is read.
        let only = self.fill_only.clone().filter(|_| !how.track_pos);
        // A block read alone leaves the passes' place as it was (`hold_fill_place`); a split
        // read keeps none, the longest run being found again.
        if !how.track_pos && only.is_none() {
            self.fill_edge = (!how.skip_bad).then_some(edge);
        }
        // A block read alone that the drive dropped in goes on past the drop skip, as a pass
        // does, not back to the sector it hung on.
        let mut detour: Option<(Range<u64>, u64)> = only
            .clone()
            .map(|r| (r.clone(), r.start.max(edge).min(r.end)));
        // The block read last: the pass passes over it, each sector being read once a pass.
        let mut done: Option<Range<u64>> = None;
        loop {
            if !how.track_pos {
                let asked = progress.directed.lock().ok().and_then(|mut d| d.take());
                if let Some(asked) = asked {
                    let range = asked.range();
                    let (start, end) = (
                        range.start.min(self.map.len()),
                        range.end.min(self.map.len()),
                    );
                    match asked {
                        Directed::From { .. } => {
                            edge = if how.backwards { end } else { start };
                            self.fill_edge = (!how.skip_bad).then_some(edge);
                            detour = None;
                            split = None;
                            split_from = how.skip_bad.then_some(start);
                        }
                        Directed::Block { .. } => detour = Some((start..end, start)),
                    }
                    self.events.write(
                        &Event::Directed {
                            how: asked.how().into(),
                            start,
                            end,
                        },
                        Figures::of(&self.map),
                    );
                }
            }
            // The block to read and whether its last sector is read first.
            let found = match &detour {
                Some((range, cursor)) => self
                    .map
                    .find_where(wanted_in_block, *cursor)
                    .filter(|b| b.pos < range.end)
                    .map(|b| {
                        let size = b.size.min(range.end - b.pos);
                        (Block { size, ..b }, false)
                    }),
                None if how.skip_bad => {
                    if split.is_none() {
                        split = split_from
                            .take()
                            .and_then(|at| {
                                let run = self.map.unfailed_run(at)?;
                                let at = at.clamp(run.start, run.end);
                                Some((run, at))
                            })
                            .or_else(|| {
                                let run = self.map.largest_unfailed()?;
                                let at = Map::split_at(&run, sector);
                                Some((run, at))
                            });
                    }
                    let Some((run, pivot)) = split.clone() else {
                        break;
                    };
                    let ahead = self
                        .map
                        .find_where(unfailed, pivot)
                        .filter(|b| b.pos < run.end)
                        .map(|b| {
                            let size = b.size.min(run.end - b.pos);
                            (Block { size, ..b }, false)
                        });
                    let behind = || {
                        self.map
                            .find_back_where(unfailed, pivot)
                            .filter(|b| b.end() > run.start)
                            .map(|b| {
                                let pos = b.pos.max(run.start);
                                let size = b.end() - pos;
                                (Block { pos, size, ..b }, true)
                            })
                    };
                    match ahead.or_else(behind) {
                        Some(found) => Some(found),
                        // The run is read both ways: the next longest.
                        None => {
                            split = None;
                            continue;
                        }
                    }
                }
                None if how.backwards => self.map.find_back_where(wanted, edge).map(|b| (b, true)),
                None => self.map.find_where(wanted, edge).map(|b| (b, false)),
            };
            let Some((block, last_first)) = found else {
                // The block is read: the pass goes on from where it waited, or ends.
                if let Some((range, _)) = detour.take() {
                    if only.is_none() {
                        done = Some(range);
                        continue;
                    }
                }
                break;
            };
            if detour.is_none() && !how.skip_bad {
                if let Some(done) = &done {
                    if how.backwards && done.contains(&(block.end() - 1)) {
                        edge = done.start;
                        continue;
                    }
                    if !how.backwards && done.contains(&block.pos) {
                        edge = done.end;
                        continue;
                    }
                }
            }
            let len = sector.min(block.size);
            let at = if last_first {
                block.end() - len
            } else {
                block.pos
            };
            // Known before the tick publishes it, so the strip rings the sector being read.
            if how.track_pos {
                self.map.current_pos = at;
            } else {
                self.fill_at = Some(at);
            }
            self.tick(settings, stop, progress, watch)?;
            let ok = self.read(source, at, len)?;
            count.read += len;
            if ok {
                count.recovered += len;
            } else if how.any_unread {
                self.map.set(at, len, Status::Bad);
            }
            match &mut detour {
                Some((_, cursor)) => *cursor = at + len,
                None => {
                    edge = if how.backwards { at } else { at + len };
                    if !how.track_pos && !how.skip_bad {
                        self.fill_edge = Some(edge);
                    }
                }
            }
            // Counted before the save, which may end the pass.
            on_count(count);
            if ok && how.any_unread && self.last_save.elapsed() >= Duration::from_secs(1) {
                self.save_timed()?;
            }
        }
        Ok(())
    }

    /// Bytes not rescued yet, in any state.
    pub fn unread(&self) -> u64 {
        self.map.len() - self.map.count(Status::Rescued)
    }

    /// One pass of Fill the gaps over every area not rescued yet, one sector at a time,
    /// each sector once, forwards or backwards. The map's phase and position are left as
    /// they were, so the map stays the run's and ddrescue reads it the same; only statuses
    /// change, to rescued or to bad. `on_count` hears of every read, and `watch` is asked
    /// every `every` (the heat pause). A pass that ended with the drive gone carries on past
    /// the drop skip when it is called again after `skip_drop`.
    #[allow(clippy::too_many_arguments)]
    pub fn fill_pass(
        &mut self,
        source: &mut dyn BlockSource,
        backwards: bool,
        stop: &AtomicBool,
        progress: &Progress,
        every: Duration,
        watch: &mut dyn FnMut() -> Watch,
        on_count: &mut dyn FnMut(&SweepCount),
    ) -> Result<SweepCount, Outcome> {
        let settings = Settings {
            health_every: every,
            ..Settings::for_len(self.map.len())
        };
        let how = Sweep {
            backwards,
            any_unread: true,
            track_pos: false,
            skip_bad: self.map.reads_before_bad(),
        };
        let mut count = SweepCount::default();
        self.filling = Some(backwards);
        self.last_health = Instant::now();
        let swept = self.sweep(
            source, &settings, stop, progress, watch, how, &mut count, on_count,
        );
        // Between passes and after the last, nothing is being read.
        self.fill_at = None;
        self.publish(progress);
        // A drop leaves `filling` for `skip_drop`; any other end clears it.
        if !matches!(swept, Err(Halt::Gone(_))) {
            self.filling = None;
        }
        swept.map(|()| count).map_err(Halt::outcome)
    }

    /// Fill the gaps' pass has ended for good (the caller gave up waiting): no skip applies.
    pub fn end_filling(&mut self) {
        self.filling = None;
        self.fill_from = None;
    }

    /// From now on each map save keeps Fill the gaps' place at `path` (`FillPlace`): pass
    /// `pass`, read `backwards` or not, from its start until it reads.
    pub fn keep_fill_places(&mut self, path: PathBuf, pass: u32, backwards: bool) {
        self.fill_keep = Some((path, pass, backwards));
        self.fill_edge = None;
    }

    /// Fill the gaps reads only `block`, once, from here on (`Directed::Block` with no pass
    /// running).
    pub fn fill_only(&mut self, block: Range<u64>) {
        self.fill_only = Some(block);
    }

    /// The next Fill the gaps pass starts at `at` rather than at its end: where a run before
    /// this one stopped (`FillPlace`).
    pub fn carry_on_fill(&mut self, at: u64) {
        self.fill_from = Some(at.min(self.map.len()));
    }

    /// After a map save in Fill the gaps: its place, beside the image, as far as the map on
    /// disk holds its reads. A place that cannot be written leaves the one before, a little
    /// behind, which a restart reads again: the run goes on.
    fn keep_fill_place(&self) {
        let Some((path, pass, backwards)) = &self.fill_keep else {
            return;
        };
        let place = FillPlace {
            pass: *pass,
            backwards: *backwards,
            at: self.fill_edge,
        };
        if let (Some(name), Ok(json)) = (path.file_name(), serde_json::to_vec(&place)) {
            let _ = super::writer::save_map(&self.guard, &self.folder, name, &json, false);
        }
    }

    /// Writes the map as it is now beside it, as `<map name>.<what>-<date and time>`, for an
    /// undo of a step that rewrites statuses (manual step 24); the copy's path, or why not.
    pub fn keep_map_copy(&self, what: &str) -> Result<PathBuf, String> {
        let s = crate::clock::local(SystemTime::now());
        let mut name = self.map_path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(
            ".{what}-{:04}{:02}{:02}-{:02}{:02}{:02}",
            s.year, s.month, s.day, s.hour, s.minute, s.second
        ));
        let mut heading = self.heading.clone();
        heading.push(format!("Current time: {}", stamp(SystemTime::now())));
        let text = self.map.to_text(&heading);
        super::writer::save_map(&self.guard, &self.folder, &name, text.as_bytes(), true)
            .map_err(|e| format!("a copy of the map could not be kept: {e}"))?;
        Ok(self.map_path.with_file_name(name))
    }

    /// Saves the map during a run, as a timed save does: a refusal by another program
    /// holding the map passes until `MAP_LAG_LIMIT`. Err says why the run cannot go on.
    pub fn save_during(&mut self) -> Result<(), String> {
        self.save_timed().map_err(|halt| match halt.outcome() {
            Outcome::Failed(why) => why,
            other => format!("{other:?}"),
        })
    }

    /// Saves the map now (after flushing the image); Err says why it could not be.
    pub fn save_now(&mut self) -> Result<(), String> {
        self.save().map_err(|halt| match halt.outcome() {
            Outcome::Failed(why) => why,
            other => format!("{other:?}"),
        })
    }
}

// ---- the drive's health between passes -------------------------------------------------

pub(crate) fn temperature(disk: &Disk) -> Option<i32> {
    let own = match &disk.health {
        Health::Nvme(log) => log.celsius(),
        Health::Ata(attributes) => attributes
            .iter()
            .find(|a| a.id == 194 && a.raw[0] > 0)
            .map(|a| i32::from(a.raw[0])),
        Health::Unread(_) => None,
    };
    own.or_else(|| {
        disk.temperature
            .as_ref()
            .ok()
            .and_then(|t| t.current)
            .map(i32::from)
    })
}

/// The pause on the drive's error counts. It judges how fast reallocated plus pending
/// sectors grow (an NVMe drive's media errors), over the last `minutes`, not any single rise:
/// on a badly damaged drive every bad area raises them a little, and a rule on any rise
/// stops an unattended run at nearly every one. It pauses when they grew by `limit` or more
/// within the window, or by half of it while growing at least four times as fast as in the
/// window before.
///
/// The defaults, 1000 in 30 minutes, do not pause the run of 2026-11-09 at 15:57, where
/// reallocated plus pending went 9505, 9697, 9817 between 15:29 and 15:57: 312 in 28
/// minutes, under half the limit; nor at 16:11, 248 in the 5 minutes after it carried on;
/// nor at 16:40, 16 more reallocated sectors after a quiet stretch. A drive in real collapse
/// still trips it within minutes: once most reads fail, each failed read finds new pending
/// sectors, and at one a second, faster than a drive with no read limit fails them, that is
/// well over 1000 in 30 minutes; half of it, 500, at four times the window before's growth
/// catches one that turns bad in the middle of the run sooner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WearRate {
    pub on: bool,
    /// Growth within the window that pauses the run.
    pub limit: u64,
    /// The window, in minutes.
    pub minutes: u64,
}

impl Default for WearRate {
    fn default() -> Self {
        Self {
            on: true,
            limit: 1000,
            minutes: 30,
        }
    }
}

impl WearRate {
    pub fn off() -> Self {
        Self {
            on: false,
            ..Self::default()
        }
    }

    fn window(&self) -> Duration {
        Duration::from_secs(self.minutes.max(1) * 60)
    }

    /// Readings older than this are no longer needed.
    pub fn keep(&self) -> Duration {
        self.window() * 3
    }

    /// Why to pause, from the readings so far (when, and the count), oldest first, the last
    /// being the one just taken; `what` names the count.
    pub fn judge(&self, history: &[(Instant, u128)], what: &str) -> Option<String> {
        self.judged(history, what).map(|(why, _)| why)
    }

    /// `judge`, with the values that paused the run, for its event.
    pub fn judged(
        &self,
        history: &[(Instant, u128)],
        what: &str,
    ) -> Option<(String, serde_json::Value)> {
        if !self.on {
            return None;
        }
        let &(now_at, now) = history.last()?;
        let window = self.window();
        let first_within = |span: Duration| {
            history
                .iter()
                .find(|(at, _)| now_at.duration_since(*at) <= span)
                .copied()
        };
        let (base_at, base) = first_within(window)?;
        let grew = now.saturating_sub(base);
        let minutes = now_at.duration_since(base_at).as_secs().div_ceil(60);
        let limit = u128::from(self.limit);
        let values = |rule: &str, before: Option<u128>| {
            serde_json::json!({
                "rule": rule,
                "counts": what,
                "from": base,
                "to": now,
                "grew": grew,
                "minutes": minutes,
                "limit": limit,
                "window_minutes": self.minutes,
                "window_before": before,
            })
        };
        if grew >= limit {
            return Some((
                format!(
                    "Paused: the drive's {what} rose by {grew}, from {base} to {now}, in the last {minutes} min, which reaches the error pause of {limit} in {} min.",
                    self.minutes
                ),
                values("limit", None),
            ));
        }
        // The window before is judged only once the readings reach back over it.
        let covered = history
            .first()
            .is_some_and(|(at, _)| now_at.duration_since(*at) >= window * 2);
        if covered {
            let (_, earlier) = first_within(window * 2)?;
            let before = base.saturating_sub(earlier);
            if grew * 2 >= limit && grew >= before.saturating_mul(4) {
                return Some((
                    format!(
                        "Paused: the drive's {what} rose by {grew}, from {base} to {now}, in the last {minutes} min, against {before} in the {} min before: at least four times as fast, and over half the error pause of {limit} in {} min.",
                        self.minutes, self.minutes
                    ),
                    values("faster", Some(before)),
                ));
            }
        }
        None
    }
}

/// The count the error pause follows, and its name: reallocated plus pending sectors, or an
/// NVMe drive's media errors; None for a reading with neither.
pub fn wear_count(disk: &Disk) -> Option<(u128, &'static str)> {
    match &disk.health {
        Health::Nvme(log) => Some((log.media_errors, "media errors")),
        Health::Ata(list) => {
            let raw = |id: u8| list.iter().find(|a| a.id == id).map(|a| a.raw_value());
            match (raw(5), raw(197)) {
                (None, None) => None,
                (a, b) => Some((
                    u128::from(a.unwrap_or(0)) + u128::from(b.unwrap_or(0)),
                    "reallocated plus pending sectors",
                )),
            }
        }
        Health::Unread(_) => None,
    }
}

/// Why to pause for the drive's temperature: it reached the drive's own critical limit.
pub fn too_hot(now: &Disk) -> Option<String> {
    let critical = now.temperature.as_ref().ok().and_then(|t| t.critical)?;
    let current = temperature(now)?;
    (current >= i32::from(critical)).then(|| {
        format!(
            "Paused: the drive is at {current} C, its critical limit of {critical} C; let it cool."
        )
    })
}

// ---- texts -----------------------------------------------------------------------------

/// "12.3 MB/s" in decimal megabytes, as drive speeds are quoted.
pub fn rate_text(bytes_per_second: f64) -> String {
    if bytes_per_second <= 0.0 {
        return "0 MB/s".into();
    }
    let mb = bytes_per_second / 1e6;
    if mb >= 100.0 {
        format!("{mb:.0} MB/s")
    } else if mb >= 1.0 {
        format!("{mb:.1} MB/s")
    } else {
        format!("{:.0} kB/s", bytes_per_second / 1e3)
    }
}

/// "about 1 h 20 min left", or None when there is no rate to judge by.
pub fn time_left_text(remaining: u64, bytes_per_second: f64) -> Option<String> {
    if remaining == 0 {
        return Some("nothing left to copy".into());
    }
    if bytes_per_second < 1.0 {
        return None;
    }
    Some(duration_left_text(
        (remaining as f64 / bytes_per_second).ceil() as u64,
    ))
}

/// "about 1 h 20 min left" for a number of seconds; days past two.
pub fn duration_left_text(seconds: u64) -> String {
    match seconds {
        0..=59 => "less than a minute left".into(),
        60..=3599 => format!("about {} min left", seconds.div_ceil(60)),
        3600..=172_799 => format!(
            "about {} h {} min left",
            seconds / 3600,
            (seconds % 3600) / 60
        ),
        _ => format!(
            "about {} days {} h left",
            seconds / 86_400,
            (seconds % 86_400) / 3600
        ),
    }
}

/// The bytes the map's phase still has to read: what is untried while copying, untrimmed
/// while trimming, unscraped while scraping, and in a retry pass the bad bytes it has not
/// reached yet (the first pass reads backwards from the end). A sector that ends bad leaves
/// these counts as surely as one that is read, so the time spent on bad sectors is work done.
pub fn phase_left(map: &Map) -> u64 {
    match map.phase {
        Phase::Copying => map.count(Status::Untried),
        Phase::Trimming => map.count(Status::NonTrimmed),
        Phase::Scraping => map.count(Status::NonScraped),
        Phase::Retrying => {
            let at = map.current_pos;
            map.blocks
                .iter()
                .filter(|b| b.status == Status::Bad)
                .map(|b| {
                    if map.pass == 1 {
                        b.end().min(at).saturating_sub(b.pos)
                    } else {
                        b.end().saturating_sub(b.pos.max(at))
                    }
                })
                .sum()
        }
        Phase::Finished => 0,
    }
}

/// The span the time-left rate is averaged over, in seconds of reading.
const ESTIMATE_SPAN: f64 = 600.0;
/// The reading time a phase needs before its time left is said.
const ESTIMATE_WARMUP: f64 = 60.0;
/// The longest time left said as a time; past it the text says only that it is longer.
const ESTIMATE_LONGEST: f64 = 365.0 * 86_400.0;

/// The time left in the phase, from the pace of its own work (`phase_left`) averaged over the
/// last ten minutes of reading: time waiting for the drive or for it to cool is left out of
/// the pace and moves the finish time on by as much, and the average starts over with each
/// phase and pass, as each reads at its own pace. The finish time it gives is held while the
/// newer one stays within a tenth of the time left, so the time left counts down instead of
/// jumping with each sector. A time left past a year is said only as that.
#[derive(Debug, Default)]
pub struct Estimate {
    phase: Option<(Phase, u32)>,
    last: Option<(Instant, u64)>,
    /// The decaying average of bytes per second, before the start-up correction.
    rate: f64,
    /// Seconds of reading seen in this phase.
    seen: f64,
    finish: Option<Instant>,
    /// The time left is past `ESTIMATE_LONGEST`.
    beyond: bool,
}

impl Estimate {
    /// Takes a reading of the phase and its bytes left; `reading` is false while the run waits.
    pub fn observe(&mut self, now: Instant, phase: (Phase, u32), left: u64, reading: bool) {
        if self.phase != Some(phase) {
            *self = Self {
                phase: Some(phase),
                last: Some((now, left)),
                ..Self::default()
            };
            return;
        }
        let Some((then, before)) = self.last.replace((now, left)) else {
            return;
        };
        let waited = now.saturating_duration_since(then);
        if !reading {
            // The phase's time left does not pass while nothing is read.
            if let Some(finish) = &mut self.finish {
                *finish += waited;
            }
            return;
        }
        let dt = waited.as_secs_f64();
        if dt <= 0.0 {
            return;
        }
        let done = before.saturating_sub(left) as f64;
        self.rate += (1.0 - (-dt / ESTIMATE_SPAN).exp()) * (done / dt - self.rate);
        self.seen += dt;
        let Some(rate) = self.pace() else {
            return;
        };
        let seconds = left as f64 / rate;
        self.beyond = seconds > ESTIMATE_LONGEST;
        if self.beyond {
            self.finish = None;
            return;
        }
        let projected = now + Duration::from_secs_f64(seconds);
        let keep = self.finish.is_some_and(|held| {
            let tolerance = projected
                .saturating_duration_since(now)
                .div_f64(10.0)
                .max(Duration::from_secs(60));
            held.max(projected) - held.min(projected) <= tolerance
        });
        if !keep {
            self.finish = Some(projected);
        }
    }

    /// The averaged pace in bytes per second, once the phase has run long enough to judge.
    fn pace(&self) -> Option<f64> {
        if self.seen < ESTIMATE_WARMUP {
            return None;
        }
        let rate = self.rate / (1.0 - (-self.seen / ESTIMATE_SPAN).exp());
        (rate > 0.0).then_some(rate)
    }

    /// "about 2 h 10 min left in this phase", or None while it is not known yet.
    pub fn text(&self, now: Instant) -> Option<String> {
        if self.last.is_some_and(|(_, left)| left == 0) {
            return Some("nothing left in this phase".into());
        }
        if self.beyond {
            return Some("more than a year left in this phase at this pace".into());
        }
        let left = self.finish?.saturating_duration_since(now).as_secs();
        Some(format!("{} in this phase", duration_left_text(left)))
    }
}

/// The progress line: "Rescued 1.2 GB · Bad 65.5 kB · Not tried 3.4 GB".
pub fn counts_text(rescued: u64, failed: u64, untried: u64) -> String {
    format!(
        "Rescued {}  ·  Bad {}  ·  Not tried {}",
        bytes_text(rescued),
        bytes_text(failed),
        bytes_text(untried)
    )
}

/// Rate over a sliding window of (time, rescued bytes) samples.
pub fn window_rate(samples: &[(Instant, u64)]) -> f64 {
    match (samples.first(), samples.last()) {
        (Some(first), Some(last)) if last.0 > first.0 => {
            last.1.saturating_sub(first.1) as f64 / (last.0 - first.0).as_secs_f64()
        }
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::MemDisk;
    use std::os::windows::fs::FileExt;
    use std::sync::Arc;

    /// The example mapfile in the GNU ddrescue manual, section "Mapfile structure".
    const MANUAL_EXAMPLE: &str = "\
# Mapfile. Created by GNU ddrescue version 1.30
# Command line: ddrescue -d -c18 /dev/fd0 fdimage mapfile
# Start time:   2015-07-21 09:37:44
# Current time: 2015-07-21 09:38:19
# Copying non-tried blocks... Pass 1 (forwards)
# current_pos  current_status  current_pass
0x00120000     ?               1
#      pos        size  status
0x00000000  0x00117000  +
0x00117000  0x00000200  -
0x00117200  0x00001000  /
0x00118200  0x00007E00  *
0x00120000  0x00048000  ?
";

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 / 512 + i) as u8).collect()
    }

    fn folder(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("diagtool-rescue-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn settings(len: u64) -> Settings {
        Settings {
            cluster: 4096,
            skip: 4096,
            max_skip: len / 8,
            ..Settings::for_len(len)
        }
    }

    /// A test disk that reports a disk number, for the destination rule.
    struct OnDisk(MemDisk, u32);

    impl BlockSource for OnDisk {
        fn len(&self) -> u64 {
            self.0.len()
        }
        fn sector_size(&self) -> u32 {
            self.0.sector_size()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            self.0.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.0.describe()
        }
        fn disk_number(&self) -> Option<u32> {
            Some(self.1)
        }
        fn identity(&self) -> Option<SourceId> {
            self.0.identity()
        }
    }

    /// A test disk that asks the run to stop after a number of reads.
    struct StopAfter {
        disk: MemDisk,
        stop: Arc<AtomicBool>,
        after: usize,
    }

    impl BlockSource for StopAfter {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            self.disk.sector_size()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            if self.disk.reads.len() + 1 >= self.after {
                self.stop.store(true, Ordering::Relaxed);
            }
            self.disk.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.disk.describe()
        }
        fn identity(&self) -> Option<SourceId> {
            self.disk.identity()
        }
    }

    fn rescue(
        source: &mut dyn BlockSource,
        folder: &Path,
        settings: &Settings,
        stop: &AtomicBool,
    ) -> (Outcome, Map) {
        let plan = plan_with(&*source, folder, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &*source).unwrap();
        let outcome = run.run(source, settings, stop, &Progress::default(), &mut || {
            Watch::Fine
        });
        (outcome, run.map.clone())
    }

    /// Runs a rescue of a 1 MiB disk that saves its map at every step, with the map held
    /// without sharing delete (as Python's open holds it) for `held`, from the start.
    fn rescue_with_map_held(name: &str, held: Duration, limit: Duration) -> (Outcome, Map, Map) {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = folder(name);
        let len = 1 << 20;
        let mut disk = MemDisk::new(vec![5u8; len]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.map_lag_limit = limit;
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(dir.join("image.map"))
            .unwrap();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(held);
            drop(holder);
        });
        let settings = Settings {
            cluster: 4096,
            save_every: Duration::ZERO,
            health_every: Duration::ZERO,
            ..Settings::for_len(len as u64)
        };
        let outcome = run.run(
            &mut disk,
            &settings,
            &AtomicBool::new(false),
            &Progress::default(),
            &mut || {
                std::thread::sleep(Duration::from_millis(3));
                Watch::Fine
            },
        );
        reader.join().unwrap();
        let ran = run.map.clone();
        drop(run);
        let saved = saved_map(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        (outcome, ran, saved)
    }

    /// The guard: timed saves refused because another program holds the map do not end
    /// the run; it carries on, saves once the map is let go, and ends with it whole.
    #[test]
    fn a_held_map_does_not_end_the_run() {
        let (outcome, ran, saved) = rescue_with_map_held(
            "map-held",
            Duration::from_millis(400),
            Duration::from_secs(60),
        );
        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(saved.count(Status::Rescued), 1 << 20);
        assert_eq!(saved.count(Status::Rescued), ran.count(Status::Rescued));
    }

    /// The guard: a drive that drops while another program holds the map ends the pass as
    /// gone at once, to wait for the drive; the drop's save does not wait on the map.
    #[test]
    fn a_drop_with_the_map_held_goes_on_to_wait() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = folder("drop-held");
        let len = 1 << 20;
        let mut disk = MemDisk::new(vec![5u8; len]);
        disk.stalls_after = Some(20);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(dir.join("image.map"))
            .unwrap();
        let started = Instant::now();
        let outcome = run.run(
            &mut disk,
            &Settings {
                cluster: 4096,
                ..Settings::for_len(len as u64)
            },
            &AtomicBool::new(false),
            &Progress::default(),
            &mut || Watch::Fine,
        );
        let took = started.elapsed();
        drop(holder);
        assert!(matches!(outcome, Outcome::Gone(_)), "{outcome:?}");
        assert!(
            took < Duration::from_secs(3),
            "the drop waited {took:?} on the map"
        );
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a map held past the limit ends the run with a write failure saying so, and
    /// the map saved last is left whole.
    #[test]
    fn a_map_held_past_the_limit_ends_the_run() {
        let (outcome, _, saved) = rescue_with_map_held(
            "map-held-long",
            Duration::from_secs(2),
            Duration::from_millis(100),
        );
        assert!(
            matches!(&outcome, Outcome::Failed(why) if why.contains("another program has held the map")),
            "{outcome:?}"
        );
        assert_eq!(saved.len(), 1 << 20);
    }

    fn saved_map(folder: &Path) -> Map {
        Map::parse(&std::fs::read_to_string(folder.join("image.map")).unwrap()).unwrap()
    }

    /// The image the source should give: its data, with zeros where it is bad.
    fn expected_image(disk: &MemDisk) -> Vec<u8> {
        let mut want = disk.data.clone();
        for range in disk.bad.iter().chain(&disk.slow) {
            want[range.start as usize..range.end as usize].fill(0);
        }
        want
    }

    /// The guard: a map with a block that runs past u64::MAX is refused, saying where, and
    /// a position past its blocks is taken back to their end, so no caller sees a wrapped end.
    #[test]
    fn a_map_block_running_past_the_top_of_the_address_space_is_refused() {
        let top = "\
0x00000000     ?               1
0x00000000  0xFFFFFFFFFFFFFFF0  +
0xFFFFFFFFFFFFFFF0  0x00000020  ?
";
        let why = Map::parse(top).unwrap_err();
        assert!(why.contains("line 3") && why.contains("past"), "{why}");
        let wraps = Map::parse("0x0 ? 1\n0x0 0xFFFFFFFFFFFFFFFF +\n0xFFFFFFFFFFFFFFFF 0x2 -\n");
        assert!(wraps.is_err());
        // Up to the last byte is representable.
        let edge = Map::parse("0x0 ? 1\n0x0 0xFFFFFFFFFFFFFFFF +\n").unwrap();
        assert_eq!(edge.len(), u64::MAX);
        let far = Map::parse("0xFFFFFFFFFFFFFFFF ? 1\n0x0 0x1000 +\n").unwrap();
        assert_eq!(far.current_pos, 0x1000);
    }

    #[test]
    fn the_manual_example_round_trips() {
        let map = Map::parse(MANUAL_EXAMPLE).unwrap();
        assert_eq!(map.current_pos, 0x120000);
        assert_eq!(map.phase, Phase::Copying);
        assert_eq!(map.pass, 1);
        assert_eq!(map.len(), 0x168000);
        assert_eq!(
            map.blocks
                .iter()
                .map(|b| b.status.symbol())
                .collect::<String>(),
            "+-/*?"
        );
        assert_eq!(map.count(Status::Bad), 0x200);
        let heading: Vec<String> = MANUAL_EXAMPLE
            .lines()
            .take(4)
            .map(|l| l.trim_start_matches("# ").to_string())
            .collect();
        let text = map.to_text(&heading);
        assert_eq!(
            text, MANUAL_EXAMPLE,
            "the written map differs from the manual's"
        );
        assert_eq!(Map::parse(&text).unwrap(), map);
    }

    #[test]
    fn maps_in_other_spellings_read_the_same() {
        // Decimal and octal numbers, a two-field status line, comments after fields, and
        // adjacent blocks of one status.
        let text = "0  +\n0 512 + # first\n01000 512 +\n1024 01000 -\n";
        let map = Map::parse(text).unwrap();
        assert_eq!(map.phase, Phase::Finished);
        assert_eq!(map.pass, 1);
        assert_eq!(
            map.blocks,
            vec![
                Block {
                    pos: 0,
                    size: 1024,
                    status: Status::Rescued
                },
                Block {
                    pos: 1024,
                    size: 512,
                    status: Status::Bad
                },
            ]
        );
        assert!(
            Map::parse("0 ?\n0 512 +\n1024 512 +\n").is_err(),
            "a gap was accepted"
        );
        assert!(Map::parse("0 x\n").is_err());
        assert!(Map::parse("# only comments\n").is_err());
        // A line not understood is quoted short, however long it is.
        let long = format!("0 ?\n{}\n", "x".repeat(8 << 20));
        let why = Map::parse(&long).unwrap_err();
        assert_eq!(
            why,
            format!(
                "line 2 of the map is not understood: {}... (8388608 characters)",
                "x".repeat(80)
            )
        );
        assert_eq!(
            Map::parse("0 x\n").unwrap_err(),
            "line 1 of the map is not understood: 0 x"
        );
    }

    #[test]
    fn marking_splits_and_merges_blocks() {
        let mut map = Map::new(10_240);
        map.set(1024, 1024, Status::Rescued);
        map.set(2048, 1024, Status::Rescued);
        map.set(0, 1024, Status::Rescued);
        assert_eq!(map.blocks.len(), 2);
        map.set(1536, 512, Status::Bad);
        assert_eq!(
            map.blocks
                .iter()
                .map(|b| (b.pos, b.status.symbol()))
                .collect::<Vec<_>>(),
            vec![(0, '+'), (1536, '-'), (2048, '+'), (3072, '?')]
        );
        assert_eq!(map.find(Status::Rescued, 1600).unwrap().pos, 2048);
        assert_eq!(map.find_back(Status::Untried, 10_240).unwrap().pos, 3072);
        assert_eq!(map.find_back(Status::Rescued, 1000).unwrap().size, 1000);
        assert_eq!(
            map.strip(10),
            vec![
                Cell::Rescued,
                Cell::Failed,
                Cell::Rescued,
                Cell::Untried,
                Cell::Untried,
                Cell::Untried,
                Cell::Untried,
                Cell::Untried,
                Cell::Untried,
                Cell::Untried
            ]
        );
    }

    #[test]
    fn a_healthy_disk_is_copied_in_one_pass() {
        let dir = folder("healthy");
        let disk_data = data(1 << 20);
        let mut disk = MemDisk::new(disk_data.clone());
        let (outcome, map) = rescue(&mut disk, &dir, &settings(1 << 20), &AtomicBool::new(false));
        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(map.count(Status::Rescued), 1 << 20);
        assert_eq!(
            disk.reads.len(),
            (1 << 20) / 4096,
            "a healthy area was read twice"
        );
        assert_eq!(std::fs::read(dir.join("image.img")).unwrap(), disk_data);
        assert_eq!(saved_map(&dir).phase, Phase::Finished);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every pass in turn: skipping, backwards, forwards, sweeping, trimming and scraping.
    #[test]
    fn every_pass_ends_with_only_the_bad_sectors_unread() {
        let dir = folder("passes");
        let len = 1 << 20;
        let mut disk = MemDisk::new(data(len));
        disk.bad.push(100_352..105_472); // a run of bad sectors inside one cluster and the next
        disk.bad.push(409_600..410_112); // one bad sector
        disk.slow.push(700_416..701_440); // two sectors that time out
        let (outcome, map) = rescue(
            &mut disk,
            &dir,
            &settings(len as u64),
            &AtomicBool::new(false),
        );
        assert_eq!(outcome, Outcome::Finished);
        let bad: Vec<(u64, u64)> = map
            .blocks
            .iter()
            .filter(|b| b.status == Status::Bad)
            .map(|b| (b.pos, b.end()))
            .collect();
        assert_eq!(
            bad,
            vec![(100_352, 105_472), (409_600, 410_112), (700_416, 701_440)]
        );
        assert_eq!(map.count(Status::Untried), 0);
        assert_eq!(map.count(Status::NonTrimmed), 0);
        assert_eq!(map.count(Status::NonScraped), 0);
        assert_eq!(
            std::fs::read(dir.join("image.img")).unwrap(),
            expected_image(&disk)
        );
        // Trimming and scraping read single sectors.
        assert!(disk.reads.iter().any(|(_, len)| *len == 512));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: no failed area is read again until every untried area has been read, and
    /// no good area is ever read twice.
    #[test]
    fn failed_areas_wait_until_untried_areas_are_done() {
        let dir = folder("order");
        let len = 2 << 20;
        let mut disk = MemDisk::new(data(len));
        disk.bad.push(200_704..400_000_u64.div_ceil(512) * 512);
        disk.bad.push(1_000_448..1_001_472);
        disk.slow.push(1_500_160..1_500_672);
        let (outcome, _) = rescue(
            &mut disk,
            &dir,
            &settings(len as u64),
            &AtomicBool::new(false),
        );
        assert_eq!(outcome, Outcome::Finished);
        let failing = |start: u64, end: u64| {
            disk.bad
                .iter()
                .chain(&disk.slow)
                .any(|r| r.start < end && start < r.end)
        };
        let mut read_before: Vec<(u64, u64)> = Vec::new();
        let mut first_reread = None;
        let mut last_fresh = 0;
        for (index, (pos, size)) in disk.reads.iter().enumerate() {
            let (start, end) = (*pos, *pos + *size as u64);
            let earlier: Vec<&(u64, u64)> = read_before
                .iter()
                .filter(|(s, e)| *s < end && start < *e)
                .collect();
            if earlier.is_empty() {
                last_fresh = index;
            } else {
                first_reread.get_or_insert(index);
                // Only what failed is read again; a byte read once is never read twice.
                assert!(
                    earlier.iter().all(|(s, e)| failing(*s, *e)),
                    "{start}..{end} was read again after a good read"
                );
            }
            read_before.push((start, end));
        }
        let first_reread = first_reread.expect("failed areas were never trimmed");
        assert!(
            first_reread > last_fresh,
            "read {first_reread} re-read a failed area before untried read {last_fresh}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_skip_doubles_after_each_error_and_resets_on_good_data() {
        let dir = folder("skip");
        let len: u64 = 4 << 20;
        let mut disk = MemDisk::new(data(len as usize));
        disk.bad.push(1 << 20..3 << 20);
        let mut set = settings(len);
        set.max_skip = 256 << 10;
        let (outcome, _) = rescue(&mut disk, &dir, &set, &AtomicBool::new(false));
        assert_eq!(outcome, Outcome::Finished);
        let reads = &disk.reads;
        // Pass 1 is the run of rising positions at the start.
        let mut pass1 = vec![reads[0].0];
        for (pos, _) in &reads[1..] {
            if *pos <= *pass1.last().unwrap() {
                break;
            }
            pass1.push(*pos);
        }
        let in_bad: Vec<u64> = pass1
            .iter()
            .copied()
            .filter(|pos| (1 << 20..3 << 20).contains(pos))
            .collect();
        let gaps: Vec<u64> = in_bad.windows(2).map(|w| w[1] - w[0] - 4096).collect();
        assert_eq!(&gaps[..4], &[4096, 8192, 16_384, 32_768]);
        assert!(gaps.iter().all(|g| *g <= 256 << 10));
        assert!(
            gaps.contains(&(256 << 10)),
            "the skip never reached its cap: {gaps:?}"
        );
        // After the bad area the reads go one cluster at a time again.
        let after: Vec<u64> = pass1
            .iter()
            .copied()
            .skip_while(|pos| *pos < 3 << 20)
            .take(3)
            .collect();
        assert_eq!(after[1] - after[0], 4096);
        assert_eq!(after[2] - after[1], 4096);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dying_drive_stops_the_run_with_the_map_saved() {
        let dir = folder("dying");
        let len = 1 << 20;
        let mut disk = MemDisk::new(data(len));
        disk.dies_after = Some(40);
        let (outcome, map) = rescue(
            &mut disk,
            &dir,
            &settings(len as u64),
            &AtomicBool::new(false),
        );
        assert!(matches!(outcome, Outcome::Gone(ref why) if why.contains("stopped answering")));
        assert_eq!(
            disk.reads.len(),
            41,
            "the run kept reading a drive that was gone"
        );
        assert_eq!(map.count(Status::Rescued), 40 * 4096);
        assert_eq!(saved_map(&dir), map);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: stopping saves the map with everything read up to the stop.
    #[test]
    fn stopping_saves_the_map() {
        let dir = folder("stop");
        let len = 1 << 20;
        let stop = Arc::new(AtomicBool::new(false));
        let mut source = StopAfter {
            disk: MemDisk::new(data(len)),
            stop: stop.clone(),
            after: 10,
        };
        let mut set = settings(len as u64);
        set.save_every = Duration::from_secs(3600);
        let (outcome, map) = rescue(&mut source, &dir, &set, &stop);
        assert_eq!(outcome, Outcome::Stopped);
        assert_eq!(map.count(Status::Rescued), 10 * 4096);
        let saved = saved_map(&dir);
        assert_eq!(saved, map, "the map on disk is not the map at the stop");
        let image = std::fs::read(dir.join("image.img")).unwrap();
        assert_eq!(&image[..10 * 4096], &source.disk.data[..10 * 4096]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_and_resume_give_the_same_image_and_map() {
        let len = 2 << 20;
        let mut whole = MemDisk::new(data(len));
        whole.bad.push(300_032..310_272);
        whole.bad.push(1_200_128..1_200_640);
        whole.slow.push(1_800_192..1_800_704);
        let set = Settings {
            retries: 2,
            ..settings(len as u64)
        };
        let straight = folder("straight");
        let (outcome, straight_map) = rescue(&mut whole, &straight, &set, &AtomicBool::new(false));
        assert_eq!(outcome, Outcome::Finished);

        let resumed = folder("resumed");
        let stops = [5, 80, 30, 7, 3, 2, 50];
        let mut runs = 0;
        loop {
            let stop = Arc::new(AtomicBool::new(false));
            let mut disk = MemDisk::new(whole.data.clone());
            disk.bad = whole.bad.clone();
            disk.slow = whole.slow.clone();
            let mut source = StopAfter {
                disk,
                stop: stop.clone(),
                after: stops.get(runs).copied().unwrap_or(usize::MAX),
            };
            let plan = plan_with(&source, &resumed, "image", u64::MAX / 2, "NTFS").unwrap();
            assert_eq!(plan.resumed, runs > 0);
            let mut run = Rescue::open(plan, &source).unwrap();
            let outcome = run.run(&mut source, &set, &stop, &Progress::default(), &mut || {
                Watch::Fine
            });
            runs += 1;
            if outcome == Outcome::Finished {
                break;
            }
            assert_eq!(outcome, Outcome::Stopped);
            assert!(runs < 50);
        }
        assert!(runs > 3, "the run never stopped");
        let mut resumed_map = saved_map(&resumed);
        resumed_map.current_pos = straight_map.current_pos;
        assert_eq!(resumed_map.blocks, straight_map.blocks);
        assert_eq!(
            std::fs::read(resumed.join("image.img")).unwrap(),
            std::fs::read(straight.join("image.img")).unwrap()
        );
        std::fs::remove_dir_all(&straight).unwrap();
        std::fs::remove_dir_all(&resumed).unwrap();
    }

    #[test]
    fn retries_read_each_bad_sector_once_per_pass_and_keep_what_comes_back() {
        let dir = folder("retry");
        let len = 256 << 10;
        let mut disk = MemDisk::new(data(len));
        disk.bad.push(65_536..66_560);
        let (_, map) = rescue(
            &mut disk,
            &dir,
            &settings(len as u64),
            &AtomicBool::new(false),
        );
        assert_eq!(map.count(Status::Bad), 1024);
        // The same disk heals: two retry passes over the finished map.
        let reads_before = disk.reads.len();
        disk.bad.clear();
        let set = Settings {
            retries: 2,
            ..settings(len as u64)
        };
        let (outcome, map) = rescue(&mut disk, &dir, &set, &AtomicBool::new(false));
        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(map.count(Status::Rescued), len as u64);
        assert_eq!(
            disk.reads.len() - reads_before,
            2,
            "each bad sector is read once"
        );
        assert_eq!(std::fs::read(dir.join("image.img")).unwrap(), disk.data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Replays a run's reads over `bad` and returns every read that touched a sector
    /// already read on its own and failed: a retry.
    fn retried_reads(reads: &[(u64, usize)], bad: &[std::ops::Range<u64>]) -> Vec<(u64, usize)> {
        let mut failed_alone = std::collections::BTreeSet::new();
        let mut retried = Vec::new();
        for &(pos, size) in reads {
            let end = pos + size as u64;
            if (pos..end).step_by(512).any(|s| failed_alone.contains(&s)) {
                retried.push((pos, size));
            }
            let failed = bad.iter().any(|b| b.start < end && pos < b.end);
            if failed && size == 512 {
                failed_alone.insert(pos);
            }
        }
        retried
    }

    /// The guard: with no retry passes chosen, a run reads no sector again that already
    /// failed on its own, whatever its copying, trimming and scraping meet: a failed area's
    /// untried edges and middle are read once, and an area of one sector that fails while
    /// copying is marked bad, not left for trimming to read again. The reverse pass, which
    /// does read bad sectors again, is the first retry pass and runs only when chosen.
    #[test]
    fn with_no_retries_chosen_no_failed_sector_is_read_again() {
        let len: u64 = (256 << 10) + 512;
        let bad = vec![
            65_536..66_560,                 // inside a cluster
            131_072..135_168,               // a whole cluster's first sectors
            200_192..200_704,               // one sector
            (256 << 10)..(256 << 10) + 512, // the last sector, an area of one sector
        ];
        for retries in [0, 1] {
            let dir = folder(&format!("noretry{retries}"));
            let mut disk = MemDisk::new(data(len as usize));
            disk.bad = bad.clone();
            let set = Settings {
                retries,
                ..settings(len)
            };
            let (outcome, map) = rescue(&mut disk, &dir, &set, &AtomicBool::new(false));
            assert_eq!(outcome, Outcome::Finished);
            let bad_bytes: u64 = bad.iter().map(|b| b.end - b.start).sum();
            assert_eq!(map.count(Status::Bad), bad_bytes, "retries {retries}");
            let retried = retried_reads(&disk.reads, &bad);
            if retries == 0 {
                assert!(
                    retried.is_empty(),
                    "read again with no retries chosen: {retried:?}"
                );
            } else {
                assert!(!retried.is_empty(), "the reverse pass chosen did not run");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The guard: an area that reads only from its far side, behind a bad sector that stops
    /// trimming from that side, is rescued by the reverse pass; each sector there is read
    /// at most once by it, and the map says it ran as ddrescue's backwards retry.
    #[test]
    fn the_reverse_pass_reads_damage_from_the_far_side() {
        let dir = folder("reverse");
        let len: u64 = 1 << 20;
        let mut disk = MemDisk::new(data(len as usize));
        let far = 266_240..294_912; // 56 sectors that read only backwards
        disk.far_side.push(far.clone());
        disk.bad.push(294_912..295_424); // the sector above them never reads
        let one_retry = Settings {
            retries: 1,
            ..settings(len)
        };
        let (outcome, map) = rescue(&mut disk, &dir, &one_retry, &AtomicBool::new(false));
        assert_eq!(outcome, Outcome::Finished);
        let bad: Vec<(u64, u64)> = map
            .blocks
            .iter()
            .filter(|b| b.status.failed())
            .map(|b| (b.pos, b.end()))
            .collect();
        assert_eq!(bad, vec![(294_912, 295_424)], "the far side was not read");
        let mut want = disk.data.clone();
        want[294_912..295_424].fill(0);
        assert_eq!(std::fs::read(dir.join("image.img")).unwrap(), want);
        // The reverse pass is the run of falling reads at the end, from the bad sector down.
        let mut tail: Vec<u64> = Vec::new();
        for (pos, size) in disk.reads.iter().rev() {
            if *size != 512 || tail.last().is_some_and(|last| pos <= last) {
                break;
            }
            tail.push(*pos);
        }
        assert_eq!(tail.last(), Some(&294_912), "{tail:?}");
        assert!(tail.iter().all(|pos| far.start <= *pos), "{tail:?}");
        let mut seen = tail.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), tail.len(), "a sector was read twice");
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        assert!(text.contains("# Finished"), "{text}");
        let mut during = Map::new(len);
        during.phase = Phase::Retrying;
        during.pass = 1;
        let text = during.to_text(&[]);
        assert!(text.contains("Retry 1 (backwards)"), "{text}");
        assert_eq!(Map::parse(&text).unwrap(), during);
        assert_eq!(
            Phase::Retrying.name(2),
            "Retry 2: reading bad sectors once more, forwards",
            "the second retry is named retry 2"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_health_change_pauses_between_passes() {
        let dir = folder("pause");
        let len = 1 << 20;
        let mut disk = MemDisk::new(data(len));
        disk.bad.push(4096..8192);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        let mut readings = 0;
        let mut watch = || {
            readings += 1;
            if readings == 1 {
                Watch::Pause("Paused: test.".into())
            } else {
                Watch::Fine
            }
        };
        let outcome = run.run(
            &mut disk,
            &settings(len as u64),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut watch,
        );
        assert_eq!(outcome, Outcome::Paused("Paused: test.".into()));
        assert_eq!(
            saved_map(&dir).pass,
            1,
            "paused after pass 1, before pass 2"
        );
        assert!(saved_map(&dir).count(Status::Untried) > 0);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/recovery")
                .join(name),
        )
        .unwrap()
    }

    fn photos_on(len: u64) -> Settings {
        Settings {
            photos_first: PhotosFirst::default(),
            ..settings(len)
        }
    }

    /// Where the file system puts one file, as (start, end) areas.
    fn areas_of(data: &[u8], wanted: &str) -> Vec<(u64, u64)> {
        let mut reader = Reader::new(Box::new(MemDisk::new(data.to_vec())));
        let stop = AtomicBool::new(false);
        let found = crate::recovery::fs::parts::find(
            &mut reader,
            crate::recovery::fs::parts::Search::Tables,
            &stop,
            &Default::default(),
        );
        let listing =
            crate::recovery::fs::scan(&mut reader, &found.volumes[0], &stop, &Default::default())
                .unwrap();
        let file = listing.files.iter().find(|f| f.name == wanted).unwrap();
        let crate::recovery::fs::Data::Runs(runs) = &file.data else {
            panic!("{wanted} is resident");
        };
        let mut areas = Vec::new();
        for run in runs {
            if let crate::recovery::fs::Place::At(at) = run.place {
                areas.push((at, at + run.len));
            }
        }
        areas
    }

    fn touches(read: &(u64, usize), areas: &[(u64, u64)]) -> bool {
        let (pos, len) = (read.0, read.0 + read.1 as u64);
        areas.iter().any(|(s, e)| *s < len && pos < *e)
    }

    /// The guard: with photos first, every read of a photo's or video's area comes before
    /// any read of another file's content, the image is whole, and the map is a plain
    /// ddrescue map that names photos first nowhere.
    #[test]
    fn photo_areas_are_read_before_other_areas() {
        for (image, photo, other) in [
            ("ntfs.img", "photo.jpg", "tone.wav"),
            ("fat32.img", "Holiday photo.jpg", "budget.xlsx"),
        ] {
            let dir = folder(&format!("order-{image}"));
            let data = fixture(image);
            let len = data.len() as u64;
            let photos = areas_of(&data, photo);
            let others = areas_of(&data, other);
            let mut disk = MemDisk::new(data);
            let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let mut run = Rescue::open(plan, &disk).unwrap();
            let progress = Progress::default();
            let outcome = run.run(
                &mut disk,
                &photos_on(len),
                &AtomicBool::new(false),
                &progress,
                &mut || Watch::Fine,
            );
            assert_eq!(outcome, Outcome::Finished);
            let status = progress.photos.lock().unwrap().clone().unwrap();
            assert_eq!(status.state, PhotosState::Done, "{status:?}");
            assert!(
                status.files >= 2 && status.rescued == status.area,
                "{status:?}"
            );
            assert!(
                status.text().starts_with("Photos first: "),
                "{}",
                status.text()
            );
            let last_photo = disk
                .reads
                .iter()
                .rposition(|r| touches(r, &photos))
                .unwrap();
            let first_other = disk.reads.iter().position(|r| touches(r, &others)).unwrap();
            assert!(
                last_photo < first_other,
                "{image}: {photo} read at {last_photo}, {other} first read at {first_other}"
            );
            assert_eq!(std::fs::read(dir.join("image.img")).unwrap(), disk.data);
            let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
            assert!(!text.contains("hoto"), "{text}");
            let map = Map::parse(&text).unwrap();
            assert_eq!(map.phase, Phase::Finished);
            assert_eq!(map.count(Status::Rescued), len);
            drop(run);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A bad sector inside a photo is marked as pass 1 marks one and the rest of the
    /// photos are still read first; a resumed run reads the records back from the image,
    /// not the drive.
    #[test]
    fn photos_first_skips_damage_and_resumes_from_the_image() {
        let dir = folder("photos-bad");
        let data = fixture("ntfs.img");
        let len = data.len() as u64;
        let photo = areas_of(&data, "photo.jpg");
        let bad = photo[0].0 + 4096..photo[0].0 + 4608;
        let mut disk = MemDisk::new(data);
        disk.bad.push(bad.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let mut first = StopAfter {
            disk,
            stop: stop.clone(),
            after: 60,
        };
        let plan = plan_with(&first, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &first).unwrap();
        let outcome = run.run(
            &mut first,
            &photos_on(len),
            &stop,
            &Progress::default(),
            &mut || Watch::Fine,
        );
        assert_eq!(outcome, Outcome::Stopped);
        let rescued_before = run.map.clone();
        drop(run);
        let mut disk = first.disk;
        let reads_before = disk.reads.len();
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        let outcome = run.run(
            &mut disk,
            &photos_on(len),
            &AtomicBool::new(false),
            &Progress::default(),
            &mut || Watch::Fine,
        );
        assert_eq!(outcome, Outcome::Finished);
        for (pos, size) in &disk.reads[reads_before..] {
            assert!(
                !rescued_before.all(*pos, *size as u64, Status::Rescued),
                "{pos} was rescued before the stop and read from the drive again"
            );
        }
        let bad_left: Vec<(u64, u64)> = run
            .map
            .blocks
            .iter()
            .filter(|b| b.status.failed())
            .map(|b| (b.pos, b.end()))
            .collect();
        assert_eq!(bad_left, vec![(bad.start, bad.end)]);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: photos first's record reads never touch a sector already bad, and a record
    /// read of one sector that fails marks it bad, so neither it nor a later trim reads it
    /// again.
    #[test]
    fn record_reads_through_the_rescue_never_read_a_bad_sector_again() {
        let dir = folder("tap-bad");
        let len: u64 = 1 << 20;
        let mut disk = MemDisk::new(data(len as usize));
        disk.bad.push(8192..8704);
        disk.bad.push(20_480..20_992);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.map.set(8192, 512, Status::Bad);
        let set = settings(len);
        let stop = AtomicBool::new(false);
        let progress = Progress::default();
        let (mut halt, mut late) = (None, false);
        {
            let mut tap = Tap {
                rescue: &mut run,
                source: &mut disk,
                settings: &set,
                stop: &stop,
                progress: &progress,
                deadline: Instant::now() + Duration::from_secs(600),
                halt: &mut halt,
                late: &mut late,
            };
            let mut buf = vec![0u8; 4096];
            assert!(tap.read_at(8192 - 1024, &mut buf).is_err());
            let mut one = vec![0u8; 512];
            assert!(tap.read_at(20_480, &mut one).is_err());
            assert!(tap.read_at(0, &mut buf).is_ok());
        }
        assert_eq!(
            disk.reads,
            vec![(20_480, 512), (0, 4096)],
            "a bad sector was read again"
        );
        assert!(
            run.map.all(20_480, 512, Status::Bad),
            "a failed sector is not marked bad"
        );
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// No file system, or records past their time limit: the usual order, said so.
    #[test]
    fn photos_first_falls_back_to_the_usual_order() {
        let dir = folder("photos-none");
        let len = 1 << 20;
        let mut disk = MemDisk::new(data(len));
        let (outcome, map) = {
            let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let mut run = Rescue::open(plan, &disk).unwrap();
            let progress = Progress::default();
            let outcome = run.run(
                &mut disk,
                &photos_on(len as u64),
                &AtomicBool::new(false),
                &progress,
                &mut || Watch::Fine,
            );
            let status = progress.photos.lock().unwrap().clone().unwrap();
            assert!(
                matches!(&status.state, PhotosState::FellBack(why) if why.contains("no file system")),
                "{status:?}"
            );
            assert!(status.text().contains("usual order"), "{}", status.text());
            (outcome, run.map.clone())
        };
        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(map.count(Status::Rescued), len as u64);
        std::fs::remove_dir_all(&dir).unwrap();
        let dir = folder("photos-late");
        let data = fixture("ntfs.img");
        let len = data.len() as u64;
        let mut disk = MemDisk::new(data);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        let progress = Progress::default();
        let late = Settings {
            photos_first: PhotosFirst {
                enabled: true,
                records_limit_secs: 0,
            },
            ..settings(len)
        };
        let outcome = run.run(
            &mut disk,
            &late,
            &AtomicBool::new(false),
            &progress,
            &mut || Watch::Fine,
        );
        assert_eq!(outcome, Outcome::Finished);
        let status = progress.photos.lock().unwrap().clone().unwrap();
        assert!(
            matches!(&status.state, PhotosState::FellBack(why) if why.contains("took longer")),
            "{status:?}"
        );
        assert_eq!(std::fs::read(dir.join("image.img")).unwrap(), disk.data);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a new phase sets aside only the damaged areas around the hangs, not what
    /// copying set aside ahead of them, so the phase reads the rest in its outside stage.
    #[test]
    fn a_new_phase_sets_aside_only_the_damaged_areas() {
        let dir = folder("phase-fit");
        let mib = 1u64 << 20;
        let len = 64 * mib;
        let mut disk = MemDisk::new(vec![3u8; len as usize]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.map.set(0, len, Status::Rescued);
        run.map.set(8 * mib, 64 << 10, Status::NonTrimmed);
        run.map.set(40 * mib, 4096, Status::NonTrimmed);
        run.zones.start_phase(Phase::Copying);
        run.zones
            .hang(8 * mib, 4096, false, len, 512, 48 * mib, None);
        run.map.phase = Phase::Trimming;
        run.map.pass = 1;
        run.map.current_pos = 0;
        let settings = Settings {
            retries: 0,
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        let outcome = run.run(
            &mut disk,
            &settings,
            &AtomicBool::new(false),
            &Progress::default(),
            &mut || Watch::Fine,
        );
        assert_eq!(outcome, Outcome::Finished);
        let zones: Vec<(u64, u64)> = run.zones.list().iter().map(|z| (z.from, z.to)).collect();
        assert_eq!(zones, [(8 * mib, 8 * mib + 4096)]);
        assert_eq!(run.map.count(Status::Rescued), len);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: zones rebuilt from the event log after copying are the damaged areas the
    /// map shows around each logged hang, not the spans the pauses set aside, which were
    /// doubled guesses; in copying the span set aside, still untried, is kept too.
    #[test]
    fn the_rebuilt_zones_are_the_damaged_areas_around_the_logged_hangs() {
        let dir = folder("rebuild-areas");
        std::fs::create_dir_all(&dir).unwrap();
        let mib = 1u64 << 20;
        let mut map = Map::new(1024 * mib);
        map.set(0, 1024 * mib, Status::Rescued);
        map.set(100 * mib, 5 * mib, Status::Bad);
        map.set(110 * mib, mib, Status::NonScraped);
        map.set(300 * mib, 2 * mib, Status::NonScraped);
        map.phase = Phase::Scraping;
        let log = [
            format!(
                r#"{{"event":"paused","kind":"drive-gone","values":{{"skipped_from":{},"skipped_to":{},"hang_from":{},"hang_to":{}}}}}"#,
                100 * mib,
                900 * mib,
                100 * mib,
                100 * mib + 4096
            ),
            format!(r#"{{"event":"drive_gone","position":{}}}"#, 301 * mib),
            format!(
                r#"{{"event":"paused","kind":"drive-gone","values":{{"skipped_from":{},"skipped_to":{}}}}}"#,
                301 * mib,
                301 * mib + (1 << 30)
            ),
        ];
        let path = dir.join("image.events.jsonl");
        std::fs::write(&path, log.join("\n")).unwrap();
        let zones = zones_from_log(&path, &map, 512);
        let got: Vec<(u64, u64)> = zones.list().iter().map(|z| (z.from, z.to)).collect();
        assert_eq!(got, [(100 * mib, 111 * mib), (300 * mib, 302 * mib)]);
        map.phase = Phase::Copying;
        let zones = zones_from_log(&path, &map, 512);
        let got: Vec<(u64, u64)> = zones.list().iter().map(|z| (z.from, z.to)).collect();
        assert_eq!(got, [(100 * mib, 1024 * mib)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The zones a real rescue resumes with, from its map and event log:
    /// `RESCUE_STEM="D:/DriveRescue/.../Disk 4 ..." cargo test --lib -- --ignored
    /// the_zones_of_a_real_rescue --nocapture`.
    #[test]
    #[ignore = "reads a rescue's files named by RESCUE_STEM"]
    fn the_zones_of_a_real_rescue() {
        let stem = std::env::var("RESCUE_STEM").expect("RESCUE_STEM");
        let map = Map::parse(&std::fs::read_to_string(format!("{stem}.map")).unwrap()).unwrap();
        let mut zones = zones_from_log(Path::new(&format!("{stem}.events.jsonl")), &map, 512);
        zones.start_phase(map.phase);
        zones.fit(|at, end| map.area(at, end, AREA_BRIDGE, failed));
        let gb = |b: u64| b as f64 / 1e9;
        for z in zones.list() {
            let unread: u64 = map
                .blocks
                .iter()
                .filter(|b| failed(b.status) && b.pos < z.to && z.from < b.end())
                .map(|b| b.end().min(z.to) - b.pos.max(z.from))
                .sum();
            println!(
                "zone {:.3} GB + {:.1} MB, {} hangs, {:.1} MB failed",
                gb(z.from),
                (z.to - z.from) as f64 / 1e6,
                z.hangs.len(),
                unread as f64 / 1e6
            );
        }
        println!("{} zones, phase {:?}", zones.list().len(), map.phase);
    }

    /// The guard (round 10): a drop during photos first ends photos first and leaves
    /// copying's place where it was, though photos first has returned and cleared its flag
    /// by the time the pause takes the drop; the flag goes with the dropped read.
    #[test]
    fn a_photos_first_drop_is_taken_as_photos_first_s_after_it_returns() {
        let dir = folder("photos-latch");
        let len = 4u64 << 20;
        let mut source = Hangs {
            disk: MemDisk::new(vec![1u8; len as usize]),
            hang: std::iter::once((2 << 20)..(2 << 20) + 4096).collect(),
        };
        let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &source.disk).unwrap();
        run.map.current_pos = 0;
        run.in_photos = true;
        assert!(run.read(&mut source, 2 << 20, 4096).is_err());
        run.in_photos = false;
        assert!(run.skip_drop(512, DROP_SKIP).is_some());
        assert!(run.photos_ended, "photos first goes on after its drop");
        assert_eq!(run.map.current_pos, 0, "copying moved past a photo's place");
        // An ordinary copying drop afterwards is not taken as photos first's.
        run.photos_ended = false;
        assert!(run.read(&mut source, 2 << 20, 4096).is_err());
        assert!(run.skip_drop(512, DROP_SKIP).is_some());
        assert!(!run.photos_ended);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (round 10): a zone is open to its zone stage until its second hang in the
    /// phase, which the pause then says.
    #[test]
    fn a_zone_closes_for_the_phase_at_its_second_hang() {
        let dir = folder("zone-open");
        let disk = MemDisk::new(vec![1u8; 4 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.zones.start_phase(Phase::Copying);
        assert!(!run.zone_open(1 << 20));
        run.dropped = Some((1 << 20, 4096));
        run.skip_drop(512, 64 << 10);
        assert!(run.zone_open(1 << 20));
        run.dropped = Some(((1 << 20) + 8192, 512));
        run.skip_drop(512, 64 << 10);
        assert!(!run.zone_open(1 << 20));
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (round 9's gap): a log written before pauses said whether they made a zone
    /// is read by its runs and phases: a drop in Fill the gaps or a retry pass seeds none.
    #[test]
    fn an_older_log_seeds_zones_only_from_rescue_phases_that_make_them() {
        let dir = folder("legacy-log");
        std::fs::create_dir_all(&dir).unwrap();
        let mib = 1u64 << 20;
        let mut map = Map::new(1024 * mib);
        map.set(0, 1024 * mib, Status::Rescued);
        map.phase = Phase::Scraping;
        let pause = |at: u64| {
            format!(
                r#"{{"event":"paused","kind":"drive-gone","values":{{"skipped_from":{at},"skipped_to":{},"hang_from":{at},"hang_to":{}}}}}"#,
                at + mib,
                at + 512
            )
        };
        let log = [
            r#"{"event":"started","run":"rescue image"}"#.to_string(),
            r#"{"event":"phase","phase":"scraping","pass":1}"#.to_string(),
            pause(100 * mib),
            r#"{"event":"phase","phase":"retrying","pass":1}"#.to_string(),
            pause(200 * mib),
            r#"{"event":"started","run":"fill the gaps"}"#.to_string(),
            r#"{"event":"phase","phase":"scraping","pass":1}"#.to_string(),
            pause(300 * mib),
            r#"{"event":"started","run":"rescue image"}"#.to_string(),
            r#"{"event":"phase","phase":"trimming","pass":1}"#.to_string(),
            pause(400 * mib),
        ];
        let path = dir.join("image.events.jsonl");
        std::fs::write(&path, log.join("\n")).unwrap();
        let zones = zones_from_log(&path, &map, 512);
        let got: Vec<u64> = zones.list().iter().map(|z| z.from).collect();
        assert_eq!(got, [100 * mib, 400 * mib]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a damaged area is the failed blocks around a place, joined across gaps of
    /// up to the bridge, both ways and in turn, whatever lies between; blocks farther apart
    /// are another area. A retry pass's or Fill the gaps' drop skip goes past it, not a
    /// doubled guess.
    #[test]
    fn a_damaged_area_is_the_failed_blocks_within_the_bridge() {
        let mib = 1u64 << 20;
        let mut map = Map::new(1024 * mib);
        map.set(0, 1024 * mib, Status::Rescued);
        map.set(100 * mib, 4096, Status::Bad);
        map.set(108 * mib, 512, Status::Bad);
        map.set(110 * mib, mib, Status::NonScraped);
        map.set(120 * mib, 512, Status::NonTrimmed);
        map.set(125 * mib, 2 * mib, Status::Untried);
        map.set(200 * mib, 512, Status::Bad);
        let bridge = 16 * mib;
        // From inside a block, from a read past its end, from a rescued place between.
        for at in [110 * mib + 4096, 100 * mib, 115 * mib] {
            assert_eq!(
                map.area(at, at + 512, bridge, failed),
                (100 * mib, 120 * mib + 512),
                "{at}"
            );
        }
        assert_eq!(
            map.area(200 * mib, 200 * mib + 512, bridge, failed),
            (200 * mib, 200 * mib + 512)
        );
        assert_eq!(
            map.area(500 * mib, 500 * mib + 512, bridge, failed),
            (500 * mib, 500 * mib + 512)
        );
        // A smaller bridge splits it; untried counts only where it is asked for.
        assert_eq!(
            map.area(100 * mib, 100 * mib + 512, mib, failed),
            (100 * mib, 100 * mib + 4096)
        );
        assert_eq!(
            map.area(120 * mib, 120 * mib + 512, bridge, |s| s != Status::Rescued),
            (100 * mib, 127 * mib)
        );
        // A retry pass's drop skips the area, forwards; Fill the gaps backwards; neither takes
        // untried bytes for damage, and a read in them skips the first skip ahead too.
        let dir = folder("area-skip");
        let disk = MemDisk::new(vec![1u8; 1024 * mib as usize]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.map = map;
        run.map.phase = Phase::Retrying;
        run.map.pass = 2;
        run.dropped = Some((100 * mib, 4096));
        assert_eq!(
            run.skip_drop(512, DROP_SKIP),
            Some((100 * mib, 120 * mib + 512))
        );
        assert_eq!(run.map.current_pos, 120 * mib + 512);
        run.dropped = Some((125 * mib, 4096));
        let skip = 1024 * mib / 20 / 512 * 512;
        assert_eq!(
            run.skip_drop(512, DROP_SKIP),
            Some((125 * mib, 125 * mib + skip))
        );
        // Fill the gaps while anything that never failed is left skips nothing: the sector it
        // hung on is bad, and the next sweep splits what is left around it.
        run.filling = Some(true);
        run.dropped = Some((120 * mib, 512));
        assert_eq!(
            run.skip_drop(512, DROP_SKIP),
            Some((120 * mib, 120 * mib + 512))
        );
        assert_eq!((run.fill_from, run.fill_edge), (None, None));
        let hung = run.map.find_where(|_| true, 120 * mib).unwrap();
        assert_eq!(
            (hung.pos, hung.size, hung.status),
            (120 * mib, 512, Status::Bad)
        );
        // With only bad sectors left, a backwards pass goes on before the damaged area.
        for status in [Status::Untried, Status::NonTrimmed, Status::NonScraped] {
            run.map.set_where(0, 1024 * mib, status, Status::Rescued);
        }
        run.filling = Some(true);
        run.dropped = Some((120 * mib, 512));
        let span = run.skip_drop(512, DROP_SKIP).unwrap();
        assert!(span.0 < 120 * mib && span.1 == 120 * mib + 512, "{span:?}");
        assert_eq!(run.fill_from, Some(span.0));
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the error pause judges how fast the counts grow over its window, not any
    /// rise. The run of 2026-11-09 is not paused at any of its readings up to 15:57; a drive
    /// in collapse is, and so is one that speeds up sharply against the window before.
    #[test]
    fn the_error_pause_judges_the_rate_not_a_single_rise() {
        let rule = WearRate::default();
        let t0 = Instant::now();
        let at = |minutes: u64| t0 + Duration::from_secs(minutes * 60);
        // Reallocated plus pending at 14:54, 15:29, 15:52 and 15:57.
        let run = [
            (at(0), 8977 + 488),
            (at(35), 9009 + 496),
            (at(58), 9201 + 496),
            (at(63), 9305 + 512),
        ];
        for end in 1..=run.len() {
            assert_eq!(
                rule.judge(&run[..end], "x"),
                None,
                "paused at reading {end}"
            );
        }
        // Resumed at 16:06:52 and read again at 16:11:53: 248 more in 5 min.
        let resumed = [(at(0), 9305 + 512), (at(5), 9537 + 528)];
        assert_eq!(rule.judge(&resumed, "x"), None);
        // Paused at 16:40:01 for 16 more reallocated sectors, pending unchanged, after a
        // quiet window: a rise from nothing is not taken as speeding up.
        let quiet = [
            (at(0), 9657 + 536),
            (at(30), 9657 + 536),
            (at(60), 9673 + 536),
        ];
        assert_eq!(rule.judge(&quiet, "x"), None);
        // Collapse: 50 more a minute.
        let collapse: Vec<(Instant, u128)> = (0..=20)
            .map(|m| (at(m), 10_000 + 50 * u128::from(m)))
            .collect();
        assert_eq!(rule.judge(&collapse[..20], "x"), None);
        let why = rule
            .judge(&collapse, "reallocated plus pending sectors")
            .unwrap();
        assert!(
            why.contains("reallocated plus pending sectors rose by 1000, from 10000 to 11000, in the last 20 min")
                && why.contains("1000 in 30 min"),
            "{why}"
        );
        // Speeding up: 100 in the window before, 500 in this one.
        let faster = [(at(0), 0), (at(30), 100), (at(60), 600)];
        let why = rule.judge(&faster, "media errors").unwrap();
        assert!(
            why.contains("rose by 500") && why.contains("against 100 in the 30 min before"),
            "{why}"
        );
        // Steady under the limit, and the rule off.
        assert_eq!(
            rule.judge(&[(at(0), 0), (at(30), 400), (at(60), 800)], "x"),
            None
        );
        assert_eq!(WearRate::off().judge(&collapse, "x"), None);
    }

    #[test]
    fn the_counts_and_the_critical_temperature_are_read() {
        use crate::tools::drives::health::fixtures;
        use crate::tools::drives::health::{parse_nvme_health, parse_smart_attributes};
        let ata = |raw: &[u8]| Health::Ata(parse_smart_attributes(raw).unwrap());
        let worse = fixtures::disk(ata(&fixtures::pending_smart()));
        let (count, what) = wear_count(&worse).unwrap();
        assert!(count >= 24, "{count}");
        assert_eq!(what, "reallocated plus pending sectors");
        let nvme = |log: Vec<u8>| Health::Nvme(parse_nvme_health(&log).unwrap());
        let a = fixtures::disk(nvme(fixtures::healthy_nvme()));
        assert_eq!(wear_count(&a).map(|(_, what)| what), Some("media errors"));
        assert_eq!(too_hot(&a), None);
        let mut hot = a.clone();
        if let Health::Nvme(log) = &mut hot.health {
            log.temperature_kelvin = 273 + 85;
        }
        let why = too_hot(&hot).unwrap();
        assert!(why.contains("critical limit of 85 C"), "{why}");
    }

    #[test]
    fn a_destination_without_room_is_refused_before_anything_is_read() {
        let dir = folder("space");
        let disk = MemDisk::new(data(1 << 20));
        let err = plan_with(&disk, &dir, "image", 1 << 20, "NTFS").unwrap_err();
        assert!(err.contains("needs up to 1.0 MB more"), "{err}");
        let err = plan_with(&disk, &dir, "image", u64::MAX / 2, "FAT32");
        assert!(err.is_ok(), "a small image fits on FAT32");
        assert_eq!(
            check_space(1, u64::MAX / 2, "FAT32", 5 << 30).unwrap_err(),
            "the destination is FAT32, which cannot hold a file over 4 GiB; the image needs 5.4 GB"
        );
        assert!(disk.reads.is_empty());
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "a file was made"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: an image on the disk being rescued is refused before anything is read.
    #[test]
    fn a_destination_on_the_source_disk_is_refused() {
        let dir = folder("samedisk");
        let disks = crate::tools::drives::device::disks_of_path(&dir).unwrap();
        let source = OnDisk(MemDisk::new(data(1 << 20)), disks[0]);
        let err = plan(&source, &dir, "image").unwrap_err();
        assert!(err.contains("the disk being recovered"), "{err}");
        assert!(source.0.reads.is_empty());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let elsewhere = OnDisk(MemDisk::new(data(1 << 20)), 9999);
        assert!(plan(&elsewhere, &dir, "image").is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the image is checked through its own handle when it is made, so a folder
    /// that leads to the source disk by then, after the plan checked it by name, gets nothing.
    #[test]
    fn a_folder_changed_after_planning_gets_no_image() {
        use crate::tools::drives::device::disks_of_path;
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"target\tmp");
        std::fs::create_dir_all(&base).unwrap();
        let planned = base.join(format!("diagtool-rescue-moved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&planned);
        std::fs::create_dir_all(&planned).unwrap();
        let source_side = folder("moved-target");
        let disk = disks_of_path(&source_side).unwrap()[0];
        assert!(
            !disks_of_path(&planned).unwrap().contains(&disk),
            "the temporary folder and the target folder share disk {disk}; this test needs two disks"
        );
        let source = OnDisk(MemDisk::new(data(1 << 20)), disk);
        let plan = plan(&source, &planned, "image").unwrap();
        // The folder now leads to the source disk, as a changed mount point would.
        std::fs::remove_dir(&planned).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&planned)
            .arg(&source_side)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let err = Rescue::open(plan, &source).err().unwrap();
        std::fs::remove_dir(&planned).unwrap();
        assert!(err.contains("the disk being recovered"), "{err}");
        assert_eq!(std::fs::read_dir(&source_side).unwrap().count(), 0);
        assert!(source.0.reads.is_empty());
        std::fs::remove_dir_all(&source_side).unwrap();
    }

    /// An image writer that takes at most `each` bytes per write and `budget` bytes in all,
    /// then takes nothing, as a full or failing destination does.
    struct Grudging {
        image: Arc<Mutex<Vec<u8>>>,
        each: usize,
        budget: usize,
    }

    impl Sink for Grudging {
        fn write_at(&mut self, data: &[u8], pos: u64) -> std::io::Result<usize> {
            let n = data.len().min(self.each).min(self.budget);
            let mut image = self.image.lock().unwrap();
            image[pos as usize..pos as usize + n].copy_from_slice(&data[..n]);
            self.budget -= n;
            Ok(n)
        }
        fn flush_data(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The guard: a block is marked rescued only when every byte of it reached the image;
    /// short writes are finished, and a write that takes nothing ends the run with the map
    /// saved.
    #[test]
    fn short_image_writes_are_finished_or_fail_never_marked_rescued() {
        let len = 256 << 10;
        for (budget, finished) in [(usize::MAX, true), (10_000, false)] {
            let dir = folder(&format!("short-{finished}"));
            let mut disk = MemDisk::new(data(len));
            let image = Arc::new(Mutex::new(vec![0u8; len]));
            let sink = Grudging {
                image: image.clone(),
                each: 1000,
                budget,
            };
            let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let guard = Guard::new(disk.disk_number());
            let folder = guard.base(&dir).unwrap();
            let mut run = Rescue::begin(plan, &disk, guard, folder, Box::new(sink)).unwrap();
            let outcome = run.run(
                &mut disk,
                &settings(len as u64),
                &AtomicBool::new(false),
                &Progress::default(),
                &mut || Watch::Fine,
            );
            let saved = saved_map(&dir);
            let image = image.lock().unwrap();
            for block in saved.blocks.iter().filter(|b| b.status == Status::Rescued) {
                let range = block.pos as usize..block.end() as usize;
                assert!(
                    image[range.clone()] == disk.data[range.clone()],
                    "{range:?} is marked rescued but the image does not hold it"
                );
            }
            if finished {
                assert_eq!(outcome, Outcome::Finished);
                assert_eq!(saved.count(Status::Rescued), len as u64);
            } else {
                assert!(
                    matches!(&outcome, Outcome::Failed(why) if why.contains("could not be written")),
                    "{outcome:?}"
                );
                assert_eq!(saved.count(Status::Rescued), 2 * 4096);
            }
            drop(run);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// An image writer that keeps which bytes were made durable, and checks before every
    /// write that the map on disk claims nothing beyond them, as power lost then would show.
    struct Durable {
        map_path: PathBuf,
        written: Vec<bool>,
        durable: Arc<Mutex<Vec<bool>>>,
    }

    /// The rescued blocks of the saved map that are not all durable in the image.
    fn claimed_beyond(map_path: &Path, durable: &[bool]) -> Vec<(u64, u64)> {
        let Ok(text) = std::fs::read_to_string(map_path) else {
            return Vec::new();
        };
        let map = Map::parse(&text).unwrap();
        map.blocks
            .iter()
            .filter(|b| b.status == Status::Rescued)
            .filter(|b| !durable[b.pos as usize..b.end() as usize].iter().all(|d| *d))
            .map(|b| (b.pos, b.end()))
            .collect()
    }

    impl Sink for Durable {
        fn write_at(&mut self, data: &[u8], pos: u64) -> std::io::Result<usize> {
            let beyond = claimed_beyond(&self.map_path, &self.durable.lock().unwrap());
            assert!(
                beyond.is_empty(),
                "the map was saved claiming unflushed blocks {beyond:?}"
            );
            self.written[pos as usize..pos as usize + data.len()].fill(true);
            Ok(data.len())
        }
        fn flush_data(&mut self) -> std::io::Result<()> {
            self.durable.lock().unwrap().copy_from_slice(&self.written);
            Ok(())
        }
    }

    /// The guard: the image is flushed before every map save, during the run, at its end and
    /// on Stop, so a power cut never leaves a map claiming data the image does not hold.
    #[test]
    fn the_image_is_flushed_before_every_map_save() {
        let len = 256 << 10;
        for stop_after in [None, Some(20)] {
            let dir = folder(&format!("durable-{}", stop_after.is_some()));
            let durable = Arc::new(Mutex::new(vec![false; len]));
            let sink = Durable {
                map_path: dir.join("image.map"),
                written: vec![false; len],
                durable: durable.clone(),
            };
            let stop = Arc::new(AtomicBool::new(false));
            let mut source = StopAfter {
                disk: MemDisk::new(data(len)),
                stop: stop.clone(),
                after: stop_after.unwrap_or(usize::MAX),
            };
            let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let folder = Guard::default().base(&dir).unwrap();
            let mut run =
                Rescue::begin(plan, &source, Guard::default(), folder, Box::new(sink)).unwrap();
            let mut settings = settings(len as u64);
            settings.save_every = Duration::ZERO;
            let outcome = run.run(
                &mut source,
                &settings,
                &stop,
                &Progress::default(),
                &mut || Watch::Fine,
            );
            let expected = if stop_after.is_some() {
                Outcome::Stopped
            } else {
                Outcome::Finished
            };
            assert_eq!(outcome, expected);
            let map_path = dir.join("image.map");
            assert!(saved_map(&dir).count(Status::Rescued) > 0);
            let beyond = claimed_beyond(&map_path, &durable.lock().unwrap());
            assert!(
                beyond.is_empty(),
                "the last map claims unflushed blocks {beyond:?}"
            );
            drop(run);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The guard: two drives of one model and size with blank serials are never matched by
    /// themselves; resuming needs the person's yes.
    #[test]
    fn drives_without_serial_numbers_are_matched_only_when_confirmed() {
        let dir = folder("blank-serial");
        let mut first = MemDisk::new(data(1 << 20));
        first.serial = String::new();
        stopped_rescue(&dir, first);
        let mut blank = MemDisk::new(data(1 << 20));
        blank.serial = "  ".into();
        assert!(plan_with(&blank, &dir, "image", u64::MAX / 2, "NTFS")
            .unwrap()
            .unconfirmed
            .is_some());
        let other = MemDisk {
            serial: String::new(),
            ..MemDisk::new(data(1 << 20))
        };
        let mut plan = plan_with(&other, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(
            plan.unconfirmed
                .as_ref()
                .is_some_and(|why| why.contains("Without a serial number")),
            "{:?}",
            plan.unconfirmed
        );
        let refused = Rescue::open(
            plan_with(&other, &dir, "image", u64::MAX / 2, "NTFS").unwrap(),
            &other,
        );
        assert!(
            refused.is_err(),
            "a drive with no serial was resumed unasked"
        );
        assert!(other.reads.is_empty());
        plan.confirm();
        assert!(Rescue::open(plan, &other).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Stops a rescue of `disk` in `dir` after a few reads, leaving an image and its map.
    fn stopped_rescue(dir: &Path, disk: MemDisk) -> MemDisk {
        let stop = Arc::new(AtomicBool::new(false));
        let mut source = StopAfter {
            disk,
            stop: stop.clone(),
            after: 20,
        };
        let (outcome, map) = rescue(&mut source, dir, &settings(1 << 20), &stop);
        assert_eq!(outcome, Outcome::Stopped);
        assert!(map.count(Status::Rescued) > 0);
        source.disk
    }

    /// The guard: an image shorter than what its map says was rescued, or not the drive's
    /// size, is refused before anything is read, and nothing is changed.
    #[test]
    fn a_resume_refuses_an_image_that_cannot_hold_its_map() {
        let dir = folder("cutshort");
        let disk = stopped_rescue(&dir, MemDisk::new(data(1 << 20)));
        let image = dir.join("image.img");
        let rescued = saved_map(&dir).count(Status::Rescued);
        // Cut short below the rescued data, as a copy that stopped part way leaves it.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap()
            .set_len(rescued / 2)
            .unwrap();
        let err = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(err.contains("was cut short or replaced"), "{err}");
        // Long enough for the rescued data, but not the drive's size.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap()
            .set_len(rescued + 4096)
            .unwrap();
        let err = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(err.contains("always the drive's size"), "{err}");
        assert_eq!(std::fs::metadata(&image).unwrap().len(), rescued + 4096);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The drive in its USB enclosure: the adapter's model and serial number, the drive's own
    /// identity behind it.
    fn in_enclosure(own_serial: &str) -> MemDisk {
        MemDisk {
            model: "ASMT 2115".into(),
            serial: "000000000000000000AB".into(),
            drive: Some(DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: own_serial.into(),
            }),
            ..MemDisk::new(data(1 << 20))
        }
    }

    /// The same drive on a SATA port: Windows reports the drive's own model and serial.
    fn on_sata(own_serial: &str) -> MemDisk {
        MemDisk {
            model: "ST2000LM007-1R8174".into(),
            serial: own_serial.into(),
            ..in_enclosure(own_serial)
        }
    }

    /// The guard: a map made through a USB adapter names the drive's own serial number, and
    /// resumes on the bare drive on a SATA port, found in the folder under the name the
    /// enclosure gave it; a drive with another serial number of its own is refused.
    #[test]
    fn a_map_made_over_usb_resumes_on_the_bare_drive() {
        let dir = folder("usb-to-sata");
        let usb = stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        for line in [
            "# Source model: ASMT 2115\n",
            "# Source serial: 000000000000000000AB\n",
            "# Source size: 1048576 bytes\n",
            "# Source sector size: 512 bytes\n",
            "# Source scope: disk\n",
            "# Source disk size: 1048576 bytes\n",
            "# Source drive model: ST2000LM007-1R8174\n",
            "# Source drive serial: WDZ1ABCD\n",
        ] {
            assert!(text.contains(line), "{line}");
        }
        assert!(Map::parse(&text).is_ok(), "still a ddrescue mapfile");
        assert_eq!(map_identity(&text), usb.identity());
        let rescued = saved_map(&dir).count(Status::Rescued);
        // The bare drive, under the name the image was given and under the one its own
        // description gives on SATA.
        let bare = on_sata("WDZ1ABCD");
        for stem in ["image", "Disk 2 ST2000LM007-1R8174 1 MB"] {
            let plan = plan_with(&bare, &dir, stem, u64::MAX / 2, "NTFS").unwrap();
            assert!(plan.resumed && plan.unconfirmed.is_none(), "{stem}");
            assert_eq!(plan.image, dir.join("image.img"));
            assert_eq!(plan.map.count(Status::Rescued), rescued);
        }
        // Another drive of the same model, its own serial number different, in either place.
        for other in [on_sata("WDZ9XYZ"), in_enclosure("WDZ9XYZ")] {
            let err = plan_with(&other, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
            assert!(
                err.contains("map of another drive")
                    && err.contains("WDZ1ABCD")
                    && err.contains("WDZ9XYZ"),
                "{err}"
            );
            // Not found under another name, so a new image starts there instead.
            let fresh = plan_with(&other, &dir, "Disk 2 other", u64::MAX / 2, "NTFS").unwrap();
            assert!(!fresh.resumed);
        }
        // Back in the enclosure, as before.
        let again = plan_with(
            &in_enclosure("WDZ1ABCD"),
            &dir,
            "image",
            u64::MAX / 2,
            "NTFS",
        );
        assert!(again.unwrap().unconfirmed.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the same drive reporting another sector size or size through the other
    /// connection is refused, saying so; size equality stays mandatory.
    #[test]
    fn a_moved_drive_reporting_another_size_is_refused() {
        let dir = folder("usb-size");
        stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        let mut sectors = on_sata("WDZ1ABCD");
        sectors.sector = 4096;
        let err = plan_with(&sectors, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(
            err.contains("512-byte sectors") && err.contains("4096-byte sectors"),
            "{err}"
        );
        let larger = MemDisk {
            data: data((1 << 20) + 4096),
            ..on_sata("WDZ1ABCD")
        };
        let err = plan_with(&larger, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(
            err.contains("1048576 bytes") && err.contains("1052672 bytes"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: when either side lacks the drive's own identity, the rules are as before:
    /// a map without the new lines resumes on the drive Windows names the same, and the
    /// moved drive is refused, since what Windows reports for it differs.
    #[test]
    fn without_the_drive_identity_on_both_the_old_rules_hold() {
        let dir = folder("usb-old");
        let usb = stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        let old = older(&text);
        std::fs::write(dir.join("image.map"), &old).unwrap();
        let named = map_identity(&old).unwrap();
        assert_eq!(
            (named.drive, named.sector, named.scope, named.disk_size),
            (None, None, None, None)
        );
        let plan = plan_with(&usb, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.resumed && plan.unconfirmed.is_none());
        let err = plan_with(&on_sata("WDZ1ABCD"), &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(err.contains("map of another drive"), "{err}");
        // A drive that gave no identity of its own against a map that has one.
        std::fs::write(dir.join("image.map"), &text).unwrap();
        let plain = MemDisk {
            drive: None,
            ..on_sata("WDZ1ABCD")
        };
        // Windows names it differently, which the same drive moved to a SATA port also does:
        // without its own serial it cannot be told either way, so the technician confirms.
        let plan = plan_with(&plain, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.unconfirmed.is_some(), "{plan:?}");
        let enclosed = MemDisk {
            drive: None,
            ..in_enclosure("WDZ1ABCD")
        };
        // The same adapter names it, but the drive's own serial in the map is not seen now:
        // the technician confirms, since another drive behind the adapter reports the same.
        let plan = plan_with(&enclosed, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(
            plan.unconfirmed
                .as_deref()
                .is_some_and(|why| why.contains("did not give its own serial number")),
            "{plan:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A map as versions before the drive's own identity, sector size, scope and drive size
    /// wrote it: `text` without those lines.
    fn older(text: &str) -> String {
        let new = [
            SOURCE_DRIVE_MODEL,
            SOURCE_DRIVE_SERIAL,
            SOURCE_SECTOR,
            SOURCE_SCOPE,
            SOURCE_DISK_SIZE,
        ];
        text.lines()
            .filter(|l| !new.iter().any(|key| l.starts_with(key)))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    /// The guard: a map that does not say which part of the drive it was made from needs the
    /// technician's yes on a volume, since two volumes of one size on one drive look alike to
    /// it; on a whole disk it resumes as it always did.
    #[test]
    fn a_map_without_a_scope_is_confirmed_on_a_volume() {
        let dir = folder("scope-less");
        let source = stopped_rescue(&dir, volume(in_enclosure("WDZ1ABCD"), 1 << 20));
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        let scopeless: String = text
            .lines()
            .filter(|l| !l.starts_with(SOURCE_SCOPE))
            .map(|l| format!("{l}\n"))
            .collect();
        for map in [scopeless, older(&text)] {
            std::fs::write(dir.join("image.map"), &map).unwrap();
            let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            assert!(
                plan.unconfirmed
                    .as_ref()
                    .is_some_and(|why| why.contains("which part of the drive")),
                "{:?}",
                plan.unconfirmed
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
        let dir = folder("scope-less-disk");
        let source = stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        std::fs::write(dir.join("image.map"), older(&text)).unwrap();
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.resumed && plan.unconfirmed.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two images of one drive in a folder are not chosen between: both are named.
    #[test]
    fn two_images_of_a_moved_drive_are_both_named() {
        let dir = folder("usb-two");
        stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        for ext in ["img", "map"] {
            std::fs::copy(
                dir.join(format!("image.{ext}")),
                dir.join(format!("copy.{ext}")),
            )
            .unwrap();
        }
        let err = plan_with(
            &on_sata("WDZ1ABCD"),
            &dir,
            "Disk 2 bare",
            u64::MAX / 2,
            "NTFS",
        )
        .unwrap_err();
        assert!(err.contains("copy.map, image.map"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same drive's volume at `offset`.
    fn volume(disk: MemDisk, offset: u64) -> MemDisk {
        MemDisk {
            scope: Scope::Volume { offset },
            ..disk
        }
    }

    /// The guard: two volumes of one size on one drive refuse each other's maps, by name
    /// and through the search for a moved drive, and each still resumes its own.
    #[test]
    fn two_volumes_of_one_drive_refuse_each_others_maps() {
        let dir = folder("usb-volumes");
        stopped_rescue(&dir, volume(in_enclosure("WDZ1ABCD"), 1 << 20));
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        assert!(text.contains("# Source scope: volume at byte 1048576\n"));
        let second = volume(on_sata("WDZ1ABCD"), 3 << 20);
        let err = plan_with(&second, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(
            err.contains("the volume at byte 1048576")
                && err.contains("the volume at byte 3145728"),
            "{err}"
        );
        let fresh = plan_with(&second, &dir, "Disk 2 other", u64::MAX / 2, "NTFS").unwrap();
        assert!(!fresh.resumed && fresh.image == dir.join("Disk 2 other.img"));
        let own = volume(on_sata("WDZ1ABCD"), 1 << 20);
        let plan = plan_with(&own, &dir, "Disk 2 bare", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.resumed && plan.image == dir.join("image.img"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a map of the whole disk and a map of a volume never stand for each other,
    /// whether or not the drive's own identity is known.
    #[test]
    fn a_disk_and_a_volume_never_match() {
        for (name, map_scope, read_scope) in [
            ("scope-disk", Scope::Disk, Scope::Volume { offset: 0 }),
            ("scope-volume", Scope::Volume { offset: 0 }, Scope::Disk),
        ] {
            let dir = folder(name);
            stopped_rescue(
                &dir,
                MemDisk {
                    scope: map_scope,
                    ..in_enclosure("WDZ1ABCD")
                },
            );
            for (drive, stem) in [(true, "image"), (true, "Disk 2 bare"), (false, "image")] {
                let reader = MemDisk {
                    scope: read_scope,
                    drive: drive.then(|| in_enclosure("WDZ1ABCD").drive.unwrap()),
                    ..on_sata("WDZ1ABCD")
                };
                match plan_with(&reader, &dir, stem, u64::MAX / 2, "NTFS") {
                    Err(err) => assert!(err.contains("part of the drive"), "{err}"),
                    Ok(plan) => assert!(!plan.resumed, "{name} {stem}"),
                }
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The guard: a search for a moved drive that cannot look at every map says so, naming
    /// the folder, and starts no image beside the one that may be there.
    #[test]
    fn a_search_that_cannot_tell_is_refused() {
        let bare = on_sata("WDZ1ABCD");
        let refused = |dir: &Path, why: &str| {
            let err = plan_with(&bare, dir, "Disk 2 bare", u64::MAX / 2, "NTFS").unwrap_err();
            assert!(
                err.contains(&dir.display().to_string())
                    && err.contains(why)
                    && err.contains("choose another folder"),
                "{err}"
            );
            assert!(!dir.join("Disk 2 bare.img").exists());
            assert!(!dir.join("Disk 2 bare.map").exists());
        };
        // More images with maps than are looked through.
        let dir = folder("usb-cap");
        for n in 0..=MOVED_MAPS {
            std::fs::write(dir.join(format!("{n}.img")), b"").unwrap();
            std::fs::write(dir.join(format!("{n}.map")), b"# Rescue map\n").unwrap();
        }
        refused(&dir, "more than the 256 looked through");
        std::fs::remove_dir_all(&dir).unwrap();
        // A map that cannot be read, is not text, or whose heading runs past what is read.
        let dir = folder("usb-unread");
        stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        std::fs::rename(dir.join("image.map"), dir.join("kept.map")).unwrap();
        std::fs::write(dir.join("other.img"), b"").unwrap();
        {
            use std::os::windows::fs::OpenOptionsExt;
            let _held = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(dir.join("other.map"))
                .unwrap();
            refused(&dir, "could not be read");
        }
        std::fs::write(dir.join("other.map"), b"# Source\xff\n0x0 + 1\n").unwrap();
        refused(&dir, "is not a rescue map");
        let long = "# padding\n".repeat(2000);
        std::fs::write(dir.join("other.map"), long).unwrap();
        refused(&dir, "runs past its first 16 KiB");
        // Once the folder can be told apart, the drive's image is found.
        std::fs::remove_file(dir.join("other.map")).unwrap();
        std::fs::rename(dir.join("kept.map"), dir.join("image.map")).unwrap();
        let plan = plan_with(&bare, &dir, "Disk 2 bare", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.resumed && plan.image == dir.join("image.img"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a map names the drive it was made from; another drive of the same model
    /// and size is refused with both named, and a map that names no drive is resumed only
    /// once confirmed.
    #[test]
    fn a_resume_reads_only_the_drive_the_map_was_made_from() {
        let dir = folder("identity");
        let mut first = MemDisk::new(data(1 << 20));
        first.serial = "CUSTOMER-A".into();
        let first = stopped_rescue(&dir, first);
        let text = std::fs::read_to_string(dir.join("image.map")).unwrap();
        assert_eq!(map_identity(&text), first.identity());
        assert!(
            Map::parse(&text).is_ok(),
            "the map is still a ddrescue mapfile"
        );
        let mut other = MemDisk::new(data(1 << 20));
        other.serial = "CUSTOMER-B".into();
        let err = plan_with(&other, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(
            err.contains("serial CUSTOMER-A") && err.contains("serial CUSTOMER-B"),
            "{err}"
        );
        let same = plan_with(&first, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(same.resumed && same.unconfirmed.is_none());
        // A map with no drive named, as GNU ddrescue writes it.
        let bare: String = text
            .lines()
            .filter(|l| !l.starts_with("# Source"))
            .map(|l| format!("{l}\n"))
            .collect();
        std::fs::write(dir.join("image.map"), bare).unwrap();
        let mut plan = plan_with(&other, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan
            .unconfirmed
            .as_ref()
            .is_some_and(|why| why.contains("does not name")));
        let refused = Rescue::open(
            plan_with(&other, &dir, "image", u64::MAX / 2, "NTFS").unwrap(),
            &other,
        );
        assert!(refused.is_err(), "an unconfirmed map was resumed");
        assert!(other.reads.is_empty());
        plan.confirm();
        assert!(Rescue::open(plan, &other).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lone_image_or_map_is_left_alone() {
        let dir = folder("lone");
        let disk = MemDisk::new(data(1 << 20));
        std::fs::write(dir.join("image.img"), b"someone's file").unwrap();
        let err = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap_err();
        assert!(err.contains("without its map"), "{err}");
        assert_eq!(
            std::fs::read(dir.join("image.img")).unwrap(),
            b"someone's file"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn image_names_come_from_the_drive() {
        assert_eq!(
            stem_for("Disk 4, Kingston DataTraveler 3.0, 28.9 GB"),
            "Disk 4 Kingston DataTraveler 3.0 28.9 GB"
        );
        assert_eq!(stem_for(r"D:\a:b*c?.."), "D a b c");
        assert_eq!(stem_for("  ,, "), "Rescue image");
    }

    /// The guard (the time left should take in the read time of bad sectors): sectors scraped to bad are work done; a run of slow
    /// reads or a pause for the drive does not throw the time left about; it counts down
    /// between readings; and a new phase starts its pace over.
    #[test]
    fn the_time_left_is_steady_and_counts_bad_sectors_as_work() {
        let mib = 1u64 << 20;
        let mut map = Map::new(1024 * mib);
        map.set(0, 1024 * mib, Status::Rescued);
        map.set(100 * mib, 300 * mib, Status::NonScraped);
        map.phase = Phase::Scraping;
        assert_eq!(phase_left(&map), 300 * mib);
        map.set(100 * mib, mib, Status::Bad);
        assert_eq!(phase_left(&map), 299 * mib, "a bad sector is work done");
        map.phase = Phase::Retrying;
        map.pass = 1;
        map.current_pos = 100 * mib + 4096;
        assert_eq!(phase_left(&map), 4096, "the first retry reads backwards");
        map.pass = 2;
        assert_eq!(phase_left(&map), mib - 4096);

        // 10 kB/s on average, read in bursts: 20 kB in one second, then nothing for one.
        let t0 = Instant::now();
        let phase = (Phase::Scraping, 1);
        let mut e = Estimate::default();
        let mut left = 100_000_000u64;
        e.observe(t0, phase, left, true);
        let mut shown = Vec::new();
        let mut before_pause = None;
        let mut paused = Duration::ZERO;
        for s in 1..=1200u64 {
            // The drive is gone for two minutes in the middle.
            let reading = !(600..720).contains(&s);
            if reading && s % 2 == 1 {
                left -= 20_000;
            }
            let now = t0 + Duration::from_secs(s);
            e.observe(now, phase, left, reading);
            if !reading {
                paused += Duration::from_secs(1);
            }
            if s == 599 {
                before_pause = e.text(now);
            }
            if s == 719 {
                // The time left stands still while nothing is read, and does not jump after.
                assert_eq!(e.text(now), before_pause, "a pause moved the time left");
            }
            if s < 60 {
                assert_eq!(
                    e.text(t0 + Duration::from_secs(s)),
                    None,
                    "said before a minute"
                );
            }
            if s >= 120 && s % 30 == 0 {
                // On the reading clock: the finish less the time spent waiting.
                shown.push(e.finish.unwrap() - paused);
            }
        }
        // 100 MB at 10 kB/s is 10,000 s from the start, about 8,800 s left at 1200 s, less the
        // two minutes not read.
        let at = t0 + Duration::from_secs(1200);
        let left_s = e.finish.unwrap().saturating_duration_since(at).as_secs();
        assert!((8_400..=9_600).contains(&left_s), "{left_s}");
        let moved = shown.windows(2).filter(|w| w[0] != w[1]).count();
        assert!(moved <= 2, "the finish time moved {moved} times");
        assert_eq!(
            e.text(at).unwrap(),
            format!("{} in this phase", duration_left_text(left_s))
        );
        // At a pace that would take past a year, it says only that.
        let slow = (Phase::Retrying, 2);
        let mut far = Estimate::default();
        far.observe(t0, slow, 1 << 40, true);
        far.observe(t0 + Duration::from_secs(120), slow, (1 << 40) - 1200, true);
        assert_eq!(
            far.text(t0 + Duration::from_secs(120)).unwrap(),
            "more than a year left in this phase at this pace"
        );
        assert_eq!(
            duration_left_text(3 * 86_400 + 7200),
            "about 3 days 2 h left"
        );
        // A new phase starts over.
        e.observe(at, (Phase::Retrying, 1), 4096, true);
        assert_eq!(e.text(at + Duration::from_secs(1)), None);
        e.observe(at + Duration::from_secs(1), (Phase::Retrying, 1), 0, true);
        assert_eq!(
            e.text(at + Duration::from_secs(1)).unwrap(),
            "nothing left in this phase"
        );
    }

    #[test]
    fn rates_and_time_left_read_plainly() {
        assert_eq!(rate_text(45_200_000.0), "45.2 MB/s");
        assert_eq!(rate_text(150_000_000.0), "150 MB/s");
        assert_eq!(rate_text(12_000.0), "12 kB/s");
        assert_eq!(time_left_text(0, 0.0).unwrap(), "nothing left to copy");
        assert_eq!(time_left_text(100, 0.0), None);
        assert_eq!(
            time_left_text(4_800_000_000, 1_000_000.0).unwrap(),
            "about 1 h 20 min left"
        );
        assert_eq!(
            time_left_text(90_000_000, 1_000_000.0).unwrap(),
            "about 2 min left"
        );
        assert_eq!(
            counts_text(1 << 30, 65_536, 0),
            "Rescued 1.1 GB  ·  Bad 65.5 kB  ·  Not tried 0 B"
        );
    }

    /// Images a real disk, read-only, with administrator rights: DIAGTOOL_LIVE_DISK names
    /// the disk and DIAGTOOL_LIVE_FOLDER a new folder on another disk; DIAGTOOL_LIVE_RETRIES
    /// sets the retry passes (default 1) and DIAGTOOL_LIVE_STOP_MS when the first run is
    /// stopped (default 10,000, less for a small disk). Stops, resumes to the end, compares
    /// samples of the image with the disk, then deletes it all.
    #[test]
    #[ignore = "reads a physical disk; needs administrator rights and two environment variables"]
    fn live_rescue_image_of_a_disk() {
        let number: u32 = std::env::var("DIAGTOOL_LIVE_DISK")
            .expect("DIAGTOOL_LIVE_DISK")
            .parse()
            .unwrap();
        assert!(number > 2, "disks 0 to 2 are too large to image here");
        assert!(![3, 4].contains(&number), "disk {number} is not to be read");
        let folder =
            PathBuf::from(std::env::var("DIAGTOOL_LIVE_FOLDER").expect("DIAGTOOL_LIVE_FOLDER"));
        assert!(!folder.exists(), "{} must be new", folder.display());
        std::fs::create_dir(&folder).unwrap();
        let mut source =
            super::super::open_source(&super::super::SourceChoice::Disk(number)).unwrap();
        let len = source.len();
        let retries = std::env::var("DIAGTOOL_LIVE_RETRIES").map_or(1, |r| r.parse().unwrap());
        let settings = Settings {
            retries,
            ..Settings::for_len(len)
        };
        eprintln!("retries: {retries}");
        let stem = stem_for(&source.describe());
        eprintln!(
            "source: {} ({len} bytes, sector {})",
            source.describe(),
            source.sector_size()
        );
        let started = Instant::now();
        let mut runs = Vec::new();
        loop {
            let stop = Arc::new(AtomicBool::new(false));
            if runs.is_empty() {
                let flag = stop.clone();
                let after =
                    std::env::var("DIAGTOOL_LIVE_STOP_MS").map_or(10_000, |ms| ms.parse().unwrap());
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(after));
                    flag.store(true, Ordering::Relaxed);
                });
            }
            let mut plan = plan(source.as_ref(), &folder, &stem).unwrap();
            let resumed = plan.resumed;
            // A drive with no serial number (a virtual disk) resumes on the technician's
            // word that it is the same drive, which this test gives.
            plan.confirm();
            let mut run = Rescue::open(plan, source.as_ref()).unwrap();
            let at = Instant::now();
            let outcome = run.run(
                source.as_mut(),
                &settings,
                &stop,
                &Progress::default(),
                &mut || Watch::Fine,
            );
            let rescued = run.map.count(Status::Rescued);
            eprintln!(
                "run {}: {outcome:?} resumed={resumed} after {:.1} s, rescued {rescued}, failed {}",
                runs.len() + 1,
                at.elapsed().as_secs_f64(),
                run.map.failed()
            );
            runs.push(outcome.clone());
            if outcome != Outcome::Stopped {
                break;
            }
        }
        let total = started.elapsed().as_secs_f64();
        assert_eq!(runs.first(), Some(&Outcome::Stopped));
        assert_eq!(runs.last(), Some(&Outcome::Finished));
        let map = Map::parse(&std::fs::read_to_string(folder.join(format!("{stem}.map"))).unwrap())
            .unwrap();
        eprintln!(
            "finished in {total:.1} s, {:.1} MB/s; rescued {} bytes, failed {}, blocks {}",
            len as f64 / total / 1e6,
            map.count(Status::Rescued),
            map.failed(),
            map.blocks.len()
        );
        // Samples of the image against fresh reads of the disk, start, end and between.
        let image = File::open(folder.join(format!("{stem}.img"))).unwrap();
        assert_eq!(image.metadata().unwrap().len(), len);
        let sector = u64::from(source.sector_size());
        let mut from_disk = vec![0u8; 65_536];
        let mut from_image = vec![0u8; 65_536];
        let last = (len - 65_536) / sector * sector;
        for k in 0..=64u64 {
            let pos = (last / 64 * k) / sector * sector;
            source.read_at(pos, &mut from_disk).unwrap();
            image.seek_read(&mut from_image, pos).unwrap();
            assert!(
                from_disk == from_image,
                "the image differs from the disk at {pos}"
            );
        }
        eprintln!("65 samples of 64 KiB match the disk");
        drop(image);
        std::fs::remove_dir_all(&folder).unwrap();
        assert!(!folder.exists());
    }

    /// A drive that hangs (drops off the bus) on any read touching `hang`, as a failing
    /// drive does, and reads everything else.
    struct Hangs {
        disk: MemDisk,
        hang: Vec<std::ops::Range<u64>>,
    }

    impl BlockSource for Hangs {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            self.disk.sector_size()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
            let end = offset + buf.len() as u64;
            if self.hang.iter().any(|h| h.start < end && offset < h.end) {
                self.disk.reads.push((offset, buf.len()));
                return Err(ReadError::Gone(1117));
            }
            self.disk.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.disk.describe()
        }
        fn identity(&self) -> Option<SourceId> {
            self.disk.identity()
        }
    }

    /// The guard, end to end: a run over a drive that hangs at two places, with failing
    /// sectors around them, changes no status that no read covered (trimming's middle between
    /// two failed edges aside), hangs at most twice per zone in each phase, and rescues
    /// everything away from the hang places. Before rc.7 each skip handed the bytes it never
    /// read to the next phase, which then started at the hang (2026-11-09 and 10).
    #[test]
    fn the_zones_change_nothing_unread_and_keep_to_their_budget() {
        let dir = folder("hang-zones");
        let len: u64 = 4 << 20;
        let mut data = vec![0u8; len as usize];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i / 4096) as u8;
        }
        let mib = 1u64 << 20;
        let hang = vec![mib..mib + 8192, mib + 300_000..mib + 300_512];
        let mut disk = MemDisk::new(data);
        disk.bad = vec![
            mib - 2048..mib,
            mib + 8192..mib + 10_240,
            mib + 299_008..mib + 300_000,
        ];
        let mut source = Hangs {
            disk,
            hang: hang.clone(),
        };
        let settings = Settings {
            cluster: 4096,
            retries: 0,
            drop_skip: 64 << 10,
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &source.disk).unwrap();
        let mut drops: Vec<(Phase, u64)> = Vec::new();
        loop {
            match run.run(
                &mut source,
                &settings,
                &AtomicBool::new(false),
                &Progress::default(),
                &mut || Watch::Fine,
            ) {
                Outcome::Gone(_) => {
                    drops.push((run.map.phase, run.dropped.unwrap().0));
                    assert!(drops.len() <= 12, "the drive dropped {drops:?}");
                    run.skip_drop(512, settings.drop_skip);
                }
                Outcome::Finished => break,
                other => panic!("{other:?}"),
            }
        }
        // What the zones left is said at the end.
        let ended = Ended {
            outcome: Outcome::Finished,
            map_saved: true,
            zones_left: run.zones_left(),
        };
        let said = end_text(&ended, Some(&run.map));
        assert_eq!(
            said.contains("Fill the gaps reads it"),
            ended.zones_left > 0,
            "{said}"
        );
        // At most two hangs per zone in each phase.
        for zone in run.zones.list() {
            for phase in [Phase::Copying, Phase::Trimming, Phase::Scraping] {
                let n = drops
                    .iter()
                    .filter(|(p, at)| *p == phase && zone.from <= *at && *at < zone.to)
                    .count();
                assert!(n <= 2, "{n} hangs in {zone:?} in {phase:?}: {drops:?}");
            }
        }
        // Every status but untried came from a read over its bytes; a non-scraped middle
        // lies between two failed edges.
        let covered = |pos: u64, end: u64| {
            let mut reads: Vec<(u64, u64)> = source
                .disk
                .reads
                .iter()
                .map(|&(o, l)| (o, o + l as u64))
                .filter(|&(o, e)| o < end && pos < e)
                .collect();
            reads.sort_unstable();
            let mut at = pos;
            for (o, e) in reads {
                if o > at {
                    return false;
                }
                at = at.max(e);
            }
            at >= end
        };
        let blocks = run.map.blocks.clone();
        for (i, b) in blocks.iter().enumerate() {
            match b.status {
                Status::Untried => {}
                Status::NonScraped => assert!(
                    i > 0
                        && blocks[i - 1].status == Status::Bad
                        && blocks.get(i + 1).is_some_and(|n| n.status == Status::Bad),
                    "{b:?} non-scraped without failed edges"
                ),
                _ => assert!(
                    covered(b.pos, b.end()),
                    "{b:?} changed with no read over it"
                ),
            }
        }
        // Everything away from the hang places was rescued.
        for b in blocks.iter().filter(|b| b.status != Status::Rescued) {
            assert!(
                hang.iter()
                    .any(|h| b.pos < h.end + 65_536 && h.start < b.end() + 65_536),
                "{b:?} was left unread away from the hang places"
            );
        }
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a Resume of the same map keeps the hang zones, so a drop next to the place
    /// the last run dropped sets aside twice as much; on 2026-11-09 a second drop 31 s after
    /// a Resume at the same place skipped 1 GiB again.
    #[test]
    fn a_resume_keeps_the_zones() {
        let dir = folder("drop-memory");
        let len: u64 = 64 << 20;
        let mut source = Hangs {
            disk: MemDisk::new(vec![1u8; len as usize]),
            hang: vec![(8 << 20)..(8 << 20) + 4096, (9 << 20)..(9 << 20) + 4096],
        };
        let settings = Settings {
            cluster: 4096,
            retries: 0,
            drop_skip: 1 << 20,
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        let stop = AtomicBool::new(false);
        let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &source.disk).unwrap();
        let first = run.run(
            &mut source,
            &settings,
            &stop,
            &Progress::default(),
            &mut || Watch::Fine,
        );
        assert!(matches!(first, Outcome::Gone(_)), "{first:?}");
        let (from, to) = run.skip_drop(512, settings.drop_skip).unwrap();
        assert_eq!(to - from, 1 << 20);
        run.save_during().unwrap();
        drop(run);
        // A new run on the same map, as Resume makes, drops again just past the skip.
        let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &source.disk).unwrap();
        let again = run.run(
            &mut source,
            &settings,
            &stop,
            &Progress::default(),
            &mut || Watch::Fine,
        );
        assert!(matches!(again, Outcome::Gone(_)), "{again:?}");
        let (from, to) = run.skip_drop(512, settings.drop_skip).unwrap();
        assert_eq!(
            to - from,
            2 << 20,
            "the skip did not double across the Resume"
        );
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a drive that gives no identity of its own at a run's start keeps the one
    /// the map holds for it, where the map names the same source by what Windows reports; on
    /// 2026-11-09 a run started without it rewrote the map's heading without the drive's own
    /// serial, so every later return could only be confirmed by hand.
    #[test]
    fn a_run_keeps_the_drive_s_own_identity_from_its_map() {
        let id = |serial: &str, own: Option<&str>| SourceId {
            model: "Seagate Expansion".into(),
            serial: serial.into(),
            size: 2_000_398_933_504,
            drive: own.map(|s| DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: s.into(),
            }),
            sector: Some(512),
            scope: Some(Scope::Disk),
            disk_size: None,
        };
        let own = |kept: Option<SourceId>| kept.and_then(|k| k.drive).map(|d| d.serial);
        assert_eq!(
            own(kept_identity(
                Some(id("NA88E0R0", None)),
                Some(id("NA88E0R0", Some("WCC1VNYJ")))
            )),
            Some("WCC1VNYJ".into())
        );
        // Another source by what Windows reports, or a blank serial: nothing is taken.
        assert_eq!(
            own(kept_identity(
                Some(id("OTHER", None)),
                Some(id("NA88E0R0", Some("WCC1VNYJ")))
            )),
            None
        );
        assert_eq!(
            own(kept_identity(
                Some(id("", None)),
                Some(id("", Some("WCC1VNYJ")))
            )),
            None
        );
        // The drive's own identity, when it gave one, is its own.
        assert_eq!(
            own(kept_identity(
                Some(id("NA88E0R0", Some("NEW"))),
                Some(id("NA88E0R0", Some("WCC1VNYJ")))
            )),
            Some("NEW".into())
        );
    }

    /// The guard for the whole class: wherever a map holds the drive's own serial, what
    /// Windows reports and the heading's optional lines never make a drive the same; only
    /// an equal own serial does, and a known change of shape is refused before anything is
    /// left to the technician. Round 6 found a map without a scope line resumed on a Windows
    /// match, and a changed sector size offered for confirmation.
    #[test]
    fn the_drive_s_own_serial_decides_wherever_the_map_holds_it() {
        let map = Path::new("image.map");
        let id = |windows: &str, own: Option<&str>, sector, scope, size| SourceId {
            model: "Seagate Expansion".into(),
            serial: windows.into(),
            size,
            drive: own.map(|s| DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: s.into(),
            }),
            sector,
            scope,
            disk_size: None,
        };
        let size = 2_000_398_933_504u64;
        for map_sector in [None, Some(512)] {
            for map_scope in [None, Some(Scope::Disk)] {
                let made = id("NA88E0R0", Some("WCC1VNYJ"), map_sector, map_scope, size);
                for windows in ["NA88E0R0", "OTHER", ""] {
                    for own in [None, Some("WCC1VNYJ"), Some("OTHERDRV"), Some("  ")] {
                        for sector in [None, Some(512), Some(4096)] {
                            for this_size in [size, size + 4096] {
                                let this = id(windows, own, sector, Some(Scope::Disk), this_size);
                                let got = match_drive(map, Some(&made), Some(&this));
                                let case = format!("map sector {map_sector:?} scope {map_scope:?}; drive windows {windows:?} own {own:?} sector {sector:?} size {this_size}: {got:?}");
                                let own = own.map(str::trim).filter(|s| !s.is_empty());
                                let shape_changed = this_size != size
                                    || matches!((map_sector, sector), (Some(a), Some(b)) if a != b);
                                if matches!(got, Match::Same) {
                                    assert_eq!(own, Some("WCC1VNYJ"), "{case}");
                                    assert!(map_sector.is_some() && map_sector == sector, "{case}");
                                }
                                if shape_changed || own.is_some_and(|o| o != "WCC1VNYJ") {
                                    assert!(matches!(got, Match::Other(_)), "{case}");
                                }
                                if own.is_none() && !shape_changed {
                                    assert!(matches!(got, Match::Unconfirmed(_)), "{case}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// The guard: a doubt the technician accepted stays accepted, however often the dialog's
    /// accept is passed on; a second `confirm` cleared it.
    #[test]
    fn a_confirmation_stays_confirmed() {
        let dir = folder("usb-confirm-twice");
        stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        let enclosed = MemDisk {
            drive: None,
            ..in_enclosure("WDZ1ABCD")
        };
        let mut plan = plan_with(&enclosed, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        plan.confirm();
        plan.confirm();
        assert!(plan.confirmed);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: what a run remembers goes with the map it saved; a drop whose map was never
    /// saved leaves the map on disk as it was, and a Resume of it starts from what was
    /// remembered with it, not from a skip that map never took.
    #[test]
    fn a_skip_not_saved_is_not_remembered() {
        let dir = folder("drop-memory-unsaved");
        let len: u64 = 64 << 20;
        let mut source = Hangs {
            disk: MemDisk::new(vec![1u8; len as usize]),
            hang: std::iter::once((8 << 20)..(8 << 20) + 4096).collect(),
        };
        let settings = Settings {
            cluster: 4096,
            retries: 0,
            drop_skip: 1 << 20,
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        let stop = AtomicBool::new(false);
        for _ in 0..2 {
            let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let mut run = Rescue::open(plan, &source.disk).unwrap();
            let gone = run.run(
                &mut source,
                &settings,
                &stop,
                &Progress::default(),
                &mut || Watch::Fine,
            );
            assert!(matches!(gone, Outcome::Gone(_)), "{gone:?}");
            let (from, to) = run.skip_drop(512, settings.drop_skip).unwrap();
            assert!(
                to - from < 2 << 20,
                "a skip the saved map never took: {}",
                to - from
            );
            // The run ends without saving the map after the drop.
            drop(run);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: what a run remembers holds only for the map it left at the path; another
    /// map and image put there, resumed, start with the first drop skip.
    #[test]
    fn a_map_put_in_another_s_place_starts_with_the_first_skip() {
        let dir = folder("drop-memory-swap");
        let other = folder("drop-memory-other");
        let len: u64 = 64 << 20;
        let mut source = Hangs {
            disk: MemDisk::new(vec![1u8; len as usize]),
            hang: vec![(8 << 20)..(8 << 20) + 4096, (9 << 20)..(9 << 20) + 4096],
        };
        let settings = Settings {
            cluster: 4096,
            retries: 0,
            drop_skip: 1 << 20,
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        let stop = AtomicBool::new(false);
        // A map and image of the same drive made elsewhere, never run.
        let plan = plan_with(&source.disk, &other, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &source.disk).unwrap();
        run.save_now().unwrap();
        drop(run);
        let skip_once = |source: &mut Hangs| {
            let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let resumed = plan.resumed;
            let mut run = Rescue::open(plan, &source.disk).unwrap();
            let gone = run.run(source, &settings, &stop, &Progress::default(), &mut || {
                Watch::Fine
            });
            assert!(matches!(gone, Outcome::Gone(_)), "{gone:?}");
            let (from, to) = run.skip_drop(512, settings.drop_skip).unwrap();
            run.save_during().unwrap();
            (resumed, to - from)
        };
        assert_eq!(skip_once(&mut source), (false, 1 << 20));
        let (resumed, doubled) = skip_once(&mut source);
        assert!(resumed && doubled >= 2 << 20, "{doubled}");
        for ext in ["img", "map"] {
            std::fs::copy(
                other.join(format!("image.{ext}")),
                dir.join(format!("image.{ext}")),
            )
            .unwrap();
        }
        assert_eq!(
            skip_once(&mut source),
            (true, 1 << 20),
            "the map put in its place took the old run's skip"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&other).unwrap();
    }

    /// The guard: the strip shows what most of each cell is, a mostly rescued cell with failed
    /// blocks as partly rescued, and failed areas still to be read apart from bad ones; it
    /// drew a 98 % rescued stretch all red when each cell took its worst byte.
    #[test]
    fn the_strip_shows_each_cell_s_majority() {
        let mut map = Map::new(4000);
        map.set(0, 1000, Status::Rescued);
        map.set(1000, 990, Status::Rescued);
        map.set(1990, 10, Status::NonTrimmed);
        map.set(2000, 1000, Status::NonScraped);
        map.set(3000, 1000, Status::Bad);
        assert_eq!(
            map.strip(4),
            vec![Cell::Rescued, Cell::Partly, Cell::ToRetry, Cell::Failed]
        );
    }

    /// The guard: each cell's rescued share moves with every block rescued in it, so the
    /// strip shows progress inside a cell whose color has not changed yet.
    #[test]
    fn the_strip_fills_as_blocks_are_rescued() {
        let mut map = Map::new(4000);
        map.set(0, 2000, Status::NonScraped);
        map.set(2000, 2000, Status::Rescued);
        assert_eq!(map.strip_rescued(2), vec![0.0, 1.0]);
        map.set(0, 500, Status::Rescued);
        assert_eq!(map.strip(2), vec![Cell::ToRetry, Cell::Rescued]);
        assert_eq!(map.strip_rescued(2), vec![0.25, 1.0]);
        map.set(500, 10, Status::Rescued);
        assert!(map.strip_rescued(2)[0] > 0.25);
        // A cell narrower than a byte takes the byte at its place.
        let mut tiny = Map::new(2);
        tiny.set(0, 1, Status::Rescued);
        assert_eq!(tiny.strip_rescued(4), vec![1.0, 1.0, 0.0, 0.0]);
    }

    /// The guard: a strip wider than its map shows each cell the byte at its place, and a
    /// block ending on a cell's edge counts only in its own cell; cells narrower than a byte
    /// were painted as still to be read whatever the map held there.
    #[test]
    fn the_strip_of_a_map_smaller_than_it_shows_each_byte() {
        let mut map = Map::new(3);
        map.set(0, 1, Status::Rescued);
        map.set(1, 1, Status::Bad);
        assert_eq!(
            map.strip(6),
            vec![
                Cell::Rescued,
                Cell::Rescued,
                Cell::Failed,
                Cell::Failed,
                Cell::Untried,
                Cell::Untried
            ]
        );
        let mut map = Map::new(10);
        map.set(0, 5, Status::Rescued);
        map.set(5, 5, Status::Bad);
        assert_eq!(map.strip(2), vec![Cell::Rescued, Cell::Failed]);
        assert_eq!(map.strip(1), vec![Cell::Failed]);
    }

    fn status_at(map: &Map, pos: u64) -> Status {
        map.blocks
            .iter()
            .find(|b| b.pos <= pos && pos < b.end())
            .map(|b| b.status)
            .unwrap()
    }

    /// The guard for the whole class: in every phase and pass that sets hang zones, with photos
    /// first or not, whatever its length, outside a zone or inside one, a drop changes no
    /// status but the read it interrupted (a failed read of its length), the place joins the
    /// zones, nothing in a zone is offered before the phase's work outside, and a zone is read
    /// from its far side within its budget. Every fix before rc.7 changed the status of bytes
    /// the skip never read, so the next phase started at the hang.
    #[test]
    fn a_drop_changes_no_status_but_the_read_it_interrupted() {
        let dir = folder("drop-matrix");
        let len: u64 = 4 << 20;
        let disk = MemDisk::new(vec![1u8; len as usize]);
        let block = (1u64 << 20, 2u64 << 20);
        let pos = block.0 + 8192;
        let cases = [
            (Phase::Copying, 1),
            (Phase::Copying, 2),
            (Phase::Copying, 3),
            (Phase::Copying, 4),
            (Phase::Trimming, 1),
            (Phase::Scraping, 1),
        ];
        for (phase, pass) in cases {
            for photos in [false, true] {
                if photos && (phase, pass) != (Phase::Copying, 1) {
                    continue;
                }
                for in_zone in [false, true] {
                    for read in [512u64, 4096, 65536] {
                        let case = format!(
                            "{phase:?} pass {pass} photos {photos} in a zone {in_zone} read {read}"
                        );
                        let _ = std::fs::remove_dir_all(&dir);
                        std::fs::create_dir_all(&dir).unwrap();
                        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
                        let mut run = Rescue::open(plan, &disk).unwrap();
                        let reads = match phase {
                            Phase::Copying => Status::Untried,
                            Phase::Trimming => Status::NonTrimmed,
                            _ => Status::NonScraped,
                        };
                        run.map.set(0, 4096, Status::Rescued);
                        run.map.set(block.0, block.1 - block.0, reads);
                        run.map.set(3 << 20, 4096, Status::Bad);
                        run.map.phase = phase;
                        run.map.pass = pass;
                        run.map.current_pos = pos;
                        run.zones.start_phase(phase);
                        if in_zone {
                            run.zones
                                .hang(block.0, 512, false, len, 512, block.1 - block.0, None);
                        }
                        run.in_photos = photos;
                        let before = run.map.clone();
                        run.dropped = Some((pos, read));
                        let span = run
                            .skip_drop(512, 64 << 10)
                            .unwrap_or_else(|| panic!("{case}: no span"));
                        let mut want = before;
                        want.set_where(pos, read, reads, Status::after_failed_read(read, 512));
                        assert_eq!(
                            run.map.blocks, want.blocks,
                            "{case}: a status changed that no read covered"
                        );
                        assert!(span.0 <= pos && pos + read <= span.1, "{case}: {span:?}");
                        let zone = run
                            .zones
                            .first_overlap(pos, pos + read)
                            .unwrap_or_else(|| panic!("{case}: the place is in no zone"))
                            .clone();
                        assert!(
                            zone.hangs.iter().any(|&(h, e)| h <= pos && pos + read <= e),
                            "{case}: {zone:?}"
                        );
                        assert_eq!(zone.spent, if in_zone { 2 } else { 1 }, "{case}");
                        for next in [
                            run.find_outside(reads, 0),
                            run.find_back_outside(reads, len),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            assert!(
                                run.zones.first_overlap(next.pos, next.end()).is_none(),
                                "{case}: {next:?} offered inside a zone"
                            );
                        }
                        let piece = run.zone_piece(reads, 512);
                        if in_zone {
                            assert!(
                                piece.is_none(),
                                "{case}: a spent zone read again: {piece:?}"
                            );
                        } else if span != (pos, pos + read) {
                            let (piece, down) =
                                piece.unwrap_or_else(|| panic!("{case}: the zone is never read"));
                            // Read towards the hang from the far side of what the zone
                            // holds of the status read, on whichever side comes first.
                            let held: Vec<Block> = run
                                .map
                                .blocks
                                .iter()
                                .filter(|b| b.status == reads && b.pos < span.1 && span.0 < b.end())
                                .copied()
                                .collect();
                            let low = held[0].pos.max(span.0);
                            let high = held[held.len() - 1].end().min(span.1);
                            if down {
                                assert!(
                                    pos + read <= piece.pos && piece.end() == high,
                                    "{case}: {piece:?}"
                                );
                            } else {
                                assert!(
                                    piece.end() <= pos && piece.pos == low,
                                    "{case}: {piece:?}"
                                );
                            }
                        }
                        if phase == Phase::Copying && !in_zone && !photos {
                            let at = run.map.current_pos;
                            assert!(at <= span.0 || span.1 <= at, "{case}: goes on at {at}");
                        }
                        drop(run);
                    }
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a resume in a new app session takes its hang zones from the drops in the
    /// rescue's event log, with the hang where the pause names it or where the drop event
    /// stood; a new map does not, and a line it cannot read is passed over.
    #[test]
    fn a_resume_rebuilds_the_zones_from_the_event_log() {
        let dir = folder("zones-from-log");
        let disk = stopped_rescue(&dir, MemDisk::new(data(1 << 20)));
        let log = [
            r#"{"event":"drive_gone","position":200704}"#,
            r#"{"event":"paused","kind":"drive-gone","values":{"skipped_from":200704,"skipped_to":266240}}"#,
            "not json",
            r#"{"event":"drive_gone","position":700416}"#,
            r#"{"event":"paused","kind":"drive-gone","values":{"skipped_from":634880,"skipped_to":700416}}"#,
            r#"{"event":"paused","kind":"drive-gone","values":{"skipped_from":900000,"skipped_to":901120,"hang_from":900096,"hang_to":900608}}"#,
            r#"{"event":"paused","kind":"heat","values":{"skipped_from":1,"skipped_to":2}}"#,
            r#"{"event":"paused","kind":"drive-gone","values":{"skipped_from":400000,"skipped_to":465536,"zoned":false}}"#,
        ];
        std::fs::write(dir.join("image.events.jsonl"), log.join("\n")).unwrap();
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.resumed);
        let run = Rescue::open(plan, &disk).unwrap();
        type Seen = (u64, u64, Vec<(u64, u64)>);
        let zones: Vec<Seen> = run
            .zones
            .list()
            .iter()
            .map(|z| (z.from, z.to, z.hangs.clone()))
            .collect();
        assert_eq!(
            zones,
            [
                (200704, 266240, vec![(200704, 201216)]),
                (634880, 700416, vec![(699904, 700416)]),
                (900000, 901120, vec![(900096, 900608)]),
            ]
        );
        assert!(run.zones.list().iter().all(|z| z.spent == 0));
        drop(run);
        // A new map at another stem starts with no zones.
        let plan = plan_with(&disk, &dir, "other", u64::MAX / 2, "NTFS").unwrap();
        assert!(!plan.resumed);
        assert!(Rescue::open(plan, &disk).unwrap().zones.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard (round 9): only copying, trimming and scraping make hang zones, so a retry
    /// pass's or Fill the gaps' drop is told as a skip for a later pass; and what a zone is
    /// said to be left with is what no phase finished reading, not its bad sectors.
    #[test]
    fn retry_and_fill_make_no_zone_and_bad_sectors_are_not_left() {
        let dir = folder("zoned");
        let disk = MemDisk::new(vec![1u8; 1 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        for (phase, want) in [
            (Phase::Copying, Some(Status::Untried)),
            (Phase::Trimming, Some(Status::NonTrimmed)),
            (Phase::Scraping, Some(Status::NonScraped)),
            (Phase::Retrying, None),
        ] {
            run.map.phase = phase;
            assert_eq!(run.zoned(), want, "{phase:?}");
        }
        run.map.phase = Phase::Copying;
        run.filling = Some(false);
        assert_eq!(run.zoned(), None, "Fill the gaps");
        run.filling = None;
        run.zones.seed(65536, 131072, (65536, 66048));
        run.map.set(0, 1 << 20, Status::Rescued);
        run.map.set(65536, 4096, Status::Bad);
        assert_eq!(run.zones_left(), 0, "bad sectors were read");
        run.map.set(70000 / 512 * 512, 512, Status::NonScraped);
        run.map.set(80000 / 512 * 512, 1024, Status::Untried);
        run.map.set(90000 / 512 * 512, 512, Status::NonTrimmed);
        assert_eq!(run.zones_left(), 2048);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a square's own grid holds what the strip counts in that square, cell by
    /// cell, and its amounts add up to the square; the inspector draws it.
    /// The guard for manual step 27: what a run recovered is found against the map it began
    /// with, square by square and as areas, near areas told as one, and the newest copy kept
    /// before Fill the gaps is the map it began with.
    #[test]
    fn what_a_run_recovered_is_found_by_square_and_by_area() {
        const GB: u64 = 1 << 30;
        let len = 8 * GB;
        let mut before = Map::new(len);
        before.set(0, len, Status::Rescued);
        before.set(GB, 64 << 10, Status::Bad);
        before.set(GB + (512 << 20), 64 << 10, Status::NonScraped);
        before.set(5 * GB, 1 << 20, Status::Untried);
        let mut after = before.clone();
        after.set(GB + 4096, 8192, Status::Rescued); // 8 kB in the first
        after.set(GB + (512 << 20), 4096, Status::Rescued); // 4 kB in the second, 512 MB on
        after.set(5 * GB, 1 << 20, Status::Rescued); // all of the third
                                                     // By square: 8 squares of 1 GB.
        let gained = after.strip_gained_in(&before, &(0..len), 8);
        assert_eq!(gained, vec![0, 12288, 0, 0, 0, 1 << 20, 0, 0]);
        // By area: the first two are within the bridge and told as one, from the first byte
        // recovered to the last.
        let areas = after.gains(&before, GAINS_BRIDGE);
        assert_eq!(
            areas,
            vec![
                (5 * GB..5 * GB + (1 << 20), 1 << 20),
                (GB + 4096..GB + (512 << 20) + 4096, 12288),
            ]
        );
        let apart = after.gains(&before, 1 << 20);
        assert_eq!(apart.len(), 3, "{apart:?}");
        let text = after.gains_text(&before).unwrap();
        assert!(
            text.starts_with("Recovered this run: 1.1 MB, 1.0 MB at 5.4 GB to"),
            "{text}"
        );
        assert_eq!(before.gains_text(&before), None);
        assert!(after.gains(&Map::new(len - 512), GAINS_BRIDGE).is_empty());

        // The newest copy kept before Fill the gaps, by hand or by the app.
        let dir = std::env::temp_dir().join(format!("diagtool-gains-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let map_path = dir.join("image.map");
        std::fs::write(&map_path, after.to_text(&[])).unwrap();
        assert!(latest_map_copy(&map_path, &after).is_none());
        let mut older = before.clone();
        older.set(0, 4096, Status::Bad);
        std::fs::write(dir.join("image.map.before-fill"), older.to_text(&[])).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(
            dir.join("image.map.before-fill-20261110-121700"),
            before.to_text(&[]),
        )
        .unwrap();
        std::fs::write(
            dir.join("other.map.before-fill-20261110-131700"),
            older.to_text(&[]),
        )
        .unwrap();
        assert_eq!(latest_map_copy(&map_path, &after), Some(before.clone()));
        assert!(latest_map_copy(&map_path, &Map::new(len - 512)).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_square_of_the_strip_is_its_own_strip() {
        let mut map = Map::new(1 << 20);
        map.set(0, 1 << 20, Status::Rescued);
        map.set(5000 / 512 * 512, 512, Status::Bad);
        map.set(300_000 / 512 * 512, 4096, Status::NonScraped);
        map.set(700_000 / 512 * 512, 65536, Status::Untried);
        let cells = 16;
        let whole = map.strip(cells);
        let shares = map.strip_rescued(cells);
        for (c, (&cell, &share)) in whole.iter().zip(&shares).enumerate() {
            let square = Map::strip_edge_in(&(0..map.len()), c, cells)
                ..Map::strip_edge_in(&(0..map.len()), c + 1, cells);
            let amounts = map.amounts_in(&square);
            assert_eq!(
                amounts.iter().sum::<u64>(),
                square.end - square.start,
                "{c}"
            );
            // One cell over the square is the strip's cell.
            assert_eq!(map.strip_in(&square, 1), vec![cell], "{c}");
            assert_eq!(map.strip_rescued_in(&square, 1)[0], share, "{c}");
            // Its own cells add up to it.
            let inner = map.strip_bytes_in(&square, 64);
            let mut sum = [0u64; 4];
            for counts in &inner {
                for k in 0..4 {
                    sum[k] += counts[k];
                }
            }
            assert_eq!(sum, amounts, "{c}");
        }
        // At sector level each cell is the sector's own state.
        let square = 4608..6144;
        assert_eq!(
            map.strip_in(&square, 3),
            vec![Cell::Failed, Cell::Rescued, Cell::Rescued]
        );
        assert_eq!(Map::strip_cell_in(&square, 5200, 3), Some(1));
        assert_eq!(Map::strip_cell_in(&square, 6144, 3), None);
        assert_eq!(Map::strip_cell_in(&square, 4607, 3), None);
        assert_eq!(map.amounts_in(&square), [1024, 0, 0, 512]);
    }

    /// The guard: Fill the gaps says which sector it reads, though the map's position stays
    /// the run's and its phase finished; the strip's ring sat on the map's end, so the current block had no outline.
    #[test]
    fn fill_the_gaps_says_where_it_reads() {
        struct Slow {
            disk: MemDisk,
            progress: std::sync::Arc<Progress>,
            seen: Vec<(u64, Option<u64>)>,
        }
        impl BlockSource for Slow {
            fn len(&self) -> u64 {
                self.disk.len()
            }
            fn sector_size(&self) -> u32 {
                self.disk.sector_size()
            }
            fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
                let shown = *self.progress.reading.lock().unwrap();
                self.seen.push((offset, shown));
                // Past the window's refresh, so the next read's tick publishes.
                std::thread::sleep(Duration::from_millis(220));
                self.disk.read_at(offset, buf)
            }
            fn describe(&self) -> String {
                self.disk.describe()
            }
        }
        let dir = folder("fill-reading");
        let disk = MemDisk::new(vec![1u8; 1 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.map.set(0, 1 << 20, Status::Rescued);
        run.map.set(4096, 512, Status::NonScraped);
        run.map.set(65536, 512, Status::NonScraped);
        run.map.set(131072, 512, Status::Bad);
        run.map.phase = Phase::Finished;
        run.map.current_pos = 1 << 20;
        let progress = std::sync::Arc::new(Progress::default());
        let mut source = Slow {
            disk,
            progress: progress.clone(),
            seen: Vec::new(),
        };
        let stop = AtomicBool::new(false);
        run.fill_pass(
            &mut source,
            false,
            &stop,
            &progress,
            Duration::from_secs(3600),
            &mut || Watch::Fine,
            &mut |_| {},
        )
        .unwrap();
        let read: Vec<u64> = source.seen.iter().map(|(at, _)| *at).collect();
        assert_eq!(
            read,
            vec![4096, 65536],
            "the bad sector waits for a pass of its own"
        );
        // Each read after the first was published as it began, at its own sector.
        for (at, shown) in &source.seen[1..] {
            assert_eq!(*shown, Some(*at), "reading {at}");
        }
        assert_eq!(
            run.map.current_pos,
            1 << 20,
            "the map's position stays the run's"
        );
        assert_eq!(
            *progress.reading.lock().unwrap(),
            None,
            "nothing read after the pass"
        );
        // With nothing else left, the next pass reads the bad sector.
        source.seen.clear();
        run.fill_pass(
            &mut source,
            true,
            &stop,
            &progress,
            Duration::from_secs(3600),
            &mut || Watch::Fine,
            &mut |_| {},
        )
        .unwrap();
        let read: Vec<u64> = source.seen.iter().map(|(at, _)| *at).collect();
        assert_eq!(read, vec![131072]);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: while anything that never failed is left, Fill the gaps reads the longest
    /// run of it first, from its middle forwards to its end and then backwards to its start,
    /// leaving the bad sectors; a place asked for splits its own run there.
    #[test]
    fn fill_the_gaps_splits_the_longest_run_from_its_middle() {
        let dir = folder("fill-split");
        let disk = MemDisk::new(vec![1u8; 1 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        let fresh = |run: &mut Rescue| {
            run.map.set(0, 1 << 20, Status::Rescued);
            run.map.set(4096, 2048, Status::NonScraped);
            run.map.set(65536, 4096, Status::NonScraped);
            run.map.set(16384, 512, Status::Bad);
            run.map.phase = Phase::Finished;
        };
        fresh(&mut run);
        assert_eq!(run.map.largest_unfailed(), Some(65536..69632));
        assert_eq!(run.map.unfailed_run(9000), Some(65536..69632));
        assert_eq!(run.map.unfailed_run(5000), Some(4096..6144));
        let pass = |run: &mut Rescue| {
            let mut source = MemDisk::new(vec![1u8; 1 << 20]);
            run.fill_pass(
                &mut source,
                true,
                &AtomicBool::new(false),
                &Progress::default(),
                Duration::from_secs(3600),
                &mut || Watch::Fine,
                &mut |_| {},
            )
            .unwrap();
            source.reads.iter().map(|r| r.0).collect::<Vec<u64>>()
        };
        assert_eq!(
            pass(&mut run),
            vec![67584, 68096, 68608, 69120, 67072, 66560, 66048, 65536, 5120, 5632, 4608, 4096]
        );
        // A place asked for splits its own run there, then the longest left.
        fresh(&mut run);
        run.carry_on_fill(4608);
        assert_eq!(
            pass(&mut run),
            vec![4608, 5120, 5632, 4096, 67584, 68096, 68608, 69120, 67072, 66560, 66048, 65536]
        );
        // With nothing else left, the bad sector.
        assert_eq!(pass(&mut run), vec![16384]);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a block read alone that the drive dropped in carries on past the drop
    /// skip's place, not at the block's first sector, where the drive hung (2026-11-10, a
    /// block read at 97.27 GB hung at the same sector after each replug).
    #[test]
    fn a_block_read_alone_goes_on_past_a_drop() {
        let dir = folder("block-drop");
        let disk = MemDisk::new(vec![1u8; 1 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        run.map.set(0, 1 << 20, Status::Rescued);
        run.map.set(4096, 4096, Status::NonScraped);
        run.map.phase = Phase::Finished;
        let mut source = MemDisk::new(vec![1u8; 1 << 20]);
        run.fill_only(4096..8192);
        // Where `skip_drop` leaves the pass after a drop at 4096.
        run.fill_from = Some(6144);
        let progress = Progress::default();
        run.fill_pass(
            &mut source,
            false,
            &AtomicBool::new(false),
            &progress,
            Duration::from_secs(3600),
            &mut || Watch::Fine,
            &mut |_| {},
        )
        .unwrap();
        let read: Vec<u64> = source.reads.iter().map(|r| r.0).collect();
        assert_eq!(read, vec![6144, 6656, 7168, 7680]);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the reading mark and the strip place a byte in the same cell, at every
    /// edge; the mark had its own arithmetic, which put a byte on an edge one cell early.
    #[test]
    fn the_mark_and_the_strip_agree_on_every_byte() {
        for (len, cells) in [(10u64, 3usize), (3, 6), (1000, 7), (4096, 4096), (5, 1)] {
            let map = Map::new(len);
            for pos in 0..len {
                let c = map.strip_cell(pos, cells);
                assert!(c < cells, "{len} {cells} {pos}");
                assert!(
                    map.strip_edge(c, cells) <= pos && pos < map.strip_edge(c + 1, cells),
                    "{len} bytes in {cells} cells: byte {pos} drawn in cell {c}"
                );
            }
        }
    }

    /// The guard: the read a drop interrupted is marked failed also in photos first, which
    /// left it untried, so copying read it again and the drive hung there again.
    #[test]
    fn the_read_a_drop_interrupted_goes_to_trimming() {
        let dir = folder("drop-inflight");
        let disk = MemDisk::new(vec![1u8; 1 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let mut run = Rescue::open(plan, &disk).unwrap();
        assert_eq!(run.map.phase, Phase::Copying);
        run.in_photos = true;
        run.dropped = Some((4096, 4096));
        assert!(run.skip_drop(512, 64 << 10).is_some() && run.photos_ended);
        assert_eq!(status_at(&run.map, 4096), Status::NonTrimmed);
        assert_eq!(status_at(&run.map, 8191), Status::NonTrimmed);
        assert_eq!(status_at(&run.map, 8192), Status::Untried);
        // A one-sector read is the sector the drive hung on: bad, held for a retry pass.
        run.in_photos = false;
        run.dropped = Some((65536, 512));
        assert!(run.skip_drop(512, 64 << 10).is_some());
        assert_eq!(status_at(&run.map, 65536), Status::Bad);
        drop(run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a new map at a path used before in the app session starts with the first
    /// drop skip, not the one the deleted map's run had doubled to.
    #[test]
    fn a_new_map_at_an_old_path_starts_with_the_first_skip() {
        let dir = folder("drop-memory-new");
        let len: u64 = 64 << 20;
        let mut source = Hangs {
            disk: MemDisk::new(vec![1u8; len as usize]),
            hang: std::iter::once((8 << 20)..(8 << 20) + 4096).collect(),
        };
        let settings = Settings {
            cluster: 4096,
            retries: 0,
            drop_skip: 1 << 20,
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        let stop = AtomicBool::new(false);
        let mut skip_once = || {
            let plan = plan_with(&source.disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let mut run = Rescue::open(plan, &source.disk).unwrap();
            let gone = run.run(
                &mut source,
                &settings,
                &stop,
                &Progress::default(),
                &mut || Watch::Fine,
            );
            assert!(matches!(gone, Outcome::Gone(_)), "{gone:?}");
            let (from, to) = run.skip_drop(512, settings.drop_skip).unwrap();
            run.save_during().unwrap();
            to - from
        };
        assert_eq!(skip_once(), 1 << 20);
        // The map and image are deleted and a new rescue starts at the same path.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(skip_once(), 1 << 20, "the new map took the old run's skip");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the drive's own serial is taken from the map's heading only when the
    /// technician confirmed the map is this drive's; what the adapter reports is the same
    /// for another drive behind it, so it alone never vouches for the map's drive serial.
    #[test]
    fn a_drive_serial_is_taken_from_the_map_only_when_confirmed() {
        let dir = folder("usb-confirm");
        stopped_rescue(&dir, in_enclosure("WDZ1ABCD"));
        let enclosed = MemDisk {
            drive: None,
            ..in_enclosure("WDZ1ABCD")
        };
        let own = |run: &Rescue| {
            run.source_id()
                .and_then(|s| s.drive.as_ref())
                .map(|d| d.serial.clone())
        };
        let mut plan = plan_with(&enclosed, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(plan.unconfirmed.is_some() && !plan.confirmed);
        plan.confirm();
        assert!(plan.confirmed && plan.unconfirmed.is_none());
        let run = Rescue::open(plan, &enclosed).unwrap();
        assert_eq!(own(&run), Some("WDZ1ABCD".to_string()));
        drop(run);
        let plan = plan_with(&enclosed, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        assert!(!plan.confirmed);
        // Unconfirmed, the run does not start at all.
        assert!(Rescue::open(plan, &enclosed).is_err());
        // A plan with nothing in doubt is accepted, not confirmed over a doubt.
        let mut plan = plan_with(
            &in_enclosure("WDZ1ABCD"),
            &dir,
            "image",
            u64::MAX / 2,
            "NTFS",
        )
        .unwrap();
        assert!(plan.unconfirmed.is_none());
        plan.confirm();
        assert!(!plan.confirmed);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
