//! The pace of a copy to its destination, measured as it goes over the files written lately,
//! and the time left from it. A file costs some time for being a file (making it, its
//! folder, its flush) and some for each byte; small files on a USB drive are slow for the
//! first, large ones for the second, so both are fitted and the time left is costed with the
//! files and bytes that remain.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The most files the window holds, and the time it spans at least before it lets one go.
const WINDOW_FILES: usize = 512;
const WINDOW_SECS: f64 = 60.0;
/// Files to have been timed before a time left is given.
const FIRST_FILES: usize = 4;

/// The files written lately: how long each took and how many bytes it wrote.
#[derive(Clone, Debug, Default)]
pub struct Rate {
    files: VecDeque<(f64, u64)>,
    secs: f64,
    bytes: u64,
}

impl Rate {
    /// One file written: it took `secs` and wrote `bytes`.
    pub fn file(&mut self, secs: f64, bytes: u64) {
        self.files.push_back((secs.max(0.0), bytes));
        self.secs += secs.max(0.0);
        self.bytes += bytes;
        while self.files.len() > WINDOW_FILES
            || (self.files.len() > FIRST_FILES && self.secs - self.files[0].0 > WINDOW_SECS)
        {
            let (secs, bytes) = self.files.pop_front().expect("a file");
            self.secs -= secs;
            self.bytes -= bytes;
        }
    }

    /// Bytes written per second over the window.
    pub fn bytes_per_sec(&self) -> f64 {
        if self.secs > 0.0 {
            self.bytes as f64 / self.secs
        } else {
            0.0
        }
    }

    /// Files written per second over the window.
    pub fn files_per_sec(&self) -> f64 {
        if self.secs > 0.0 {
            self.files.len() as f64 / self.secs
        } else {
            0.0
        }
    }

    /// The seconds a file takes for being one and for each byte, fitted to the window by
    /// least squares, neither below zero; None before enough files.
    pub fn costs(&self) -> Option<(f64, f64)> {
        let n = self.files.len() as f64;
        if self.files.len() < FIRST_FILES || self.secs <= 0.0 {
            return None;
        }
        let (mut sx, mut sy, mut sxx, mut sxy) = (0.0, 0.0, 0.0, 0.0);
        for &(secs, bytes) in &self.files {
            let x = bytes as f64;
            sx += x;
            sy += secs;
            sxx += x * x;
            sxy += x * secs;
        }
        let spread = n * sxx - sx * sx;
        // Files all of one size cannot tell the two costs apart: their time goes to their
        // bytes when they have any, else to their being files.
        if spread <= 1e-9 * sxx.max(1.0) * n {
            return Some(if sx > 0.0 {
                (0.0, sy / sx)
            } else {
                (sy / n, 0.0)
            });
        }
        let per_byte = (n * sxy - sx * sy) / spread;
        let per_file = (sy - per_byte * sx) / n;
        Some(if per_byte < 0.0 {
            (sy / n, 0.0)
        } else if per_file < 0.0 {
            (0.0, sxy / sxx)
        } else {
            (per_file, per_byte)
        })
    }

    /// The time `files` holding `bytes` take at the window's pace.
    pub fn time_left(&self, files: u64, bytes: u64) -> Option<Duration> {
        let (per_file, per_byte) = self.costs()?;
        let secs = per_file * files as f64 + per_byte * bytes as f64;
        Some(Duration::from_secs_f64(secs.clamp(0.0, 1e9)))
    }
}

/// The pace shared with a window or a command line while a recovery copies: its rates and
/// the time left, and the files done and to do.
#[derive(Debug)]
pub struct Pace {
    bytes_per_sec: AtomicU64,
    files_per_sec: AtomicU64,
    /// Milliseconds left; `UNKNOWN` until the pace is known.
    left_ms: AtomicU64,
    pub files_done: AtomicU64,
    pub files_total: AtomicU64,
}

const UNKNOWN: u64 = u64::MAX;

impl Default for Pace {
    fn default() -> Self {
        Self {
            bytes_per_sec: AtomicU64::new(0),
            files_per_sec: AtomicU64::new(0),
            left_ms: AtomicU64::new(UNKNOWN),
            files_done: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
        }
    }
}

impl Pace {
    /// Puts `rate` and the time it gives for `files` holding `bytes` that remain.
    pub fn set(&self, rate: &Rate, files: u64, bytes: u64) {
        let put = |to: &AtomicU64, v: f64| to.store(v.to_bits(), Ordering::Relaxed);
        put(&self.bytes_per_sec, rate.bytes_per_sec());
        put(&self.files_per_sec, rate.files_per_sec());
        let left = rate.time_left(files, bytes).map_or(UNKNOWN, |d| {
            d.as_millis().min(u128::from(UNKNOWN - 1)) as u64
        });
        self.left_ms.store(left, Ordering::Relaxed);
    }

    pub fn bytes_per_sec(&self) -> f64 {
        f64::from_bits(self.bytes_per_sec.load(Ordering::Relaxed))
    }

    pub fn files_per_sec(&self) -> f64 {
        f64::from_bits(self.files_per_sec.load(Ordering::Relaxed))
    }

    /// The time left, once enough files were written to tell.
    pub fn time_left(&self) -> Option<Duration> {
        match self.left_ms.load(Ordering::Relaxed) {
            UNKNOWN => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The time left is costed per file and per byte from the files written lately: a
    /// destination that takes 0.1 s a file and 10 ns a byte is fitted so, small files left
    /// are costed by their number and large ones by their bytes; files of one size give
    /// their time to their bytes; old files leave the window.
    #[test]
    fn the_time_left_comes_from_the_files_written_lately() {
        let mut rate = Rate::default();
        assert_eq!(rate.time_left(10, 10), None);
        for i in 0..40u64 {
            let bytes = (i % 4) * 25_000_000 + 1000;
            rate.file(0.1 + bytes as f64 * 1e-8, bytes);
        }
        let (per_file, per_byte) = rate.costs().unwrap();
        assert!((per_file - 0.1).abs() < 1e-6, "{per_file}");
        assert!((per_byte - 1e-8).abs() < 1e-12, "{per_byte}");
        let small = rate.time_left(1000, 1000 * 4096).unwrap().as_secs_f64();
        assert!((small - 100.04).abs() < 0.01, "{small}");
        let large = rate.time_left(2, 20_000_000_000).unwrap().as_secs_f64();
        assert!((large - 200.2).abs() < 0.01, "{large}");
        assert!(rate.bytes_per_sec() > 0.0 && rate.files_per_sec() > 0.0);
        // A window of one size: 1 MB in 0.5 s each, so 2 MB/s.
        let mut even = Rate::default();
        for _ in 0..10 {
            even.file(0.5, 1_000_000);
        }
        let left = even.time_left(4, 4_000_000).unwrap().as_secs_f64();
        assert!((left - 2.0).abs() < 1e-9, "{left}");
        assert!((even.files_per_sec() - 2.0).abs() < 1e-9);
        // Slow files from long ago leave the window once a minute of newer ones is in it.
        let mut moving = Rate::default();
        for _ in 0..10 {
            moving.file(30.0, 1_000_000);
        }
        for _ in 0..200 {
            moving.file(0.5, 1_000_000);
        }
        let left = moving.time_left(1, 1_000_000).unwrap().as_secs_f64();
        assert!((left - 0.5).abs() < 1e-9, "{left}");
        let pace = Pace::default();
        assert_eq!(pace.time_left(), None);
        pace.set(&moving, 120, 120_000_000);
        assert_eq!(pace.time_left(), Some(Duration::from_secs(60)));
        assert!((pace.bytes_per_sec() - 2_000_000.0).abs() < 1.0);
    }
}
