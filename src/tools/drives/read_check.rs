//! The read check: reads every file the current user can open on a volume, around Windows'
//! cache, and lists the files the drive could not read back. Nothing is written; online-only
//! cloud files are skipped so nothing is downloaded, and links are not followed.
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_NO_RECALL,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

const CHUNK: usize = 1 << 20;
/// Files listed by name; more are counted.
pub const LISTED: usize = 500;

const ATTR_REPARSE: u32 = 0x400;
const ATTR_OFFLINE: u32 = 0x1000;
const ATTR_RECALL_ON_OPEN: u32 = 0x4_0000;
const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

/// What a failed open or read means for the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The drive could not read the data: a bad sector or a device fault.
    Bad,
    /// The current user may not read it; administrator rights may.
    Denied,
    /// A program holds it open or locked.
    InUse,
    /// It went away while the check ran.
    Gone,
    /// Anything else, listed but not taken as a drive fault.
    Other,
}

/// Windows error codes sorted by what they say about the drive.
pub fn classify(code: u32) -> Failure {
    match code {
        // CRC, sector not found, read fault, device hardware error, I/O device error, file
        // or disk structure corrupt.
        23 | 27 | 30 | 483 | 1117 | 1392 | 1393 => Failure::Bad,
        5 => Failure::Denied,
        32 | 33 => Failure::InUse,
        2 | 3 => Failure::Gone,
        _ => Failure::Other,
    }
}

pub fn failure_text(code: u32) -> String {
    match classify(code) {
        Failure::Bad => format!("the drive could not read it back (error {code})"),
        Failure::Denied => "needs administrator rights".into(),
        Failure::InUse => "a program has it locked".into(),
        Failure::Gone => "removed while the check ran".into(),
        Failure::Other => format!("could not be read (error {code})"),
    }
}

/// A file that failed, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failed {
    pub path: PathBuf,
    pub code: u32,
}

#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    /// Failures so far, for the window to list while the check runs.
    pub failed: Mutex<Vec<Failed>>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub files: u64,
    pub bytes: u64,
    /// Files that failed for a reason other than access or locks, up to LISTED.
    pub failed: Vec<Failed>,
    /// Failures beyond LISTED.
    pub more_failed: u64,
    pub bad: u64,
    pub denied: u64,
    pub in_use: u64,
    pub online_only: u64,
    pub folders_denied: u64,
    pub stopped: bool,
    pub elapsed: Duration,
}

struct Buffer(*mut u8);

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: frees the allocation made in `read_all`.
        unsafe { VirtualFree(self.0.cast(), 0, MEM_RELEASE) };
    }
}

/// Reads one file to its end without Windows' cache; Err holds the Windows error.
fn read_file(
    path: &Path,
    buffer: &Buffer,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Result<u64, u32> {
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `name` is NUL-terminated; shared fully so no program is disturbed.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_NO_RECALL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads the calling thread's last-error value.
        return Err(unsafe { GetLastError() });
    }
    let mut total = 0u64;
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Ok(total);
        }
        let mut got = 0u32;
        // SAFETY: the buffer is CHUNK bytes, page-aligned, as unbuffered reads require.
        let ok = unsafe { ReadFile(handle, buffer.0, CHUNK as u32, &mut got, null_mut()) };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error value.
            break Err(unsafe { GetLastError() });
        }
        total += u64::from(got);
        progress.bytes.fetch_add(u64::from(got), Ordering::Relaxed);
        // A short read is the end of the file; the next read would start unaligned.
        if (got as usize) < CHUNK {
            break Ok(total);
        }
    };
    // SAFETY: closes the handle opened above.
    unsafe { CloseHandle(handle) };
    result
}

/// Walks `root` depth first and reads every file, until done or `cancel` is set.
pub fn run(root: &Path, cancel: &AtomicBool, progress: &Progress) -> Report {
    let started = Instant::now();
    let mut report = Report::default();
    // SAFETY: a fresh committed allocation, freed by Buffer's Drop.
    let memory = unsafe { VirtualAlloc(null(), CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if memory.is_null() {
        report.stopped = true;
        return report;
    }
    let buffer = Buffer(memory.cast());
    let mut folders = vec![root.to_path_buf()];
    'walk: while let Some(folder) = folders.pop() {
        let entries = match std::fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(_) => {
                report.folders_denied += 1;
                continue;
            }
        };
        for entry in entries.flatten() {
            if cancel.load(Ordering::Relaxed) {
                report.stopped = true;
                break 'walk;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let attributes = meta.file_attributes();
            if attributes & (ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS) != 0 {
                report.online_only += 1;
                continue;
            }
            if attributes & ATTR_REPARSE != 0 {
                continue;
            }
            if meta.is_dir() {
                folders.push(entry.path());
                continue;
            }
            let path = entry.path();
            match read_file(&path, &buffer, cancel, progress) {
                Ok(bytes) => {
                    report.files += 1;
                    report.bytes += bytes;
                    progress.files.fetch_add(1, Ordering::Relaxed);
                }
                Err(code) => match classify(code) {
                    Failure::Denied => report.denied += 1,
                    Failure::InUse => report.in_use += 1,
                    Failure::Gone => {}
                    kind => {
                        if kind == Failure::Bad {
                            report.bad += 1;
                        }
                        if report.failed.len() < LISTED {
                            let failed = Failed { path, code };
                            if let Ok(mut shown) = progress.failed.lock() {
                                shown.push(failed.clone());
                            }
                            report.failed.push(failed);
                        } else {
                            report.more_failed += 1;
                        }
                    }
                },
            }
        }
    }
    if cancel.load(Ordering::Relaxed) {
        report.stopped = true;
    }
    report.elapsed = started.elapsed();
    report
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!(
        "{} {}",
        super::details::grouped(n.into()),
        if n == 1 { one } else { many }
    )
}

/// The outcome in one paragraph: what was read, what failed, and what was skipped and why.
pub fn summary(report: &Report) -> String {
    let mut parts = vec![format!(
        "{} {} ({}) in {} s.",
        if report.stopped {
            "Stopped after reading"
        } else {
            "Read"
        },
        plural(report.files, "file", "files"),
        super::details::decimal_size(report.bytes.into()),
        report.elapsed.as_secs()
    )];
    parts.push(if report.bad == 0 {
        "The drive read back every file it was asked for.".into()
    } else {
        format!(
            "The drive could not read {} back: their data sits on damaged parts of the drive.",
            plural(report.bad, "file", "files")
        )
    });
    let other = report.failed.len() as u64 + report.more_failed - report.bad;
    if other > 0 {
        parts.push(format!(
            "{} failed for other reasons and are listed.",
            plural(other, "file", "files")
        ));
    }
    let mut skipped = Vec::new();
    if report.denied > 0 {
        skipped.push(format!(
            "{} that need administrator rights",
            plural(report.denied, "file", "files")
        ));
    }
    if report.folders_denied > 0 {
        skipped.push(format!(
            "{} that need administrator rights",
            plural(report.folders_denied, "folder", "folders")
        ));
    }
    if report.in_use > 0 {
        skipped.push(format!(
            "{} locked by programs",
            plural(report.in_use, "file", "files")
        ));
    }
    if report.online_only > 0 {
        skipped.push(format!(
            "{} kept only online, so not downloaded",
            plural(report.online_only, "cloud file", "cloud files")
        ));
    }
    if !skipped.is_empty() {
        parts.push(format!("Not read: {}.", skipped.join(", ")));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_sorted_by_what_they_say_about_the_drive() {
        assert_eq!(classify(23), Failure::Bad);
        assert_eq!(classify(1117), Failure::Bad);
        assert_eq!(classify(5), Failure::Denied);
        assert_eq!(classify(32), Failure::InUse);
        assert_eq!(classify(2), Failure::Gone);
        assert_eq!(classify(87), Failure::Other);
        assert!(failure_text(23).contains("could not read it back"));
        assert_eq!(failure_text(5), "needs administrator rights");
    }

    #[test]
    fn a_folder_of_files_is_read_to_the_last_byte() {
        let root = std::env::temp_dir().join(format!("dt-read-check-{}", std::process::id()));
        std::fs::create_dir_all(root.join("inner")).unwrap();
        let sizes = [0usize, 1, 4097, (2 << 20) + 5];
        for (i, size) in sizes.iter().enumerate() {
            let folder = if i % 2 == 0 {
                root.clone()
            } else {
                root.join("inner")
            };
            std::fs::write(folder.join(format!("f{i}.bin")), vec![7u8; *size]).unwrap();
        }
        let progress = Progress::default();
        let report = run(&root, &AtomicBool::new(false), &progress);
        for (i, _) in sizes.iter().enumerate() {
            let folder = if i % 2 == 0 {
                root.clone()
            } else {
                root.join("inner")
            };
            std::fs::remove_file(folder.join(format!("f{i}.bin"))).unwrap();
        }
        std::fs::remove_dir(root.join("inner")).unwrap();
        std::fs::remove_dir(&root).unwrap();
        assert_eq!(report.files, 4);
        assert_eq!(report.bytes, sizes.iter().sum::<usize>() as u64);
        assert_eq!(progress.bytes.load(Ordering::Relaxed), report.bytes);
        assert!(report.failed.is_empty() && report.bad == 0);
        assert!(!report.stopped);
        assert!(summary(&report).contains("read back every file"));
    }

    #[test]
    fn a_stopped_check_says_so() {
        let report = run(
            &std::env::temp_dir(),
            &AtomicBool::new(true),
            &Progress::default(),
        );
        assert!(report.stopped);
        assert!(summary(&report).starts_with("Stopped after reading"));
    }

    #[test]
    fn the_summary_names_damage_and_what_was_skipped() {
        let report = Report {
            files: 1200,
            bytes: 5_000_000_000,
            failed: vec![
                Failed {
                    path: PathBuf::from(r"C:\a"),
                    code: 23,
                },
                Failed {
                    path: PathBuf::from(r"C:\b"),
                    code: 87,
                },
            ],
            bad: 1,
            denied: 30,
            in_use: 2,
            online_only: 4,
            folders_denied: 9,
            elapsed: Duration::from_secs(61),
            ..Report::default()
        };
        let text = summary(&report);
        assert!(
            text.starts_with("Read 1,200 files (5.0 GB) in 61 s."),
            "{text}"
        );
        assert!(text.contains("could not read 1 file back"));
        assert!(text.contains("1 file failed for other reasons"));
        assert!(text.contains("30 files that need administrator rights"));
        assert!(text.contains("9 folders that need administrator rights"));
        assert!(text.contains("4 cloud files kept only online"));
    }
}
