//! A full map of one drive for the drive space window: every folder's size, and the largest
//! files in each folder and on the whole drive. Reads directory metadata only; nothing is
//! opened or deleted. Junctions and symbolic links are not followed, and cloud-only files
//! count as nothing, as in `toolkit space`.
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::space::{classify, file_size, list_dir, name_of, Kind};

/// Largest files kept per folder: enough that the drive's largest files are all kept.
pub const KEEP_FILES: usize = 50;
/// Threads that pull folders from the shared queue.
pub const THREADS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Folder {
    pub name: String,
    /// The parent folder's index; the root is its own parent.
    pub parent: usize,
    /// Bytes of the files directly in this folder.
    pub own: u64,
    /// Bytes of everything under this folder.
    pub total: u64,
    /// Files directly in this folder.
    pub files: u64,
    pub children: Vec<usize>,
    /// The largest files directly in this folder, largest first, at most `KEEP_FILES`.
    pub largest: Vec<File>,
    /// The folder could not be listed (usually access denied); its size counts as nothing.
    pub unreadable: bool,
    /// Stop ended the scan before this folder, or one under it, was listed.
    pub unfinished: bool,
}

#[derive(Debug, Default)]
pub struct Map {
    pub root: PathBuf,
    /// Folders in discovery order: index 0 is the root and children come after their parent.
    pub folders: Vec<Folder>,
    pub unreadable: u64,
    pub skipped_links: u64,
    pub cancelled: bool,
    pub elapsed: Duration,
}

/// Counters the window reads while a scan runs.
#[derive(Debug, Default)]
pub struct Progress {
    pub folders: AtomicU64,
    pub bytes: AtomicU64,
}

/// One line of the window's list: a folder to enter or a file to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub name: String,
    pub bytes: u64,
    /// The folder's index, or None for a file.
    pub folder: Option<usize>,
    /// The folder's size is a minimum because the scan stopped inside it.
    pub partial: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub lines: Vec<Line>,
    /// Items in the folder not shown, and their bytes.
    pub rest_items: u64,
    pub rest_bytes: u64,
    pub total: u64,
}

impl Map {
    /// The full path of a folder.
    pub fn path(&self, index: usize) -> PathBuf {
        let mut names = Vec::new();
        let mut at = index;
        while at != 0 {
            names.push(self.folders[at].name.as_str());
            at = self.folders[at].parent;
        }
        let mut path = self.root.clone();
        for name in names.iter().rev() {
            path.push(name);
        }
        path
    }

    /// The largest `limit` folders and files directly in a folder, largest first.
    pub fn view(&self, index: usize, limit: usize) -> View {
        let folder = &self.folders[index];
        let mut lines: Vec<Line> = folder
            .children
            .iter()
            .map(|&child| Line {
                name: self.folders[child].name.clone(),
                bytes: self.folders[child].total,
                folder: Some(child),
                partial: self.folders[child].unfinished,
            })
            .chain(folder.largest.iter().map(|file| Line {
                name: file.name.clone(),
                bytes: file.bytes,
                folder: None,
                partial: false,
            }))
            .collect();
        lines.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        lines.truncate(limit);
        let shown: u64 = lines.iter().map(|line| line.bytes).sum();
        let items = folder.children.len() as u64 + folder.files;
        View {
            rest_items: items - lines.len() as u64,
            rest_bytes: folder.total.saturating_sub(shown),
            total: folder.total,
            lines,
        }
    }

    /// The largest files anywhere on the map, largest first, with the folder each is in.
    pub fn largest_files(&self, limit: usize) -> Vec<(usize, File)> {
        let mut all: Vec<(usize, File)> = self
            .folders
            .iter()
            .enumerate()
            .flat_map(|(index, folder)| folder.largest.iter().map(move |f| (index, f.clone())))
            .collect();
        all.sort_by(|a, b| {
            b.1.bytes
                .cmp(&a.1.bytes)
                .then_with(|| a.1.name.cmp(&b.1.name))
        });
        all.truncate(limit);
        all
    }
}

struct Shared {
    queue: VecDeque<(PathBuf, usize)>,
    folders: Vec<Folder>,
    active: usize,
    unreadable: u64,
    skipped_links: u64,
}

/// Maps everything under `root` with `threads` workers sharing one queue. Setting `cancel`
/// ends the scan early; folders not yet listed are marked unfinished.
pub fn scan(root: &Path, threads: usize, cancel: &AtomicBool, progress: &Progress) -> Map {
    let started = Instant::now();
    let name = root.to_string_lossy().trim_end_matches('\\').to_string();
    let shared = Mutex::new(Shared {
        queue: VecDeque::from([(root.to_path_buf(), 0)]),
        folders: vec![Folder {
            name,
            ..Folder::default()
        }],
        active: 0,
        unreadable: 0,
        skipped_links: 0,
    });
    let wake = Condvar::new();
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| worker(&shared, &wake, cancel, progress));
        }
    });
    let shared = shared.into_inner().unwrap_or_else(|e| e.into_inner());
    let mut folders = shared.folders;
    for index in (1..folders.len()).rev() {
        let (total, unfinished, parent) = {
            let f = &folders[index];
            (f.total + f.own, f.unfinished, f.parent)
        };
        folders[index].total = total;
        folders[parent].total += total;
        folders[parent].unfinished |= unfinished;
    }
    folders[0].total += folders[0].own;
    Map {
        root: root.to_path_buf(),
        folders,
        unreadable: shared.unreadable,
        skipped_links: shared.skipped_links,
        cancelled: cancel.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
    }
}

/// One folder's listing, gathered without the lock.
struct Listing {
    bytes: u64,
    files: u64,
    largest: Vec<File>,
    subdirs: Vec<OsString>,
    links: u64,
}

fn list(dir: &Path) -> Result<Listing, u32> {
    let mut listing = Listing {
        bytes: 0,
        files: 0,
        largest: Vec::new(),
        subdirs: Vec::new(),
        links: 0,
    };
    list_dir(dir, |data| match classify(data.dwFileAttributes) {
        Kind::File => {
            let bytes = file_size(data);
            listing.bytes += bytes;
            listing.files += 1;
            listing.largest.push(File {
                name: String::from_utf16_lossy(name_of(data)),
                bytes,
            });
        }
        Kind::Cloud => listing.files += 1,
        Kind::Reparse => listing.links += 1,
        Kind::Dir => listing.subdirs.push(OsString::from_wide(name_of(data))),
    })?;
    listing
        .largest
        .sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    listing.largest.truncate(KEEP_FILES);
    Ok(listing)
}

fn worker(shared: &Mutex<Shared>, wake: &Condvar, cancel: &AtomicBool, progress: &Progress) {
    loop {
        let (path, index) = {
            let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if cancel.load(Ordering::Relaxed) {
                    let left: Vec<(PathBuf, usize)> = guard.queue.drain(..).collect();
                    for (_, index) in left {
                        guard.folders[index].unfinished = true;
                    }
                    wake.notify_all();
                    return;
                }
                if let Some(task) = guard.queue.pop_front() {
                    guard.active += 1;
                    break task;
                }
                if guard.active == 0 {
                    wake.notify_all();
                    return;
                }
                guard = wake
                    .wait_timeout(guard, Duration::from_millis(50))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        };
        let listed = list(&path);
        progress.folders.fetch_add(1, Ordering::Relaxed);
        let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
        guard.active -= 1;
        match listed {
            Ok(listing) => {
                progress.bytes.fetch_add(listing.bytes, Ordering::Relaxed);
                guard.skipped_links += listing.links;
                let folder = &mut guard.folders[index];
                folder.own = listing.bytes;
                folder.files = listing.files;
                folder.largest = listing.largest;
                for name in listing.subdirs {
                    let child = guard.folders.len();
                    guard.folders.push(Folder {
                        name: name.to_string_lossy().into_owned(),
                        parent: index,
                        ..Folder::default()
                    });
                    guard.folders[index].children.push(child);
                    guard.queue.push_back((path.join(&name), child));
                }
            }
            Err(_) => {
                guard.unreadable += 1;
                guard.folders[index].unreadable = true;
            }
        }
        wake.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!("diagtool-map-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn file(&self, relative: &str, size: usize) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, vec![7u8; size]).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn map_of(scratch: &Scratch, threads: usize) -> Map {
        scan(
            &scratch.0,
            threads,
            &AtomicBool::new(false),
            &Progress::default(),
        )
    }

    fn sample() -> Scratch {
        let s = Scratch::new("sample");
        s.file("big/a.bin", 5000);
        s.file("big/deeper/b.bin", 3000);
        s.file("small/c.bin", 100);
        s.file("top.bin", 2000);
        s.file("tiny.txt", 10);
        s
    }

    #[test]
    fn totals_roll_up_and_a_view_lists_folders_and_files_largest_first() {
        let s = sample();
        let map = map_of(&s, 4);
        assert_eq!(map.folders[0].total, 10_110);
        let view = map.view(0, 10);
        let names: Vec<(&str, u64, bool)> = view
            .lines
            .iter()
            .map(|l| (l.name.as_str(), l.bytes, l.folder.is_some()))
            .collect();
        assert_eq!(
            names,
            [
                ("big", 8000, true),
                ("top.bin", 2000, false),
                ("small", 100, true),
                ("tiny.txt", 10, false)
            ]
        );
        assert_eq!(
            (view.rest_items, view.rest_bytes, view.total),
            (0, 0, 10_110)
        );
        let big = view.lines[0].folder.unwrap();
        assert_eq!(map.path(big), s.0.join("big"));
        let inside = map.view(big, 10);
        assert_eq!(inside.lines[0].name, "a.bin");
        assert_eq!(inside.lines[1].name, "deeper");
        assert!(!map.cancelled && map.unreadable == 0);
    }

    #[test]
    fn a_short_view_counts_what_it_leaves_out() {
        let s = sample();
        let view = map_of(&s, 2).view(0, 2);
        assert_eq!(view.lines.len(), 2);
        assert_eq!((view.rest_items, view.rest_bytes), (2, 110));
    }

    #[test]
    fn one_thread_and_many_give_the_same_map() {
        let s = sample();
        let (one, many) = (map_of(&s, 1), map_of(&s, 8));
        assert_eq!(one.view(0, 10), many.view(0, 10));
        assert_eq!(one.largest_files(10), many.largest_files(10));
    }

    #[test]
    fn the_largest_files_come_from_every_folder() {
        let s = sample();
        let map = map_of(&s, 4);
        let files: Vec<(String, u64)> = map
            .largest_files(3)
            .into_iter()
            .map(|(folder, f)| {
                (
                    map.path(folder).join(&f.name).to_string_lossy().into(),
                    f.bytes,
                )
            })
            .collect();
        let expect = |rel: &str, n| (s.0.join(rel).to_string_lossy().into_owned(), n);
        assert_eq!(
            files,
            [
                expect("big\\a.bin", 5000),
                expect("big\\deeper\\b.bin", 3000),
                expect("top.bin", 2000)
            ]
        );
    }

    #[test]
    fn a_folder_keeps_only_its_largest_files_but_counts_them_all() {
        let s = Scratch::new("many");
        for i in 0..(KEEP_FILES + 5) {
            s.file(&format!("f{i:03}.bin"), i + 1);
        }
        let map = map_of(&s, 2);
        let root = &map.folders[0];
        assert_eq!(root.files, (KEEP_FILES + 5) as u64);
        assert_eq!(root.largest.len(), KEEP_FILES);
        assert_eq!(root.largest[0].bytes, (KEEP_FILES + 5) as u64);
        let all: u64 = (1..=(KEEP_FILES + 5) as u64).sum();
        assert_eq!(root.total, all);
    }

    #[test]
    fn a_junction_is_counted_but_not_followed() {
        let s = sample();
        let outside = Scratch::new("outside");
        outside.file("huge.bin", 50_000);
        let link = s.0.join("link");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.0)
            .output()
            .unwrap();
        assert!(made.status.success());
        let map = map_of(&s, 4);
        assert_eq!(map.folders[0].total, 10_110);
        assert_eq!(map.skipped_links, 1);
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn cancelling_marks_the_map_unfinished() {
        let s = sample();
        let map = scan(&s.0, 2, &AtomicBool::new(true), &Progress::default());
        assert!(map.cancelled);
        assert!(map.folders[0].unfinished);
        assert!(map.view(0, 10).lines.is_empty());
    }

    #[test]
    fn a_missing_root_is_unreadable_not_a_crash() {
        let s = Scratch::new("gone");
        let gone = s.0.join("absent");
        let map = scan(&gone, 2, &AtomicBool::new(false), &Progress::default());
        assert!(map.folders[0].unreadable);
        assert_eq!((map.unreadable, map.folders[0].total), (1, 0));
    }
}
