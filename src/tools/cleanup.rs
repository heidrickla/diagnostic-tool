//! The drive space window's cleanup: temporary files nobody has changed for a week, and the
//! Recycle Bin. Runs as the current user, so only files that user may delete are removed.
//!
//! What makes a temporary file safe to remove: it is inside a temp folder found by walking
//! down from that folder without following any junction or link; it is not a link itself;
//! it is not read-only or a system file; and both its creation and last change are older
//! than `AGE`. Each file is checked again just before it is removed, and a file in use
//! fails to delete and is left. Folders are removed only when they end up empty and were
//! created before `AGE`. The temp folders themselves are never removed.
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM, WIN32_FIND_DATAW,
};

use super::space::{file_size, list_dir, name_of, windows_dir};

/// A temporary file unchanged for this long is left behind by a program that is done with it.
pub const AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// The temp walk stops here; what it found so far is still offered.
const PLAN_TIME: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TempPlan {
    pub roots: Vec<PathBuf>,
    /// Files to remove with their sizes.
    pub files: Vec<(PathBuf, u64)>,
    /// Folders to try to remove afterwards, deepest first.
    pub folders: Vec<PathBuf>,
    pub bytes: u64,
    /// Files left because they are recent, read-only, system or links.
    pub kept: u64,
    /// Folders that could not be listed.
    pub unreadable: u64,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    pub files: u64,
    pub bytes: u64,
    pub folders: u64,
    /// Files that could not be removed, usually because a program has them open.
    pub failed: u64,
    /// Files that changed since the plan and were left.
    pub changed: u64,
}

const LOCKED: u32 = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_REPARSE_POINT;

fn filetime(time: windows_sys::Win32::Foundation::FILETIME) -> SystemTime {
    // FILETIME counts 100 ns from 1601; the Unix epoch is 11 644 473 600 s later.
    let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    let unix = (ticks / 10_000_000).saturating_sub(11_644_473_600);
    UNIX_EPOCH + Duration::from_secs(unix)
}

fn old(data: &WIN32_FIND_DATAW, cutoff: SystemTime) -> bool {
    filetime(data.ftCreationTime) < cutoff && filetime(data.ftLastWriteTime) < cutoff
}

/// The current user's temp folder and the Windows temp folder, without duplicates.
pub fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    if let Some(windows) = windows_dir() {
        roots.push(windows.join("Temp"));
    }
    let mut unique: Vec<PathBuf> = Vec::new();
    for root in roots {
        let key = root.to_string_lossy().trim_end_matches('\\').to_lowercase();
        let short = key.len() <= 3;
        if !short
            && !unique
                .iter()
                .any(|u| u.to_string_lossy().trim_end_matches('\\').to_lowercase() == key)
        {
            unique.push(root);
        }
    }
    unique
}

/// Finds what is safe to remove under `roots` as of `now`.
pub fn plan_temp(roots: &[PathBuf], now: SystemTime) -> TempPlan {
    let cutoff = now.checked_sub(AGE).unwrap_or(UNIX_EPOCH);
    let deadline = Instant::now() + PLAN_TIME;
    let mut plan = TempPlan {
        roots: roots.to_vec(),
        ..TempPlan::default()
    };
    for root in roots {
        // A temp folder that is itself a link is not walked at all.
        match std::fs::symlink_metadata(root) {
            Ok(meta)
                if meta.is_dir() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 => {}
            _ => continue,
        }
        let mut stack: Vec<PathBuf> = vec![root.clone()];
        let mut order: Vec<PathBuf> = Vec::new();
        while let Some(dir) = stack.pop() {
            if Instant::now() >= deadline {
                plan.timed_out = true;
                break;
            }
            let mut subdirs = Vec::new();
            let listed = list_dir(&dir, |data| {
                let name = OsString::from_wide(name_of(data));
                let attributes = data.dwFileAttributes;
                if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                        subdirs.push((dir.join(&name), old(data, cutoff)));
                    }
                } else if attributes & LOCKED == 0 && old(data, cutoff) {
                    let bytes = file_size(data);
                    plan.files.push((dir.join(&name), bytes));
                    plan.bytes += bytes;
                } else {
                    plan.kept += 1;
                }
            });
            if listed.is_err() {
                plan.unreadable += 1;
                continue;
            }
            for (sub, created_long_ago) in subdirs {
                if created_long_ago {
                    order.push(sub.clone());
                }
                stack.push(sub);
            }
        }
        // Deepest first, so a parent is tried after its children.
        order.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        plan.folders.extend(order);
    }
    plan
}

/// Whether a planned file is still what the plan saw: a plain, old, unlocked file.
fn still_safe(path: &Path, cutoff: SystemTime) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let created = meta.created().unwrap_or(SystemTime::now());
    let modified = meta.modified().unwrap_or(SystemTime::now());
    meta.is_file() && meta.file_attributes() & LOCKED == 0 && created < cutoff && modified < cutoff
}

/// Removes what `plan` found, checking each file again first.
pub fn remove_temp(plan: &TempPlan, now: SystemTime) -> Removed {
    let cutoff = now.checked_sub(AGE).unwrap_or(UNIX_EPOCH);
    let mut removed = Removed::default();
    for (path, bytes) in &plan.files {
        if !still_safe(path, cutoff) {
            removed.changed += 1;
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {
                removed.files += 1;
                removed.bytes += bytes;
            }
            Err(_) => removed.failed += 1,
        }
    }
    for folder in &plan.folders {
        let plain = std::fs::symlink_metadata(folder)
            .is_ok_and(|m| m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0);
        let is_root = plan.roots.iter().any(|r| r == folder);
        // remove_dir only removes an empty folder.
        if plain && !is_root && std::fs::remove_dir(folder).is_ok() {
            removed.folders += 1;
        }
    }
    removed
}

/// Bytes and items in the Recycle Bins of every drive, for the current user.
pub fn recycle_bin() -> Result<(u64, u64), String> {
    use windows_sys::Win32::UI::Shell::{SHQueryRecycleBinW, SHQUERYRBINFO};
    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: a null root asks for every drive; info is a sized out structure.
    let result = unsafe { SHQueryRecycleBinW(std::ptr::null(), &mut info) };
    if result < 0 {
        return Err(format!(
            "the Recycle Bin could not be read (0x{:08X})",
            result as u32
        ));
    }
    Ok((info.i64Size.max(0) as u64, info.i64NumItems.max(0) as u64))
}

/// Empties every drive's Recycle Bin for the current user, without Windows' own prompt.
pub fn empty_recycle_bin() -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::{
        SHEmptyRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND,
    };
    // SAFETY: no owner window and a null root, meaning every drive.
    let result = unsafe {
        SHEmptyRecycleBinW(
            std::ptr::null_mut(),
            std::ptr::null(),
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
        )
    };
    // E_UNEXPECTED is what an already empty bin returns.
    if result >= 0 || result as u32 == 0x8000_FFFF {
        Ok(())
    } else {
        Err(format!(
            "the Recycle Bin could not be emptied (0x{:08X})",
            result as u32
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes};
    use std::os::windows::fs::FileTimesExt;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "diagtool-clean-{tag}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        /// A file whose creation and last change are `days` ago.
        fn file(&self, relative: &str, size: usize, days: u64) -> PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, vec![1u8; size]).unwrap();
            let when = SystemTime::now() - Duration::from_secs(days * 24 * 3600);
            let times = FileTimes::new().set_modified(when).set_created(when);
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(times)
                .unwrap();
            path
        }

        /// Marks a folder as created `days` ago.
        fn age_folder(&self, relative: &str, days: u64) {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            let when = SystemTime::now() - Duration::from_secs(days * 24 * 3600);
            let dir = File::options()
                .write(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(self.0.join(relative))
                .unwrap();
            dir.set_times(FileTimes::new().set_created(when).set_modified(when))
                .unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn only_files_a_week_old_on_both_clocks_are_planned() {
        let s = Scratch::new("age");
        let gone = s.file("old.tmp", 100, 30);
        s.file("new.tmp", 100, 1);
        let edge = s.file("six-days.tmp", 100, 6);
        // Created long ago but changed yesterday: still in use.
        let touched = s.file("touched.tmp", 100, 30);
        File::options()
            .write(true)
            .open(&touched)
            .unwrap()
            .set_times(FileTimes::new().set_modified(SystemTime::now()))
            .unwrap();
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        assert_eq!(plan.files, [(gone, 100)]);
        assert_eq!((plan.bytes, plan.kept), (100, 3));
        assert!(edge.exists());
    }

    #[test]
    fn read_only_files_are_kept() {
        let s = Scratch::new("ro");
        let path = s.file("locked.tmp", 10, 30);
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms.clone()).unwrap();
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        assert!(plan.files.is_empty());
        #[allow(clippy::permissions_set_readonly_false)] // Windows only: clears the read-only bit.
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    #[test]
    fn a_junction_inside_temp_is_never_walked_or_removed() {
        let s = Scratch::new("junction");
        let outside = Scratch::new("precious");
        let precious = outside.file("keep-me.doc", 500, 90);
        let link = s.0.join("link");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.0)
            .output()
            .unwrap();
        assert!(made.status.success());
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        assert!(plan.files.iter().all(|(p, _)| !p.starts_with(&link)));
        assert!(!plan.folders.contains(&link));
        let removed = remove_temp(&plan, SystemTime::now());
        assert_eq!(removed.files, 0);
        assert!(precious.exists() && link.exists());
        std::fs::remove_dir(&link).unwrap();
    }

    #[test]
    fn a_temp_root_that_is_a_link_is_not_walked() {
        let s = Scratch::new("rootlink");
        let outside = Scratch::new("target");
        let precious = outside.file("keep.doc", 50, 90);
        let link = s.0.join("temp");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.0)
            .output()
            .unwrap();
        assert!(made.status.success());
        let plan = plan_temp(std::slice::from_ref(&link), SystemTime::now());
        assert!(plan.files.is_empty());
        remove_temp(&plan, SystemTime::now());
        assert!(precious.exists());
        std::fs::remove_dir(&link).unwrap();
    }

    #[test]
    fn removal_takes_old_files_and_the_old_folders_they_leave_empty() {
        let s = Scratch::new("remove");
        s.file("a/b/old1.tmp", 300, 30);
        s.file("a/old2.tmp", 200, 30);
        let fresh = s.file("c/new.tmp", 50, 0);
        s.age_folder("a/b", 30);
        s.age_folder("a", 30);
        s.age_folder("c", 30);
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        assert_eq!(plan.bytes, 500);
        let removed = remove_temp(&plan, SystemTime::now());
        assert_eq!((removed.files, removed.bytes, removed.folders), (2, 500, 2));
        assert!(!s.0.join("a").exists());
        assert!(fresh.exists(), "a folder still holding a recent file stays");
        assert!(s.0.exists(), "the temp folder itself stays");
    }

    #[test]
    fn a_temp_folder_itself_is_never_removed_even_when_listed() {
        let s = Scratch::new("root");
        let plan = TempPlan {
            roots: vec![s.0.clone()],
            folders: vec![s.0.clone()],
            ..TempPlan::default()
        };
        assert_eq!(remove_temp(&plan, SystemTime::now()).folders, 0);
        assert!(s.0.exists());
    }

    #[test]
    fn a_new_folder_is_kept_even_when_empty() {
        let s = Scratch::new("newdir");
        s.file("d/old.tmp", 10, 30);
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        remove_temp(&plan, SystemTime::now());
        assert!(s.0.join("d").exists());
    }

    #[test]
    fn a_file_changed_after_the_plan_is_left() {
        let s = Scratch::new("changed");
        let path = s.file("old.tmp", 10, 30);
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        std::fs::write(&path, b"in use again").unwrap();
        let removed = remove_temp(&plan, SystemTime::now());
        assert_eq!((removed.files, removed.changed), (0, 1));
        assert!(path.exists());
    }

    #[test]
    fn an_open_file_fails_and_is_left() {
        let s = Scratch::new("open");
        let path = s.file("held.tmp", 10, 30);
        let plan = plan_temp(std::slice::from_ref(&s.0), SystemTime::now());
        use std::os::windows::fs::OpenOptionsExt;
        let held = File::options()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        let removed = remove_temp(&plan, SystemTime::now());
        drop(held);
        assert_eq!((removed.files, removed.failed), (0, 1));
        assert!(path.exists());
    }

    #[test]
    fn the_temp_roots_are_real_folders_without_duplicates() {
        let roots = temp_roots();
        assert!(!roots.is_empty());
        assert!(roots.iter().all(|r| r.to_string_lossy().len() > 3));
        let mut keys: Vec<String> = roots
            .iter()
            .map(|r| r.to_string_lossy().trim_end_matches('\\').to_lowercase())
            .collect();
        keys.dedup();
        assert_eq!(keys.len(), roots.len());
    }

    #[test]
    fn the_recycle_bin_reads_without_changing() {
        let first = recycle_bin().unwrap();
        assert_eq!(recycle_bin().unwrap(), first);
    }
}
