//! The place a stopped step keeps beside the image (the edge check's, Fill the gaps'): a small
//! file read and removed only through the image's folder, opened and checked through the
//! source's guard, never by a path that can lead somewhere else by then. It is kept with
//! `writer::save_map`.
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

use serde::de::DeserializeOwned;

use super::dest::{self, Folder, Guard};
use super::{writer, BlockSource};

/// The folder of `image`, opened and checked through the guard of `source` (never on its
/// drive), for the files kept and written beside the image.
pub fn held(image: &Path, source: &dyn BlockSource) -> Result<(Guard, Folder), String> {
    let guard = Guard::of(&source.protected());
    let parent = image
        .parent()
        .ok_or_else(|| format!("{} is not a file in a folder", image.display()))?;
    let folder = guard
        .base(parent)
        .map_err(|e| format!("{} could not be opened: {e}", parent.display()))?;
    Ok((guard, folder))
}

/// The place kept as `name` in `folder`; None when there is none or it is not a `T`.
pub fn read<T: DeserializeOwned>(guard: &Guard, folder: &Folder, name: &OsStr) -> Option<T> {
    let mut kept = Vec::new();
    writer::open_earlier(guard, folder, name)
        .ok()?
        .read_to_end(&mut kept)
        .ok()?;
    serde_json::from_slice(&kept).ok()
}

/// Removes the place kept as `name` in `folder`, a finished step's; why not, when not. A
/// place that is not there is gone already.
pub fn remove(guard: &Guard, folder: &Folder, name: &OsStr) -> Option<String> {
    let removed = match writer::open_earlier(guard, folder, name) {
        Ok(file) => dest::remove(file),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    removed
        .err()
        .map(|e| format!("The kept place could not be removed: {e}."))
}

/// The one end of a run that keeps a place: `save_log` saves and checks the run's event log,
/// then the place `name` is removed when the run `complete`d and the log saved, and every
/// problem on the way (the folder that could not be opened, the log, the removal) is
/// returned. No other code removes a place, so no exit of a run can skip the log or the check.
pub fn finish(
    held: &Result<(Guard, Folder), String>,
    name: &OsStr,
    complete: bool,
    save_log: impl FnOnce() -> Option<String>,
) -> Vec<String> {
    let mut problems: Vec<String> = held.as_ref().err().cloned().into_iter().collect();
    let logged = save_log();
    let saved = logged.is_none();
    problems.extend(logged);
    if let (true, true, Ok((guard, folder))) = (complete, saved, held) {
        problems.extend(remove(guard, folder, name));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::MemDisk;

    /// A place is read and removed through the held folder; one that is not there reads as
    /// none and is removed without complaint.
    #[test]
    fn a_place_is_read_and_removed_through_the_held_folder() {
        let dir = std::env::temp_dir().join(format!("diagtool-place-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (guard, folder) = held(&dir.join("image.img"), &MemDisk::new(vec![0; 512])).unwrap();
        let name = OsStr::new("image.edges.json");
        assert_eq!(read::<Vec<u32>>(&guard, &folder, name), None);
        assert_eq!(remove(&guard, &folder, name), None);
        std::fs::write(dir.join(name), b"[1,2]").unwrap();
        assert_eq!(read::<Vec<u32>>(&guard, &folder, name), Some(vec![1, 2]));
        assert_eq!(read::<String>(&guard, &folder, name), None);
        assert_eq!(remove(&guard, &folder, name), None);
        assert!(!dir.join(name).exists());
        drop(folder);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the finalizer removes the place only for a complete run whose log saved,
    /// and returns the folder's, the log's and the removal's problems.
    #[test]
    fn the_finalizer_removes_the_place_only_after_a_saved_log_and_says_every_problem() {
        let dir = std::env::temp_dir().join(format!("diagtool-finish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let beside = held_in(&dir.join("image.img"));
        let name = OsStr::new("image.fill.json");
        let kept = || dir.join(name).exists();
        std::fs::write(dir.join(name), b"{}").unwrap();
        assert!(finish(&beside, name, false, || None).is_empty());
        assert!(kept(), "an incomplete run lost its place");
        assert_eq!(
            finish(&beside, name, true, || Some("log".into())),
            vec!["log".to_string()]
        );
        assert!(kept(), "the place went before the log was saved");
        assert!(finish(&beside, name, true, || None).is_empty());
        assert!(!kept());
        let no_folder = held_in(&dir.join("absent").join("image.img"));
        let problems = finish(&no_folder, name, true, || Some("log".into()));
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains("could not be opened"), "{problems:?}");
        drop(beside);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn held_in(image: &Path) -> Result<(Guard, Folder), String> {
        held(image, &MemDisk::new(vec![0; 512]))
    }
}
