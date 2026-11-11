//! Photos first: which areas of a drive hold photos and videos, from its file systems' own
//! records (NTFS's MFT, FAT and exFAT tables), deleted files included, so a rescue image can
//! read those areas before the rest, for a drive that reads some files and times out on
//! others, so as many photos as possible come back intact. This module only lists; `image::Rescue` reads what it lists into the image.
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};

use super::fs::{self, parts, Data, Place, State, Why};
use super::reader::Reader;

/// The file name endings taken as photos and videos: JPEG, HEIC/HEIF, PNG, GIF, TIFF, the
/// camera raw formats CR2, CR3, NEF, ARW, DNG, ORF, RAF and RW2, and MP4 and MOV video.
pub const ENDINGS: &[&str] = &[
    "jpg", "jpeg", "jpe", "heic", "heif", "png", "gif", "tif", "tiff", "cr2", "cr3", "nef", "arw",
    "dng", "orf", "raf", "rw2", "mp4", "mov",
];

/// Whether a file of this name is a photo or video, by its ending.
pub fn is_photo(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, ending)| ENDINGS.contains(&ending.to_ascii_lowercase().as_str()))
}

/// Photos first's options for a rescue image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhotosFirst {
    /// Read the photos' and videos' areas before the rest. The window starts with it on.
    pub enabled: bool,
    /// The longest the file systems' records may take to read, in seconds, 10 to 3600;
    /// past it the rescue goes on in the usual order. Default 900.
    pub records_limit_secs: u64,
}

impl Default for PhotosFirst {
    fn default() -> Self {
        Self {
            enabled: true,
            records_limit_secs: 900,
        }
    }
}

impl PhotosFirst {
    pub fn off() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Refuses values outside their bounds.
    pub fn check(&self) -> Result<(), String> {
        if !(10..=3600).contains(&self.records_limit_secs) {
            return Err(format!(
                "records_limit_secs must be 10 to 3600, not {}",
                self.records_limit_secs
            ));
        }
        Ok(())
    }
}

/// What the file systems list as photos and videos.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhotoList {
    /// Photo and video files found, deleted ones included.
    pub files: u64,
    /// Of them, deleted.
    pub deleted: u64,
    /// Their size in bytes.
    pub bytes: u64,
    /// The source areas holding them, as (start, end) byte offsets, sorted and merged.
    /// Small files kept inside NTFS's records have none: they come with the records.
    pub extents: Vec<(u64, u64)>,
    /// The volumes read, for people: "Partition 1, NTFS, 500.1 GB at 1.0 MB".
    pub volumes: Vec<String>,
    /// What could not be read or made sense of.
    pub notes: Vec<String>,
}

/// Lists the photos and videos on every volume the partition tables name (or the source
/// itself when it is one volume). A deleted file whose start was read and is not what its
/// type begins with, or whose space the volume now gives to another file, is left out: its
/// area no longer holds it. Err when no volume this tool reads is found.
pub fn list(reader: &mut Reader, stop: &AtomicBool) -> Result<PhotoList, String> {
    let progress = fs::Progress::default();
    let finds = parts::find(reader, parts::Search::Tables, stop, &progress);
    let mut list = PhotoList {
        notes: finds.notes,
        ..PhotoList::default()
    };
    if finds.volumes.is_empty() {
        return Err("no file system this tool reads was found".into());
    }
    let len = reader.len();
    let mut extents = Vec::new();
    let mut merged = 0usize;
    let mut read_any = false;
    let mut unplaced = 0u64;
    for volume in &finds.volumes {
        let listing = match fs::scan(reader, volume, stop, &progress) {
            Ok(listing) => listing,
            Err(why) => {
                list.notes.push(format!("{}: {why}", volume.describe()));
                continue;
            }
        };
        read_any = true;
        list.volumes.push(volume.describe());
        list.notes.extend(
            listing
                .notes
                .into_iter()
                .map(|note| format!("{}: {note}", volume.describe())),
        );
        for file in listing.files {
            let gone =
                file.state == State::Overwritten || matches!(file.why, Some(Why::Mismatch(_)));
            if !is_photo(&file.name) || gone {
                continue;
            }
            let mut areas = Vec::new();
            if let Data::Runs(runs) = file.data {
                for run in fs::cut(runs, file.size) {
                    if let Place::At(start) = run.place {
                        let end = start.saturating_add(run.len).min(len);
                        if start < end {
                            areas.push((start, end));
                        }
                    }
                }
                // A record that no longer says where its content is (seen with JPEGs deleted
                // on a Windows 11 NTFS volume) gives nothing to read first.
                if areas.is_empty() && file.size > 0 {
                    unplaced += 1;
                    continue;
                }
            }
            list.files += 1;
            list.deleted += u64::from(file.deleted);
            list.bytes += file.size;
            extents.extend(areas);
            // Merged as they grow, so the areas held stay no more than the distinct ones
            // (the listing that gave them was held within its scan's budget).
            if extents.len() >= merged.saturating_mul(2).max(MERGE_AT) {
                extents = merge(extents);
                merged = extents.len();
            }
        }
        extents = merge(extents);
        merged = extents.len();
    }
    if unplaced > 0 {
        let (count, have) = if unplaced == 1 {
            ("1 photo or video".to_string(), "has")
        } else {
            (format!("{unplaced} photos or videos"), "have")
        };
        list.notes.push(format!(
            "{count} {have} no recorded place on the drive (their records give none); Find files by type may still find them"
        ));
    }
    if !read_any {
        return Err(list.notes.join("; "));
    }
    list.extents = merge(extents);
    Ok(list)
}

/// Areas gathered before the first merge.
const MERGE_AT: usize = 1 << 16;

/// Sorts and joins touching or overlapping areas.
fn merge(mut areas: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    areas.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(areas.len());
    for (start, end) in areas {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::MemDisk;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/recovery")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn photo_and_video_endings_are_known() {
        for name in [
            "a.JPG",
            "b.heic",
            "IMG_1.CR3",
            "c.rw2",
            "clip.MOV",
            "x.y.tiff",
        ] {
            assert!(is_photo(name), "{name}");
        }
        for name in ["notes.txt", "jpg", "report.docx", "a.mp3"] {
            assert!(!is_photo(name), "{name}");
        }
        assert_eq!(
            merge(vec![(10, 20), (0, 5), (20, 30), (25, 26)]),
            vec![(0, 5), (10, 30)]
        );
    }

    /// The fixtures' photos and videos, live and deleted, are listed with their areas; the
    /// other files are not.
    #[test]
    fn photos_are_listed_from_the_file_systems_records() {
        let stop = AtomicBool::new(false);
        // NTFS: photo.jpg and image.png in use, old.gif deleted.
        let mut reader = Reader::new(Box::new(MemDisk::new(fixture("ntfs.img"))));
        let found = list(&mut reader, &stop).unwrap();
        assert_eq!((found.files, found.deleted), (3, 1), "{found:?}");
        assert!(!found.extents.is_empty());
        assert!(found.volumes[0].contains("NTFS"), "{found:?}");
        // Two areas: one of the three is small enough to live in its NTFS record.
        assert_eq!(found.extents.len(), 2, "{found:?}");
        // FAT32: two JPEGs in use, anim.gif, clip.mp4 and Beach clip.mov deleted.
        let mut reader = Reader::new(Box::new(MemDisk::new(fixture("fat32.img"))));
        let found = list(&mut reader, &stop).unwrap();
        assert_eq!((found.files, found.deleted), (5, 3), "{found:?}");
        let held: u64 = found.extents.iter().map(|(s, e)| e - s).sum();
        assert!(held >= found.bytes, "{held} of {}", found.bytes);
        // No file system: said so.
        let mut reader = Reader::new(Box::new(MemDisk::new(vec![0x5A; 1 << 20])));
        assert!(list_err(&mut reader).contains("no file system"));
    }

    fn list_err(reader: &mut Reader) -> String {
        list(reader, &AtomicBool::new(false)).unwrap_err()
    }
}
