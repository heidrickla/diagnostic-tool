//! Repair on a copy: never on the source drive or its image. A differencing disk is made
//! over the image (the image, with its fixed-VHD footer, is the read-only parent), the copy
//! is attached read-write, and the repairs write only to it: a partition table rebuilt from
//! the lost-volume search, and `chkdsk /f` on one of its volumes. The copy holds only what
//! the repairs changed. It is kept as the repaired copy or discarded.
//!
//! The copy is a VHD, not a VHDX: Windows makes a differencing disk only in its parent's
//! format ("The format ... does not match that for parent disk" for a VHDX over a VHD).
//!
//! The copy is made by Windows' virtual disk service at a path resolved from a held,
//! checked folder handle (by volume GUID, with no letter or junction left to redirect it),
//! and the file it made is opened by its one name in that folder and checked to be off the
//! source disk before it is attached; a copy that landed there is removed.
//!
//! The one handle that can write to the copy's disk is a `handles::CopyDisk`, opened once,
//! right after the attach, by the number Windows gave the copy; it refuses the source disk
//! and the disk Windows runs from. It is held until the detach, and before every write, and
//! before chkdsk, it is checked through itself to still be the copy: the virtual disk file
//! behind it (storage dependency information) must be the file this repair made. A disk
//! number is never looked up again to write.
use std::ffi::OsStr;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::{Child as Process, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Storage::Vhd::{
    CreateVirtualDisk, GetVirtualDiskInformation, CREATE_VIRTUAL_DISK_FLAG_NONE,
    CREATE_VIRTUAL_DISK_PARAMETERS, CREATE_VIRTUAL_DISK_VERSION_2, GET_VIRTUAL_DISK_INFO,
    GET_VIRTUAL_DISK_INFO_PARENT_LOCATION, OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS,
    OPEN_VIRTUAL_DISK_PARAMETERS, OPEN_VIRTUAL_DISK_VERSION_2, VIRTUAL_DISK_ACCESS_NONE,
    VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
};
use windows_sys::Win32::System::Ioctl::{
    CREATE_DISK, DRIVE_LAYOUT_INFORMATION_EX, PARTITION_INFORMATION_EX, PARTITION_STYLE_GPT,
    PARTITION_STYLE_MBR,
};

use super::dest::{Folder, Guard};
use super::fs::parts::{Finds, Unread};
use super::fs::{FsKind, Origin, Volume};
use super::ledger::Ledger;
use super::vdisk::{self, error_text, DiskHandle, Event, Footed, VolumeInfo};
use crate::handles::CopyDisk;
use crate::tools::drives::bytes_text;
use serde::{Deserialize, Serialize};

/// GPT's basic data partition type, EBD0A0A2-B9E5-4433-87C0-68B6B72699C7.
const BASIC_DATA: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0xebd0a0a2_b9e5_4433_87c0_68b6b72699c7);
/// The first byte a GPT partition may use with 512-byte sectors: after the header and a
/// 128-entry table.
const GPT_FIRST: u64 = 34 * 512;

// ---- the rebuilt partition table ----------------------------------------------------------

/// One partition of a rebuilt table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub start: u64,
    pub len: u64,
    /// "NTFS", or "unknown" for a current partition whose file system this tool does not
    /// read (BitLocker, for one).
    pub what: String,
    /// The MBR type byte: 07 for NTFS and exFAT (and BitLocker), 0C, 0E or 01 for FAT.
    pub mbr_type: u8,
}

impl Entry {
    pub fn describe(&self) -> String {
        format!(
            "{}, {} at {}",
            self.what,
            bytes_text(self.len),
            bytes_text(self.start)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Style {
    Mbr,
    Gpt,
}

/// A partition table to write: its style and its partitions in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub style: Style,
    pub entries: Vec<Entry>,
    /// Volumes the search found that were left out, and why, for people.
    pub left_out: Vec<String>,
}

fn mbr_type(kind: FsKind) -> u8 {
    match kind {
        FsKind::Ntfs | FsKind::ExFat => 0x07,
        FsKind::Fat32 => 0x0C,
        FsKind::Fat16 => 0x0E,
        FsKind::Fat12 => 0x01,
    }
}

/// Builds a partition table from what the lost-volume search found on a disk of
/// `disk_len` bytes: every volume it found and every current partition, in order of
/// place. Where two overlap, a current partition wins over a lost volume, and of two lost
/// volumes the one found first. MBR when four or fewer partitions all end within 2 TiB,
/// GPT otherwise.
pub fn plan_table(finds: &Finds, disk_len: u64) -> Result<Table, String> {
    if finds.volumes.iter().any(|v| v.origin == Origin::Whole) {
        return Err("The image holds one volume and no partition table, and needs none.".into());
    }
    let current = |o: &Origin| matches!(o, Origin::Mbr(_) | Origin::Gpt(_));
    // Current partitions first, so they win where they overlap a lost volume.
    let mut candidates: Vec<(Entry, bool, String)> = Vec::new();
    let mut ordered: Vec<&Volume> = finds.volumes.iter().collect();
    ordered.sort_by_key(|v| !current(&v.origin));
    for v in ordered {
        candidates.push((
            Entry {
                start: v.start,
                len: v.len.div_ceil(512) * 512,
                what: v.kind.label().to_string(),
                mbr_type: mbr_type(v.kind),
            },
            current(&v.origin),
            v.describe(),
        ));
    }
    for u in &finds.unread {
        candidates.push((
            Entry {
                start: u.start,
                len: u.len,
                what: "unknown file system".into(),
                mbr_type: 0x07,
            },
            true,
            Unread::describe(u),
        ));
    }
    candidates.sort_by_key(|(_, is_current, _)| !*is_current);
    let mut entries: Vec<Entry> = Vec::new();
    let mut left_out = Vec::new();
    for (entry, _, about) in candidates {
        let end = entry.start.saturating_add(entry.len);
        if entry.start == 0 || !entry.start.is_multiple_of(512) || end > disk_len {
            left_out.push(format!("{about}: it does not fit on the disk"));
            continue;
        }
        if entries
            .iter()
            .any(|e| e.start < end && entry.start < e.start + e.len)
        {
            left_out.push(format!(
                "{about}: it overlaps a partition already in the table"
            ));
            continue;
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err("The search found no volume to put in a partition table.".into());
    }
    entries.sort_by_key(|e| e.start);
    let fits_mbr = entries.len() <= 4
        && entries
            .iter()
            .all(|e| e.start + e.len <= (u64::from(u32::MAX)) * 512);
    let style = if fits_mbr { Style::Mbr } else { Style::Gpt };
    if style == Style::Gpt {
        let last = disk_len.saturating_sub(GPT_FIRST - 512);
        if entries
            .iter()
            .any(|e| e.start < GPT_FIRST || e.start + e.len > last)
        {
            return Err("The volumes found need a GPT table, and one of them lies where GPT keeps its own records.".into());
        }
    }
    Ok(Table {
        style,
        entries,
        left_out,
    })
}

/// The bytes of a DRIVE_LAYOUT_INFORMATION_EX for `table`, in a buffer of u64 so its
/// 64-bit fields are aligned.
fn layout_bytes(table: &Table, signature: u32, disk_id: [u8; 16]) -> (Vec<u64>, usize) {
    let head = std::mem::size_of::<DRIVE_LAYOUT_INFORMATION_EX>()
        - std::mem::size_of::<PARTITION_INFORMATION_EX>();
    let entry = std::mem::size_of::<PARTITION_INFORMATION_EX>();
    // MBR layouts are given in fours.
    let count = match table.style {
        Style::Mbr => 4,
        Style::Gpt => table.entries.len(),
    };
    let size = head + entry * count;
    let mut buffer = vec![0u64; size.div_ceil(8)];
    let base = buffer.as_mut_ptr().cast::<u8>();
    // SAFETY: the buffer holds the header and `count` entries, aligned to 8.
    unsafe {
        let layout = &mut *base.cast::<DRIVE_LAYOUT_INFORMATION_EX>();
        layout.PartitionCount = count as u32;
        match table.style {
            Style::Mbr => {
                layout.PartitionStyle = PARTITION_STYLE_MBR as u32;
                layout.Anonymous.Mbr.Signature = signature;
            }
            Style::Gpt => {
                layout.PartitionStyle = PARTITION_STYLE_GPT as u32;
                layout.Anonymous.Gpt.DiskId = guid(disk_id);
                layout.Anonymous.Gpt.MaxPartitionCount = 128;
            }
        }
        for (index, e) in table.entries.iter().enumerate() {
            let p = &mut *base
                .add(head + index * entry)
                .cast::<PARTITION_INFORMATION_EX>();
            p.StartingOffset = e.start as i64;
            p.PartitionLength = e.len as i64;
            p.PartitionNumber = index as u32 + 1;
            p.RewritePartition = true;
            match table.style {
                Style::Mbr => {
                    p.PartitionStyle = PARTITION_STYLE_MBR;
                    p.Anonymous.Mbr.PartitionType = e.mbr_type;
                    p.Anonymous.Mbr.RecognizedPartition = true;
                    p.Anonymous.Mbr.HiddenSectors = (e.start / 512) as u32;
                }
                Style::Gpt => {
                    p.PartitionStyle = PARTITION_STYLE_GPT;
                    p.Anonymous.Gpt.PartitionType = BASIC_DATA;
                    let mut id = rand::random::<[u8; 16]>();
                    id[6] = (id[6] & 0x0F) | 0x40;
                    id[8] = (id[8] & 0x3F) | 0x80;
                    p.Anonymous.Gpt.PartitionId = guid(id);
                    let name: Vec<u16> = "Recovered".encode_utf16().collect();
                    p.Anonymous.Gpt.Name[..name.len()].copy_from_slice(&name);
                }
            }
        }
        // MBR slots past the table's entries stay unused but must be marked to rewrite.
        if table.style == Style::Mbr {
            for index in table.entries.len()..4 {
                let p = &mut *base
                    .add(head + index * entry)
                    .cast::<PARTITION_INFORMATION_EX>();
                p.PartitionStyle = PARTITION_STYLE_MBR;
                p.RewritePartition = true;
            }
        }
    }
    (buffer, size)
}

fn guid(bytes: [u8; 16]) -> windows_sys::core::GUID {
    windows_sys::core::GUID::from_u128(u128::from_be_bytes(bytes))
}

// ---- the copy ------------------------------------------------------------------------------

/// "<image name> repaired copy.vhd" in `folder`, numbered so nothing is overwritten.
pub fn copy_path(image: &Path, folder: &Path) -> PathBuf {
    let stem = image
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Image".into());
    let mut path = folder.join(format!("{stem} repaired copy.vhd"));
    let mut n = 2;
    while path.exists() {
        path = folder.join(format!("{stem} repaired copy ({n}).vhd"));
        n += 1;
    }
    path
}

/// A repair under way: the image with its footer as the read-only parent, and the copy
/// attached read-write. Dropping it detaches the copy, keeps it, and takes the footer off.
pub struct Repair {
    handle: Option<DiskHandle>,
    /// The copy's disk, open for writing from the attach to the detach.
    writer: Option<CopyDisk>,
    footed: Footed,
    /// Where the copy is, for people.
    pub copy: PathBuf,
    /// The same file by its volume GUID, resolved from the held folder: every open, attach
    /// and removal of the copy goes through this.
    at: PathBuf,
    /// The folder the copy is in, held for the whole repair so it cannot be swapped.
    _folder: Option<Folder>,
    /// The copy's disk number while attached, as Windows gave it at the attach.
    pub disk: u32,
    source: crate::recovery::dest::Protected,
    pub ledger: Ledger,
    entry: usize,
}

impl Repair {
    /// Makes the copy of `image` in `folder` (never on `source`, the disk being recovered)
    /// and attaches it read-write.
    fn start(
        image: &Path,
        folder: &Path,
        source: &crate::recovery::dest::Protected,
    ) -> Result<Self, String> {
        // The drive the image was made from, as this open of it says.
        let made = super::ImageFile::open(image)
            .map_err(|e| format!("{} could not be opened: {e}", image.display()))?;
        let source = &source.clone().join(super::BlockSource::protected(&made));
        drop(made);
        super::check_destination(folder, source)?;
        // Held from here to the end: checked through its handle, and every path to the copy
        // is resolved from it, so no junction or letter changed later can move the copy.
        let guard = Guard::of(source);
        let base = guard
            .base(folder)
            .map_err(|e| format!("{} could not be used: {e}", folder.display()))?;
        let resolved = base.resolved()?;
        let footed = Footed::put_on(image)?;
        let copy = copy_path(image, folder);
        let name = copy
            .file_name()
            .map(OsStr::to_os_string)
            .ok_or_else(|| "The copy has no name.".to_string())?;
        let at = PathBuf::from(format!("{resolved}\\{}", name.to_string_lossy()));
        make_copy(image, &at, &footed).map_err(|why| match why {
            vdisk::Unanswered::Code(error) => format!(
                "The copy {} could not be made: {}",
                copy.display(),
                error_text(error)
            ),
            no_answer => format!(
                "The copy {} was not made: {}.",
                copy.display(),
                no_answer.text("making it")
            ),
        })?;
        let mut ledger = Ledger::default();
        // The file Windows made, entered first, then opened by its name in the held folder
        // and checked through its own handle; one on the source disk is removed there and
        // then.
        let (entry, file) = super::writer::adopt(
            &guard,
            &base,
            &name,
            &mut ledger,
            super::writer::Entry {
                tag: 0,
                source: image.to_path_buf(),
                note: "repaired copy (differencing disk)".into(),
                size: 0,
            },
        );
        let mut repair = Self {
            handle: None,
            writer: None,
            footed,
            copy: copy.clone(),
            at: at.clone(),
            _folder: Some(base),
            disk: 0,
            source: source.clone(),
            ledger,
            entry,
        };
        let file = match file {
            Ok(file) => file,
            Err(why) => {
                if std::fs::metadata(&at).is_err() {
                    repair.ledger.removed(entry, why.to_string());
                }
                let why = format!(
                    "{} was not kept: {why}. Nothing was written to it.",
                    copy.display()
                );
                return Err(match repair.finish(false) {
                    Ok(_) => why,
                    Err(more) => format!("{why} {more}"),
                });
            }
        };
        let handle = vdisk::open_disk(&at, VIRTUAL_STORAGE_TYPE_DEVICE_VHD, false)
            .map_err(|code| format!("The copy could not be opened: {}", error_text(code)));
        let attached = handle.and_then(|handle| {
            let handle = vdisk::attach(handle, false, &at, &repair.footed).map_err(|e| {
                format!(
                    "Windows did not attach the copy: {}",
                    e.text("attaching the copy")
                )
            })?;
            let bound = vdisk::physical_disk(&handle)
                .and_then(|disk| Ok((disk, CopyDisk::open(disk, source, file)?)));
            match bound {
                Ok((disk, writer)) => Ok((handle, disk, writer)),
                Err(why) => match vdisk::detach(handle, &at, &repair.footed) {
                    Ok(()) => Err(why),
                    Err(e) => Err(format!(
                        "{why} Windows reported an error detaching the copy: {}",
                        e.text("detaching the copy")
                    )),
                },
            }
        });
        match attached {
            Ok((handle, disk, writer)) => {
                repair.handle = Some(handle);
                repair.writer = Some(writer);
                repair.disk = disk;
                Ok(repair)
            }
            Err(why) => match repair.finish(false) {
                Ok(_) => Err(why),
                Err(more) => Err(format!("{why} {more}")),
            },
        }
    }

    /// The copy's disk number now, checked through the held handle to still be the copy.
    fn checked(&self) -> Result<(&CopyDisk, u32), String> {
        let (Some(_), Some(writer)) = (&self.handle, &self.writer) else {
            return Err("The copy is no longer attached.".into());
        };
        let number = writer.check()?;
        if let Some(refused) = Guard::of(&self.source).refuses_disk(number) {
            return Err(format!(
                "Disk {number} is never written: {}.",
                refused.reason
            ));
        }
        Ok((writer, number))
    }

    /// The image the copy is made over.
    pub fn image(&self) -> &Path {
        &self.footed.image
    }

    pub fn volumes(&self) -> Vec<VolumeInfo> {
        vdisk::volumes_of_disk(self.disk)
    }

    /// Writes `table` to the copy through the handle held since the attach, checked before
    /// each write to still be the copy, and has Windows read it again. Ok holds a note when
    /// Windows was not asked to read it.
    fn write_layout(&self, table: &Table) -> Result<Option<String>, String> {
        let (disk, _) = self.checked()?;
        let style = match table.style {
            Style::Mbr => PARTITION_STYLE_MBR,
            Style::Gpt => PARTITION_STYLE_GPT,
        };
        let signature = rand::random::<u32>() | 1;
        let mut disk_id = rand::random::<[u8; 16]>();
        disk_id[6] = (disk_id[6] & 0x0F) | 0x40;
        disk_id[8] = (disk_id[8] & 0x3F) | 0x80;
        let mut create = CREATE_DISK {
            PartitionStyle: style,
            ..Default::default()
        };
        match table.style {
            Style::Mbr => create.Anonymous.Mbr.Signature = signature,
            Style::Gpt => {
                create.Anonymous.Gpt.DiskId = guid(disk_id);
                create.Anonymous.Gpt.MaxPartitionCount = 128;
            }
        }
        let (layout, size) = layout_bytes(table, signature, disk_id);
        // A volume Windows mounted from what is left of the copy's old table is closed for
        // the write. A fresh, empty table first, since the copy's may be missing or damaged;
        // then the rebuilt one.
        // The whole set, or nothing is written: a volume Windows does not place may be on the
        // copy, and a table written under it leaves it open on the old layout.
        let mounted = super::target::every_volume_on(self.disk)
            .map_err(|why| format!("Nothing was written to the copy: {why}."))?;
        disk.write_table(&create, &layout, size, &mounted)
    }

    /// Closes the copy's volumes, then detaches it holding them closed, keeps or removes it,
    /// and takes the footer off. A volume that does not close, or a set of volumes that
    /// cannot be read whole, stops it there: the copy stays attached, since detaching under
    /// a mounted volume cuts off what Windows has not yet written to it. A kept copy is
    /// entered whole only once its detach has succeeded; otherwise it is partial, and its
    /// record says why.
    fn finish(&mut self, keep: bool) -> Result<String, String> {
        let mut problems = Vec::new();
        // The copy's volumes are written out and closed first, and held closed through the
        // detach: Windows mounts a volume again after chkdsk, and a detach under a mounted
        // volume cut off its last writes (the kept copy then did not mount) or waited for
        // them up to 180 s.
        let mut closed = Vec::new();
        let mut unclosed = Vec::new();
        if let (Some(_), Some(writer)) = (&self.handle, &self.writer) {
            match super::target::every_volume_on(self.disk) {
                Ok(volumes) => {
                    for guid in volumes {
                        match writer.close_volume(&guid) {
                            Ok(handle) => closed.push(handle),
                            Err(why) => unclosed.push(why),
                        }
                    }
                }
                Err(why) => {
                    unclosed.push(format!("the copy's volumes could not all be found: {why}"))
                }
            }
        }
        if !unclosed.is_empty() {
            // The volumes that did close are let go again: the copy stays in use.
            drop(closed);
            return Err(format!(
                "{} The copy was not detached and stays attached, since detaching it now would cut off what Windows has not yet written to it. Close whatever has its volumes open, then end the repair again.",
                unclosed
                    .iter()
                    .map(|why| format!("Before the detach, {why}."))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        // The writable handle goes next: it is never held past the detach. The closed
        // volumes travel with the detach and are let go only once Windows has answered it.
        self.writer = None;
        // None once the copy is let go; else why it may not have all its writes.
        let mut unfinished = None;
        if let Some(handle) = self.handle.take() {
            if let Err(e) = vdisk::detach_holding(handle, &self.at, &self.footed, closed) {
                let why = format!(
                    "Windows reported an error detaching the copy: {}",
                    e.text("detaching the copy")
                );
                problems.push(why.clone());
                unfinished = Some(why);
            }
        }
        let size = std::fs::metadata(&self.at).map(|m| m.len());
        if self.ledger.get(self.entry).state == super::ledger::State::Open {
            let removed = if keep {
                None
            } else {
                Some(remove_after_detach(&self.at))
            };
            match (removed, unfinished) {
                (Some(Ok(())), _) => self.ledger.removed(self.entry, "discarded as chosen"),
                (Some(Err(why)), _) => {
                    problems.push(why.clone());
                    self.ledger.partial(self.entry, format!("not discarded: {why}"));
                }
                (None, Some(why)) => self.ledger.partial(
                    self.entry,
                    format!("kept, but its detach did not succeed, so it may lack its last writes: {why}"),
                ),
                // Entered whole only now: the detach that makes it complete has succeeded.
                (None, None) => self.ledger.whole(self.entry),
            }
        }
        if let Err(why) = self.footed.take_off() {
            problems.push(why);
        }
        let output = self.ledger.get(self.entry);
        let text = match &output.state {
            super::ledger::State::Removed(_) => format!("{} was discarded.", self.copy.display()),
            super::ledger::State::Partial(why) => format!(
                "The copy {} is kept but not whole: {why}. Check it with chkdsk before relying on it, or discard it.",
                self.copy.display()
            ),
            _ => format!(
                "The repaired copy is kept: {} ({}). It holds only the changes and needs {} to stay where it is, unchanged; open it with Open an image as a drive.",
                self.copy.display(),
                match &size {
                    Ok(size) => bytes_text(*size),
                    Err(e) => format!("its size could not be read: {e}"),
                },
                self.footed.image.display()
            ),
        };
        if problems.is_empty() {
            Ok(text)
        } else {
            Err(format!("{text} {}", problems.join(" ")))
        }
    }
}

/// Copies whose volumes would not close when their window went: attached for as long as
/// this process runs, never detached under a mounted volume by this program.
static STILL_ATTACHED: std::sync::Mutex<Vec<(DiskHandle, CopyDisk, vdisk::FootHold)>> =
    std::sync::Mutex::new(Vec::new());

impl Drop for Repair {
    fn drop(&mut self) {
        // A window closed without a choice keeps the copy: nothing is lost unasked. What
        // failed in letting it go is recorded where the report finds it.
        if let Err(why) = self.finish(true) {
            let mut why = why;
            if let (Some(handle), Some(writer)) = (self.handle.take(), self.writer.take()) {
                // A volume did not close, so the copy stays attached until this process
                // ends, which lets it go; the image's footer then comes off at the next
                // start, and the end of the process does not wait for it.
                let keep = self.footed.keep();
                keep.leave_to_next_start();
                STILL_ATTACHED
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((handle, writer, keep));
                why.push_str(" It stays attached until this program ends, and the footer on the image comes off when the recovery window next starts.");
            }
            crate::handles::record_unseen("Repair on a copy", &why);
        }
    }
}

/// Makes the copy at `at`, a differencing disk over `image`, within `ATTACH_LIMIT`
/// (`timed::owned`): Windows opens the image to make it, so `footed`'s footer stays due
/// until the call has ended. A copy Windows makes after the wait is closed and removed
/// again at once, and recorded; nothing else is ever at `at`, a name no file had.
fn make_copy(image: &Path, at: &Path, footed: &Footed) -> Result<(), vdisk::Unanswered> {
    let job = super::timed::Job::new(
        format!("making the copy {}", at.display()),
        vdisk::ATTACH_LIMIT,
    )
    .answered_within(vdisk::VDISK_ANSWER)
    // A late copy is removed again (20 tries 100 ms apart), and the footer then comes off.
    .undone_within(COPY_UNDO + vdisk::FOOTER_UNDO)
    .settled_by(super::pending::Pending::Copy {
        at: at.to_path_buf(),
    });
    let keep = footed.keep();
    let image = image.to_path_buf();
    let at = at.to_path_buf();
    let late_at = at.clone();
    match super::timed::owned(
        job,
        None,
        move || {
            let parent = super::disk::wide(&image.to_string_lossy());
            let mut params = CREATE_VIRTUAL_DISK_PARAMETERS {
                Version: CREATE_VIRTUAL_DISK_VERSION_2,
                ..Default::default()
            };
            // The Version2 arm of a zeroed union.
            params.Anonymous.Version2.ParentPath = parent.as_ptr();
            params.Anonymous.Version2.ParentVirtualStorageType =
                vdisk::storage_type(VIRTUAL_STORAGE_TYPE_DEVICE_VHD);
            let kind = vdisk::storage_type(VIRTUAL_STORAGE_TYPE_DEVICE_VHD);
            let wide_at = super::disk::wide(&at.to_string_lossy());
            let mut raw = std::ptr::null_mut();
            // SAFETY: every pointer is valid for the call; the handle is written on success.
            let error = unsafe {
                CreateVirtualDisk(
                    &kind,
                    wide_at.as_ptr(),
                    VIRTUAL_DISK_ACCESS_NONE,
                    std::ptr::null_mut(),
                    CREATE_VIRTUAL_DISK_FLAG_NONE,
                    0,
                    &params,
                    std::ptr::null(),
                    &mut raw,
                )
            };
            let made = (error == 0).then(|| DiskHandle(raw));
            (error, made, keep)
        },
        move |(error, made, keep): (u32, Option<DiskHandle>, vdisk::FootHold)| {
            if error != 0 {
                return;
            }
            drop(made);
            let text = match remove_after_detach(&late_at) {
                Ok(()) => format!(
                    "{} was made after its time limit, so it was removed again.",
                    late_at.display()
                ),
                Err(why) => format!("{} was made after its time limit. {why}", late_at.display()),
            };
            crate::handles::record_unseen("Repair on a copy", &text);
            // Windows has let the image go: a footer still due comes off now.
            drop(keep);
        },
    ) {
        super::timed::Waited::Done((0, _, _)) => Ok(()),
        super::timed::Waited::Done((error, _, _)) => Err(vdisk::Unanswered::Code(error)),
        _ => Err(vdisk::Unanswered::NoAnswer),
    }
}

/// How long removing a copy takes once Windows has let it go: 20 tries 100 ms apart.
const COPY_UNDO: Duration = Duration::from_secs(3);

/// Removes the copy once Windows has let it go.
fn remove_after_detach(copy: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..20 {
        match std::fs::remove_file(copy) {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("{} could not be removed: {last}", copy.display()))
}

/// The parent a differencing disk names: the image a kept repaired copy was made over.
pub fn parent_of(copy: &Path) -> Result<PathBuf, String> {
    let mut params = OPEN_VIRTUAL_DISK_PARAMETERS {
        Version: OPEN_VIRTUAL_DISK_VERSION_2,
        ..Default::default()
    };
    params.Anonymous.Version2.GetInfoOnly = 1;
    let kind = vdisk::storage_type(VIRTUAL_STORAGE_TYPE_DEVICE_VHD);
    let name = super::disk::wide(&copy.to_string_lossy());
    let mut raw = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call.
    let error = unsafe {
        windows_sys::Win32::Storage::Vhd::OpenVirtualDisk(
            &kind,
            name.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS,
            &params,
            &mut raw,
        )
    };
    if error != 0 {
        return Err(format!(
            "{} could not be read as a virtual disk: {}",
            copy.display(),
            error_text(error)
        ));
    }
    let handle = DiskHandle(raw);
    let mut buffer = vec![0u64; 512];
    let mut size = (buffer.len() * 8) as u32;
    // SAFETY: the buffer is writable for `size` bytes; Version is set first.
    let error = unsafe {
        let info = buffer.as_mut_ptr().cast::<GET_VIRTUAL_DISK_INFO>();
        (*info).Version = GET_VIRTUAL_DISK_INFO_PARENT_LOCATION;
        GetVirtualDiskInformation(handle.0, &mut size, info, std::ptr::null_mut())
    };
    if error != 0 {
        return Err(format!(
            "{} names no image it was made over: {}",
            copy.display(),
            error_text(error)
        ));
    }
    // ParentLocationBuffer: NUL-separated paths after the 4-byte version, padding and the
    // 4-byte ParentResolved.
    // SAFETY: the buffer holds what Windows wrote, as u16 from byte 12.
    let words = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(12).cast::<u16>(),
            (size as usize).saturating_sub(12) / 2,
        )
    };
    let folder = copy.parent().unwrap_or(Path::new("."));
    for text in words.split(|c| *c == 0).map(String::from_utf16_lossy) {
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let path = Path::new(text);
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            folder.join(text.trim_start_matches(".\\"))
        };
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "{} was made over an image that is no longer where it was.",
        copy.display()
    ))
}

/// Opens a kept repaired copy read-only as a drive: its image gets its footer back (the
/// same bytes as when the copy was made) and the copy is attached over it.
pub fn open_kept(copy: &Path) -> Result<vdisk::Attached, String> {
    let parent = parent_of(copy)?;
    let footed = Footed::put_on(&parent)?;
    let handle = vdisk::open_disk(copy, VIRTUAL_STORAGE_TYPE_DEVICE_VHD, true).map_err(|code| {
        format!(
            "{} could not be opened over {}: {}",
            copy.display(),
            parent.display(),
            error_text(code)
        )
    })?;
    let handle = vdisk::attach(handle, true, copy, &footed).map_err(|e| {
        format!(
            "Windows did not attach {}: {}",
            copy.display(),
            e.text("attaching it")
        )
    })?;
    let disk = match vdisk::physical_disk(&handle) {
        Ok(disk) => disk,
        Err(why) => {
            return Err(match vdisk::detach(handle, copy, &footed) {
                Ok(()) => why,
                Err(e) => format!("{why} Detaching it again: {}.", e.text("detaching it")),
            })
        }
    };
    Ok(vdisk::Attached::from_parts(handle, footed, disk))
}

// ---- chkdsk --------------------------------------------------------------------------------

/// chkdsk.exe in System32, by its full path.
fn chkdsk_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    Path::new(&root).join(r"System32\chkdsk.exe")
}

/// Text in the console's OEM code page, as chkdsk writes it to a pipe.
pub fn oem_text(bytes: &[u8]) -> String {
    use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP};
    if bytes.is_empty() {
        return String::new();
    }
    let mut wide = vec![0u16; bytes.len()];
    // SAFETY: both buffers are valid for the lengths given.
    let n = unsafe {
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            wide.len() as i32,
        )
    };
    String::from_utf16_lossy(&wide[..n.max(0) as usize])
}

/// A chkdsk run on a volume of the copy, its lines sent as they come.
struct Chkdsk {
    process: Process,
    lines: mpsc::Receiver<String>,
}

impl Chkdsk {
    /// Runs `chkdsk <volume> /f /x` on a volume of the copy: `/x` dismounts it first, so
    /// no question is asked. The volume is named by its "\\?\Volume{guid}" path, which
    /// always names the same volume, never by a drive letter, which can move to another
    /// drive; just before the start, the copy's disk is checked through its held handle and
    /// the volume's own extents must lie on it.
    fn start(repair: &Repair, volume: &VolumeInfo) -> Result<Self, String> {
        let (copy, _) = repair.checked()?;
        let target = volume.guid_path.trim_end_matches('\\').to_string();
        copy.holds_volume(&target)?;
        let mut process = Command::new(chkdsk_path())
            .args([target.as_str(), "/f", "/x"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("chkdsk could not be started: {e}"))?;
        let (sender, lines) = mpsc::channel();
        if let Some(out) = process.stdout.take() {
            let sender = sender.clone();
            std::thread::spawn(move || read_lines(out, sender));
        }
        if let Some(err) = process.stderr.take() {
            std::thread::spawn(move || read_lines(err, sender));
        }
        Ok(Self { process, lines })
    }

    /// The exit code once it has ended.
    fn ended(&mut self) -> Option<i32> {
        match self.process.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            Ok(None) => None,
            Err(_) => Some(-1),
        }
    }

    fn stop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for Chkdsk {
    fn drop(&mut self) {
        if self.ended().is_none() {
            self.stop();
        }
    }
}

/// Splits chkdsk's output at line ends and at the carriage returns its progress uses.
fn read_lines(mut from: impl Read, to: mpsc::Sender<String>) {
    let mut reader = std::io::BufReader::new(&mut from);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                let text = oem_text(&line);
                // Of a progress line rewritten with carriage returns, the last state.
                let last = text
                    .split('\r')
                    .map(str::trim_end)
                    .rfind(|s| !s.trim().is_empty())
                    .unwrap_or("")
                    .to_string();
                if to.send(last).is_err() {
                    return;
                }
            }
        }
    }
}

/// What chkdsk's exit code means, and for one that is not a clean end, chkdsk's own last
/// line, which says which it was (for example "Cannot open volume for direct access.").
fn said_with_reason(code: i32, lines: &std::collections::VecDeque<String>) -> String {
    let meaning = chkdsk_result(code);
    let last = lines.iter().rev().find(|l| !l.trim().is_empty());
    match last {
        Some(last) if !matches!(code, 0..=2) => format!("{meaning} chkdsk said: {}", last.trim()),
        _ => meaning.into(),
    }
}

/// What chkdsk's exit code means (documented: 0 no errors, 1 errors fixed, 2 cleanup done,
/// 3 could not check or errors left).
pub fn chkdsk_result(code: i32) -> &'static str {
    match code {
        0 => "chkdsk found no errors.",
        1 => "chkdsk found errors and fixed them on the copy.",
        2 => "chkdsk tidied the file system on the copy; no errors were left.",
        3 => "chkdsk could not check the volume, or errors are left that it could not fix.",
        _ => "chkdsk ended without saying how it went.",
    }
}

// ---- the engine ----------------------------------------------------------------------------

/// Options of Repair on a copy's start.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairOptions {
    /// The raw image to repair a copy of; it becomes the copy's read-only parent and is
    /// never written (only its footer comes and goes, as for Open an image as a drive).
    pub image: PathBuf,
    /// The folder the copy is made in: an existing folder, never on `source_disk`.
    pub folder: PathBuf,
    /// The disk being recovered, if any; the copy is refused there.
    #[serde(default)]
    pub source_disk: crate::recovery::dest::Protected,
}

/// A repair's copy, made and attached.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairStarted {
    /// "<image> repaired copy.vhd", a differencing VHD holding only the changes.
    pub copy: PathBuf,
    pub image: PathBuf,
    /// The copy's disk number while attached; the only disk the repairs write.
    pub disk: u32,
    pub volumes: Vec<VolumeInfo>,
}

/// Starts Repair on a copy: makes the copy over the image and attaches it read-write.
/// Returns the repair, which the steps below are run on, and what was made.
pub fn start_repair(
    options: &RepairOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<(Repair, RepairStarted), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("Stopped before the copy was made.".into());
    }
    events(Event::Phase {
        text: "Making the copy and attaching it".into(),
    });
    let repair = Repair::start(&options.image, &options.folder, &options.source_disk)?;
    events(Event::Phase {
        text: "Waiting for Windows to mount its volumes".into(),
    });
    let volumes = vdisk::wait_for_volumes(repair.disk);
    let started = RepairStarted {
        copy: repair.copy.clone(),
        image: repair.image().to_path_buf(),
        disk: repair.disk,
        volumes,
    };
    Ok((repair, started))
}

/// Options of the lost-partition search for a rebuilt table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindOptions {
    /// The image to search; it is only read.
    pub image: PathBuf,
    /// Look in every sector (true) or only where partitions start, every 1 MiB (false).
    /// Unset: every sector for images up to 64 GB, else every 1 MiB.
    #[serde(default)]
    pub every_sector: Option<bool>,
}

/// Images up to this size are searched sector by sector by default.
pub const SEARCH_EVERY_UP_TO: u64 = 64_000_000_000;

/// Searches an image for its volumes, lost ones included, and plans the partition table
/// that would bring them back. Progress is in bytes searched.
pub fn find_table(
    options: &FindOptions,
    events: &dyn Fn(Event),
    cancel: &AtomicBool,
) -> Result<Table, String> {
    use super::fs::{parts, Progress};
    let file = super::ImageFile::open(&options.image)
        .map_err(|e| format!("{} could not be read: {e}", options.image.display()))?;
    let len = super::BlockSource::len(&file);
    let every = options.every_sector.unwrap_or(len <= SEARCH_EVERY_UP_TO);
    let search = if every {
        parts::Search::Every
    } else {
        parts::Search::Aligned
    };
    events(Event::Phase {
        text: if every {
            "Searching every sector for volumes".into()
        } else {
            "Searching where partitions start for volumes".into()
        },
    });
    let progress = Progress::default();
    let finds = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut reader = super::reader::Reader::new(Box::new(file));
            parts::find(&mut reader, search, cancel, &progress)
        });
        while !worker.is_finished() {
            events(Event::Progress {
                done: len / 1000 * u64::from(progress.permille()),
                total: len,
            });
            std::thread::sleep(Duration::from_millis(250));
        }
        worker.join().map_err(|_| "The search failed.".to_string())
    })?;
    for note in &finds.notes {
        events(Event::Warning { text: note.clone() });
    }
    plan_table(&finds, len)
}

/// Options of writing a rebuilt table to the copy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteTableOptions {
    /// The table to write, as `find_table` planned it.
    pub table: Table,
    /// Confirms the disk to write: the copy's disk number, as `RepairStarted::disk` gives
    /// it. Any other number is refused.
    pub confirm_disk: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteTableResult {
    pub disk: u32,
    /// What did not go as it should after the table was written (Windows not asked to read
    /// it); each was also sent as a warning.
    #[serde(default)]
    pub notes: Vec<String>,
    /// The copy's volumes once Windows has read the new table.
    pub volumes: Vec<VolumeInfo>,
}

/// Options of a chkdsk run on a volume of the copy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChkdskOptions {
    /// A volume of the copy: its drive letter ("E:") or "\\?\Volume{guid}\".
    pub volume: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChkdskResult {
    pub volume: String,
    /// chkdsk's exit code: 0 no errors, 1 errors fixed, 2 cleanup done, 3 not checked or
    /// errors left; -1 when it was stopped or gave none.
    pub exit_code: i32,
    pub meaning: String,
    /// Its output, the last `CHKDSK_LINES` lines; every line was also sent as an event.
    pub lines: Vec<String>,
    pub stopped: bool,
}

/// How many of chkdsk's lines a result keeps.
pub const CHKDSK_LINES: usize = 2000;

/// Why a repair did not end, with the repair when its copy is still attached.
pub struct NotEnded {
    pub why: String,
    pub repair: Option<Box<Repair>>,
}

impl std::fmt::Debug for NotEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotEnded")
            .field("why", &self.why)
            .field("still_attached", &self.repair.is_some())
            .finish()
    }
}

/// Options of the repair's end.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndOptions {
    /// Keep the repaired copy (true), or delete it and every repair made to it (false).
    pub keep: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndResult {
    pub copy: PathBuf,
    pub kept: bool,
    /// The copy's size on its drive when kept; None when it was discarded or its size could
    /// not be read (`size_error` says why).
    pub size: Option<u64>,
    #[serde(default)]
    pub size_error: Option<String>,
    /// The image a kept copy needs, unchanged and where it is.
    pub image: PathBuf,
    pub text: String,
}

impl Repair {
    /// Writes a rebuilt partition table to the copy, and only to the copy.
    pub fn write_table(
        &self,
        options: &WriteTableOptions,
        events: &dyn Fn(Event),
    ) -> Result<WriteTableResult, String> {
        if options.confirm_disk != self.disk {
            return Err(format!(
                "Disk {} is not the copy (Disk {}), so nothing was written.",
                options.confirm_disk, self.disk
            ));
        }
        events(Event::Phase {
            text: "Writing the partition table to the copy".into(),
        });
        let notes: Vec<String> = self.write_layout(&options.table)?.into_iter().collect();
        for note in &notes {
            events(Event::Warning { text: note.clone() });
        }
        events(Event::Phase {
            text: "Waiting for Windows to mount its volumes".into(),
        });
        Ok(WriteTableResult {
            disk: self.disk,
            notes,
            volumes: vdisk::wait_for_volumes(self.disk),
        })
    }

    /// Runs `chkdsk /f /x` on a volume of the copy and waits for it; each line of its
    /// output is sent as it comes. Cancel stops it.
    pub fn chkdsk(
        &self,
        options: &ChkdskOptions,
        events: &dyn Fn(Event),
        cancel: &AtomicBool,
    ) -> Result<ChkdskResult, String> {
        let wanted = options.volume.trim_end_matches('\\').to_ascii_lowercase();
        let named = |volumes: Vec<VolumeInfo>| {
            volumes.into_iter().find(|v| {
                v.guid_path.trim_end_matches('\\').to_ascii_lowercase() == wanted
                    || v.letter().is_some_and(|l| l.to_ascii_lowercase() == wanted)
            })
        };
        // Windows mounts a volume again a moment after a new table is read; a volume not
        // listed at first is looked for again once the copy's volumes have settled.
        let volume = named(self.volumes())
            .or_else(|| named(vdisk::wait_for_volumes(self.disk)))
            .ok_or_else(|| format!("{} is not a volume of the copy.", options.volume))?;
        events(Event::Phase {
            text: format!("chkdsk /f on {}", volume.describe()),
        });
        let mut run = Chkdsk::start(self, &volume)?;
        let mut lines = std::collections::VecDeque::new();
        let take = |run: &Chkdsk, lines: &mut std::collections::VecDeque<String>| {
            for line in run.lines.try_iter().filter(|l| !l.trim().is_empty()) {
                events(Event::Line { text: line.clone() });
                if lines.len() == CHKDSK_LINES {
                    lines.pop_front();
                }
                lines.push_back(line);
            }
        };
        let mut stopped = false;
        let code = loop {
            take(&run, &mut lines);
            if let Some(code) = run.ended() {
                break code;
            }
            if cancel.load(Ordering::Relaxed) {
                run.stop();
                stopped = true;
                break -1;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        // The readers finish the last lines once the pipes close.
        std::thread::sleep(Duration::from_millis(100));
        take(&run, &mut lines);
        Ok(ChkdskResult {
            volume: volume.describe(),
            exit_code: code,
            meaning: if stopped {
                "chkdsk was stopped; the copy may be left half repaired.".into()
            } else {
                said_with_reason(code, &lines)
            },
            lines: lines.into(),
            stopped,
        })
    }

    /// Detaches the copy, keeps it or deletes it, and takes the footer off the image. A copy
    /// whose volumes did not close is not detached: the repair comes back with why, still
    /// attached, to be ended again.
    pub fn end(mut self, options: &EndOptions) -> Result<EndResult, NotEnded> {
        let text = match self.finish(options.keep) {
            Ok(text) => text,
            Err(why) if self.handle.is_some() => {
                return Err(NotEnded {
                    why,
                    repair: Some(Box::new(self)),
                })
            }
            Err(why) => return Err(NotEnded { why, repair: None }),
        };
        let kept = !matches!(
            self.ledger.get(self.entry).state,
            super::ledger::State::Removed(_)
        );
        let size = match kept {
            true => std::fs::metadata(&self.at)
                .map(|m| Some(m.len()))
                .map_err(|e| format!("the kept copy's size could not be read: {e}")),
            false => Ok(None),
        };
        Ok(EndResult {
            copy: self.copy.clone(),
            kept,
            size: size.as_ref().ok().copied().flatten(),
            size_error: size.err(),
            image: self.footed.image.clone(),
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish_body() -> &'static str {
        let code = include_str!("repair.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let at = code.find("    fn finish(&mut self, keep: bool)").unwrap();
        let body = &code[at..];
        &body[..body.find("\n    }\n").unwrap()]
    }

    /// The guard (cause D): the copy's volumes are the whole set Windows places on it, or
    /// nothing changes: no detach, and no table written, under a volume left out because it
    /// could not be read.
    #[test]
    fn an_unread_volume_list_stops_the_detach_and_the_table() {
        let code = include_str!("repair.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let finish = finish_body();
        let listed = finish
            .find("match super::target::every_volume_on(self.disk) {")
            .unwrap();
        assert!(finish[listed..].contains(
            "unclosed.push(format!(\"the copy's volumes could not all be found: {why}\"))"
        ));
        assert!(listed < finish.find("if !unclosed.is_empty() {").unwrap());
        let layout = &code[code.find("    fn write_layout(").unwrap()..];
        let layout = &layout[..layout.find("\n    }\n").unwrap()];
        assert!(layout.contains("super::target::every_volume_on(self.disk)"));
        assert!(layout
            .contains(".map_err(|why| format!(\"Nothing was written to the copy: {why}.\"))?;"));
        for body in [finish, layout] {
            assert!(
                !body.contains("volumes_of_disk("),
                "an inventory that skips what it cannot read"
            );
            assert!(!body.contains("self.volumes()"));
        }
        let target = include_str!("target.rs");
        let every = &target[target.find("pub(crate) fn every_volume_on(").unwrap()..];
        let every = &every[..every.find("\n}\n").unwrap()];
        assert!(
            every.contains("let all = all_volumes()?;") && every.contains("on_disk(number, &all)")
        );
    }

    /// The guard (cause E): a kept copy is entered whole only once its detach succeeded; a
    /// failed or late detach leaves it partial, with why.
    #[test]
    fn a_kept_copy_is_whole_only_once_detached() {
        let finish = finish_body();
        assert_eq!(finish.matches(".whole(").count(), 1);
        assert!(finish.contains("(None, None) => self.ledger.whole(self.entry),"));
        let detached = finish.find("vdisk::detach_holding(").unwrap();
        assert!(detached < finish.find("self.ledger.whole(").unwrap());
        assert!(finish.contains("(None, Some(why)) => self.ledger.partial("));
    }
    use crate::recovery::fs::Claim;

    const MIB: u64 = 1 << 20;

    fn volume(kind: FsKind, start: u64, len: u64, origin: Origin) -> Volume {
        Volume {
            kind,
            start,
            len,
            origin,
            claims: Vec::<Claim>::new(),
        }
    }

    #[test]
    fn a_table_is_rebuilt_from_what_the_search_found() {
        let finds = Finds {
            volumes: vec![
                volume(FsKind::Fat32, 126 * MIB, 100 * MIB, Origin::Found),
                volume(FsKind::Ntfs, MIB, 120 * MIB + 512, Origin::Backup),
            ],
            unread: Vec::new(),
            notes: Vec::new(),
        };
        let table = plan_table(&finds, 256 * MIB).unwrap();
        assert_eq!(table.style, Style::Mbr);
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].start, MIB);
        assert_eq!(table.entries[0].mbr_type, 0x07);
        assert_eq!(table.entries[1].mbr_type, 0x0C);
        assert!(table.left_out.is_empty());
    }

    /// The guard: a lost volume never displaces a current partition it overlaps, and
    /// nothing is placed past the disk's end or over sector 0.
    #[test]
    fn current_partitions_win_and_nothing_overlaps() {
        let finds = Finds {
            volumes: vec![
                volume(FsKind::Ntfs, MIB, 200 * MIB, Origin::Found),
                volume(FsKind::Fat32, 2 * MIB, 50 * MIB, Origin::Mbr(1)),
                volume(FsKind::ExFat, 300 * MIB, 50 * MIB, Origin::Found),
                volume(FsKind::Ntfs, 0, MIB, Origin::Found),
            ],
            unread: vec![Unread {
                origin: Origin::Mbr(2),
                start: 100 * MIB,
                len: 10 * MIB,
            }],
            notes: Vec::new(),
        };
        let table = plan_table(&finds, 320 * MIB).unwrap();
        let starts: Vec<u64> = table.entries.iter().map(|e| e.start).collect();
        assert_eq!(starts, [2 * MIB, 100 * MIB]);
        assert_eq!(table.left_out.len(), 3);
        for pair in table.entries.windows(2) {
            assert!(pair[0].start + pair[0].len <= pair[1].start);
        }
    }

    #[test]
    fn more_than_four_partitions_get_gpt() {
        let volumes = (1..=5)
            .map(|i| volume(FsKind::Ntfs, i * 10 * MIB, 5 * MIB, Origin::Found))
            .collect();
        let finds = Finds {
            volumes,
            unread: Vec::new(),
            notes: Vec::new(),
        };
        assert_eq!(plan_table(&finds, 100 * MIB).unwrap().style, Style::Gpt);
        let whole = Finds {
            volumes: vec![volume(FsKind::Fat32, 0, MIB, Origin::Whole)],
            unread: Vec::new(),
            notes: Vec::new(),
        };
        assert!(plan_table(&whole, MIB).is_err());
    }

    #[test]
    fn layouts_carry_each_partition_where_it_was_found() {
        let table = Table {
            style: Style::Mbr,
            entries: vec![Entry {
                start: MIB,
                len: 120 * MIB,
                what: "NTFS".into(),
                mbr_type: 7,
            }],
            left_out: Vec::new(),
        };
        let (buffer, size) = layout_bytes(&table, 0x1234, [0; 16]);
        // SAFETY: the buffer was built as a layout.
        let layout = unsafe { &*buffer.as_ptr().cast::<DRIVE_LAYOUT_INFORMATION_EX>() };
        assert_eq!(layout.PartitionCount, 4);
        assert_eq!(layout.PartitionEntry[0].StartingOffset, MIB as i64);
        // SAFETY: the MBR arm was written.
        assert_eq!(
            unsafe { layout.PartitionEntry[0].Anonymous.Mbr.PartitionType },
            7
        );
        assert!(size >= std::mem::size_of::<DRIVE_LAYOUT_INFORMATION_EX>());
    }

    /// This file without its tests.
    fn code() -> &'static str {
        let all = include_str!("repair.rs");
        &all[..all.find("#[cfg(test)]").expect("the tests module")]
    }

    /// The body of `fn <name>(` in this file's code.
    fn body(name: &str) -> &'static str {
        let code = code();
        let from = &code[code.find(&format!("fn {name}")).expect(name)..];
        &from[..from.find("\n    }\n").expect(name)]
    }

    /// The guard: the copy's disk is opened for writing once, at the attach, through
    /// `handles::CopyDisk` (which refuses the source and Windows' disks and checks the file
    /// behind the handle; its tests), and every destructive step goes through that held
    /// handle after checking through it that the file behind it is still the copy; no disk
    /// number or drive letter is looked up again to write or to run chkdsk.
    #[test]
    fn the_copy_is_written_only_through_its_held_and_checked_handle() {
        assert_eq!(
            code().matches("CopyDisk::open(").count(),
            1,
            "the disk is opened for writing somewhere besides the attach"
        );
        assert!(body("start(\n        image: &Path").contains("CopyDisk::open(disk, source, file)"));
        let write = body("write_layout(");
        assert_eq!(write.matches("self.checked()?").count(), 1, "{write}");
        assert!(
            write.contains("disk.write_table(&create, &layout, size, &mounted)"),
            "{write}"
        );
        let chkdsk = body("start(repair: &Repair");
        assert!(chkdsk.contains("repair.checked()?"), "{chkdsk}");
        assert!(chkdsk.contains("copy.holds_volume(&target)?"), "{chkdsk}");
        assert!(
            !chkdsk.contains(".letter()"),
            "chkdsk is run by a drive letter"
        );
    }

    /// The guard: the copy is made at a path resolved from the held folder handle, by volume
    /// GUID, so a junction in the chosen path is not in the path the copy is made at.
    #[test]
    fn the_copy_is_made_at_the_held_folders_resolved_path() {
        let start = body("start(\n        image: &Path");
        assert!(start.contains("base.resolved()?"), "{start}");
        assert!(start.contains("make_copy(image, &at, &footed)"), "{start}");
        let make = body("make_copy(image: &Path");
        assert!(make.contains("wide(&at.to_string_lossy())"), "{make}");
        assert!(make.contains("wide_at.as_ptr()"), "{make}");
        assert!(
            start.contains(
                "writer::adopt(\n            &guard,\n            &base,\n            &name,"
            ),
            "{start}"
        );
        let top = std::env::temp_dir().join(format!("diagtool-resolve-{}", std::process::id()));
        let real = top.join("real");
        let link = top.join("link");
        std::fs::create_dir_all(&real).unwrap();
        let made = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let held = Guard::default().base(&link).unwrap();
        let resolved = held.resolved().unwrap();
        assert!(resolved.starts_with(r"\\?\Volume{"), "{resolved}");
        assert!(resolved.ends_with(r"\real"), "{resolved}");
        drop(held);
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn copies_are_named_after_the_image_and_never_overwrite() {
        let folder = std::env::temp_dir().join(format!("diagtool-repair-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let first = copy_path(Path::new(r"D:\x\Disk 4 Kingston.img"), &folder);
        assert!(first.ends_with("Disk 4 Kingston repaired copy.vhd"));
        std::fs::write(&first, b"x").unwrap();
        let second = copy_path(Path::new(r"D:\x\Disk 4 Kingston.img"), &folder);
        assert!(second.ends_with("Disk 4 Kingston repaired copy (2).vhd"));
        std::fs::remove_file(&first).unwrap();
        std::fs::remove_dir(&folder).unwrap();
        assert!(chkdsk_result(1).contains("fixed"));
        // An exit that is not a clean end says chkdsk's own last line; a clean one does not.
        let lines: std::collections::VecDeque<String> = [
            "The type of the file system is NTFS.".to_string(),
            "Cannot open volume for direct access.".into(),
            "  ".into(),
        ]
        .into();
        assert_eq!(
            said_with_reason(3, &lines),
            "chkdsk could not check the volume, or errors are left that it could not fix. chkdsk said: Cannot open volume for direct access."
        );
        assert_eq!(said_with_reason(0, &lines), chkdsk_result(0));
        assert_eq!(said_with_reason(3, &Default::default()), chkdsk_result(3));
    }

    /// Needs administrator rights and an image with a wiped partition table: set
    /// DIAGTOOL_REPAIR_IMAGE to it and DIAGTOOL_REPAIR_FOLDER to an output folder, both under
    /// D:\diagtool-qa. With only the primary GPT wiped, Windows mounts the volume from the
    /// backup before the table is written, the case that once left chkdsk at exit 3.
    /// Searches the image for lost volumes, makes the copy, writes the rebuilt table to it,
    /// runs chkdsk /f on its first volume (which must end 0 or 1), reopens the kept copy's
    /// parent, and discards the copy; the image must end unchanged.
    #[test]
    #[ignore]
    fn live_repair_on_a_copy() {
        use crate::recovery::fs::{parts, Progress};
        use crate::recovery::reader::Reader;
        let image = PathBuf::from(std::env::var("DIAGTOOL_REPAIR_IMAGE").unwrap());
        let folder = PathBuf::from(std::env::var("DIAGTOOL_REPAIR_FOLDER").unwrap());
        // DIAGTOOL_PENDING_FILE: the journal, kept as a recovery window keeps it, so a run
        // killed part way leaves what `pending::tests::live_settle_what_a_killed_run_left`
        // settles.
        if let Ok(journal) = std::env::var("DIAGTOOL_PENDING_FILE") {
            crate::recovery::pending::JOURNAL.use_file(PathBuf::from(journal));
        }
        let hash = |p: &Path| {
            let data = std::fs::read(p).unwrap();
            ring::digest::digest(&ring::digest::SHA256, &data)
                .as_ref()
                .to_vec()
        };
        // The image as it was before this tool touched it: a footer an earlier run left, the
        // exact bytes this tool writes for this image, is the tool's and comes off. The end
        // compares every byte, so a footer left by this run fails it.
        let before = {
            let own = vdisk::own_footer(&std::fs::File::open(&image).unwrap());
            let data = std::fs::read(&image).unwrap();
            if let Some(len) = own {
                println!(
                    "an earlier run's footer is on the image; the image is its first {len} bytes"
                );
            }
            let data = &data[..own.map_or(data.len(), |len| len as usize)];
            ring::digest::digest(&ring::digest::SHA256, data)
                .as_ref()
                .to_vec()
        };
        let source =
            crate::recovery::open_source(&crate::recovery::SourceChoice::Image(image.clone()))
                .unwrap();
        let mut reader = Reader::new(source);
        let finds = parts::find(
            &mut reader,
            parts::Search::Every,
            &AtomicBool::new(false),
            &Progress::default(),
        );
        let table = plan_table(&finds, reader.len()).unwrap();
        drop(reader);
        for e in &table.entries {
            println!("table entry: {}", e.describe());
        }
        let events = |e: Event| println!("event: {e:?}");
        let no = AtomicBool::new(false);
        let (repair, started) = start_repair(
            &RepairOptions {
                image: image.clone(),
                folder: folder.clone(),
                source_disk: Default::default(),
            },
            &events,
            &no,
        )
        .unwrap();
        println!("started: {}", serde_json::to_string(&started).unwrap());
        let writer = repair.writer.as_ref().unwrap();
        println!("files behind the copy's disk: {:?}", writer.backing());
        println!("checked through the held handle: Disk {:?}", writer.check());
        println!(
            "copy {} attached as disk {}",
            repair.copy.display(),
            repair.disk
        );
        println!(
            "volumes before: {:?}",
            repair
                .volumes()
                .iter()
                .map(|v| v.describe())
                .collect::<Vec<_>>()
        );
        assert!(repair
            .write_table(
                &WriteTableOptions {
                    table: table.clone(),
                    confirm_disk: repair.disk + 1,
                },
                &events,
            )
            .is_err());
        let volumes = repair
            .write_table(
                &WriteTableOptions {
                    table: table.clone(),
                    confirm_disk: repair.disk,
                },
                &events,
            )
            .unwrap()
            .volumes;
        for v in &volumes {
            println!("after the table: {} {}", v.describe(), v.guid_path);
        }
        // The first volume with a file system: a found stretch the search could not name
        // (here the reserved partition GPT keeps) is a volume too, and chkdsk says it does
        // not check RAW volumes.
        let first = volumes
            .iter()
            .find(|v| v.file_system == "NTFS")
            .expect("an NTFS volume on the repaired copy")
            .clone();
        let quiet = |e: Event| {
            if let Event::Line { text } = e {
                if text.contains("Windows has") || text.contains("found no problems") {
                    println!("  | {text}");
                }
            }
        };
        let result = repair
            .chkdsk(
                &ChkdskOptions {
                    volume: first.letter().unwrap_or(first.guid_path.clone()),
                },
                &quiet,
                &no,
            )
            .unwrap();
        println!(
            "chkdsk exit {}: {} ({} lines)",
            result.exit_code,
            result.meaning,
            result.lines.len()
        );
        for line in &result.lines {
            println!("  chkdsk | {line}");
        }
        // A table written under a volume Windows had mounted from the old one's remains
        // left chkdsk unable to open the new volume (exit 3, "Cannot open volume for direct
        // access."); the copy's volumes are now closed for the write.
        assert!(
            matches!(result.exit_code, 0 | 1),
            "chkdsk exit {}: {}",
            result.exit_code,
            result.meaning
        );
        let copy = repair.copy.clone();
        // DIAGTOOL_REPAIR_PAUSE: seconds between chkdsk and the end, as a person takes.
        if let Some(pause) = std::env::var("DIAGTOOL_REPAIR_PAUSE")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            std::thread::sleep(std::time::Duration::from_secs(pause));
        }
        let started_end = std::time::Instant::now();
        match repair.end(&EndOptions { keep: true }) {
            Ok(ended) => println!("ended: {}", serde_json::to_string(&ended).unwrap()),
            Err(not) => {
                // Windows held the detach past its limit: the late detach takes the footer
                // off once Windows lets the image go, and this process waits for it as the
                // recovery window's process does before it ends.
                let why = &not.why;
                println!(
                    "end after {:.1} s: {why}",
                    started_end.elapsed().as_secs_f64()
                );
                assert!(not.repair.is_none(), "the copy was left attached: {why}");
                assert!(why.contains("within 60 s"), "{why}");
                let duties = &crate::recovery::timed::DUTIES;
                duties.ending();
                assert!(duties.wait_all(), "left: {:?}", duties.left());
                println!(
                    "the late detach ended {:.1} s after the end began; image {} bytes",
                    started_end.elapsed().as_secs_f64(),
                    std::fs::metadata(&image).unwrap().len()
                );
            }
        }
        println!(
            "parent of the kept copy: {}",
            parent_of(&copy).unwrap().display()
        );
        let (kept, opened) = vdisk::attach_image(
            &vdisk::AttachOptions {
                image: copy.clone(),
                make_plain: false,
            },
            &events,
            &no,
        )
        .unwrap();
        println!(
            "kept copy reopened: {}",
            serde_json::to_string(&opened).unwrap()
        );
        // The kept copy's repaired volume mounts: its last writes reached the copy.
        assert!(
            opened.volumes.iter().any(|v| v.file_system == "NTFS"),
            "the kept copy's volume does not mount"
        );
        kept.close().unwrap();
        std::fs::remove_file(&copy).unwrap();
        assert_eq!(hash(&image), before, "the image changed");
    }
}
