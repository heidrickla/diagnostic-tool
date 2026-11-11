//! Writing a rescue image to a replacement drive, so a customer's failing drive becomes a
//! working one. This is the one recovery tool that destroys data, on the drive it writes, so
//! most of it is guards: which drives may be written (`refusals`), what the technician types
//! to confirm (`Confirm`), and an order of writing that never leaves a half-written drive
//! looking whole (the first MiB is zeroed first and written last). Areas the map marks as not
//! rescued are written as zeros and listed. Every chunk is hashed as written and read back
//! after. Growing the last partition to a larger drive is optional and off by default.
//!
//! This module works on a `Target` and the image file; the physical disk, its volumes and
//! Windows' part are in `target.rs`.
use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use serde::{Deserialize, Serialize};

use super::image::{map_identity, Map, Status};
use super::{Scope, SourceId};
use crate::tools::drives::ata::DriveId;
use crate::tools::drives::bytes_text;

/// The first part of the drive, which holds the partition table: zeroed before anything else
/// is written and written last, so a drive whose writing stopped has no table at all.
pub const HEAD: u64 = 1 << 20;
/// Bytes per write after the head, and per hash for the check after writing.
pub const CHUNK: u64 = 4 << 20;

// ---- the image -------------------------------------------------------------------------

/// The partition table at the start of an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// GPT, laid out for sectors of this many bytes.
    Gpt(u32),
    Mbr,
    /// No partition table: a whole-drive file system, or not recognised.
    None,
}

/// A rescue image and what its map says of it.
#[derive(Clone, Debug)]
pub struct ImageInfo {
    pub image: PathBuf,
    /// The map beside it; None when there is none, and then every byte counts as read.
    pub map_path: Option<PathBuf>,
    /// The drive's size: the map's length, or the file's without a map.
    pub len: u64,
    pub map: Map,
    /// The drive it was made from, as the map's comment lines name it.
    pub made_from: Option<SourceId>,
    pub layout: Layout,
    /// The partition table ID of the drive it was made from, from the image's own first
    /// sectors (`image_table`); None when they were not read or hold no table.
    pub table: Option<String>,
}

impl ImageInfo {
    /// Areas the map does not mark as rescued, written as zeros.
    pub fn not_rescued(&self) -> Vec<Range<u64>> {
        self.map
            .blocks
            .iter()
            .filter(|b| b.status != Status::Rescued)
            .map(|b| b.pos..b.end())
            .collect()
    }

    pub fn not_rescued_bytes(&self) -> u64 {
        self.not_rescued().iter().map(|r| r.end - r.start).sum()
    }

    /// What the image is, as plain data for a person or an agent.
    pub fn summary(&self) -> ImageSummary {
        ImageSummary {
            image: self.image.clone(),
            map: self.map_path.clone(),
            len: self.len,
            layout: self.layout,
            made_from: self.made_from.as_ref().map(|id| MadeFrom {
                model: id.model.clone(),
                serial: id.serial.clone(),
                size: id.size,
            }),
            not_rescued: self.not_rescued(),
            not_rescued_bytes: self.not_rescued_bytes(),
        }
    }
}

/// The drive an image was made from, as its map names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MadeFrom {
    pub model: String,
    /// Empty when the drive reported none.
    pub serial: String,
    /// Bytes.
    pub size: u64,
}

/// An image as the engines report it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSummary {
    pub image: PathBuf,
    /// The map beside it; None when there is none and every byte counts as read.
    pub map: Option<PathBuf>,
    /// The drive's size in bytes, which the target must hold.
    pub len: u64,
    pub layout: Layout,
    /// None when the map does not name its drive (GNU ddrescue, older versions).
    pub made_from: Option<MadeFrom>,
    /// Byte ranges the map does not mark as rescued; they are written as zeros.
    pub not_rescued: Vec<Range<u64>>,
    pub not_rescued_bytes: u64,
}

/// The image file, held open with only read sharing while it is in use here, so no rescue
/// can write it and nothing can replace it; reads past its end come back as zeros (a GNU
/// ddrescue image may stop short of its drive).
pub struct ImageReader {
    file: File,
    file_len: u64,
}

impl ImageReader {
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Fills `buf` from `offset`; past the file's end with zeros.
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            if at >= self.file_len {
                buf[done..].fill(0);
                break;
            }
            let want = (buf.len() - done).min((self.file_len - at) as usize);
            match self.file.seek_read(&mut buf[done..done + want], at)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => done += n,
            }
        }
        Ok(())
    }
}

/// The image and its map, held open with read sharing only while the window has them.
pub struct Held {
    pub reader: ImageReader,
    pub map: Option<File>,
}

/// FILE_SHARE_READ: others may read, but not write, delete or rename while it is held.
const READ_SHARE_ONLY: u32 = 1;

/// Opens `path` to read, letting others only read it while it is held: it cannot be
/// written, renamed or deleted under the reader.
pub(crate) fn open_held(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(READ_SHARE_ONLY)
        .open(path)
}

/// Opens an image and its map (if there is one beside it) and reads what they say.
pub fn load_image(image: &Path) -> Result<(ImageInfo, Held), String> {
    let file = open_held(image).map_err(|e| match e.raw_os_error() {
        Some(32) => format!(
            "{} is in use, perhaps by a rescue image that is still running; stop it first",
            image.display()
        ),
        _ => format!("{} could not be opened: {e}", image.display()),
    })?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("{} could not be read: {e}", image.display()))?
        .len();
    if file_len == 0 {
        return Err(format!("{} is empty", image.display()));
    }
    let located = super::locate_map(image).map_err(|why| format!("{}: {why}", image.display()))?;
    let (map, made_from, map_file, map_path) = match located {
        Some((map_path, mut held)) => {
            let mut text = String::new();
            io::Read::read_to_string(&mut held, &mut text)
                .map_err(|e| format!("{} could not be read: {e}", map_path.display()))?;
            let map = Map::parse(&text).map_err(|e| format!("{}: {e}", map_path.display()))?;
            (map, map_identity(&text), Some(held), Some(map_path))
        }
        None => {
            let mut map = Map::new(file_len);
            map.set(0, file_len, Status::Rescued);
            (map, None, None, None)
        }
    };
    let len = map.len();
    if len == 0 {
        return Err(format!("the map beside {} is empty", image.display()));
    }
    check_lengths(image, file_len, &map)?;
    let mut reader = ImageReader { file, file_len };
    let head = read_head(&mut reader)
        .map_err(|e| format!("{} could not be read: {e}", image.display()))?;
    let layout = layout_of(&head);
    let table = made_from.as_ref().and_then(|m| image_table(&head, m));
    Ok((
        ImageInfo {
            image: image.to_path_buf(),
            map_path,
            len,
            map,
            made_from,
            layout,
            table,
        },
        Held {
            reader,
            map: map_file,
        },
    ))
}

/// An image longer than its map is another drive's; one shorter than the map's last
/// rescued byte is missing data its map says it holds.
fn check_lengths(image: &Path, file_len: u64, map: &Map) -> Result<(), String> {
    if file_len > map.len() {
        return Err(format!(
            "{} is {} and its map is for a drive of {}: they do not belong together",
            image.display(),
            bytes_text(file_len),
            bytes_text(map.len())
        ));
    }
    let rescued_to = map
        .blocks
        .iter()
        .filter(|b| b.status == Status::Rescued)
        .map(|b| b.end())
        .max()
        .unwrap_or(0);
    if file_len < rescued_to {
        return Err(format!(
            "{} is {}, but its map says data was rescued up to {}: the image was cut short",
            image.display(),
            bytes_text(file_len),
            bytes_text(rescued_to)
        ));
    }
    Ok(())
}

/// The partition table at the image's start, read from its first 8 KiB.
/// The image's first 8 KiB, where its partition table is.
fn read_head(reader: &mut ImageReader) -> io::Result<Vec<u8>> {
    let mut head = vec![0u8; 8192];
    reader.read(0, &mut head)?;
    Ok(head)
}

/// The ID a drive's partition table holds, as Windows reports it (`DiskInfo::disk_id`): the
/// GPT disk GUID, or the MBR signature as eight hex digits. None without a partition table
/// or for an MBR with no signature.
pub fn table_id(head: &[u8]) -> Option<String> {
    match layout_of(head) {
        Layout::Gpt(sector) => {
            let at = sector as usize + 56;
            let g = head.get(at..at + 16)?;
            g.iter()
                .any(|b| *b != 0)
                .then(|| crate::handles::guid_text(g))
        }
        Layout::Mbr => {
            let signature = u32::from_le_bytes(head.get(440..444)?.try_into().ok()?);
            (signature != 0).then(|| format!("{signature:08X}"))
        }
        Layout::None => None,
    }
}

/// The partition table ID of the drive an image of `made_from` was made from, from the
/// image's first 8 KiB `head` (zeros where never read). Only a whole drive's image starts
/// with its table; a map that does not say what was read is trusted only for a GPT header,
/// since a volume's boot sector can pass for an MBR.
pub fn image_table(head: &[u8], made_from: &SourceId) -> Option<String> {
    match made_from.scope {
        Some(Scope::Disk) => table_id(head),
        None if matches!(layout_of(head), Layout::Gpt(_)) => table_id(head),
        _ => None,
    }
}

pub fn layout_of(head: &[u8]) -> Layout {
    if head.len() < 512 || head[510..512] != [0x55, 0xAA] {
        return Layout::None;
    }
    let protective = (0..4).any(|i| head[446 + 16 * i + 4] == 0xEE);
    if protective {
        for sector in [512u32, 4096] {
            let at = sector as usize;
            if head.len() >= at + 8 && &head[at..at + 8] == b"EFI PART" {
                return Layout::Gpt(sector);
            }
        }
    }
    if (0..4).any(|i| head[446 + 16 * i + 4] != 0) {
        Layout::Mbr
    } else {
        Layout::None
    }
}

// ---- which drives may be written -------------------------------------------------------

/// A volume on a drive, for the list and the confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// "E:" or a folder it is mounted at; empty when it has neither.
    pub mount: String,
    pub label: String,
    pub file_system: String,
    /// Its bytes on this drive.
    pub size: u64,
    /// Other disks it also lies on (a spanned or striped volume).
    pub other_disks: Vec<u32>,
}

impl VolumeInfo {
    /// "E: Photos (NTFS, 500.1 GB)".
    pub fn text(&self) -> String {
        let mut name = self.mount.clone();
        if !self.label.is_empty() {
            if !name.is_empty() {
                name.push(' ');
            }
            name.push_str(&self.label);
        }
        if name.is_empty() {
            name = "a volume with no letter".into();
        }
        let fs = if self.file_system.is_empty() {
            "file system not read".to_string()
        } else {
            self.file_system.clone()
        };
        format!("{name} ({fs}, {})", bytes_text(self.size))
    }
}

/// A physical disk the image could be written to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskInfo {
    pub number: u32,
    pub model: String,
    pub serial: String,
    pub size: u64,
    /// Bytes per logical sector; 0 when Windows did not report it, which is refused.
    pub sector: u32,
    pub volumes: Vec<VolumeInfo>,
    /// The ID its partition table holds: the GPT disk GUID, or the MBR signature as eight hex
    /// digits; empty on a blank disk.
    #[serde(default)]
    pub disk_id: String,
    /// Where Windows has it attached, as port:bus:target:LUN; empty when Windows does not say.
    #[serde(default)]
    pub location: String,
    /// Attached through USB, where what Windows reports is the adapter's.
    #[serde(default)]
    pub usb: bool,
    /// The drive's own model and serial number from IDENTIFY; None when it was not read (not
    /// an ATA drive, or an adapter that does not pass ATA commands).
    #[serde(default)]
    pub drive: Option<DriveId>,
}

impl DiskInfo {
    /// "Disk 5, Samsung SSD 870, serial S5Y1NX0R, 1.0 TB".
    pub fn text(&self) -> String {
        format!(
            "Disk {}, {}, {}, {}",
            self.number,
            self.model_text(),
            self.serial_text(),
            crate::tools::drives::size_text(self.size)
        )
    }

    pub fn model_text(&self) -> &str {
        if self.model.trim().is_empty() {
            "model not reported"
        } else {
            self.model.trim()
        }
    }

    pub fn serial_text(&self) -> String {
        if self.serial.trim().is_empty() {
            "no serial number".into()
        } else {
            format!("serial {}", self.serial.trim())
        }
    }

    /// "disk ID 1A2B3C4D, location 3:0:1:0": what tells a drive apart when its serial
    /// number does not. Empty when Windows gives neither.
    pub fn ident_text(&self) -> String {
        let mut parts = Vec::new();
        if !self.disk_id.is_empty() {
            parts.push(format!("disk ID {}", self.disk_id));
        }
        if !self.location.is_empty() {
            parts.push(format!("location {}", self.location));
        }
        parts.join(", ")
    }

    pub fn volumes_text(&self) -> String {
        if self.volumes.is_empty() {
            "no volumes".into()
        } else {
            self.volumes
                .iter()
                .map(VolumeInfo::text)
                .collect::<Vec<_>>()
                .join("; ")
        }
    }
}

/// The disks that must never be written, each found through a handle or a device number.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guards {
    /// Holding the Windows folder.
    pub system: Vec<u32>,
    /// Holding the partition the computer starts from.
    pub boot: Vec<u32>,
    /// Holding the image file or its map.
    pub image: Vec<u32>,
    /// Holding this program's file.
    pub program: Vec<u32>,
    /// Holding a page file.
    pub paging: Vec<u32>,
    /// What could not be found out; while any is missing, no disk is offered.
    pub unknown: Vec<String>,
}

/// What `is_source` says of the drive `made_from` names itself, by serial number; its other
/// answers are doubts.
pub const SAME_DRIVE: &str = "it is the drive this image was made from";

/// Whether `disk` is the drive `made_from` names: the same serial number, or, when either
/// has no serial number, the same model and size, which cannot be told apart. A map made
/// through a USB adapter also names the drive's own serial number, which Windows reports
/// once the drive is on a SATA port. `table` is the source's partition table ID when known:
/// a disk whose own table ID is known and differs is another drive, whatever its name.
pub fn is_source(
    disk: &DiskInfo,
    made_from: &SourceId,
    table: Option<&str>,
) -> Option<&'static str> {
    let other_table = table.is_some_and(|table| {
        let own = disk.disk_id.trim();
        !own.is_empty() && !own.eq_ignore_ascii_case(table.trim())
    });
    // The whole drive's size: a volume's map gives its own size and, when it was read, its
    // drive's. A volume's map without the drive's size cannot say it.
    let source_size = match (made_from.disk_size, made_from.scope) {
        (Some(size), _) => Some(size),
        (None, Some(Scope::Disk)) => Some(made_from.size),
        (None, _) => None,
    };
    // A map from before the scope was kept gave the whole drive's size as its size.
    let matched_size = match made_from.scope {
        None => source_size.or(Some(made_from.size)),
        Some(_) => source_size,
    };
    let sized = |size: u64| matched_size == Some(size);
    if let Some(drive) = &made_from.drive {
        let own = drive.serial.trim();
        let named = |serial: &str| !own.is_empty() && serial.trim().eq_ignore_ascii_case(own);
        if disk.drive.as_ref().is_some_and(|d| named(&d.serial))
            || (named(&disk.serial)
                && (disk.model.trim() == drive.model.trim() || sized(disk.size)))
        {
            return Some(SAME_DRIVE);
        }
        // Behind an adapter that hides the drive's own serial, the source looks like any
        // other drive of its size.
        if !own.is_empty()
            && !other_table
            && disk.usb
            && disk.drive.is_none()
            && source_size.is_none_or(|size| size == disk.size)
        {
            return Some(
                "it cannot be ruled out as the drive this image was made from, behind another adapter; connect it through SATA or an adapter that passes ATA commands",
            );
        }
    }
    let (a, b) = (disk.serial.trim(), made_from.serial.trim());
    if !a.is_empty() && !b.is_empty() {
        return (a.eq_ignore_ascii_case(b)
            && (disk.model.trim() == made_from.model.trim() || sized(disk.size)))
        .then_some(SAME_DRIVE);
    }
    (!other_table
        && disk.model.trim() == made_from.model.trim()
        && matched_size.is_none_or(|size| size == disk.size))
    .then_some(
        "it may be the drive this image was made from: the same model and size, and no serial number to tell them apart",
    )
}

/// Every reason `disk` may not be written with `image`; empty when it may.
pub fn refusals(disk: &DiskInfo, image: &ImageInfo, guards: &Guards) -> Vec<String> {
    let mut why = Vec::new();
    for unknown in &guards.unknown {
        why.push(format!("{unknown}, so no drive can be written safely"));
    }
    if let Some(made_from) = &image.made_from {
        if let Some(reason) = is_source(disk, made_from, image.table.as_deref()) {
            why.push(reason.into());
        }
    }
    let named = [
        (&guards.image, "it holds the image or its map"),
        (&guards.system, "Windows runs from it"),
        (&guards.boot, "the computer starts from it"),
        (&guards.program, "it holds this program"),
        (&guards.paging, "it holds Windows' page file"),
    ];
    for (disks, reason) in named {
        if disks.contains(&disk.number) {
            why.push(reason.into());
        }
    }
    for volume in &disk.volumes {
        if !volume.other_disks.is_empty() {
            let others: Vec<String> = volume.other_disks.iter().map(u32::to_string).collect();
            why.push(format!(
                "its volume {} also lies on disk {}, which would be damaged too",
                volume.text(),
                others.join(", ")
            ));
        }
    }
    if disk.size == 0 {
        why.push("it reports no media".into());
    } else if disk.size < image.len {
        why.push(format!(
            "it is smaller than the image: {} against {} ({} against {} bytes)",
            bytes_text(disk.size),
            bytes_text(image.len),
            disk.size,
            image.len
        ));
    }
    if disk.sector == 0 {
        why.push(
            "Windows did not report its sector size, so the image's layout cannot be placed on it"
                .into(),
        );
    } else if let Layout::Gpt(sector) = image.layout {
        if sector != disk.sector {
            why.push(format!(
                "its sectors are {} bytes and the image's partitions are laid out for {sector}-byte sectors, so Windows would not find them",
                disk.sector
            ));
        }
    }
    why
}

/// What the technician types to confirm a drive, chosen so that no other connected drive
/// shares it: the last four characters of its serial number; when another drive's serial
/// ends the same way or it has none, the first eight characters of its disk ID; failing
/// that its size and location; and only when Windows gives neither, its number and size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirm {
    Serial(String),
    DiskId(String),
    SizeAndLocation(String),
    NumberAndSize(String),
}

fn letters(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// The last four letters or digits of a serial number, when it has four.
fn serial_tail(serial: &str) -> Option<String> {
    let all = letters(serial);
    (all.len() >= 4).then(|| all[all.len() - 4..].to_string())
}

/// The first eight letters or digits of a disk ID, when it has eight.
fn id_head(id: &str) -> Option<String> {
    let all = letters(id);
    (all.len() >= 8).then(|| all[..8].to_string())
}

/// Words and numbers only, lower case, single spaces: "2.1 GB, 3:0:1:0" is "2.1 gb 3 0 1 0".
fn words(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

impl Confirm {
    /// The confirmation for `disk`, given every disk Windows lists (`connected` may hold
    /// `disk` itself, which is skipped by its number).
    pub fn of(disk: &DiskInfo, connected: &[DiskInfo]) -> Self {
        let others: Vec<&DiskInfo> = connected
            .iter()
            .filter(|d| d.number != disk.number)
            .collect();
        if let Some(tail) = serial_tail(&disk.serial) {
            if others
                .iter()
                .all(|o| serial_tail(&o.serial) != Some(tail.clone()))
            {
                return Confirm::Serial(tail);
            }
        }
        if let Some(head) = id_head(&disk.disk_id) {
            if others
                .iter()
                .all(|o| id_head(&o.disk_id) != Some(head.clone()))
            {
                return Confirm::DiskId(head);
            }
        }
        let size = crate::tools::drives::size_text(disk.size);
        if !disk.location.is_empty() && others.iter().all(|o| o.location != disk.location) {
            return Confirm::SizeAndLocation(format!("{size} {}", disk.location));
        }
        Confirm::NumberAndSize(format!("{} {size}", disk.number))
    }

    /// What the window asks for.
    pub fn prompt(&self, number: u32) -> String {
        match self {
            Confirm::Serial(_) => format!(
                "To confirm, type the last four letters or digits of disk {number}'s serial number:"
            ),
            Confirm::DiskId(_) => format!(
                "Disk {number}'s serial number does not tell it apart from the other drives. To confirm, type the first eight letters or digits of its disk ID as listed:"
            ),
            Confirm::SizeAndLocation(_) => format!(
                "Disk {number}'s serial number and disk ID do not tell it apart from the other drives. To confirm, type its size and its location as listed, with a space between:"
            ),
            Confirm::NumberAndSize(_) => format!(
                "Disk {number} has no serial number, disk ID or location that tells it apart from the other drives. To confirm, type its disk number and its size as listed, with a space between:"
            ),
        }
    }

    /// Whether `typed` matches, ignoring case, spaces and punctuation.
    pub fn matches(&self, typed: &str) -> bool {
        match self {
            Confirm::Serial(expected) | Confirm::DiskId(expected) => letters(typed) == *expected,
            Confirm::SizeAndLocation(expected) | Confirm::NumberAndSize(expected) => {
                !typed.trim().is_empty() && words(typed) == words(expected)
            }
        }
    }
}

// ---- writing ---------------------------------------------------------------------------

/// A drive being written: positioned reads and writes of whole sectors.
pub trait Target {
    fn len(&self) -> u64;
    fn sector(&self) -> u32;
    /// Writes `data` at `offset`; both are multiples of the sector size.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;
    /// Fills `buf` from `offset`; both are multiples of the sector size.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Makes what was written durable.
    fn flush(&mut self) -> io::Result<()>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A drive in memory, for tests.
pub struct MemTarget {
    pub data: Vec<u8>,
    pub sector: u32,
    /// Fails the write that covers this offset.
    pub fail_at: Option<u64>,
}

impl MemTarget {
    pub fn new(len: usize, fill: u8) -> Self {
        Self {
            data: vec![fill; len],
            sector: 512,
            fail_at: None,
        }
    }
}

impl Target for MemTarget {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn sector(&self) -> u32 {
        self.sector
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let s = u64::from(self.sector);
        assert!(
            offset.is_multiple_of(s) && (data.len() as u64).is_multiple_of(s),
            "unaligned write"
        );
        if self
            .fail_at
            .is_some_and(|at| (offset..offset + data.len() as u64).contains(&at))
        {
            return Err(io::Error::other("the drive refused the write"));
        }
        self.data[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        Ok(())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let s = u64::from(self.sector);
        assert!(
            offset.is_multiple_of(s) && (buf.len() as u64).is_multiple_of(s),
            "unaligned read"
        );
        buf.copy_from_slice(&self.data[offset as usize..offset as usize + buf.len()]);
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Where a run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Step {
    Preparing = 0,
    Writing = 1,
    Checking = 2,
    Growing = 3,
    Finishing = 4,
}

impl Step {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Step::Writing,
            2 => Step::Checking,
            3 => Step::Growing,
            4 => Step::Finishing,
            _ => Step::Preparing,
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            Step::Preparing => "Preparing the drive: closing its volumes",
            Step::Writing => "Writing the image",
            Step::Checking => "Reading back what was written to check it",
            Step::Growing => "Growing the last partition",
            Step::Finishing => "Handing the drive back to Windows",
        }
    }
}

/// What a run tells whoever drives it, as it goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A step began; `total` is the bytes it covers, 0 for a step without a byte count.
    Step { step: Step, total: u64 },
    /// Bytes done in the current step, after each chunk (at most 4 MiB apart).
    Bytes { step: Step, done: u64, total: u64 },
    /// A chunk read back differently in the check after writing.
    Mismatch { start: u64, end: u64 },
    /// Something a person should know that does not stop the run.
    Warning { text: String },
}

/// Where the events of a run go.
pub type EventSink = Box<dyn Fn(Event) + Send + Sync>;

/// A run's progress: kept as figures and sent as events.
#[derive(Default)]
pub struct Progress {
    step: AtomicU8,
    pub done: AtomicU64,
    pub total: AtomicU64,
    /// Chunks that read back differently so far.
    pub mismatches: AtomicU64,
    sink: Option<EventSink>,
}

impl Progress {
    /// Progress that sends each event to `sink`.
    pub fn with(sink: EventSink) -> Self {
        Self {
            sink: Some(sink),
            ..Self::default()
        }
    }

    fn send(&self, event: Event) {
        if let Some(sink) = &self.sink {
            sink(event);
        }
    }

    pub fn step(&self) -> Step {
        Step::from_u8(self.step.load(Ordering::Relaxed))
    }

    pub fn set_step(&self, step: Step, total: u64) {
        self.step.store(step as u8, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.send(Event::Step { step, total });
    }

    fn advance(&self, done: u64) {
        self.done.store(done, Ordering::Relaxed);
        self.send(Event::Bytes {
            step: self.step(),
            done,
            total: self.total.load(Ordering::Relaxed),
        });
    }

    fn mismatch(&self, area: &Range<u64>) {
        self.mismatches.fetch_add(1, Ordering::Relaxed);
        self.send(Event::Mismatch {
            start: area.start,
            end: area.end,
        });
    }

    pub fn warn(&self, text: &str) {
        self.send(Event::Warning { text: text.into() });
    }
}

/// One chunk as written: where, how long, and the SHA-256 of what was written.
#[derive(Clone, Debug)]
pub struct Chunk {
    pub pos: u64,
    pub len: u64,
    pub hash: [u8; 32],
}

/// The chunks of a drive of `len` bytes, padded to whole sectors: the head first, then
/// `CHUNK`-sized pieces.
pub fn chunks_of(len: u64, sector: u64) -> Vec<Range<u64>> {
    let end = len.div_ceil(sector) * sector;
    let mut out = Vec::new();
    let head = HEAD.min(end);
    out.push(0..head);
    let mut pos = head;
    while pos < end {
        let next = (pos + CHUNK).min(end);
        out.push(pos..next);
        pos = next;
    }
    out
}

/// Zeros the parts of `buf` (holding `pos..`) that `not_rescued` covers.
fn blank(buf: &mut [u8], pos: u64, not_rescued: &[Range<u64>]) {
    let end = pos + buf.len() as u64;
    for r in not_rescued {
        if r.end <= pos || r.start >= end {
            continue;
        }
        let from = (r.start.max(pos) - pos) as usize;
        let to = (r.end.min(end) - pos) as usize;
        buf[from..to].fill(0);
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ending {
    Finished,
    /// Stop was pressed (and confirmed).
    Stopped,
    Failed(String),
}

/// The check after writing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checked {
    /// Bytes read back and compared, from the start.
    pub through: u64,
    /// Every chunk was read back.
    pub complete: bool,
    /// Chunks that read back differently, or could not be read back.
    pub mismatches: Vec<Range<u64>>,
}

/// What a run did, for its end text and report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ran {
    pub ending: Ending,
    /// Something was written to the drive: its old contents are gone.
    pub touched: bool,
    /// Bytes of the image written so far, the head counted only once written.
    pub written: u64,
    /// The head, and so the partition table, was written: the drive is whole.
    pub head_written: bool,
    pub checked: Option<Checked>,
    pub grown: Option<GrowEnd>,
    /// What else happened that a person should know, such as Windows not reading the new
    /// partition table.
    pub notes: Vec<String>,
    /// What kept the drive's volumes closed while it was written: the disk offline, the
    /// volumes locked, or both, naming each volume. Empty when the drive was never opened.
    #[serde(default)]
    pub held: String,
    /// Why the drive did not confirm the last writes when the writer was let go: then what
    /// was written may not all be on it, and it is not entered whole.
    #[serde(default)]
    pub unconfirmed: Option<String>,
}

impl Ran {
    pub fn new() -> Self {
        Self {
            ending: Ending::Finished,
            touched: false,
            written: 0,
            head_written: false,
            checked: None,
            grown: None,
            notes: Vec::new(),
            held: String::new(),
            unconfirmed: None,
        }
    }
}

impl Default for Ran {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes the image to `target`: the head and the target's last MiB are zeroed first, then
/// everything after the head in order, then the head. Returns the chunks as written.
pub fn write_image(
    reader: &mut ImageReader,
    image: &ImageInfo,
    target: &mut dyn Target,
    stop: &AtomicBool,
    progress: &Progress,
    ran: &mut Ran,
) -> Result<Vec<Chunk>, Ending> {
    let sector = u64::from(target.sector().max(512));
    let chunks = chunks_of(image.len, sector);
    let padded = chunks.last().map_or(0, |c| c.end);
    if padded > target.len() {
        return Err(Ending::Failed(format!(
            "the drive is {} and the image needs {}",
            bytes_text(target.len()),
            bytes_text(padded)
        )));
    }
    let not_rescued = image.not_rescued();
    progress.set_step(Step::Writing, padded);
    let fail = |what: &str, e: io::Error| Ending::Failed(format!("{what}: {e}"));
    // No partition table until the end: a stop or failure leaves the drive plainly empty.
    let zeros = vec![0u8; HEAD as usize];
    let head_len = chunks[0].end;
    ran.touched = true;
    target
        .write_at(0, &zeros[..head_len as usize])
        .map_err(|e| fail("the start of the drive could not be cleared", e))?;
    // An old GPT's backup copy at the drive's end would otherwise outlive the write.
    let tail_start = target.len().saturating_sub(HEAD).max(padded);
    if tail_start < target.len() {
        target
            .write_at(tail_start, &zeros[..(target.len() - tail_start) as usize])
            .map_err(|e| fail("the end of the drive could not be cleared", e))?;
    }
    target
        .flush()
        .map_err(|e| fail("the drive did not confirm the write", e))?;
    let mut buf = vec![0u8; CHUNK as usize];
    let mut out = vec![
        Chunk {
            pos: 0,
            len: 0,
            hash: [0; 32],
        };
        chunks.len()
    ];
    let mut write_one =
        |index: usize, target: &mut dyn Target, reader: &mut ImageReader| -> Result<(), Ending> {
            let r = &chunks[index];
            let len = (r.end - r.start) as usize;
            let data = &mut buf[..len];
            // The image ends mid-sector only when the drive's sectors are larger; pad with zeros.
            let from_image = (image.len.saturating_sub(r.start) as usize).min(len);
            reader
                .read(r.start, &mut data[..from_image])
                .map_err(|e| fail("the image could not be read", e))?;
            data[from_image..].fill(0);
            blank(data, r.start, &not_rescued);
            out[index] = Chunk {
                pos: r.start,
                len: len as u64,
                hash: sha256(data),
            };
            target
                .write_at(r.start, data)
                .map_err(|e| fail(&format!("writing at {} failed", bytes_text(r.start)), e))
        };
    for (index, chunk) in chunks.iter().enumerate().skip(1) {
        if stop.load(Ordering::Relaxed) {
            return Err(Ending::Stopped);
        }
        write_one(index, target, reader)?;
        ran.written = chunk.end - head_len;
        progress.advance(ran.written);
    }
    target
        .flush()
        .map_err(|e| fail("the drive did not confirm the write", e))?;
    if stop.load(Ordering::Relaxed) {
        return Err(Ending::Stopped);
    }
    write_one(0, target, reader)?;
    target
        .flush()
        .map_err(|e| fail("the drive did not confirm the write", e))?;
    ran.written = padded;
    ran.head_written = true;
    progress.advance(padded);
    Ok(out)
}

/// Reads every chunk back and compares its hash with the one taken as it was written.
pub fn check_written(
    target: &mut dyn Target,
    chunks: &[Chunk],
    stop: &AtomicBool,
    progress: &Progress,
) -> Checked {
    let total = chunks.iter().map(|c| c.len).sum();
    progress.set_step(Step::Checking, total);
    progress.mismatches.store(0, Ordering::Relaxed);
    let mut checked = Checked::default();
    let mut buf = vec![0u8; CHUNK as usize];
    let mut done = 0;
    for chunk in chunks {
        if stop.load(Ordering::Relaxed) {
            return checked;
        }
        let data = &mut buf[..chunk.len as usize];
        let same = target.read_at(chunk.pos, data).is_ok() && sha256(data) == chunk.hash;
        if !same {
            let area = chunk.pos..chunk.pos + chunk.len;
            progress.mismatch(&area);
            checked.mismatches.push(area);
        }
        done += chunk.len;
        checked.through = done;
        progress.advance(done);
    }
    checked.complete = true;
    checked
}

/// Writes, checks and, if asked, grows: everything a run does to the drive itself.
pub fn run_on(
    reader: &mut ImageReader,
    image: &ImageInfo,
    target: &mut dyn Target,
    grow_asked: bool,
    stop: &AtomicBool,
    progress: &Progress,
) -> Ran {
    run_steps(
        reader,
        image,
        target,
        grow_asked,
        stop,
        progress,
        &mut |_| {},
    )
}

/// `run_on` with a call between the writing and the check; the live test changes a byte
/// there to see the check find it.
pub fn run_steps(
    reader: &mut ImageReader,
    image: &ImageInfo,
    target: &mut dyn Target,
    grow_asked: bool,
    stop: &AtomicBool,
    progress: &Progress,
    between: &mut dyn FnMut(&mut dyn Target),
) -> Ran {
    let mut ran = Ran::new();
    let chunks = match write_image(reader, image, target, stop, progress, &mut ran) {
        Ok(chunks) => chunks,
        Err(ending) => {
            ran.ending = ending;
            return ran;
        }
    };
    between(target);
    let checked = check_written(target, &chunks, stop, progress);
    let stopped = !checked.complete;
    let clean = checked.mismatches.is_empty();
    ran.checked = Some(checked);
    if stopped {
        ran.ending = Ending::Stopped;
        return ran;
    }
    if grow_asked {
        ran.grown = Some(if clean {
            progress.set_step(Step::Growing, 0);
            grow(target, image.len)
        } else {
            GrowEnd::NotGrown(
                "the check after writing found differences, so nothing more was changed".into(),
            )
        });
    }
    ran
}

// ---- growing the last partition --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    Gpt,
    Mbr,
}

/// The file system in a partition, from its first sector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    Ntfs,
    ExFat,
    Fat,
    Other,
    /// Its first sector could not be read; `Grown::fs_error` says why.
    Unread,
}

impl FsKind {
    pub fn of(boot: &[u8]) -> Self {
        if boot.len() < 90 {
            return FsKind::Other;
        }
        if &boot[3..11] == b"NTFS    " {
            FsKind::Ntfs
        } else if &boot[3..11] == b"EXFAT   " {
            FsKind::ExFat
        } else if &boot[82..87] == b"FAT32" || &boot[54..57] == b"FAT" {
            FsKind::Fat
        } else {
            FsKind::Other
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FsKind::Ntfs => "NTFS",
            FsKind::ExFat => "exFAT",
            FsKind::Fat => "FAT",
            FsKind::Other => "an unrecognized file system",
            FsKind::Unread => "a file system whose first sector could not be read",
        }
    }
}

/// A partition grown to fill the drive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grown {
    pub table: Table,
    /// Its number in the table, from 1.
    pub number: u32,
    pub offset: u64,
    pub old_len: u64,
    pub new_len: u64,
    pub fs: FsKind,
    /// Why its file system's first sector could not be read, when it could not.
    #[serde(default)]
    pub fs_error: Option<String>,
    /// A limit met on the way, such as MBR's 2 TiB.
    pub note: Option<String>,
    /// Extending its NTFS file system through Windows: None until tried.
    pub fs_extended: Option<Result<u64, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrowEnd {
    Grown(Grown),
    NotGrown(String),
}

/// CRC-32 as GPT uses it (IEEE 802.3, reflected).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Windows' recovery partition type, DE94BBA4-06D1-4D40-A16A-BFD50179D6AC, as stored.
const GPT_RECOVERY: [u8; 16] = [
    0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC,
];

/// Partitions end on a whole MiB, as Windows lays them out.
const ALIGN: u64 = 1 << 20;

fn read_sectors(target: &mut dyn Target, lba: u64, count: u64) -> Result<Vec<u8>, String> {
    let s = u64::from(target.sector());
    let mut buf = vec![0u8; (count * s) as usize];
    target
        .read_at(lba * s, &mut buf)
        .map_err(|e| format!("the partition table could not be read: {e}"))?;
    Ok(buf)
}

fn write_sectors(target: &mut dyn Target, lba: u64, data: &[u8]) -> Result<(), String> {
    let s = u64::from(target.sector());
    target
        .write_at(lba * s, data)
        .map_err(|e| format!("the partition table could not be written: {e}"))
}

/// The file system at `offset`, and why its first sector could not be read when it could
/// not: an unread sector is not taken for an unrecognized file system.
fn fs_at(target: &mut dyn Target, offset: u64) -> (FsKind, Option<String>) {
    let s = target.sector() as usize;
    let mut boot = vec![0u8; s];
    match target.read_at(offset, &mut boot) {
        Ok(()) => (FsKind::of(&boot), None),
        Err(e) => (FsKind::Unread, Some(e.to_string())),
    }
}

/// Grows the last partition of a drive written with an image of `image_len` bytes to the
/// drive's end: GPT moves its backup header and entries to the new end, MBR extends the
/// entry. The file system inside is extended afterwards, through Windows.
pub fn grow(target: &mut dyn Target, image_len: u64) -> GrowEnd {
    match grow_table(target, image_len) {
        Ok(end) => end,
        Err(why) => GrowEnd::NotGrown(why),
    }
}

fn grow_table(target: &mut dyn Target, image_len: u64) -> Result<GrowEnd, String> {
    let s = u64::from(target.sector());
    let sectors = target.len() / s;
    if target.len() < image_len + ALIGN {
        return Ok(GrowEnd::NotGrown(
            "the drive is not larger than the image by a MiB or more".into(),
        ));
    }
    let mbr = read_sectors(target, 0, 1)?;
    if mbr[510..512] != [0x55, 0xAA] {
        return Ok(GrowEnd::NotGrown("the image has no partition table".into()));
    }
    if (0..4).any(|i| mbr[446 + 16 * i + 4] == 0xEE) {
        grow_gpt(target, mbr, sectors)
    } else {
        grow_mbr(target, mbr, sectors)
    }
}

fn grow_gpt(target: &mut dyn Target, mut mbr: Vec<u8>, sectors: u64) -> Result<GrowEnd, String> {
    let s = u64::from(target.sector());
    let mut header = read_sectors(target, 1, 1)?;
    let size = le32(&header, 12) as usize;
    if &header[..8] != b"EFI PART" || !(92..=s as usize).contains(&size) || le64(&header, 24) != 1 {
        return Ok(GrowEnd::NotGrown(
            "the GPT header at the start of the drive is not valid".into(),
        ));
    }
    let mut check = header[..size].to_vec();
    put32(&mut check, 16, 0);
    if crc32(&check) != le32(&header, 16) {
        return Ok(GrowEnd::NotGrown(
            "the GPT header's checksum does not match".into(),
        ));
    }
    let (entries_lba, count, entry_size) = (
        le64(&header, 72),
        u64::from(le32(&header, 80)),
        u64::from(le32(&header, 84)),
    );
    if !(128..=4096).contains(&entry_size) || count == 0 || count > 4096 {
        return Ok(GrowEnd::NotGrown(
            "the GPT's partition list has an unusual shape".into(),
        ));
    }
    let entry_sectors = (count * entry_size).div_ceil(s);
    let mut entries = read_sectors(target, entries_lba, entry_sectors)?;
    let table_len = (count * entry_size) as usize;
    if crc32(&entries[..table_len]) != le32(&header, 88) {
        return Ok(GrowEnd::NotGrown(
            "the GPT's partition list checksum does not match".into(),
        ));
    }
    let old_backup = le64(&header, 32);
    let new_last = sectors - 1;
    if new_last <= old_backup {
        return Ok(GrowEnd::NotGrown(
            "the drive is not larger than the image's partition table says".into(),
        ));
    }
    let backup_entries = new_last - entry_sectors;
    let last_usable = backup_entries - 1;
    // The partition ending last.
    let last = (0..count as usize)
        .map(|i| {
            (
                i,
                &entries[i * entry_size as usize..(i + 1) * entry_size as usize],
            )
        })
        .filter(|(_, e)| e[..16].iter().any(|b| *b != 0))
        .max_by_key(|(_, e)| le64(e, 40))
        .map(|(i, e)| (i, e[..16].to_vec(), le64(e, 32), le64(e, 40)));
    let Some((index, kind, first, end)) = last else {
        return Ok(GrowEnd::NotGrown("the drive has no partitions".into()));
    };
    if kind == GPT_RECOVERY {
        return Ok(GrowEnd::NotGrown(format!(
            "the last partition, number {}, is Windows' recovery partition, so it was not grown; the new space is left unallocated after it",
            index + 1
        )));
    }
    let per_align = (ALIGN / s).max(1);
    let new_end = ((last_usable + 1) / per_align * per_align).saturating_sub(1);
    if new_end <= end {
        return Ok(GrowEnd::NotGrown(
            "there is no room after the last partition".into(),
        ));
    }
    let at = index * entry_size as usize;
    put64(&mut entries, at + 40, new_end);
    let entries_crc = crc32(&entries[..table_len]);
    // The primary header now points at the new end.
    put64(&mut header, 32, new_last);
    put64(&mut header, 48, last_usable);
    put32(&mut header, 88, entries_crc);
    put32(&mut header, 16, 0);
    let crc = crc32(&header[..size]);
    put32(&mut header, 16, crc);
    // The backup: the same with its own place, pointing back at the primary.
    let mut backup = header.clone();
    put64(&mut backup, 24, new_last);
    put64(&mut backup, 32, 1);
    put64(&mut backup, 72, backup_entries);
    put32(&mut backup, 16, 0);
    let crc = crc32(&backup[..size]);
    put32(&mut backup, 16, crc);
    // The protective MBR covers the whole drive, up to what 32 bits hold.
    for i in 0..4 {
        let e = 446 + 16 * i;
        if mbr[e + 4] == 0xEE {
            put32(&mut mbr, e + 12, (new_last).min(u64::from(u32::MAX)) as u32);
        }
    }
    // The backup goes first, so a stop between the two leaves the old primary consistent.
    write_sectors(target, backup_entries, &entries)?;
    write_sectors(target, new_last, &backup)?;
    target.flush().map_err(|e| e.to_string())?;
    write_sectors(target, entries_lba, &entries)?;
    write_sectors(target, 1, &header)?;
    write_sectors(target, 0, &mbr)?;
    // The old backup header, now inside the grown partition past its file system, is
    // cleared so nothing takes it for the drive's table.
    write_sectors(target, old_backup, &vec![0u8; s as usize])?;
    target.flush().map_err(|e| e.to_string())?;
    let offset = first * s;
    let (fs, fs_error) = fs_at(target, offset);
    Ok(GrowEnd::Grown(Grown {
        table: Table::Gpt,
        number: index as u32 + 1,
        offset,
        old_len: (end + 1 - first) * s,
        new_len: (new_end + 1 - first) * s,
        fs,
        fs_error,
        note: None,
        fs_extended: None,
    }))
}

fn grow_mbr(target: &mut dyn Target, mut mbr: Vec<u8>, sectors: u64) -> Result<GrowEnd, String> {
    let s = u64::from(target.sector());
    let last = (0..4)
        .map(|i| (i, 446 + 16 * i))
        .filter(|(_, e)| mbr[e + 4] != 0 && le32(&mbr, e + 12) != 0)
        .max_by_key(|(_, e)| u64::from(le32(&mbr, e + 8)) + u64::from(le32(&mbr, e + 12)));
    let Some((index, e)) = last else {
        return Ok(GrowEnd::NotGrown("the drive has no partitions".into()));
    };
    let kind = mbr[e + 4];
    if matches!(kind, 0x05 | 0x0F | 0x85) {
        return Ok(GrowEnd::NotGrown(
            "the last partition is a logical drive inside an extended partition, which this tool does not grow".into(),
        ));
    }
    if kind == 0x27 {
        return Ok(GrowEnd::NotGrown(format!(
            "the last partition, number {}, is a recovery partition, so it was not grown; the new space is left unallocated after it",
            index + 1
        )));
    }
    let start = u64::from(le32(&mbr, e + 8));
    let old_count = u64::from(le32(&mbr, e + 12));
    let limit = u64::from(u32::MAX);
    let mut note = None;
    let mut end = sectors;
    if end > limit {
        end = limit;
        note = Some(format!(
            "An MBR partition table reaches only the first {} of a drive, so the rest of this drive stays unused.",
            bytes_text(limit * s)
        ));
    }
    let per_align = (ALIGN / s).max(1);
    let end = end / per_align * per_align;
    let new_count = end.saturating_sub(start);
    if new_count <= old_count {
        return Ok(GrowEnd::NotGrown(
            "there is no room after the last partition".into(),
        ));
    }
    put32(&mut mbr, e + 12, new_count as u32);
    // The ending cylinder, head and sector: past what CHS can say, as Windows writes it.
    mbr[e + 5..e + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    write_sectors(target, 0, &mbr)?;
    target.flush().map_err(|e| e.to_string())?;
    let offset = start * s;
    let (fs, fs_error) = fs_at(target, offset);
    Ok(GrowEnd::Grown(Grown {
        table: Table::Mbr,
        number: index as u32 + 1,
        offset,
        old_len: old_count * s,
        new_len: new_count * s,
        fs,
        fs_error,
        note,
        fs_extended: None,
    }))
}

// ---- what a run says -------------------------------------------------------------------

/// "1 area", "2 areas".
pub fn areas(n: usize) -> String {
    if n == 1 {
        "1 area".into()
    } else {
        format!("{n} areas")
    }
}

/// "at 1.2 GB, 4.1 kB" for each area, at most `most` of them.
pub fn areas_text(areas: &[Range<u64>], most: usize) -> String {
    let mut parts: Vec<String> = areas
        .iter()
        .take(most)
        .map(|r| {
            format!(
                "at {}, {}",
                bytes_text(r.start),
                bytes_text(r.end - r.start)
            )
        })
        .collect();
    if areas.len() > most {
        parts.push(format!("and {} more", areas.len() - most));
    }
    parts.join("; ")
}

/// What the grow option did, in a sentence or two.
pub fn grow_text(grown: &GrowEnd) -> String {
    match grown {
        GrowEnd::NotGrown(why) => format!("The last partition was not grown: {why}."),
        GrowEnd::Grown(g) => {
            let table = match g.table {
                Table::Gpt => "GPT",
                Table::Mbr => "MBR",
            };
            let mut text = format!(
                "Partition {} ({table}) was grown from {} to {}.",
                g.number,
                bytes_text(g.old_len),
                bytes_text(g.new_len)
            );
            if let Some(note) = &g.note {
                text.push(' ');
                text.push_str(note);
            }
            match (&g.fs, &g.fs_extended) {
                (FsKind::Ntfs, Some(Ok(size))) => text.push_str(&format!(
                    " Its NTFS file system was extended by Windows and now holds {}.",
                    bytes_text(*size)
                )),
                (FsKind::Ntfs, Some(Err(why))) => text.push_str(&format!(
                    " Its NTFS file system was not extended: {why}. Disk Management's Extend Volume can do it."
                )),
                (FsKind::Ntfs, None) => text.push_str(
                    " Its NTFS file system was not extended; Disk Management's Extend Volume can do it.",
                ),
                (FsKind::Unread, _) => text.push_str(&format!(
                    " Its file system's first sector could not be read ({}), so it was not extended; Disk Management's Extend Volume can do it once the drive reads.",
                    g.fs_error.as_deref().unwrap_or("no reason was given")
                )),
                (fs, _) => text.push_str(&format!(
                    " It holds {}, which Windows cannot extend in place, so the file system keeps its old size and the added space is not used until the volume is formatted again.",
                    fs.name()
                )),
            }
            text
        }
    }
}

/// The window's text when a run ends.
pub fn end_text(ran: &Ran, image: &ImageInfo, disk: &DiskInfo) -> String {
    let name = format!("Disk {}", disk.number);
    let unusable =
        format!("{name} has no partition table now and cannot be used until it is written again.");
    let areas = image.not_rescued();
    let zeros = match areas.len() {
        0 => String::new(),
        1 => format!(
            " One area the rescue could not read was written as zeros, and files over it may be damaged: {}.",
            areas_text(&areas, 5)
        ),
        n => format!(
            " {n} areas the rescue could not read ({} in all) were written as zeros, and files over them may be damaged: {}.",
            bytes_text(image.not_rescued_bytes()),
            areas_text(&areas, 5)
        ),
    };
    let grown = ran
        .grown
        .as_ref()
        .map(|g| format!(" {}", grow_text(g)))
        .unwrap_or_default();
    let notes: String = ran.notes.iter().map(|n| format!(" Also: {n}.")).collect();
    let text = match (&ran.ending, ran.head_written, &ran.checked) {
        (Ending::Failed(why), false, _) if !ran.touched => {
            format!("Nothing was written to {name}: {why}.")
        }
        (Ending::Failed(why), false, _) => format!("Writing failed: {why}. {unusable}"),
        (Ending::Stopped, false, _) => format!(
            "Stopped after writing {} of {}. {unusable}",
            bytes_text(ran.written),
            bytes_text(image.len)
        ),
        (_, true, Some(checked)) if !checked.mismatches.is_empty() => format!(
            "The image was written, but {} read back differently ({}). Do not use this drive: write it again, and if that happens again, use another drive.",
            if checked.mismatches.len() == 1 {
                "one part".to_string()
            } else {
                format!("{} parts", checked.mismatches.len())
            },
            areas_text(&checked.mismatches, 5)
        ),
        (Ending::Stopped, true, Some(checked)) => format!(
            "The image was written, and the check after writing was stopped after {} of {}; what was checked read back the same.{zeros}",
            bytes_text(checked.through),
            bytes_text(image.len)
        ),
        (Ending::Failed(why), true, _) => format!(
            "The image was written, then something failed: {why}.{zeros}"
        ),
        // The headline's "Finished" is the ledger's whole: the same condition, read once.
        _ => match drive_condition(ran) {
            None => format!(
                "Finished. {name} now holds the image, and every part read back the same.{zeros}{grown} If the drive the image came from is connected too, disconnect it: Windows takes one of two identical drives offline."
            ),
            Some(why) => format!(
                "The image was written and read back the same, but it is not complete: {why}.{zeros}"
            ),
        },
    };
    format!("{text}{notes}")
}

/// The ledger row's state for the drive.
fn drive_condition(ran: &Ran) -> Option<String> {
    match (&ran.ending, ran.head_written, &ran.checked) {
        (Ending::Failed(why), false, _) if !ran.touched => {
            Some(format!("nothing was written: {why}"))
        }
        (Ending::Failed(why), false, _) => Some(format!(
            "writing failed: {why}; the drive has no partition table and cannot be used until it is written again"
        )),
        (Ending::Stopped, false, _) => Some(
            "stopped before the end; the drive has no partition table and cannot be used until it is written again".into(),
        ),
        (_, true, Some(checked)) if !checked.mismatches.is_empty() => Some(format!(
            "{} read back differently; do not use this drive",
            match checked.mismatches.len() {
                1 => "1 chunk".to_string(),
                n => format!("{n} chunks"),
            }
        )),
        // Whole only once the drive has confirmed the writes that make it complete.
        _ if ran.unconfirmed.is_some() => Some(format!(
            "{}, so what was written may not all be on it; check it before use",
            ran.unconfirmed.as_deref().unwrap_or_default()
        )),
        _ => None,
    }
}

/// Everything a report says.
pub struct Report<'a> {
    pub image: &'a ImageInfo,
    pub disk: &'a DiskInfo,
    pub ran: &'a Ran,
    pub started: String,
    pub ended: String,
    pub grow_asked: bool,
}

/// The report's name, beside the image.
pub const REPORT_NAME: &str = "Write report.txt";

/// Writes the report into `out` from the ledger and the run.
pub fn write_report(out: &mut dyn Write, r: &Report) -> io::Result<()> {
    use super::output::END;
    let image = r.image;
    let disk = r.disk;
    let made_from = image
        .made_from
        .as_ref()
        .map_or_else(|| "not named by the map".into(), SourceId::text);
    let map = image.map_path.as_ref().map_or_else(
        || "none beside the image, so every byte was written as the image holds it".into(),
        |p| p.display().to_string(),
    );
    write!(
        out,
        "Write report\r\nThis report is complete only if its last line reads \"End of report\" with a full stop.\r\n\r\nImage: {}\r\nMap: {map}\r\nMade from: {made_from}\r\nWritten to: Disk {}, {}, {}, {} bytes\r\nErased: {}\r\nStarted: {}\r\nEnded: {}\r\n\r\nDrive\r\n",
        image.image.display(),
        disk.number,
        disk.model_text(),
        disk.serial_text(),
        disk.size,
        disk.volumes_text(),
        r.started,
        r.ended
    )?;
    // The drive is the run's one output, entered in a ledger like every recovery output.
    let mut ledger = super::ledger::Ledger::default();
    let id = ledger.made(
        0,
        PathBuf::from(format!("Disk {}", disk.number)),
        image.image.clone(),
        String::new(),
        image.len,
    );
    ledger.wrote(id, r.ran.written.min(image.len));
    ledger.zeroed(id, image.not_rescued());
    match drive_condition(r.ran) {
        Some(why) => ledger.partial(id, why),
        None => ledger.whole(id),
    }
    ledger.write_rows(out, Path::new(""), false)?;
    let areas = image.not_rescued();
    write!(
        out,
        "\r\nNot rescued, written as zeros: {}, {} bytes\r\n",
        self::areas(areas.len()),
        image.not_rescued_bytes()
    )?;
    for a in &areas {
        write!(
            out,
            "bytes {}-{}\t{} bytes ({})\r\n",
            a.start,
            a.end,
            a.end - a.start,
            bytes_text(a.end - a.start)
        )?;
    }
    match areas.len() {
        0 => {}
        1 => write!(out, "Files over this area may be damaged.\r\n")?,
        _ => write!(out, "Files over these areas may be damaged.\r\n")?,
    }
    if !r.ran.held.is_empty() {
        write!(out, "\r\nWhile it was written\r\n{}\r\n", r.ran.held)?;
    }
    write!(out, "\r\nCheck after writing\r\n")?;
    match &r.ran.checked {
        None => write!(out, "Not done: the image was not written in full.\r\n")?,
        Some(c) => {
            if c.complete && c.mismatches.is_empty() {
                write!(
                    out,
                    "Every chunk read back the same ({} bytes).\r\n",
                    c.through
                )?;
            } else if !c.complete {
                write!(
                    out,
                    "Stopped after {} bytes; the rest was not checked.\r\n",
                    c.through
                )?;
            }
            for m in &c.mismatches {
                write!(
                    out,
                    "READ BACK DIFFERENTLY: bytes {}-{}\r\n",
                    m.start, m.end
                )?;
            }
        }
    }
    write!(out, "\r\nGrowing the last partition\r\n")?;
    match (&r.ran.grown, r.grow_asked) {
        (_, false) => write!(out, "Off.\r\n")?,
        (None, true) => write!(out, "Not reached.\r\n")?,
        (Some(g), true) => write!(out, "{}\r\n", grow_text(g))?,
    }
    // The summary comes after the table, so a report cut short never shows one.
    write!(out, "\r\n{}\r\n", end_text(r.ran, image, disk))?;
    write!(out, "{END}")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard (cause E): the window's headline says "Finished" exactly when the ledger
    /// enters the drive whole: both read `drive_condition`, and the headline nowhere else.
    #[test]
    fn the_headline_finishes_only_when_the_ledger_is_whole() {
        let code = include_str!("restore.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let end = &code[code.find("pub fn end_text(").unwrap()..];
        let end = &end[..end.find("\n}\n").unwrap()];
        assert_eq!(end.matches("\"Finished.").count(), 1);
        let finished = end.find("\"Finished.").unwrap();
        let condition = end[..finished]
            .rfind("match drive_condition(ran) {")
            .unwrap();
        assert!(end[condition..finished].contains("None => format!("));
        let row = &code[code.find("    match drive_condition(r.ran) {").unwrap()..];
        assert!(row.starts_with("    match drive_condition(r.ran) {\n        Some(why) => ledger.partial(id, why),\n        None => ledger.whole(id),"));
    }

    /// The guard (cause E): the drive is entered whole only once it has confirmed the writes
    /// that make it complete; one that did not is partial, and says why.
    #[test]
    fn a_drive_that_did_not_confirm_its_writes_is_not_whole() {
        let mut ran = Ran::new();
        ran.touched = true;
        ran.head_written = true;
        assert_eq!(drive_condition(&ran), None);
        ran.unconfirmed = Some("the drive did not confirm its last writes (x)".into());
        let why = drive_condition(&ran).unwrap();
        assert!(why.contains("may not all be on it"), "{why}");
        let target = include_str!("target.rs");
        let target = target.split("#[cfg(test)]").next().unwrap();
        assert!(target.contains("ran.unconfirmed = unconfirmed;"));
        assert!(
            !target.contains("writer.finish()"),
            "the drive's confirmation is dropped"
        );
    }

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("diagtool-restore-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 + 1).collect()
    }

    /// The guard (round 11): a volume's map is matched by its drive's size, never the
    /// volume's: with no serial number to go by, a drive of the volume's model and of the
    /// drive's size is the one it may be, and a map without the drive's size cannot rule
    /// out any drive of that model.
    #[test]
    fn a_volume_s_map_is_matched_by_its_drive_s_size() {
        let volume = |disk_size| SourceId {
            model: "Samsung SSD 870".into(),
            serial: String::new(),
            size: 100 << 30,
            drive: None,
            sector: Some(512),
            scope: Some(Scope::Volume { offset: 1 << 20 }),
            disk_size,
        };
        let drive = disk(4, "", 500 << 30);
        assert!(is_source(&drive, &volume(Some(500 << 30)), None).is_some());
        assert!(is_source(&drive, &volume(Some(250 << 30)), None).is_none());
        assert!(is_source(&drive, &volume(None), None).is_some());
        // With a serial number, the drive's size stands in for a model that reads differently.
        let mut named = volume(Some(500 << 30));
        named.serial = "S5Y1".into();
        named.model = "Samsung SSD 870 EVO".into();
        assert!(is_source(&disk(4, "S5Y1", 500 << 30), &named, None).is_some());
    }

    /// A drive's first 8 KiB holding an MBR with `signature`, or a GPT for `sector`-byte
    /// sectors with the disk GUID 1A2B3C4D-0000-4000-8000-000000000001.
    fn head(gpt: Option<usize>, signature: u32) -> Vec<u8> {
        let mut head = vec![0u8; 8192];
        head[440..444].copy_from_slice(&signature.to_le_bytes());
        head[510] = 0x55;
        head[511] = 0xAA;
        head[446 + 4] = if gpt.is_some() { 0xEE } else { 0x07 };
        if let Some(sector) = gpt {
            head[sector..sector + 8].copy_from_slice(b"EFI PART");
            head[sector + 56..sector + 72].copy_from_slice(&[
                0x4D, 0x3C, 0x2B, 0x1A, 0, 0, 0, 0x40, 0x80, 0, 0, 0, 0, 0, 0, 1,
            ]);
        }
        head
    }

    /// The guard: a partition table ID read from an image's own first sectors, as Windows
    /// would report it for the drive, and only where the image starts with the drive's table.
    #[test]
    fn an_image_s_partition_table_is_read_as_windows_names_it() {
        const GUID: &str = "{1A2B3C4D-0000-4000-8000-000000000001}";
        assert_eq!(table_id(&head(Some(512), 0)).as_deref(), Some(GUID));
        assert_eq!(table_id(&head(Some(4096), 0)).as_deref(), Some(GUID));
        assert_eq!(
            table_id(&head(None, 0x1A2B_3C4D)).as_deref(),
            Some("1A2B3C4D")
        );
        assert_eq!(table_id(&head(None, 0)), None, "an MBR with no signature");
        assert_eq!(table_id(&[0u8; 8192]), None, "never read");
        let mut id = info(1 << 30).made_from.unwrap();
        id.scope = Some(Scope::Disk);
        assert_eq!(
            image_table(&head(None, 7), &id).as_deref(),
            Some("00000007")
        );
        // A volume's image starts with its boot sector, which can pass for an MBR.
        id.scope = Some(Scope::Volume { offset: 1 << 20 });
        assert_eq!(image_table(&head(Some(512), 7), &id), None);
        // A map that does not say what was read: only a GPT header is unmistakable.
        id.scope = None;
        assert_eq!(image_table(&head(None, 7), &id), None);
        assert_eq!(image_table(&head(Some(512), 7), &id).as_deref(), Some(GUID));
    }

    /// The guard: a drive of the source's model and size with another partition table is
    /// another drive; the same table, or a table that could not be read, leaves the doubt.
    /// The source's own serial number refuses whatever its table.
    #[test]
    fn a_partition_table_tells_a_look_alike_from_the_source() {
        let source = SourceId {
            model: "Samsung SSD 870".into(),
            serial: String::new(),
            size: 500 << 30,
            drive: None,
            sector: Some(512),
            scope: Some(Scope::Disk),
            disk_size: Some(500 << 30),
        };
        const TABLE: &str = "{1A2B3C4D-0000-4000-8000-000000000001}";
        let table = Some(TABLE);
        let mut other = disk(4, "S5Y1", 500 << 30);
        assert!(is_source(&other, &source, table).is_some(), "no table read");
        other.disk_id = "{9F8E7D6C-0000-4000-8000-000000000002}".into();
        assert_eq!(is_source(&other, &source, table), None);
        assert!(
            is_source(&other, &source, None).is_some(),
            "the source's not known"
        );
        other.disk_id = "{1a2b3c4d-0000-4000-8000-000000000001}".into();
        assert!(
            is_source(&other, &source, table).is_some(),
            "the same table"
        );
        // Named by its serial number, a repartitioned source is still the source.
        let mut named = source.clone();
        named.serial = "S5Y1".into();
        other.disk_id = "{9F8E7D6C-0000-4000-8000-000000000002}".into();
        assert_eq!(is_source(&other, &named, table), Some(SAME_DRIVE));
        // Behind an adapter that hides the drive's own serial number.
        let (image, mut candidate) = usb_case(None, 1_000_000_000);
        let made_from = image.made_from.as_ref().unwrap();
        assert!(is_source(&candidate, made_from, table).is_some());
        candidate.disk_id = "{9F8E7D6C-0000-4000-8000-000000000002}".into();
        assert_eq!(is_source(&candidate, made_from, table), None);
        candidate.disk_id = TABLE.into();
        assert!(is_source(&candidate, made_from, table).is_some());
    }

    fn disk(number: u32, serial: &str, size: u64) -> DiskInfo {
        DiskInfo {
            number,
            model: "Samsung SSD 870".into(),
            serial: serial.into(),
            size,
            sector: 512,
            volumes: Vec::new(),
            disk_id: String::new(),
            location: String::new(),
            usb: false,
            drive: None,
        }
    }

    fn info(len: u64) -> ImageInfo {
        let mut map = Map::new(len);
        map.set(0, len, Status::Rescued);
        ImageInfo {
            image: PathBuf::from(r"D:\x.img"),
            map_path: None,
            len,
            map,
            made_from: Some(SourceId {
                model: "Samsung SSD 870".into(),
                serial: "S5Y1NX0R123456".into(),
                size: len,
                drive: None,
                sector: None,
                scope: None,
                disk_size: None,
            }),
            layout: Layout::Mbr,
            table: None,
        }
    }

    /// Writes `data` and a map marking `bad` as bad, and loads them.
    fn image_with(dir: &Path, data: &[u8], bad: &[Range<u64>]) -> (ImageInfo, Held) {
        let path = dir.join("drive.img");
        std::fs::write(&path, data).unwrap();
        let mut map = Map::new(data.len() as u64);
        map.set(0, data.len() as u64, Status::Rescued);
        for r in bad {
            map.set(r.start, r.end - r.start, Status::Bad);
        }
        map.phase = super::super::image::Phase::Finished;
        let heading = vec![
            "Source model: Test disk".to_string(),
            "Source serial: TEST-0001".into(),
            format!("Source size: {} bytes", data.len()),
        ];
        std::fs::write(dir.join("drive.map"), map.to_text(&heading)).unwrap();
        load_image(&path).unwrap()
    }

    #[test]
    fn the_source_system_and_image_disks_are_refused() {
        let image = info(1_000_000_000);
        let guards = Guards {
            system: vec![0],
            boot: vec![0],
            image: vec![1, 2],
            program: vec![1, 2],
            paging: vec![1, 2],
            unknown: Vec::new(),
        };
        // The system and boot disk.
        let why = refusals(&disk(0, "AAAA1111", 2_000_000_000), &image, &guards);
        assert!(why.contains(&"Windows runs from it".to_string()), "{why:?}");
        assert!(
            why.contains(&"the computer starts from it".to_string()),
            "{why:?}"
        );
        // The disks of a striped volume holding the image, the program and the page file.
        for number in [1, 2] {
            let why = refusals(&disk(number, "BBBB", 2_000_000_000), &image, &guards);
            assert_eq!(why.len(), 3, "{why:?}");
        }
        // The drive the image came from, by serial number, even at another disk number.
        let why = refusals(&disk(7, "s5y1nx0r123456", 1_000_000_000), &image, &guards);
        assert_eq!(why, vec!["it is the drive this image was made from"]);
        // Too small.
        let why = refusals(&disk(8, "OTHER", 999_999_488), &image, &guards);
        assert_eq!(why.len(), 1);
        assert!(
            why[0].starts_with("it is smaller than the image"),
            "{why:?}"
        );
        // A good replacement: same model, another serial, larger.
        assert!(refusals(&disk(9, "OTHER", 2_000_000_000), &image, &guards).is_empty());
        // The same size and model as the source is fine with a different serial.
        assert!(refusals(&disk(9, "OTHER", 1_000_000_000), &image, &guards).is_empty());
    }

    /// The guard: an image made through a USB adapter names the drive's own serial number,
    /// so the drive is refused as a target once it is on a SATA port, where Windows reports
    /// that serial number and not the adapter's.
    #[test]
    fn a_drive_imaged_through_a_usb_adapter_is_refused_on_sata() {
        let mut image = info(1_000_000_000);
        let made_from = image.made_from.as_mut().unwrap();
        made_from.model = "ASMT 2115".into();
        made_from.serial = "00000000000000000000".into();
        made_from.drive = Some(crate::tools::drives::ata::DriveId {
            model: "ST2000LM007-1R8174".into(),
            serial: "WDZ1ABCD".into(),
        });
        let guards = Guards::default();
        let mut bare = disk(6, "WDZ1ABCD", 1_000_000_000);
        bare.model = "ST2000LM007-1R8174".into();
        assert_eq!(
            refusals(&bare, &image, &guards),
            vec!["it is the drive this image was made from"]
        );
        // Another drive of that model is a fine target.
        bare.serial = "WDZ9XYZ".into();
        assert!(refusals(&bare, &image, &guards).is_empty());
        // Back in its enclosure it is refused by the adapter's serial number, as before.
        let enclosed = DiskInfo {
            model: "ASMT 2115".into(),
            ..disk(6, "00000000000000000000", 1_000_000_000)
        };
        assert!(!refusals(&enclosed, &image, &guards).is_empty());
    }

    /// An image made over USB of the whole drive with its own serial number WDZ1ABCD, and a
    /// drive on another USB adapter: `own` is its own identity, None when it could not be read.
    fn usb_case(own: Option<&str>, size: u64) -> (ImageInfo, DiskInfo) {
        let mut image = info(1_000_000_000);
        let made_from = image.made_from.as_mut().unwrap();
        made_from.scope = Some(Scope::Disk);
        made_from.disk_size = Some(1_000_000_000);
        made_from.model = "ASMT 2115".into();
        made_from.serial = "00000000000000000000".into();
        made_from.drive = Some(DriveId {
            model: "ST2000LM007-1R8174".into(),
            serial: "WDZ1ABCD".into(),
        });
        let candidate = DiskInfo {
            model: "JMicron JMS578".into(),
            usb: true,
            drive: own.map(|serial| DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: serial.into(),
            }),
            ..disk(7, "0123456789AB", size)
        };
        (image, candidate)
    }

    /// The guard: the source in another enclosure, whose serial number Windows reports is
    /// that adapter's, is refused by the drive's own serial number.
    #[test]
    fn the_source_in_another_enclosure_is_refused() {
        let (image, candidate) = usb_case(Some("WDZ1ABCD"), 1_000_000_000);
        assert_eq!(
            refusals(&candidate, &image, &Guards::default()),
            vec!["it is the drive this image was made from"]
        );
        // Its own serial number decides whatever size the adapter reports.
        let (image, candidate) = usb_case(Some(" wdz1abcd "), 999_999_488);
        assert!(!refusals(&candidate, &image, &Guards::default()).is_empty());
    }

    /// The guard: a drive on USB of the source's size whose own identity could not be read
    /// may be the source behind an adapter that hides it, so it is refused, saying how to
    /// tell; at another size it is another drive.
    #[test]
    fn a_usb_drive_of_the_source_size_with_no_identity_is_refused() {
        let (image, candidate) = usb_case(None, 1_000_000_000);
        let why = refusals(&candidate, &image, &Guards::default());
        assert!(
            why.len() == 1
                && why[0].contains("cannot be ruled out")
                && why[0].contains("through SATA or an adapter that passes ATA commands"),
            "{why:?}"
        );
        let (image, candidate) = usb_case(None, 2_000_000_000);
        assert!(refusals(&candidate, &image, &Guards::default()).is_empty());
    }

    /// The guard: a 500 GB volume imaged on a 1 TB drive is refused by the drive's size when
    /// the drive comes back behind an adapter that hides its identity; a 500 GB drive is not.
    #[test]
    fn a_volume_source_is_refused_by_its_drive_size() {
        let (mut image, candidate) = usb_case(None, 1_000_000_000_000);
        let made_from = image.made_from.as_mut().unwrap();
        made_from.size = 500_000_000_000;
        made_from.scope = Some(Scope::Volume { offset: 1 << 20 });
        made_from.disk_size = Some(1_000_000_000_000);
        let why = refusals(&candidate, &image, &Guards::default());
        assert!(
            why.len() == 1 && why[0].contains("cannot be ruled out"),
            "{why:?}"
        );
        let half = DiskInfo {
            size: 500_000_000_000,
            ..candidate
        };
        assert!(refusals(&half, &image, &Guards::default()).is_empty());
    }

    /// The guard: without the drive's size, a whole-disk map falls back to its size, and a
    /// volume's map, or one that names no part, refuses a hidden USB drive of any size.
    #[test]
    fn without_the_drive_size_a_volume_map_refuses_any_hidden_usb_drive() {
        let (mut image, candidate) = usb_case(None, 2_000_000_000);
        image.made_from.as_mut().unwrap().disk_size = None;
        assert!(refusals(&candidate, &image, &Guards::default()).is_empty());
        let same = DiskInfo {
            size: 1_000_000_000,
            ..candidate.clone()
        };
        assert!(!refusals(&same, &image, &Guards::default()).is_empty());
        for scope in [Some(Scope::Volume { offset: 0 }), None] {
            image.made_from.as_mut().unwrap().scope = scope;
            let why = refusals(&candidate, &image, &Guards::default());
            assert!(
                why.len() == 1 && why[0].contains("cannot be ruled out"),
                "{scope:?} {why:?}"
            );
        }
        // A drive whose own identity was read is judged by it, not by size.
        let other = DiskInfo {
            drive: Some(DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: "WDZ9XYZ".into(),
            }),
            ..candidate
        };
        assert!(refusals(&other, &image, &Guards::default()).is_empty());
    }

    /// Another drive on USB, and an NVMe drive with no ATA identity at the source's size,
    /// are fine targets.
    #[test]
    fn another_drive_and_an_nvme_target_are_allowed() {
        let (image, candidate) = usb_case(Some("WDZ9XYZ"), 1_000_000_000);
        assert!(refusals(&candidate, &image, &Guards::default()).is_empty());
        let nvme = DiskInfo {
            model: "Samsung SSD 980".into(),
            ..disk(8, "0025_3852_1190_1234.", 1_000_000_000)
        };
        assert!(refusals(&nvme, &image, &Guards::default()).is_empty());
    }

    #[test]
    fn without_serial_numbers_a_drive_like_the_source_is_refused() {
        let mut image = info(1_000_000_000);
        image.made_from.as_mut().unwrap().serial = String::new();
        let guards = Guards::default();
        let why = refusals(&disk(5, "", 1_000_000_000), &image, &guards);
        assert!(why[0].starts_with("it may be the drive"), "{why:?}");
        let why = refusals(&disk(5, "NEWDRIVE", 1_000_000_000), &image, &guards);
        assert!(why[0].starts_with("it may be the drive"), "{why:?}");
        // Another size is another drive.
        assert!(refusals(&disk(5, "", 2_000_000_000), &image, &guards).is_empty());
    }

    #[test]
    fn what_could_not_be_found_refuses_every_disk() {
        let image = info(1000);
        let guards = Guards {
            unknown: vec!["the disk Windows runs from could not be found".into()],
            ..Guards::default()
        };
        let why = refusals(&disk(9, "OTHER", 2_000_000_000), &image, &guards);
        assert_eq!(
            why,
            vec![
                "the disk Windows runs from could not be found, so no drive can be written safely"
            ]
        );
    }

    #[test]
    fn a_volume_that_spans_another_disk_and_a_sector_mismatch_are_refused() {
        let mut image = info(1_000_000_000);
        image.layout = Layout::Gpt(512);
        let mut target = disk(5, "OTHER", 2_000_000_000);
        target.volumes.push(VolumeInfo {
            mount: "D:".into(),
            label: "Archive".into(),
            file_system: "NTFS".into(),
            size: 1_000_000_000,
            other_disks: vec![6],
        });
        target.sector = 4096;
        let why = refusals(&target, &image, &Guards::default());
        assert_eq!(why.len(), 2, "{why:?}");
        assert!(why[0].contains("also lies on disk 6"), "{why:?}");
        assert!(why[1].contains("4096 bytes"), "{why:?}");
    }

    /// The guard: a drive whose sector size Windows did not report is refused, whatever the
    /// image's layout; its size is never taken as 512 bytes.
    #[test]
    fn a_drive_with_no_sector_size_is_refused() {
        for layout in [Layout::Mbr, Layout::Gpt(512)] {
            let mut image = info(1_000_000_000);
            image.layout = layout;
            let mut target = disk(5, "OTHER", 2_000_000_000);
            target.sector = 0;
            let why = refusals(&target, &image, &Guards::default());
            assert_eq!(why.len(), 1, "{why:?}");
            assert!(why[0].contains("did not report its sector size"), "{why:?}");
        }
    }

    /// The guard: the confirmation is something no other connected drive shares. A serial
    /// whose last four another drive's serial shares gives way to the disk ID, then to the
    /// size and location, and only without either to the number and size.
    #[test]
    fn the_confirmation_names_what_tells_the_drive_apart() {
        let d = disk(5, "0000_0000_0000_0001_00A0_7523_E87A_60DA.", 2_000_000_000);
        let confirm = Confirm::of(&d, std::slice::from_ref(&d));
        assert_eq!(confirm, Confirm::Serial("60DA".into()));
        assert!(confirm.matches("60da"));
        assert!(confirm.matches(" 60DA "));
        assert!(!confirm.matches("E87A"));
        assert!(!confirm.matches(""));

        // Two drives of one model whose serials end alike.
        let mut a = disk(5, "WD-AAAA1234", 2_000_000_000);
        a.disk_id = "{1A2B3C4D-0000-4000-8000-000000000001}".into();
        a.location = "3:0:1:0".into();
        let mut b = disk(6, "WD-BBBB1234", 2_000_000_000);
        b.disk_id = "{9F8E7D6C-0000-4000-8000-000000000002}".into();
        b.location = "3:0:2:0".into();
        let both = [a.clone(), b.clone()];
        let confirm = Confirm::of(&a, &both);
        assert_eq!(confirm, Confirm::DiskId("1A2B3C4D".into()));
        assert!(confirm.matches("1a2b3c4d"));
        assert!(
            !confirm.matches("1234"),
            "the shared serial ending confirms it"
        );
        assert!(confirm.prompt(5).contains("disk ID"));

        // Blank drives: no disk ID, so the size and location.
        a.disk_id.clear();
        b.disk_id.clear();
        let both = [a.clone(), b.clone()];
        let confirm = Confirm::of(&a, &both);
        assert_eq!(confirm, Confirm::SizeAndLocation("2.0 GB 3:0:1:0".into()));
        assert!(confirm.matches("2.0 gb 3:0:1:0"));
        assert!(confirm.matches("2.0 GB, 3 0 1 0"));
        assert!(!confirm.matches("2.0 GB 3:0:2:0"));
        assert!(!confirm.matches("1234"));
        assert!(a.ident_text().contains("location 3:0:1:0"));

        // Disk IDs that begin alike do not tell drives apart either.
        a.disk_id = "1A2B3C4D".into();
        b.disk_id = "{1A2B3C4D-0000-4000-8000-000000000002}".into();
        let both = [a.clone(), b.clone()];
        assert!(matches!(
            Confirm::of(&a, &both),
            Confirm::SizeAndLocation(_)
        ));

        // Nothing but the number.
        let d = disk(5, "  ", 2_147_483_648);
        let confirm = Confirm::of(&d, &[]);
        assert_eq!(confirm, Confirm::NumberAndSize("5 2.1 GB".into()));
        assert!(confirm.matches("5  2.1 gb"));
        assert!(!confirm.matches("4 2.1 GB"));
        assert!(!confirm.matches(""));
        assert!(confirm.prompt(5).contains("no serial number"));
    }

    #[test]
    fn layouts_are_read_from_the_first_sectors() {
        let mut head = vec![0u8; 8192];
        assert_eq!(layout_of(&head), Layout::None);
        head[510] = 0x55;
        head[511] = 0xAA;
        head[446 + 4] = 0x07;
        assert_eq!(layout_of(&head), Layout::Mbr);
        head[446 + 4] = 0xEE;
        head[4096..4104].copy_from_slice(b"EFI PART");
        assert_eq!(layout_of(&head), Layout::Gpt(4096));
        head[512..520].copy_from_slice(b"EFI PART");
        assert_eq!(layout_of(&head), Layout::Gpt(512));
    }

    #[test]
    fn the_image_is_written_with_unrescued_areas_as_zeros_and_checks_clean() {
        let dir = temp("write");
        let len = 9 * (1 << 20) + 3 * 512;
        let data = pattern(len);
        let bad = [(2 << 20) + 512..(2 << 20) + 4096, 7 << 20..(7 << 20) + 512];
        let (image, mut held) = image_with(&dir, &data, &bad);
        assert_eq!(image.not_rescued(), bad.to_vec());
        let mut target = MemTarget::new(16 << 20, 0xEE);
        let ran = run_on(
            &mut held.reader,
            &image,
            &mut target,
            false,
            &AtomicBool::new(false),
            &Progress::default(),
        );
        assert_eq!(ran.ending, Ending::Finished);
        assert!(ran.head_written);
        let checked = ran.checked.clone().unwrap();
        assert!(checked.complete && checked.mismatches.is_empty());
        let mut expected = data.clone();
        for r in &bad {
            expected[r.start as usize..r.end as usize].fill(0);
        }
        assert_eq!(&target.data[..len], &expected[..]);
        // The old contents past the image are left, but the drive's last MiB is cleared.
        assert!(target.data[len..(15 << 20)].iter().all(|b| *b == 0xEE));
        assert!(target.data[15 << 20..].iter().all(|b| *b == 0));
        let disk = disk(5, "OTHER", 16 << 20);
        let text = end_text(&ran, &image, &disk);
        assert!(
            text.starts_with("Finished. Disk 5 now holds the image"),
            "{text}"
        );
        // A drive that did not confirm its last writes is partial in the ledger, so the
        // headline does not say Finished either.
        let mut unconfirmed = ran.clone();
        unconfirmed.unconfirmed = Some("the drive did not confirm its last writes (x)".into());
        let said = end_text(&unconfirmed, &image, &disk);
        assert!(
            !said.contains("Finished") && said.contains("not complete"),
            "{said}"
        );
        assert!(
            text.contains("2 areas the rescue could not read (4.1 kB in all)"),
            "{text}"
        );
        assert!(
            text.contains("at 2.1 MB, 3.6 kB; at 7.3 MB, 512 B"),
            "{text}"
        );
        drop(held);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A target that records the order of writes and stops the run after `stop_after`.
    struct Watched {
        inner: MemTarget,
        writes: Vec<u64>,
        stop_after: usize,
        stop: std::sync::Arc<AtomicBool>,
    }

    impl Target for Watched {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn sector(&self) -> u32 {
            self.inner.sector()
        }
        fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
            self.writes.push(offset);
            if self.writes.len() >= self.stop_after {
                self.stop.store(true, Ordering::Relaxed);
            }
            self.inner.write_at(offset, data)
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_at(offset, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_partition_table_is_cleared_first_and_written_last() {
        let dir = temp("order");
        let len = 10 << 20;
        let mut data = pattern(len);
        data[510] = 0x55;
        data[511] = 0xAA;
        let (image, mut held) = image_with(&dir, &data, &[]);
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let mut target = Watched {
            inner: MemTarget::new(len, 0x55),
            writes: Vec::new(),
            stop_after: usize::MAX,
            stop: stop.clone(),
        };
        let ran = run_on(
            &mut held.reader,
            &image,
            &mut target,
            false,
            &stop,
            &Progress::default(),
        );
        assert_eq!(ran.ending, Ending::Finished);
        assert_eq!(target.writes.first(), Some(&0), "the head is cleared first");
        assert_eq!(target.writes.last(), Some(&0), "the head is written last");
        assert_eq!(target.writes.iter().filter(|w| **w == 0).count(), 2);
        // Stopped part way: the head stays zeros, so nothing looks like a whole drive.
        let mut target = Watched {
            inner: MemTarget::new(len, 0x55),
            writes: Vec::new(),
            stop_after: 2,
            stop: stop.clone(),
        };
        stop.store(false, Ordering::Relaxed);
        let ran = run_on(
            &mut held.reader,
            &image,
            &mut target,
            false,
            &stop,
            &Progress::default(),
        );
        assert_eq!(ran.ending, Ending::Stopped);
        assert!(!ran.head_written);
        assert!(target.inner.data[..HEAD as usize].iter().all(|b| *b == 0));
        let text = end_text(&ran, &image, &disk(5, "OTHER", len as u64));
        assert!(
            text.contains("has no partition table now and cannot be used"),
            "{text}"
        );
        drop(held);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_write_leaves_no_partition_table() {
        let dir = temp("fail");
        let data = pattern(6 << 20);
        let (image, mut held) = image_with(&dir, &data, &[]);
        let mut target = MemTarget::new(8 << 20, 0x11);
        target.fail_at = Some(3 << 20);
        let ran = run_on(
            &mut held.reader,
            &image,
            &mut target,
            false,
            &AtomicBool::new(false),
            &Progress::default(),
        );
        assert!(matches!(ran.ending, Ending::Failed(_)), "{:?}", ran.ending);
        assert!(!ran.head_written && ran.checked.is_none());
        assert!(target.data[..HEAD as usize].iter().all(|b| *b == 0));
        drop(held);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_byte_changed_after_writing_is_found_by_the_check() {
        let dir = temp("flip");
        let data = pattern(9 << 20);
        let (image, mut held) = image_with(&dir, &data, &[]);
        let mut target = MemTarget::new(10 << 20, 0);
        let stop = AtomicBool::new(false);
        let progress = Progress::default();
        let mut ran = Ran::new();
        let chunks = write_image(
            &mut held.reader,
            &image,
            &mut target,
            &stop,
            &progress,
            &mut ran,
        )
        .unwrap();
        target.data[(6 << 20) + 17] ^= 0x40;
        let checked = check_written(&mut target, &chunks, &stop, &progress);
        assert!(checked.complete);
        assert_eq!(checked.mismatches, vec![(5 << 20)..(9 << 20)]);
        assert_eq!(progress.mismatches.load(Ordering::Relaxed), 1);
        ran.checked = Some(checked);
        let text = end_text(&ran, &image, &disk(5, "X", 10 << 20));
        assert!(
            text.contains("one part read back differently (at 5.2 MB, 4.2 MB)"),
            "{text}"
        );
        drop(held);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_image_and_map_that_do_not_belong_together_are_refused() {
        let dir = temp("lengths");
        let path = dir.join("drive.img");
        std::fs::write(&path, vec![1u8; 4096]).unwrap();
        let mut map = Map::new(2048);
        map.set(0, 2048, Status::Rescued);
        std::fs::write(dir.join("drive.map"), map.to_text(&[])).unwrap();
        let err = load_image(&path).err().unwrap();
        assert!(err.contains("do not belong together"), "{err}");
        let mut map = Map::new(8192);
        map.set(0, 8192, Status::Rescued);
        std::fs::write(dir.join("drive.map"), map.to_text(&[])).unwrap();
        let err = load_image(&path).err().unwrap();
        assert!(err.contains("cut short"), "{err}");
        // A ddrescue image may stop short of an unread tail; that tail is zeros.
        let mut map = Map::new(8192);
        map.set(0, 4096, Status::Rescued);
        std::fs::write(dir.join("drive.map"), map.to_text(&[])).unwrap();
        let (info, mut held) = load_image(&path).unwrap();
        assert_eq!(info.len, 8192);
        let mut buf = vec![9u8; 8192];
        held.reader.read(0, &mut buf).unwrap();
        assert!(buf[..4096].iter().all(|b| *b == 1) && buf[4096..].iter().all(|b| *b == 0));
        // Held: it cannot be written or replaced while in use here.
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(held);
        // Without a map, every byte counts as read.
        std::fs::remove_file(dir.join("drive.map")).unwrap();
        let (info, held) = load_image(&path).unwrap();
        assert!(info.map_path.is_none() && info.not_rescued().is_empty());
        drop(held);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// A GPT drive image of `sectors` sectors with partitions (type, first, last).
    pub(crate) fn gpt_image(sectors: u64, parts: &[([u8; 16], u64, u64)]) -> Vec<u8> {
        let s = 512usize;
        let mut d = vec![0u8; sectors as usize * s];
        d[446 + 4] = 0xEE;
        put32(&mut d, 446 + 8, 1);
        put32(&mut d, 446 + 12, (sectors - 1) as u32);
        d[510] = 0x55;
        d[511] = 0xAA;
        let mut entries = vec![0u8; 128 * 128];
        for (i, (kind, first, last)) in parts.iter().enumerate() {
            let e = i * 128;
            entries[e..e + 16].copy_from_slice(kind);
            entries[e + 16] = i as u8 + 1;
            put64(&mut entries, e + 32, *first);
            put64(&mut entries, e + 40, *last);
            // An NTFS boot sector at the partition's start.
            d[*first as usize * s + 3..*first as usize * s + 11].copy_from_slice(b"NTFS    ");
        }
        let crc = crc32(&entries);
        let last = sectors - 1;
        let mut h = vec![0u8; s];
        h[..8].copy_from_slice(b"EFI PART");
        put32(&mut h, 8, 0x0001_0000);
        put32(&mut h, 12, 92);
        put64(&mut h, 24, 1);
        put64(&mut h, 32, last);
        put64(&mut h, 40, 34);
        put64(&mut h, 48, last - 33);
        put64(&mut h, 72, 2);
        put32(&mut h, 80, 128);
        put32(&mut h, 84, 128);
        put32(&mut h, 88, crc);
        let hc = crc32(&h[..92]);
        put32(&mut h, 16, hc);
        let mut b = h.clone();
        put64(&mut b, 24, last);
        put64(&mut b, 32, 1);
        put64(&mut b, 72, last - 32);
        put32(&mut b, 16, 0);
        let bc = crc32(&b[..92]);
        put32(&mut b, 16, bc);
        d[s..2 * s].copy_from_slice(&h);
        d[2 * s..34 * s].copy_from_slice(&entries);
        d[(last as usize - 32) * s..last as usize * s].copy_from_slice(&entries);
        d[last as usize * s..].copy_from_slice(&b);
        d
    }

    const BASIC_DATA: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    /// Checks a GPT the way firmware and Windows do: both headers, their checksums and
    /// their entries, each pointing at the other.
    fn gpt_valid(d: &[u8]) -> (u64, u64) {
        let s = 512usize;
        let sectors = (d.len() / s) as u64;
        let h = &d[s..2 * s];
        let b = &d[(sectors as usize - 1) * s..];
        for (header, mine, other) in [(h, 1, sectors - 1), (b, sectors - 1, 1)] {
            assert_eq!(&header[..8], b"EFI PART");
            let mut c = header[..92].to_vec();
            put32(&mut c, 16, 0);
            assert_eq!(crc32(&c), le32(header, 16), "header checksum");
            assert_eq!(le64(header, 24), mine);
            assert_eq!(le64(header, 32), other);
            let at = le64(header, 72) as usize * s;
            assert_eq!(crc32(&d[at..at + 128 * 128]), le32(header, 88), "entries");
        }
        assert_eq!(le64(h, 48), sectors - 34);
        assert_eq!(le32(d, 446 + 12) as u64, sectors - 1);
        (le64(&d[2 * s..], 32), le64(&d[2 * s..], 40))
    }

    #[test]
    fn growing_a_gpt_moves_its_backup_to_the_new_end() {
        let image = gpt_image(8192, &[(BASIC_DATA, 2048, 6143)]);
        gpt_valid(&image);
        let mut target = MemTarget::new(64 << 20, 0x77);
        target.data[..image.len()].copy_from_slice(&image);
        let grown = grow(&mut target, image.len() as u64);
        let GrowEnd::Grown(g) = grown else {
            panic!("{grown:?}")
        };
        assert_eq!((g.table, g.number, g.fs), (Table::Gpt, 1, FsKind::Ntfs));
        assert_eq!(g.offset, 2048 * 512);
        assert_eq!(g.old_len, 4096 * 512);
        let (first, last) = gpt_valid(&target.data);
        assert_eq!(first, 2048);
        // Ends on the last whole MiB before the backup entries.
        assert_eq!((last + 1) * 512, 63 << 20);
        assert_eq!(g.new_len, (last + 1 - 2048) * 512);
        // The old backup header is gone.
        assert!(target.data[8191 * 512..8192 * 512].iter().all(|b| *b == 0));
        assert!(
            grow_text(&GrowEnd::Grown(g)).contains("Partition 1 (GPT) was grown from 2.1 MB to")
        );
    }

    #[test]
    fn a_recovery_partition_last_is_not_grown() {
        let image = gpt_image(
            8192,
            &[(BASIC_DATA, 2048, 4095), (GPT_RECOVERY, 4096, 6143)],
        );
        let mut target = MemTarget::new(64 << 20, 0);
        target.data[..image.len()].copy_from_slice(&image);
        let before = target.data.clone();
        let grown = grow(&mut target, image.len() as u64);
        assert!(
            matches!(&grown, GrowEnd::NotGrown(why) if why.contains("recovery partition")),
            "{grown:?}"
        );
        assert_eq!(target.data, before, "nothing was changed");
    }

    #[test]
    fn a_damaged_gpt_is_left_alone() {
        let mut image = gpt_image(8192, &[(BASIC_DATA, 2048, 6143)]);
        image[2 * 512 + 40] ^= 1;
        let mut target = MemTarget::new(64 << 20, 0);
        target.data[..image.len()].copy_from_slice(&image);
        let before = target.data.clone();
        assert!(matches!(
            grow(&mut target, image.len() as u64),
            GrowEnd::NotGrown(_)
        ));
        assert_eq!(target.data, before);
    }

    fn mbr_image(sectors: u64, parts: &[(u8, u32, u32)]) -> Vec<u8> {
        let mut d = vec![0u8; sectors as usize * 512];
        for (i, (kind, start, count)) in parts.iter().enumerate() {
            let e = 446 + 16 * i;
            d[e + 4] = *kind;
            put32(&mut d, e + 8, *start);
            put32(&mut d, e + 12, *count);
            let at = *start as usize * 512;
            d[at + 3..at + 11].copy_from_slice(b"NTFS    ");
        }
        d[510] = 0x55;
        d[511] = 0xAA;
        d
    }

    /// A file system whose first sector cannot be read is said to be unread, with why, and
    /// never taken for an unrecognized one.
    #[test]
    fn a_file_system_that_cannot_be_read_is_said_to_be_unread() {
        struct Refuses(MemTarget);
        impl Target for Refuses {
            fn len(&self) -> u64 {
                self.0.len()
            }
            fn sector(&self) -> u32 {
                self.0.sector()
            }
            fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
                self.0.write_at(offset, data)
            }
            fn read_at(&mut self, _: u64, _: &mut [u8]) -> io::Result<()> {
                Err(io::Error::other("the drive refused the read"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut target = Refuses(MemTarget::new(1 << 20, 0));
        let (fs, why) = fs_at(&mut target, 4096);
        assert_eq!(
            (fs, why.as_deref()),
            (FsKind::Unread, Some("the drive refused the read"))
        );
        let image = mbr_image(8192, &[(0x07, 2048, 2048), (0x07, 4096, 4096)]);
        let mut target = MemTarget::new(32 << 20, 0);
        target.data[..image.len()].copy_from_slice(&image);
        let GrowEnd::Grown(mut g) = grow(&mut target, image.len() as u64) else {
            panic!()
        };
        (g.fs, g.fs_error) = (FsKind::Unread, why);
        assert!(grow_text(&GrowEnd::Grown(g)).contains(
            "Its file system's first sector could not be read (the drive refused the read)"
        ));
    }

    #[test]
    fn growing_an_mbr_extends_the_last_entry() {
        let image = mbr_image(8192, &[(0x07, 2048, 2048), (0x07, 4096, 4096)]);
        let mut target = MemTarget::new(32 << 20, 0);
        target.data[..image.len()].copy_from_slice(&image);
        let GrowEnd::Grown(g) = grow(&mut target, image.len() as u64) else {
            panic!()
        };
        assert_eq!((g.table, g.number, g.offset), (Table::Mbr, 2, 4096 * 512));
        assert_eq!(le32(&target.data, 446 + 16 + 12), (32 << 20) / 512 - 4096);
        assert_eq!(le32(&target.data, 446 + 12), 2048, "the first is unchanged");
        assert_eq!(g.new_len, (32 << 20) - 4096 * 512);
        // An extended partition last is not grown.
        let image = mbr_image(8192, &[(0x07, 2048, 2048), (0x0F, 4096, 4096)]);
        let mut target = MemTarget::new(32 << 20, 0);
        target.data[..image.len()].copy_from_slice(&image);
        assert!(matches!(
            grow(&mut target, image.len() as u64),
            GrowEnd::NotGrown(_)
        ));
    }

    #[test]
    fn the_report_lists_the_drive_the_zeroed_areas_and_ends_complete() {
        let image = {
            let mut i = info(10 << 20);
            i.map.set(3 << 20, 4096, Status::Bad);
            i
        };
        let disk = disk(5, "OTHER", 20 << 20);
        let mut ran = Ran::new();
        ran.written = image.len;
        ran.head_written = true;
        ran.checked = Some(Checked {
            through: image.len,
            complete: true,
            mismatches: Vec::new(),
        });
        let mut out = Vec::new();
        write_report(
            &mut out,
            &Report {
                image: &image,
                disk: &disk,
                ran: &ran,
                started: "2026-11-06 10:00".into(),
                ended: "2026-11-06 10:05".into(),
                grow_asked: false,
            },
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Disk 5\t10485760 bytes\tDAMAGED: 4096 bytes unreadable"),
            "{text}"
        );
        assert!(
            text.contains("bytes 3145728-3149824\t4096 bytes (4.1 kB)"),
            "{text}"
        );
        assert!(text.contains("Every chunk read back the same"), "{text}");
        assert!(text.ends_with("\r\nEnd of report."), "{text}");
        // A stopped run's row says the drive cannot be used.
        ran.head_written = false;
        ran.ending = Ending::Stopped;
        ran.written = 4 << 20;
        ran.checked = None;
        let mut out = Vec::new();
        write_report(
            &mut out,
            &Report {
                image: &image,
                disk: &disk,
                ran: &ran,
                started: String::new(),
                ended: String::new(),
                grow_asked: true,
            },
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("PARTIAL: stopped before the end; the drive has no partition table"),
            "{text}"
        );
        assert!(text.contains("4.2 MB of 10.5 MB"), "{text}");
        // One chunk and one area are named in the singular.
        ran.head_written = true;
        ran.ending = Ending::Finished;
        ran.checked = Some(Checked {
            through: image.len,
            complete: true,
            mismatches: std::iter::once(0..CHUNK).collect(),
        });
        let mut out = Vec::new();
        write_report(
            &mut out,
            &Report {
                image: &image,
                disk: &disk,
                ran: &ran,
                started: String::new(),
                ended: String::new(),
                grow_asked: false,
            },
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("PARTIAL: 1 chunk read back differently"),
            "{text}"
        );
        assert!(
            text.contains("Files over this area may be damaged."),
            "{text}"
        );
        ran.checked.as_mut().unwrap().mismatches.clear();
        let end = end_text(&ran, &image, &disk);
        assert!(
            end.contains(
                "One area the rescue could not read was written as zeros, and files over it"
            ),
            "{end}"
        );
    }
}
