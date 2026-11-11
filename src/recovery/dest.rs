//! The destination rule: output never lands on the disk being recovered. A chosen folder is
//! checked by name before anything is read, for an early message. Then it is opened and
//! checked through its handle, and every output file and folder is created relative to an
//! open, checked folder handle, never by path: a junction, a mount point or a path changed
//! in between cannot carry a creation or a write to the source. Folder handles deny delete
//! sharing, so a folder in use cannot be renamed aside or replaced. A link met inside the
//! destination is opened as itself and refused.
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileRenameInformation, NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, GENERIC_READ, GENERIC_WRITE, HANDLE, OBJ_CASE_INSENSITIVE,
    UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    ExtendedFileIdType, FileDispositionInfo, FileIdInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, OpenFileById,
    SetFileInformationByHandle, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0,
    FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::tools::drives::device;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// A file system flag: files can be opened by their IDs. FAT and exFAT do not set it.
const FILE_SUPPORTS_OPEN_BY_FILE_ID: u32 = 0x0100_0000;
/// IO_STATUS_BLOCK.Information after NtCreateFile made the file.
const FILE_CREATED: usize = 2;
/// What a folder handle may do: list, add files and folders, set times, and remove itself
/// if it was just made and is refused.
const FOLDER_ACCESS: u32 = FILE_LIST_DIRECTORY
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_TRAVERSE
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | SYNCHRONIZE;
/// Folders are shared for reading and writing, never for delete: while the handle is open
/// the folder cannot be renamed, moved or removed.
const FOLDER_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const FILE_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

#[cfg(test)]
thread_local! {
    /// How many times a test's thread asked which disk an open handle is on.
    static DISK_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The disks output must not be on: the source's `protected_disks`. An image's own drive is
/// not among them (its file is in use and cannot be overwritten); the drive it was made
/// from is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Guard {
    disks: Vec<u32>,
    /// The drives output must not reach by identity, checked at each output's open.
    drives: Vec<Guarded>,
    /// Why what must not be written could not be learned; then nothing is written unconfirmed.
    unknown: Option<String>,
    granted: Vec<String>,
}

/// What output must not be written to while a source is read: its own disk by number, and
/// for an image the drive its map names, by identity, under whatever number it is connected
/// when each output is opened. `unknown` says why the drive an image was made from could not
/// be learned; nothing is written then.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Protected {
    pub disks: Vec<u32>,
    pub drives: Vec<Guarded>,
    pub unknown: Option<String>,
    /// Disks a person confirmed are not the drive being recovered, by `Refusal::key`: a doubt
    /// about them is set aside. The drive's own disk and serial number are never set aside.
    pub granted: Vec<String>,
}

/// A drive output must not reach, by its identity and, when known, its partition table's ID,
/// which tells it from a drive of the same model and size where serial numbers cannot.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Guarded {
    pub id: super::SourceId,
    pub table: Option<String>,
    /// Rescued bytes of the drive at a few places, from its image (`Sample`).
    #[serde(default)]
    pub samples: Vec<Sample>,
}

/// The first `bytes.len()` bytes at `pos` (a multiple of 4096) of the drive an image was made
/// from, as the image holds them where its map marks them rescued. A disk in doubt is read
/// there: other bytes, another drive; the same bytes everywhere, that drive or a copy of it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sample {
    pub pos: u64,
    pub bytes: Vec<u8>,
}

impl Guarded {
    pub fn new(id: super::SourceId, table: Option<String>) -> Self {
        let table = table.filter(|t| !t.trim().is_empty());
        Self {
            id,
            table,
            samples: Vec::new(),
        }
    }
}

/// Whether `source` holds every sample's bytes: Some(false) at the first that differs, None
/// when one could not be read (or lies past its end).
pub(crate) fn compare_samples(
    source: &mut dyn super::BlockSource,
    samples: &[Sample],
) -> Option<bool> {
    for sample in samples {
        let mut buf = vec![0u8; 4096.max(sample.bytes.len())];
        if sample.pos + buf.len() as u64 > source.len() {
            return None;
        }
        source.read_at(sample.pos, &mut buf).ok()?;
        if buf[..sample.bytes.len()] != sample.bytes[..] {
            return Some(false);
        }
    }
    Some(true)
}

/// Disk `number` opened for raw reads (administrator rights); in tests, what the test gives.
fn open_raw(number: u32) -> Option<Box<dyn super::BlockSource>> {
    #[cfg(test)]
    if let Some(open) = OPEN_RAW.with(std::cell::Cell::get) {
        return open(number);
    }
    super::disk::PhysicalDisk::open(number)
        .ok()
        .map(|disk| Box::new(disk) as Box<dyn super::BlockSource>)
}

/// A test's way to open a disk raw.
#[cfg(test)]
pub(crate) type OpenRaw = fn(u32) -> Option<Box<dyn super::BlockSource>>;

#[cfg(test)]
thread_local! {
    /// A test's stand-in for raw disk reads, for this thread only.
    pub(crate) static OPEN_RAW: std::cell::Cell<Option<OpenRaw>> = const { std::cell::Cell::new(None) };
}

/// What a disk whose bytes are the image's at every sample is refused for.
pub const SAME_DATA: &str =
    "its data is the image's at every place compared: it is the drive this image was made from, or a copy of it";

/// How long a comparison of a disk with an image's samples stands; output checks at each
/// open, and a disk is not read again for each file.
const COMPARED_FOR: std::time::Duration = std::time::Duration::from_secs(60);

/// Comparisons made lately: the disk and the samples compared, when, and whether they matched.
static COMPARED: std::sync::Mutex<Vec<(String, std::time::Instant, bool)>> =
    std::sync::Mutex::new(Vec::new());

/// Whether disk `number`, as `disk` describes it, holds `drive`'s sampled bytes: Some(true)
/// at every sample, Some(false) where one differs, None without samples or when the disk
/// could not be read there (it stays a doubt).
fn holds_samples(number: u32, disk: &super::restore::DiskInfo, drive: &Guarded) -> Option<bool> {
    if drive.samples.is_empty() {
        return None;
    }
    let key = format!(
        "{number}|{}|{}|{}|{}|{:?}",
        disk.model,
        disk.serial,
        disk.size,
        disk.disk_id,
        drive
            .samples
            .iter()
            .map(|s| (
                s.pos,
                s.bytes.len(),
                s.bytes.iter().map(|b| u64::from(*b)).sum::<u64>()
            ))
            .collect::<Vec<_>>()
    );
    if let Ok(mut compared) = COMPARED.lock() {
        compared.retain(|(_, at, _)| at.elapsed() < COMPARED_FOR);
        if let Some((_, _, same)) = compared.iter().find(|(k, _, _)| *k == key) {
            return Some(*same);
        }
    }
    let same = compare_samples(open_raw(number)?.as_mut(), &drive.samples)?;
    if let Ok(mut compared) = COMPARED.lock() {
        compared.push((key, std::time::Instant::now(), same));
    }
    Some(same)
}

/// Why a disk is not written. `firm` when it is the drive being recovered: its number, or
/// the drive's serial number. Otherwise a doubt (the same model and size, a drive behind an
/// adapter that hides its serial, a disk that could not be read, an image whose drive is not
/// known), which a person clears by confirming the disk is not it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The whole sentence, for a notice.
    pub why: String,
    /// The reason alone, for a question.
    pub reason: String,
    pub firm: bool,
    pub disk: u32,
    /// The disk as it can be named: model, serial number and size, or its number.
    pub about: String,
    /// What a confirmation of this disk is kept under (`Protected::granted`).
    pub key: String,
}

impl Protected {
    /// One disk by its number: a disk or volume source.
    pub fn disk(number: u32) -> Self {
        Self {
            disks: vec![number],
            ..Self::default()
        }
    }

    /// Nothing could be learned of what must not be written, for `why`.
    pub fn unknown(why: String) -> Self {
        Self {
            unknown: Some(why),
            ..Self::default()
        }
    }

    /// Both protections at once.
    pub fn join(mut self, other: Protected) -> Self {
        self.disks.extend(other.disks);
        self.drives.extend(other.drives);
        self.unknown = self.unknown.or(other.unknown);
        self.granted.extend(other.granted);
        self
    }
}

/// An output folder held open and checked: what is made in it is made through this handle.
#[derive(Debug)]
pub struct Folder {
    handle: File,
    path: PathBuf,
    /// The guard that checked its disk when `Guard::base` opened its base. It was reached
    /// from there without a link, so it is on that disk: what that same guard makes in it
    /// is not asked again which disk it is on.
    checked_by: Option<std::sync::Arc<Guard>>,
}

impl Folder {
    /// Where it was when opened, for people and reports.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sets its times through its own handle.
    pub fn set_times(&self, times: std::fs::FileTimes) -> io::Result<()> {
        self.handle.set_times(times)
    }

    pub fn try_clone(&self) -> io::Result<Folder> {
        Ok(Folder {
            handle: self.handle.try_clone()?,
            path: self.path.clone(),
            checked_by: self.checked_by.clone(),
        })
    }

    /// A folder opened as `Guard::base` opens one, but sharing delete, so a test can move
    /// it aside while it is held, as a parent changed between a check and a creation.
    #[cfg(test)]
    pub fn sharing_delete(path: &Path) -> io::Result<Folder> {
        let handle = OpenOptions::new()
            .access_mode(FOLDER_ACCESS & !DELETE)
            .share_mode(FOLDER_SHARE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        Ok(Folder {
            handle,
            path: path.to_path_buf(),
            checked_by: None,
        })
    }
}

/// An output made earlier and closed: which file it is and where it was, so it can be
/// opened again with no handle held in between and no path followed.
#[derive(Clone, Debug)]
pub struct Made {
    key: Key,
    /// Its full path by volume GUID when it was made; it must still be there.
    at: String,
    path: PathBuf,
}

/// How a closed output is found again.
#[derive(Clone, Debug)]
enum Key {
    /// By its file ID, where the file system opens files by ID.
    Id { volume: u64, id: [u8; 16] },
    /// Where it does not (FAT, exFAT): by its names below the held base folder, one folder
    /// handle at a time, and then by its size and creation time.
    Walk {
        names: Vec<OsString>,
        len: u64,
        created: Option<std::time::SystemTime>,
    },
}

impl Made {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// What an open handle is, for the checks.
enum Kind {
    File,
    Folder,
}

impl Guard {
    pub fn new(disks: impl IntoIterator<Item = u32>) -> Self {
        let mut disks: Vec<u32> = disks.into_iter().collect();
        disks.sort_unstable();
        disks.dedup();
        Self {
            disks,
            drives: Vec::new(),
            unknown: None,
            granted: Vec::new(),
        }
    }

    /// The guard for one source: its `BlockSource::protected`.
    pub fn of(protected: &Protected) -> Self {
        Self {
            drives: protected.drives.clone(),
            unknown: protected.unknown.clone(),
            granted: protected.granted.clone(),
            ..Self::new(protected.disks.iter().copied())
        }
    }

    pub fn disks(&self) -> &[u32] {
        &self.disks
    }

    fn guards(&self) -> bool {
        !self.disks.is_empty() || !self.drives.is_empty() || self.unknown.is_some()
    }

    /// Why disk `number` must not be written, asked of the disk as it is now: firm for one of
    /// the guarded numbers or a guarded drive's serial number; a doubt for a disk that cannot
    /// be told from a guarded drive, unless a person confirmed it (`granted`).
    pub fn refuses_disk(&self, number: u32) -> Option<Refusal> {
        let firm = |reason: String, about: String, key: String| Refusal {
            why: reason.clone(),
            reason,
            firm: true,
            disk: number,
            about,
            key,
        };
        if self.disks.contains(&number) {
            let reason = format!("disk {number} is the disk being recovered");
            return Some(firm(
                reason,
                format!("Disk {number}"),
                format!("disk {number}"),
            ));
        }
        if self.drives.is_empty() && self.unknown.is_none() {
            return None;
        }
        let read = super::target::identity_of(number);
        let (about, key) = match &read {
            Ok(d) => (
                format!(
                    "Disk {number}, {}, serial {}, {}",
                    d.model.trim(),
                    if d.serial.trim().is_empty() {
                        "none"
                    } else {
                        d.serial.trim()
                    },
                    crate::tools::drives::bytes_text(d.size)
                ),
                format!("{}|{}|{}", d.model.trim(), d.serial.trim(), d.size),
            ),
            Err(_) => (format!("Disk {number}"), format!("disk {number}")),
        };
        let mut doubt = None;
        match &read {
            Ok(disk) => {
                for drive in &self.drives {
                    // The same drive guarded twice (by its disk and by a reader of it) lends
                    // its table to the copy that has none.
                    let table = drive.table.as_deref().or_else(|| {
                        self.drives
                            .iter()
                            .find(|o| {
                                o.id.model.trim() == drive.id.model.trim()
                                    && o.id.serial.trim() == drive.id.serial.trim()
                                    && o.id.drive == drive.id.drive
                            })
                            .and_then(|o| o.table.as_deref())
                    });
                    match super::restore::is_source(disk, &drive.id, table) {
                        Some(super::restore::SAME_DRIVE) => {
                            let reason = format!("disk {number}: {}", super::restore::SAME_DRIVE);
                            return Some(firm(reason, about, key));
                        }
                        // Read where the image holds the drive's data: that settles it.
                        Some(why) => match holds_samples(number, disk, drive) {
                            Some(false) => {}
                            Some(true) => {
                                return Some(firm(
                                    format!("disk {number}: {SAME_DATA}"),
                                    about,
                                    key,
                                ))
                            }
                            None => doubt = doubt.or(Some(format!("disk {number}: {why}"))),
                        },
                        None => {}
                    }
                }
            }
            Err(why) => {
                doubt = Some(format!(
                    "disk {number} could not be told apart from the drive being recovered ({why})"
                ))
            }
        }
        let doubt = doubt.or_else(|| self.unknown.clone())?;
        if self.granted.contains(&key) {
            return None;
        }
        Some(Refusal {
            why: doubt.clone(),
            reason: doubt,
            firm: false,
            disk: number,
            about,
            key,
        })
    }

    /// The first refusal of a disk `what` lies on, with `why` made a whole sentence.
    fn refusal(&self, what: &Path, on: &[u32]) -> Option<Refusal> {
        let mut refusal = on.iter().find_map(|&disk| self.refuses_disk(disk))?;
        refusal.why = if refusal.firm {
            format!(
                "{} is not written: {}; choose a folder on another drive",
                what.display(),
                refusal.reason
            )
        } else {
            format!(
                "{} is not written: {}; choose a folder on another drive, or confirm the disk is not the drive being recovered",
                what.display(),
                refusal.reason
            )
        };
        Some(refusal)
    }

    /// The early check of a chosen folder, by its name, before anything is read.
    pub fn check_folder(&self, folder: &Path) -> Result<(), String> {
        self.folder_refusal(folder).map_err(|refused| refused.why)
    }

    /// `check_folder`, with what a person may confirm.
    pub fn folder_refusal(&self, folder: &Path) -> Result<(), Refusal> {
        let disks = device::disks_of_path(folder).map_err(|why| Refusal {
            why: why.clone(),
            reason: why,
            firm: true,
            disk: u32::MAX,
            about: String::new(),
            key: String::new(),
        })?;
        if disks.is_empty() {
            let why = format!(
                "Windows did not say which disk {} is on, so it cannot be checked",
                folder.display()
            );
            return Err(Refusal {
                why: why.clone(),
                reason: why,
                firm: true,
                disk: u32::MAX,
                about: String::new(),
                key: String::new(),
            });
        }
        self.refusal(folder, &disks).map_or(Ok(()), Err)
    }

    /// Checks an open output: never a link, the kind of thing made, and not on a guarded disk.
    /// `parent`: the folder it is in; when this guard checked that folder's disk, and this is
    /// no link, which disk it is on is not asked again.
    fn check(&self, file: &File, path: &Path, kind: Kind, parent: &Folder) -> Result<(), String> {
        let meta = file
            .metadata()
            .map_err(|e| format!("{} could not be checked: {e}", path.display()))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{} is a junction or link; recovered data is never written through one",
                path.display()
            ));
        }
        if meta.is_dir() != matches!(kind, Kind::Folder) {
            return Err(format!("{} is not what was made there", path.display()));
        }
        if parent.checked_by.as_deref() == Some(self) {
            return Ok(());
        }
        self.check_disks(file, path)
    }

    /// Refuses an open handle on a guarded disk, or one whose disk Windows does not name.
    fn check_disks(&self, file: &File, path: &Path) -> Result<(), String> {
        if !self.guards() {
            return Ok(());
        }
        #[cfg(test)]
        DISK_CHECKS.with(|n| n.set(n.get() + 1));
        let disks = disks_of_handle(file)
            .map_err(|why| format!("{} could not be checked: {why}", path.display()))?;
        if disks.is_empty() {
            return Err(format!(
                "Windows did not say which disk {} is on, so it cannot be checked",
                path.display()
            ));
        }
        self.refusal(path, &disks)
            .map_or(Ok(()), |refused| Err(refused.why))
    }

    /// Notes what `file`, made at `path` below `base` through this guard, is, so it can be
    /// closed and opened again later with `reopen` and the same base.
    pub fn record(&self, base: &Folder, file: &File, path: &Path) -> io::Result<Made> {
        record_as(base, file, path, opens_by_id(file)?)
    }

    /// Notes what folder `folder`, below `base`, is, so it can be closed and opened again.
    pub fn record_folder(&self, base: &Folder, folder: &Folder) -> io::Result<Made> {
        self.record(base, &folder.handle, &folder.path)
    }

    /// Opens `made` again from `base`, the way it was recorded, and checks it is the same
    /// file, still where it was made, and still passes the checks it passed then.
    fn again(
        &self,
        base: &Folder,
        made: &Made,
        access: u32,
        share: u32,
        kind: Kind,
    ) -> io::Result<File> {
        let moved = || {
            io::Error::other(format!(
                "{} was moved or replaced after it was made, so it is not written again",
                made.path.display()
            ))
        };
        let file = match &made.key {
            Key::Id { volume, id } => {
                let file = self.by_id(base, *id, access, share, &kind)?;
                if file_id(&file)? != (*volume, *id) {
                    return Err(moved());
                }
                file
            }
            Key::Walk {
                names,
                len,
                created,
            } => {
                let file = self.by_walk(base, names, &made.path, access, share, &kind)?;
                let meta = file.metadata()?;
                let same_len = matches!(kind, Kind::Folder) || meta.len() == *len;
                match same_created(*created, meta.created().ok()) {
                    Some(true) if same_len => {}
                    Some(_) => return Err(moved()),
                    None => {
                        return Err(io::Error::other(format!(
                            "{} could not be confirmed as the same file: its file system gives neither a file ID nor a creation time",
                            made.path.display()
                        )))
                    }
                }
                file
            }
        };
        if final_path(&file).map_err(io::Error::other)? != made.at {
            return Err(moved());
        }
        self.check(&file, &made.path, kind, base)
            .map_err(io::Error::other)?;
        Ok(file)
    }

    /// Opens the folders on `names` from `base` one at a time, each relative to the last
    /// one's handle and checked through its own, never through a link, then the last name.
    fn by_walk(
        &self,
        base: &Folder,
        names: &[OsString],
        path: &Path,
        access: u32,
        share: u32,
        kind: &Kind,
    ) -> io::Result<File> {
        let Some((last, folders)) = names.split_last() else {
            return Err(io::Error::other(format!(
                "{} is the base folder itself",
                path.display()
            )));
        };
        let mut folder = base.try_clone()?;
        for name in folders {
            let opened = create_in(
                &folder,
                name,
                FOLDER_ACCESS & !DELETE,
                FOLDER_SHARE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
            )?;
            let at = folder.path.join(name);
            folder = Folder {
                handle: self.made(opened, &folder, &at, Kind::Folder)?,
                path: at,
                checked_by: folder.checked_by.clone(),
            };
        }
        let options = match kind {
            Kind::File => FILE_NON_DIRECTORY_FILE,
            Kind::Folder => FILE_DIRECTORY_FILE,
        };
        let (file, _) = create_in(&folder, last, access, share, FILE_OPEN, options)?;
        Ok(file)
    }

    /// Opens file `id` on `hint`'s volume.
    fn by_id(
        &self,
        hint: &Folder,
        id: [u8; 16],
        access: u32,
        share: u32,
        kind: &Kind,
    ) -> io::Result<File> {
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: ExtendedFileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                ExtendedFileId: FILE_ID_128 { Identifier: id },
            },
        };
        let flags = match kind {
            Kind::File => FILE_FLAG_OPEN_REPARSE_POINT,
            Kind::Folder => FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        };
        // SAFETY: the hint handle is open and the descriptor lives for the call.
        let handle = unsafe {
            OpenFileById(
                hint.handle.as_raw_handle(),
                &descriptor,
                access,
                share,
                std::ptr::null(),
                flags,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenFileById returned an open handle this File now owns.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    /// Opens a file made earlier below `base` again, for reading and writing and setting
    /// its times.
    pub fn reopen(&self, base: &Folder, made: &Made) -> io::Result<File> {
        self.again(
            base,
            made,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            FILE_SHARE,
            Kind::File,
        )
    }

    /// Opens a folder made earlier below `base` again, to make things in it or set its times.
    pub fn reopen_folder(&self, base: &Folder, made: &Made) -> io::Result<Folder> {
        let handle = self.again(
            base,
            made,
            FOLDER_ACCESS & !DELETE,
            FOLDER_SHARE,
            Kind::Folder,
        )?;
        Ok(Folder {
            handle,
            path: made.path.clone(),
            checked_by: base.checked_by.clone(),
        })
    }

    /// Opens the chosen folder and checks it through its handle. The person may have chosen
    /// it through a link of their own, so it is followed; its disk is what counts.
    pub fn base(&self, path: &Path) -> io::Result<Folder> {
        let handle = OpenOptions::new()
            .access_mode(FOLDER_ACCESS & !DELETE)
            .share_mode(FOLDER_SHARE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a folder",
                path.display()
            )));
        }
        self.check_disks(&handle, path).map_err(io::Error::other)?;
        Ok(Folder {
            handle,
            path: path.to_path_buf(),
            checked_by: Some(std::sync::Arc::new(self.clone())),
        })
    }

    /// Checks what `create_in` opened, and removes it again through its own handle if it
    /// was just made and is refused.
    fn made(
        &self,
        (file, created): (File, bool),
        parent: &Folder,
        path: &Path,
        kind: Kind,
    ) -> io::Result<File> {
        match self.check(&file, path, kind, parent) {
            Ok(()) => Ok(file),
            Err(why) => {
                if created {
                    let _ = delete(&file);
                }
                Err(io::Error::other(why))
            }
        }
    }

    /// Makes folder `name` in `parent`, or takes the one there; a link there is refused.
    pub fn folder(&self, parent: &Folder, name: &OsStr) -> io::Result<Folder> {
        self.folder_as(parent, name, FILE_OPEN_IF)
    }

    /// Opens folder `name` in `parent`, one there already, making nothing; a link there is
    /// refused.
    pub fn existing_folder(&self, parent: &Folder, name: &OsStr) -> io::Result<Folder> {
        self.folder_as(parent, name, FILE_OPEN)
    }

    fn folder_as(&self, parent: &Folder, name: &OsStr, disposition: u32) -> io::Result<Folder> {
        let path = parent.path.join(name);
        let opened = create_in(
            parent,
            name,
            FOLDER_ACCESS,
            FOLDER_SHARE,
            disposition,
            FILE_DIRECTORY_FILE,
        )?;
        let handle = self.made(opened, parent, &path, Kind::Folder)?;
        Ok(Folder {
            handle,
            path,
            checked_by: parent.checked_by.clone(),
        })
    }

    /// Makes `parts` as folders inside `base`, each in the one before.
    pub fn folders<I, P>(&self, base: &Folder, parts: I) -> io::Result<Folder>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<OsStr>,
    {
        let mut folder = base.try_clone()?;
        for part in parts {
            folder = self.folder(&folder, part.as_ref())?;
        }
        Ok(folder)
    }

    /// Creates a new file `name` in `parent` for reading and writing; nothing that exists is
    /// opened.
    pub fn create_new(&self, parent: &Folder, name: &OsStr) -> io::Result<File> {
        let opened = create_in(
            parent,
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
        )?;
        self.made(opened, parent, &parent.path.join(name), Kind::File)
    }

    /// Opens an output file made earlier (a resumed image) for reading and writing.
    pub fn open_existing(&self, parent: &Folder, name: &OsStr) -> io::Result<File> {
        let opened = create_in(
            parent,
            name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        )?;
        self.made(opened, parent, &parent.path.join(name), Kind::File)
    }

    /// Opens an output an earlier run left, to be checked, written on and renamed.
    pub fn open_earlier(&self, parent: &Folder, name: &OsStr) -> io::Result<File> {
        let opened = create_in(
            parent,
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        )?;
        self.made(opened, parent, &parent.path.join(name), Kind::File)
    }

    /// Opens a scratch file to be renamed over another output (a map being saved): made
    /// new, or emptied if a stopped save left it; able to be renamed by `rename_over`.
    pub fn create_scratch(&self, parent: &Folder, name: &OsStr) -> io::Result<File> {
        let opened = create_in(
            parent,
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
        )?;
        let file = self.made(opened, parent, &parent.path.join(name), Kind::File)?;
        file.set_len(0)?;
        Ok(file)
    }
}

/// NtCreateFile of `name`, one name and never a path, relative to `parent`'s handle,
/// without following a link. Returns the handle and whether it was made.
fn create_in(
    parent: &Folder,
    name: &OsStr,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> io::Result<(File, bool)> {
    let wide: Vec<u16> = name.encode_wide().collect();
    let separator = |c: &u16| *c == u16::from(b'\\') || *c == u16::from(b'/') || *c == 0;
    if wide.is_empty()
        || wide.iter().any(separator)
        || name == "."
        || name == ".."
        || wide.len() * 2 > usize::from(u16::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a single name", name.to_string_lossy()),
        ));
    }
    let object = UNICODE_STRING {
        Length: (wide.len() * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.handle.as_raw_handle(),
        ObjectName: &object,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer is to a live local for the length of the call; the name buffer
    // outlives it and holds `Length` bytes.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    nt_result(status)?;
    // SAFETY: NtCreateFile succeeded, so `handle` is an open handle this File now owns.
    let file = unsafe { File::from_raw_handle(handle) };
    Ok((file, status_block.Information == FILE_CREATED))
}

impl Folder {
    /// Its full path with its volume by GUID, as Windows resolves the held handle: no drive
    /// letter, junction or mount point in it. While the handle is held the folder cannot be
    /// renamed or removed, and neither can a folder above it.
    pub(crate) fn resolved(&self) -> Result<String, String> {
        final_path(&self.handle)
    }
}

impl Guard {
    /// Checks a file something else made by its name in `parent` (Windows' virtual disk
    /// service makes its files itself): opened by its one name relative to the held folder,
    /// never through a link, and refused and removed through its own handle when it is a
    /// link or on a guarded disk. Returns its volume serial number and file ID.
    pub fn adopt(&self, parent: &Folder, name: &OsStr) -> io::Result<(u64, [u8; 16])> {
        let opened = create_in(
            parent,
            name,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_SHARE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        )?;
        // Taken as made here, so a refused file is removed.
        let file = self.made(
            (opened.0, true),
            parent,
            &parent.path.join(name),
            Kind::File,
        )?;
        file_id(&file)
    }
}

/// The volume serial number and file ID of whatever `path` names now, opened for its
/// attributes only, which no sharing mode of another opener refuses.
pub(crate) fn id_of_path(path: &Path) -> io::Result<(u64, [u8; 16])> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    file_id(&file)
}

/// Removes the file or empty folder behind `file` through its handle, which needs DELETE.
fn delete(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the handle is open and `info` is the structure the class names.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The volume `folder` is on, by the GUID name Windows gives its held handle, opened so its
/// cache can be flushed in one call; that needs administrator rights.
pub fn volume_to_flush(folder: &Folder) -> io::Result<File> {
    let path = folder.resolved().map_err(io::Error::other)?;
    let end = path
        .find("}\\")
        .filter(|_| path.starts_with(r"\\?\Volume{"))
        .ok_or_else(|| io::Error::other(format!("{path} names no volume")))?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path[..=end])
}

/// Removes a file made by `create_new` and not wanted after all, through its handle.
pub fn remove(file: File) -> io::Result<()> {
    delete(&file)
}

/// Renames the file behind `file`, a checked scratch file, to `name` in `folder`, replacing
/// what is there. It goes by the handles, so the file renamed is the one that was checked
/// and it stays in the folder that was checked.
pub fn rename_over(file: &File, folder: &Folder, name: &OsStr) -> io::Result<()> {
    rename(file, folder, name, true)
}

/// Renames the file behind `file`, an output made by `create_new`, to `name` in `folder`,
/// by the handles; fails with AlreadyExists when the name is taken, so nothing is replaced.
pub fn rename_new(file: &File, folder: &Folder, name: &OsStr) -> io::Result<()> {
    rename(file, folder, name, false)
}

fn rename(file: &File, folder: &Folder, name: &OsStr, replace: bool) -> io::Result<()> {
    let name: Vec<u16> = name.encode_wide().collect();
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = header + (name.len() + 1) * 2;
    // A u64 buffer keeps the structure's handle field aligned.
    let mut buffer = vec![0u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `buffer` holds `size` zeroed bytes: the structure and the name with its NUL.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = folder.handle.as_raw_handle();
        (*info).FileNameLength = (name.len() * 2) as u32;
        let to = std::ptr::addr_of_mut!((*info).FileName).cast::<u16>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), to, name.len());
    }
    // The native call, since only it takes a folder handle for the new name.
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open with DELETE access and the buffer is `size` bytes.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            info.cast(),
            size as u32,
            FileRenameInformation,
        )
    };
    nt_result(status)
}

fn nt_result(status: i32) -> io::Result<()> {
    if status < 0 {
        // SAFETY: a plain conversion of a status code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

/// Notes `file`, made at `path` below `base`, by its ID or, when `by_id` is false, by its
/// names below `base`, its size and its creation time.
fn record_as(base: &Folder, file: &File, path: &Path, by_id: bool) -> io::Result<Made> {
    let key = if by_id {
        let (volume, id) = file_id(file)?;
        Key::Id { volume, id }
    } else {
        let names = path
            .strip_prefix(&base.path)
            .map_err(|_| {
                io::Error::other(format!(
                    "{} is not inside {}",
                    path.display(),
                    base.path.display()
                ))
            })?
            .iter()
            .map(OsStr::to_os_string)
            .collect();
        let meta = file.metadata()?;
        Key::Walk {
            names,
            len: meta.len(),
            created: meta.created().ok(),
        }
    };
    Ok(Made {
        key,
        at: final_path(file).map_err(io::Error::other)?,
        path: path.to_path_buf(),
    })
}

/// With no file ID, the creation time is what tells a file from another made at the same
/// place: whether the two match, or None when either is missing and it cannot be told.
fn same_created(
    recorded: Option<std::time::SystemTime>,
    now: Option<std::time::SystemTime>,
) -> Option<bool> {
    Some(recorded? == now?)
}

/// Whether the file system under `file` opens files by their IDs; FAT and exFAT do not.
fn opens_by_id(file: &File) -> io::Result<bool> {
    let mut flags = 0u32;
    // SAFETY: the handle is open; only the flags are asked for, into a live local.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & FILE_SUPPORTS_OPEN_BY_FILE_ID != 0)
}

/// The volume serial number and 128-bit ID of an open file or folder.
fn file_id(file: &File) -> io::Result<(u64, [u8; 16])> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is open and `info` is the structure the class names.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// The full path of an open file or folder, with its volume by GUID.
fn final_path(file: &File) -> Result<String, String> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the handle is open and the buffer is writable for its stated length.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_GUID,
            )
        } as usize;
        if n == 0 {
            return Err(format!(
                "Windows did not name its volume ({})",
                io::Error::last_os_error()
            ));
        }
        if n < buffer.len() {
            buffer.truncate(n);
            break;
        }
        buffer.resize(n + 1, 0);
    }
    Ok(String::from_utf16_lossy(&buffer))
}

/// The disks under an open file or folder: the handle's volume by its GUID name, then that
/// volume's extents.
pub(crate) fn disks_of_handle(file: &File) -> Result<Vec<u32>, String> {
    let name = final_path(file)?;
    let volume = name
        .find('}')
        .map(|end| &name[..=end])
        .filter(|volume| volume.starts_with(r"\\?\Volume{"))
        .ok_or_else(|| format!("its volume has no GUID name ({name})"))?;
    device::disks_of_volume(volume)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("diagtool-dest-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A junction (a directory link) at `link` to `target`, made without a console window.
    fn junction_to(link: &Path, target: &Path) {
        use std::os::windows::process::CommandExt;
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .creation_flags(0x0800_0000)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink: {made:?}");
    }

    /// Which disk the destination is on is asked once, when the base is opened, however many
    /// folders and files are made below it, and when they are opened again.
    #[test]
    fn the_disk_is_checked_once_per_destination_however_much_is_made() {
        let out = temp("once");
        let other = device::disks_of_path(&out).unwrap()[0].wrapping_add(1);
        let guard = Guard::new([other]);
        DISK_CHECKS.with(|n| n.set(0));
        let base = guard.base(&out).unwrap();
        let deep = guard.folders(&base, ["a", "b", "c"]).unwrap();
        let mut made = Vec::new();
        for i in 0..25 {
            let name = OsString::from(format!("f{i}.bin"));
            let file = guard.create_new(&deep, &name).unwrap();
            made.push(
                guard
                    .record(&base, &file, &deep.path().join(&name))
                    .unwrap(),
            );
        }
        for m in &made {
            guard.reopen(&base, m).unwrap();
        }
        assert_eq!(DISK_CHECKS.with(std::cell::Cell::get), 1);
        let _ = std::fs::remove_dir_all(&out);
    }

    /// A junction inside the destination is still refused where it is met, whether a file
    /// or a folder is made through it, though the disk is no longer asked at each creation.
    #[test]
    fn a_junction_inside_the_destination_is_still_refused() {
        let out = temp("junction-out");
        let elsewhere = temp("junction-target");
        junction_to(&out.join("link"), &elsewhere);
        let other = device::disks_of_path(&out).unwrap()[0].wrapping_add(1);
        let guard = Guard::new([other]);
        let base = guard.base(&out).unwrap();
        let why = guard
            .folder(&base, OsStr::new("link"))
            .unwrap_err()
            .to_string();
        assert!(why.contains("junction or link"), "{why}");
        assert!(guard.folders(&base, ["link", "inside"]).is_err());
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
        let _ = std::fs::remove_dir(out.join("link"));
        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    /// The guard: what is made in a folder is made through its handle. Here the folder is
    /// moved aside after it was opened and checked, and a junction to the disk being
    /// recovered is put at its old path; nothing is created there, not even for a moment.
    #[test]
    fn a_creation_never_follows_a_path_changed_after_the_check() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"target\tmp");
        std::fs::create_dir_all(&base).unwrap();
        let out = base.join(format!("diagtool-dest-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(out.join("parent")).unwrap();
        let source_side = temp("race-source");
        let disk = device::disks_of_path(&source_side).unwrap()[0];
        assert!(
            !device::disks_of_path(&out).unwrap().contains(&disk),
            "the temporary folder and the target folder share disk {disk}; this test needs two disks"
        );
        let guard = Guard::new([disk]);
        let parent = Folder::sharing_delete(&out.join("parent")).unwrap();
        guard.check_disks(&parent.handle, parent.path()).unwrap();
        std::fs::rename(out.join("parent"), out.join("aside")).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(out.join("parent"))
            .arg(&source_side)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed: {made:?}");
        let before = std::fs::metadata(&source_side).unwrap().modified().unwrap();
        let file = guard.create_new(&parent, OsStr::new("a.bin"));
        let folder = guard.folder(&parent, OsStr::new("sub"));
        let after = std::fs::metadata(&source_side).unwrap().modified().unwrap();
        let entries = std::fs::read_dir(&source_side).unwrap().count();
        std::fs::remove_dir(out.join("parent")).unwrap();
        assert!(file.is_ok() && folder.is_ok(), "{file:?} {folder:?}");
        assert!(out.join(r"aside\a.bin").is_file() && out.join(r"aside\sub").is_dir());
        assert_eq!(entries, 0, "an entry was made on the disk being recovered");
        assert_eq!(before, after, "the source folder was written");
        drop((file, folder, parent));
        std::fs::remove_dir_all(&out).unwrap();
        std::fs::remove_dir_all(&source_side).unwrap();
    }

    /// The guard: a file made by name by something else (the virtual disk service) is
    /// checked through its own handle, opened in the held folder, and removed when it is on
    /// a guarded disk.
    #[test]
    fn a_file_made_elsewhere_on_a_guarded_disk_is_refused_and_removed() {
        let dir = temp("adopt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("copy.vhd");
        std::fs::write(&path, b"made by the service").unwrap();
        let here = device::disks_of_path(&dir).unwrap();
        let open = Guard::default();
        let base = open.base(&dir).unwrap();
        let id = open.adopt(&base, OsStr::new("copy.vhd")).unwrap();
        assert_eq!(id_of_path(&path).unwrap(), id);
        let guarded = Guard::new(here);
        let err = guarded.adopt(&base, OsStr::new("copy.vhd")).unwrap_err();
        assert!(
            err.to_string().contains("the disk being recovered"),
            "{err}"
        );
        assert!(
            !path.exists(),
            "a refused file was left on the guarded disk"
        );
        drop(base);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_is_checked_through_its_handle() {
        let dir = temp("handle");
        let disks = device::disks_of_path(&dir).unwrap();
        let base = Guard::new([9999]).base(&dir).unwrap();
        let name = OsStr::new("a.bin");
        let refused = Guard::new(disks.clone())
            .create_new(&base, name)
            .unwrap_err();
        assert!(
            refused.to_string().contains("the disk being recovered"),
            "{refused}"
        );
        assert!(
            !dir.join("a.bin").exists(),
            "a refused file was left behind"
        );
        assert!(Guard::new(disks.clone()).base(&dir).is_err());
        let made = Guard::new([9999]).create_new(&base, name).unwrap();
        assert_eq!(disks_of_handle(&made).unwrap(), disks);
        drop(made);
        assert!(Guard::new(disks).open_existing(&base, name).is_err());
        assert!(Guard::new([9999]).open_existing(&base, name).is_ok());
        assert!(Guard::new([9999])
            .create_new(&base, OsStr::new(r"..\escape.bin"))
            .is_err());
        drop(base);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A scratch file is renamed over its target in the folder that was checked.
    #[test]
    fn a_scratch_file_is_renamed_in_its_folder() {
        let dir = temp("scratch");
        std::fs::write(dir.join("image.map"), b"old").unwrap();
        let guard = Guard::new([9999]);
        let base = guard.base(&dir).unwrap();
        let mut scratch = guard
            .create_scratch(&base, OsStr::new("image.map.new"))
            .unwrap();
        io::Write::write_all(&mut scratch, b"new").unwrap();
        rename_over(&scratch, &base, OsStr::new("image.map")).unwrap();
        drop(scratch);
        assert_eq!(std::fs::read(dir.join("image.map")).unwrap(), b"new");
        assert!(!dir.join("image.map.new").exists());
        drop(base);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a folder in use cannot be renamed aside while it is held, so nothing can
    /// be put in its place.
    #[test]
    fn a_held_folder_cannot_be_moved_aside() {
        let dir = temp("held");
        let guard = Guard::new([9999]);
        let base = guard.base(&dir).unwrap();
        let sub = guard.folder(&base, OsStr::new("sub")).unwrap();
        assert!(std::fs::rename(dir.join("sub"), dir.join("aside")).is_err());
        drop(sub);
        drop(base);
        assert!(std::fs::rename(dir.join("sub"), dir.join("aside")).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: an output closed and opened again by its ID is the file that was made,
    /// still where it was made; one moved away, or another put in its place, is refused.
    #[test]
    fn a_closed_output_is_opened_again_only_where_it_was_made() {
        let dir = temp("reopen");
        let guard = Guard::new([9999]);
        let base = guard.base(&dir).unwrap();
        let name = OsStr::new("a.bin");
        let made = guard.create_new(&base, name).unwrap();
        let record = guard.record(&base, &made, &dir.join("a.bin")).unwrap();
        assert!(matches!(record.key, Key::Id { .. }), "NTFS opens by ID");
        drop(made);
        assert!(guard.reopen(&base, &record).is_ok());
        std::fs::rename(dir.join("a.bin"), dir.join("moved.bin")).unwrap();
        let moved = guard.reopen(&base, &record).unwrap_err();
        assert!(moved.to_string().contains("moved or replaced"), "{moved}");
        std::fs::write(dir.join("a.bin"), b"another file").unwrap();
        assert!(guard.reopen(&base, &record).is_err());
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), b"another file");
        drop(base);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard for destinations with no file IDs (FAT, exFAT), forced here on NTFS: an
    /// output is found again by walking its folders from the held base, each opened through
    /// the last one's handle and checked through its own. A folder swapped for a junction,
    /// a file moved away, or another file put in its place, is refused.
    #[test]
    fn without_file_ids_an_output_is_found_again_by_its_folders_from_the_base() {
        let dir = temp("walk");
        let elsewhere = temp("walk-other");
        let guard = Guard::new([9999]);
        let base = guard.base(&dir).unwrap();
        let sub = guard.folder(&base, OsStr::new("sub")).unwrap();
        let made = guard.create_new(&sub, OsStr::new("a.bin")).unwrap();
        made.set_len(100).unwrap();
        let path = dir.join(r"sub\a.bin");
        let record = record_as(&base, &made, &path, false).unwrap();
        let folder_record = record_as(&base, &sub.handle, &sub.path, false).unwrap();
        assert!(matches!(&record.key, Key::Walk { names, .. } if names.len() == 2));
        drop((made, sub));
        // Left alone, both are found and the file can be written.
        let again = guard.reopen(&base, &record).unwrap();
        std::os::windows::fs::FileExt::seek_write(&again, b"second pass", 0).unwrap();
        drop(again);
        assert!(guard.reopen_folder(&base, &folder_record).is_ok());
        // Another file of another size in its place is refused.
        std::fs::rename(&path, dir.join(r"sub\kept.bin")).unwrap();
        std::fs::write(&path, b"another file").unwrap();
        let replaced = guard.reopen(&base, &record).unwrap_err();
        assert!(
            replaced.to_string().contains("moved or replaced"),
            "{replaced}"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(dir.join(r"sub\kept.bin"), &path).unwrap();
        assert!(guard.reopen(&base, &record).is_ok());
        // Its folder moved aside and a junction to another folder put in its place.
        std::fs::write(elsewhere.join("a.bin"), vec![0u8; 100]).unwrap();
        std::fs::rename(dir.join("sub"), dir.join("sub-moved")).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dir.join("sub"))
            .arg(&elsewhere)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let through = guard.reopen(&base, &record).unwrap_err();
        assert!(
            through.to_string().contains("junction or link"),
            "{through}"
        );
        assert_eq!(
            std::fs::read(elsewhere.join("a.bin")).unwrap(),
            vec![0u8; 100]
        );
        assert!(guard.reopen_folder(&base, &folder_record).is_err());
        // A file system that gives no creation time at all is never taken as a match.
        let t = std::time::SystemTime::now();
        assert_eq!(same_created(None, None), None);
        assert_eq!(same_created(Some(t), None), None);
        assert_eq!(same_created(Some(t), Some(t)), Some(true));
        assert_eq!(
            same_created(Some(t), Some(t + std::time::Duration::from_secs(1))),
            Some(false)
        );
        // Without a creation time to tell it apart, even the file left in place is refused.
        std::fs::remove_dir(dir.join("sub")).unwrap();
        std::fs::rename(dir.join("sub-moved"), dir.join("sub")).unwrap();
        assert!(guard.reopen(&base, &record).is_ok());
        let mut untimed = record.clone();
        if let Key::Walk { created, .. } = &mut untimed.key {
            *created = None;
        }
        let unconfirmed = guard.reopen(&base, &untimed).unwrap_err();
        assert!(
            unconfirmed
                .to_string()
                .contains("could not be confirmed as the same file"),
            "{unconfirmed}"
        );
        drop(base);
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();
    }
}
