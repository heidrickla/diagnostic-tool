//! The replacement drive's side of writing an image (`restore.rs`): listing the disks,
//! finding the disks that must never be written, and clearing one. A disk is opened for
//! writing only through a `Cleared`, which only `clear` makes, after the disk was held by
//! its number, read again through that handle, and every refusal was checked again. The
//! handles themselves are `crate::handles`': `DiskWriter` proves the handle it opens for
//! writing is the held, confirmed drive, by its device number, identity, size, disk ID and
//! location, before any of its volumes is touched; its volumes, the whole set or the write
//! is refused, are then locked and dismounted, each checked through its own handle to lie
//! on that disk alone, and Windows keeps the disk offline while it is written.
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
    GetVolumePathNamesForVolumeNameW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use crate::handles::{
    self, device_number, extents_of, wide, DiskWriter, HeldDisk, Identity, FILE_DEVICE_DISK,
};
use serde::{Deserialize, Serialize};

use super::restore::{
    self, Confirm, DiskInfo, Ending, EventSink, FsKind, GrowEnd, Guards, Held, ImageInfo,
    ImageSummary, Progress, Ran, Step, VolumeInfo, REPORT_NAME,
};
use super::timed::Waited;
use crate::tools::drives::ata::DriveId;
use crate::tools::drives::device;
use crate::tools::drives::health::BUS_USB;

/// The most physical disks listed, as the drive window probes them.
const MAX_DISKS: u32 = device::MAX_DISKS;
/// How long a grown volume may take to come back before its file system is extended.
const MOUNT_WAIT: Duration = Duration::from_secs(30);

/// Where a volume lies, as far as Windows says.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Place {
    /// Its extents: (disk, offset, length) each.
    Extents(Vec<(u32, u64, u64)>),
    /// Its extents could not be read, but its own device number could: (device type, number).
    /// A CD drive, or a card reader with no card.
    Device(u32, u32),
    /// Neither could be read: the Windows error.
    Unknown(u32),
}

/// A volume Windows knows, by its GUID name, with where it lies.
#[derive(Debug)]
struct Volume {
    /// "\\?\Volume{guid}\".
    guid: String,
    place: Place,
}

impl Volume {
    /// Its extents, or none when they could not be read.
    fn extents(&self) -> &[(u32, u64, u64)] {
        match &self.place {
            Place::Extents(extents) => extents,
            _ => &[],
        }
    }
}

/// How long listing every volume and where each lies may take: a volume of a failing drive
/// can stop answering its queries, and the list gates a change (`timed::in_time`).
pub(crate) const INVENTORY_LIMIT: Duration = Duration::from_secs(30);

/// Every volume Windows lists, each with where it lies as far as Windows says, within
/// `INVENTORY_LIMIT`; Err when the list could not be read to its end in that time, which
/// refuses what it gates.
fn all_volumes() -> Result<Vec<Volume>, String> {
    match super::timed::in_time(INVENTORY_LIMIT, None, all_volumes_now) {
        Waited::Done(listed) => listed,
        _ => Err(format!(
            "Windows did not list the volumes and where they lie within {} s",
            INVENTORY_LIMIT.as_secs()
        )),
    }
}

/// `all_volumes` itself, on the bounded call's thread.
fn all_volumes_now() -> Result<Vec<Volume>, String> {
    let mut out = Vec::new();
    let mut name = vec![0u16; 64];
    // SAFETY: `name` is writable for its stated length.
    let find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if find == INVALID_HANDLE_VALUE {
        // SAFETY: reads this thread's last error.
        let e = unsafe { GetLastError() };
        return Err(format!(
            "Windows did not list the volumes: {}",
            device::reason(e)
        ));
    }
    let ended = loop {
        let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
        let guid = String::from_utf16_lossy(&name[..end]);
        let place = match handles::query(guid.trim_end_matches('\\')) {
            Err(e) => Place::Unknown(e),
            Ok(handle) => match extents_of(&handle) {
                Ok(extents) => Place::Extents(extents),
                Err(e) => match device_number(&handle) {
                    Ok((kind, number)) => Place::Device(kind, number),
                    Err(_) => Place::Unknown(e),
                },
            },
        };
        out.push(Volume { guid, place });
        // SAFETY: `find` is open and `name` is writable for its stated length.
        if unsafe { FindNextVolumeW(find, name.as_mut_ptr(), name.len() as u32) } == 0 {
            // SAFETY: reads this thread's last error.
            break unsafe { GetLastError() };
        }
    };
    // SAFETY: `find` came from FindFirstVolumeW.
    unsafe { FindVolumeClose(find) };
    if ended != ERROR_NO_MORE_FILES {
        return Err(format!(
            "Windows stopped listing the volumes part way: {}",
            device::reason(ended)
        ));
    }
    Ok(out)
}

/// The volumes with a part on disk `number`: the whole set, or why it cannot be known. A
/// volume whose extents could not be read is taken to be elsewhere only when its own device
/// number puts it on another device; otherwise it may be on the disk, and could not be
/// closed, so nothing may be written.
fn volumes_of(number: u32, all: &[Volume]) -> Result<Vec<&Volume>, String> {
    on_disk(number, all).map_err(|(guid, why)| {
        format!(
            "Nothing was written: Windows could not say which disk the volume {guid} is on{why}, so it may be on disk {number} and could not be closed for the write. Disconnect the drives not in use and start again."
        )
    })
}

/// `volumes_of`'s set, or the volume Windows does not place and why.
fn on_disk(number: u32, all: &[Volume]) -> Result<Vec<&Volume>, (String, String)> {
    let mut on = Vec::new();
    for volume in all {
        match &volume.place {
            Place::Extents(extents) if !extents.is_empty() => {
                if extents.iter().any(|(d, _, _)| *d == number) {
                    on.push(volume);
                }
            }
            Place::Device(kind, other) if *kind != FILE_DEVICE_DISK || *other != number => {}
            Place::Extents(_) | Place::Device(..) | Place::Unknown(_) => {
                let why = match &volume.place {
                    Place::Unknown(e) => format!(" ({})", device::reason(*e)),
                    _ => String::new(),
                };
                return Err((volume.guid.trim_end_matches('\\').to_string(), why));
            }
        }
    }
    Ok(on)
}

/// Every volume with a part on disk `number`, by GUID path: the whole set, or why it cannot
/// be known (the list cut short, or a volume Windows does not place). For a change that
/// must close every volume of a disk first: a repair's copy before its detach and before a
/// table is written to it.
pub(crate) fn every_volume_on(number: u32) -> Result<Vec<String>, String> {
    let all = all_volumes()?;
    on_disk(number, &all)
        .map(|on| on.iter().map(|v| v.guid.clone()).collect())
        .map_err(|(guid, why)| {
            format!("Windows could not say which disk the volume {guid} is on{why}, so it may be on disk {number}")
        })
}

/// The volume's first mount point ("E:" or a folder), its label and file system.
fn volume_names(guid: &str) -> (String, String, String) {
    let root = wide(guid);
    let mut paths = vec![0u16; 1024];
    let mut returned = 0u32;
    // SAFETY: `root` is NUL-terminated and `paths` writable for its stated length.
    let mount = if unsafe {
        GetVolumePathNamesForVolumeNameW(
            root.as_ptr(),
            paths.as_mut_ptr(),
            paths.len() as u32,
            &mut returned,
        )
    } != 0
    {
        let end = paths.iter().position(|c| *c == 0).unwrap_or(0);
        let first = String::from_utf16_lossy(&paths[..end]);
        if first.len() == 3 && first.ends_with(":\\") {
            first[..2].to_string()
        } else {
            first
        }
    } else {
        String::new()
    };
    let mut label = vec![0u16; 261];
    let mut fs = vec![0u16; 64];
    // SAFETY: `root` is NUL-terminated and the buffers are writable for their lengths.
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            null_mut(),
            null_mut(),
            null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } != 0;
    let text = |b: &[u16]| {
        let end = b.iter().position(|c| *c == 0).unwrap_or(0);
        String::from_utf16_lossy(&b[..end])
    };
    if ok {
        (mount, text(&label), text(&fs))
    } else {
        (mount, String::new(), String::new())
    }
}

/// The volumes with a part on disk `number`, for the list.
fn volumes_on(number: u32, volumes: &[Volume]) -> Vec<VolumeInfo> {
    volumes
        .iter()
        .filter(|v| v.extents().iter().any(|(d, _, _)| *d == number))
        .map(|v| {
            let (mount, label, file_system) = volume_names(&v.guid);
            let mut other_disks: Vec<u32> = v
                .extents()
                .iter()
                .map(|(d, _, _)| *d)
                .filter(|d| *d != number)
                .collect();
            other_disks.sort_unstable();
            other_disks.dedup();
            VolumeInfo {
                mount,
                label,
                file_system,
                size: v
                    .extents()
                    .iter()
                    .filter(|(d, _, _)| *d == number)
                    .map(|(_, _, len)| *len)
                    .sum(),
                other_disks,
            }
        })
        .collect()
}

/// What a disk is, for the list and the confirmation, from its identity as read through a
/// handle on it and the drive's own identity, `drive`. A size or sector size Windows did not
/// report is 0, which `restore::refusals` refuses.
fn disk_info(number: u32, id: &Identity, drive: Option<DriveId>) -> DiskInfo {
    DiskInfo {
        number,
        model: id.model.clone(),
        serial: id.serial.clone(),
        size: id.size.unwrap_or(0),
        sector: id.sector.unwrap_or(0),
        volumes: Vec::new(),
        disk_id: id.disk_id.clone(),
        location: id.location.clone(),
        usb: id.bus == BUS_USB,
        drive,
    }
}

/// What disk `number`'s held handle reports: identity, size, sector size, disk ID and
/// location, and the drive's own identity, read with IDENTIFY so an image's source is known
/// behind any adapter. The volumes are left for the caller.
fn read_identity(disk: &HeldDisk) -> Result<DiskInfo, String> {
    Ok(disk_info(
        disk.number(),
        &disk.identity()?,
        device::ata_identity(disk),
    ))
}

/// Holds disk `number`, opened with no access right.
fn open_disk(number: u32) -> Result<HeldDisk, String> {
    HeldDisk::open(number).map_err(|e| handles::failure(number, e))
}

/// Reads disk `number` by its number, with no access right: identity, size, sector size,
/// disk ID, location and volumes.
fn describe(number: u32, volumes: &[Volume]) -> Result<DiskInfo, String> {
    let mut disk = read_identity(&open_disk(number)?)?;
    disk.volumes = volumes_on(number, volumes);
    Ok(disk)
}

/// Every disk Windows lists, without volumes, read with no access right: what a
/// confirmation must tell a disk apart from.
fn connected() -> Vec<DiskInfo> {
    (0..MAX_DISKS)
        .filter_map(|n| read_identity(&open_disk(n).ok()?).ok())
        .collect()
}

/// Disk `number` as it is now, without volumes, read with no access right: what the output
/// guard asks of the disk an output lies on (`dest::Guard::refuses_disk`).
pub fn identity_of(number: u32) -> Result<DiskInfo, String> {
    read_identity(&open_disk(number)?)
}

/// Every physical disk Windows lists, with its volumes; Err when the volumes could not be
/// listed, so no disk is shown as having none. Reading a volume's label can wait on a failing
/// drive, so the window calls this off its own thread with a time limit.
pub fn list_disks() -> Result<Vec<DiskInfo>, String> {
    let volumes =
        all_volumes().map_err(|why| format!("The disks' volumes could not be read: {why}"))?;
    Ok((0..MAX_DISKS)
        .filter_map(|n| describe(n, &volumes).ok())
        .collect())
}

// ---- the disks that must never be written ----------------------------------------------

/// Opens a file or folder asking for no access, only to ask Windows where it lies.
fn open_to_locate(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn registry_text(key: &str, value: &str, multi: bool) -> Result<Vec<String>, u32> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
    };
    let (key, value) = (wide(key), wide(value));
    let flags = if multi {
        RRF_RT_REG_MULTI_SZ
    } else {
        RRF_RT_REG_SZ
    };
    const ERROR_MORE_DATA: u32 = 234;
    let mut buffer = vec![0u16; 4096];
    let bytes = loop {
        let mut bytes = (buffer.len() * 2) as u32;
        // SAFETY: the names are NUL-terminated and `buffer` is writable for `bytes`.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                flags,
                null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        match status {
            0 => break bytes,
            // A longer value: `bytes` is the size it needs, given once more room than that.
            ERROR_MORE_DATA
                if (bytes as usize) / 2 + 1 > buffer.len() && buffer.len() < 1 << 20 =>
            {
                buffer = vec![0u16; bytes as usize / 2 + 1];
            }
            other => return Err(other),
        }
    };
    buffer.truncate(bytes as usize / 2);
    Ok(String::from_utf16_lossy(&buffer)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

fn windows_folder() -> Option<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buffer = vec![0u16; 1024];
    // SAFETY: `buffer` is writable for its stated length.
    let n = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    (n > 0 && (n as usize) < buffer.len())
        .then(|| PathBuf::from(String::from_utf16_lossy(&buffer[..n as usize])))
}

/// The disks under a file or folder, through its own handle.
fn disks_under(path: &Path) -> Result<Vec<u32>, String> {
    let file = open_to_locate(path).map_err(|e| e.to_string())?;
    let disks = super::dest::disks_of_handle(&file)?;
    if disks.is_empty() {
        return Err("Windows named no disk".into());
    }
    Ok(disks)
}

/// Finds the disks that must never be written: those under the held image and map, the
/// Windows folder, the partition the computer starts from, this program and every page
/// file. Whatever cannot be found is named, and then no disk is offered.
pub fn gather_guards(held: &Held) -> Guards {
    let mut guards = Guards::default();
    let mut unknown = Vec::new();
    let mut add = |what: &str, result: Result<Vec<u32>, String>| -> Vec<u32> {
        match result {
            Ok(disks) if !disks.is_empty() => disks,
            Ok(_) => {
                unknown.push(format!("the disk {what} could not be found"));
                Vec::new()
            }
            Err(why) => {
                unknown.push(format!("the disk {what} could not be found ({why})"));
                Vec::new()
            }
        }
    };
    let mut image = add(
        "holding the image",
        super::dest::disks_of_handle(held.reader.file()),
    );
    if let Some(map) = &held.map {
        image.extend(add("holding the map", super::dest::disks_of_handle(map)));
    }
    guards.image = image;
    guards.system = add(
        "Windows runs from",
        windows_folder()
            .ok_or_else(|| "Windows did not name its folder".to_string())
            .and_then(|p| disks_under(&p)),
    );
    guards.boot = add(
        "the computer starts from",
        registry_text(r"SYSTEM\Setup", "SystemPartition", false)
            .map_err(|e| format!("error {e}"))
            .and_then(|v| v.into_iter().next().ok_or_else(|| "no value".into()))
            .and_then(|device_name| {
                device::disks_of_volume(&format!(r"\\?\GLOBALROOT{device_name}"))
            }),
    );
    guards.program = add(
        "holding this program",
        std::env::current_exe()
            .map_err(|e| e.to_string())
            .and_then(|p| disks_under(&p)),
    );
    // No page file is a setting, not a failure: only a value that is not there means none.
    // Any other error leaves the page files unknown, and then no disk is offered.
    let mut pages_unread = None;
    let pages = match registry_text(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "ExistingPageFiles",
        true,
    ) {
        Ok(pages) => pages,
        Err(ERROR_FILE_NOT_FOUND) => Vec::new(),
        Err(e) => {
            pages_unread = Some(format!(
                "the page files could not be read (error {e}), so the disks holding them are not known"
            ));
            Vec::new()
        }
    };
    for page in pages {
        let path = PathBuf::from(page.trim_start_matches(r"\??\"));
        // A page file is held open by Windows; its folder lies on the same volume.
        let disks = disks_under(&path).or_else(|_| match path.parent() {
            Some(folder) => disks_under(folder),
            None => Err("it has no folder".into()),
        });
        let disks = add(&format!("holding the page file {}", path.display()), disks);
        guards.paging.extend(disks);
    }
    unknown.extend(pages_unread);
    guards.unknown = unknown;
    for list in [
        &mut guards.image,
        &mut guards.system,
        &mut guards.boot,
        &mut guards.program,
        &mut guards.paging,
    ] {
        list.sort_unstable();
        list.dedup();
    }
    guards
}

// ---- the cleared disk and its writing --------------------------------------------------

/// A disk that passed every check just now. Only `clear` makes one, and only through one is
/// a disk or its volume opened for writing.
pub struct Cleared {
    disk: DiskInfo,
    /// What the disk reported through `held` when it was cleared; the handle opened for
    /// writing must report the same.
    identity: Identity,
    /// The disk, held by `clear` with no access right. It stays with that drive: once the
    /// drive is disconnected it fails, and a drive that takes the number later is not the
    /// one it reaches.
    held: HeldDisk,
}

impl Cleared {
    pub fn disk(&self) -> &DiskInfo {
        &self.disk
    }
}

/// Checks disk `number` from the start: it is opened and held, read again through that
/// handle, the whole set of its volumes must be known, `confirm` must match it (what tells it
/// apart from every other connected disk, `Confirm::of`), the guards are found again through
/// the held image's handles, and no refusal may apply.
pub fn clear(
    number: u32,
    confirm: &str,
    image: &ImageInfo,
    held: &Held,
) -> Result<Cleared, String> {
    let drive = open_disk(number)?;
    let identity = drive.identity()?;
    // Read again on the held drive, so the refusal of the image's source holds for it.
    let mut now = disk_info(number, &identity, device::ata_identity(&drive));
    let volumes =
        all_volumes().map_err(|why| format!("Disk {number} cannot be written: {why}."))?;
    volumes_of(number, &volumes)?;
    now.volumes = volumes_on(number, &volumes);
    let guards = gather_guards(held);
    let why = restore::refusals(&now, image, &guards);
    if !why.is_empty() {
        return Err(format!(
            "Disk {number} cannot be written: {}.",
            why.join("; ")
        ));
    }
    let expected = Confirm::of(&now, &connected());
    if !expected.matches(confirm) {
        return Err(format!(
            "The confirmation does not match {}: {}",
            now.text(),
            expected.prompt(number)
        ));
    }
    Ok(Cleared {
        disk: now,
        identity,
        held: drive,
    })
}

/// Whether the write may go on, from what holds the disk's volumes closed: the disk offline
/// keeps every volume from mounting again; without it each volume must be locked, since a
/// volume only dismounted can be mounted again by Windows in the middle of the write.
/// `volumes` is each volume's name and whether it locked. Ok gives the report's line on
/// what was held; Err why nothing is written and what the technician can do.
fn hold_text(offline: bool, volumes: &[(String, bool)]) -> Result<String, String> {
    let names = |locked: bool| -> Vec<&str> {
        volumes
            .iter()
            .filter(|(_, l)| *l == locked)
            .map(|(n, _)| n.as_str())
            .collect()
    };
    let (locked, open) = (names(true), names(false));
    let list = |n: &[&str]| match n {
        [] => String::new(),
        [one] => (*one).to_string(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
    };
    match (offline, open.is_empty()) {
        (true, true) if locked.is_empty() => {
            Ok("Windows took the disk offline for the write; it had no volumes to close.".into())
        }
        (true, true) => Ok(format!(
            "Windows took the disk offline for the write, and {} {} locked and closed.",
            list(&locked),
            if locked.len() == 1 { "was" } else { "were" }
        )),
        (true, false) => Ok(format!(
            "Windows took the disk offline for the write, which kept {} closed: {} could not be locked, because a program had files open there, and {} dismounted.",
            list(&open),
            if open.len() == 1 { "it" } else { "they" },
            if open.len() == 1 { "was" } else { "were" }
        )),
        (false, true) if locked.is_empty() => Err(
            "Nothing was written: Windows did not take the disk offline for the write. Disconnect the drive, connect it again and start again.".into(),
        ),
        (false, true) => Ok(format!(
            "Windows did not take the disk offline for the write; {} {} locked and closed for the whole write instead.",
            list(&locked),
            if locked.len() == 1 { "was" } else { "were" }
        )),
        (false, false) => Err(format!(
            "Nothing was written: {} could not be locked, because a program has files open there, and Windows did not take the disk offline, so it could open {} again in the middle of the write. Close the programs using {} (File Explorer windows too) and start again.",
            list(&open),
            if open.len() == 1 { "it" } else { "them" },
            list(&open)
        )),
    }
}

/// Opens the cleared disk for writing (`DiskWriter::open` proves it is the drive that was
/// confirmed), then closes every volume on it, the whole set found while that disk is held,
/// and takes it offline. Refuses before any volume is touched when the disk is not the one
/// confirmed or the set of its volumes cannot be known, and before anything is written when
/// a volume could not be locked and the disk could not be taken offline (`hold_text`).
/// Returns the writer and the report's line on what held the volumes closed.
pub fn open_for_write(cleared: &Cleared) -> Result<(DiskWriter<'_>, String), String> {
    let number = cleared.disk.number;
    let mut writer = DiskWriter::open(&cleared.held, &cleared.identity)?;
    let all = all_volumes().map_err(|why| format!("Nothing was written: {why}"))?;
    let mut names = Vec::new();
    for volume in volumes_of(number, &all)? {
        let locked = writer.close_volume(&volume.guid)?;
        let mount = volume_names(&volume.guid).0;
        let name = if mount.is_empty() {
            format!("the volume {}", volume.guid.trim_end_matches('\\'))
        } else {
            mount
        };
        names.push((name, locked));
    }
    let offline = writer.take_offline();
    // A hold that fails returns here: dropping the writer lets its volumes go, so Windows
    // mounts them again, and puts back an offline it set; nothing was written.
    let held = hold_text(offline, &names)?;
    Ok((writer, held))
}

/// Extends the NTFS file system of the grown partition at `offset` through Windows, once
/// its volume has come back. Returns the file system's new size.
pub fn extend_ntfs(cleared: &Cleared, offset: u64) -> Result<u64, String> {
    let number = cleared.disk.number;
    let started = Instant::now();
    let volume = loop {
        // A list that could not be read is said, not taken as a volume not back yet.
        let listed = all_volumes();
        let found = listed.as_ref().ok().and_then(|all| {
            all.iter().find(|v| {
                v.extents()
                    .iter()
                    .any(|(d, at, _)| *d == number && *at == offset)
            })
        });
        if let Some(volume) = found {
            break volume.guid.clone();
        }
        if started.elapsed() > MOUNT_WAIT {
            return Err(match listed {
                Ok(_) => format!(
                    "its volume did not come back within {} s",
                    MOUNT_WAIT.as_secs()
                ),
                Err(why) => format!(
                    "its volume was not found within {} s: {why}",
                    MOUNT_WAIT.as_secs()
                ),
            });
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let (_, _, fs) = volume_names(&volume);
    if fs != "NTFS" {
        return Err(format!(
            "Windows does not see NTFS on it (it reports {})",
            if fs.is_empty() { "nothing" } else { &fs }
        ));
    }
    handles::extend_ntfs(&cleared.held, &volume, offset)
}

fn stamp() -> String {
    crate::clock::local(std::time::SystemTime::now()).long()
}

/// What to write where: the options of the Write image engine, as plain data a window or an
/// agent fills in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteOptions {
    /// The rescue image file. Its GNU ddrescue map is the same name with ".map" beside it;
    /// without one every byte counts as read.
    pub image: PathBuf,
    /// The physical disk to erase and write, `\\.\PhysicalDriveN`: 0 to 31. Every disk
    /// `refusals` names is refused, however it is asked for.
    pub disk: u32,
    /// The confirmation a person gives for that disk, checked against the disk as read just
    /// before writing and every disk connected then (`Confirm::of`): the last four letters or
    /// digits of its serial number, the first eight of its disk ID, its size and location such
    /// as "2.1 GB 3:0:1:0", or its number and size such as "5 2.1 GB" (case, spaces and
    /// punctuation ignored).
    pub confirm: String,
    /// Grow the last partition to fill a larger drive, and extend its NTFS file system.
    /// Off unless set.
    #[serde(default)]
    pub grow: bool,
}

/// What the Write image engine did, as plain data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteResult {
    /// Why nothing was written, when the options were refused before the disk was opened.
    pub refused: Option<String>,
    pub image: Option<ImageSummary>,
    /// The disk as read just before writing.
    pub disk: Option<DiskInfo>,
    /// What the run did; None when it was refused.
    pub ran: Option<Ran>,
    /// `Write report.txt` beside the image, once the run began.
    pub report: Option<PathBuf>,
    /// Why the report is missing or incomplete.
    pub report_error: Option<String>,
    /// How the report file ended, from its ledger entry: "read in full", or "PARTIAL: why".
    #[serde(default)]
    pub report_ended: Option<String>,
    /// The end in plain words, as the window shows it.
    pub summary: String,
}

impl WriteResult {
    fn refused(why: String, image: Option<ImageSummary>) -> Self {
        Self {
            summary: format!("Nothing was written. {why}"),
            refused: Some(why),
            image,
            disk: None,
            ran: None,
            report: None,
            report_error: None,
            report_ended: None,
        }
    }

    /// Finished, every chunk read back the same, and nothing else to note.
    pub fn clean(&self) -> bool {
        self.ran.as_ref().is_some_and(|ran| {
            ran.ending == Ending::Finished
                && ran.notes.is_empty()
                && ran
                    .checked
                    .as_ref()
                    .is_some_and(|c| c.mismatches.is_empty())
        })
    }
}

/// The Write image engine: writes `options.image` to disk `options.disk` once every guard
/// and the confirmation pass, sending `events` as it goes and stopping at the next chunk
/// once `cancel` is set (a stop while writing leaves the disk with no partition table).
/// Needs administrator rights.
pub fn write_image(options: &WriteOptions, events: EventSink, cancel: &AtomicBool) -> WriteResult {
    write_image_with(options, events, cancel, &mut |_| {})
}

/// `write_image` with a call made between the writing and the check, for the live test that
/// changes a byte on the drive to see the check find it.
pub fn write_image_with(
    options: &WriteOptions,
    events: EventSink,
    cancel: &AtomicBool,
    between: &mut dyn FnMut(&mut dyn restore::Target),
) -> WriteResult {
    let (info, mut held) = match restore::load_image(&options.image) {
        Ok(loaded) => loaded,
        Err(why) => return WriteResult::refused(why, None),
    };
    let summary = info.summary();
    let cleared = match clear(options.disk, &options.confirm, &info, &held) {
        Ok(cleared) => cleared,
        Err(why) => return WriteResult::refused(why, Some(summary)),
    };
    let progress = Progress::with(events);
    let (ran, report, report_error, report_ended) = run_with(
        &cleared,
        &info,
        &mut held,
        options.grow,
        cancel,
        &progress,
        between,
    );
    let mut text = restore::end_text(&ran, &info, &cleared.disk);
    match (&report, &report_error) {
        (Some(path), None) => text.push_str(&format!(" The report is {}.", path.display())),
        (Some(path), Some(why)) => text.push_str(&format!(
            " The report {} is incomplete: {why}.",
            path.display()
        )),
        (None, Some(why)) => text.push_str(&format!(" The report could not be saved: {why}.")),
        (None, None) => {}
    }
    WriteResult {
        refused: None,
        image: Some(summary),
        disk: Some(cleared.disk.clone()),
        ran: Some(ran),
        report,
        report_error,
        report_ended,
        summary: text,
    }
}

/// A disk the image could go to, with every reason it may not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub disk: DiskInfo,
    /// Empty when it may be written.
    pub refusals: Vec<String>,
    /// What `WriteOptions::confirm` must hold for it, in the words a person is asked.
    pub confirm_prompt: String,
    /// What the typed confirmation is checked against.
    pub confirm: Confirm,
}

impl Candidate {
    /// The disk as listed: with its disk ID and location too when its confirmation asks for
    /// one of them, so what is asked for is on screen.
    pub fn name_text(&self) -> String {
        let ident = self.disk.ident_text();
        match self.confirm {
            Confirm::Serial(_) => self.disk.text(),
            _ if ident.is_empty() => self.disk.text(),
            _ => format!("{}, {ident}", self.disk.text()),
        }
    }
}

/// The disks an image could be written to, as the list engine gives them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidates {
    pub image: ImageSummary,
    pub guards: Guards,
    pub disks: Vec<Candidate>,
}

/// The list engine: every disk Windows lists, each with the reasons it may not be written
/// with `image` and what its confirmation asks for. Reads only; needs administrator rights.
/// A volume label can wait on a failing drive, so a window calls this off its own thread.
pub fn candidates(image: &Path) -> Result<Candidates, String> {
    let (info, held) = restore::load_image(image)?;
    let guards = gather_guards(&held);
    let listed = list_disks()?;
    let disks = listed
        .iter()
        .cloned()
        .map(|disk| {
            let confirm = Confirm::of(&disk, &listed);
            Candidate {
                refusals: restore::refusals(&disk, &info, &guards),
                confirm_prompt: confirm.prompt(disk.number),
                confirm,
                disk,
            }
        })
        .collect();
    Ok(Candidates {
        image: info.summary(),
        guards,
        disks,
    })
}

/// The run on a cleared disk: closes its volumes and takes it offline, writes and checks the
/// image, grows the last partition if asked, hands the disk back to Windows, extends a grown
/// NTFS file system, and writes the report beside the image.
#[allow(clippy::too_many_arguments)]
fn run_with(
    cleared: &Cleared,
    image: &ImageInfo,
    held: &mut Held,
    grow: bool,
    stop: &AtomicBool,
    progress: &Progress,
    between: &mut dyn FnMut(&mut dyn restore::Target),
) -> (Ran, Option<PathBuf>, Option<String>, Option<String>) {
    let started = stamp();
    progress.set_step(Step::Preparing, 0);
    let mut ran = match open_for_write(cleared) {
        Ok((mut writer, hold)) => {
            let mut ran = restore::run_steps(
                &mut held.reader,
                image,
                &mut writer,
                grow,
                stop,
                progress,
                between,
            );
            ran.held = hold;
            progress.set_step(Step::Finishing, 0);
            let (finished, unconfirmed) = writer.finish_noting();
            if let Err(why) = finished {
                ran.notes.push(why);
            }
            ran.unconfirmed = unconfirmed;
            ran
        }
        Err(why) => {
            let mut ran = Ran::new();
            ran.ending = Ending::Failed(why);
            ran
        }
    };
    if let Some(GrowEnd::Grown(grown)) = &mut ran.grown {
        if grown.fs == FsKind::Ntfs {
            grown.fs_extended = Some(extend_ntfs(cleared, grown.offset));
        }
    }
    for note in &ran.notes {
        progress.warn(note);
    }
    let ended = stamp();
    let (report, report_error, report_ended) =
        write_report_beside(cleared, image, &ran, started, ended, grow);
    (ran, report, report_error, report_ended)
}

/// Writes the report into a new file beside the image through the one writer, made through
/// the destination guard with the written disk guarded and entered in a ledger of its own:
/// its path, why it is missing or incomplete, and how it ended ("read in full", or
/// "PARTIAL: why").
fn write_report_beside(
    cleared: &Cleared,
    image: &ImageInfo,
    ran: &Ran,
    started: String,
    ended: String,
    grow_asked: bool,
) -> (Option<PathBuf>, Option<String>, Option<String>) {
    let Some(folder) = image.image.parent() else {
        return (None, Some("the image has no folder".into()), None);
    };
    let report = restore::Report {
        image,
        disk: &cleared.disk,
        ran,
        started,
        ended,
        grow_asked,
    };
    let mut text = Vec::new();
    if let Err(e) = restore::write_report(&mut text, &report) {
        return (
            None,
            Some(format!("it could not be put together: {e}")),
            None,
        );
    }
    let guard = super::dest::Guard::new([cleared.disk.number]);
    let base = match guard.base(folder) {
        Ok(base) => base,
        Err(e) => return (None, Some(e.to_string()), None),
    };
    let (made, ended) = super::writer::write_lone_report(&guard, &base, REPORT_NAME, &text);
    (made.path, made.error, ended)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard: a volume that could not be locked on a disk Windows did not take offline
    /// stops the write before anything is written, naming the volume and what to do; the
    /// report's line says exactly what held the volumes otherwise.
    #[test]
    fn a_write_stops_when_neither_a_lock_nor_offline_holds_a_volume() {
        let e = || ("E:".to_string(), false);
        let f = || ("F:".to_string(), true);
        let refused = hold_text(false, &[e(), f()]).unwrap_err();
        assert!(
            refused.starts_with("Nothing was written: E: could not be locked"),
            "{refused}"
        );
        assert!(refused.contains("Close the programs using E:"), "{refused}");
        assert!(hold_text(false, &[]).is_err());
        let locked = hold_text(false, &[f()]).unwrap();
        assert!(
            locked.contains("did not take the disk offline") && locked.contains("F: was locked"),
            "{locked}"
        );
        let offline = hold_text(true, &[e(), f()]).unwrap();
        assert!(
            offline.contains("kept E: closed") && !offline.contains("F:"),
            "{offline}"
        );
        let open = body("pub fn open_for_write(");
        assert!(
            open.ends_with("    let held = hold_text(offline, &names)?;\n    Ok((writer, held))"),
            "the writer is handed out before the hold is checked, or a hold that fails does not stop the write"
        );
    }

    /// The guard: a disk is opened for writing only through a `Cleared`, which only `clear`
    /// makes, after the refusals and the typed confirmation; the opens themselves are
    /// `crate::handles`' (its guard), and each takes the disk `clear` held.
    #[test]
    fn a_disk_is_opened_for_writing_only_once_cleared() {
        let all = include_str!("target.rs");
        let code = &all[..all.find("#[cfg(test)]").unwrap()];
        for named in ["GENERIC_WRITE", "CreateFileW", "FSCTL_", "IOCTL_DISK_SET"] {
            assert!(!code.contains(named), "target.rs names {named}");
        }
        // The struct, its impl and the one made in clear.
        assert_eq!(code.matches("Cleared {").count(), 3, "made outside clear");
        let clear = body("pub fn clear(");
        assert!(clear.contains("restore::refusals(") && clear.contains("Ok(Cleared {"));
        // The typed confirmation is checked by the engine against the disk as read now, and
        // against every disk connected now.
        assert!(
            clear.contains("Confirm::of(&now, &connected())")
                && clear.contains(".matches(confirm)")
        );
        // Every act on the disk takes the disk clear held and the identity read through it.
        assert_eq!(code.matches("DiskWriter::open(").count(), 1);
        assert!(body("pub fn open_for_write(cleared: &Cleared)")
            .contains("DiskWriter::open(&cleared.held, &cleared.identity)?"));
        assert_eq!(code.matches("handles::extend_ntfs(").count(), 1);
        assert!(body("pub fn extend_ntfs(cleared: &Cleared")
            .contains("handles::extend_ntfs(&cleared.held, &volume, offset)"));
    }

    /// The code before the tests, from `start` to the end of that item.
    fn body(start: &str) -> &'static str {
        let all = include_str!("target.rs");
        let code = &all[..all.find("#[cfg(test)]").unwrap()];
        let item = &code[code
            .find(start)
            .unwrap_or_else(|| panic!("{start} is gone"))..];
        &item[..item.find("\n}\n").unwrap()]
    }

    /// The guard: the set of volumes closed for a write is the whole set or nothing is
    /// written. A volume whose extents could not be read is passed over only when its own
    /// device number puts it on another device, and a list read part way stops the write.
    #[test]
    fn a_volume_that_cannot_be_placed_stops_the_write() {
        let v = |place| Volume {
            guid: r"\\?\Volume{1}\".into(),
            place,
        };
        let all = [
            v(Place::Extents(vec![(5, 1 << 20, 1 << 30)])),
            v(Place::Extents(vec![(2, 0, 1)])),
            // A CD drive and an empty card reader.
            v(Place::Device(2, 0)),
            v(Place::Device(FILE_DEVICE_DISK, 7)),
        ];
        assert_eq!(volumes_of(5, &all).unwrap().len(), 1);
        for unknown in [
            Place::Unknown(21),
            Place::Device(FILE_DEVICE_DISK, 5),
            Place::Extents(Vec::new()),
        ] {
            let all = [v(Place::Extents(vec![(2, 0, 1)])), v(unknown)];
            let why = volumes_of(5, &all).unwrap_err();
            assert!(
                why.starts_with("Nothing was written") && why.contains("may be on disk 5"),
                "{why}"
            );
        }
        assert!(body("pub fn clear(").contains("volumes_of(number, &volumes)?;"));
        assert!(
            body("pub fn open_for_write(").contains("for volume in volumes_of(number, &all)? {")
        );
        assert!(body("fn all_volumes_now(").contains("if ended != ERROR_NO_MORE_FILES {"));
        assert!(!body("fn all_volumes_now(").contains("if let Ok(extents)"));
    }

    /// The guard: the disk is held and read through that handle when it is cleared, and the
    /// handle opened for writing is proven to be it (`handles::DiskWriter::open`, whose own
    /// test covers the identity) before any of its volumes is listed, locked or dismounted.
    #[test]
    fn the_disk_is_proven_before_its_volumes_are_closed() {
        let open = body("pub fn open_for_write(");
        let disk_at = open
            .find("DiskWriter::open(&cleared.held, &cleared.identity)?")
            .unwrap();
        for later in [
            "all_volumes()",
            "writer.close_volume(",
            "writer.take_offline()",
        ] {
            assert!(
                disk_at < open.find(later).unwrap(),
                "{later} before the disk is proven"
            );
        }
        let clear = body("pub fn clear(");
        assert!(clear.contains("let drive = open_disk(number)?;"));
        assert!(clear.contains("let identity = drive.identity()?;"));
        // The drive's own identity is read on the held drive before the refusals.
        let own = clear
            .find("disk_info(number, &identity, device::ata_identity(&drive))")
            .unwrap();
        assert!(own < clear.find("restore::refusals(").unwrap());
        assert!(clear.contains("held: drive,"));
        // Disks are read with no access right.
        assert!(!body("fn describe(").contains("open_read"));
        assert!(body("fn open_disk(").contains("HeldDisk::open(number)"));
        // Unknown is never fine: a sector size or size Windows did not report is kept as 0,
        // which `restore::refusals` refuses, and a volume list that failed is said.
        let unknown = Identity {
            model: "Msft Virtual Disk".into(),
            serial: String::new(),
            size: None,
            sector: None,
            disk_id: String::new(),
            location: String::new(),
            bus: 0,
        };
        let info = disk_info(5, &unknown, None);
        assert_eq!((info.size, info.sector), (0, 0));
        assert!(body("pub fn list_disks(").contains("all_volumes().map_err("));
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
    }

    /// Panics unless disk `number` is the virtual disk attached from `vhd`, asked of
    /// Windows' storage module, so no live test can reach a real disk.
    fn assert_vhd(number: u32, vhd: &str) {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Disk -Number {number}).Location"),
            ])
            .output()
            .unwrap();
        let location = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            location.eq_ignore_ascii_case(vhd),
            "disk {number} is {location:?}, not the test's virtual disk {vhd}"
        );
        println!("disk {number} is the virtual disk {location}");
    }

    /// Makes a rescue image of a test VHD with the rescue image tool's own reader, then
    /// marks an area of its map as not rescued. DIAG_RESTORE_SRC (disk number),
    /// DIAG_RESTORE_SRC_VHD (its file), DIAG_RESTORE_FOLDER (a new folder) and, optionally,
    /// DIAG_RESTORE_BAD ("start:length" in bytes). Needs administrator rights; reads only.
    #[test]
    #[ignore = "reads a test VHD; needs administrator rights and environment variables"]
    fn live_make_image_of_a_vhd() {
        use crate::recovery::image::{self, Map, Status};
        let number: u32 = var("DIAG_RESTORE_SRC").parse().unwrap();
        assert_vhd(number, &var("DIAG_RESTORE_SRC_VHD"));
        let folder = PathBuf::from(var("DIAG_RESTORE_FOLDER"));
        std::fs::create_dir(&folder).unwrap();
        let mut source =
            crate::recovery::open_source(&crate::recovery::SourceChoice::Disk(number)).unwrap();
        let stem = image::stem_for(&source.describe());
        let plan = image::plan(source.as_ref(), &folder, &stem).unwrap();
        let (image_path, map_path) = (plan.image.clone(), plan.map_path.clone());
        let mut rescue = image::Rescue::open(plan, source.as_ref()).unwrap();
        let settings = image::Settings::for_len(source.len());
        let outcome = rescue.run(
            source.as_mut(),
            &settings,
            &AtomicBool::new(false),
            &image::Progress::default(),
            &mut || image::Watch::Fine,
        );
        assert_eq!(outcome, image::Outcome::Finished);
        drop(rescue);
        if let Ok(bad) = std::env::var("DIAG_RESTORE_BAD") {
            let (start, len) = bad.split_once(':').unwrap();
            let text = std::fs::read_to_string(&map_path).unwrap();
            let mut map = Map::parse(&text).unwrap();
            map.set(start.parse().unwrap(), len.parse().unwrap(), Status::Bad);
            let heading: Vec<String> = text
                .lines()
                .filter(|l| {
                    [
                        "# Mapfile",
                        "# Command",
                        "# Source ",
                        "# Start",
                        "# Current",
                    ]
                    .iter()
                    .any(|k| l.starts_with(k))
                })
                .map(|l| l[2..].to_string())
                .collect();
            std::fs::write(&map_path, map.to_text(&heading)).unwrap();
        }
        let (info, _held) = restore::load_image(&image_path).unwrap();
        println!(
            "image {} of {} bytes, {:?}, made from {:?}, not rescued {:?}",
            image_path.display(),
            info.len,
            info.layout,
            info.made_from,
            info.not_rescued()
        );
    }

    /// Reads the test VHD DIAG_RESTORE_DST (attached from DIAG_RESTORE_DST_VHD), checked to be
    /// that VHD, with the reasons it may not be written, then writes the image
    /// DIAG_RESTORE_IMAGE to it. No other disk is opened but with no access right, to tell
    /// the confirmation apart. DIAG_RESTORE_FLIP=1 changes a byte at 300 MiB between the
    /// writing and the check; DIAG_RESTORE_GROW=1 grows the last partition. Needs
    /// administrator rights; erases the test VHD.
    #[test]
    #[ignore = "erases a test VHD; needs administrator rights and environment variables"]
    fn live_write_image_to_a_vhd() {
        let number: u32 = var("DIAG_RESTORE_DST").parse().unwrap();
        let vhd = var("DIAG_RESTORE_DST_VHD");
        let flip = std::env::var("DIAG_RESTORE_FLIP").is_ok_and(|v| v == "1");
        let grow = std::env::var("DIAG_RESTORE_GROW").is_ok_and(|v| v == "1");
        let image = PathBuf::from(var("DIAG_RESTORE_IMAGE"));
        assert_vhd(number, &vhd);
        let (info, held) = restore::load_image(&image).unwrap();
        println!("image: {}", serde_json::to_string(&info.summary()).unwrap());
        let guards = gather_guards(&held);
        println!("guards: {}", serde_json::to_string(&guards).unwrap());
        drop(held);
        let disk = describe(number, &all_volumes().unwrap()).unwrap();
        let refusals = restore::refusals(&disk, &info, &guards);
        println!(
            "{}  ·  {}  ·  {}  ·  {}",
            disk.text(),
            disk.ident_text(),
            disk.volumes_text(),
            if refusals.is_empty() {
                "can be written".to_string()
            } else {
                format!("refused: {}", refusals.join("; "))
            }
        );
        let confirm = Confirm::of(&disk, &connected());
        println!("confirmation: {}", confirm.prompt(number));
        let answer = match confirm {
            Confirm::Serial(v)
            | Confirm::DiskId(v)
            | Confirm::SizeAndLocation(v)
            | Confirm::NumberAndSize(v) => v,
        };
        let mut options = WriteOptions {
            image,
            disk: number,
            confirm: "WRONG".into(),
            grow,
        };
        // A wrong confirmation is refused by the engine before the disk is opened.
        assert_vhd(number, &vhd);
        let refused = write_image(&options, Box::new(|_| {}), &AtomicBool::new(false));
        println!("wrong confirmation: {}", refused.summary);
        assert!(refused.refused.is_some() && refused.ran.is_none());
        options.confirm = answer;
        println!("options: {}", serde_json::to_string(&options).unwrap());
        let flip_at = 300u64 << 20;
        let mut between = |t: &mut dyn restore::Target| {
            if flip {
                let mut sector = vec![0u8; 4096];
                t.read_at(flip_at, &mut sector).unwrap();
                sector[100] ^= 0x01;
                t.write_at(flip_at, &sector).unwrap();
                t.flush().unwrap();
                println!("changed one byte at {} after writing", flip_at + 100);
            }
        };
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = events.clone();
        let sink: EventSink = Box::new(move |e| kept.lock().unwrap().push(e));
        assert_vhd(number, &vhd);
        let started = Instant::now();
        let result = write_image_with(&options, sink, &AtomicBool::new(false), &mut between);
        let events = events.lock().unwrap();
        let steps: Vec<String> = events
            .iter()
            .filter(|e| !matches!(e, restore::Event::Bytes { .. }))
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        println!(
            "{} events in {:.1} s; besides byte counts: {}",
            events.len(),
            started.elapsed().as_secs_f64(),
            steps.join(" ")
        );
        let json = serde_json::to_string(&result).unwrap();
        println!("result: {json}");
        let ran = result.ran.as_ref().unwrap();
        if flip {
            let mismatches = &ran.checked.as_ref().unwrap().mismatches;
            assert_eq!(mismatches.len(), 1, "{mismatches:?}");
            assert!(mismatches[0].contains(&(flip_at + 100)));
        } else {
            assert!(result.clean(), "{}", result.summary);
        }
        assert!(result.report_error.is_none());
    }

    /// A drive that takes the confirmed disk's number is refused before anything on it is
    /// touched. Holds DIAG_SWAP_A (a disk number), attached from DIAG_SWAP_A_VHD, as cleared,
    /// detaches it, attaches DIAG_SWAP_B_VHD with no drive letter, which must take the same
    /// number, and opens for writing. Needs administrator rights; nothing is written. Leaves
    /// DIAG_SWAP_B_VHD attached.
    #[test]
    #[ignore = "detaches and attaches test VHDs; needs administrator rights and environment variables"]
    fn live_a_drive_that_takes_the_number_is_refused() {
        let number: u32 = var("DIAG_SWAP_A").parse().unwrap();
        let (a, b) = (var("DIAG_SWAP_A_VHD"), var("DIAG_SWAP_B_VHD"));
        assert_vhd(number, &a);
        let drive = open_disk(number).unwrap();
        let identity = drive.identity().unwrap();
        let disk = disk_info(number, &identity, device::ata_identity(&drive));
        println!("cleared: {} ({})", disk.text(), disk.ident_text());
        let cleared = Cleared {
            disk,
            identity,
            held: drive,
        };
        assert!(cleared.held.still_held().is_ok());
        let ps = |command: &str| {
            let out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", command])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{command}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        ps(&format!("Dismount-DiskImage -ImagePath '{a}' | Out-Null"));
        let now = ps(&format!(
            "(Mount-DiskImage -ImagePath '{b}' -NoDriveLetter -PassThru | Get-Disk).Number"
        ));
        println!("{b} attached as disk {now}");
        assert_eq!(
            now,
            number.to_string(),
            "the second VHD took another number"
        );
        assert_vhd(number, &b);
        let other = open_disk(number).unwrap().identity().unwrap();
        println!(
            "now at that number: {} serial {:?} disk ID {} location {}; Windows tells it apart: {}",
            other.model,
            other.serial,
            other.disk_id,
            other.location,
            other != cleared.identity
        );
        let held = cleared.held.still_held().unwrap_err();
        println!("held handle: {held}");
        let refused = open_for_write(&cleared)
            .err()
            .expect("a different drive was opened for writing");
        println!("open for writing: {refused}");
        assert!(refused.contains("nothing was written"), "{refused}");
    }
}
