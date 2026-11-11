//! Identity-bound handles on disks and volumes. This is the one place in the program that
//! names a disk by its number (`\\.\PhysicalDriveN`), opens a disk or volume with any right
//! beyond reading, or sends a command that changes one: locking, dismounting or extending a
//! volume, taking a disk offline or online, writing a partition table, or an ATA command that
//! Windows passes only on a read-write handle. Each of those acts takes a type made here that
//! was opened once, checked by identity through that same handle, and is held until the act
//! ends; a disk number, drive letter or path is never looked up again to act.
//!
//! - `HeldDisk`: a disk opened by its number, its number checked on the handle. A handle stays
//!   with its device, so every later open of that disk is proven to be it by the held handle
//!   still answering to the number after the open: a drive that left makes the held handle
//!   fail, and one that took the number since is never reached.
//! - `DiskWriter`: the replacement drive open for writing (`recovery::target`), proven to be
//!   the drive whose identity was confirmed before any of its volumes is touched, its volumes
//!   closed and the disk offline; offline is undone only when this tool did it and it still
//!   holds. `extend_ntfs` grows a volume on a held disk.
//! - `CopyDisk`: the differencing copy a repair writes (`recovery::repair`), proven through
//!   its own handle to be the copy's file before every write.
//! - `AtaDisk`: the three ATA read commands on a read-write handle proven to be a held disk,
//!   carried as its bus calls for (Windows' ATA paths, or SCSI/ATA Translation over USB);
//!   `SctDrive` adds the drive's model and serial number and sends the SCT read limit.
//!
//! Output folders are the other half of the rule: `recovery::dest` opens a chosen folder once,
//! checks it through its handle (`dest::disks_of_handle`), holds it, and makes every file
//! relative to it. The source guard below fails if any act named here appears elsewhere in
//! `src/`.
use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_NO_BUFFERING,
    FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows_sys::Win32::Storage::Vhd::{
    GetStorageDependencyInformation, GET_STORAGE_DEPENDENCY_FLAG_DISK_HANDLE,
    GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES, STORAGE_DEPENDENCY_INFO,
    STORAGE_DEPENDENCY_INFO_TYPE_2, STORAGE_DEPENDENCY_INFO_VERSION_2,
};
use windows_sys::Win32::System::Ioctl::{
    StorageAccessAlignmentProperty, StorageDeviceProperty, CREATE_DISK, DISK_ATTRIBUTE_OFFLINE,
    FSCTL_DISMOUNT_VOLUME, FSCTL_EXTEND_VOLUME, FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_LOCK_VOLUME,
    IOCTL_DISK_CREATE_DISK, IOCTL_DISK_GET_DISK_ATTRIBUTES, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
    IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_SET_DISK_ATTRIBUTES,
    IOCTL_DISK_SET_DRIVE_LAYOUT_EX, IOCTL_DISK_UPDATE_PROPERTIES, IOCTL_STORAGE_GET_DEVICE_NUMBER,
    IOCTL_STORAGE_QUERY_PROPERTY, SMART_RCV_DRIVE_DATA,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

use crate::recovery::disk::Aligned;
use crate::recovery::pending::Pending;
use crate::recovery::restore;
use crate::recovery::timed::{owned, Duty, Job, Waited, DUTIES};
use crate::tools::drives::ata::{self, AtaCommand, Carrier, Direction, Failure};
use crate::tools::drives::device;
use crate::tools::drives::health;
use crate::tools::drives::sat;
use crate::tools::drives::sct::{self, Refusal};

/// A kernel handle, closed on drop.
pub(crate) struct Handle(pub(crate) HANDLE);

// SAFETY: a kernel handle may be used from any thread.
unsafe impl Send for Handle {}
// SAFETY: the handle is only passed to Windows, which serializes calls on a handle opened
// for synchronous I/O; no Rust data is shared through it.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful open and is closed once here.
        unsafe { CloseHandle(self.0) };
    }
}

pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One synchronous DeviceIoControl on a handle opened without FILE_FLAG_OVERLAPPED; the
/// bytes the driver wrote.
pub(crate) fn ioctl(
    handle: &Handle,
    code: u32,
    input: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, u32> {
    let (mut bytes, returned) = ioctl_all(handle, code, input, out_len)?;
    bytes.truncate(returned.min(out_len));
    Ok(bytes)
}

/// `ioctl`, with the whole output buffer, the bytes the driver did not write left zero,
/// and the count the driver gave.
fn ioctl_all(
    handle: &Handle,
    code: u32,
    input: &[u8],
    out_len: usize,
) -> Result<(Vec<u8>, usize), u32> {
    // An 8-byte-aligned buffer, since drivers read the reply's 64-bit fields in place.
    let mut buffer = vec![0u64; out_len.div_ceil(8)];
    let mut returned = 0u32;
    // SAFETY: the buffers are valid for the lengths given; the call is synchronous.
    let ok = unsafe {
        DeviceIoControl(
            handle.0,
            code,
            if input.is_empty() {
                null()
            } else {
                input.as_ptr().cast::<c_void>()
            },
            input.len() as u32,
            buffer.as_mut_ptr().cast::<c_void>(),
            out_len as u32,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: reads this thread's last error.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: the u64 buffer holds at least `out_len` bytes, all initialised.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), out_len) };
    Ok((bytes.to_vec(), returned as usize))
}

/// Others may keep reading and writing a disk or volume opened here.
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
/// FILE_DEVICE_DISK in STORAGE_DEVICE_NUMBER.
pub(crate) const FILE_DEVICE_DISK: u32 = 7;
/// IOCTL_SCSI_GET_ADDRESS (ntddscsi.h); like the other identity queries it needs no right.
const IOCTL_SCSI_GET_ADDRESS: u32 = 0x0004_1018;
/// ERROR_INVALID_DATA: a reply too short, or a disk that answered with another number.
const ERROR_INVALID_DATA: u32 = 13;

/// What a handle on a disk or volume may do. Only this module chooses it, and only its
/// writing types get `ReadWrite`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    /// Descriptors, sizes, layout, extents, device numbers: no access right at all.
    Query,
    /// Reading the disk's sectors: the source, which is never written.
    Read,
    /// Writing, and the ATA commands Windows passes only on a read-write handle.
    ReadWrite,
}

const fn rights(access: Access) -> u32 {
    match access {
        Access::Query => 0,
        Access::Read => GENERIC_READ,
        Access::ReadWrite => GENERIC_READ | GENERIC_WRITE,
    }
}

fn disk_path(number: u32) -> String {
    format!("\\\\.\\PhysicalDrive{number}")
}

/// The one CreateFileW on a disk or volume in the program.
fn open(path: &str, access: Access, flags: u32) -> Result<Handle, u32> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and outlives the call; no security attributes or
    // template handle are passed.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            rights(access),
            SHARE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads this thread's last error.
        Err(unsafe { GetLastError() })
    } else {
        Ok(Handle(handle))
    }
}

/// Opens a volume ("\\?\Volume{guid}", "\\.\E:") or a device interface by its path with no
/// access right, for queries. A disk is opened by its number, through `query_disk` or
/// `HeldDisk`.
pub(crate) fn query(path: &str) -> Result<Handle, u32> {
    open(path, Access::Query, 0)
}

/// Opens disk `number` with no access right, for queries that bind nothing to it.
pub(crate) fn query_disk(number: u32) -> Result<Handle, u32> {
    open(&disk_path(number), Access::Query, 0)
}

/// Why disk `number` could not be opened, for people.
pub fn failure(number: u32, error: u32) -> String {
    match error {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => format!("Disk {number} is not connected"),
        ERROR_ACCESS_DENIED => format!("Disk {number} needs administrator rights to be read"),
        other => format!("Disk {number} could not be opened (error {other})"),
    }
}

/// STORAGE_DEVICE_NUMBER: (device type, number). Needs no access right.
pub(crate) fn device_number(handle: &Handle) -> Result<(u32, u32), u32> {
    let reply = ioctl(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], 12)?;
    if reply.len() < 8 {
        return Err(ERROR_INVALID_DATA);
    }
    let at = |i: usize| u32::from_le_bytes(reply[i..i + 4].try_into().unwrap());
    Ok((at(0), at(4)))
}

/// VOLUME_DISK_EXTENTS: (disk, offset, length) for each extent.
pub(crate) fn parse_extents(reply: &[u8]) -> Vec<(u32, u64, u64)> {
    let count = reply
        .get(..4)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    (0..count.min(64))
        .map_while(|i| {
            let e = reply.get(8 + i * 24..8 + i * 24 + 24)?;
            Some((
                u32::from_le_bytes(e[..4].try_into().ok()?),
                u64::from_le_bytes(e[8..16].try_into().ok()?),
                u64::from_le_bytes(e[16..24].try_into().ok()?),
            ))
        })
        .collect()
}

/// Where an open volume lies: its extents.
pub(crate) fn extents_of(handle: &Handle) -> Result<Vec<(u32, u64, u64)>, u32> {
    ioctl(
        handle,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &[],
        8 + 24 * 64,
    )
    .map(|reply| parse_extents(&reply))
}

/// STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR: BytesPerLogicalSector at offset 16, or the geometry's
/// BytesPerSector; None when neither is reported.
pub(crate) fn logical_sector(info: &Handle) -> Option<u32> {
    let mut input = Vec::with_capacity(12);
    input.extend_from_slice(&StorageAccessAlignmentProperty.to_le_bytes());
    input.extend_from_slice(&0i32.to_le_bytes());
    input.resize(12, 0);
    if let Ok(reply) = ioctl(info, IOCTL_STORAGE_QUERY_PROPERTY, &input, 28) {
        if let Some(bytes) = reply.get(16..20) {
            let size = u32::from_le_bytes(bytes.try_into().ok()?);
            if size >= 512 && size.is_power_of_two() {
                return Some(size);
            }
        }
    }
    // DISK_GEOMETRY_EX: BytesPerSector at offset 20.
    let reply = ioctl(info, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], 256).ok()?;
    let size = u32::from_le_bytes(reply.get(20..24)?.try_into().ok()?);
    (size >= 512 && size.is_power_of_two()).then_some(size)
}

/// The ID in a DRIVE_LAYOUT_INFORMATION_EX: the GPT disk GUID as Windows writes it, or the
/// MBR signature as eight hex digits; empty for a blank disk.
pub(crate) fn parse_disk_id(reply: &[u8]) -> String {
    let u32_at = |i: usize| {
        reply
            .get(i..i + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    match u32_at(0) {
        Some(0) => match u32_at(8) {
            Some(signature) if signature != 0 => format!("{signature:08X}"),
            _ => String::new(),
        },
        Some(1) => match reply.get(8..24) {
            Some(g) if g.iter().any(|b| *b != 0) => guid_text(g),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// A GUID's 16 bytes as Windows writes it: "{1A2B3C4D-0000-4000-8000-000000000001}".
pub(crate) fn guid_text(g: &[u8]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes(g[..4].try_into().unwrap()),
        u16::from_le_bytes(g[4..6].try_into().unwrap()),
        u16::from_le_bytes(g[6..8].try_into().unwrap()),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// SCSI_ADDRESS (port, bus, target, LUN at bytes 4 to 7) as "3:0:1:0".
pub(crate) fn parse_location(reply: &[u8]) -> String {
    match reply.get(4..8) {
        Some(a) => format!("{}:{}:{}:{}", a[0], a[1], a[2], a[3]),
        None => String::new(),
    }
}

/// What a disk handle reports about the drive behind it, through queries that need no access
/// right: what tells one drive from another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub model: String,
    pub serial: String,
    /// Bytes; None when Windows did not report it.
    pub size: Option<u64>,
    /// Bytes per logical sector; None when Windows did not report it.
    pub sector: Option<u32>,
    /// The GPT disk GUID or MBR signature; empty for a blank disk or when not read.
    pub disk_id: String,
    /// "port:bus:target:LUN"; empty when not read.
    pub location: String,
    /// The bus type the descriptor names (`health::BUS_USB` and the rest).
    pub bus: i32,
}

impl Identity {
    /// Reads it through `handle`. Err only when the descriptor, which names the model and
    /// serial number, could not be read.
    pub(crate) fn read(handle: &Handle) -> Result<Self, String> {
        let mut query = Vec::with_capacity(12);
        query.extend_from_slice(&StorageDeviceProperty.to_le_bytes());
        query.resize(12, 0);
        let reply = ioctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &query, 1024)
            .map_err(|e| format!("its descriptor could not be read: {}", device::reason(e)))?;
        let identity = health::parse_device_descriptor(&reply)
            .ok_or_else(|| "its descriptor was malformed".to_string())?;
        let size = ioctl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], 256)
            .ok()
            .and_then(|reply| Some(u64::from_le_bytes(reply.get(24..32)?.try_into().ok()?)));
        let layout = ioctl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 48 + 144 * 256);
        let address = ioctl(handle, IOCTL_SCSI_GET_ADDRESS, &[], 8);
        Ok(Self {
            model: crate::tools::drives::display_name(&identity),
            serial: health::parse_descriptor_serial(&reply),
            size,
            sector: logical_sector(handle),
            disk_id: layout.map_or_else(|_| String::new(), |r| parse_disk_id(&r)),
            location: address.map_or_else(|_| String::new(), |r| parse_location(&r)),
            bus: identity.bus,
        })
    }
}

// ---- the held disk -------------------------------------------------------------------------

/// A disk opened by its number and checked on the handle to be that number, held so every
/// later open of it is proven to be it (`again`).
pub struct HeldDisk {
    number: u32,
    handle: Handle,
}

impl HeldDisk {
    /// Opens disk `number` with no access right. Err is the Windows error (`failure` words it).
    pub fn open(number: u32) -> Result<Self, u32> {
        Self::open_with(number, Access::Query)
    }

    /// Opens disk `number` for reading only, for the source's size query.
    pub fn open_read(number: u32) -> Result<Self, u32> {
        Self::open_with(number, Access::Read)
    }

    fn open_with(number: u32, access: Access) -> Result<Self, u32> {
        let handle = open(&disk_path(number), access, 0)?;
        match device_number(&handle)? {
            (FILE_DEVICE_DISK, n) if n == number => Ok(Self { number, handle }),
            _ => Err(ERROR_INVALID_DATA),
        }
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    /// The held handle, for queries.
    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The drive's identity, read through the held handle.
    pub fn identity(&self) -> Result<Identity, String> {
        Identity::read(&self.handle).map_err(|why| format!("Disk {}: {why}", self.number))
    }

    /// The held drive is still there and still answers to its number. A handle stays with
    /// its device, so once the drive leaves this fails for good.
    pub fn still_held(&self) -> Result<(), String> {
        match device_number(&self.handle) {
            Ok((FILE_DEVICE_DISK, n)) if n == self.number => Ok(()),
            _ => Err(format!(
                "Disk {} is no longer the drive that was checked: it was disconnected, or another drive took its number",
                self.number
            )),
        }
    }

    /// Opens the disk again by its number and proves the new handle is the held drive: the
    /// held handle still answers to the number after the open, so the number named the held
    /// drive when it was opened.
    fn again(&self, access: Access, flags: u32) -> Result<Handle, String> {
        let handle =
            open(&disk_path(self.number), access, flags).map_err(|e| failure(self.number, e))?;
        // Last, so the number opened above was the held drive's.
        self.still_held()?;
        Ok(handle)
    }

    /// Opens the disk again for reading only with `flags` (the source's overlapped reader),
    /// proven to be the held drive.
    pub(crate) fn read_again(&self, flags: u32) -> Result<Handle, String> {
        self.again(Access::Read, flags)
    }
}

/// Records what went wrong when something was let go without anyone to tell (a value
/// dropped by a panic or a closed window): in the session's change record, which the
/// findings report lists, or on standard error when no record is open.
pub fn record_unseen(what: &str, why: &str) {
    if let Err(no_record) = crate::change_record::append(what, &[why.to_string()]) {
        eprintln!("{what}: {why} ({no_record})");
    }
}

// ---- the replacement drive's writer --------------------------------------------------------

/// How long a lock, a dismount, or taking a disk offline or online may take. A command still
/// running then keeps what undoes it (`timed::owned`).
pub(crate) const COMMAND_LIMIT: Duration = Duration::from_secs(30);

/// The longest the process's end waits for Windows to answer one of those commands, a
/// chosen bound four times the limit (none was measured past it).
pub(crate) const COMMAND_ANSWER: Duration = Duration::from_secs(120);

/// How long letting a handle go takes, as an undo.
const LET_GO: Duration = Duration::from_secs(1);

/// Locks a volume if it can, writes out what it holds, then dismounts it, as one bounded job;
/// the handle travels with it. A lock fails while files are open on it, and the dismount
/// then closes them. Done holds the handle, whether it locked, and the answer: an Err when
/// the volume could not be written out or dismounted. A job that ends after its caller gave
/// up lets the volume go at once, so Windows mounts it again on its next use, and `late`
/// says what it did.
fn lock_and_dismount(
    what: String,
    handle: Handle,
    late: impl FnOnce(&str) + Send + 'static,
) -> Waited<(Handle, bool, Result<(), u32>)> {
    owned(
        Job::new(what, COMMAND_LIMIT)
            .answered_within(COMMAND_ANSWER)
            .undone_within(LET_GO),
        None,
        move || {
            let locked = ioctl(&handle, FSCTL_LOCK_VOLUME, &[], 0).is_ok();
            // A lock writes the volume out; without one, the flush does, and its failure is
            // the answer even when the dismount goes through.
            // SAFETY: the handle is open.
            let flushed = if locked || unsafe { FlushFileBuffers(handle.0) } != 0 {
                Ok(())
            } else {
                // SAFETY: reads this thread's last error.
                Err(unsafe { GetLastError() })
            };
            let dismounted = ioctl(&handle, FSCTL_DISMOUNT_VOLUME, &[], 0).map(|_| ());
            (handle, locked, flushed.and(dismounted))
        },
        move |(handle, _, dismounted): (Handle, bool, Result<(), u32>)| {
            drop(handle);
            late(match dismounted {
                Ok(()) => "was closed after its time limit and let go again at once, so Windows mounts it as before",
                Err(_) => "answered after its time limit without closing, and was let go",
            });
        },
    )
}

/// The count of a disk this tool took offline, until it is online again.
fn online_duty(number: u32, (model, serial): (String, String)) -> Duty {
    DUTIES.holder(
        &format!("bringing disk {number} online"),
        COMMAND_ANSWER,
        Pending::Offline {
            number,
            model: Some(model),
            serial: Some(serial),
        },
    )
}

/// GET_DISK_ATTRIBUTES: Attributes at offset 8. Needs no write right.
fn disk_attributes(handle: &Handle) -> Result<u64, u32> {
    let reply = ioctl(handle, IOCTL_DISK_GET_DISK_ATTRIBUTES, &[], 16)?;
    reply
        .get(8..16)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or(ERROR_INVALID_DATA)
}

/// SET_DISK_ATTRIBUTES for offline or online, not kept across a restart, so a disk left
/// offline by a crash comes back with the next start.
fn set_offline(handle: &Handle, offline: bool) -> Result<(), u32> {
    let mut input = vec![0u8; 40];
    input[..4].copy_from_slice(&40u32.to_le_bytes());
    // Persist (byte 4) stays FALSE.
    let attributes = if offline { DISK_ATTRIBUTE_OFFLINE } else { 0 };
    input[8..16].copy_from_slice(&attributes.to_le_bytes());
    input[16..24].copy_from_slice(&DISK_ATTRIBUTE_OFFLINE.to_le_bytes());
    ioctl(handle, IOCTL_DISK_SET_DISK_ATTRIBUTES, &input, 0).map(|_| ())
}

/// What taking the disk offline for a write should do, from what the disk says first.
#[derive(Debug, PartialEq, Eq)]
enum Offline {
    /// It is offline already: nothing to do, and nothing to put back.
    Already,
    /// It is online: take it offline, and put it back after.
    Take,
    /// Its state could not be read: leave it, since it could not be put back exactly.
    Unknown,
}

fn offline_step(now: Result<u64, u32>) -> Offline {
    match now {
        Ok(attributes) if attributes & DISK_ATTRIBUTE_OFFLINE != 0 => Offline::Already,
        Ok(_) => Offline::Take,
        Err(_) => Offline::Unknown,
    }
}

/// What putting the disk back online should do, from what this tool did and what the disk
/// says now: online only when this tool took it offline and it is still offline.
#[derive(Debug, PartialEq, Eq)]
enum Online {
    /// Bring it online.
    Bring,
    /// Leave it: this tool did not take it offline, or it is online already.
    Leave,
    /// Leave it, and say so: whether it is still offline could not be read.
    Unknown(u32),
}

fn online_step(took_offline: bool, now: Result<u64, u32>) -> Online {
    match (took_offline, now) {
        (false, _) => Online::Leave,
        (true, Ok(attributes)) if attributes & DISK_ATTRIBUTE_OFFLINE != 0 => Online::Bring,
        (true, Ok(_)) => Online::Leave,
        (true, Err(e)) => Online::Unknown(e),
    }
}

/// The replacement drive open for writing: proven to be the confirmed drive, its volumes
/// locked and dismounted and held closed, and the disk offline to Windows while it is
/// written. `finish` hands it back; dropping it does the same and records what failed.
pub struct DiskWriter<'a> {
    disk: &'a HeldDisk,
    /// Shared with a bounded offline or online command, which may outlive its wait.
    handle: Arc<Handle>,
    len: u64,
    sector: u32,
    buffer: Aligned,
    /// Locked, dismounted volumes, held so nothing mounts them while the disk is written.
    volumes: Vec<Handle>,
    /// The disk is offline for the write, by this tool or already.
    offline: bool,
    /// This tool took it offline, so it is this tool's to bring back.
    took_offline: bool,
    /// Counted from the moment it went offline until it is online again, so the process's
    /// end waits for it and the next start says it if the end comes first.
    offline_duty: Option<Duty>,
    /// Why the drive did not confirm the last writes, once let go.
    unconfirmed: Option<String>,
    /// The confirmed drive's model and serial number, journalled with a disk taken offline.
    named: (String, String),
    wrote: bool,
    done: bool,
}

impl<'a> DiskWriter<'a> {
    /// Opens `disk` for writing and proves on the new handle, before any of its volumes is
    /// touched, that it is the drive `confirmed` describes: its device number, model, serial
    /// number, size, sector size, disk ID and location, and the held handle still answering
    /// to the number after the open.
    pub fn open(disk: &'a HeldDisk, confirmed: &Identity) -> Result<Self, String> {
        let number = disk.number;
        let (Some(len), Some(sector)) = (confirmed.size, confirmed.sector) else {
            return Err(format!(
                "Disk {number} did not report its size and sector size, so nothing was written"
            ));
        };
        let handle = open(
            &disk_path(number),
            Access::ReadWrite,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        )
        .map_err(|e| {
            format!(
                "Disk {number} could not be opened for writing: {}",
                device::reason(e)
            )
        })?;
        match device_number(&handle) {
            Ok((FILE_DEVICE_DISK, opened)) if opened == number => {}
            Ok((_, opened)) => {
                return Err(format!(
                    "The handle opened for disk {number} is device {opened}; nothing was written"
                ))
            }
            Err(e) => {
                return Err(format!(
                    "Disk {number} did not give its number: {}; nothing was written",
                    device::reason(e)
                ))
            }
        }
        let now = Identity::read(&handle).map_err(|why| format!("Disk {number}: {why}"))?;
        if &now != confirmed {
            return Err(format!(
                "Disk {number} changed between the check and the write; nothing was written"
            ));
        }
        // Last, so the number read above was the held drive's.
        disk.still_held()
            .map_err(|why| format!("{why}; nothing was written"))?;
        Ok(Self {
            disk,
            handle: Arc::new(handle),
            len,
            sector,
            buffer: Aligned::new(restore::CHUNK as usize, (sector as usize).max(4096)),
            volumes: Vec::new(),
            offline: false,
            took_offline: false,
            offline_duty: None,
            unconfirmed: None,
            named: (confirmed.model.clone(), confirmed.serial.clone()),
            wrote: false,
            done: false,
        })
    }

    /// Opens volume `guid`, found on the disk, for writing; proves through its own handle
    /// that it lies on the held disk alone; then locks it if it can and dismounts it, and
    /// holds it closed until the writer is let go. Returns whether it locked: a lock fails
    /// while files are open on it, and the dismount then closes them.
    pub fn close_volume(&mut self, guid: &str) -> Result<bool, String> {
        let number = self.disk.number;
        let path = guid.trim_end_matches('\\');
        let handle = open(path, Access::ReadWrite, 0).map_err(|e| {
            format!(
                "{path} could not be opened for writing: {}",
                device::reason(e)
            )
        })?;
        let extents = extents_of(&handle)
            .map_err(|e| format!("{path}: its disks could not be read: {}", device::reason(e)))?;
        if extents.is_empty() || extents.iter().any(|(d, _, _)| *d != number) {
            return Err(format!(
                "a volume on disk {number} also lies on another disk; nothing was written"
            ));
        }
        self.disk
            .still_held()
            .map_err(|why| format!("{why}; nothing was written"))?;
        let late = move |what: &str| {
            record_unseen(
                "Write image to a replacement drive",
                &format!("A volume on disk {number} {what}; nothing was written to the disk."),
            );
        };
        match lock_and_dismount(format!("closing {path} on disk {number}"), handle, late) {
            Waited::Done((handle, locked, Ok(()))) => {
                self.volumes.push(handle);
                Ok(locked)
            }
            Waited::Done((_, _, Err(e))) => Err(format!(
                "a volume on disk {number} could not be closed: {}",
                device::reason(e)
            )),
            _ => Err(format!(
                "a volume on disk {number} did not answer closing within {} s, so nothing was written; it is let go once Windows answers, and the session's change record says so",
                COMMAND_LIMIT.as_secs()
            )),
        }
    }

    /// Takes the disk offline for the write, unless it already is; whether it is offline.
    /// A disk whose state cannot be read is left as it is, so nothing is changed that could
    /// not be put back exactly; its volumes then must hold the write closed by their locks.
    /// The read and the set are one bounded job: one that ends after the wait brought the
    /// disk back online at once (the write went on with it online, held closed by its
    /// volumes' locks) and is recorded.
    pub fn take_offline(&mut self) -> bool {
        let handle = self.handle.clone();
        let number = self.disk.number;
        let named = self.named.clone();
        let taking = owned(
            Job::new(format!("taking disk {number} offline"), COMMAND_LIMIT)
                .answered_within(COMMAND_ANSWER)
                // A late one is brought online again at once.
                .undone_within(COMMAND_ANSWER),
            None,
            move || {
                let step = offline_step(disk_attributes(&handle));
                let took = step == Offline::Take && set_offline(&handle, true).is_ok();
                // Counted before this job ends, so nothing is left uncounted between them.
                let duty = took.then(|| online_duty(number, named));
                (step, took, handle, duty)
            },
            move |(_, took, handle, duty): (Offline, bool, Arc<Handle>, Option<Duty>)| {
                if !took {
                    return;
                }
                let text = match set_offline(&handle, false) {
                    Ok(()) => format!(
                        "Disk {number} went offline after its time limit, so it was brought online again at once."
                    ),
                    Err(e) => {
                        if let Some(duty) = duty {
duty.leave();
}
                        format!(
                            "Disk {number} went offline after its time limit, and Windows did not bring it online again ({}); Disk Management can, or a restart will.",
                            device::reason(e)
                        )
                    }
                };
                record_unseen("Write image to a replacement drive", &text);
            },
        );
        match taking {
            Waited::Done((Offline::Already, _, _, _)) => self.offline = true,
            Waited::Done((Offline::Take, took, _, duty)) => {
                self.took_offline = took;
                self.offline = took;
                self.offline_duty = duty;
            }
            _ => self.offline = false,
        }
        self.offline
    }

    /// Whether the disk is offline to Windows while it is written.
    pub fn offline(&self) -> bool {
        self.offline
    }

    /// Makes the writes durable, puts the disk back online if this tool took it offline and
    /// it still is, and has Windows read its new partition table; its volumes then mount again.
    pub fn finish(mut self) -> Result<(), String> {
        self.release()
    }

    /// `finish`, with why the drive did not confirm its last writes, when it did not: what
    /// was written may then not all be on it.
    pub fn finish_noting(mut self) -> (Result<(), String>, Option<String>) {
        let finished = self.release();
        (finished, self.unconfirmed.take())
    }

    fn release(&mut self) -> Result<(), String> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        let mut problems = Vec::new();
        if self.wrote {
            // SAFETY: the handle is open.
            if unsafe { FlushFileBuffers(self.handle.0) } == 0 {
                // SAFETY: reads this thread's last error.
                let e = unsafe { GetLastError() };
                let why = format!(
                    "the drive did not confirm its last writes ({})",
                    device::reason(e)
                );
                self.unconfirmed = Some(why.clone());
                problems.push(why);
            }
        }
        self.volumes.clear();
        // Residual: Windows has no set-if for a disk's attributes, so the compare and the
        // set are two calls. They go back to back on the one handle held for the write, in
        // one bounded job, so the window is one call long; a disk another program took
        // offline in that moment would be brought online. A job that ends after the wait is
        // the put back itself, and is recorded.
        let handle = self.handle.clone();
        let took = self.took_offline;
        let number = self.disk.number;
        // The disk's count travels with the job and ends once it is online again.
        let duty = self.offline_duty.take();
        let online = owned(
            Job::new(format!("bringing disk {number} online"), COMMAND_LIMIT)
                .answered_within(COMMAND_ANSWER)
                .undone_within(LET_GO),
            None,
            move || {
                let step = online_step(took, disk_attributes(&handle));
                let brought = (step == Online::Bring).then(|| set_offline(&handle, false));
                let duty = match (&step, &brought) {
                    (_, Some(Err(_))) | (Online::Unknown(_), _) => {
                        if let Some(duty) = duty {
                            duty.leave();
                        }
                        None
                    }
                    _ => duty,
                };
                (step, brought, duty)
            },
            move |(step, brought, _): (Online, Option<Result<(), u32>>, Option<Duty>)| {
                let text = match (step, brought) {
                    (_, Some(Ok(()))) => format!(
                        "Disk {number} was brought online again after its time limit."
                    ),
                    (_, Some(Err(e))) => format!(
                        "Windows did not bring disk {number} online again after its time limit ({}); Disk Management can, or a restart will.",
                        device::reason(e)
                    ),
                    (Online::Unknown(e), None) => format!(
                        "Windows did not say after its time limit whether disk {number} is still offline ({}), so it was left as it is; Disk Management can bring it online, or a restart will.",
                        device::reason(e)
                    ),
                    _ => return,
                };
                record_unseen("Write image to a replacement drive", &text);
            },
        );
        match online {
            Waited::Done((_, Some(Err(e)), _)) => problems.push(format!(
                "Windows did not bring the disk online again ({}); Disk Management can, or a restart will",
                device::reason(e)
            )),
            Waited::Done((Online::Unknown(e), _, _)) => problems.push(format!(
                "Windows did not say whether the disk is still offline ({}), so it was left as it is; Disk Management can bring it online, or a restart will",
                device::reason(e)
            )),
            Waited::Done(_) => {}
            _ => problems.push(format!(
                "Windows did not answer bringing the disk online within {} s; it is brought online once Windows answers, and the session's change record says so; Disk Management can, or a restart will",
                COMMAND_LIMIT.as_secs()
            )),
        }
        if self.wrote {
            if let Err(e) = ioctl(&self.handle, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0) {
                problems.push(format!(
                    "Windows was not asked to read the new partition table ({}); unplugging the drive and connecting it again does it",
                    device::reason(e)
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    fn io(&mut self, offset: u64, len: usize, write: bool) -> std::io::Result<()> {
        // SAFETY: OVERLAPPED is plain data; zero is its empty state.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.Anonymous.Anonymous.Offset = offset as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        let mut done = 0u32;
        let data = self.buffer.slice();
        // SAFETY: the handle is synchronous, the buffer is aligned and holds `len` bytes,
        // and the OVERLAPPED only gives the position.
        let ok = unsafe {
            if write {
                WriteFile(
                    self.handle.0,
                    data.as_ptr(),
                    len as u32,
                    &mut done,
                    &mut overlapped,
                )
            } else {
                ReadFile(
                    self.handle.0,
                    data.as_mut_ptr(),
                    len as u32,
                    &mut done,
                    &mut overlapped,
                )
            }
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if done as usize != len {
            return Err(std::io::Error::other(format!(
                "the drive took {done} of {len} bytes"
            )));
        }
        Ok(())
    }
}

impl restore::Target for DiskWriter<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector(&self) -> u32 {
        self.sector
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.wrote = true;
        for (i, piece) in data.chunks(restore::CHUNK as usize).enumerate() {
            self.buffer.slice()[..piece.len()].copy_from_slice(piece);
            self.io(offset + (i as u64) * restore::CHUNK, piece.len(), true)?;
        }
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        for (i, piece) in buf.chunks_mut(restore::CHUNK as usize).enumerate() {
            self.io(offset + (i as u64) * restore::CHUNK, piece.len(), false)?;
            piece.copy_from_slice(&self.buffer.slice()[..piece.len()]);
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // SAFETY: the handle is open.
        if unsafe { FlushFileBuffers(self.handle.0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for DiskWriter<'_> {
    fn drop(&mut self) {
        if let Err(why) = self.release() {
            record_unseen("Write image to a replacement drive", &why);
        }
    }
}

/// NTFS_VOLUME_DATA_BUFFER: (sectors, bytes per sector, total clusters, bytes per cluster).
fn ntfs_data(handle: &Handle) -> Result<(u64, u32, u64, u32), u32> {
    let reply = ioctl(handle, FSCTL_GET_NTFS_VOLUME_DATA, &[], 96)?;
    if reply.len() < 48 {
        return Err(ERROR_INVALID_DATA);
    }
    let u64_at = |at: usize| u64::from_le_bytes(reply[at..at + 8].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(reply[at..at + 4].try_into().unwrap());
    Ok((u64_at(8), u32_at(40), u64_at(16), u32_at(44)))
}

/// Extends the NTFS file system of volume `guid`, the grown partition at `offset` on the held
/// disk, to fill its partition. The volume is opened for writing and proven through its own
/// handle to lie on the held disk alone with an extent at `offset`, with the held handle still
/// answering to its number. Returns the file system's new size.
pub fn extend_ntfs(disk: &HeldDisk, guid: &str, offset: u64) -> Result<u64, String> {
    let number = disk.number;
    let path = guid.trim_end_matches('\\');
    let handle = open(path, Access::ReadWrite, 0).map_err(|e| {
        format!(
            "{path} could not be opened for writing: {}",
            device::reason(e)
        )
    })?;
    let extents = extents_of(&handle)
        .map_err(|e| format!("{path}: its disks could not be read: {}", device::reason(e)))?;
    if extents.is_empty()
        || extents.iter().any(|(d, _, _)| *d != number)
        || !extents.iter().any(|(_, at, _)| *at == offset)
    {
        return Err(format!(
            "the volume found is not the grown partition on disk {number} alone"
        ));
    }
    disk.still_held()?;
    let partition = ioctl(&handle, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)
        .ok()
        .and_then(|reply| Some(u64::from_le_bytes(reply.get(..8)?.try_into().ok()?)))
        .ok_or("the partition's size could not be read")?;
    let (sectors, bytes_per_sector, _, _) = ntfs_data(&handle)
        .map_err(|e| format!("the file system could not be read: {}", device::reason(e)))?;
    let bytes_per_sector = u64::from(bytes_per_sector.max(512));
    let wanted = partition / bytes_per_sector;
    if wanted > sectors {
        let input = (wanted as i64).to_le_bytes();
        ioctl(&handle, FSCTL_EXTEND_VOLUME, &input, 0)
            .map_err(|e| format!("Windows refused to extend it: {}", device::reason(e)))?;
    }
    let (_, _, clusters, cluster) = ntfs_data(&handle)
        .map_err(|e| format!("the file system could not be read: {}", device::reason(e)))?;
    Ok(clusters * u64::from(cluster))
}

// ---- the repair's copy ---------------------------------------------------------------------

/// The disks Windows runs from, which are never written; empty when they could not be found.
fn system_disks() -> Vec<u32> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    device::disks_of_path(Path::new(&root)).unwrap_or_default()
}

/// The copy a repair writes, a differencing virtual disk: its disk open for writing from the
/// attach to the detach, and the file it must be.
pub struct CopyDisk {
    handle: Handle,
    /// The copy file's volume serial number and file ID, read through the folder it was
    /// made in.
    file: (u64, [u8; 16]),
}

impl CopyDisk {
    /// Opens disk `number`, the number Windows gave the copy at its attach, for writing, and
    /// proves through that handle that the virtual disk file behind it is `file`. The source
    /// disk and the disk Windows runs from are refused before anything is opened, and so is
    /// everything when that disk cannot be found.
    pub fn open(
        number: u32,
        source: &crate::recovery::dest::Protected,
        file: (u64, [u8; 16]),
    ) -> Result<Self, String> {
        if let Some(refused) = crate::recovery::dest::Guard::of(source).refuses_disk(number) {
            return Err(format!(
                "Disk {number} is never written: {}.",
                refused.reason
            ));
        }
        let system = system_disks();
        if system.is_empty() || system.contains(&number) {
            return Err(format!(
                "Disk {number} holds Windows itself, or the disk Windows runs from could not be found, so nothing is written."
            ));
        }
        let handle = open(&disk_path(number), Access::ReadWrite, 0).map_err(|code| {
            format!(
                "The copy, Disk {number}, could not be opened for writing: {}",
                crate::recovery::vdisk::error_text(code)
            )
        })?;
        let copy = Self { handle, file };
        copy.check()?;
        Ok(copy)
    }

    /// Checks through the held handle that it is still the copy: the disk is there, and the
    /// virtual disk file behind it is the file this repair made. Returns the disk number
    /// Windows gives it now.
    pub fn check(&self) -> Result<u32, String> {
        let number = device_number(&self.handle)
            .map(|(_, n)| n)
            .map_err(|code| {
                format!(
                    "The copy's disk is no longer there ({}); nothing was written.",
                    crate::recovery::vdisk::error_text(code)
                )
            })?;
        let backing = backing_files(&self.handle)?;
        // The attached file is the highest level; its parent, the image, is level 0.
        let leaf = backing.iter().map(|(level, _)| *level).max();
        let is_copy = backing
            .iter()
            .filter(|(level, _)| Some(*level) == leaf)
            .any(|(_, path)| {
                crate::recovery::dest::id_of_path(Path::new(path)).ok() == Some(self.file)
            });
        if !is_copy {
            let behind: Vec<&str> = backing.iter().map(|(_, path)| path.as_str()).collect();
            return Err(format!(
                "Disk {number} is not the copy this repair made (it is {}), so nothing was written to it.",
                behind.join(" over ")
            ));
        }
        Ok(number)
    }

    /// The virtual disk files behind the copy's disk, with their levels, for people.
    pub fn backing(&self) -> Result<Vec<(u32, String)>, String> {
        backing_files(&self.handle)
    }

    /// Checks that volume `guid` lies on the copy alone, the copy checked first; its number.
    /// chkdsk is then run on the volume by that GUID name, which names one volume for good.
    pub fn holds_volume(&self, guid: &str) -> Result<u32, String> {
        let number = self.check()?;
        let path = guid.trim_end_matches('\\');
        let extents = query(path).and_then(|volume| extents_of(&volume));
        match extents {
            Ok(e) if !e.is_empty() && e.iter().all(|(d, _, _)| *d == number) => Ok(number),
            _ => Err("That volume is not on the copy.".into()),
        }
    }

    /// Opens volume `guid` of the copy for writing, checks through that handle that it lies
    /// on the copy alone, the copy checked first, then locks it if it can, writes it out and
    /// dismounts it. The handle holds it closed until it is let go.
    pub(crate) fn close_volume(&self, guid: &str) -> Result<Handle, String> {
        let number = self.check()?;
        let path = guid.trim_end_matches('\\');
        let handle = open(path, Access::ReadWrite, 0).map_err(|e| {
            format!(
                "{path} on the copy could not be opened to close it: {}",
                device::reason(e)
            )
        })?;
        let extents = extents_of(&handle)
            .map_err(|e| format!("{path}: its disks could not be read: {}", device::reason(e)))?;
        if extents.is_empty() || extents.iter().any(|(d, _, _)| *d != number) {
            return Err(format!("{path} is not on the copy alone"));
        }
        let named = path.to_string();
        let late = move |what: &str| {
            record_unseen("Repair on a copy", &format!("{named} on the copy {what}."));
        };
        match lock_and_dismount(format!("closing {path} on the copy"), handle, late) {
            Waited::Done((handle, _, Ok(()))) => Ok(handle),
            Waited::Done((_, _, Err(e))) => Err(format!(
                "{path} on the copy could not be closed: {}",
                device::reason(e)
            )),
            _ => Err(format!(
                "{path} on the copy did not answer closing within {} s; it is let go once Windows answers, and the session's change record says so",
                COMMAND_LIMIT.as_secs()
            )),
        }
    }

    /// Writes a new partition table to the copy: a fresh, empty one (`create`), then
    /// `layout`, the copy checked through its handle before each, then has Windows read it.
    /// `layout` holds a DRIVE_LAYOUT_INFORMATION_EX of `len` bytes. The copy's mounted
    /// `volumes` are closed first and held closed until Windows has read the new table: a
    /// table written under a mounted volume leaves that volume open on the old one, and
    /// chkdsk then cannot open the volume the new table makes. Ok holds a note when Windows
    /// was not asked to read it.
    pub fn write_table(
        &self,
        create: &CREATE_DISK,
        layout: &[u64],
        len: usize,
        volumes: &[String],
    ) -> Result<Option<String>, String> {
        if len > layout.len() * 8 {
            return Err("The partition table to write is cut short; nothing was written.".into());
        }
        let closed = volumes
            .iter()
            .map(|guid| {
                self.close_volume(guid)
                    .map_err(|why| format!("{why}; nothing was written"))
            })
            .collect::<Result<Vec<Handle>, String>>()?;
        self.check()?;
        control(
            &self.handle,
            IOCTL_DISK_CREATE_DISK,
            (create as *const CREATE_DISK).cast(),
            std::mem::size_of::<CREATE_DISK>(),
        )
        .map_err(|code| {
            format!(
                "A new table could not be started on the copy: {}",
                crate::recovery::vdisk::error_text(code)
            )
        })?;
        self.check()?;
        control(
            &self.handle,
            IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
            layout.as_ptr().cast(),
            len,
        )
        .map_err(|code| {
            format!(
                "The partition table could not be written to the copy: {}",
                crate::recovery::vdisk::error_text(code)
            )
        })?;
        let note = control(&self.handle, IOCTL_DISK_UPDATE_PROPERTIES, null(), 0)
            .err()
            .map(|code| {
                format!(
                    "Windows was not asked to read the copy's new partition table ({}); its volumes may not appear until the copy is opened again",
                    crate::recovery::vdisk::error_text(code)
                )
            });
        // Let go once the new table is read, so Windows mounts what it holds.
        drop(closed);
        Ok(note)
    }
}

fn control(handle: &Handle, code: u32, input: *const c_void, len: usize) -> Result<(), u32> {
    let mut returned = 0u32;
    // SAFETY: the input is valid for `len` bytes; the call is synchronous.
    let ok = unsafe {
        DeviceIoControl(
            handle.0,
            code,
            input,
            len as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: reads this thread's last error.
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

/// The virtual disk files behind an open disk handle, with their ancestor levels (the
/// attached file is the highest, its parent level 0), from its storage dependency
/// information.
fn backing_files(disk: &Handle) -> Result<Vec<(u32, String)>, String> {
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    let mut buffer = vec![0u64; 512];
    loop {
        let size = (buffer.len() * 8) as u32;
        let info = buffer.as_mut_ptr().cast::<STORAGE_DEPENDENCY_INFO>();
        // SAFETY: the buffer is 8-aligned and holds `size` bytes, enough for the header.
        unsafe { (*info).Version = STORAGE_DEPENDENCY_INFO_VERSION_2 };
        let mut used = 0u32;
        // SAFETY: the handle is open and the buffer writable for `size` bytes.
        let error = unsafe {
            GetStorageDependencyInformation(
                disk.0,
                // A disk handle is refused (error 87) without the host volumes flag.
                GET_STORAGE_DEPENDENCY_FLAG_DISK_HANDLE | GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES,
                size,
                info,
                &mut used,
            )
        };
        if error == ERROR_INSUFFICIENT_BUFFER && used as usize > buffer.len() * 8 {
            buffer = vec![0u64; (used as usize).div_ceil(8)];
            continue;
        }
        if error != 0 {
            return Err(format!(
                "Windows did not say which file is behind the copy's disk: {}",
                crate::recovery::vdisk::error_text(error)
            ));
        }
        // SAFETY: Windows filled in the header and `NumberEntries` version-2 entries, whose
        // strings point into the same buffer.
        let entries = unsafe {
            let count = (*info).NumberEntries as usize;
            let first = std::ptr::addr_of!((*info).Anonymous.Version2Entries)
                .cast::<STORAGE_DEPENDENCY_INFO_TYPE_2>();
            (0..count)
                .map(|i| {
                    let entry = &*first.add(i);
                    let host = wide_text(entry.HostVolumeName);
                    let relative = wide_text(entry.DependentVolumeRelativePath);
                    (entry.AncestorLevel, join_backing(&host, &relative))
                })
                .collect()
        };
        return Ok(entries);
    }
}

/// A NUL-terminated wide string, or empty for a null pointer.
///
/// # Safety
/// `text` is null or points to a NUL-terminated UTF-16 string.
unsafe fn wide_text(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: the caller's promise: a NUL ends the string.
    unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    }
}

/// "\\?\Volume{guid}\" and "folder\copy.vhd" (with or without its leading backslash)
/// joined into one path.
fn join_backing(host: &str, relative: &str) -> String {
    format!(
        "{}\\{}",
        host.trim_end_matches('\\'),
        relative.trim_start_matches('\\')
    )
}

// ---- ATA commands --------------------------------------------------------------------------

/// IOCTL_ATA_PASS_THROUGH: CTL_CODE(IOCTL_SCSI_BASE, 0x040B, METHOD_BUFFERED,
/// FILE_READ_ACCESS | FILE_WRITE_ACCESS).
const IOCTL_ATA_PASS_THROUGH: u32 = 0x0004_D02C;
/// IOCTL_SCSI_PASS_THROUGH: CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED,
/// FILE_READ_ACCESS | FILE_WRITE_ACCESS).
const IOCTL_SCSI_PASS_THROUGH: u32 = 0x0004_D004;

/// A disk's STORAGE_DEVICE_DESCRIPTOR, read on `handle`.
fn descriptor_of(handle: &Handle) -> Result<Vec<u8>, u32> {
    let mut query = Vec::with_capacity(12);
    query.extend_from_slice(&StorageDeviceProperty.to_le_bytes());
    query.resize(12, 0);
    ioctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &query, 1024)
}

/// The bus in a disk's descriptor, read on `handle`.
fn bus_of(handle: &Handle) -> Result<i32, u32> {
    health::parse_device_descriptor(&descriptor_of(handle)?)
        .map(|identity| identity.bus)
        .ok_or(ERROR_INVALID_DATA)
}

/// A disk open read-write for the ATA commands Windows passes only on such a handle, proven
/// to be a held disk, with the carrier its bus calls for. Through it go only the commands
/// `ata::Command` can build: the three data-in reads of `AtaCommand` and, through
/// `SctDrive`, the SCT read limit.
pub struct AtaDisk {
    handle: Handle,
    carrier: Carrier,
    /// Set once a USB adapter has taken ATA PASS-THROUGH (12) and not (16).
    twelve: AtomicBool,
}

impl AtaDisk {
    /// Opens `disk` read-write, its number checked on the new handle and the held handle still
    /// answering to it after the open; the carrier is chosen by the bus read on the new
    /// handle, and a bus that carries no ATA command is refused.
    pub fn open(disk: &HeldDisk) -> Result<Self, String> {
        let handle = open(&disk_path(disk.number), Access::ReadWrite, 0).map_err(|e| match e {
            ERROR_ACCESS_DENIED => "needs administrator rights".to_string(),
            other => device::reason(other),
        })?;
        match device_number(&handle) {
            Ok((FILE_DEVICE_DISK, n)) if n == disk.number => {}
            _ => return Err("the disk opened is not the one read".into()),
        }
        let bus = bus_of(&handle)
            .map_err(|e| format!("its bus could not be read: {}", device::reason(e)))?;
        let carrier = ata::carrier(Some(bus))?;
        disk.still_held()?;
        Ok(Self {
            handle,
            carrier,
            twelve: AtomicBool::new(false),
        })
    }

    /// Sends one command through the carrier and reads what came back; an error in the
    /// drive's returned registers is the drive's refusal.
    pub fn execute(&self, command: &ata::Command) -> Result<ata::Answer, Failure> {
        let not_passed = |e: u32| Failure::NotPassed(device::reason(e));
        let answer = match (self.carrier, command.direction()) {
            (Carrier::Windows, Direction::In) => ioctl(
                &self.handle,
                SMART_RCV_DRIVE_DATA,
                &ata::smart_rcv_input(command),
                ata::SMART_RCV_REPLY,
            )
            .map_err(not_passed)
            .and_then(|reply| ata::smart_rcv_answer(&reply)),
            (Carrier::Windows, Direction::Out) => ioctl(
                &self.handle,
                IOCTL_ATA_PASS_THROUGH,
                &ata::pass_through_input(command),
                ata::PASS_THROUGH_HEADER + ata::SECTOR,
            )
            .map_err(not_passed)
            .and_then(|reply| ata::pass_through_answer(&reply, command)),
            // A SCSI pass-through's status and sense are read by their own fields, so the
            // whole buffer is read, whatever count the driver gives.
            (Carrier::Sat, _) => sat::exchange(command, &self.twelve, |form| {
                ioctl_all(
                    &self.handle,
                    IOCTL_SCSI_PASS_THROUGH,
                    &sat::input(command, form),
                    sat::LEN,
                )
                .map(|(reply, _)| reply)
                .map_err(not_passed)
            }),
        }?;
        ata::checked(command, answer)
    }

    /// One of the three reads; the 512 bytes the drive sent.
    pub fn read(&self, command: AtaCommand) -> Result<Vec<u8>, Failure> {
        self.execute(&ata::Command::read(command))
            .map(|answer| answer.data)
    }

    /// The drive's descriptor, read on this handle.
    fn descriptor(&self) -> Result<Vec<u8>, u32> {
        descriptor_of(&self.handle)
    }
}

/// One ATA drive's read limit (SCT Error Recovery Control, the read timer), bound to the
/// drive it was meant for. The read-write handle is opened once, proven to be the disk held
/// by number; the bus, the model and serial number and the IDENTIFY data are all read on it,
/// and every command goes through it, so a drive that leaves and another that takes its
/// number is never sent anything. The caller keeps it for the run and sends one command at a
/// time.
pub struct SctDrive {
    ata: AtaDisk,
}

impl SctDrive {
    /// Opens disk `number` for its read limit, when it is the drive with this model and
    /// serial number. An NVMe drive, a drive on another bus, or one whose identify data says
    /// it has no such setting is refused without a read-write handle where that is known
    /// first; a drive that is not the one named, or names no serial number, is refused.
    pub fn open(number: u32, model: &str, serial: &str) -> Result<Self, Refusal> {
        // A first look with no access right, so a drive on another bus is never opened for
        // writing; everything that decides is read again below on the handle that is kept.
        let held = HeldDisk::open(number).map_err(|e| {
            Refusal::Refused(format!("could not open the disk: {}", device::reason(e)))
        })?;
        let bus = bus_of(held.handle()).ok();
        device::ata_bus(bus)?;
        let ata = AtaDisk::open(&held).map_err(Refusal::Refused)?;
        let reply = ata.descriptor().map_err(|e| {
            Refusal::NotTheDrive(format!(
                "its description was not read: {}",
                device::reason(e)
            ))
        })?;
        let identity = health::parse_device_descriptor(&reply)
            .ok_or_else(|| Refusal::NotTheDrive("its description was malformed".into()))?;
        device::ata_bus(Some(identity.bus))?;
        device::same_drive(
            number,
            (
                &crate::tools::drives::display_name(&identity),
                &health::parse_descriptor_serial(&reply),
            ),
            (model, serial),
        )?;
        // Where the drive answers IDENTIFY, its word 206 says whether it has the setting; over
        // a USB adapter that passes no IDENTIFY, the command itself finds out.
        if let Ok(identify) = ata.read(AtaCommand::Identify) {
            if !sct::supported(&identify) {
                return Err(Refusal::NoSetting);
            }
        }
        Ok(Self { ata })
    }

    /// Reads or sets the read limit; for a read, the limit in tenths of a second. The call
    /// blocks until the drive or its driver answers.
    pub fn send(&self, request: sct::Request) -> Result<Option<u16>, Refusal> {
        let answer = self
            .ata
            .execute(&ata::Command::sct(request))
            .map_err(|failure| Refusal::Refused(failure.text().to_string()))?;
        sct::limit(request, &answer).map_err(Refusal::Refused)
    }
}

#[cfg(test)]
mod tests;
