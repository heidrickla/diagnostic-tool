//! Reading a physical disk, and files on a failing volume, with a time limit on every read.
//! Every handle here is opened for reading only (`ACCESS`), shared, uncached and overlapped,
//! so a read that hangs can be cancelled instead of holding the tool.
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_IO_PENDING,
    ERROR_PATH_NOT_FOUND, GENERIC_READ, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
use windows_sys::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED,
};

use super::{BlockSource, ReadError, Scope};

/// The only access any source handle asks for. Never a write right.
pub const ACCESS: u32 = GENERIC_READ;
/// Others may keep reading and writing the disk; this tool only reads.
pub const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
/// Uncached, so every read reaches the drive, and overlapped, so it can be cancelled.
pub const FLAGS: u32 = FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED;
/// How long one read may take before it is cancelled and counted as timed out.
pub const READ_LIMIT: Duration = Duration::from_secs(20);
/// After a cancel, how long to wait for the driver to give the buffer back.
const CANCEL_GRACE: Duration = Duration::from_secs(30);
/// How long the drive has to answer the presence probe (its size, READ CAPACITY) after a read
/// failed. A drive that answers does so in milliseconds; half the read limit means the probe
/// never waits longer than the read that prompted it, and a probe given up on costs a pause
/// with the map saved, never a mark on the map.
pub const PROBE_LIMIT: Duration = Duration::from_secs(10);

const ERROR_DEV_NOT_EXIST: u32 = 55;
const ERROR_NO_SUCH_DEVICE: u32 = 433;
const ERROR_IO_DEVICE: u32 = 1117;
const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;
const ERROR_OPERATION_ABORTED: u32 = 995;

use crate::handles::HeldDisk;
pub(crate) use crate::handles::{ioctl, logical_sector, wide, Handle};

/// Opens `path` with `ACCESS` only and the given flags. Every source handle comes from here.
pub(crate) fn open_read(path: &str, flags: u32, share: u32) -> Result<Handle, u32> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            ACCESS,
            share,
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

/// Maps a failed read's Win32 error. The codes that say the device is gone are gone; every
/// other failure, whatever its code, asks `present` whether the drive is still there, so a
/// drive that is absent or resetting is never recorded as a bad area.
pub fn classify(code: u32, present: impl FnOnce() -> bool) -> ReadError {
    match code {
        ERROR_DEVICE_NOT_CONNECTED | ERROR_NO_SUCH_DEVICE | ERROR_DEV_NOT_EXIST => {
            ReadError::Gone(code)
        }
        other => {
            if present() {
                ReadError::Bad(other)
            } else {
                ReadError::Gone(other)
            }
        }
    }
}

/// What a physical read that did not bring back all it asked for means. Every way it can
/// fail, a short read included, asks `answering` whether the drive is still there before it
/// is called a bad area or a slow one.
pub(crate) fn failed_read(timed: Timed, answering: impl FnOnce() -> bool) -> ReadError {
    match timed {
        Timed::Done(_) => classify(ERROR_HANDLE_EOF, answering),
        Timed::Failed(code) => classify(code, answering),
        // A read past its limit is a hang's first sign as much as a slow bad area's.
        Timed::Expired if answering() => ReadError::TimedOut,
        Timed::Expired | Timed::Stuck => ReadError::Gone(ERROR_IO_DEVICE),
    }
}

/// Whether the drive is shown to be answering after a failed read: Windows still holds its
/// device (`held`), and the drive itself answered a read-only query in time (`answers`).
/// Windows' device object alone is not enough: after a USB reset it can stay for good while
/// every read, size and SMART query fails, and a failure recorded then would be the drive's
/// absence written into the map as damage.
pub fn shown_answering(held: impl FnOnce() -> bool, answers: impl FnOnce() -> bool) -> bool {
    held() && answers()
}

/// A buffer whose start is aligned for uncached reads.
pub(crate) struct Aligned {
    raw: Vec<u8>,
    start: usize,
    len: usize,
}

impl Aligned {
    pub(crate) fn new(len: usize, align: usize) -> Self {
        let raw = vec![0u8; len + align];
        let start = raw.as_ptr().align_offset(align);
        Self { raw, start, len }
    }

    pub(crate) fn slice(&mut self) -> &mut [u8] {
        &mut self.raw[self.start..self.start + self.len]
    }
}

/// How one timed read ended.
pub(crate) enum Timed {
    Done(usize),
    Failed(u32),
    Expired,
    /// The driver kept the buffer past the grace period; the handle cannot be used again.
    Stuck,
}

/// An overlapped read-only handle with an aligned buffer and an event for timed reads.
pub(crate) struct TimedReader {
    handle: Handle,
    event: Handle,
    buffer: Aligned,
    align: usize,
    limit: Duration,
    stuck: bool,
}

impl TimedReader {
    pub(crate) fn new(handle: Handle, align: usize, limit: Duration) -> Result<Self, u32> {
        // SAFETY: a manual-reset, unnamed event.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            // SAFETY: reads this thread's last error.
            return Err(unsafe { GetLastError() });
        }
        Ok(Self {
            handle,
            event: Handle(event),
            buffer: Aligned::new(0, align),
            align,
            limit,
            stuck: false,
        })
    }

    /// Reads `len` bytes at `offset` (both aligned) into the internal buffer.
    pub(crate) fn read(&mut self, offset: u64, len: usize) -> (Timed, &[u8]) {
        if self.stuck {
            return (Timed::Stuck, &[]);
        }
        if self.buffer.len < len {
            self.buffer = Aligned::new(len, self.align);
        }
        // The OVERLAPPED lives on the heap so it can be leaked with the buffer if stuck.
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.Anonymous.Anonymous.Offset = offset as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        overlapped.hEvent = self.event.0;
        let pointer = self.buffer.slice().as_mut_ptr();
        // SAFETY: the event handle is valid.
        unsafe { ResetEvent(self.event.0) };
        // SAFETY: the buffer and OVERLAPPED stay valid until the read completes: on a timeout
        // the read is cancelled and waited for, and leaked if it never completes.
        let ok = unsafe {
            ReadFile(
                self.handle.0,
                pointer,
                len as u32,
                null_mut(),
                overlapped.as_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: reads this thread's last error.
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                return (Timed::Failed(error), &[]);
            }
        }
        let millis = self.limit.as_millis().min(u32::MAX as u128 - 1) as u32;
        // SAFETY: the event handle is valid.
        let mut timed_out = false;
        if unsafe { WaitForSingleObject(self.event.0, millis) } != WAIT_OBJECT_0 {
            timed_out = true;
            // SAFETY: cancels only this read on this handle.
            unsafe { CancelIoEx(self.handle.0, overlapped.as_ref()) };
            let grace = CANCEL_GRACE.as_millis() as u32;
            // SAFETY: the event handle is valid.
            if unsafe { WaitForSingleObject(self.event.0, grace) } != WAIT_OBJECT_0 {
                // The driver still owns the buffer: keep it alive for good and stop reading.
                self.stuck = true;
                std::mem::forget(std::mem::replace(
                    &mut self.buffer,
                    Aligned::new(0, self.align),
                ));
                std::mem::forget(overlapped);
                return (Timed::Stuck, &[]);
            }
        }
        let mut got = 0u32;
        // SAFETY: the read has completed (its event is set), so this does not wait.
        let ok = unsafe { GetOverlappedResult(self.handle.0, overlapped.as_ref(), &mut got, 0) };
        if ok == 0 {
            // SAFETY: reads this thread's last error.
            let error = unsafe { GetLastError() };
            return match error {
                ERROR_OPERATION_ABORTED if timed_out => (Timed::Expired, &[]),
                ERROR_HANDLE_EOF => (Timed::Done(0), &[]),
                other => (Timed::Failed(other), &[]),
            };
        }
        let got = got as usize;
        (Timed::Done(got), &self.buffer.slice()[..got])
    }

    /// One query with no input, `code` (a read-only one), on this handle, waited for up to
    /// `limit` as a read is; the reply's bytes when it came back in time.
    pub(crate) fn query(&mut self, code: u32, out_len: usize, limit: Duration) -> Option<Vec<u8>> {
        if self.stuck {
            return None;
        }
        // Both live on the heap so they can be leaked if the driver keeps them.
        let mut out = vec![0u8; out_len];
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = self.event.0;
        // SAFETY: the event handle is valid.
        unsafe { ResetEvent(self.event.0) };
        // SAFETY: the output buffer and OVERLAPPED stay valid until the call completes: on a
        // timeout it is cancelled and waited for, and both are leaked if it never completes.
        let ok = unsafe {
            DeviceIoControl(
                self.handle.0,
                code,
                null(),
                0,
                out.as_mut_ptr().cast(),
                out_len as u32,
                null_mut(),
                overlapped.as_mut(),
            )
        };
        // SAFETY: reads this thread's last error.
        if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return None;
        }
        let millis = limit.as_millis().min(u32::MAX as u128 - 1) as u32;
        // SAFETY: the event handle is valid.
        if unsafe { WaitForSingleObject(self.event.0, millis) } != WAIT_OBJECT_0 {
            // SAFETY: cancels only this call on this handle.
            unsafe { CancelIoEx(self.handle.0, overlapped.as_ref()) };
            let grace = CANCEL_GRACE.as_millis() as u32;
            // SAFETY: the event handle is valid.
            if unsafe { WaitForSingleObject(self.event.0, grace) } != WAIT_OBJECT_0 {
                self.stuck = true;
                std::mem::forget(out);
                std::mem::forget(overlapped);
            }
            return None;
        }
        let mut got = 0u32;
        // SAFETY: the call has completed (its event is set), so this does not wait.
        let ok = unsafe { GetOverlappedResult(self.handle.0, overlapped.as_ref(), &mut got, 0) };
        if ok == 0 {
            return None;
        }
        out.truncate(got as usize);
        Some(out)
    }
}

/// A physical disk, `\\.\PhysicalDriveN`, opened for reading only, or one volume on it (an
/// unlocked BitLocker volume, read decrypted). Needs administrator rights.
pub struct PhysicalDisk {
    number: u32,
    /// The disk, held from the open: the reader was proven through it to be this drive, its
    /// identity was read through it, and a failed read asks it whether the drive is still
    /// there.
    held: HeldDisk,
    /// Set for a volume: its "\\?\Volume{guid}" path, checked when a read fails.
    volume: Option<String>,
    reader: TimedReader,
    /// A second overlapped read-only handle on the disk, proven to be the held drive, for
    /// the presence probe after a failed read (`answering`).
    probe: TimedReader,
    /// The whole disk's size, which the probe's answer must still give; None when Windows
    /// did not report it for a volume's disk.
    disk_len: Option<u64>,
    len: u64,
    sector: u32,
    describe: String,
    identity: Option<super::SourceId>,
}

pub(crate) fn open_failure(what: &str, error: u32) -> String {
    match error {
        ERROR_ACCESS_DENIED => format!("{what} needs administrator rights to be read"),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => format!("{what} is not connected"),
        other => format!("{what} could not be opened (error {other})"),
    }
}

impl PhysicalDisk {
    /// Opens disk `number` for reading. The disk is held by its number, its size, sector
    /// size and identity are read through that handle, and the overlapped reader is proven
    /// to be the held drive.
    pub fn open(number: u32) -> Result<Self, String> {
        let what = format!("Disk {number}");
        // The size and sector queries go through the held handle, with the same read access.
        let held = HeldDisk::open_read(number).map_err(|e| open_failure(&what, e))?;
        let len = ioctl(held.handle(), IOCTL_DISK_GET_LENGTH_INFO, &[], 8)
            .ok()
            .and_then(|reply| Some(u64::from_le_bytes(reply.get(..8)?.try_into().ok()?)))
            .ok_or_else(|| format!("{what} did not report its size (no media?)"))?;
        if len == 0 {
            return Err(format!("{what} reports a size of zero (no media?)"));
        }
        let sector = Sector::of(held.handle());
        let handle = held.read_again(FLAGS)?;
        let align = (sector.bytes() as usize).max(4096);
        let reader = TimedReader::new(handle, align, READ_LIMIT)
            .map_err(|e| format!("{what}: no event for timed reads (error {e})"))?;
        let probe = probe_on(&held, &what)?;
        let identity = source_id(&held, len, sector, Scope::Disk);
        let describe = describe_disk(number, len, identity.as_ref(), sector);
        Ok(Self {
            number,
            held,
            volume: None,
            reader,
            probe,
            disk_len: Some(len),
            len,
            sector: sector.bytes(),
            describe,
            identity,
        })
    }

    /// Whether the drive is shown to be answering: Windows still holds it (and the volume,
    /// for a volume), and the drive reports its size again, the same as before, within
    /// `PROBE_LIMIT`. The size query is IOCTL_DISK_GET_LENGTH_INFO, which the disk driver
    /// answers by sending READ CAPACITY to the drive every time; the geometry queries can be
    /// answered from what Windows kept, so they say nothing about the drive.
    fn answering(&mut self) -> bool {
        let (held, volume, disk_len) = (&self.held, &self.volume, self.disk_len);
        let probe = &mut self.probe;
        shown_answering(
            || held.still_held().is_ok() && volume.as_deref().is_none_or(volume_present),
            || {
                probe
                    .query(IOCTL_DISK_GET_LENGTH_INFO, 8, PROBE_LIMIT)
                    .and_then(|reply| Some(u64::from_le_bytes(reply.get(..8)?.try_into().ok()?)))
                    .is_some_and(|len| len > 0 && disk_len.is_none_or(|known| known == len))
            },
        )
    }
}

/// The probe's handle: the held disk opened again for reading, overlapped, proven to be it.
fn probe_on(held: &HeldDisk, what: &str) -> Result<TimedReader, String> {
    let handle = held.read_again(FLAGS)?;
    TimedReader::new(handle, 4096, PROBE_LIMIT)
        .map_err(|e| format!("{what}: no event for timed queries (error {e})"))
}

/// What identifies the held drive to a rescue map, read through the held handle: the model
/// and serial number Windows reports, `len`, the sector size when reported, the part of the
/// drive read (`scope`), the whole drive's size, and the drive's own identity from IDENTIFY, which is read only
/// (`device::ata_identity`) and is None for a drive that is not ATA or did not answer.
fn source_id(held: &HeldDisk, len: u64, sector: Sector, scope: Scope) -> Option<super::SourceId> {
    let id = held.identity().ok()?;
    Some(super::SourceId {
        model: id.model,
        serial: id.serial,
        size: len,
        scope: Some(scope),
        disk_size: id.size,
        drive: crate::tools::drives::device::ata_identity(held),
        sector: match sector {
            Sector::Reported(bytes) => Some(bytes),
            Sector::Assumed => None,
        },
    })
}

/// A source's bytes per sector, or 512 assumed when Windows did not report it; the
/// assumption is said in the source's description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sector {
    Reported(u32),
    Assumed,
}

impl Sector {
    fn of(info: &Handle) -> Self {
        match logical_sector(info) {
            Some(bytes) => Sector::Reported(bytes),
            None => Sector::Assumed,
        }
    }

    fn bytes(self) -> u32 {
        match self {
            Sector::Reported(bytes) => bytes,
            Sector::Assumed => 512,
        }
    }

    /// What the description adds: nothing for a reported size.
    fn note(self) -> &'static str {
        match self {
            Sector::Reported(_) => "",
            Sector::Assumed => ", sector size not reported (read as 512 bytes)",
        }
    }
}

impl PhysicalDisk {
    /// Opens one volume, `path` "\\?\Volume{guid}", on disk `disk`, for reading only, the
    /// same way as a disk. A BitLocker volume reads decrypted once it is unlocked.
    /// `describe` names it for people.
    pub fn open_volume(path: &str, disk: u32, describe: String) -> Result<Self, String> {
        let path = path.trim_end_matches('\\');
        let what = describe.clone();
        // Which disk the volume is on comes from the volume itself, before anything else:
        // the guard keeps output off that disk, so a number named wrongly is refused.
        let (disk, offset) = volume_disk(path, disk, &what)?;
        // Then the disk is held, and the volume checked again to lie on it, at the same
        // place, while it is held, so the identity read through the held handle is the
        // volume's drive and the scope a map records is where the volume lies.
        let held = HeldDisk::open(disk).map_err(|e| open_failure(&format!("Disk {disk}"), e))?;
        if volume_disk(path, disk, &what)? != (disk, offset) {
            return Err(format!("{what} moved on Disk {disk} while it was opened"));
        }
        held.still_held()?;
        let info = open_read(path, 0, SHARE).map_err(|e| open_failure(&what, e))?;
        let len = ioctl(&info, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)
            .ok()
            .and_then(|reply| Some(u64::from_le_bytes(reply.get(..8)?.try_into().ok()?)))
            .ok_or_else(|| format!("{what} did not report its size"))?;
        if len == 0 {
            return Err(format!("{what} reports a size of zero"));
        }
        let sector = Sector::of(&info);
        drop(info);
        let handle = open_read(path, FLAGS, SHARE).map_err(|e| open_failure(&what, e))?;
        let align = (sector.bytes() as usize).max(4096);
        let reader = TimedReader::new(handle, align, READ_LIMIT)
            .map_err(|e| format!("{what}: no event for timed reads (error {e})"))?;
        let probe = probe_on(&held, &what)?;
        let identity = source_id(&held, len, sector, Scope::Volume { offset });
        Ok(Self {
            number: disk,
            held,
            volume: Some(path.to_string()),
            reader,
            probe,
            disk_len: identity.as_ref().and_then(|id| id.disk_size),
            len,
            sector: sector.bytes(),
            describe: format!("{describe}{}", sector.note()),
            identity,
        })
    }
}

/// The disk volume `path` lies on and the byte where it starts there, read from its own
/// extents through a handle with no access right, and checked against `named`: a volume on
/// another disk, on more than one disk, or whose extents cannot be read is refused.
pub(crate) fn volume_disk(path: &str, named: u32, what: &str) -> Result<(u32, u64), String> {
    let name = wide(path.trim_end_matches('\\'));
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0,
            SHARE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads this thread's last error.
        return Err(open_failure(what, unsafe { GetLastError() }));
    }
    let handle = Handle(handle);
    let reply = ioctl(
        &handle,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &[],
        8 + 24 * 64,
    )
    .map_err(|e| format!("{what}: Windows did not say which disk it is on (error {e})"))?;
    let extents = crate::tools::drives::health::parse_volume_extents(&reply);
    let disks: Vec<u32> = extents.iter().map(|(disk, _, _)| *disk).collect();
    let disk = one_disk(&disks, named, what)?;
    let start = extents
        .iter()
        .map(|(_, offset, _)| *offset)
        .min()
        .ok_or_else(|| format!("{what}: Windows did not say where it lies"))?;
    Ok((disk, start))
}

/// The one disk in `disks`, a volume's extents, when it is `named`.
pub(crate) fn one_disk(disks: &[u32], named: u32, what: &str) -> Result<u32, String> {
    match disks {
        [] => Err(format!("{what}: Windows did not say which disk it is on")),
        [first, rest @ ..] if rest.iter().any(|d| d != first) => Err(format!(
            "{what} lies on more than one disk, which the recovery tools do not read"
        )),
        [disk, ..] if *disk != named => Err(format!(
            "{what} is on Disk {disk}, not Disk {named}, so it is not read"
        )),
        [disk, ..] => Ok(*disk),
    }
}

/// Whether a volume is still there. A zero-access open asks for no rights at all.
fn volume_present(path: &str) -> bool {
    open_read_none(path)
}

fn open_read_none(path: &str) -> bool {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0,
            SHARE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return false;
    }
    drop(Handle(handle));
    true
}

/// "Disk 3, Kingston DataTraveler 3.0, 28.9 GB". The model comes from the descriptor
/// query, which needs no access right; no health data is read here.
fn describe_disk(
    number: u32,
    len: u64,
    identity: Option<&super::SourceId>,
    sector: Sector,
) -> String {
    let model = identity.map_or("model not read", |id| id.model.as_str());
    let model = if model.trim().is_empty() {
        "model not reported"
    } else {
        model
    };
    format!(
        "Disk {number}, {model}, {}{}",
        crate::tools::drives::size_text(len),
        sector.note()
    )
}

impl BlockSource for PhysicalDisk {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let timed = match self.reader.read(offset, buf.len()) {
            (Timed::Done(got), data) if got == buf.len() => {
                buf.copy_from_slice(data);
                return Ok(());
            }
            (timed, _) => timed,
        };
        Err(failed_read(timed, || self.answering()))
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }

    fn disk_number(&self) -> Option<u32> {
        Some(self.number)
    }

    fn answering(&mut self) -> bool {
        PhysicalDisk::answering(self)
    }

    fn identity(&self) -> Option<super::SourceId> {
        self.identity.clone()
    }
}

/// A file on a (possibly failing) volume, read uncached with a time limit, never followed
/// through a link. `len` is the file's own length; reads past it come back as zeros.
pub struct TimedFile {
    path: std::path::PathBuf,
    reader: TimedReader,
    len: u64,
    sector: u32,
}

impl TimedFile {
    pub fn open(path: &std::path::Path, len: u64, sector: u32) -> Result<Self, ReadError> {
        let text = path.to_string_lossy().to_string();
        let handle = open_read(
            &text,
            FLAGS | FILE_FLAG_OPEN_REPARSE_POINT,
            SHARE | FILE_SHARE_DELETE,
        )
        .map_err(|code| classify(code, || path_present(path)))?;
        let align = (sector as usize).max(4096);
        let reader = TimedReader::new(handle, align, READ_LIMIT).map_err(ReadError::Bad)?;
        Ok(Self {
            path: path.to_path_buf(),
            reader,
            len,
            sector,
        })
    }
}

/// Whether the volume holding `path` is still there.
fn path_present(path: &std::path::Path) -> bool {
    path.ancestors()
        .last()
        .is_some_and(|root| std::fs::metadata(root).is_ok())
}

impl BlockSource for TimedFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let path = self.path.clone();
        match self.reader.read(offset, buf.len()) {
            (Timed::Done(got), data) => {
                // Past the end of the file the rest is zeros, as the file's length says.
                buf[..got].copy_from_slice(data);
                buf[got..].fill(0);
                if got < buf.len() && offset + (got as u64) < self.len {
                    return Err(ReadError::Bad(ERROR_HANDLE_EOF));
                }
                Ok(())
            }
            (Timed::Failed(code), _) => Err(classify(code, || path_present(&path))),
            (Timed::Expired, _) => Err(ReadError::TimedOut),
            (Timed::Stuck, _) => Err(ReadError::Gone(ERROR_IO_DEVICE)),
        }
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

/// The volume holding the temp folder, by its GUID name.
#[cfg(test)]
pub(crate) fn temp_volume() -> String {
    use windows_sys::Win32::Storage::FileSystem::{
        GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    };
    let dir = wide(&std::env::temp_dir().to_string_lossy());
    let mut mount = vec![0u16; 1024];
    let mut name = vec![0u16; 64];
    // SAFETY: the inputs are NUL-terminated and the outputs writable for their lengths.
    unsafe {
        assert_ne!(
            GetVolumePathNameW(dir.as_ptr(), mount.as_mut_ptr(), 1024),
            0
        );
        assert_ne!(
            GetVolumeNameForVolumeMountPointW(mount.as_ptr(), name.as_mut_ptr(), 64),
            0
        );
    }
    let end = name.iter().position(|c| *c == 0).unwrap();
    String::from_utf16_lossy(&name[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::{
        WriteFile, DELETE, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        WRITE_DAC, WRITE_OWNER,
    };

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("diagtool-{name}-{}.bin", std::process::id()))
    }

    /// The guard: no source handle carries a write right, and a write through one is refused.
    #[test]
    fn a_source_handle_cannot_write() {
        let writes = GENERIC_WRITE
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER;
        assert_eq!(
            ACCESS & writes,
            0,
            "source access {ACCESS:#x} has a write right"
        );
        let path = temp("nowrite");
        std::fs::write(&path, vec![7u8; 4096]).unwrap();
        let handle = open_read(&path.to_string_lossy(), 0, SHARE | FILE_SHARE_DELETE).unwrap();
        let data = [0u8; 16];
        let mut written = 0u32;
        // SAFETY: a synchronous write attempt through the read-only handle.
        let ok = unsafe {
            WriteFile(
                handle.0,
                data.as_ptr(),
                data.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        drop(handle);
        let after = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(ok, 0, "the write went through a source handle");
        assert_eq!(error, ERROR_ACCESS_DENIED);
        assert!(after.iter().all(|b| *b == 7));
    }

    #[test]
    fn device_errors_map_to_gone_only_when_the_drive_left() {
        assert_eq!(classify(1167, || true), ReadError::Gone(1167));
        assert_eq!(classify(433, || true), ReadError::Gone(433));
        assert_eq!(classify(1117, || true), ReadError::Bad(1117));
        assert_eq!(classify(1117, || false), ReadError::Gone(1117));
        assert_eq!(classify(23, || false), ReadError::Gone(23));
        assert_eq!(classify(23, || true), ReadError::Bad(23));
        assert_eq!(classify(38, || false), ReadError::Gone(38));
    }

    /// The guard: every failed physical read asks the drive before it is marked, a short
    /// read and a CRC error as much as a device error, and a stuck read never is.
    #[test]
    fn every_failed_read_asks_the_drive_first() {
        assert_eq!(failed_read(Timed::Done(100), || false), ReadError::Gone(38));
        assert_eq!(failed_read(Timed::Done(100), || true), ReadError::Bad(38));
        assert_eq!(
            failed_read(Timed::Failed(23), || false),
            ReadError::Gone(23)
        );
        assert_eq!(failed_read(Timed::Failed(23), || true), ReadError::Bad(23));
        assert_eq!(failed_read(Timed::Expired, || true), ReadError::TimedOut);
        assert_eq!(failed_read(Timed::Expired, || false), ReadError::Gone(1117));
        assert_eq!(
            failed_read(Timed::Stuck, || panic!("a stuck handle is not asked")),
            ReadError::Gone(1117)
        );
    }

    /// The guard: Windows still holding the device is not the drive answering. After a USB
    /// reset the device object stays while every read fails with 1117; those failures must
    /// not count as bad sectors.
    #[test]
    fn a_held_drive_that_does_not_answer_is_gone_not_bad() {
        let held_silent = || shown_answering(|| true, || false);
        assert_eq!(classify(1117, held_silent), ReadError::Gone(1117));
        assert_eq!(
            classify(1117, || shown_answering(|| true, || true)),
            ReadError::Bad(1117)
        );
        assert_eq!(
            classify(1117, || shown_answering(|| false, || true)),
            ReadError::Gone(1117)
        );
    }

    #[test]
    fn a_timed_file_reads_uncached_and_pads_past_its_end() {
        let path = temp("timed");
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let mut file = TimedFile::open(&path, data.len() as u64, 512).unwrap();
        let mut buf = vec![0u8; 8192];
        file.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[..8192]);
        file.read_at(8192, &mut buf).unwrap();
        assert_eq!(&buf[..10_000 - 8192], &data[8192..]);
        assert!(buf[10_000 - 8192..].iter().all(|b| *b == 0));
        drop(file);
        std::fs::remove_file(&path).unwrap();
    }

    /// The guard: a volume source's disk is the one its own extents name. A volume named
    /// with another disk's number is refused before it is read, so the output guard can
    /// never be handed a disk the volume is not on.
    #[test]
    fn a_volume_named_with_the_wrong_disk_is_refused() {
        let volume = temp_volume();
        let disks = crate::tools::drives::device::disks_of_volume(&volume).unwrap();
        let real = disks[0];
        let wrong = (0..64).find(|d| !disks.contains(d)).unwrap();
        let refused = PhysicalDisk::open_volume(&volume, wrong, "The volume".into())
            .err()
            .expect("a volume named with a disk it is not on was opened");
        assert!(
            refused.contains(&format!("is on Disk {real}, not Disk {wrong}")),
            "{refused}"
        );
        // With its own disk it gets as far as the read handle (administrator rights).
        if let Err(why) = PhysicalDisk::open_volume(&volume, real, "The volume".into()) {
            assert!(why.contains("administrator"), "{why}");
        }
        assert!(one_disk(&[], 3, "V").is_err());
        assert!(one_disk(&[3, 4], 3, "V")
            .unwrap_err()
            .contains("more than one disk"));
        assert_eq!(one_disk(&[3, 3], 3, "V"), Ok(3));
    }

    #[test]
    fn a_missing_disk_is_named_not_connected() {
        let err = PhysicalDisk::open(31).err().unwrap();
        assert!(
            err.contains("not connected") || err.contains("administrator"),
            "{err}"
        );
    }
}
