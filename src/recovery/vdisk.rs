//! Opening a disk image as a drive: a raw image (a rescue image or any `dd` image) is
//! attached read-only through the Virtual Disk API, so Windows gives its volumes drive
//! letters and Explorer can browse them.
//!
//! Windows attaches only virtual disk files, so while the image is attached it carries a
//! 512-byte fixed-VHD footer at its end (Microsoft's "Virtual Hard Disk Image Format
//! Specification": a fixed VHD is the raw disk followed by that footer). Detaching cuts the
//! file back to the image's exact length. A footer this tool left behind, after a crash or a
//! power cut, is found by its creator mark and removed on the next open; a footer some
//! other program wrote (a real .vhd) is never touched. The footer of an image is the same
//! bytes every time, so a differencing disk made over it opens again later.
//!
//! The attachment lives only as long as its handle: when the process ends in any way,
//! Windows detaches the disk. While attached, the image is held open with read sharing
//! only, so nothing (a resumed rescue image included) can write to it.
use std::fs::File;
use std::io;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
    GetVolumePathNamesForVolumeNameW, FILE_SHARE_READ,
};
use windows_sys::Win32::Storage::Vhd::{
    AttachVirtualDisk, DetachVirtualDisk, GetVirtualDiskPhysicalPath, OpenVirtualDisk,
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY,
    ATTACH_VIRTUAL_DISK_PARAMETERS, ATTACH_VIRTUAL_DISK_VERSION_1, DETACH_VIRTUAL_DISK_FLAG_NONE,
    OPEN_VIRTUAL_DISK_FLAG_NONE, OPEN_VIRTUAL_DISK_PARAMETERS, OPEN_VIRTUAL_DISK_VERSION_2,
    VIRTUAL_DISK_ACCESS_NONE, VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
    VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
};

use super::pending::Pending;
use super::timed::{Duty, Job, DUTIES};
use crate::tools::drives::bytes_text;

/// The footer's length, and where it sits: the last 512 bytes of the file.
pub const FOOTER: u64 = 512;
/// The largest disk a VHD can describe: 2040 GiB.
pub const MAX_VHD: u64 = 2040 << 30;
const COOKIE: &[u8; 8] = b"conectix";
/// The creator mark of a footer this tool wrote. Only these are ever removed.
const CREATOR: &[u8; 4] = b"dtol";
/// Seconds from 1970-01-01 to 2000-01-01, the VHD time stamp's start.
const VHD_EPOCH: u64 = 946_684_800;
/// How long Windows may take to mount the volumes of a newly attached disk.
const MOUNT_WAIT: Duration = Duration::from_secs(8);

/// A fixed-VHD footer read back from a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Footer {
    pub current_size: u64,
    pub disk_type: u32,
    pub creator: [u8; 4],
}

impl Footer {
    /// A fixed disk's footer written by this tool.
    pub fn is_ours(&self) -> bool {
        &self.creator == CREATOR && self.disk_type == 2
    }
}

/// Cylinders, heads and sectors per track for a disk of `len` bytes, by the specification's
/// algorithm (appendix "CHS Calculation").
pub fn geometry(len: u64) -> (u16, u8, u8) {
    let mut total = len / 512;
    total = total.min(65535 * 16 * 255);
    let (sectors, heads, cylinder_times_heads);
    if total >= 65535 * 16 * 63 {
        sectors = 255;
        heads = 16;
        cylinder_times_heads = total / sectors;
    } else {
        let mut s = 17;
        let mut cth = total / s;
        let mut h = cth.div_ceil(1024).max(4);
        if cth >= h * 1024 || h > 16 {
            s = 31;
            h = 16;
            cth = total / s;
        }
        if cth >= h * 1024 {
            s = 63;
            h = 16;
            cth = total / s;
        }
        sectors = s;
        heads = h;
        cylinder_times_heads = cth;
    }
    let cylinders = cylinder_times_heads / heads;
    (cylinders as u16, heads as u8, sectors as u8)
}

fn checksum(footer: &[u8; 512]) -> u32 {
    let sum = footer
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .fold(0u32, |sum, (_, b)| sum.wrapping_add(u32::from(*b)));
    !sum
}

/// The fixed-VHD footer for a raw image of `len` bytes. `stamp` (seconds since 2000) and
/// `id` come from the image file itself, so the same image always gets the same footer.
pub fn footer_for(len: u64, stamp: u32, id: [u8; 16]) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[0..8].copy_from_slice(COOKIE);
    f[8..12].copy_from_slice(&2u32.to_be_bytes()); // features: reserved bit
    f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // format version 1.0
    f[16..24].copy_from_slice(&u64::MAX.to_be_bytes()); // data offset: none, a fixed disk
    f[24..28].copy_from_slice(&stamp.to_be_bytes());
    f[28..32].copy_from_slice(CREATOR);
    f[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    f[36..40].copy_from_slice(b"Wi2k");
    f[40..48].copy_from_slice(&len.to_be_bytes()); // original size
    f[48..56].copy_from_slice(&len.to_be_bytes()); // current size
    let (c, h, s) = geometry(len);
    f[56..58].copy_from_slice(&c.to_be_bytes());
    f[58] = h;
    f[59] = s;
    f[60..64].copy_from_slice(&2u32.to_be_bytes()); // disk type: fixed
    f[68..84].copy_from_slice(&id);
    let sum = checksum(&f);
    f[64..68].copy_from_slice(&sum.to_be_bytes());
    f
}

/// Reads a footer: the cookie and the checksum must match.
pub fn parse_footer(f: &[u8; 512]) -> Option<Footer> {
    if &f[0..8] != COOKIE {
        return None;
    }
    let stored = u32::from_be_bytes(f[64..68].try_into().ok()?);
    if stored != checksum(f) {
        return None;
    }
    Some(Footer {
        current_size: u64::from_be_bytes(f[48..56].try_into().ok()?),
        disk_type: u32::from_be_bytes(f[60..64].try_into().ok()?),
        creator: f[28..32].try_into().ok()?,
    })
}

/// The fixed-VHD footer at the end of `file`, when there is one that describes exactly the
/// bytes before it.
pub fn trailing_footer(file: &File) -> io::Result<Option<Footer>> {
    let len = file.metadata()?.len();
    if len < 2 * FOOTER || !len.is_multiple_of(512) {
        return Ok(None);
    }
    let mut tail = [0u8; 512];
    let mut done = 0;
    while done < tail.len() {
        match file.seek_read(&mut tail[done..], len - FOOTER + done as u64)? {
            0 => return Ok(None),
            n => done += n,
        }
    }
    Ok(parse_footer(&tail)
        .filter(|footer| footer.disk_type == 2 && footer.current_size == len - FOOTER))
}

/// Whether a file is a differencing VHD, such as a kept repaired copy: a dynamic VHD keeps
/// a copy of its footer in its first 512 bytes, with disk type 4.
pub fn is_differencing(path: &Path) -> bool {
    let mut head = [0u8; 512];
    File::open(path)
        .and_then(|f| f.seek_read(&mut head, 0))
        .is_ok_and(|n| n == 512)
        && parse_footer(&head).is_some_and(|f| f.disk_type == 4)
}

/// The disk's own length inside a file that may end with a fixed-VHD footer: a real fixed
/// VHD, or a raw image that still carries this tool's footer. Readers use it so the footer
/// is never read as disk data.
pub fn data_len(file: &File) -> io::Result<u64> {
    let len = file.metadata()?.len();
    Ok(match trailing_footer(file)? {
        Some(footer) => footer.current_size,
        None => len,
    })
}

/// Removes the footer this tool left on an image of `len` bytes, if it is there: a resumed
/// rescue image calls this on its write handle. Another program's footer, or a file of
/// any other length, is left as it is. True when a footer was removed.
pub fn strip_left_footer(file: &File, len: u64) -> io::Result<bool> {
    match trailing_footer(file)? {
        Some(footer) if footer.is_ours() && footer.current_size == len => {
            file.set_len(len)?;
            file.sync_all()?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// The image's own length when `file` ends in exactly the footer this tool writes for it,
/// byte for byte: one an earlier run left behind. None when it does not, or it cannot be
/// read.
pub fn own_footer(file: &File) -> Option<u64> {
    let len = file.metadata().ok()?.len();
    let footer = trailing_footer(file).ok()??;
    let mut tail = [0u8; 512];
    let read = file.seek_read(&mut tail, len - FOOTER).ok()?;
    let (stamp, id) = identity_of(file, footer.current_size);
    (read == tail.len() && tail == footer_for(footer.current_size, stamp, id))
        .then_some(footer.current_size)
}

/// The footer's time stamp and unique id for an image, from its creation time and length.
fn identity_of(file: &File, len: u64) -> (u32, [u8; 16]) {
    let created = file
        .metadata()
        .and_then(|m| m.created())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let nanos = created
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seconds = (nanos / 1_000_000_000) as u64;
    let stamp = seconds.saturating_sub(VHD_EPOCH).min(u64::from(u32::MAX)) as u32;
    let mut seed = b"diagtool vhd footer".to_vec();
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&len.to_le_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA256, &seed);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest.as_ref()[..16]);
    // A version 4 style UUID, so tools that check its form accept it.
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    (stamp, id)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// "Windows error 1234" with Windows' own words for it, for people.
pub fn error_text(code: u32) -> String {
    let words = io::Error::from_raw_os_error(code as i32).to_string();
    let words = words.split(" (os error").next().unwrap_or("").trim();
    if words.is_empty() {
        format!("Windows error {code}")
    } else {
        format!("{words} (Windows error {code})")
    }
}

/// A virtual disk handle, closed on drop. Closing the last handle of a disk attached
/// without a permanent lifetime detaches it.
pub(crate) struct DiskHandle(pub(crate) HANDLE);

// SAFETY: a kernel handle may be used from any thread.
unsafe impl Send for DiskHandle {}

impl Drop for DiskHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful OpenVirtualDisk or CreateVirtualDisk.
        unsafe { CloseHandle(self.0) };
    }
}

/// The disk number Windows gave an attached virtual disk.
pub(crate) fn physical_disk(handle: &DiskHandle) -> Result<u32, String> {
    let mut buffer = vec![0u16; 300];
    let mut size = (buffer.len() * 2) as u32;
    // SAFETY: the buffer is writable for `size` bytes.
    let error = unsafe { GetVirtualDiskPhysicalPath(handle.0, &mut size, buffer.as_mut_ptr()) };
    if error != 0 {
        return Err(format!(
            "Windows did not say which disk it attached: {}",
            error_text(error)
        ));
    }
    disk_number_of(&from_wide(&buffer))
        .ok_or_else(|| "Windows named the attached disk in a form this tool does not read".into())
}

/// 5 from "\\.\PhysicalDrive5".
pub fn disk_number_of(path: &str) -> Option<u32> {
    let lower = path.to_ascii_lowercase();
    let at = lower.find("physicaldrive")?;
    path[at + "physicaldrive".len()..].trim().parse().ok()
}

/// What happened to the footer when an image was attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FooterUse {
    /// This tool appended it and removes it on detach.
    Added,
    /// It was already there, left by an earlier run of this tool; removed on detach.
    LeftOver,
    /// The file is a real fixed VHD; its footer is its own and stays.
    Own,
}

/// An image carrying its footer, held open with read sharing only so nothing writes to it.
/// Dropping it removes the footer this tool put there.
pub struct Footed {
    hold: Option<File>,
    due: Arc<Due>,
    pub image: PathBuf,
    /// The image's own length, without any footer.
    pub image_len: u64,
    /// What was found and done when the footer was put on.
    pub footer: FooterUse,
}

/// Where this tool's footer on an image stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// On the image, not yet asked to come off.
    On,
    /// Off, or never this tool's to take off.
    Off,
    /// A Windows call that may still have the image open outlived the attempt: it comes off
    /// when the last such call ends.
    Waiting,
    /// It could not come off and nothing holds the image any more: the next open removes it.
    Left,
}

/// The footer's removal, shared by the image's holder (`Footed`) and every Windows call that
/// may have the image open (`FootHold`), so it stays due until the last of them ends: one
/// that ends after its caller gave up takes the footer off as Windows lets the image go.
struct Due {
    image: PathBuf,
    len: u64,
    stage: Mutex<Stage>,
    /// Counted while the footer is this tool's to take off (`timed::Duties::holder`), so the
    /// process's end waits for it and the next start settles it if the end comes first.
    duty: Mutex<Option<Duty>>,
}

/// How long taking the footer off takes once Windows has let the image go: 20 tries 100 ms
/// apart (`remove_footer_patiently`), with the writes.
pub(crate) const FOOTER_UNDO: Duration = Duration::from_secs(5);

/// The longest the process's end waits for the virtual disk service to answer an attach,
/// a detach or the making of a copy: past the 180 s a first detach was measured to be held
/// (6 of 6 cold runs, 2026-11-07).
pub(crate) const VDISK_ANSWER: Duration = Duration::from_secs(240);

impl Drop for Due {
    /// The last holder was a call that kept the image past the holder's attempt: the footer
    /// comes off now, and the change record says so, as the holder said it would.
    fn drop(&mut self) {
        let stage = *self.stage.get_mut().unwrap_or_else(PoisonError::into_inner);
        if !matches!(stage, Stage::Waiting | Stage::On) {
            return;
        }
        let duty = self
            .duty
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let text = match remove_footer_patiently(&self.image, self.len) {
            Ok(()) => format!(
                "The footer this tool put on {} was taken off once Windows let the image go.",
                self.image.display()
            ),
            Err(last) => {
                // Still on: the next start, or the next open, takes it off.
                if let Some(duty) = duty {
                    duty.leave();
                }
                format!(
                    "{last}. The footer is removed when the recovery window next starts, or the next time {} is opened here.",
                    self.image.display()
                )
            }
        };
        crate::handles::record_unseen("Open an image as a drive", &text);
    }
}

/// Takes off a footer a recovery window left on `image` (`len` its own length) when it
/// ended, as the next one starts, by compare-and-swap on one handle: the image is opened
/// with read sharing only, so nothing else writes to it meanwhile, its last 512 bytes must
/// be exactly the footer this tool writes for an image of `len` bytes, and that same handle
/// cuts them off. Anything else is left as it is. Err when it could not be checked, to be
/// tried again at the next start.
pub(crate) fn settle_footer(image: &Path, len: u64) -> Result<String, String> {
    let file = match open_for_footer(image) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(format!("{} is no longer there.", image.display()))
        }
        Err(e) => {
            return Err(format!(
                "The footer on {} could not be checked ({e}); it is tried again at the next start.",
                image.display()
            ))
        }
    };
    if own_footer(&file) != Some(len) {
        return Ok(format!(
            "{} no longer ends in the footer this tool put on it, so it was left as it is.",
            image.display()
        ));
    }
    match file.set_len(len).and_then(|()| file.sync_all()) {
        Ok(()) => Ok(format!(
            "The footer this tool put on {} was taken off.",
            image.display()
        )),
        Err(e) => Err(format!(
            "The footer this tool put on {} is still on ({e}); it is tried again at the next start.",
            image.display()
        )),
    }
}

/// Keeps an image's footer due while a Windows call that may have the image open runs: the
/// call's thread carries it to the call's real end, past any time limit.
pub(crate) struct FootHold {
    due: Arc<Due>,
}

impl FootHold {
    /// The footer is left for the next start to take off, and the end of this process does
    /// not wait for it: for an image something holds until the process ends.
    pub(crate) fn leave_to_next_start(&self) {
        let duty = self
            .due
            .duty
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(duty) = duty {
            duty.leave();
        }
    }
}

/// Removes this tool's footer, retrying while Windows still holds the file a moment after a
/// detach.
fn remove_footer_patiently(image: &Path, len: u64) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..20 {
        match remove_footer(image, len) {
            Ok(_) => return Ok(()),
            Err(why) => last = why,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

impl Footed {
    /// Puts the footer on an image, or finds the one there, and holds the image. An image
    /// Windows will not attach as it is stored (sparse, compressed) is refused before
    /// anything is written; `plain_needed` says why and `make_plain` changes it.
    pub fn put_on(path: &Path) -> Result<Self, String> {
        if let Some(why) = plain_needed(path)? {
            return Err(why.text);
        }
        let (footer, image_len) = prepare(path)?;
        let stage = if footer == FooterUse::Own {
            Stage::Off
        } else {
            Stage::On
        };
        let duty = (stage == Stage::On).then(|| {
            DUTIES.holder(
                &format!("taking the footer off {}", path.display()),
                VDISK_ANSWER + FOOTER_UNDO,
                Pending::Footer {
                    image: path.to_path_buf(),
                    len: image_len,
                },
            )
        });
        let mut footed = Self {
            hold: None,
            due: Arc::new(Due {
                image: path.to_path_buf(),
                len: image_len,
                stage: Mutex::new(stage),
                duty: Mutex::new(duty),
            }),
            image: path.to_path_buf(),
            image_len,
            footer,
        };
        match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
        {
            Ok(hold) => footed.hold = Some(hold),
            Err(e) => {
                let why = format!("{} could not be held open: {e}", path.display());
                return Err(match footed.take_off() {
                    Ok(()) => why,
                    Err(more) => format!("{why} {more}"),
                });
            }
        }
        Ok(footed)
    }

    /// What a Windows call that may open the image carries to its end (attach, detach,
    /// making a copy over it), so the footer stays due until that call has really ended.
    pub(crate) fn keep(&self) -> FootHold {
        FootHold {
            due: self.due.clone(),
        }
    }

    /// Lets the image go and removes this tool's footer. Err says why it is still on: it
    /// comes off when a Windows call still holding the image ends, or else on the next open.
    pub fn take_off(&mut self) -> Result<(), String> {
        drop(self.hold.take());
        let mut stage = self
            .due
            .stage
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *stage == Stage::Off {
            return Ok(());
        }
        match remove_footer_patiently(&self.image, self.image_len) {
            Ok(()) => {
                *stage = Stage::Off;
                drop(
                    self.due
                        .duty
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take(),
                );
                Ok(())
            }
            Err(last) if Arc::strong_count(&self.due) > 1 => {
                *stage = Stage::Waiting;
                Err(format!(
                    "{last}. Windows has not let the image go yet; the footer is taken off as soon as it does, and the session's change record says so."
                ))
            }
            Err(last) => {
                *stage = Stage::Left;
                // Nothing holds the image: the next start settles it from the journal.
                let duty = self
                    .due
                    .duty
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(duty) = duty {
                    duty.leave();
                }
                Err(format!(
                    "{last}. The footer is removed when the recovery window next starts, or the next time the image is opened here."
                ))
            }
        }
    }
}

impl Drop for Footed {
    /// A footer never asked to come off is taken off here, and a failure is recorded where
    /// it is seen later, since no window is left to say it. One already asked about was said
    /// then; one a Windows call still holds comes off when that call ends.
    fn drop(&mut self) {
        drop(self.hold.take());
        let untried = *self
            .due
            .stage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            == Stage::On;
        if untried {
            if let Err(why) = self.take_off() {
                crate::handles::record_unseen("Open an image as a drive", &why);
            }
        }
    }
}

/// An image attached read-only. Dropping it detaches the disk and removes the footer.
pub struct Attached {
    handle: Option<DiskHandle>,
    pub footed: Footed,
    pub disk: u32,
}

/// Opens `path` for the footer's write with read sharing only: nobody else may write to it
/// meanwhile, and it fails while the image is attached or being written.
fn open_for_footer(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Checks that an image can be attached as a fixed VHD, from its length. A file that
/// already ends in a fixed-VHD footer is measured without it.
pub fn check_attachable(len: u64) -> Result<(), String> {
    if len == 0 {
        return Err("the image is empty".into());
    }
    if !len.is_multiple_of(512) {
        return Err(format!(
            "the image is {} long, not a whole number of 512-byte sectors, so Windows cannot attach it",
            bytes_text(len)
        ));
    }
    if len > MAX_VHD {
        return Err(format!(
            "the image is {}, and Windows attaches an image this way only up to {}",
            bytes_text(len),
            bytes_text(MAX_VHD)
        ));
    }
    Ok(())
}

/// Puts the footer on an image (or finds the one there) and returns its use and the
/// image's own length. Nothing but the 512 bytes past the image's end is written.
fn prepare(path: &Path) -> Result<(FooterUse, u64), String> {
    let file = open_for_footer(path).map_err(|e| {
        format!(
            "{} could not be opened to attach it (is it open in another program, or still being written?): {e}",
            path.display()
        )
    })?;
    let what = |e: io::Error| format!("{} could not be read: {e}", path.display());
    let len = file.metadata().map_err(what)?.len();
    if let Some(footer) = trailing_footer(&file).map_err(what)? {
        check_attachable(footer.current_size)?;
        if !footer.is_ours() {
            return Ok((FooterUse::Own, footer.current_size));
        }
        // Left by an earlier run; it is rewritten so its bytes are this image's.
        let (stamp, id) = identity_of(&file, footer.current_size);
        let bytes = footer_for(footer.current_size, stamp, id);
        file.seek_write(&bytes, footer.current_size)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("{} could not be prepared: {e}", path.display()))?;
        return Ok((FooterUse::LeftOver, footer.current_size));
    }
    check_attachable(len)?;
    let (stamp, id) = identity_of(&file, len);
    let bytes = footer_for(len, stamp, id);
    let written = super::write_all_at(&mut &file, &bytes, len).and_then(|_| file.sync_all());
    if let Err(e) = written {
        // Never leave a partial footer behind; one that could not be cut off is said.
        let cut = match file.set_len(len) {
            Ok(()) => String::new(),
            Err(c) => format!(
                ", and the {} bytes written after the image could not be cut off again ({c}); \
                 they are removed the next time the image is opened here",
                FOOTER
            ),
        };
        return Err(format!(
            "{} could not be prepared for attaching: {e}{cut}",
            path.display()
        ));
    }
    Ok((FooterUse::Added, len))
}

impl super::Sink for &File {
    fn write_at(&mut self, data: &[u8], pos: u64) -> io::Result<usize> {
        self.seek_write(data, pos)
    }

    fn flush_data(&mut self) -> io::Result<()> {
        self.sync_data()
    }
}

/// Removes this tool's footer from an image of `len` bytes. Ok(false) when none was there.
pub fn remove_footer(path: &Path, len: u64) -> Result<bool, String> {
    let file = open_for_footer(path)
        .map_err(|e| format!("{} could not be opened: {e}", path.display()))?;
    strip_left_footer(&file, len).map_err(|e| {
        format!(
            "the footer could not be removed from {}: {e}",
            path.display()
        )
    })
}

/// Why an image must be changed before Windows attaches it, and the room that takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainNeeded {
    pub text: String,
    /// Bytes more the image will take on its drive once plain.
    pub more: u64,
    /// Whether this tool can change it (an encrypted file it cannot).
    pub fixable: bool,
}

const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

/// Bytes the file takes on its drive now.
fn allocated(path: &Path) -> u64 {
    use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;
    let name = wide(&path.to_string_lossy());
    let mut high = 0u32;
    // SAFETY: `name` is NUL-terminated and `high` writable.
    let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
    if low == u32::MAX {
        return 0;
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Windows attaches only image files that are not sparse, compressed or encrypted. A rescue
/// image is sparse, so its unread areas take no room. None when the image can be attached
/// as it is.
pub fn plain_needed(path: &Path) -> Result<Option<PlainNeeded>, String> {
    use std::os::windows::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
    let attributes = meta.file_attributes();
    if attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
        return Ok(Some(PlainNeeded {
            text: format!("{} is encrypted with Windows file encryption, and Windows attaches only unencrypted images. Copy it to a folder that is not encrypted, as the account that encrypted it, and open the copy.", path.display()),
            more: 0,
            fixable: false,
        }));
    }
    let mut kinds = Vec::new();
    if attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
        kinds.push("sparse (areas never written take no room)");
    }
    if attributes & FILE_ATTRIBUTE_COMPRESSED != 0 {
        kinds.push("compressed");
    }
    if kinds.is_empty() {
        return Ok(None);
    }
    let more = meta.len().saturating_sub(allocated(path));
    Ok(Some(PlainNeeded {
        text: format!(
            "{} is stored {}, and Windows attaches only images stored as plain files. Making it plain keeps every byte of it as it is and takes {} more on its drive.",
            path.display(),
            kinds.join(" and "),
            bytes_text(more)
        ),
        more,
        fixable: true,
    }))
}

/// Stores an image as a plain file: not compressed, not sparse. Its contents do not
/// change. Refused when its drive has not the room. Can take minutes for a large image.
pub fn make_plain(path: &Path) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::{FSCTL_SET_COMPRESSION, FSCTL_SET_SPARSE};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let Some(needed) = plain_needed(path)? else {
        return Ok(());
    };
    if !needed.fixable {
        return Err(needed.text);
    }
    let folder = path.parent().unwrap_or(path);
    let (free, _) = super::image::space_of(folder)?;
    // A margin for the file system's own records.
    if free < needed.more + (64 << 20) {
        return Err(format!(
            "{} needs {} more to be stored plain, and its drive has {} free.",
            path.display(),
            bytes_text(needed.more),
            bytes_text(free)
        ));
    }
    let file = open_for_footer(path)
        .map_err(|e| format!("{} could not be opened: {e}", path.display()))?;
    let control = |code: u32, input: &[u8]| -> io::Result<()> {
        let mut returned = 0u32;
        // SAFETY: the handle is open and the input buffer valid for its length.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    use std::os::windows::fs::MetadataExt;
    let attributes = file.metadata().map(|m| m.file_attributes()).unwrap_or(0);
    if attributes & FILE_ATTRIBUTE_COMPRESSED != 0 {
        // COMPRESSION_FORMAT_NONE.
        control(FSCTL_SET_COMPRESSION, &0u16.to_le_bytes())
            .map_err(|e| format!("{} could not be uncompressed: {e}", path.display()))?;
    }
    if attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
        // FILE_SET_SPARSE_BUFFER with SetSparse FALSE.
        control(FSCTL_SET_SPARSE, &[0u8])
            .map_err(|e| format!("{} could not be made a plain file: {e}", path.display()))?;
    }
    file.sync_all()
        .map_err(|e| format!("{} could not be saved: {e}", path.display()))?;
    match plain_needed(path)? {
        None => Ok(()),
        Some(still) => Err(still.text),
    }
}

pub(crate) fn storage_type(device: u32) -> VIRTUAL_STORAGE_TYPE {
    VIRTUAL_STORAGE_TYPE {
        DeviceId: device,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    }
}

/// Opens a virtual disk file, read-only or not.
pub(crate) fn open_disk(path: &Path, device: u32, read_only: bool) -> Result<DiskHandle, u32> {
    let mut params = OPEN_VIRTUAL_DISK_PARAMETERS {
        Version: OPEN_VIRTUAL_DISK_VERSION_2,
        ..Default::default()
    };
    params.Anonymous.Version2.ReadOnly = i32::from(read_only);
    let kind = storage_type(device);
    let name = wide(&path.to_string_lossy());
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; the handle is written on success.
    let error = unsafe {
        OpenVirtualDisk(
            &kind,
            name.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            &params,
            &mut handle,
        )
    };
    if error != 0 {
        return Err(error);
    }
    Ok(DiskHandle(handle))
}

/// How long attaching or detaching a virtual disk may take.
pub const ATTACH_LIMIT: Duration = Duration::from_secs(60);

/// Why an attach or a detach did not succeed: Windows' error code, or no answer within
/// `ATTACH_LIMIT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unanswered {
    Code(u32),
    NoAnswer,
}

impl Unanswered {
    /// For people, with what was being done.
    pub(crate) fn text(self, what: &str) -> String {
        match self {
            Unanswered::Code(code) => error_text(code),
            Unanswered::NoAnswer => format!(
                "Windows did not finish {what} within {} s; it is undone once Windows answers, and the session's change record says so",
                ATTACH_LIMIT.as_secs()
            ),
        }
    }
}

/// Attaches an opened virtual disk for the handle's lifetime, read-only or read-write,
/// within `ATTACH_LIMIT` (`timed::owned`). The handle travels with the call: an attach that
/// ends after the limit is detached again at once and recorded, never left attached with
/// no one holding it. So does `footed`'s footer, which stays due until the call has ended.
pub(crate) fn attach(
    handle: DiskHandle,
    read_only: bool,
    image: &Path,
    footed: &Footed,
) -> Result<DiskHandle, Unanswered> {
    let job = Job::new(format!("attaching {}", image.display()), ATTACH_LIMIT)
        .answered_within(VDISK_ANSWER)
        // A late attach is detached again at once, and the footer then comes off.
        .undone_within(VDISK_ANSWER + FOOTER_UNDO);
    let image = image.to_path_buf();
    let keep = footed.keep();
    match super::timed::owned(
        job,
        None,
        move || {
            let attached = attach_now(&handle, read_only);
            (handle, attached, keep)
        },
        move |(handle, attached, keep): (DiskHandle, Result<(), u32>, FootHold)| {
            if attached.is_err() {
                return;
            }
            let detached = detach_now(&handle);
            // Closing the handle detaches it in any case: its lifetime is the handle's.
            drop(handle);
            crate::handles::record_unseen(
                "Open an image as a drive",
                &match detached {
                    Ok(()) => format!(
                        "{} was attached after its time limit, so it was detached again.",
                        image.display()
                    ),
                    Err(code) => format!(
                        "{} was attached after its time limit; detaching it reported {}, and closing its handle let it go.",
                        image.display(),
                        error_text(code)
                    ),
                },
            );
            // Windows has let the image go: a footer still due comes off now.
            drop(keep);
        },
    ) {
        super::timed::Waited::Done((handle, Ok(()), _)) => Ok(handle),
        super::timed::Waited::Done((_, Err(code), _)) => Err(Unanswered::Code(code)),
        _ => Err(Unanswered::NoAnswer),
    }
}

/// Detaches a virtual disk and closes its handle, within `ATTACH_LIMIT`. A detach that
/// ends after the limit is recorded; closing the handle at its end detaches it anyway, and
/// `footed`'s footer, due until then, comes off as Windows lets the image go.
pub(crate) fn detach(handle: DiskHandle, image: &Path, footed: &Footed) -> Result<(), Unanswered> {
    detach_holding(handle, image, footed, ())
}

/// `detach`, with what the detach needs held until Windows has let the disk go: `held`
/// travels with the job and is let go only once the detach has returned, also when that is
/// after its caller gave up (a repair's closed volumes, so a late detach never finds them
/// mounted again).
pub(crate) fn detach_holding<H: Send + 'static>(
    handle: DiskHandle,
    image: &Path,
    footed: &Footed,
    held: H,
) -> Result<(), Unanswered> {
    let job = Job::new(format!("detaching {}", image.display()), ATTACH_LIMIT)
        .answered_within(VDISK_ANSWER)
        .undone_within(FOOTER_UNDO);
    let image = image.to_path_buf();
    let keep = footed.keep();
    match super::timed::owned(
        job,
        None,
        move || {
            let detached = detach_now(&handle);
            drop(handle);
            drop(held);
            (detached, keep)
        },
        move |(late, keep): (Result<(), u32>, FootHold)| {
            crate::handles::record_unseen(
                "Open an image as a drive",
                &match late {
                    Ok(()) => format!("{} was detached after its time limit.", image.display()),
                    Err(code) => format!(
                        "Detaching {} after its time limit reported {}; closing its handle let it go.",
                        image.display(),
                        error_text(code)
                    ),
                },
            );
            drop(keep);
        },
    ) {
        super::timed::Waited::Done((Ok(()), _)) => Ok(()),
        super::timed::Waited::Done((Err(code), _)) => Err(Unanswered::Code(code)),
        _ => Err(Unanswered::NoAnswer),
    }
}

/// AttachVirtualDisk itself; called only through `attach`. A read-only disk gets drive
/// letters, for Explorer. A writable one (a repair's copy) gets none, for any volume it ever
/// shows: Windows Search takes up a lettered volume and writes to it while it is repaired;
/// chkdsk reaches the copy's volumes by their GUID paths.
fn attach_now(handle: &DiskHandle, read_only: bool) -> Result<(), u32> {
    let params = ATTACH_VIRTUAL_DISK_PARAMETERS {
        Version: ATTACH_VIRTUAL_DISK_VERSION_1,
        ..Default::default()
    };
    let flags = if read_only {
        ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
    } else {
        ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER
    };
    // SAFETY: the handle is open; no security descriptor or overlapped is passed.
    let error = unsafe {
        AttachVirtualDisk(
            handle.0,
            std::ptr::null_mut(),
            flags,
            0,
            &params,
            std::ptr::null(),
        )
    };
    if error != 0 {
        Err(error)
    } else {
        Ok(())
    }
}

/// DetachVirtualDisk itself; called only through `attach` and `detach`.
fn detach_now(handle: &DiskHandle) -> Result<(), u32> {
    // SAFETY: the handle is open.
    let error = unsafe { DetachVirtualDisk(handle.0, DETACH_VIRTUAL_DISK_FLAG_NONE, 0) };
    if error != 0 {
        Err(error)
    } else {
        Ok(())
    }
}

/// Why Windows refused to attach, in plain words where the cause is known.
fn attach_refusal(path: &Path, code: u32) -> String {
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
    // ERROR_VIRTDISK_UNSUPPORTED... and the file system limits Windows names for a VHD.
    const ERROR_NOT_SUPPORTED: u32 = 50;
    match code {
        ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD => {
            "Attaching an image needs administrator rights; open the recovery window with the Recovery button in the drive window.".into()
        }
        ERROR_NOT_SUPPORTED => format!(
            "Windows cannot attach {} where it is stored: {}. Copy the image to an NTFS drive and open the copy.",
            path.display(),
            error_text(code)
        ),
        other => format!(
            "Windows did not attach {}: {}",
            path.display(),
            error_text(other)
        ),
    }
}

impl Attached {
    /// Attaches the image at `path` read-only: puts the footer on, opens it as a VHD and
    /// attaches it. On any failure the footer it added is taken off again.
    pub fn open(path: &Path) -> Result<Self, String> {
        let footed = Footed::put_on(path)?;
        let handle = open_disk(path, VIRTUAL_STORAGE_TYPE_DEVICE_VHD, true)
            .map_err(|code| attach_refusal(path, code))?;
        let handle = attach(handle, true, path, &footed).map_err(|e| match e {
            Unanswered::Code(code) => attach_refusal(path, code),
            no_answer => format!(
                "{} was not opened: {}.",
                path.display(),
                no_answer.text("attaching it")
            ),
        })?;
        let disk = match physical_disk(&handle) {
            Ok(disk) => disk,
            Err(why) => {
                return Err(match detach(handle, path, &footed) {
                    Ok(()) => why,
                    Err(e) => format!("{why} Detaching it again: {}.", e.text("detaching it")),
                })
            }
        };
        Ok(Self {
            handle: Some(handle),
            footed,
            disk,
        })
    }

    /// A disk already attached read-only over `footed`, for the kept repaired copy.
    pub(crate) fn from_parts(handle: DiskHandle, footed: Footed, disk: u32) -> Self {
        Self {
            handle: Some(handle),
            footed,
            disk,
        }
    }

    pub fn image(&self) -> &Path {
        &self.footed.image
    }

    /// Detaches the disk and removes the footer, cutting the file back to the image's own
    /// length. Err says what could not be done; the footer is then removed on the next open.
    pub fn close(mut self) -> Result<(), String> {
        self.finish()
    }

    fn finish(&mut self) -> Result<(), String> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        if let Err(e) = detach(handle, &self.footed.image, &self.footed) {
            // Closing the handle detached it anyway: its lifetime is the handle's.
            let footer = match self.footed.take_off() {
                Ok(()) => String::new(),
                Err(why) => format!(" {why}"),
            };
            return Err(format!(
                "Windows reported an error detaching {}: {}.{footer}",
                self.footed.image.display(),
                e.text("detaching it")
            ));
        }
        self.footed.take_off()
    }
}

impl Drop for Attached {
    /// A detach or footer removal that failed with no window left to say it is recorded.
    fn drop(&mut self) {
        if let Err(why) = self.finish() {
            crate::handles::record_unseen("Open an image as a drive", &why);
        }
    }
}

/// One Windows volume on a disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// "\\?\Volume{guid}\".
    pub guid_path: String,
    pub disk: u32,
    /// Byte offset of the volume on its disk, and its length.
    pub offset: u64,
    pub len: u64,
    /// Where it is mounted: "E:\" and any folder mount points.
    pub mounts: Vec<String>,
    /// "NTFS", "FAT32"; empty when Windows does not recognise the file system (a locked
    /// BitLocker volume, a damaged one).
    pub file_system: String,
    pub label: String,
}

impl VolumeInfo {
    /// "E:" for the first drive letter.
    pub fn letter(&self) -> Option<String> {
        self.mounts
            .iter()
            .find(|m| m.len() == 3 && m.ends_with(":\\"))
            .map(|m| m[..2].to_string())
    }

    /// "E: (NTFS, Photos), 1.2 GB" for people.
    pub fn describe(&self) -> String {
        let place = self
            .letter()
            .unwrap_or_else(|| "No drive letter".to_string());
        let kind = match (self.file_system.as_str(), self.label.as_str()) {
            ("", _) => "file system not recognized".to_string(),
            (fs, "") => fs.to_string(),
            (fs, label) => format!("{fs}, {label}"),
        };
        format!("{place} ({kind}), {}", bytes_text(self.len))
    }
}

fn volume_mounts(guid_path: &str) -> Vec<String> {
    let name = wide(guid_path);
    let mut buffer = vec![0u16; 1024];
    let mut needed = 0u32;
    // SAFETY: the buffer is writable for its length.
    let ok = unsafe {
        GetVolumePathNamesForVolumeNameW(
            name.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Vec::new();
    }
    buffer
        .split(|c| *c == 0)
        .take_while(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

fn volume_names(guid_path: &str) -> (String, String) {
    let name = wide(guid_path);
    let mut label = vec![0u16; 261];
    let mut fs = vec![0u16; 64];
    // SAFETY: the buffers are writable for their lengths.
    let ok = unsafe {
        GetVolumeInformationW(
            name.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    };
    if ok == 0 {
        return (String::new(), String::new());
    }
    (from_wide(&fs), from_wide(&label))
}

/// Every Windows volume, by its GUID path.
fn all_volumes() -> Vec<String> {
    let mut names = Vec::new();
    let mut buffer = vec![0u16; 64];
    // SAFETY: the buffer is writable for its length.
    let find = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if find == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return names;
    }
    loop {
        names.push(from_wide(&buffer));
        // SAFETY: the find handle is open and the buffer writable.
        if unsafe { FindNextVolumeW(find, buffer.as_mut_ptr(), buffer.len() as u32) } == 0 {
            break;
        }
    }
    // SAFETY: closes the find handle once.
    unsafe { FindVolumeClose(find) };
    names
}

/// The volumes Windows has on disk `disk`, by their place on it.
pub fn volumes_of_disk(disk: u32) -> Vec<VolumeInfo> {
    let mut found = Vec::new();
    for guid_path in all_volumes() {
        let Ok(extents) = crate::tools::drives::device::volume_extents(&guid_path) else {
            continue;
        };
        let Some((_, offset, len)) = extents.iter().find(|(d, _, _)| *d == disk).copied() else {
            continue;
        };
        let (file_system, label) = volume_names(&guid_path);
        found.push(VolumeInfo {
            mounts: volume_mounts(&guid_path),
            guid_path,
            disk,
            offset,
            len,
            file_system,
            label,
        });
    }
    found.sort_by_key(|v| v.offset);
    found
}

/// Waits up to a few seconds for Windows to mount `disk`'s volumes and give them letters,
/// and returns them. A disk with no volume Windows reads returns what is there at the end.
pub fn wait_for_volumes(disk: u32) -> Vec<VolumeInfo> {
    let start = Instant::now();
    let mut last = Vec::new();
    let mut steady = 0;
    while start.elapsed() < MOUNT_WAIT {
        let now = volumes_of_disk(disk);
        let lettered = !now.is_empty() && now.iter().all(|v| !v.mounts.is_empty());
        if now == last && !now.is_empty() {
            steady += 1;
        } else {
            steady = 0;
        }
        last = now;
        if lettered || steady >= 4 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    last
}

// ---- the engine ----------------------------------------------------------------------------

/// What the drive engines (open as a drive, BitLocker, repair on a copy) report as they go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A step begins: "Attaching the image read-only".
    Phase { text: String },
    /// Work done out of a total, in the unit of the phase (bytes searched).
    Progress { done: u64, total: u64 },
    /// The item being worked on: a volume.
    Item { text: String },
    /// One line of a program's output (chkdsk).
    Line { text: String },
    /// Something that did not stop the work but should be known.
    Warning { text: String },
}

/// Options of Open an image as a drive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttachOptions {
    /// A raw disk image (a rescue image, any `dd` image), a fixed VHD, or a repaired copy
    /// kept by Repair on a copy (a differencing VHD, attached over its image). At most
    /// 2040 GiB and a whole number of 512-byte sectors.
    pub image: PathBuf,
    /// Confirms storing a sparse or compressed image as a plain file, which Windows needs:
    /// every byte stays as it is, it takes `PlainNeeded::more` more room, which must be
    /// free, and it can take minutes. Without it such an image is refused with the reason.
    #[serde(default)]
    pub make_plain: bool,
}

/// What Open an image as a drive did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttachResult {
    /// The disk number Windows gave the image while attached.
    pub disk: u32,
    /// The raw image carrying the footer: for a repaired copy, the image it was made over.
    pub image: PathBuf,
    /// The image's own length; the file is cut back to it on detach.
    pub image_len: u64,
    pub footer: FooterUse,
    /// The repaired copy attached over `image`, when one was opened.
    pub copy: Option<PathBuf>,
    /// The image was stored as a plain file first.
    pub made_plain: bool,
    pub volumes: Vec<VolumeInfo>,
    /// "E:" and so on, the drive letters that appeared.
    pub letters: Vec<String>,
    /// Byte offsets of the volumes whose boot sector is BitLocker's.
    pub bitlocker: Vec<u64>,
}

/// Opens an image as a drive, read-only. Returns the attachment, which detaches and takes
/// the footer off when closed or dropped, and what it did.
pub fn attach_image(
    options: &AttachOptions,
    events: &dyn Fn(Event),
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(Attached, AttachResult), String> {
    use std::sync::atomic::Ordering;
    let path = &options.image;
    let copy = is_differencing(path);
    let mut made_plain = false;
    if !copy {
        if let Some(needed) = plain_needed(path)? {
            if !needed.fixable || !options.make_plain {
                return Err(needed.text);
            }
            events(Event::Phase {
                text: "Storing the image as a plain file".into(),
            });
            make_plain(path)?;
            made_plain = true;
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("Stopped before the image was attached.".into());
    }
    events(Event::Phase {
        text: "Attaching the image read-only".into(),
    });
    let attached = if copy {
        super::repair::open_kept(path)?
    } else {
        Attached::open(path)?
    };
    events(Event::Phase {
        text: "Waiting for Windows to mount its volumes".into(),
    });
    let volumes = wait_for_volumes(attached.disk);
    let bitlocker =
        super::bitlocker::bitlocker_offsets(attached.disk, &volumes).unwrap_or_else(|why| {
            events(Event::Warning {
                text: format!("BitLocker volumes could not be looked for: {why}"),
            });
            Vec::new()
        });
    let result = AttachResult {
        disk: attached.disk,
        image: attached.footed.image.clone(),
        image_len: attached.footed.image_len,
        footer: attached.footed.footer,
        copy: copy.then(|| path.clone()),
        made_plain,
        letters: volumes.iter().filter_map(VolumeInfo::letter).collect(),
        volumes,
        bitlocker,
    };
    Ok((attached, result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("diagtool-vdisk-{}-{name}", std::process::id()))
    }

    /// A 64 MiB disk gets 17 sectors per track and 8 heads; just under 65535 x 16 x 63
    /// sectors, 63 sectors; from there on, and at the 2040 GiB limit, 255 sectors and 16
    /// heads.
    #[test]
    fn geometry_follows_the_specification() {
        assert_eq!(geometry(64 << 20), (963, 8, 17));
        let edge = 65535 * 16 * 63 * 512;
        assert_eq!(geometry(edge - 512), (65534, 16, 63));
        assert_eq!(geometry(edge), (16191, 16, 255));
        let (c, h, s) = geometry(MAX_VHD);
        assert_eq!((h, s), (16, 255));
        assert_eq!(c, 65535);
    }

    #[test]
    fn a_footer_reads_back_and_its_checksum_guards_it() {
        let footer = footer_for(1 << 30, 12345, [7; 16]);
        assert_eq!(&footer[0..8], b"conectix");
        let parsed = parse_footer(&footer).unwrap();
        assert_eq!(parsed.current_size, 1 << 30);
        assert!(parsed.is_ours());
        let mut broken = footer;
        broken[100] ^= 1;
        assert_eq!(parse_footer(&broken), None);
        let mut other = footer;
        other[28..32].copy_from_slice(b"win ");
        let sum = checksum(&other);
        other[64..68].copy_from_slice(&sum.to_be_bytes());
        assert!(!parse_footer(&other).unwrap().is_ours());
    }

    /// The guard: only this tool's own footer is ever removed, only from an image of the
    /// length it describes, and the image's bytes are left as they were.
    #[test]
    fn only_this_tools_footer_is_removed_and_the_image_is_kept_whole() {
        let path = temp("strip.img");
        let image: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut with_ours = image.clone();
        with_ours.extend_from_slice(&footer_for(4096, 1, [1; 16]));
        std::fs::write(&path, &with_ours).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(data_len(&file).unwrap(), 4096);
        // A different length is not this footer's image.
        assert!(!strip_left_footer(&file, 4608).unwrap());
        assert!(strip_left_footer(&file, 4096).unwrap());
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), image);
        // Another program's footer stays.
        let mut theirs = footer_for(4096, 1, [1; 16]);
        theirs[28..32].copy_from_slice(b"win ");
        let sum = checksum(&theirs);
        theirs[64..68].copy_from_slice(&sum.to_be_bytes());
        let mut with_theirs = image.clone();
        with_theirs.extend_from_slice(&theirs);
        std::fs::write(&path, &with_theirs).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(!strip_left_footer(&file, 4096).unwrap());
        assert_eq!(data_len(&file).unwrap(), 4096);
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), with_theirs);
        std::fs::remove_file(&path).unwrap();
    }

    /// The guard: a Windows call that still has the image open after its caller gave up
    /// keeps the footer due, and the footer comes off when that call ends, so the image is
    /// left as it was instead of to the next open.
    #[test]
    fn a_footer_a_late_call_still_holds_comes_off_when_the_call_ends() {
        use std::sync::mpsc;
        let path = temp("late.img");
        let image: Vec<u8> = (0..8192u32).map(|i| (i % 249) as u8).collect();
        std::fs::write(&path, &image).unwrap();
        let mut footed = Footed::put_on(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8192 + FOOTER);
        let (held, is_held) = mpsc::channel();
        let (go, let_go) = mpsc::channel::<()>();
        let (ended, has_ended) = mpsc::channel();
        let keep = footed.keep();
        let windows = path.clone();
        // Windows' side: the image open, as an attached disk's is, past the caller's limit.
        let waited = super::super::timed::owned(
            Job::new("holding the image open", Duration::from_millis(50)),
            None,
            move || {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ)
                    .open(&windows)
                    .unwrap();
                held.send(()).unwrap();
                let_go.recv().unwrap();
                drop(file);
                keep
            },
            move |keep: FootHold| {
                drop(keep);
                ended.send(()).unwrap();
            },
        );
        assert!(matches!(waited, super::super::timed::Waited::NoAnswer));
        is_held.recv().unwrap();
        let why = footed.take_off().unwrap_err();
        assert!(why.contains("as soon as it does"), "{why}");
        drop(footed);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8192 + FOOTER);
        go.send(()).unwrap();
        has_ended.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), image, "the footer was left");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_same_image_gets_the_same_footer() {
        let path = temp("same.img");
        std::fs::write(&path, vec![0u8; 8192]).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(identity_of(&file, 8192), identity_of(&file, 8192));
        assert_ne!(identity_of(&file, 8192).1, identity_of(&file, 16384).1);
        drop(file);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn images_windows_cannot_attach_are_refused_first() {
        assert!(check_attachable(0).is_err());
        assert!(check_attachable(1000).is_err());
        assert!(check_attachable(MAX_VHD + 512).is_err());
        assert!(check_attachable(1 << 30).is_ok());
        assert_eq!(disk_number_of(r"\\.\PhysicalDrive12"), Some(12));
        assert_eq!(disk_number_of(r"\\.\PHYSICALDRIVE3"), Some(3));
        assert_eq!(disk_number_of(r"\\.\CdRom0"), None);
    }

    /// Needs administrator rights and an image: set DIAGTOOL_VDISK_IMAGE to a raw image
    /// under D:\diagtool-qa\vdisk. Attaches it read-only, lists its volumes, detaches, and
    /// checks the file is byte-for-byte the length it was.
    #[test]
    #[ignore]
    fn live_attach_a_raw_image_read_only() {
        let path = PathBuf::from(std::env::var("DIAGTOOL_VDISK_IMAGE").unwrap());
        if let Some(why) = plain_needed(&path).unwrap() {
            println!("needs plain: {}", why.text);
            make_plain(&path).unwrap();
            assert_eq!(plain_needed(&path).unwrap(), None);
        }
        let before = std::fs::metadata(&path).unwrap().len();
        let image_len = data_len(&File::open(&path).unwrap()).unwrap();
        let attached = Attached::open(&path).unwrap();
        println!(
            "attached as disk {}, footer {:?}, image {} bytes",
            attached.disk, attached.footed.footer, attached.footed.image_len
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            attached.footed.image_len + FOOTER
        );
        for v in wait_for_volumes(attached.disk) {
            println!("  {} {} at {}", v.describe(), v.guid_path, v.offset);
            for name in [r"Docs\hello.txt", "fat.txt"] {
                if let Ok(text) = std::fs::read_to_string(format!("{}{name}", v.guid_path)) {
                    println!("    {name}: {}", text.trim());
                }
            }
            // Read-only: nothing can be written to the volume.
            let probe = format!("{}write-probe.txt", v.guid_path);
            println!(
                "    write refused: {}",
                std::fs::write(&probe, b"x").is_err()
            );
        }
        // Nothing else may write to the image while it is attached.
        assert!(open_for_footer(&path).is_err());
        attached.close().unwrap();
        // The file ends as the image alone, whatever footer it came with.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), image_len);
        println!("before {before}, after {image_len}");
    }
}
