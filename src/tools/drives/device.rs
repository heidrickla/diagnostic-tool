//! Win32 reads of physical disks: IOCTL_STORAGE_QUERY_PROPERTY with zero desired access for
//! everything that allows it. The ATA data-in commands and the SCT read limit need a
//! read-write handle, which only `crate::handles` opens: an ATA data-in command goes through
//! an `AtaDisk` of its own, proven to be the disk read and closed after it, and the read
//! limit through `handles::SctDrive`. Both carry the command as the disk's bus calls for:
//! Windows' ATA paths, or SCSI/ATA Translation through a USB adapter. Nothing here opens a
//! handle itself.
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_FUNCTION,
    ERROR_INVALID_PARAMETER, ERROR_NOT_READY, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetLogicalDrives, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
};
use windows_sys::Win32::System::Ioctl::{
    NVMeDataTypeIdentify, NVMeDataTypeLogPage, ProtocolTypeNvme,
    StorageAdapterProtocolSpecificProperty, StorageDeviceProperty,
    StorageDeviceProtocolSpecificProperty, StorageDeviceSeekPenaltyProperty,
    StorageDeviceTemperatureProperty, StorageDeviceTrimProperty, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
    IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_STORAGE_PREDICT_FAILURE, IOCTL_STORAGE_QUERY_PROPERTY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::DeviceIoControl;

use super::ata::{self, AtaCommand, DriveId, Failure};
use super::details::{self, Details, Link, Volume};
use super::health::{self, Disk, Health, BUS_ATA, BUS_NVME, BUS_RAID, BUS_SATA, BUS_USB};
use super::sct::Refusal;
/// The read limit's drive, which `crate::handles` opens and checks.
pub use crate::handles::SctDrive;
use crate::handles::{self, AtaDisk, Handle, HeldDisk};

/// Physical drive numbers probed: 0 to 31.
pub const MAX_DISKS: u32 = 32;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
/// NVMe log page 02h, SMART / Health Information.
const NVME_LOG_HEALTH: u32 = 2;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One DeviceIoControl call; returns the bytes the driver wrote.
fn ioctl(handle: &Handle, code: u32, input: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
    // An 8-byte-aligned buffer, since drivers read the reply's 64-bit fields in place.
    let mut buffer = vec![0u64; out_len.div_ceil(8)];
    let mut returned = 0u32;
    // SAFETY: input and output pointers are valid for the lengths given for the whole
    // synchronous call; the handle was opened without FILE_FLAG_OVERLAPPED.
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
        // SAFETY: reads the calling thread's last-error value.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: the u64 buffer holds at least `out_len` initialised bytes.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), out_len) };
    Ok(bytes[..(returned as usize).min(out_len)].to_vec())
}

/// STORAGE_PROPERTY_QUERY: PropertyId, QueryType (standard), then any extra parameters;
/// padded to the struct's 12-byte size, which drivers check (error 24 otherwise).
fn query(handle: &Handle, property: i32, extra: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
    let mut input = Vec::with_capacity(12 + extra.len());
    input.extend_from_slice(&property.to_le_bytes());
    input.extend_from_slice(&0i32.to_le_bytes());
    input.extend_from_slice(extra);
    input.resize(input.len().max(12), 0);
    ioctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &input, out_len)
}

pub fn reason(error: u32) -> String {
    match error {
        ERROR_ACCESS_DENIED => "needs administrator rights".into(),
        ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER => {
            "the driver does not support it".into()
        }
        ERROR_NOT_READY => "no media in the drive".into(),
        other => format!("the driver refused it (error {other})"),
    }
}

/// Whether this process runs with an elevated (administrator) token.
pub fn elevated() -> Option<bool> {
    let mut token = null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` receives a new handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = Handle(token);
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = 0u32;
    // SAFETY: `elevation` is a TOKEN_ELEVATION of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    (ok != 0).then_some(elevation.TokenIsElevated != 0)
}

/// Drive letters of fixed and removable volumes, by the disk numbers they lie on.
pub fn volumes_by_disk() -> BTreeMap<u32, Vec<char>> {
    let mut map: BTreeMap<u32, Vec<char>> = BTreeMap::new();
    // SAFETY: no arguments; returns a bit mask of drive letters.
    let mask = unsafe { GetLogicalDrives() };
    for (index, letter) in ('A'..='Z').enumerate() {
        if mask & (1 << index) == 0 {
            continue;
        }
        let root = wide(&format!("{letter}:\\"));
        // SAFETY: `root` is NUL-terminated.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        if kind != DRIVE_FIXED && kind != DRIVE_REMOVABLE {
            continue;
        }
        let Ok(volume) = handles::query(&format!("\\\\.\\{letter}:")) else {
            continue;
        };
        let Ok(reply) = ioctl(
            &volume,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            &[],
            8 + 24 * 16,
        ) else {
            continue;
        };
        for disk in health::parse_disk_extents(&reply) {
            let letters = map.entry(disk).or_default();
            if !letters.contains(&letter) {
                letters.push(letter);
            }
        }
    }
    map
}

/// The physical disks the volume holding `path` lies on (more than one for a spanned volume).
/// The path must exist; a folder or file on any volume, or a mount point, works.
pub fn disks_of_path(path: &std::path::Path) -> Result<Vec<u32>, String> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    };
    let target = wide(&path.to_string_lossy());
    let mut mount = vec![0u16; 1024];
    // SAFETY: target is NUL-terminated and mount is writable for its stated length.
    if unsafe { GetVolumePathNameW(target.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0 {
        return Err(format!(
            "{} is not on a volume Windows knows",
            path.display()
        ));
    }
    let mut name = vec![0u16; 64];
    // SAFETY: mount is NUL-terminated and name is writable for its stated length.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), name.as_mut_ptr(), name.len() as u32)
    } == 0
    {
        return Err(format!(
            "the volume of {} has no volume name",
            path.display()
        ));
    }
    let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    disks_of_volume(&String::from_utf16_lossy(&name[..end]))
}

/// The physical disks a volume lies on, from its GUID name, "\\?\Volume{guid}" with or
/// without the closing backslash.
pub fn disks_of_volume(volume: &str) -> Result<Vec<u32>, String> {
    // "\\?\Volume{guid}\" names the root; without the slash it names the volume itself.
    let volume = volume.trim_end_matches('\\');
    let handle = handles::query(volume)
        .map_err(|e| format!("the volume could not be opened: {}", reason(e)))?;
    let reply = ioctl(
        &handle,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &[],
        8 + 24 * 16,
    )
    .map_err(|e| format!("the volume's disks could not be read: {}", reason(e)))?;
    Ok(health::parse_disk_extents(&reply))
}

/// Where a volume lies, from its GUID name ("\\?\Volume{guid}" with or without the closing
/// backslash): each extent as (disk number, byte offset, length).
pub fn volume_extents(volume: &str) -> Result<Vec<(u32, u64, u64)>, String> {
    let volume = volume.trim_end_matches('\\');
    let handle = handles::query(volume)
        .map_err(|e| format!("the volume could not be opened: {}", reason(e)))?;
    let reply = ioctl(
        &handle,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &[],
        8 + 24 * 16,
    )
    .map_err(|e| format!("the volume's disks could not be read: {}", reason(e)))?;
    Ok(health::parse_volume_extents(&reply))
}

/// Reads one physical disk, or None when no disk has that number.
pub fn read_disk(number: u32, volumes: &BTreeMap<u32, Vec<char>>) -> Option<Disk> {
    let held = match HeldDisk::open(number) {
        Ok(held) => held,
        Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => return None,
        Err(error) => {
            let why = format!("could not open the disk: {}", reason(error));
            return Some(Disk {
                number,
                identity: Err(why.clone()),
                size: Err(why.clone()),
                solid_state: Err(why.clone()),
                volumes: volumes.get(&number).cloned().unwrap_or_default(),
                temperature: Err(why.clone()),
                predicts_failure: Err(why.clone()),
                health: Health::Unread(why),
            });
        }
    };
    let handle = held.handle();
    let identity = query(handle, StorageDeviceProperty, &[], 1024)
        .map_err(reason)
        .and_then(|reply| {
            health::parse_device_descriptor(&reply)
                .ok_or_else(|| "the device descriptor was malformed".to_string())
        });
    let size = ioctl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], 256)
        .map_err(reason)
        .and_then(|reply| {
            health::parse_geometry_size(&reply).ok_or_else(|| "no size in the reply".to_string())
        });
    let solid_state = query(handle, StorageDeviceSeekPenaltyProperty, &[], 12)
        .map_err(reason)
        .and_then(|reply| {
            health::parse_seek_penalty(&reply).ok_or_else(|| "malformed reply".to_string())
        });
    let temperature = query(handle, StorageDeviceTemperatureProperty, &[], 24 + 16 * 8)
        .map_err(reason)
        .and_then(|reply| {
            health::parse_temperature(&reply).ok_or_else(|| "malformed reply".to_string())
        });
    let predicts_failure = ioctl(handle, IOCTL_STORAGE_PREDICT_FAILURE, &[], 4 + 512)
        .map_err(reason)
        .and_then(|reply| {
            health::u32_at(&reply, 0)
                .map(|flag| flag != 0)
                .ok_or_else(|| "malformed reply".to_string())
        });
    let health = match &identity {
        Ok(identity) => drive_health(&held, identity.bus),
        Err(why) => Health::Unread(format!("the bus type is unknown ({why})")),
    };
    Some(Disk {
        number,
        identity,
        size,
        solid_state,
        volumes: volumes.get(&number).cloned().unwrap_or_default(),
        temperature,
        predicts_failure,
        health,
    })
}

fn drive_health(held: &HeldDisk, bus: i32) -> Health {
    match bus {
        BUS_NVME => nvme_health(held.handle()),
        // A USB adapter with SCSI/ATA Translation passes SMART to the drive behind it.
        BUS_ATA | BUS_SATA | BUS_RAID | BUS_USB => ata_health(held, bus),
        // Virtual (14), virtual disk file (15) and Storage Spaces (16) disks.
        14..=16 => Health::Unread("a virtual disk has no health data of its own".into()),
        other => Health::Unread(format!(
            "this tool reads no health data over {} connections",
            health::bus_name(other)
        )),
    }
}

/// One NVMe log page or identify structure through a protocol-specific property query, as
/// Microsoft documents for stornvme: adapter property first, then device property.
fn nvme_query(
    handle: &Handle,
    data_type: i32,
    value: u32,
    length: usize,
) -> Result<Vec<u8>, String> {
    // STORAGE_PROTOCOL_SPECIFIC_DATA (40 bytes): type, data type, request value, sub-value 0,
    // data offset (40, just past this struct), data length, then zeros.
    let mut specific = [0u8; 40];
    specific[0..4].copy_from_slice(&ProtocolTypeNvme.to_le_bytes());
    specific[4..8].copy_from_slice(&(data_type as u32).to_le_bytes());
    specific[8..12].copy_from_slice(&value.to_le_bytes());
    specific[16..20].copy_from_slice(&40u32.to_le_bytes());
    specific[20..24].copy_from_slice(&(length as u32).to_le_bytes());
    let mut extra = specific.to_vec();
    extra.resize(40 + length, 0);
    let out_len = 8 + extra.len();
    let mut last = String::new();
    for property in [
        StorageAdapterProtocolSpecificProperty,
        StorageDeviceProtocolSpecificProperty,
    ] {
        match query(handle, property, &extra, out_len) {
            Ok(reply) => match health::protocol_data(&reply, length) {
                Ok(data) => return Ok(data.to_vec()),
                Err(why) => last = why,
            },
            Err(error) => last = reason(error),
        }
    }
    Err(last)
}

/// The NVMe SMART / Health Information log.
fn nvme_health(handle: &Handle) -> Health {
    match nvme_query(
        handle,
        NVMeDataTypeLogPage,
        NVME_LOG_HEALTH,
        health::NVME_HEALTH_LOG_SIZE,
    ) {
        Ok(log) => match health::parse_nvme_health(&log) {
            Some(parsed) => Health::Nvme(parsed),
            None => Health::Unread(
                "the NVMe health log could not be read: the health log was malformed".into(),
            ),
        },
        Err(last) => Health::Unread(format!("the NVMe health log could not be read: {last}")),
    }
}

// ---- the drive window's further reads ------------------------------------------------

/// NVMe log page 06h, Device Self-test, and Identify CNS 01h, the controller.
const NVME_LOG_SELF_TEST: u32 = 6;
const NVME_IDENTIFY_CONTROLLER: u32 = 1;

/// Partitions, lettered volumes, TRIM, the PCIe link, and for NVMe the identify data and
/// self-test log, all read as the current user.
pub fn read_details(number: u32, bus: Option<i32>) -> Details {
    let handle = match handles::query_disk(number) {
        Ok(handle) => handle,
        Err(error) => {
            return Details::unread(&format!("could not open the disk: {}", reason(error)))
        }
    };
    let layout = ioctl(
        &handle,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        &[],
        details::LAYOUT_HEADER + details::PARTITION_ENTRY * 128,
    )
    .map_err(reason)
    .and_then(|reply| {
        details::parse_layout(&reply)
            .ok_or_else(|| "the partition table reply was malformed".into())
    });
    // DEVICE_TRIM_DESCRIPTOR: version, size, then TrimEnabled.
    let trim = query(&handle, StorageDeviceTrimProperty, &[], 12)
        .map_err(reason)
        .and_then(|reply| {
            reply
                .get(8)
                .map(|&enabled| enabled != 0)
                .ok_or_else(|| "malformed reply".into())
        });
    let not_nvme = |what: &str| -> String {
        match bus {
            Some(BUS_ATA | BUS_SATA) => format!(
                "a SATA drive's {what} needs administrator rights (ATA commands need write access to the disk)"
            ),
            Some(BUS_RAID) => format!("the {what} is not passed through the RAID driver"),
            Some(other) => format!("not reported over {}", health::bus_name(other)),
            None => "the bus type is unknown".into(),
        }
    };
    let (identify, self_test, link) = if bus == Some(BUS_NVME) {
        let identify = nvme_query(
            &handle,
            NVMeDataTypeIdentify,
            NVME_IDENTIFY_CONTROLLER,
            details::NVME_IDENTIFY_SIZE,
        )
        .and_then(|data| {
            details::parse_nvme_identify(&data)
                .ok_or_else(|| "the identify data was malformed".into())
        });
        // A drive whose identify data says it runs no self-tests has no log to read.
        let self_test = if matches!(&identify, Ok(id) if !id.self_test) {
            Err("this drive does not run self-tests".to_string())
        } else {
            nvme_query(
                &handle,
                NVMeDataTypeLogPage,
                NVME_LOG_SELF_TEST,
                details::NVME_SELF_TEST_LOG_SIZE,
            )
            .and_then(|data| {
                details::parse_self_test_log(&data)
                    .ok_or_else(|| "the self-test log was malformed".into())
            })
        };
        (identify, self_test, pci_link(number))
    } else {
        (
            Err(not_nvme("identify data")),
            Err(not_nvme("self-test log")),
            Err(not_nvme("link speed")),
        )
    };
    Details {
        link,
        layout,
        volumes: volumes_on(number),
        trim,
        windows_trim: windows_trim(),
        identify,
        self_test,
    }
}

/// Whether Windows sends TRIM to drives on NTFS: DisableDeleteNotification 0 or absent.
fn windows_trim() -> Result<bool, String> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
    };
    const NOT_FOUND: u32 = 2;
    let key = wide(r"SYSTEM\CurrentControlSet\Control\FileSystem");
    let name = wide("DisableDeleteNotification");
    let mut value = 0u32;
    let mut size = 4u32;
    // SAFETY: both strings are NUL-terminated; `value` holds the 4 bytes a DWORD needs.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    match status {
        0 => Ok(value == 0),
        NOT_FOUND => Ok(true),
        other => Err(format!("the setting could not be read (error {other})")),
    }
}

/// Lettered volumes with a part on disk `number`, with free space and file system.
fn volumes_on(number: u32) -> Vec<Volume> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
    let mut found = Vec::new();
    // SAFETY: no arguments; returns a bit mask of drive letters.
    let mask = unsafe { GetLogicalDrives() };
    for (index, letter) in ('A'..='Z').enumerate() {
        if mask & (1 << index) == 0 {
            continue;
        }
        let root = wide(&format!("{letter}:\\"));
        // SAFETY: `root` is NUL-terminated.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        if kind != DRIVE_FIXED && kind != DRIVE_REMOVABLE {
            continue;
        }
        let Ok(volume) = handles::query(&format!("\\\\.\\{letter}:")) else {
            continue;
        };
        let Ok(reply) = ioctl(
            &volume,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            &[],
            8 + 24 * 16,
        ) else {
            continue;
        };
        let extents = details::parse_extents(&reply);
        if !extents.iter().any(|(disk, _)| *disk == number) {
            continue;
        }
        let mut name = [0u16; 64];
        // SAFETY: `root` is NUL-terminated and `name` is writable for its stated length; the
        // label, serial and flags are not asked for.
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                name.as_mut_ptr(),
                name.len() as u32,
            )
        };
        let file_system = if ok != 0 {
            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            Ok(String::from_utf16_lossy(&name[..end]))
        } else {
            Err("not read".to_string())
        };
        let mut other_disks: Vec<u32> = extents
            .iter()
            .map(|(disk, _)| *disk)
            .filter(|disk| *disk != number)
            .collect();
        other_disks.sort_unstable();
        other_disks.dedup();
        found.push(Volume {
            letter,
            offsets: extents
                .iter()
                .filter(|(disk, _)| *disk == number)
                .map(|(_, offset)| *offset)
                .collect(),
            other_disks,
            space: crate::tools::space::disk_space(letter),
            file_system,
        });
    }
    found
}

/// PCI link properties of the controller above disk `number`: the disk's device node is
/// found through its interface's device number, then its parents are read.
fn pci_link(number: u32) -> Result<Link, String> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
        SetupDiGetDeviceInterfaceDetailW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
        SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA,
    };
    use windows_sys::Win32::System::Ioctl::{
        GUID_DEVINTERFACE_DISK, IOCTL_STORAGE_GET_DEVICE_NUMBER,
    };
    // SAFETY: the class GUID is a static; no enumerator or window.
    let set = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_DISK,
            null(),
            null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if set == -1 {
        return Err("Windows did not list the disks' devices".into());
    }
    let mut found = None;
    for index in 0..64u32 {
        let mut data = SP_DEVICE_INTERFACE_DATA {
            cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: `set` is a live device information set and `data` is sized.
        if unsafe {
            SetupDiEnumDeviceInterfaces(set, null(), &GUID_DEVINTERFACE_DISK, index, &mut data)
        } == 0
        {
            break;
        }
        let mut required = 0u32;
        // SAFETY: a size query with no output buffer.
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(set, &data, null_mut(), 0, &mut required, null_mut())
        };
        if required < 8 {
            continue;
        }
        let mut buffer = vec![0u64; (required as usize).div_ceil(8)];
        let detail = buffer
            .as_mut_ptr()
            .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
        let mut info = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: `detail` points to `required` writable, 8-byte-aligned bytes; cbSize is the
        // fixed part's size as the API requires.
        let ok = unsafe {
            (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            SetupDiGetDeviceInterfaceDetailW(set, &data, detail, required, null_mut(), &mut info)
        };
        if ok == 0 {
            continue;
        }
        // SAFETY: DevicePath is a NUL-terminated string inside the buffer just filled.
        let path: Vec<u16> = unsafe {
            let start = std::ptr::addr_of!((*detail).DevicePath).cast::<u16>();
            let words = (required as usize - 4) / 2;
            let slice = std::slice::from_raw_parts(start, words);
            let end = slice.iter().position(|&c| c == 0).unwrap_or(words);
            slice[..end].to_vec()
        };
        let Ok(device) = handles::query(&String::from_utf16_lossy(&path)) else {
            continue;
        };
        // STORAGE_DEVICE_NUMBER: device type, then the device number at 4.
        let matches = ioctl(&device, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], 12)
            .ok()
            .and_then(|reply| health::u32_at(&reply, 4))
            == Some(number);
        if matches {
            found = Some(info.DevInst);
            break;
        }
    }
    // SAFETY: `set` came from SetupDiGetClassDevsW and is freed once.
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    let mut node = found.ok_or("the disk's device was not found")?;
    for _ in 0..4 {
        let mut parent = 0u32;
        // SAFETY: `node` is a device instance handle from SetupAPI or a previous parent call.
        if unsafe {
            windows_sys::Win32::Devices::DeviceAndDriverInstallation::CM_Get_Parent(
                &mut parent,
                node,
                0,
            )
        } != 0
        {
            break;
        }
        node = parent;
        let link = Link {
            speed: devnode_u32(node, 9),
            width: devnode_u32(node, 10),
            max_speed: devnode_u32(node, 11),
            max_width: devnode_u32(node, 12),
        };
        if link.speed.is_some() || link.width.is_some() {
            return Ok(link);
        }
    }
    Err("Windows did not report the controller's PCIe link".into())
}

/// One DEVPKEY_PciDevice_* property (property ids 9 to 12 are current and maximum link
/// speed and width) as a 32-bit number.
fn devnode_u32(node: u32, pid: u32) -> Option<u32> {
    use windows_sys::core::GUID;
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::CM_Get_DevNode_PropertyW;
    use windows_sys::Win32::Devices::Properties::DEVPROP_TYPE_UINT32;
    use windows_sys::Win32::Foundation::DEVPROPKEY;
    let key = DEVPROPKEY {
        fmtid: GUID::from_u128(0x3ab22e31_8264_4b4e_9af5_a8d2d8e33e62),
        pid,
    };
    let mut kind = 0u32;
    let mut value = 0u32;
    let mut size = 4u32;
    // SAFETY: `value` holds the 4 bytes passed as the buffer size.
    let status = unsafe {
        CM_Get_DevNode_PropertyW(
            node,
            &key,
            &mut kind,
            (&mut value as *mut u32).cast(),
            &mut size,
            0,
        )
    };
    (status == 0 && kind == DEVPROP_TYPE_UINT32).then_some(value)
}

/// One ATA data-in command on a read-write handle of its own, proven to be the held disk and
/// closed before returning; the 512 bytes the drive sent, or why not.
fn ata_read(held: &HeldDisk, command: AtaCommand) -> Result<Vec<u8>, Failure> {
    let ata = AtaDisk::open(held).map_err(Failure::Open)?;
    let data = ata.read(command);
    drop(ata);
    data
}

/// The drive's own model and serial number from IDENTIFY, read on the held disk; None for a
/// drive on a bus that carries no ATA command (NVMe, a virtual disk), and for one that
/// does not answer IDENTIFY or gives no serial number (a USB flash stick, an adapter
/// without SCSI/ATA Translation).
pub fn ata_identity(held: &HeldDisk) -> Option<DriveId> {
    let bus = query(held.handle(), StorageDeviceProperty, &[], 1024)
        .ok()
        .and_then(|reply| health::parse_device_descriptor(&reply))?
        .bus;
    ata::carrier(Some(bus)).ok()?;
    ata::drive_id(&ata_read(held, AtaCommand::Identify).ok()?)
}

/// The buses an SCT command is sent on.
pub(crate) fn ata_bus(bus: Option<i32>) -> Result<(), Refusal> {
    match bus {
        Some(BUS_ATA | BUS_SATA | BUS_RAID | BUS_USB) => Ok(()),
        Some(BUS_NVME) => Err(Refusal::NotAta("NVMe".into())),
        Some(other) => Err(Refusal::NotAta(health::bus_name(other).into())),
        None => Err(Refusal::NotAta("an unknown bus".into())),
    }
}

/// Whether the drive found on disk `number` (model, serial) is the one meant. A drive with
/// no serial number cannot be told from another of its model, so it is refused.
pub(crate) fn same_drive(
    number: u32,
    found: (&str, &str),
    meant: (&str, &str),
) -> Result<(), Refusal> {
    let (meant_model, meant_serial) = (meant.0.trim(), meant.1.trim());
    if meant_serial.is_empty() {
        return Err(Refusal::NotTheDrive(
            "the drive reports no serial number, so it cannot be told apart from another".into(),
        ));
    }
    if found.0.trim() != meant_model || found.1.trim() != meant_serial {
        return Err(Refusal::NotTheDrive(format!(
            "disk {number} is now {} serial {}, not the drive being read ({meant_model} serial {meant_serial})",
            found.0.trim(),
            found.1.trim()
        )));
    }
    Ok(())
}

/// ATA SMART attributes, through the ATA reader; over USB, through the adapter, which may
/// not pass them.
fn ata_health(held: &HeldDisk, bus: i32) -> Health {
    match ata_read(held, AtaCommand::SmartReadData) {
        Ok(data) => match health::parse_smart_attributes(&data) {
            Some(attributes) => Health::Ata(attributes),
            None => Health::Unread("the SMART attribute table was malformed".into()),
        },
        Err(why) => Health::Unread(unread_smart(bus, &why)),
    }
}

/// Why SMART attributes were not read, for people.
fn unread_smart(bus: i32, why: &Failure) -> String {
    match why {
        Failure::Open(text) if text == "needs administrator rights" => {
            "SMART attributes need administrator rights".into()
        }
        Failure::NotPassed(text) if bus == BUS_USB => {
            format!("this USB adapter does not pass SMART commands ({text})")
        }
        other => format!("SMART attributes not read: {}", other.text()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This file without its tests.
    fn code() -> &'static str {
        let all = include_str!("device.rs");
        &all[..all.find("#[cfg(test)]").expect("the tests module")]
    }

    /// The guard: this file opens no handle itself and names no write right; a disk is reached
    /// through `crate::handles` (its guard covers every file), and the ATA reader takes one
    /// `AtaDisk`, proven to be the held disk, for one command and lets it go.
    #[test]
    fn the_drive_window_opens_disks_only_through_the_handles_module() {
        let code = code();
        for named in ["CreateFileW", "GENERIC_WRITE", "PhysicalDrive{"] {
            assert!(!code.contains(named), "device.rs names {named}");
        }
        let reader = &code[code.find("fn ata_read(").unwrap()..];
        let reader = &reader[..reader.find("\n}\n").unwrap()];
        assert!(
            reader.contains("AtaDisk::open(held).map_err(Failure::Open)?")
                && reader.contains("drop(ata);")
                && reader.matches("ata.read(command)").count() == 1,
            "the ATA reader sends one command and closes its handle"
        );
        assert_eq!(code.matches("AtaDisk::open(").count(), 1);
    }

    #[test]
    fn a_drive_is_the_one_meant_only_by_model_and_serial() {
        let meant = ("WDC WD10EZEX", "WD-123");
        assert!(same_drive(3, ("WDC WD10EZEX ", " WD-123"), meant).is_ok());
        let Err(Refusal::NotTheDrive(why)) = same_drive(3, ("WDC WD10EZEX", "WD-999"), meant)
        else {
            panic!("another serial was taken");
        };
        assert!(why.contains("disk 3") && why.contains("WD-999"), "{why}");
        assert!(same_drive(3, ("ST1000", "WD-123"), meant).is_err());
        assert!(matches!(
            same_drive(3, ("WDC WD10EZEX", ""), ("WDC WD10EZEX", " ")),
            Err(Refusal::NotTheDrive(_))
        ));
        for bus in [BUS_ATA, BUS_SATA, BUS_RAID, BUS_USB] {
            assert!(ata_bus(Some(bus)).is_ok());
        }
        assert!(matches!(ata_bus(Some(BUS_NVME)), Err(Refusal::NotAta(_))));
        assert!(matches!(ata_bus(None), Err(Refusal::NotAta(_))));
    }

    /// The guard: the commands themselves are built by `ata` (its guard) and sent by
    /// `crate::handles` alone (its guard); this file names none of the controls that carry
    /// them.
    #[test]
    fn the_ata_reader_sends_only_three_read_commands() {
        let code = code();
        for control in [
            "SMART_SEND_DRIVE_COMMAND",
            "SMART_RCV_DRIVE_DATA",
            "IOCTL_ATA_PASS_THROUGH",
            "IOCTL_SCSI_PASS_THROUGH",
        ] {
            assert!(!code.contains(control), "device.rs names {control}");
        }
        // The reads sent are the ones named here, all of `ata::ATA_COMMANDS`.
        for (at, _) in code.match_indices("ata_read(") {
            let call = &code[at..at + code[at..].find(')').unwrap()];
            assert!(
                call.starts_with("ata_read(held: &HeldDisk")
                    || call.ends_with("AtaCommand::SmartReadData")
                    || call.ends_with("AtaCommand::Identify"),
                "{call}"
            );
        }
    }

    #[test]
    fn a_usb_adapter_that_refuses_smart_is_named() {
        let refused =
            Failure::NotPassed("the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00".into());
        assert_eq!(
            unread_smart(BUS_USB, &refused),
            "this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)"
        );
        assert_eq!(
            unread_smart(
                BUS_SATA,
                &Failure::NotPassed("the driver does not support it".into())
            ),
            "SMART attributes not read: the driver does not support it"
        );
        let admin = Failure::Open("needs administrator rights".into());
        for bus in [BUS_SATA, BUS_USB] {
            assert_eq!(
                unread_smart(bus, &admin),
                "SMART attributes need administrator rights"
            );
        }
        // A drive that refused it over USB is the drive, not the adapter.
        let drive = Failure::Refused("the drive refused it (status 0x51, error 0x04)".into());
        assert_eq!(
            unread_smart(BUS_USB, &drive),
            "SMART attributes not read: the drive refused it (status 0x51, error 0x04)"
        );
    }
}
