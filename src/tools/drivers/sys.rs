//! The Win32 side of the drivers tool: the INF folder, the driver store location of a
//! package, and the SetupAPI and Configuration Manager device scan. Everything here reads.
use std::collections::HashSet;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, SetupGetInfDriverStoreLocationW,
    CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT, SPDRP_CLASS, SPDRP_DEVICEDESC, SPDRP_DRIVER,
    SPDRP_FRIENDLYNAME, SP_DEVINFO_DATA,
};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

use super::{
    decode_inf, is_published_name, original_name, parse_inf, signer_from, DeviceRow, DeviceScan,
    Gathered, Package, Signer,
};
use crate::events::{local_names, redact};
use crate::tools::hash::sys::{verify_embedded, wide_path};

/// An INF larger than this is not read.
const INF_LIMIT: u64 = 8 << 20;
/// Set when a device node has a problem number.
const DN_HAS_PROBLEM: u32 = 0x0000_0400;

fn windows_dir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// The INF folder's `.inf` file names, split into published (`oemN.inf`) and the rest.
fn list_infs(dir: &Path) -> Result<(Vec<String>, Vec<String>), String> {
    let entries = std::fs::read_dir(dir).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => "access denied".to_string(),
        _ => format!("the INF folder could not be read ({error})"),
    })?;
    let (mut third, mut inbox) = (Vec::new(), Vec::new());
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.to_ascii_lowercase().ends_with(".inf") {
            continue;
        }
        if is_published_name(&name) {
            third.push(name);
        } else {
            inbox.push(name);
        }
    }
    third.sort();
    inbox.sort();
    Ok((third, inbox))
}

fn read_inf(path: &Path) -> Result<super::InfFacts, String> {
    let metadata = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => "access denied".to_string(),
        _ => "the file could not be read".to_string(),
    })?;
    if metadata.len() > INF_LIMIT {
        return Err("the INF is larger than 8 MiB".into());
    }
    let bytes = std::fs::read(path).map_err(|_| "the file could not be read".to_string())?;
    Ok(parse_inf(&decode_inf(&bytes)))
}

/// The package's INF inside the driver store, from Windows.
fn store_location(inf: &Path) -> Option<PathBuf> {
    let name: Vec<u16> = inf.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut buffer = [0u16; 520];
    let mut needed = 0u32;
    // SAFETY: `name` is nul-terminated and `buffer` is writable for its stated length.
    let ok = unsafe {
        SetupGetInfDriverStoreLocationW(
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return None;
    }
    let end = buffer.iter().position(|&u| u == 0)?;
    Some(PathBuf::from(String::from_utf16_lossy(&buffer[..end])))
}

fn third_party_package(dir: &Path, name: &str, deadline: Instant) -> (Package, bool) {
    let facts = read_inf(&dir.join(name));
    let store = store_location(&dir.join(name));
    let original = store
        .as_ref()
        .and_then(|path| path.parent())
        .and_then(|folder| original_name(&folder.to_string_lossy()));
    let catalog = facts.as_ref().ok().and_then(|f| f.catalog.clone());
    let mut skipped = false;
    let signer = match (&store, &catalog) {
        _ if Instant::now() >= deadline => {
            skipped = true;
            Signer::NotChecked
        }
        (Some(store), Some(catalog)) => {
            let path = store.parent().map(|folder| folder.join(catalog));
            match path {
                Some(path) if path.is_file() => signer_from(verify_embedded(&wide_path(&path))),
                _ => Signer::Unavailable("the catalog file is not in the driver store".into()),
            }
        }
        (None, _) => Signer::Unavailable("Windows has no driver store entry for it".into()),
        (_, None) => Signer::Unavailable("the INF names no catalog file".into()),
    };
    (
        Package {
            inf: name.to_string(),
            original,
            facts,
            signer,
        },
        skipped,
    )
}

fn third_party(dir: &Path, names: &[String], deadline: Instant) -> (Vec<Package>, usize) {
    let next = AtomicUsize::new(0);
    let found = Mutex::new(Vec::new());
    let skipped = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while let Some(name) = names.get(next.fetch_add(1, Ordering::SeqCst)) {
                    let (package, cut) = third_party_package(dir, name, deadline);
                    if cut {
                        skipped.fetch_add(1, Ordering::SeqCst);
                    }
                    if let Ok(mut list) = found.lock() {
                        list.push(package);
                    }
                }
            });
        }
    });
    (found.into_inner().unwrap_or_default(), skipped.into_inner())
}

fn inbox(dir: &Path, names: &[String], deadline: Instant) -> Vec<Package> {
    let mut list = Vec::new();
    for name in names {
        if Instant::now() >= deadline {
            break;
        }
        list.push(Package {
            inf: name.clone(),
            original: None,
            facts: read_inf(&dir.join(name)),
            signer: Signer::NotChecked,
        });
    }
    list
}

struct DeviceSet(isize);

impl DeviceSet {
    fn open(flags: u32) -> Result<Self, String> {
        // SAFETY: null class, enumerator and window are allowed with DIGCF_ALLCLASSES.
        let set = unsafe {
            SetupDiGetClassDevsW(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                flags,
            )
        };
        if set as isize == INVALID_HANDLE_VALUE as isize {
            return Err("Windows would not list the devices".into());
        }
        Ok(DeviceSet(set))
    }

    fn device(&self, index: u32) -> Option<SP_DEVINFO_DATA> {
        let mut data = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: `data` has its size set and the set is open.
        (unsafe { SetupDiEnumDeviceInfo(self.0, index, &mut data) } != 0).then_some(data)
    }

    /// A string property, or `None` when the device has none or it is not text.
    fn text(&self, data: &SP_DEVINFO_DATA, property: u32) -> Option<String> {
        let mut buffer = [0u16; 512];
        let mut kind = 0u32;
        // SAFETY: the buffer is writable for the byte length given.
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.0,
                data,
                property,
                &mut kind,
                buffer.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(&buffer) as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || kind != 1 {
            return None;
        }
        let end = buffer.iter().position(|&u| u == 0).unwrap_or(buffer.len());
        let text = String::from_utf16_lossy(&buffer[..end]);
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_string())
    }
}

impl Drop for DeviceSet {
    fn drop(&mut self) {
        // SAFETY: the set came from SetupDiGetClassDevsW and is destroyed once.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

/// The device's problem number, 0 when it has none.
fn problem_of(devinst: u32) -> u32 {
    let (mut status, mut problem) = (0u32, 0u32);
    // SAFETY: both out pointers are valid.
    let result = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, devinst, 0) };
    if result == CR_SUCCESS && status & DN_HAS_PROBLEM != 0 {
        problem
    } else {
        0
    }
}

fn scan_devices(deadline: Instant) -> Result<DeviceScan, String> {
    let names = local_names();
    let mut scan = DeviceScan::default();
    let mut present_ids = HashSet::new();
    let describe = |set: &DeviceSet, data: &SP_DEVINFO_DATA, present: bool, problem: u32| {
        let name = set
            .text(data, SPDRP_FRIENDLYNAME)
            .or_else(|| set.text(data, SPDRP_DEVICEDESC))
            .unwrap_or_else(|| "unnamed device".into());
        DeviceRow {
            name: redact(&name, &names),
            class: set.text(data, SPDRP_CLASS).unwrap_or_default(),
            problem,
            present,
        }
    };
    let present = DeviceSet::open(DIGCF_ALLCLASSES | DIGCF_PRESENT)?;
    for index in 0.. {
        if Instant::now() >= deadline {
            scan.cut_short = true;
            return Ok(scan);
        }
        let Some(data) = present.device(index) else {
            break;
        };
        present_ids.insert(data.DevInst);
        scan.present += 1;
        let problem = problem_of(data.DevInst);
        if problem != 0 {
            scan.rows.push(describe(&present, &data, true, problem));
        }
    }
    drop(present);
    let everything = DeviceSet::open(DIGCF_ALLCLASSES)?;
    for index in 0.. {
        if Instant::now() >= deadline {
            scan.cut_short = true;
            break;
        }
        let Some(data) = everything.device(index) else {
            break;
        };
        if present_ids.contains(&data.DevInst) || everything.text(&data, SPDRP_DRIVER).is_none() {
            continue;
        }
        scan.rows.push(describe(&everything, &data, false, 0));
    }
    Ok(scan)
}

pub fn gather(all: bool, deadline: Instant) -> Gathered {
    let dir = windows_dir().join("INF");
    let listing = list_infs(&dir);
    let (third, inbox_names) = match &listing {
        Ok((third, inbox)) => (Some(third.as_slice()), Some(inbox.as_slice())),
        Err(_) => (None, None),
    };
    let mut packages_cut = 0;
    let third_party = match (third, &listing) {
        (Some(names), _) => {
            let (list, cut) = third_party(&dir, names, deadline);
            packages_cut = cut;
            Ok(list)
        }
        (None, Err(reason)) => Err(reason.clone()),
        (None, Ok(_)) => Err("the INF folder could not be read".into()),
    };
    let inbox = match (all, inbox_names, &listing) {
        (true, Some(names), _) => Ok(inbox(&dir, names, deadline)),
        (true, None, Err(reason)) => Err(reason.clone()),
        _ => Ok(Vec::new()),
    };
    Gathered {
        third_party,
        inbox,
        devices: scan_devices(deadline),
        packages_cut,
    }
}
