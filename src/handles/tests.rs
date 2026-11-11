use super::*;
use std::path::PathBuf;

/// handles.rs without its tests.
fn code() -> &'static str {
    let all = include_str!("../handles.rs");
    &all[..all.find("#[cfg(test)]").expect("the tests module")]
}

/// The item that starts at `start` in handles.rs, up to its closing brace at `indent`.
fn body(start: &str, indent: &str) -> &'static str {
    let code = code();
    let from = &code[code
        .find(start)
        .unwrap_or_else(|| panic!("{start} is gone"))..];
    &from[..from
        .find(&format!("\n{indent}}}\n"))
        .unwrap_or_else(|| panic!("{start} does not end"))]
}

/// Every .rs file under src/, by its path from src/ with forward slashes, without its tests.
/// A file that is a test module of its own (`tests.rs`) is left out once its parent is seen
/// to declare it under `#[cfg(test)]`.
fn sources() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut folders = vec![root.clone()];
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                folders.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
    let mut files = Vec::new();
    for path in found {
        let name = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&path).unwrap();
        if path.file_name().is_some_and(|n| n == "tests.rs") {
            let parent = path.parent().unwrap().with_extension("rs");
            let declared = std::fs::read_to_string(&parent).unwrap_or_default();
            let declared = declared.replace("\r\n", "\n");
            assert!(
                ["mod tests;", "pub(crate) mod tests;"]
                    .iter()
                    .any(|m| declared.contains(&format!("#[cfg(test)]\n{m}"))),
                "{name} is skipped as a test module, but {} does not declare it under #[cfg(test)]",
                parent.display()
            );
            continue;
        }
        let code = text.split("#[cfg(test)]").next().unwrap().to_string();
        files.push((name, code));
    }
    assert!(files.len() > 100, "only {} files were found", files.len());
    files
}

/// `code` without its comment lines.
fn without_comments(code: &str) -> String {
    code.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Commands that change a disk or volume, or that Windows passes only on a read-write
/// handle: none may be sent outside this module.
const ACTS: [&str; 17] = [
    "FSCTL_LOCK_VOLUME",
    "FSCTL_DISMOUNT_VOLUME",
    "FSCTL_EXTEND_VOLUME",
    "FSCTL_SHRINK_VOLUME",
    "IOCTL_DISK_CREATE_DISK",
    "IOCTL_DISK_DELETE_DRIVE_LAYOUT",
    "IOCTL_DISK_FORMAT_",
    "IOCTL_DISK_GROW_PARTITION",
    "IOCTL_DISK_REASSIGN_BLOCKS",
    "IOCTL_DISK_RESET_SNAPSHOT_INFO",
    "IOCTL_DISK_SET_",
    "IOCTL_DISK_UPDATE_",
    "IOCTL_DISK_COPY_DATA",
    "IOCTL_ATA_PASS_THROUGH",
    "SMART_RCV_DRIVE_DATA",
    "SMART_SEND_DRIVE_COMMAND",
    "IOCTL_SCSI_PASS_THROUGH",
];

/// The access rights a CreateFileW outside this module may ask for: none, or reading.
const READ_ONLY: [&str; 4] = ["0", "ACCESS", "GENERIC_READ", "FILE_READ_ATTRIBUTES"];

/// The access (second) and disposition (fifth) arguments of each CreateFileW call in `code`.
fn create_calls(code: &str) -> Vec<(String, String)> {
    code.match_indices("CreateFileW(")
        .map(|(at, _)| {
            let args: Vec<String> = code[at + "CreateFileW(".len()..]
                .splitn(6, ',')
                .map(|a| a.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect();
            (args[1].clone(), args[4].clone())
        })
        .collect()
}

/// Why `file` breaks the rule, if it does: this module alone names a disk by number, opens a
/// disk or volume with a write right, or sends a command that changes one; output folders,
/// and what is made in them, are `recovery/dest.rs`'. Two files open a device that is not a
/// disk or volume with a write right, each allowed narrowly below.
fn breaks(name: &str, code: &str) -> Vec<String> {
    let mut why = Vec::new();
    if name == "handles.rs" {
        return why;
    }
    let lines = without_comments(code);
    if lines.contains("PhysicalDrive") {
        why.push("names a disk by its number (\\\\.\\PhysicalDriveN)".to_string());
    }
    for act in ACTS {
        if lines.contains(act) {
            why.push(format!("sends {act}"));
        }
    }
    for (access, disposition) in create_calls(&lines) {
        let allowed = READ_ONLY.contains(&access.as_str())
            // The speed test makes its own test file, which a disk or volume cannot be.
            || (name == "tools/drives/speed.rs" && disposition == "CREATE_NEW")
            // Crash dump Put back removes the folder set up made through one handle that checks
            // its identity first (`remove_folder_if`): a folder, never a disk or a volume.
            || (name == "tools/crash_dumps/windows.rs"
                && access == "DELETE | FILE_READ_ATTRIBUTES"
                && lines.matches("DELETE | FILE_READ_ATTRIBUTES").count() == 1
                && lines.contains("fn remove_folder_if(")
                && !lines.contains("IOCTL_DISK")
                && !lines.contains("IOCTL_VOLUME"))
            // The battery is opened by its device interface, and sent battery queries only.
            || (name == "tools/battery.rs"
                && lines.contains("&GUID_DEVICE_BATTERY")
                && !lines.contains("IOCTL_DISK")
                && !lines.contains("IOCTL_VOLUME"));
        if !allowed {
            why.push(format!("opens a handle with {access}"));
        }
    }
    let writes = [
        "recovery/dest.rs",
        "tools/drives/speed.rs",
        "tools/battery.rs",
    ];
    if lines.contains("GENERIC_WRITE") && !writes.contains(&name) {
        why.push("names GENERIC_WRITE".to_string());
    }
    for folder in ["NtCreateFile", "OpenFileById"] {
        if lines.contains(folder) && name != "recovery/dest.rs" {
            why.push(format!("makes or opens an output by handle ({folder})"));
        }
    }
    why
}

/// The guard: across all of src/, only this module names a disk by its number, opens a disk
/// or volume with a write right, or sends a command that changes one; only dest.rs makes
/// output relative to a held folder. Two non-disk devices with a write right are allowed by
/// name and checked to be what they say.
#[test]
fn only_the_handles_module_reaches_a_disk_or_volume_to_change_it() {
    let mut broken = Vec::new();
    for (name, code) in sources() {
        for why in breaks(&name, &code) {
            broken.push(format!("{name} {why}"));
        }
    }
    assert!(broken.is_empty(), "{}", broken.join("\n"));
    // The rule itself catches each of the acts.
    let caught = |code: &str| !breaks("recovery/x.rs", code).is_empty();
    assert!(caught(
        "let p = format!(\"\\\\\\\\.\\\\PhysicalDrive{n}\");"
    ));
    assert!(caught("ioctl(&h, FSCTL_LOCK_VOLUME, &[], 0)"));
    assert!(caught("ioctl(&h, IOCTL_DISK_SET_DISK_ATTRIBUTES, &a, 0)"));
    assert!(caught(
        "CreateFileW(\n name.as_ptr(),\n GENERIC_READ | GENERIC_WRITE,\n SHARE,\n null(),\n OPEN_EXISTING,"
    ));
    assert!(caught("let f = NtCreateFile(&mut h, a, &o, &mut s"));
    assert!(!caught(
        "CreateFileW(\n name.as_ptr(),\n GENERIC_READ,\n SHARE,\n null(),\n OPEN_EXISTING,"
    ));
    assert!(!caught("/// `\\\\.\\PhysicalDriveN`, for people"));
}

/// The guard: this module's one CreateFileW is `open`, and a write right is given only to
/// the types that act: the replacement drive's writer and its volumes, a grown volume, the
/// repair's copy and the ATA handle.
#[test]
fn write_rights_are_given_only_to_the_acting_types() {
    let code = code();
    assert_eq!(code.matches("CreateFileW(").count(), 1, "a second open");
    assert!(body("fn open(path: &str, access: Access", "").contains("rights(access)"));
    assert_eq!(rights(Access::Query), 0);
    assert_eq!(rights(Access::Read) & GENERIC_WRITE, 0);
    assert_ne!(rights(Access::ReadWrite) & GENERIC_WRITE, 0);
    // The match arm in `rights` and the six acts.
    assert_eq!(code.matches("Access::ReadWrite").count(), 7);
    for act in [
        "    pub fn open(disk: &'a HeldDisk, confirmed: &Identity)",
        "    pub fn close_volume(&mut self, guid: &str)",
        "    pub(crate) fn close_volume(&self, guid: &str) -> Result<Handle, String>",
        "pub fn extend_ntfs(disk: &HeldDisk, guid: &str, offset: u64)",
        "    pub fn open(\n        number: u32,\n        source: &crate::recovery::dest::Protected,",
        "    pub fn open(disk: &HeldDisk) -> Result<Self, String>",
    ] {
        let indent = if act.starts_with("    ") { "    " } else { "" };
        assert!(body(act, indent).contains("Access::ReadWrite"), "{act}");
    }
    // Every other open asks for no right, or for reading.
    for call in [
        "open(path, Access::Query, 0)",
        "open(&disk_path(number), Access::Query, 0)",
        "open(&disk_path(number), access, 0)",
    ] {
        assert!(code.contains(call), "{call}");
    }
}

/// The guard: each act's handle is proven before it is used. The writer checks the new
/// handle's number and identity against the confirmed drive and then that the held handle
/// still answers to the number; each volume is checked to lie on the held disk alone before
/// it is locked or dismounted; a grown volume likewise before it is extended; the ATA handle
/// is checked to be the held disk, and the read limit's drive by model and serial number
/// before it is kept.
#[test]
fn every_act_takes_a_handle_proven_to_be_its_drive() {
    let open = body(
        "    pub fn open(disk: &'a HeldDisk, confirmed: &Identity)",
        "    ",
    );
    let order = |text: &str, steps: &[&str]| {
        let at: Vec<usize> = steps
            .iter()
            .map(|s| text.find(s).unwrap_or_else(|| panic!("no {s}")))
            .collect();
        assert!(
            at.windows(2).all(|w| w[0] < w[1]),
            "out of order: {steps:?}"
        );
    };
    order(
        open,
        &[
            "Access::ReadWrite",
            "match device_number(&handle) {",
            "let now = Identity::read(&handle)",
            "if &now != confirmed {",
            "disk.still_held()",
            "Ok(Self {",
        ],
    );
    let volume = body("    pub fn close_volume(&mut self, guid: &str)", "    ");
    order(
        volume,
        &[
            "Access::ReadWrite",
            "let extents = extents_of(&handle)",
            "extents.iter().any(|(d, _, _)| *d != number)",
            ".still_held()",
            "handle, late)",
            "self.volumes.push(handle);",
        ],
    );
    // A volume of the repair's copy is closed (for the table write, and before the detach)
    // only once the copy is proven and the volume found on it alone.
    let copy_volume = body(
        "    pub(crate) fn close_volume(&self, guid: &str) -> Result<Handle, String>",
        "    ",
    );
    order(
        copy_volume,
        &[
            "let number = self.check()?;",
            "Access::ReadWrite",
            "let extents = extents_of(&handle)",
            "extents.iter().any(|(d, _, _)| *d != number)",
            "handle, late)",
            "Waited::Done((handle, _, Ok(()))) => Ok(handle)",
        ],
    );
    // The lock, the write out and the dismount, in that order, on the handle that was
    // proven.
    let closing = body("fn lock_and_dismount(", "");
    order(
        closing,
        &[
            "FSCTL_LOCK_VOLUME",
            "FlushFileBuffers(handle.0)",
            "FSCTL_DISMOUNT_VOLUME",
            "(handle, locked, flushed.and(dismounted))",
        ],
    );
    let extend = body("pub fn extend_ntfs(disk: &HeldDisk", "");
    order(
        extend,
        &[
            "Access::ReadWrite",
            "let extents = extents_of(&handle)",
            "*at == offset",
            "disk.still_held()?;",
            "FSCTL_EXTEND_VOLUME",
        ],
    );
    let again = body("    fn again(&self, access: Access, flags: u32)", "    ");
    assert!(again.ends_with("self.still_held()?;\n        Ok(handle)"));
    let ata = body(
        "    pub fn open(disk: &HeldDisk) -> Result<Self, String>",
        "    ",
    );
    order(
        ata,
        &[
            "Access::ReadWrite",
            "match device_number(&handle) {",
            "let bus = bus_of(&handle)",
            "let carrier = ata::carrier(Some(bus))?;",
            "disk.still_held()?;",
            "Ok(Self {\n            handle,\n            carrier,\n            twelve: AtomicBool::new(false),\n        })",
        ],
    );
    let sct = body(
        "    pub fn open(number: u32, model: &str, serial: &str)",
        "    ",
    );
    order(
        sct,
        &[
            "HeldDisk::open(number)",
            "device::ata_bus(bus)?;",
            "AtaDisk::open(&held)",
            "ata.descriptor()",
            "device::ata_bus(Some(identity.bus))?;",
            "device::same_drive(",
            "ata.read(AtaCommand::Identify)",
            "Ok(Self { ata })",
        ],
    );
    let code = code();
    assert_eq!(
        code.matches("Self { ata }").count(),
        1,
        "made other than by open"
    );
    let send = body("    pub fn send(&self, request: sct::Request)", "    ");
    assert!(send.contains(".ata\n            .execute(&ata::Command::sct(request))"));
    // The copy is checked through its handle before every write.
    let table = body("    pub fn write_table(", "    ");
    order(
        table,
        &[
            "self.check()?;",
            "IOCTL_DISK_CREATE_DISK",
            "self.check()?;\n        control(\n            &self.handle,\n            IOCTL_DISK_SET_DRIVE_LAYOUT_EX",
        ],
    );
}

/// The guard: an ATA command is sent only by `AtaDisk::execute`, which takes an
/// `ata::Command` (built only as one of the three reads or the SCT read limit, `ata`'s
/// guard), sends it through the control its carrier and direction call for with bytes built
/// from that command, and checks the drive's answer last. The controls' codes are checked
/// against CTL_CODE.
#[test]
fn ata_commands_go_only_through_the_one_transport() {
    // CTL_CODE(IOCTL_SCSI_BASE 4, function, METHOD_BUFFERED 0, read and write access 3).
    let ctl_code = |function: u32| (4 << 16) | (3 << 14) | (function << 2);
    assert_eq!(IOCTL_ATA_PASS_THROUGH, ctl_code(0x40B));
    assert_eq!(IOCTL_SCSI_PASS_THROUGH, ctl_code(0x401));
    assert_eq!(SMART_RCV_DRIVE_DATA, (7 << 16) | (3 << 14) | (0x22 << 2));
    let code = without_comments(code());
    // Each control is named where it is imported or defined, and once where it is sent.
    for control in [
        "SMART_RCV_DRIVE_DATA",
        "IOCTL_ATA_PASS_THROUGH",
        "IOCTL_SCSI_PASS_THROUGH",
    ] {
        assert_eq!(
            code.matches(control).count(),
            2,
            "{control} is sent elsewhere"
        );
    }
    assert!(!code.contains("SMART_SEND_DRIVE_COMMAND"));
    let execute = body("    pub fn execute(&self, command: &ata::Command)", "    ");
    for (carrier, control, input) in [
        (
            "(Carrier::Windows, Direction::In)",
            "SMART_RCV_DRIVE_DATA,",
            "&ata::smart_rcv_input(command),",
        ),
        (
            "(Carrier::Windows, Direction::Out)",
            "IOCTL_ATA_PASS_THROUGH,",
            "&ata::pass_through_input(command),",
        ),
        (
            "(Carrier::Sat, _)",
            "IOCTL_SCSI_PASS_THROUGH,",
            "&sat::input(command, form),",
        ),
    ] {
        let arm = &execute[execute
            .find(carrier)
            .unwrap_or_else(|| panic!("no {carrier}"))..];
        let (at_control, at_input) = (arm.find(control).unwrap(), arm.find(input).unwrap());
        assert!(at_control < at_input && at_input < 200, "{carrier}");
    }
    assert!(execute.ends_with("ata::checked(command, answer)"));
    // Every command made in this module is one `ata::Command` builds.
    let made: Vec<&str> = code
        .match_indices("ata::Command::")
        .map(|(at, _)| &code[at..at + code[at..].find('(').unwrap()])
        .collect();
    assert_eq!(made, ["ata::Command::read", "ata::Command::sct"]);
    assert_eq!(
        code.matches(".execute(").count(),
        2,
        "execute called elsewhere"
    );
}

/// The guard: the disk is put back online only when this tool took it offline and it is
/// still offline; a disk that was offline already is never brought online, and a state that
/// cannot be read is left and said.
#[test]
fn offline_is_undone_only_when_this_tool_did_it_and_it_still_holds() {
    let offline = DISK_ATTRIBUTE_OFFLINE;
    assert_eq!(offline_step(Ok(offline)), Offline::Already);
    assert_eq!(offline_step(Ok(0)), Offline::Take);
    assert_eq!(offline_step(Err(1)), Offline::Unknown);
    assert_eq!(online_step(true, Ok(offline)), Online::Bring);
    assert_eq!(
        online_step(true, Ok(0)),
        Online::Leave,
        "online again since"
    );
    assert_eq!(
        online_step(false, Ok(offline)),
        Online::Leave,
        "offline before"
    );
    assert_eq!(online_step(true, Err(5)), Online::Unknown(5));
    assert_eq!(online_step(false, Err(5)), Online::Leave);
    let take = body("    pub fn take_offline(&mut self) -> bool", "    ");
    // Taken offline in one owned job, read and set together; one that ends late is brought
    // online again at once.
    assert!(take.contains("let step = offline_step(disk_attributes(&handle));"));
    assert!(take.contains("step == Offline::Take && set_offline(&handle, true).is_ok()"));
    assert!(take.contains("if !took {") && take.contains("set_offline(&handle, false)"));
    assert_eq!(take.matches("set_offline(").count(), 2);
    let release = body("    fn release(&mut self) -> Result<(), String>", "    ");
    assert!(release.contains("let step = online_step(took, disk_attributes(&handle));"));
    assert!(release.contains("(step == Online::Bring).then(|| set_offline(&handle, false))"));
    assert_eq!(release.matches("set_offline(").count(), 1);
}

/// The guard: unknown is never taken as fine on the paths that change a disk. Mechanical
/// patterns, across all of src/: a sector size is never defaulted where it is read; the
/// guards that keep the replacement drive off the system's disks never default a failure
/// to nothing; and no Drop in the files that write a disk throws a result away.
#[test]
fn unknown_is_never_taken_as_fine_on_the_disk_paths() {
    let mut broken = Vec::new();
    for (name, code) in sources() {
        for (at, _) in code.match_indices("logical_sector(") {
            let rest = &code[at..];
            let statement = &rest[..rest.find(';').unwrap_or(rest.len())];
            if statement.contains(".unwrap_or") {
                broken.push(format!("{name} defaults an unread sector size"));
            }
        }
        if [
            "handles.rs",
            "recovery/target.rs",
            "recovery/repair.rs",
            "recovery/read_limit.rs",
        ]
        .contains(&name.as_str())
        {
            for (at, _) in code.match_indices("impl Drop for ") {
                let rest = &code[at..];
                let item = &rest[..rest.find("\n}\n").unwrap()];
                if item.contains("let _ =") {
                    broken.push(format!("{name} throws a result away in a Drop"));
                }
            }
        }
        if name == "handles.rs" && code.contains("let _ =") {
            broken.push(format!("{name} throws a result away"));
        }
        if name == "recovery/target.rs" {
            let guards = &code[code.find("pub fn gather_guards(").unwrap()..];
            let guards = &guards[..guards.find("\n}\n").unwrap()];
            for default in [".unwrap_or_default()", ".ok()", ".unwrap_or("] {
                if guards.contains(default) {
                    broken.push(format!("{name} gather_guards uses {default}"));
                }
            }
        }
    }
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

#[test]
fn extents_are_read_with_their_offsets_and_lengths() {
    let mut reply = vec![0u8; 8 + 48];
    reply[..4].copy_from_slice(&2u32.to_le_bytes());
    reply[8..12].copy_from_slice(&3u32.to_le_bytes());
    reply[16..24].copy_from_slice(&1_048_576u64.to_le_bytes());
    reply[24..32].copy_from_slice(&5_000u64.to_le_bytes());
    reply[32..36].copy_from_slice(&4u32.to_le_bytes());
    reply[40..48].copy_from_slice(&7u64.to_le_bytes());
    reply[48..56].copy_from_slice(&9u64.to_le_bytes());
    assert_eq!(
        parse_extents(&reply),
        vec![(3, 1_048_576, 5_000), (4, 7, 9)]
    );
    assert!(parse_extents(&[]).is_empty());
}

#[test]
fn the_disk_id_and_location_are_read() {
    let mut mbr = vec![0u8; 48];
    mbr[8..12].copy_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    assert_eq!(parse_disk_id(&mbr), "1A2B3C4D");
    let mut gpt = vec![0u8; 48];
    gpt[..4].copy_from_slice(&1u32.to_le_bytes());
    gpt[8..24].copy_from_slice(&[
        0x4D, 0x3C, 0x2B, 0x1A, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0, 0, 0, 0, 0, 1,
    ]);
    assert_eq!(
        parse_disk_id(&gpt),
        "{1A2B3C4D-0000-4000-8000-000000000001}"
    );
    let mut blank = vec![0u8; 48];
    blank[..4].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(parse_disk_id(&blank), "");
    assert_eq!(parse_disk_id(&[0u8; 48]), "", "an MBR with no signature");
    assert_eq!(parse_location(&[8, 0, 0, 0, 3, 0, 1, 0]), "3:0:1:0");
    assert_eq!(parse_location(&[]), "");
}

/// The guard: the source disk and Windows' own disk are never opened for writing as a
/// repair's copy; both are refused before anything is opened.
#[test]
fn no_disk_but_the_copy_is_opened_for_writing() {
    let file = (0, [0u8; 16]);
    let err = CopyDisk::open(7, &crate::recovery::dest::Protected::disk(7), file)
        .err()
        .unwrap();
    assert!(err.contains("never written"), "{err}");
    for system in system_disks() {
        let err = CopyDisk::open(system, &crate::recovery::dest::Protected::default(), file)
            .err()
            .unwrap();
        assert!(err.contains("Windows itself"), "{err}");
    }
}

/// A handle that is not a disk, or whose file is not the copy, is refused as the copy, and
/// nothing is written through it.
#[test]
fn a_handle_that_is_not_the_copy_is_refused() {
    let path = std::env::temp_dir().join(format!("diagtool-copy-{}", std::process::id()));
    std::fs::write(&path, [7u8; 512]).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let handle = Handle(std::os::windows::io::IntoRawHandle::into_raw_handle(file));
    let file = crate::recovery::dest::id_of_path(&path).unwrap();
    let copy = CopyDisk { handle, file };
    let err = copy.check().unwrap_err();
    assert!(err.contains("nothing was written"), "{err}");
    let create = CREATE_DISK::default();
    assert!(copy.write_table(&create, &[0u64; 8], 64, &[]).is_err());
    // A volume to close is refused through the same check, before it is opened.
    let err = copy
        .write_table(&create, &[0u64; 8], 64, &[r"\\?\Volume{0}\".into()])
        .unwrap_err();
    assert!(err.contains("nothing was written"), "{err}");
    assert!(copy.holds_volume(r"\\?\Volume{0}").is_err());
    drop(copy);
    assert_eq!(std::fs::read(&path).unwrap(), [7u8; 512]);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        join_backing(r"\\?\Volume{1}\", r"\qa\x.vhd"),
        r"\\?\Volume{1}\qa\x.vhd"
    );
    assert_eq!(
        join_backing(r"\\?\Volume{1}", r"qa\x.vhd"),
        r"\\?\Volume{1}\qa\x.vhd"
    );
}

/// A disk number that is not connected is named so, and nothing is held.
#[test]
fn a_disk_that_is_not_there_is_not_held() {
    let err = HeldDisk::open(31).err().unwrap();
    let said = failure(31, err);
    assert!(
        said.contains("not connected") || said.contains("administrator"),
        "{said}"
    );
}
