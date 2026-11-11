//! Set up and Put back: the only code in the engine that writes. Set up saves every value
//! it is about to change, as it was, before writing anything; Put back restores those
//! values byte for byte and removes what set up made when it is still empty.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use super::hold;
use super::machine::{
    FolderAccess, Hive, Key, Machine, PathKind, RawValue, VolumeKind, AEDEBUG, CRASH_CONTROL,
    LOCAL_DUMPS,
};
use super::places::{remove_folder, remove_key, restore_value, shown, Custody};
use super::readiness::{
    backing, fits, kind_name, too_small_text, Fit, Reader, APP_FULL_ROOM, APP_MINI_ROOM,
    MINIDUMP_ROOM,
};
use super::{
    dump_room, plain_path, same_place, AppDumpType, AppOptions, Change, ChangeResult, Event,
    KernelDumpType, KernelOptions, Outcome, PutBackOptions, SetUpOptions, BACKUP_FILE,
    DEFAULT_MINIDUMP_FOLDER, MAX_APP_DUMPS,
};
use crate::restore::PutBack;
use crate::tools::drives::bytes_text;

/// Variables a kernel dump path may hold: Windows writes the dump before anyone signs in.
const KERNEL_VARIABLES: &[&str] = &["SystemRoot"];
/// Variables an application dump folder may hold: the same for every account.
const APP_VARIABLES: &[&str] = &["SystemRoot", "windir", "SystemDrive", "ProgramData"];
/// The values set up writes under CrashControl.
const KERNEL_NAMES: [&str; 8] = [
    "CrashDumpEnabled",
    "FilterPages",
    "DumpFile",
    "MinidumpDir",
    "AlwaysKeepMemoryDump",
    "LogEvent",
    "Overwrite",
    "AutoReboot",
];
/// The values set up writes under LocalDumps.
const APP_NAMES: [&str; 3] = ["DumpFolder", "DumpType", "DumpCount"];
/// The one value set up writes under this program's own LocalDumps key.
pub(super) const OWN_NAME: &str = "DumpCount";
/// The format set up writes: 2 records each folder's identity, 3 what set up wrote to each
/// value and when it last wrote to each key it made, which Put back compares with what is
/// there now.
const BACKUP_VERSION: u32 = 3;
/// The most a saved value holds: a path of 260 characters is 522 bytes.
pub(super) const MAX_SAVED_BYTES: usize = 4096;

/// This program's own key under LocalDumps, which set up makes so that Windows keeps no
/// dump of it: while it holds a BitLocker recovery key its memory holds the key.
pub(super) fn own_key(exe: &str) -> String {
    format!("{}\\{exe}", LOCAL_DUMPS.path)
}

/// The values as they were before set up first changed them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Backup {
    /// Format version: 2, or 1 from before folders carried their identity.
    version: u32,
    values: Vec<Saved>,
    /// Keys that did not exist before set up made them, parents first.
    keys_made: Vec<String>,
    /// Folders set up made, parents first.
    folders_made: Vec<PathBuf>,
    /// Each made folder's identity, read once it was made; Put back removes a folder only
    /// while it still has it.
    #[serde(default)]
    folder_ids: Vec<(PathBuf, String)>,
    /// When set up last wrote to each key it made (`Machine::key_stamp`); Put back removes
    /// a key only while it still reads so. Format 3.
    #[serde(default)]
    key_stamps: Vec<(String, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    hive: Hive,
    key: String,
    name: String,
    /// `None`: the value was absent.
    before: Option<RawValue>,
    /// What set up last wrote there (`None`: it deleted the value). Put back puts the value
    /// back only while it still holds this. Format 3.
    #[serde(default)]
    after: Option<RawValue>,
}

/// One value to write (`Some`) or delete (`None`).
struct Write {
    hive: Hive,
    key: String,
    name: &'static str,
    value: Option<RawValue>,
    before: Option<RawValue>,
}

impl Write {
    fn named(&self) -> String {
        format!("{}\\{}\\{}", self.hive.name(), self.key, self.name)
    }
}

#[derive(Default)]
struct Plan {
    writes: Vec<Write>,
    /// Folders to make, parents first.
    folders: Vec<(PathBuf, FolderAccess)>,
    make_local_dumps: bool,
    /// This program's own LocalDumps key, when set up makes it.
    make_own_key: Option<String>,
    notes: Vec<String>,
}

fn label(key: &str, name: &str) -> &'static str {
    let own = key.len() > LOCAL_DUMPS.path.len()
        && key[..LOCAL_DUMPS.path.len()].eq_ignore_ascii_case(LOCAL_DUMPS.path);
    if own && name == OWN_NAME {
        return "Dumps of this app kept";
    }
    match name {
        "CrashDumpEnabled" => "Kernel dump type",
        "FilterPages" => "Active memory dump filter",
        "DumpFile" => "Memory dump file",
        "MinidumpDir" => "Small memory dump folder",
        "AlwaysKeepMemoryDump" => "Keep the memory dump when space is low",
        "LogEvent" => "Write each stop to the System log",
        "Overwrite" => "Replace the last memory dump",
        "AutoReboot" => "Restart after a stop",
        "DumpFolder" => "Application dump folder",
        "DumpType" => "Application dump type",
        "DumpCount" => "Application dumps kept",
        _ => "Value",
    }
}

/// A value as a technician reads it: the stored value and what it means.
fn describe(name: &str, value: Option<&RawValue>) -> String {
    let Some(value) = value else {
        return "absent".into();
    };
    let Some(number) = value.as_dword() else {
        return value.describe();
    };
    let meaning = match name {
        "CrashDumpEnabled" => match KernelDumpType::from_registry(number, None) {
            Ok(None) => Some("none".to_string()),
            Ok(Some(KernelDumpType::Complete)) => {
                Some("complete, or active with FilterPages".into())
            }
            Ok(Some(dump)) => Some(dump.name().into()),
            Err(_) => None,
        },
        "DumpType" => match number {
            0 => Some("custom dump".into()),
            1 => Some(AppDumpType::Mini.name().into()),
            2 => Some(AppDumpType::Full.name().into()),
            _ => None,
        },
        "DumpCount" => None,
        _ => Some(if number == 0 { "off" } else { "on" }.into()),
    };
    match meaning {
        Some(meaning) => format!("{number} ({meaning})"),
        None => number.to_string(),
    }
}

fn change(
    hive: Hive,
    key: &str,
    name: &str,
    before: Option<&RawValue>,
    after: Option<&RawValue>,
) -> Change {
    let (before, after) = (describe(name, before), describe(name, after));
    Change {
        target: format!("{}\\{key}\\{name}", hive.name()),
        text: format!("{}: {before} to {after}", label(key, name)),
        before,
        after,
        needs_restart: key.eq_ignore_ascii_case(CRASH_CONTROL.path),
    }
}

fn folder_change(path: &Path, made: bool) -> Change {
    let (before, after) = if made {
        ("absent", "made")
    } else {
        ("made by set up", "removed")
    };
    Change {
        target: path.display().to_string(),
        before: before.into(),
        after: after.into(),
        text: if made {
            format!("Folder {} made", path.display())
        } else {
            format!("Folder {} removed", path.display())
        },
        needs_restart: false,
    }
}

/// Only the variables in `allowed` may appear in `text`.
fn check_variables(text: &str, allowed: &[&str], what: &str) -> Result<(), String> {
    let parts: Vec<&str> = text.split('%').collect();
    if parts.len().is_multiple_of(2) {
        return Err(format!("{what} {text} has an unpaired %"));
    }
    for name in parts.iter().skip(1).step_by(2) {
        if !allowed.iter().any(|a| a.eq_ignore_ascii_case(name)) {
            let allowed: Vec<String> = allowed.iter().map(|a| format!("%{a}%")).collect();
            return Err(format!(
                "{what} {text} uses %{name}%; only {} may be used here",
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

/// Expands and checks a path: plain, on a local fixed disk.
fn local_path<M: Machine>(
    m: &M,
    text: &str,
    allowed: &[&str],
    what: &str,
) -> Result<(PathBuf, u64), String> {
    check_variables(text, allowed, what)?;
    let path = plain_path(&m.expand(text)?).map_err(|why| format!("{what}: {why}"))?;
    let volume = m.volume(&path)?;
    if volume.kind != VolumeKind::Fixed {
        return Err(format!(
            "{what} {} is on a {} drive; crash dumps need a local fixed disk",
            path.display(),
            kind_name(volume.kind)
        ));
    }
    Ok((path, volume.free))
}

/// Plans to make `folder` and any missing parents. Every part of the path, from the folder
/// up to its drive, must be a plain folder or missing: a junction or link in any part would
/// put the dumps in another place. The deepest part that exists must also resolve to
/// itself (a mount point, a substituted drive), and each folder made is checked again.
fn plan_folder<M: Machine>(
    m: &M,
    folder: &Path,
    access: FolderAccess,
    plan: &mut Plan,
) -> Result<bool, String> {
    let mut missing = Vec::new();
    let mut existing: Option<&Path> = None;
    for path in folder.ancestors() {
        match m.folder(path)? {
            PathKind::Folder => {
                existing.get_or_insert(path);
            }
            PathKind::Missing if existing.is_none() => missing.push(path.to_path_buf()),
            PathKind::Missing => {
                return Err(format!(
                    "{} reads as missing above a folder that exists",
                    path.display()
                ))
            }
            PathKind::Link => {
                return Err(format!(
                "{} is a link to another place; choose a folder that is not reached through one",
                path.display()
            ))
            }
            PathKind::File => return Err(format!("{} is a file, not a folder", path.display())),
        }
    }
    if let Some(existing) = existing {
        let real = m.resolved(existing)?;
        if !same_place(&real, &m.long_name(existing)?) {
            return Err(format!(
                "{} leads to {}; choose a folder that is not reached through a link",
                existing.display(),
                real.display()
            ));
        }
    }
    let made = !missing.is_empty();
    for path in missing.into_iter().rev() {
        let access = if path == folder {
            access
        } else {
            FolderAccess::Inherited
        };
        if !plan.folders.iter().any(|(p, _)| same_place(p, &path)) {
            plan.folders.push((path, access));
        }
    }
    Ok(made)
}

/// Adds a write unless the value already holds it.
fn want<M: Machine>(
    r: &mut Reader<'_, M>,
    plan: &mut Plan,
    key: Key,
    name: &'static str,
    value: Option<RawValue>,
) -> Result<(), String> {
    let before = r.get(key, name)?;
    if before == value {
        return Ok(());
    }
    plan.writes.push(Write {
        hive: key.hive,
        key: key.path.into(),
        name,
        value,
        before,
    });
    Ok(())
}

/// Writes a path value unless the one there already names the same place.
fn want_path<M: Machine>(
    r: &mut Reader<'_, M>,
    plan: &mut Plan,
    key: Key,
    name: &'static str,
    text: &str,
    path: &Path,
) -> Result<(), String> {
    let before = r.get(key, name)?;
    let same = before
        .as_ref()
        .and_then(RawValue::as_text)
        .and_then(|old| r.m.expand(&old).ok())
        .is_some_and(|old| same_place(Path::new(&old), path));
    if same {
        return Ok(());
    }
    plan.writes.push(Write {
        hive: key.hive,
        key: key.path.into(),
        name,
        value: Some(RawValue::expand_string(text)),
        before,
    });
    Ok(())
}

fn plan_kernel<M: Machine>(
    r: &mut Reader<'_, M>,
    k: &KernelOptions,
    plan: &mut Plan,
    refusals: &mut Vec<String>,
) -> Result<(), String> {
    let dump = k.dump_type;
    let memory = r.m.memory()?;
    let room = dump_room(dump, memory.physical, memory.kernel);
    let b = backing(r)?;
    if let Fit::TooSmall { needed, why } = fits(room, &b) {
        refusals.push(too_small_text(dump, needed, &why, b.windows_drive));
    }
    match local_path(r.m, &k.dump_file, KERNEL_VARIABLES, "The memory dump file") {
        Err(why) => refusals.push(why),
        Ok((file, free)) => {
            let named_dmp = file
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("dmp"));
            if !named_dmp {
                refusals.push(format!(
                    "The memory dump file {} must be a file name ending in .dmp",
                    file.display()
                ));
            } else if matches!(r.m.folder(&file)?, PathKind::Folder | PathKind::Link) {
                refusals.push(format!("{} is a folder, not a file", file.display()));
            } else {
                let existing = r.m.file_size(&file)?.unwrap_or(0);
                if dump != KernelDumpType::Small && free + existing < room {
                    refusals.push(format!(
                        "The drive for {} has {} free; {} needs about {}",
                        file.display(),
                        bytes_text(free),
                        dump.with_article(),
                        bytes_text(room)
                    ));
                }
                if let Some(parent) = file.parent() {
                    if let Err(why) = plan_folder(r.m, parent, FolderAccess::Inherited, plan) {
                        refusals.push(why);
                    }
                }
                want_path(r, plan, CRASH_CONTROL, "DumpFile", &k.dump_file, &file)?;
            }
        }
    }
    match local_path(
        r.m,
        &k.minidump_folder,
        KERNEL_VARIABLES,
        "The small memory dump folder",
    ) {
        Err(why) => refusals.push(why),
        Ok((folder, free)) => {
            if free < MINIDUMP_ROOM {
                refusals.push(format!(
                    "The drive for {} has {} free; small memory dumps need {}",
                    folder.display(),
                    bytes_text(free),
                    bytes_text(MINIDUMP_ROOM)
                ));
            }
            // Windows makes its own Minidump folder at the first small dump; another
            // folder is made here, so a missing one never costs a dump.
            let default = r.m.expand(DEFAULT_MINIDUMP_FOLDER)?;
            if !same_place(&folder, Path::new(&default)) {
                if let Err(why) = plan_folder(r.m, &folder, FolderAccess::Inherited, plan) {
                    refusals.push(why);
                }
            }
            want_path(
                r,
                plan,
                CRASH_CONTROL,
                "MinidumpDir",
                &k.minidump_folder,
                &folder,
            )?;
        }
    }
    let enabled = Some(RawValue::dword(dump.crash_dump_enabled()));
    want(r, plan, CRASH_CONTROL, "CrashDumpEnabled", enabled)?;
    match dump {
        KernelDumpType::Active => want(
            r,
            plan,
            CRASH_CONTROL,
            "FilterPages",
            Some(RawValue::dword(1)),
        )?,
        // FilterPages 1 would turn a complete dump into an active one.
        KernelDumpType::Complete => want(r, plan, CRASH_CONTROL, "FilterPages", None)?,
        _ => {}
    }
    for name in ["AlwaysKeepMemoryDump", "LogEvent", "Overwrite"] {
        want(r, plan, CRASH_CONTROL, name, Some(RawValue::dword(1)))?;
    }
    if let Some(restart) = k.restart_after_stop {
        let value = Some(RawValue::dword(u32::from(restart)));
        want(r, plan, CRASH_CONTROL, "AutoReboot", value)?;
    }
    Ok(())
}

fn plan_apps<M: Machine>(
    r: &mut Reader<'_, M>,
    a: &AppOptions,
    plan: &mut Plan,
    refusals: &mut Vec<String>,
) -> Result<(), String> {
    if !(1..=MAX_APP_DUMPS).contains(&a.count) {
        refusals.push(format!(
            "The number of application dumps kept must be 1 to {MAX_APP_DUMPS}, not {}",
            a.count
        ));
    }
    if a.dump_type == AppDumpType::Full && r.m.key_held() {
        refusals.push("Full application dumps cannot be set up now: this app holds, or has held since it started, a BitLocker recovery key, and a full dump holds a program's memory. Close the app, start it again without unlocking a drive, and set up then".into());
    }
    let room = match a.dump_type {
        AppDumpType::Mini => APP_MINI_ROOM * u64::from(a.count.clamp(1, MAX_APP_DUMPS)),
        AppDumpType::Full => APP_FULL_ROOM,
    };
    match local_path(r.m, &a.folder, APP_VARIABLES, "The application dump folder") {
        Err(why) => refusals.push(why),
        Ok((folder, free)) => {
            if free < room {
                refusals.push(format!(
                    "The drive for {} has {} free; {} {}s need about {}",
                    folder.display(),
                    bytes_text(free),
                    a.count,
                    a.dump_type.name(),
                    bytes_text(room)
                ));
            }
            match plan_folder(r.m, &folder, FolderAccess::CrashingProcesses, plan) {
                Err(why) => refusals.push(why),
                Ok(true) => plan.notes.push(format!(
                    "{} is made so that a crashing program of any signed-in account can add its dump, while each dump can be opened only by the account it came from, administrators and SYSTEM: a dump holds the program's memory, which can include what the person was working on.",
                    folder.display()
                )),
                Ok(false) => plan.notes.push(format!(
                    "{} already exists, so its permissions are left as they were; programs of other accounts can write dumps there only if those permissions let them.",
                    folder.display()
                )),
            }
            want_path(r, plan, LOCAL_DUMPS, "DumpFolder", &a.folder, &folder)?;
        }
    }
    plan.make_local_dumps = !r.m.key_exists(LOCAL_DUMPS.hive, LOCAL_DUMPS.path)?;
    let kind = Some(RawValue::dword(a.dump_type.value()));
    want(r, plan, LOCAL_DUMPS, "DumpType", kind)?;
    want(
        r,
        plan,
        LOCAL_DUMPS,
        "DumpCount",
        Some(RawValue::dword(a.count)),
    )?;
    Ok(())
}

/// Leaves this program out of application dumps whenever LocalDumps is on after set up:
/// its own LocalDumps key with DumpCount 0, which Windows reads as keep none (measured on
/// Windows 11 for an access violation and a fail fast). Planned before every other write,
/// so no moment of the set up leaves it in.
fn plan_own_app<M: Machine>(m: &M, apps_chosen: bool, plan: &mut Plan) -> Result<(), String> {
    if !apps_chosen && !m.key_exists(LOCAL_DUMPS.hive, LOCAL_DUMPS.path)? {
        return Ok(());
    }
    let exe = m.exe_name()?;
    let key = own_key(&exe);
    let before = m.read_value(LOCAL_DUMPS.hive, &key, OWN_NAME)?;
    let off = Some(RawValue::dword(0));
    if before == off {
        return Ok(());
    }
    if !m.key_exists(LOCAL_DUMPS.hive, &key)? {
        plan.make_own_key = Some(key.clone());
    }
    plan.notes.push(format!(
        "{exe} is left out of application dumps (HKLM\\{key}, DumpCount 0): while it holds a BitLocker recovery key, a dump of it would hold the key."
    ));
    plan.writes.push(Write {
        hive: LOCAL_DUMPS.hive,
        key,
        name: OWN_NAME,
        value: off,
        before,
    });
    Ok(())
}

/// Ok unless AeDebug starts a debugger by itself when a program crashes, which could save
/// this program's memory with a recovery key in it (see `crash_dumps::keep_out_of_dumps`).
pub(crate) fn debugger_off<M: Machine>(m: &M) -> Result<(), String> {
    let unread = |why: String| {
        format!("Whether a debugger starts by itself on a crash could not be read ({why}), so no recovery key is taken in.")
    };
    let auto = m
        .read_value(AEDEBUG.hive, AEDEBUG.path, "Auto")
        .map_err(unread)?;
    let debugger = m
        .read_value(AEDEBUG.hive, AEDEBUG.path, "Debugger")
        .map_err(unread)?;
    let auto = auto
        .and_then(|v| v.as_text())
        .is_some_and(|t| t.trim() == "1");
    let debugger = debugger
        .and_then(|v| v.as_text())
        .is_some_and(|t| !t.trim().is_empty());
    if auto && debugger {
        return Err("A debugger is set to start by itself when a program crashes (AeDebug Auto is 1), and it could save this app's memory, with the recovery key in it. Set AeDebug Auto to 0, or remove the debugger, then unlock.".into());
    }
    Ok(())
}

/// Hands the recovery window's exclusion over to set up's saved settings when set up is in
/// effect: the value as it was before the exclusion, and the keys made for it, become set
/// up's to put back. Ok(false) when set up has nothing saved, so the caller puts them back.
pub(super) fn take_over<M: Machine>(m: &mut M, hold: &super::hold::Hold) -> Result<bool, String> {
    let path = backup_path(m)?;
    let Some(mut backup) = read_backup(m, &path)? else {
        return Ok(false);
    };
    if backup.version < BACKUP_VERSION {
        return Err(old_format_refusal(&backup, &path));
    }
    let own = own_key(&hold.exe);
    // The exclusion wrote 0 over `hold.before`, which was there after set up: what set up
    // wrote was changed since, so the value the exclusion found is the one to put back.
    if hold.wrote {
        let saved = backup
            .values
            .iter_mut()
            .find(|v| v.key.eq_ignore_ascii_case(&own) && v.name.eq_ignore_ascii_case(OWN_NAME));
        match saved {
            Some(saved) => {
                saved.before = hold.before.clone();
                saved.after = Some(RawValue::dword(0));
            }
            None => backup.values.insert(
                0,
                Saved {
                    hive: Hive::LocalMachine,
                    key: own.clone(),
                    name: OWN_NAME.into(),
                    before: hold.before.clone(),
                    after: Some(RawValue::dword(0)),
                },
            ),
        }
    }
    for key in &hold.keys_made {
        // A key either side last wrote to and that still reads so stays set up's to
        // remove; any other is kept.
        let now = m.key_stamp(Hive::LocalMachine, key).ok().flatten();
        let stamp_of = |stamps: &[(String, u64)]| {
            stamps
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, s)| *s)
        };
        let still = now.filter(|now| {
            stamp_of(&hold.key_stamps) == Some(*now) || stamp_of(&backup.key_stamps) == Some(*now)
        });
        backup
            .key_stamps
            .retain(|(k, _)| !k.eq_ignore_ascii_case(key));
        if let Some(now) = still {
            backup.key_stamps.push((key.clone(), now));
        }
        if backup.keys_made.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            continue;
        }
        if key.eq_ignore_ascii_case(LOCAL_DUMPS.path) {
            backup.keys_made.insert(0, key.clone());
        } else {
            backup.keys_made.push(key.clone());
        }
    }
    backup.version = BACKUP_VERSION;
    let text = serde_json::to_string_pretty(&backup).map_err(|e| e.to_string())?;
    m.write_state(&path, &text)?;
    match read_backup(m, &path)? {
        Some(read) if read == backup => Ok(true),
        _ => Err(format!("{} did not read back as written", path.display())),
    }
}

pub(super) fn result(outcome: Outcome, backup: PathBuf) -> ChangeResult {
    ChangeResult {
        outcome,
        planned: Vec::new(),
        changed: Vec::new(),
        notes: Vec::new(),
        restart_needed: false,
        backup,
    }
}

fn backup_path<M: Machine>(m: &M) -> Result<PathBuf, String> {
    Ok(PathBuf::from(m.expand(BACKUP_FILE)?))
}

fn read_backup<M: Machine>(m: &M, path: &Path) -> Result<Option<Backup>, String> {
    let Some(text) = m.read_state(path)? else {
        return Ok(None);
    };
    let backup: Backup = serde_json::from_str(&text).map_err(|e| {
        format!(
            "the saved settings in {} could not be read ({e})",
            path.display()
        )
    })?;
    check_backup(&backup, &m.exe_name()?)
        .map_err(|why| format!("the saved settings in {} {why}", path.display()))?;
    Ok(Some(backup))
}

/// Ok when `after` is a value set up writes to `key\\name`: the type it writes, and a number
/// within what it writes; Err says what is wrong with it.
fn set_ups_value(key: &str, name: &str, after: Option<&RawValue>) -> Result<(), String> {
    let path_name = ["DumpFile", "MinidumpDir", "DumpFolder"]
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name));
    let own = key.len() > LOCAL_DUMPS.path.len()
        && key[..LOCAL_DUMPS.path.len()].eq_ignore_ascii_case(LOCAL_DUMPS.path);
    let number = after.and_then(RawValue::as_dword);
    let fits = match after {
        None => name.eq_ignore_ascii_case("FilterPages"),
        Some(value) if path_name => {
            value.kind == super::machine::REG_EXPAND_SZ
                && value.data.len() <= MAX_SAVED_BYTES
                && value.as_text().is_some_and(|t| !t.trim().is_empty())
        }
        Some(_) if own => number == Some(0),
        Some(_) => match number {
            None => false,
            Some(n) if name.eq_ignore_ascii_case("CrashDumpEnabled") => KernelDumpType::ALL
                .iter()
                .any(|t| t.crash_dump_enabled() == n),
            Some(n) if name.eq_ignore_ascii_case("DumpType") => n == 1 || n == 2,
            Some(n) if name.eq_ignore_ascii_case("DumpCount") => (1..=MAX_APP_DUMPS).contains(&n),
            Some(n) if name.eq_ignore_ascii_case("AutoReboot") => n <= 1,
            Some(n) => n == 1,
        },
    };
    if fits {
        Ok(())
    } else {
        Err(format!("{} is not a value set up writes", shown(after)))
    }
}

/// The refusal for a saved file from an older version, which did not record what set up
/// wrote: Put back cannot tell a value set up wrote from one changed since, so it changes
/// nothing and lists the values as they were, for putting back by hand.
fn old_format_refusal(backup: &Backup, path: &Path) -> String {
    let values: Vec<String> = backup
        .values
        .iter()
        .map(|v| {
            format!(
                "{}\\{}\\{} was {}",
                v.hive.name(),
                v.key,
                v.name,
                shown(v.before.as_ref())
            )
        })
        .collect();
    format!(
        "the saved settings in {} were written by an older version of this tool, which did not record what it wrote, so whether each value was changed since cannot be told and nothing was changed. Before set up: {}. Set them back by hand if they are still set up's, then delete that file",
        path.display(),
        if values.is_empty() {
            "nothing was saved".to_string()
        } else {
            values.join("; ")
        }
    )
}

/// Refuses a saved file that names anything set up does not write or make: each value is
/// one of set up's own under CrashControl, LocalDumps or this program's own LocalDumps key,
/// once, and no larger than a setting; the keys made are LocalDumps and that own key; the
/// folders are plain paths below a drive, once each, and every identity names one of them.
fn check_backup(backup: &Backup, exe: &str) -> Result<(), String> {
    if !matches!(backup.version, 1..=BACKUP_VERSION) {
        return Err(format!(
            "are in format {}, which this version does not read",
            backup.version
        ));
    }
    let own = own_key(exe);
    let allowed = |hive: Hive, key: &str, name: &str| {
        let named = |names: &[&str]| names.iter().any(|n| n.eq_ignore_ascii_case(name));
        hive == Hive::LocalMachine
            && ((key.eq_ignore_ascii_case(CRASH_CONTROL.path) && named(&KERNEL_NAMES))
                || (key.eq_ignore_ascii_case(LOCAL_DUMPS.path) && named(&APP_NAMES))
                || (key.eq_ignore_ascii_case(&own) && name.eq_ignore_ascii_case(OWN_NAME)))
    };
    for (i, v) in backup.values.iter().enumerate() {
        if !allowed(v.hive, &v.key, &v.name) {
            return Err(format!(
                "name {}\\{}\\{}, which set up never writes",
                v.hive.name(),
                v.key,
                v.name
            ));
        }
        if v.before
            .as_ref()
            .is_some_and(|b| b.data.len() > MAX_SAVED_BYTES)
        {
            return Err(format!(
                "hold {} bytes for {}, more than a setting",
                v.before.as_ref().map_or(0, |b| b.data.len()),
                v.name
            ));
        }
        // A write set up planned but never made leaves what was there before.
        if backup.version >= BACKUP_VERSION && v.after != v.before {
            if let Err(why) = set_ups_value(&v.key, &v.name, v.after.as_ref()) {
                return Err(format!("record {} as written by set up, but {why}", v.name));
            }
        }
        let twice = backup.values[..i].iter().any(|o| {
            o.hive == v.hive
                && o.key.eq_ignore_ascii_case(&v.key)
                && o.name.eq_ignore_ascii_case(&v.name)
        });
        if twice {
            return Err(format!("name {} twice", v.name));
        }
    }
    for (i, key) in backup.keys_made.iter().enumerate() {
        if !(key.eq_ignore_ascii_case(LOCAL_DUMPS.path) || key.eq_ignore_ascii_case(&own)) {
            return Err(format!(
                "name the key HKLM\\{key}, which set up never makes"
            ));
        }
        if backup.keys_made[..i]
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        {
            return Err(format!("name the key HKLM\\{key} twice"));
        }
    }
    for (i, folder) in backup.folders_made.iter().enumerate() {
        let text = folder.to_string_lossy();
        let plain = plain_path(&text).is_ok_and(|p| same_place(&p, folder));
        if !plain || folder.parent().is_none() {
            return Err(format!("name the folder {text}, which set up never makes"));
        }
        if backup.folders_made[..i]
            .iter()
            .any(|f| same_place(f, folder))
        {
            return Err(format!("name the folder {text} twice"));
        }
    }
    for (key, _) in &backup.key_stamps {
        if !backup.keys_made.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            return Err(format!(
                "hold when HKLM\\{key} was written, which is not a key set up made"
            ));
        }
    }
    for (folder, _) in &backup.folder_ids {
        if !backup.folders_made.iter().any(|f| same_place(f, folder)) {
            return Err(format!(
                "hold an identity for {}, which is not a folder set up made",
                folder.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn set_up<M: Machine>(
    m: &mut M,
    options: &SetUpOptions,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> ChangeResult {
    let path = match backup_path(m) {
        Ok(path) => path,
        Err(why) => return result(Outcome::Failed { reason: why }, PathBuf::new()),
    };
    let refuse = |reasons: Vec<String>| result(Outcome::Refused { reasons }, path.clone());
    if options.kernel.is_none() && options.applications.is_none() {
        return refuse(vec!["Choose kernel dumps, application dumps or both".into()]);
    }
    if m.elevated() == Some(false) {
        return refuse(vec![
            "Setting up crash dumps needs administrator rights".into()
        ]);
    }
    progress(Event::Step {
        text: "Checking the choices".into(),
    });
    let mut plan = Plan::default();
    let mut refusals = Vec::new();
    if let Err(why) = plan_own_app(&*m, options.applications.is_some(), &mut plan) {
        refusals.push(format!(
            "Whether this app is left out of application dumps could not be read: {why}"
        ));
    }
    let mut reader = Reader {
        m: &*m,
        settings: Vec::new(),
        stop: None,
    };
    if let Some(k) = &options.kernel {
        if let Err(why) = plan_kernel(&mut reader, k, &mut plan, &mut refusals) {
            refusals.push(format!("The kernel settings could not be read: {why}"));
        }
    }
    if let Some(a) = &options.applications {
        if let Err(why) = plan_apps(&mut reader, a, &mut plan, &mut refusals) {
            refusals.push(format!("The application settings could not be read: {why}"));
        }
    }
    if !refusals.is_empty() {
        return refuse(refusals);
    }
    let mut out = result(Outcome::Done, path.clone());
    out.notes = std::mem::take(&mut plan.notes);
    out.planned = plan
        .folders
        .iter()
        .map(|(folder, _)| folder_change(folder, true))
        .chain(
            plan.writes
                .iter()
                .map(|w| change(w.hive, &w.key, w.name, w.before.as_ref(), w.value.as_ref())),
        )
        .collect();
    if out.planned.is_empty() {
        out.outcome = Outcome::NothingToDo;
        return out;
    }
    if !options.confirmed {
        out.outcome = Outcome::NotConfirmed;
        return out;
    }
    if cancel.load(Ordering::Relaxed) {
        out.outcome = Outcome::Stopped;
        return out;
    }

    progress(Event::Step {
        text: format!("Saving the present values to {}", path.display()),
    });
    let mut backup = match read_backup(m, &path) {
        Ok(found) => found.unwrap_or_default(),
        Err(why) => {
            out.outcome = Outcome::Refused {
                reasons: vec![format!(
                    "{why}; Put back could not be trusted, so nothing was changed"
                )],
            };
            return out;
        }
    };
    if backup.version != 0 && backup.version < BACKUP_VERSION {
        out.outcome = Outcome::Refused {
            reasons: vec![old_format_refusal(&backup, &path)],
        };
        return out;
    }
    // Keys an earlier set up made stay its to remove only while nothing else wrote to them.
    let custody = Custody::take(&*m, &backup.keys_made, &backup.key_stamps);
    backup.key_stamps = custody.held();
    out.notes.extend(custody.lost);
    // A value already saved keeps the state before set up first changed it, unless it was
    // changed since set up last wrote it: then what was there is what Put back returns to.
    // What set up writes now is what Put back compares with.
    let mut earlier: Vec<Option<RawValue>> = Vec::new();
    for w in &plan.writes {
        let saved = backup.values.iter_mut().find(|v| {
            v.hive == w.hive
                && v.key.eq_ignore_ascii_case(&w.key)
                && v.name.eq_ignore_ascii_case(w.name)
        });
        match saved {
            Some(saved) => {
                if saved.after != w.before {
                    out.notes.push(format!(
                        "{} was changed since set up last wrote it, to {}: Put back returns it to that.",
                        w.named(),
                        describe(w.name, w.before.as_ref())
                    ));
                    saved.before = w.before.clone();
                    saved.after = w.before.clone();
                }
                earlier.push(saved.after.clone());
                saved.after = w.value.clone();
            }
            None => {
                earlier.push(w.before.clone());
                backup.values.push(Saved {
                    hive: w.hive,
                    key: w.key.clone(),
                    name: w.name.into(),
                    before: w.before.clone(),
                    after: w.value.clone(),
                });
            }
        }
    }
    backup.version = BACKUP_VERSION;
    if plan.make_local_dumps
        && !backup
            .keys_made
            .iter()
            .any(|k| k.eq_ignore_ascii_case(LOCAL_DUMPS.path))
    {
        backup.keys_made.push(LOCAL_DUMPS.path.into());
    }
    if let Some(own) = &plan.make_own_key {
        if !backup.keys_made.iter().any(|k| k.eq_ignore_ascii_case(own)) {
            backup.keys_made.push(own.clone());
        }
    }
    for (folder, _) in &plan.folders {
        if !backup.folders_made.iter().any(|f| same_place(f, folder)) {
            backup.folders_made.push(folder.clone());
        }
    }
    let text = match serde_json::to_string_pretty(&backup) {
        Ok(text) => text,
        Err(e) => {
            out.outcome = Outcome::Failed {
                reason: format!("the present values could not be saved ({e})"),
            };
            return out;
        }
    };
    let saved = m
        .write_state(&path, &text)
        .and_then(|()| read_backup(m, &path));
    match saved {
        Ok(Some(read)) if read == backup => {}
        Ok(_) => {
            out.outcome = Outcome::Failed {
                reason: format!(
                    "{} did not read back as written, so nothing was changed",
                    path.display()
                ),
            };
            return out;
        }
        Err(why) => {
            out.outcome = Outcome::Failed {
                reason: format!(
                    "the present values could not be saved ({why}), so nothing was changed"
                ),
            };
            return out;
        }
    }

    progress(Event::Step {
        text: "Making the folders and writing the settings".into(),
    });
    let outcome = apply(m, &plan, &mut out, progress, cancel);
    out.outcome = outcome;
    record_what_was_made(m, &path, &plan, &earlier, backup, &mut out);
    out.restart_needed = out.changed.iter().any(|c| c.needs_restart);
    if out.restart_needed {
        out.notes.push("The kernel settings take effect after Windows next restarts. This tool does not restart the PC.".into());
    }
    if !out.changed.is_empty() {
        let lines: Vec<String> = out.changed.iter().map(|c| c.text.clone()).collect();
        if let Err(why) = m.record_changes("Crash dumps set up", &lines) {
            out.notes.push(format!(
                "The change record for the session report could not be written: {why}"
            ));
        }
    }
    out
}

/// Saves, once the writes are done, what Put back compares with: the identity of each
/// folder this set up made, when set up last wrote to each key it made, and for a write
/// that was not made (set up stopped or failed first) the value there before it, so Put
/// back removes only those very folders and keys and puts back only what set up wrote. A
/// folder or key left without a record is kept by Put back.
fn record_what_was_made<M: Machine>(
    m: &mut M,
    path: &Path,
    plan: &Plan,
    earlier: &[Option<RawValue>],
    mut backup: Backup,
    out: &mut ChangeResult,
) {
    let first = backup.clone();
    for (folder, _) in &plan.folders {
        if backup.folder_ids.iter().any(|(f, _)| same_place(f, folder)) {
            continue;
        }
        if let Ok(Some(id)) = m.folder_id(folder) {
            backup.folder_ids.push((folder.clone(), id));
        }
    }
    for (w, earlier) in plan.writes.iter().zip(earlier) {
        if m.read_value(w.hive, &w.key, w.name).as_ref() == Ok(&w.value) {
            continue;
        }
        if let Some(saved) = backup.values.iter_mut().find(|v| {
            v.hive == w.hive
                && v.key.eq_ignore_ascii_case(&w.key)
                && v.name.eq_ignore_ascii_case(w.name)
        }) {
            saved.after = earlier.clone();
        }
    }
    let mut made_now: Vec<&str> = plan.make_own_key.iter().map(String::as_str).collect();
    if plan.make_local_dumps {
        made_now.push(LOCAL_DUMPS.path);
    }
    let mut stamps = Vec::new();
    for key in &backup.keys_made {
        let ours = made_now.iter().any(|k| k.eq_ignore_ascii_case(key))
            || backup
                .key_stamps
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(key));
        if !ours {
            continue;
        }
        match m.key_stamp(Hive::LocalMachine, key) {
            Ok(Some(stamp)) => stamps.push((key.clone(), stamp)),
            Ok(None) => {}
            Err(why) => out.notes.push(format!(
                "When HKLM\\{key} was last written could not be read ({why}); Put back keeps it."
            )),
        }
    }
    backup.key_stamps = stamps;
    if backup == first {
        return;
    }
    let saved = serde_json::to_string_pretty(&backup)
        .map_err(|e| e.to_string())
        .and_then(|text| m.write_state(path, &text))
        .and_then(|()| read_backup(m, path));
    if !matches!(saved, Ok(Some(read)) if read == backup) {
        out.notes.push(format!(
            "What set up made could not be recorded in {}; Put back keeps the folders and keys it made.",
            path.display()
        ));
    }
}

fn apply<M: Machine>(
    m: &mut M,
    plan: &Plan,
    out: &mut ChangeResult,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> Outcome {
    for (folder, access) in &plan.folders {
        if cancel.load(Ordering::Relaxed) {
            return Outcome::Stopped;
        }
        // Saving the values makes the app's own folder, which this set up planned to make.
        let saved_there =
            *access == FolderAccess::Inherited && m.folder(folder) == Ok(PathKind::Folder);
        if !saved_there {
            if let Err(why) = m.create_folder(folder, *access) {
                return Outcome::Failed {
                    reason: format!("{} could not be made: {why}", folder.display()),
                };
            }
        }
        // Checked through the folder itself: a link put in its path since the plan was
        // made shows here, before any setting names the folder.
        match m.resolved(folder) {
            Ok(real)
                if m.long_name(folder)
                    .is_ok_and(|full| same_place(&real, &full)) => {}
            Ok(real) => {
                return Outcome::Failed {
                    reason: format!(
                        "{} was made but leads to {}; no setting names it",
                        folder.display(),
                        real.display()
                    ),
                }
            }
            Err(why) => {
                return Outcome::Failed {
                    reason: format!("{} could not be checked: {why}", folder.display()),
                }
            }
        }
        let made = folder_change(folder, true);
        progress(Event::Changed {
            change: made.clone(),
        });
        out.changed.push(made);
    }
    for w in &plan.writes {
        if cancel.load(Ordering::Relaxed) {
            return Outcome::Stopped;
        }
        let (hive, key) = (w.hive, w.key.as_str());
        let done = match &w.value {
            Some(value) => m.write_value(hive, key, w.name, value),
            None => m.delete_value(hive, key, w.name),
        };
        if let Err(why) = done {
            return Outcome::Failed {
                reason: format!("{} could not be changed: {why}", w.named()),
            };
        }
        let made = change(hive, key, w.name, w.before.as_ref(), w.value.as_ref());
        progress(Event::Changed {
            change: made.clone(),
        });
        out.changed.push(made);
    }
    for w in &plan.writes {
        match m.read_value(w.hive, &w.key, w.name) {
            Ok(now) if now == w.value => {}
            Ok(now) => {
                return Outcome::Failed {
                    reason: format!(
                        "{} reads back as {}, not {}",
                        w.named(),
                        describe(w.name, now.as_ref()),
                        describe(w.name, w.value.as_ref())
                    ),
                }
            }
            Err(why) => {
                return Outcome::Failed {
                    reason: format!("{} could not be read back: {why}", w.named()),
                }
            }
        }
    }
    Outcome::Done
}

pub(crate) fn put_back<M: Machine>(
    m: &mut M,
    options: &PutBackOptions,
    progress: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> ChangeResult {
    let path = match backup_path(m) {
        Ok(path) => path,
        Err(why) => return result(Outcome::Failed { reason: why }, PathBuf::new()),
    };
    if m.elevated() == Some(false) {
        return result(
            Outcome::Refused {
                reasons: vec!["Putting the settings back needs administrator rights".into()],
            },
            path,
        );
    }
    // An exclusion a recovery window left when it ended without letting go is settled
    // first: handed to the saved settings, so this Put back takes it away with the rest.
    let settled = if options.confirmed {
        hold::settle_left(m)
    } else {
        Ok(Vec::new())
    };
    progress(Event::Step {
        text: format!("Reading {}", path.display()),
    });
    let backup = match read_backup(m, &path) {
        Ok(Some(backup)) => backup,
        Ok(None) => {
            let mut out = result(Outcome::NothingToDo, path);
            out.notes.push("Nothing to put back: set up has changed nothing here, or its changes were already put back.".into());
            return out;
        }
        Err(why) => {
            return result(
                Outcome::Refused {
                    reasons: vec![format!("{why}; nothing was changed")],
                },
                path,
            )
        }
    };
    if backup.version < BACKUP_VERSION {
        return result(
            Outcome::Refused {
                reasons: vec![old_format_refusal(&backup, &path)],
            },
            path,
        );
    }
    let mut out = result(Outcome::Done, path.clone());
    match settled {
        Ok(lines) if !lines.is_empty() => {
            if let Err(why) = m.record_changes(hold::LET_IN, &lines) {
                out.notes.push(format!(
                    "The change record for the session report could not be written: {why}"
                ));
            }
        }
        Ok(_) => {}
        Err(why) => out.notes.push(format!(
            "An exclusion from crash dumps a recovery window left could not be settled: {why}"
        )),
    }
    // While a recovery window holds a recovery key it relies on this program's exclusion
    // from application dumps: that value, and the keys set up made for it, are handed to
    // the window, which takes them away when it lets go.
    let held = match hold::held_for(m) {
        Ok(held) => held,
        Err(why) => {
            out.outcome = Outcome::Refused {
                reasons: vec![format!("Whether a recovery window relies on this app's exclusion from crash dumps could not be read: {why}; nothing was changed")],
            };
            return out;
        }
    };
    let own = held.as_deref().map(own_key);
    let kept_value = |saved: &Saved| {
        own.as_ref().is_some_and(|own| {
            saved.key.eq_ignore_ascii_case(own)
                && saved.name.eq_ignore_ascii_case(OWN_NAME)
                && saved.before != Some(RawValue::dword(0))
        })
    };
    let own_value = backup.values.iter().find(|v| kept_value(v)).cloned();
    let kept_keys: Vec<String> = match &own {
        Some(own)
            if own_value.is_some()
                || backup.keys_made.iter().any(|k| k.eq_ignore_ascii_case(own)) =>
        {
            backup
                .keys_made
                .iter()
                .filter(|k| k.eq_ignore_ascii_case(own) || k.eq_ignore_ascii_case(LOCAL_DUMPS.path))
                .cloned()
                .collect()
        }
        _ => Vec::new(),
    };
    let kept_key = |key: &String| kept_keys.iter().any(|k| k.eq_ignore_ascii_case(key));
    if let Some(own) = own
        .as_ref()
        .filter(|_| own_value.is_some() || !kept_keys.is_empty())
    {
        out.notes.push(format!(
            "HKLM\\{own}\\{OWN_NAME} stays 0 while a recovery window holds a recovery key: a dump of that window would hold the key. The window takes it away when it closes."
        ));
    }
    // What set up wrote is put back only while it is still there: a value or key someone
    // changed since is left as it is, and said.
    let mut custody = Custody::take(&*m, &backup.keys_made, &backup.key_stamps);
    let mut restores = Vec::new();
    for saved in backup.values.iter().filter(|v| !kept_value(v)) {
        let now = match m.read_value(saved.hive, &saved.key, &saved.name) {
            Ok(now) => now,
            Err(why) => {
                out.outcome = Outcome::Failed {
                    reason: format!(
                        "{}\\{}\\{} could not be read: {why}",
                        saved.hive.name(),
                        saved.key,
                        saved.name
                    ),
                };
                return out;
            }
        };
        if now == saved.before {
            continue;
        }
        if now != saved.after {
            out.notes.push(left_changed(saved, now.as_ref()));
            continue;
        }
        out.planned.push(change(
            saved.hive,
            &saved.key,
            &saved.name,
            now.as_ref(),
            saved.before.as_ref(),
        ));
        restores.push(saved);
    }
    for key in backup.keys_made.iter().rev().filter(|k| !kept_key(k)) {
        let present = match m.key_exists(Hive::LocalMachine, key) {
            Ok(present) => present,
            Err(why) => {
                out.notes.push(format!(
                    "Whether HKLM\\{key} is there could not be read ({why}); it is left as it is."
                ));
                continue;
            }
        };
        if present && custody.stamp(key).is_some() {
            out.planned.push(Change {
                target: format!("HKLM\\{key}"),
                before: "made by set up".into(),
                after: "removed if empty".into(),
                text: format!("Key HKLM\\{key} removed if nothing else is in it"),
                needs_restart: false,
            });
        }
    }
    for folder in backup.folders_made.iter().rev() {
        if m.folder(folder) == Ok(PathKind::Folder) && made_here(m, &backup, folder) {
            let mut planned = folder_change(folder, false);
            planned.text.push_str(" if empty");
            out.planned.push(planned);
        }
    }
    if !options.confirmed {
        out.notes.append(&mut custody.lost.clone());
        out.outcome = Outcome::NotConfirmed;
        return out;
    }
    if cancel.load(Ordering::Relaxed) {
        out.outcome = Outcome::Stopped;
        return out;
    }
    if own_value.is_some() || !kept_keys.is_empty() {
        let handed = hold::hand_to_holders(
            m,
            own_value.as_ref().and_then(|v| v.before.as_ref()),
            &kept_keys,
        );
        if handed != Ok(true) {
            out.outcome = Outcome::Failed {
                reason: format!(
                    "This app's exclusion from crash dumps could not be handed to the recovery window that relies on it ({}); nothing was changed",
                    handed.err().unwrap_or_else(|| "the window let go meanwhile; try again".into())
                ),
            };
            return out;
        }
    }
    progress(Event::Step {
        text: "Putting the values back".into(),
    });
    let mut kept_for_another_try = false;
    for saved in restores {
        if cancel.load(Ordering::Relaxed) {
            out.outcome = Outcome::Stopped;
            return finish_put_back(m, out);
        }
        let named = format!("{}\\{}\\{}", saved.hive.name(), saved.key, saved.name);
        match restore_value(
            m,
            &mut custody,
            saved.hive,
            &saved.key,
            &saved.name,
            &saved.after,
            &saved.before,
        ) {
            PutBack::PutBack => {
                let made = change(
                    saved.hive,
                    &saved.key,
                    &saved.name,
                    saved.after.as_ref(),
                    saved.before.as_ref(),
                );
                progress(Event::Changed {
                    change: made.clone(),
                });
                out.changed.push(made);
            }
            PutBack::AlreadyBack => {}
            PutBack::LeftChanged { now } => out.notes.push(left_changed(saved, now.as_ref())),
            PutBack::Unknown { why } | PutBack::Failed { why } => {
                kept_for_another_try = true;
                out.outcome = Outcome::Failed {
                    reason: format!(
                        "{named} could not be put back ({why}); the saved values are kept for another try"
                    ),
                };
            }
        }
    }
    if kept_for_another_try {
        out.notes.append(&mut custody.lost);
        return finish_put_back(m, out);
    }
    // The keys handed to the recovery window go with when this put back last wrote to
    // them, so the window removes only those very keys.
    if !kept_keys.is_empty() {
        let stamps: Vec<(String, u64)> = custody
            .held()
            .into_iter()
            .filter(|(k, _)| kept_key(k))
            .collect();
        if let Err(why) = hold::stamp_keys(m, &stamps) {
            out.notes.push(format!(
                "When the keys handed to the recovery window were last written could not be recorded ({why}); the window keeps them."
            ));
        }
    }
    for key in backup.keys_made.iter().rev().filter(|k| !kept_key(k)) {
        match remove_key(m, &mut custody, key) {
            None | Some(PutBack::AlreadyBack) => {}
            Some(PutBack::PutBack) => {
                let made = Change {
                    target: format!("HKLM\\{key}"),
                    before: "made by set up".into(),
                    after: "removed".into(),
                    text: format!("Key HKLM\\{key} removed"),
                    needs_restart: false,
                };
                progress(Event::Changed {
                    change: made.clone(),
                });
                out.changed.push(made);
            }
            Some(PutBack::LeftChanged { .. }) => out.notes.push(format!(
                "HKLM\\{key} is kept: it was written to since set up, so it may not be the key set up made."
            )),
            Some(PutBack::Failed { why }) | Some(PutBack::Unknown { why }) => {
                out.notes.push(format!("HKLM\\{key} is kept: {why}."))
            }
        }
    }
    out.notes.append(&mut custody.lost);
    if let Err(why) = m.remove_state(&path) {
        out.notes.push(format!(
            "{} could not be removed ({why}); Put back can run again safely.",
            path.display()
        ));
    }
    for folder in backup.folders_made.iter().rev() {
        match m.folder(folder) {
            Ok(PathKind::Folder) => {}
            Ok(_) => continue,
            Err(why) => {
                out.notes.push(format!(
                    "Whether {} is still there could not be read ({why}); it is left as it is.",
                    folder.display()
                ));
                continue;
            }
        }
        let recorded = backup
            .folder_ids
            .iter()
            .find(|(f, _)| same_place(f, folder))
            .map(|(_, id)| id.clone());
        let Some(id) = recorded else {
            out.notes.push(format!(
                "{} is kept: it is not shown to be the folder set up made, so it is not removed.",
                folder.display()
            ));
            continue;
        };
        match remove_folder(m, folder, id) {
            PutBack::PutBack => {
                let made = folder_change(folder, false);
                progress(Event::Changed {
                    change: made.clone(),
                });
                out.changed.push(made);
            }
            PutBack::AlreadyBack => {}
            PutBack::LeftChanged { .. } => out.notes.push(format!(
                "{} is kept: it is not shown to be the folder set up made, so it is not removed.",
                folder.display()
            )),
            PutBack::Failed { why } | PutBack::Unknown { why } => out
                .notes
                .push(format!("{} is kept: {why}.", folder.display())),
        }
    }
    finish_put_back(m, out)
}

/// The note for a value someone changed since set up wrote it, which Put back leaves.
fn left_changed(saved: &Saved, now: Option<&RawValue>) -> String {
    format!(
        "{}\\{}\\{} is {}, not the {} set up wrote: it was changed since, so it is left as it is (before set up it was {}).",
        saved.hive.name(),
        saved.key,
        saved.name,
        describe(&saved.name, now),
        describe(&saved.name, saved.after.as_ref()),
        describe(&saved.name, saved.before.as_ref())
    )
}

/// Whether `folder` is still the very folder set up made: it has the identity recorded
/// when it was made.
fn made_here<M: Machine>(m: &M, backup: &Backup, folder: &Path) -> bool {
    let recorded = backup
        .folder_ids
        .iter()
        .find(|(f, _)| same_place(f, folder))
        .map(|(_, id)| id);
    recorded.is_some_and(|id| m.folder_id(folder).ok().flatten().as_ref() == Some(id))
}

fn finish_put_back<M: Machine>(m: &mut M, mut out: ChangeResult) -> ChangeResult {
    out.restart_needed = out.changed.iter().any(|c| c.needs_restart);
    if out.restart_needed {
        out.notes.push("The kernel settings take effect after Windows next restarts. This tool does not restart the PC.".into());
    }
    if !out.changed.is_empty() {
        let lines: Vec<String> = out.changed.iter().map(|c| c.text.clone()).collect();
        if let Err(why) = m.record_changes("Crash dump settings put back", &lines) {
            out.notes.push(format!(
                "The change record for the session report could not be written: {why}"
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::fake::Fake;
    use super::super::machine::{MEMORY_MANAGEMENT, REG_SZ};
    use super::super::readiness;
    use super::super::{CheckOptions, Status};
    use super::*;

    fn go() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// The guard: a folder spelled with a short (8.3) name is the folder itself, not a link,
    /// so set up accepts it whether it exists or is made under a short-named parent.
    #[test]
    fn a_dump_folder_spelled_with_a_short_name_is_accepted() {
        let apps_in = |folder: &str| SetUpOptions {
            confirmed: true,
            kernel: None,
            applications: Some(AppOptions {
                folder: folder.into(),
                ..AppOptions::default()
            }),
        };
        for existing in [false, true] {
            let mut m = Fake::windows_default();
            m.folders
                .insert(r"c:\progra~1".into(), (PathKind::Folder, None));
            if existing {
                m.folders
                    .insert(r"c:\progra~1\dumps".into(), (PathKind::Folder, None));
            }
            for map in [&mut m.redirects, &mut m.short_names] {
                map.insert(r"c:\progra~1".into(), r"c:\program files".into());
            }
            let out = set(&mut m, &apps_in(r"C:\PROGRA~1\Dumps"));
            assert!(
                matches!(out.outcome, Outcome::Done),
                "existing {existing}: {out:?}"
            );
            assert!(m.value(LOCAL_DUMPS, "DumpFolder").is_some());
        }
    }

    /// The guard: an application dump folder reached through a junction is refused
    /// wherever the junction sits in its path, one that resolves elsewhere is refused, and a
    /// folder that leads elsewhere once made is never named by a setting. The check says
    /// the same of a folder under a junction.
    #[test]
    fn a_dump_folder_reached_through_a_link_is_refused() {
        let apps_in = |folder: &str| SetUpOptions {
            confirmed: true,
            kernel: None,
            applications: Some(AppOptions {
                folder: folder.into(),
                ..AppOptions::default()
            }),
        };
        let mut m = Fake::windows_default();
        m.folders
            .insert(r"c:\junction".into(), (PathKind::Link, None));
        m.folders
            .insert(r"c:\junction\crashdumps".into(), (PathKind::Folder, None));
        for folder in [r"C:\junction\CrashDumps", r"C:\junction\New\Dumps"] {
            let out = set(&mut m, &apps_in(folder));
            let Outcome::Refused { reasons } = &out.outcome else {
                panic!("{folder}: {out:?}")
            };
            assert!(
                reasons.iter().any(|r| r.contains(r"C:\junction is a link")),
                "{reasons:?}"
            );
            assert_eq!(m.writes, 0);
        }
        m.folders
            .insert(r"c:\mounted".into(), (PathKind::Folder, None));
        m.redirects
            .insert(r"c:\mounted".into(), r"d:\elsewhere".into());
        let out = set(&mut m, &apps_in(r"C:\mounted\Dumps"));
        let Outcome::Refused { reasons } = &out.outcome else {
            panic!("{out:?}")
        };
        assert!(
            reasons.iter().any(|r| r.contains("leads to")),
            "{reasons:?}"
        );
        assert_eq!(m.writes, 0);
        // A link that appears after the plan: the made folder leads elsewhere.
        m.redirects
            .insert(r"c:\later".into(), r"d:\elsewhere".into());
        let out = set(&mut m, &apps_in(r"C:\later\Dumps"));
        let Outcome::Failed { reason } = &out.outcome else {
            panic!("{out:?}")
        };
        assert!(reason.contains("no setting names it"), "{reason}");
        assert!(m.value(LOCAL_DUMPS, "DumpFolder").is_none());

        let mut m = Fake::windows_default();
        m.set_up_app_dumps();
        m.expand_string(LOCAL_DUMPS, "DumpFolder", r"C:\junction\CrashDumps");
        m.folders
            .insert(r"c:\junction".into(), (PathKind::Link, None));
        m.folders
            .insert(r"c:\junction\crashdumps".into(), (PathKind::Folder, None));
        let ready = readiness::check(&m, &CheckOptions::default(), &mut |_| {}, &go());
        let item = ready.items.iter().find(|i| i.id == "apps.folder").unwrap();
        assert!(
            matches!(&item.status, Status::NeedsChange { reason } if reason.contains("a link to another place")),
            "{item:?}"
        );
    }

    /// The guard: set up leaves this app out of application dumps, before any other value
    /// is written, whenever LocalDumps is on after it, and Put back takes that away with
    /// the rest; full application dumps are refused while this app holds, or has held, a
    /// recovery key; and a key is not taken in while a dump of this app would be kept.
    #[test]
    fn this_app_is_left_out_of_application_dumps() {
        let own = format!("{}\\DiagnosticTool.exe", LOCAL_DUMPS.path);
        let mut m = Fake::windows_default();
        let before = m.clone();
        let out = set(&mut m, &confirmed());
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert_eq!(
            m.read_value(Hive::LocalMachine, &own, "DumpCount").unwrap(),
            Some(RawValue::dword(0))
        );
        let first = out
            .changed
            .iter()
            .find(|c| c.target.starts_with("HKLM"))
            .unwrap();
        assert!(
            first.target.ends_with(r"DiagnosticTool.exe\DumpCount"),
            "{first:?}"
        );
        let out = back(&mut m);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert_eq!(m.keys, before.keys);

        let mut m = Fake::windows_default();
        m.key_held = true;
        let mut full = confirmed();
        full.applications.as_mut().unwrap().dump_type = AppDumpType::Full;
        let out = set(&mut m, &full);
        let Outcome::Refused { reasons } = &out.outcome else {
            panic!("{out:?}")
        };
        assert!(
            reasons.iter().any(|r| r.contains("recovery key")),
            "{reasons:?}"
        );
        assert_eq!(m.writes, 0);
        m.key_held = false;
        assert_eq!(set(&mut m, &full).outcome, Outcome::Done);

        let mut m = Fake::windows_default();
        assert_eq!(debugger_off(&m), Ok(()));
        m.text(AEDEBUG, "Auto", "1");
        m.text(AEDEBUG, "Debugger", r"C:\dbg\x.exe -p %ld");
        assert!(debugger_off(&m).unwrap_err().contains("AeDebug"));

        // Each way a key comes in keeps this program out of dumps first, and the window
        // marks the process and keeps it out while it is open.
        let bitlocker = include_str!("../../recovery/bitlocker.rs");
        let unlock = &bitlocker[bitlocker.find("pub fn unlock_with_key_text(").unwrap()..];
        let kept = unlock.find("keep_out_of_dumps()").unwrap();
        assert!(kept < unlock.find("RecoveryKey::parse(text)").unwrap());
        let view = include_str!("../../gui/bitlocker_view.rs");
        let find = &view[view.find("fn find_key(").unwrap()..];
        assert!(find.find("self.kept_out()").unwrap() < find.find("self.start_job(").unwrap());
        let typed = &view[view.find("    fn unlock(&mut self").unwrap()..];
        assert!(typed.find("self.kept_out()").unwrap() < typed.find("self.unlock_with(").unwrap());
        let new = &view[view.find("    fn new(disk: u32").unwrap()..];
        let new = &new[..new.find("\n    }\n").unwrap()];
        assert!(new.contains("bitlocker::mark_key_held();"));
        assert!(new.contains("crash_dumps::keep_out_of_dumps()"));
        // The key box, Unlock and Find the key stay off until the exclusion is held, a key
        // already in the box is cleared, and the window says why.
        let render = &view[view.find("    fn render(&mut self)").unwrap()..];
        let render = &render[..render.find("\n    }\n").unwrap()];
        assert!(render.contains("let protected = self.dumps.is_ok();"));
        assert!(render.contains("ui::enable(c.key, protected && !busy && locked);"));
        assert!(render.contains("ui::enable(c.unlock, protected && !busy && locked);"));
        assert!(render.contains("c.find_key,\n            protected\n"));
        assert!(render.contains("clear_key(c.key);"));
        assert!(render.contains("Err(why) => ("));
        let fields = &view[view.find("pub struct BitLockerView {").unwrap()..];
        let fields = &fields[..fields.find("\n}\n").unwrap()];
        assert!(fields
            .trim_end()
            .ends_with("dumps: Result<DumpExclusion, String>,"));
        let lookup = include_str!("../../gui/keylookup_view.rs");
        let fetch = &lookup[lookup.find("pub fn fetch_recovery_key(").unwrap()..];
        let kept = fetch.find("keep_out_of_dumps()").unwrap();
        assert!(kept < fetch.find("webview2::runtime_dll()").unwrap());
        assert!(kept < fetch.find("CreateWindowExW(").unwrap());
        let files = include_str!("../../recovery/keylookup.rs");
        let search = &files[files.find("pub fn search_key_files(").unwrap()..];
        assert!(
            search.find("keep_out_of_dumps()").unwrap()
                < search.find("local_drive_roots()").unwrap()
        );
    }

    /// The guard: Put back acts on nothing in the saved file that set up did not write or
    /// make. A key, value or folder set up never touches, a value named twice or a format it
    /// does not know is refused before anything changes, and a folder is removed only while
    /// it is the very folder set up made.
    #[test]
    fn put_back_refuses_what_set_up_never_made() {
        let mut m = Fake::windows_default();
        assert_eq!(set(&mut m, &confirmed()).outcome, Outcome::Done);
        let (file, text) = m
            .state
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let saved: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(saved["version"], 3);
        let value = |key: &str, name: &str| serde_json::json!({"hive": "local_machine", "key": key, "name": name, "before": null});
        type Edit = Box<dyn Fn(&mut serde_json::Value)>;
        let edits: Vec<Edit> = vec![
            Box::new(|v| {
                v["keys_made"]
                    .as_array_mut()
                    .unwrap()
                    .push(r"SOFTWARE\Unrelated".into())
            }),
            Box::new(|v| {
                v["keys_made"]
                    .as_array_mut()
                    .unwrap()
                    .push(format!(r"{}\notepad.exe", LOCAL_DUMPS.path).into())
            }),
            Box::new(|v| {
                v["folders_made"]
                    .as_array_mut()
                    .unwrap()
                    .push(r"C:\".into())
            }),
            Box::new(move |v| {
                v["values"]
                    .as_array_mut()
                    .unwrap()
                    .push(value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "x"))
            }),
            Box::new(move |v| {
                v["values"]
                    .as_array_mut()
                    .unwrap()
                    .push(value(CRASH_CONTROL.path, "DedicatedDumpFile"))
            }),
            Box::new(move |v| {
                v["values"]
                    .as_array_mut()
                    .unwrap()
                    .push(value(LOCAL_DUMPS.path, "DumpCount"))
            }),
            Box::new(move |v| {
                v["values"].as_array_mut().unwrap().push(value(
                    &format!(r"{}\notepad.exe", LOCAL_DUMPS.path),
                    "DumpCount",
                ))
            }),
            Box::new(|v| {
                v["folder_ids"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!([r"C:\Windows", "made:1"]))
            }),
            Box::new(|v| v["version"] = 7.into()),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut edited = saved.clone();
            edit(&mut edited);
            let mut m2 = m.clone();
            m2.state.insert(file.clone(), edited.to_string());
            let (keys, folders, writes) = (m2.keys.clone(), m2.folders.clone(), m2.writes);
            let out = back(&mut m2);
            assert!(
                matches!(out.outcome, Outcome::Refused { .. }),
                "edit {i}: {out:?}"
            );
            assert_eq!(
                (m2.keys, m2.folders, m2.writes),
                (keys, folders, writes),
                "edit {i}"
            );
        }

        // A folder named in the file with no identity set up recorded is kept, not removed.
        let mut edited = saved.clone();
        edited["folders_made"]
            .as_array_mut()
            .unwrap()
            .push(r"C:\Users\tech\AppData\Local".into());
        let mut m2 = m.clone();
        m2.state.insert(file.clone(), edited.to_string());
        let out = back(&mut m2);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert!(m2.folders.contains_key(r"c:\users\tech\appdata\local"));

        // The dump folder removed and made again since: another identity, so it is kept.
        let mut m2 = m.clone();
        m2.ids.insert(
            r"c:\programdata\diagnostictool\crashdumps".into(),
            "made:99".into(),
        );
        let out = back(&mut m2);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert!(m2
            .folders
            .contains_key(r"c:\programdata\diagnostictool\crashdumps"));
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("not shown to be the folder set up made")),
            "{:?}",
            out.notes
        );
        let out = back(&mut m);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert!(!m
            .folders
            .contains_key(r"c:\programdata\diagnostictool\crashdumps"));
    }

    /// One step of the live run on a test machine, named by DIAGTOOL_CRASHDUMP_STEP:
    /// `check`, `setup`, `full-held` (with this process marked as holding a key, full
    /// application dumps are refused), `tamper` (a saved file naming another key is refused
    /// and put back as it was), `crash` (this program ends by a fail fast; with set up done
    /// no dump of it is kept) and `putback`. Runs only where DIAGTOOL_CRASHDUMP_HOST names
    /// the computer, since it changes crash dump settings. Needs administrator rights.
    #[test]
    #[ignore = "changes crash dump settings; for a test machine named by DIAGTOOL_CRASHDUMP_HOST"]
    fn live_step() {
        use super::super::windows::Windows;
        let host = std::env::var("DIAGTOOL_CRASHDUMP_HOST").unwrap_or_default();
        let here = std::env::var("COMPUTERNAME").unwrap_or_default();
        assert!(
            !host.is_empty() && host.eq_ignore_ascii_case(&here),
            "not the test machine"
        );
        let step = std::env::var("DIAGTOOL_CRASHDUMP_STEP").unwrap();
        let mut m = Windows;
        let show = |out: &ChangeResult| {
            println!("outcome: {:?}", out.outcome);
            for c in &out.changed {
                println!("changed: {}", c.text);
            }
            for n in &out.notes {
                println!("note: {n}");
            }
        };
        println!(
            "exe: {:?}; debugger off: {:?}",
            m.exe_name(),
            debugger_off(&m)
        );
        match step.as_str() {
            "check" => {
                let r = readiness::check(&m, &CheckOptions::default(), &mut |_| {}, &go());
                for i in &r.items {
                    println!("{}: {} - {}", i.id, i.status.word(), i.summary);
                }
                println!("put back available: {}", r.put_back_available);
            }
            "setup" => show(&set_up(&mut m, &confirmed(), &mut |_| {}, &go())),
            "full-held" => {
                crate::recovery::bitlocker::mark_key_held();
                assert!(m.key_held());
                let mut full = confirmed();
                full.applications.as_mut().unwrap().dump_type = AppDumpType::Full;
                let out = set_up(&mut m, &full, &mut |_| {}, &go());
                show(&out);
                assert!(matches!(out.outcome, Outcome::Refused { .. }));
            }
            "tamper" => {
                let path = backup_path(&m).unwrap();
                let text = m.read_state(&path).unwrap().unwrap();
                let mut edited: serde_json::Value = serde_json::from_str(&text).unwrap();
                edited["keys_made"]
                    .as_array_mut()
                    .unwrap()
                    .push(r"SOFTWARE\DiagToolQaUnrelated".into());
                m.write_state(&path, &edited.to_string()).unwrap();
                let out = put_back(
                    &mut m,
                    &PutBackOptions { confirmed: true },
                    &mut |_| {},
                    &go(),
                );
                m.write_state(&path, &text).unwrap();
                show(&out);
                assert!(matches!(out.outcome, Outcome::Refused { .. }));
                assert_eq!(m.read_state(&path).unwrap().unwrap(), text);
            }
            "crash" => {
                println!("ending by a fail fast");
                std::process::abort();
            }
            "putback" => show(&put_back(
                &mut m,
                &PutBackOptions { confirmed: true },
                &mut |_| {},
                &go(),
            )),
            // The recovery window's exclusion, through the same calls the window makes.
            "hold" => {
                super::super::TOUCH_MACHINE.store(true, Ordering::SeqCst);
                crate::change_record::start_for_this_process().unwrap();
                let own = own_key(&m.exe_name().unwrap());
                let kept = super::super::keep_out_of_dumps();
                println!("kept out: {:?}", kept.as_ref().map(|_| ()));
                println!(
                    "held: {:?}",
                    m.read_value(Hive::LocalMachine, &own, OWN_NAME)
                );
                println!("hold file: {:?}", hold::held_for(&m));
                // A key outliving the call that took the exclusion keeps it.
                let key = crate::recovery::bitlocker::KeyText::new(marker("DTKEYTEXT"));
                drop(kept);
                println!(
                    "guard dropped, key alive: {:?}",
                    m.read_value(Hive::LocalMachine, &own, OWN_NAME)
                );
                drop(key);
                println!(
                    "let go: {:?}",
                    m.read_value(Hive::LocalMachine, &own, OWN_NAME)
                );
                println!("own key: {:?}", m.key_exists(Hive::LocalMachine, &own));
                println!(
                    "hold file: {:?}",
                    m.read_state(&hold::hold_path(&m).unwrap())
                );
                let record = crate::change_record::file().unwrap().to_path_buf();
                println!(
                    "change record:\n{}",
                    std::fs::read_to_string(&record).unwrap()
                );
                crate::change_record::finish();
            }
            // Holds the exclusion and a key's text, then ends by a fail fast.
            "hold-crash" => {
                super::super::TOUCH_MACHINE.store(true, Ordering::SeqCst);
                let kept = super::super::keep_out_of_dumps();
                println!("kept out: {:?}", kept.as_ref().map(|_| ()));
                let key = crate::recovery::bitlocker::KeyText::new(marker("DTKEYTEXT"));
                println!("shielded: {}; ending by a fail fast", key.shielded());
                std::process::abort();
            }
            // What the next start does with an exclusion left by a process that ended.
            "settle" => {
                super::super::TOUCH_MACHINE.store(true, Ordering::SeqCst);
                let own = own_key(&m.exe_name().unwrap());
                println!("left: {:?}", m.read_state(&hold::hold_path(&m).unwrap()));
                println!(
                    "before: {:?}",
                    m.read_value(Hive::LocalMachine, &own, OWN_NAME)
                );
                super::super::settle_left_exclusion();
                println!(
                    "after: {:?}",
                    m.read_value(Hive::LocalMachine, &own, OWN_NAME)
                );
                println!("own key: {:?}", m.key_exists(Hive::LocalMachine, &own));
                println!(
                    "hold file: {:?}",
                    m.read_state(&hold::hold_path(&m).unwrap())
                );
            }
            // No exclusion: a key's text in a block registered to be left out of dumps,
            // and the same kind of text not registered, then a fail fast.
            "shield-crash" => {
                let key = crate::recovery::bitlocker::KeyText::new(marker("DTKEYTEXT"));
                let plain = marker("DTPLAINTEXT");
                println!(
                    "shielded: {}; plain {}; ending by a fail fast",
                    key.shielded(),
                    plain.len()
                );
                std::process::abort();
            }
            // Prints the markers for DIAGTOOL_SEED, from a process other than the one dumped.
            "marker" => {
                println!("{}", marker("DTKEYTEXT"));
                println!("{}", marker("DTPLAINTEXT"));
            }
            other => panic!("no step {other}"),
        }
    }

    /// `prefix` and 40 digits from DIAGTOOL_SEED, built in place in one buffer, so the
    /// whole text is in memory only where it is kept.
    fn marker(prefix: &str) -> String {
        let mut v: u64 = std::env::var("DIAGTOOL_SEED").unwrap().parse().unwrap();
        let mut text = String::with_capacity(64);
        text.push_str(prefix);
        for _ in 0..40 {
            v = v
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            text.push(char::from(b'0' + ((v >> 33) % 10) as u8));
        }
        text
    }

    fn confirmed() -> SetUpOptions {
        SetUpOptions {
            confirmed: true,
            ..SetUpOptions::default()
        }
    }

    fn set(m: &mut Fake, options: &SetUpOptions) -> ChangeResult {
        set_up(m, options, &mut |_| {}, &go())
    }

    fn back(m: &mut Fake) -> ChangeResult {
        put_back(m, &PutBackOptions { confirmed: true }, &mut |_| {}, &go())
    }

    /// A PC as the runner VM was found: automatic dumps, no AlwaysKeepMemoryDump, a dump
    /// file stored as a literal path in a REG_SZ, no LocalDumps, AutoReboot 0.
    fn runner_like() -> Fake {
        let mut m = Fake::windows_default_without_keep();
        m.text(CRASH_CONTROL, "DumpFile", r"C:\WINDOWS\MEMORY.DMP");
        m.dword(CRASH_CONTROL, "AutoReboot", 0);
        m
    }

    #[test]
    fn unconfirmed_set_up_lists_the_changes_and_writes_nothing() {
        let mut m = runner_like();
        let before = m.clone();
        let out = set(&mut m, &SetUpOptions::default());
        assert_eq!(out.outcome, Outcome::NotConfirmed);
        assert_eq!(m.writes, 0);
        assert!(m.state.is_empty());
        assert_eq!(m.keys, before.keys);
        let texts: Vec<&str> = out.planned.iter().map(|c| c.text.as_str()).collect();
        assert!(
            texts.contains(&"Keep the memory dump when space is low: absent to 1 (on)"),
            "{texts:?}"
        );
        assert!(
            texts.contains(&r"Folder C:\ProgramData\DiagnosticTool\CrashDumps made"),
            "{texts:?}"
        );
        // The literal C:\WINDOWS\MEMORY.DMP is the default place already, and AutoReboot
        // is left alone unless asked.
        assert!(
            !texts
                .iter()
                .any(|t| t.starts_with("Memory dump file") || t.starts_with("Restart")),
            "{texts:?}"
        );
    }

    #[test]
    fn set_up_then_put_back_leaves_the_registry_exactly_as_it_was() {
        let mut m = runner_like();
        m.put(
            CRASH_CONTROL,
            "Odd",
            RawValue {
                kind: REG_SZ,
                data: vec![0x41, 0x00],
            },
        );
        let before = m.clone();
        let out = set(&mut m, &confirmed());
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert!(out.restart_needed);
        assert_eq!(
            m.value(CRASH_CONTROL, "AlwaysKeepMemoryDump"),
            Some(&RawValue::dword(1))
        );
        assert_eq!(
            m.value(LOCAL_DUMPS, "DumpCount"),
            Some(&RawValue::dword(10))
        );
        assert_eq!(
            m.folders
                .get(r"c:\programdata\diagnostictool\crashdumps")
                .map(|f| f.1),
            Some(Some(FolderAccess::CrashingProcesses))
        );
        assert!(m.record.contains(&"Crash dumps set up".to_string()));
        let ready = readiness::check(&m, &CheckOptions::default(), &mut |_| {}, &go());
        for id in ["kernel.keep", "apps.local_dumps", "apps.folder"] {
            let item = ready.items.iter().find(|i| i.id == id).unwrap();
            assert_eq!(item.status, Status::Ready, "{item:?}");
        }
        assert!(ready.put_back_available);

        let out = back(&mut m);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert_eq!(m.keys, before.keys);
        assert_eq!(m.folders, before.folders);
        assert!(m.state.is_empty());
        assert!(m
            .record
            .contains(&"Crash dump settings put back".to_string()));
        assert_eq!(back(&mut m).outcome, Outcome::NothingToDo);
    }

    #[test]
    fn a_second_set_up_keeps_the_first_saved_values() {
        let mut m = runner_like();
        let before = m.clone();
        assert_eq!(set(&mut m, &confirmed()).outcome, Outcome::Done);
        let mut options = confirmed();
        if let Some(k) = &mut options.kernel {
            k.dump_type = KernelDumpType::Small;
            k.restart_after_stop = Some(true);
        }
        let out = set(&mut m, &options);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert_eq!(
            m.value(CRASH_CONTROL, "CrashDumpEnabled"),
            Some(&RawValue::dword(3))
        );
        assert_eq!(back(&mut m).outcome, Outcome::Done);
        assert_eq!(m.keys, before.keys);
    }

    #[test]
    fn put_back_works_from_the_saved_file_alone() {
        // A new machine value holding only what a restarted app would find on disk.
        let mut m = runner_like();
        let before = m.keys.clone();
        set(&mut m, &confirmed());
        let mut restarted = m.clone();
        restarted.record.clear();
        assert_eq!(back(&mut restarted).outcome, Outcome::Done);
        assert_eq!(restarted.keys, before);
    }

    #[test]
    fn set_up_refuses_without_rights_and_with_nothing_chosen() {
        let mut m = runner_like();
        m.elevated = Some(false);
        let out = set(&mut m, &confirmed());
        assert!(
            matches!(&out.outcome, Outcome::Refused { reasons } if reasons[0].contains("administrator"))
        );
        m.elevated = Some(true);
        let out = set(
            &mut m,
            &SetUpOptions {
                confirmed: true,
                kernel: None,
                applications: None,
            },
        );
        assert!(matches!(out.outcome, Outcome::Refused { .. }));
        assert_eq!(m.writes, 0);
    }

    #[test]
    fn unsafe_and_useless_choices_are_refused_with_reasons() {
        let mut m = runner_like();
        m.multi(
            MEMORY_MANAGEMENT,
            "PagingFiles",
            &[r"C:\pagefile.sys 1024 1024"],
        );
        let options = SetUpOptions {
            confirmed: true,
            kernel: Some(KernelOptions {
                dump_type: KernelDumpType::Complete,
                dump_file: r"N:\dumps\MEMORY.DMP".into(),
                minidump_folder: r"E:\mini".into(),
                restart_after_stop: None,
            }),
            applications: Some(AppOptions {
                folder: r"%LOCALAPPDATA%\dumps".into(),
                dump_type: AppDumpType::Full,
                count: 0,
            }),
        };
        let out = set(&mut m, &options);
        let Outcome::Refused { reasons } = &out.outcome else {
            panic!("{out:?}")
        };
        let all = reasons.join("\n");
        assert!(
            all.contains("needs a page file of at least 17.4 GB on C:"),
            "{all}"
        );
        assert!(all.contains("network drive"), "{all}");
        assert!(all.contains("removable drive"), "{all}");
        assert!(all.contains("%LOCALAPPDATA%"), "{all}");
        assert!(all.contains("1 to 100, not 0"), "{all}");
        assert_eq!(m.writes, 0);
        assert!(m.state.is_empty());
    }

    #[test]
    fn a_folder_on_a_drive_without_room_is_refused() {
        let mut m = runner_like();
        m.volumes
            .insert('D', (VolumeKind::Fixed, 500 * 1024 * 1024));
        let options = SetUpOptions {
            confirmed: true,
            kernel: None,
            applications: Some(AppOptions {
                folder: r"D:\dumps".into(),
                dump_type: AppDumpType::Full,
                count: 10,
            }),
        };
        let out = set(&mut m, &options);
        assert!(
            matches!(&out.outcome, Outcome::Refused { reasons } if reasons[0].contains("524.3 MB free")),
            "{out:?}"
        );
    }

    #[test]
    fn links_files_and_odd_paths_are_refused() {
        let mut m = runner_like();
        m.folders
            .insert(r"d:\linked".into(), (PathKind::Link, None));
        m.files.insert(r"d:\afile".into(), 10);
        for (folder, word) in [
            (r"D:\linked\dumps", "link"),
            (r"D:\afile", "is a file"),
            (r"\\server\share\dumps", "drive letter"),
            (r"D:\a\..\b", "plain path"),
            (r"D:\dumps:stream", "plain path"),
            (r"%ProgramData", "unpaired"),
        ] {
            let options = SetUpOptions {
                confirmed: true,
                kernel: None,
                applications: Some(AppOptions {
                    folder: folder.into(),
                    ..AppOptions::default()
                }),
            };
            let out = set(&mut m, &options);
            assert!(
                matches!(&out.outcome, Outcome::Refused { reasons } if reasons.join(" ").contains(word)),
                "{folder}: {out:?}"
            );
        }
        assert_eq!(m.writes, 0);
    }

    #[test]
    fn a_complete_dump_clears_the_active_filter_and_an_active_one_sets_it() {
        let mut m = runner_like();
        m.volumes.insert('C', (VolumeKind::Fixed, 200 * (1 << 30)));
        m.dword(CRASH_CONTROL, "FilterPages", 1);
        let mut options = confirmed();
        options.kernel.as_mut().unwrap().dump_type = KernelDumpType::Complete;
        assert_eq!(set(&mut m, &options).outcome, Outcome::Done);
        assert_eq!(m.value(CRASH_CONTROL, "FilterPages"), None);
        assert_eq!(
            m.value(CRASH_CONTROL, "CrashDumpEnabled"),
            Some(&RawValue::dword(1))
        );
        options.kernel.as_mut().unwrap().dump_type = KernelDumpType::Active;
        assert_eq!(set(&mut m, &options).outcome, Outcome::Done);
        assert_eq!(
            m.value(CRASH_CONTROL, "FilterPages"),
            Some(&RawValue::dword(1))
        );
        back(&mut m);
        assert_eq!(
            m.value(CRASH_CONTROL, "FilterPages"),
            Some(&RawValue::dword(1))
        );
        assert_eq!(
            m.value(CRASH_CONTROL, "CrashDumpEnabled"),
            Some(&RawValue::dword(7))
        );
    }

    #[test]
    fn a_failed_write_stops_and_put_back_undoes_what_was_done() {
        let mut m = runner_like();
        let before = m.keys.clone();
        m.fail_writes(LOCAL_DUMPS, "DumpType");
        let out = set(&mut m, &confirmed());
        assert!(
            matches!(&out.outcome, Outcome::Failed { reason } if reason.contains("DumpType")),
            "{out:?}"
        );
        assert!(!out.changed.is_empty());
        m.failing_writes.clear();
        assert_eq!(back(&mut m).outcome, Outcome::Done);
        assert_eq!(m.keys, before);
    }

    #[test]
    fn cancel_before_writing_changes_nothing() {
        let mut m = runner_like();
        let out = set_up(&mut m, &confirmed(), &mut |_| {}, &AtomicBool::new(true));
        assert_eq!(out.outcome, Outcome::Stopped);
        assert_eq!(m.writes, 0);
    }

    #[test]
    fn a_folder_holding_dumps_is_kept_by_put_back() {
        let mut m = runner_like();
        set(&mut m, &confirmed());
        m.files.insert(
            r"c:\programdata\diagnostictool\crashdumps\app.exe.123.dmp".into(),
            5,
        );
        let out = back(&mut m);
        assert_eq!(out.outcome, Outcome::Done);
        assert!(
            out.notes.iter().any(|n| n.contains("CrashDumps is kept")),
            "{:?}",
            out.notes
        );
        assert!(m.value(LOCAL_DUMPS, "DumpFolder").is_none());
    }

    #[test]
    fn a_saved_file_naming_another_key_is_refused() {
        let mut m = runner_like();
        set(&mut m, &confirmed());
        let path = r"c:\programdata\diagnostictool\crash-dump-settings-before.json".to_string();
        let text = m.state[&path].replace(
            "CurrentControlSet\\\\Control\\\\CrashControl",
            "CurrentControlSet\\\\Services\\\\Tcpip",
        );
        m.state.insert(path, text);
        let writes = m.writes;
        let out = back(&mut m);
        assert!(
            matches!(&out.outcome, Outcome::Refused { reasons } if reasons[0].contains("never writes")),
            "{out:?}"
        );
        assert_eq!(m.writes, writes);
    }

    #[test]
    fn set_up_on_a_ready_pc_has_nothing_to_do() {
        let mut m = Fake::windows_default();
        m.set_up_app_dumps();
        let out = set(&mut m, &confirmed());
        assert_eq!(out.outcome, Outcome::NothingToDo, "{:?}", out.planned);
    }

    #[test]
    fn values_keep_their_bytes_through_the_saved_file() {
        let value = RawValue {
            kind: 11,
            data: vec![0, 255, 16, 1],
        };
        let text = serde_json::to_string(&value).unwrap();
        assert_eq!(text, r#"{"kind":11,"data":"00ff1001"}"#);
        assert_eq!(serde_json::from_str::<RawValue>(&text).unwrap(), value);
    }

    /// The guard: Put back puts a value back only while it still holds what set up wrote.
    /// A value changed by hand since is left as it is and said, with what set up wrote and
    /// what was there before; every other value is put back.
    #[test]
    fn put_back_leaves_a_value_changed_since_and_says_it() {
        let mut m = runner_like();
        let before = m.clone();
        assert_eq!(set(&mut m, &confirmed()).outcome, Outcome::Done);
        // Someone sets the application dump count by hand after set up.
        m.dword(LOCAL_DUMPS, "DumpCount", 25);
        let out = back(&mut m);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert_eq!(
            m.value(LOCAL_DUMPS, "DumpCount"),
            Some(&RawValue::dword(25))
        );
        assert!(
            out.notes.iter().any(|n| n.contains("DumpCount is 25")
                && n.contains("not the 10 set up wrote")
                && n.contains("left as it is")),
            "{:?}",
            out.notes
        );
        // Everything else is back as it was; the key it is in stays, holding that value.
        assert_eq!(
            m.value(CRASH_CONTROL, "AlwaysKeepMemoryDump"),
            before.value(CRASH_CONTROL, "AlwaysKeepMemoryDump")
        );
        assert_eq!(m.value(LOCAL_DUMPS, "DumpFolder"), None);
        assert!(m
            .keys
            .contains_key(&(Hive::LocalMachine, LOCAL_DUMPS.path.to_lowercase())));
        assert!(m.state.is_empty(), "the saved settings are used up");
    }

    /// The guard: a key set up made is removed only while it is the key set up made. One
    /// removed and made again since (as an installer does) is kept, and said.
    #[test]
    fn a_key_made_again_since_set_up_is_kept() {
        let mut m = runner_like();
        assert_eq!(set(&mut m, &confirmed()).outcome, Outcome::Done);
        let own = format!("{}\\DiagnosticTool.exe", LOCAL_DUMPS.path).to_lowercase();
        let local = LOCAL_DUMPS.path.to_lowercase();
        // Someone removes LocalDumps and this program's key under it, then makes an empty
        // LocalDumps of their own.
        m.keys.remove(&(Hive::LocalMachine, own.clone()));
        m.keys.remove(&(Hive::LocalMachine, local.clone()));
        m.keys
            .insert((Hive::LocalMachine, local.clone()), Default::default());
        m.touch(Hive::LocalMachine, &local);
        let out = back(&mut m);
        assert_eq!(out.outcome, Outcome::Done, "{out:?}");
        assert!(
            m.keys.contains_key(&(Hive::LocalMachine, local)),
            "their key is kept"
        );
        assert!(
            out.notes.iter().any(|n| n.contains("LocalDumps is kept")),
            "{:?}",
            out.notes
        );
    }

    /// The guard: a saved file from before set up recorded what it wrote cannot be put back
    /// safely: Put back and set up both refuse, change nothing, and list the values as they
    /// were for putting back by hand.
    #[test]
    fn an_older_saved_file_is_refused_with_the_values_as_they_were() {
        let mut m = runner_like();
        assert_eq!(set(&mut m, &confirmed()).outcome, Outcome::Done);
        let (file, text) = m
            .state
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let mut old: serde_json::Value = serde_json::from_str(&text).unwrap();
        old["version"] = 2.into();
        m.state.insert(file, old.to_string());
        // A setting changed since, so set up has something to do and reads the file.
        m.keys
            .get_mut(&(Hive::LocalMachine, CRASH_CONTROL.path.to_lowercase()))
            .unwrap()
            .remove("alwayskeepmemorydump");
        let (keys, writes) = (m.keys.clone(), m.writes);
        for out in [back(&mut m), set(&mut m, &confirmed())] {
            assert!(
                matches!(&out.outcome, Outcome::Refused { reasons }
                    if reasons[0].contains("older version")
                        && reasons[0].contains("AlwaysKeepMemoryDump was absent")),
                "{out:?}"
            );
        }
        assert_eq!((m.keys, m.writes), (keys, writes));
    }

    /// The guard: the saved file is checked against what set up writes: a value recorded
    /// as written by set up that set up never writes is refused before anything changes.
    #[test]
    fn a_recorded_write_set_up_never_makes_is_refused() {
        let mut m = runner_like();
        assert_eq!(set(&mut m, &confirmed()).outcome, Outcome::Done);
        let (file, text) = m
            .state
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let mut edited: serde_json::Value = serde_json::from_str(&text).unwrap();
        for value in edited["values"].as_array_mut().unwrap() {
            if value["name"] == "DumpType" {
                value["after"] = serde_json::json!({"kind": 4, "data": "09000000"});
            }
        }
        m.state.insert(file, edited.to_string());
        let writes = m.writes;
        let out = back(&mut m);
        assert!(
            matches!(&out.outcome, Outcome::Refused { reasons }
                if reasons[0].contains("not a value set up writes")),
            "{out:?}"
        );
        assert_eq!(m.writes, writes);
    }
}
