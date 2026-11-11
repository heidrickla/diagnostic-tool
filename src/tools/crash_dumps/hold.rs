//! The recovery window's own exclusion from application crash dumps. Before a recovery key
//! enters this process, and while application crash dumps are on (the LocalDumps key
//! exists, which Windows reads as on for every program, measured), the process writes
//! `LocalDumps\<this exe's file name>` `DumpCount` 0, which Windows reads as keep no dump of
//! it, and reads it back. A file in `%ProgramData%\DiagnosticTool` records each process
//! that relies on the exclusion and what it wrote, so the last one to let go removes only
//! that, a process that ended without letting go is settled at the next start, and crash
//! dump set up and Put back, which keep the same exclusion for their own reasons, hand it
//! over rather than remove it while the other still relies on it.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::machine::{Hive, Machine, RawValue, LOCAL_DUMPS};
use super::places::{remove_key, restore_value, shown, Custody};
use super::setup::{self, own_key, MAX_SAVED_BYTES, OWN_NAME};
use crate::restore::PutBack;

/// Where the exclusion's holders and what it wrote are kept.
pub const HOLD_FILE: &str = r"%ProgramData%\DiagnosticTool\recovery-dump-exclusion.json";
const HOLD_VERSION: u32 = 1;
/// More holders than this is not a file this program wrote.
const MAX_HOLDERS: usize = 64;

/// The change record's heading for the exclusion made.
pub const KEPT_OUT: &str = "Kept this program out of crash dumps while a recovery key was in use";
/// The change record's heading for the exclusion taken away again.
pub const LET_IN: &str =
    "Took away this program's exclusion from crash dumps once no recovery key was in use";

/// The exclusion as the file records it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Hold {
    version: u32,
    /// The program file name the exclusion is under.
    pub(super) exe: String,
    /// Each process relying on it: id and start time.
    pub(super) holders: Vec<(u32, u64)>,
    /// Whether this file owns the value: it wrote it, or Put back handed it over.
    pub(super) wrote: bool,
    /// The value before it was written: `None` when absent.
    pub(super) before: Option<RawValue>,
    /// Keys made for it that are removed with it when empty, parents first.
    pub(super) keys_made: Vec<String>,
    /// When this program last wrote to each of those keys (`Machine::key_stamp`); a key
    /// that reads otherwise, or has no time here, is kept.
    #[serde(default)]
    pub(super) key_stamps: Vec<(String, u64)>,
}

impl Hold {
    fn new(exe: &str) -> Self {
        Self {
            version: HOLD_VERSION,
            exe: exe.into(),
            ..Self::default()
        }
    }
}

pub(super) fn hold_path<M: Machine>(m: &M) -> Result<PathBuf, String> {
    Ok(PathBuf::from(m.expand(HOLD_FILE)?))
}

/// Refuses a file naming anything but this exclusion: a program file name, its own key
/// and LocalDumps, a value no larger than a setting, a bounded list of holders.
fn check(hold: &Hold) -> Result<(), String> {
    if hold.version != HOLD_VERSION {
        return Err(format!(
            "is in format {}, which this version does not read",
            hold.version
        ));
    }
    let exe = &hold.exe;
    let plain = !exe.is_empty()
        && exe.len() <= 255
        && !exe.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|'])
        && exe.to_ascii_lowercase().ends_with(".exe");
    if !plain {
        return Err(format!("names {exe:?}, which is not a program file name"));
    }
    if hold.holders.len() > MAX_HOLDERS {
        return Err(format!("names {} holders", hold.holders.len()));
    }
    if hold
        .before
        .as_ref()
        .is_some_and(|b| b.data.len() > MAX_SAVED_BYTES)
    {
        return Err("holds a value larger than a setting".into());
    }
    let own = own_key(exe);
    for (i, key) in hold.keys_made.iter().enumerate() {
        if !(key.eq_ignore_ascii_case(LOCAL_DUMPS.path) || key.eq_ignore_ascii_case(&own)) {
            return Err(format!(
                "names the key HKLM\\{key}, which the exclusion never makes"
            ));
        }
        if hold.keys_made[..i]
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        {
            return Err(format!("names the key HKLM\\{key} twice"));
        }
    }
    for (key, _) in &hold.key_stamps {
        if !hold.keys_made.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            return Err(format!(
                "holds when HKLM\\{key} was written, which is not a key it made"
            ));
        }
    }
    Ok(())
}

fn read<M: Machine>(m: &M, path: &Path) -> Result<Option<Hold>, String> {
    let Some(text) = m.read_state(path)? else {
        return Ok(None);
    };
    let hold: Hold = serde_json::from_str(&text)
        .map_err(|e| format!("{} could not be read ({e})", path.display()))?;
    check(&hold).map_err(|why| format!("{} {why}", path.display()))?;
    Ok(Some(hold))
}

/// Writes the file and reads it back.
fn save<M: Machine>(m: &mut M, path: &Path, hold: &Hold) -> Result<(), String> {
    let text = serde_json::to_string_pretty(hold).map_err(|e| e.to_string())?;
    m.write_state(path, &text)?;
    match read(m, path)? {
        Some(read) if read == *hold => Ok(()),
        _ => Err(format!("{} did not read back as written", path.display())),
    }
}

/// The file with the holders that still run, `None` when there is no file.
fn live<M: Machine>(m: &M, path: &Path) -> Result<Option<Hold>, String> {
    let mut hold = read(m, path)?;
    if let Some(hold) = hold.as_mut() {
        hold.holders
            .retain(|&(pid, started)| m.running(pid, started));
    }
    Ok(hold)
}

fn line(key: &str, before: Option<&RawValue>, after: Option<&RawValue>) -> String {
    let show = |v: Option<&RawValue>| v.map_or("absent".to_string(), RawValue::describe);
    format!(
        "HKLM\\{key}\\{OWN_NAME}: {} to {}",
        show(before),
        show(after)
    )
}

/// The refusal when the exclusion cannot be made sure of, `why` saying what failed.
fn cannot(why: &str) -> String {
    format!(
        "{why}. Windows is set to keep a dump of any program that crashes (application crash dumps are on), and this program could not make sure it is left out, so no recovery key is taken in: a dump of it would hold the key. Run this program with administrator rights, or turn application crash dumps off (remove HKLM\\{}, or Put back in Crash dump readiness if this tool turned them on), then try again.",
        LOCAL_DUMPS.path
    )
}

/// Adds this process to the exclusion's holders and, while application crash dumps are
/// on, makes sure this program's own LocalDumps `DumpCount` is 0, writing it if not, then
/// reads it back. Ok carries the change record's lines (none when nothing was written).
/// Err is a sentence saying why no recovery key may be taken in; the caller then lets go.
pub(super) fn keep_out<M: Machine>(m: &mut M) -> Result<Vec<String>, String> {
    let unread = |why: String| {
        cannot(&format!(
            "Whether Windows would keep a dump of this program could not be read ({why})"
        ))
    };
    let path = hold_path(m).map_err(unread)?;
    let exe = m.exe_name().map_err(unread)?;
    // A holder recorded without its start time would read as ended, and its exclusion be
    // taken away while it runs.
    let me = m.this_process().map_err(|why| {
        cannot(&format!(
            "This program could not record itself as relying on its exclusion from crash dumps ({why})"
        ))
    })?;
    let on = m
        .key_exists(Hive::LocalMachine, LOCAL_DUMPS.path)
        .map_err(unread)?;
    let key = own_key(&exe);
    let off = Some(RawValue::dword(0));
    let mut lines = Vec::new();
    let found = match live(m, &path) {
        Ok(found) => found,
        Err(why) if on => return Err(unread(why)),
        // Nothing to keep out of while application dumps are off.
        Err(_) => return Ok(lines),
    };
    let mut hold = match found {
        Some(hold) if hold.exe.eq_ignore_ascii_case(&exe) => hold,
        Some(hold) if hold.holders.is_empty() => {
            lines.extend(settle(m, &path, hold).map_err(unread)?);
            Hold::new(&exe)
        }
        Some(hold) => {
            return Err(format!(
                "Another copy of this program, {}, is keeping itself out of crash dumps while it holds a recovery key, and both cannot be kept track of at once, so no recovery key is taken in here. Close that copy, then try again.",
                hold.exe
            ))
        }
        None => Hold::new(&exe),
    };
    if !hold.holders.contains(&me) {
        hold.holders.push(me);
    }
    let now = if on {
        m.read_value(Hive::LocalMachine, &key, OWN_NAME)
            .map_err(unread)?
    } else {
        None
    };
    let write = on && now != off;
    let mut made = false;
    if write {
        // A value changed since this program wrote 0 is someone else's: it is the one to
        // put back, not the one found before.
        if hold.wrote {
            lines.push(format!(
                "HKLM\\{key}\\{OWN_NAME} was changed since this program wrote 0, to {}: that is what is put back once no recovery key is in use",
                shown(now.as_ref())
            ));
        }
        hold.wrote = true;
        hold.before = now.clone();
        made = !m.key_exists(Hive::LocalMachine, &key).map_err(unread)?;
        if made && !hold.keys_made.iter().any(|k| k.eq_ignore_ascii_case(&key)) {
            hold.keys_made.push(key.clone());
        }
    }
    // Saved before the write, so a process that ends at any point leaves what it wrote
    // recorded for the next start to take away.
    if let Err(why) = save(m, &path, &hold) {
        if on {
            return Err(cannot(&format!(
                "This program could not record its exclusion from crash dumps ({why})"
            )));
        }
        return Ok(lines);
    }
    if !on {
        return Ok(lines);
    }
    if write {
        let mut custody = Custody::take(&*m, &hold.keys_made, &hold.key_stamps);
        custody.before_write(&*m, &key);
        m.write_value(Hive::LocalMachine, &key, OWN_NAME, &RawValue::dword(0))
            .map_err(|why| {
                cannot(&format!(
                    "HKLM\\{key}\\{OWN_NAME} could not be written ({why})"
                ))
            })?;
        custody.after_write(&*m, &key, made);
        lines.push(line(&key, now.as_ref(), off.as_ref()));
        hold.key_stamps = custody.held();
        if let Err(why) = save(m, &path, &hold) {
            lines.push(format!(
                "When HKLM\\{key} was written could not be recorded ({why}); the key is kept when the exclusion is taken away"
            ));
        }
    }
    match m.read_value(Hive::LocalMachine, &key, OWN_NAME) {
        Ok(read) if read == off => Ok(lines),
        Ok(read) => Err(cannot(&format!(
            "HKLM\\{key}\\{OWN_NAME} reads back as {}, not 0",
            read.as_ref()
                .map_or("absent".to_string(), RawValue::describe)
        ))),
        Err(why) => Err(cannot(&format!(
            "HKLM\\{key}\\{OWN_NAME} could not be read back ({why})"
        ))),
    }
}

/// Takes this process off the holders; the last holder settles the exclusion
/// (`settle`). Ok carries the change record's lines.
pub(super) fn let_go<M: Machine>(m: &mut M) -> Result<Vec<String>, String> {
    let path = hold_path(m)?;
    let me = m.this_process()?;
    let Some(mut hold) = live(m, &path)? else {
        return Ok(Vec::new());
    };
    hold.holders.retain(|h| *h != me);
    if !hold.holders.is_empty() {
        save(m, &path, &hold)?;
        return Ok(Vec::new());
    }
    settle(m, &path, hold)
}

/// Settles an exclusion left by processes that ended without letting go, as at the start
/// of the recovery window and before Put back. Nothing changes while a holder runs.
pub(super) fn settle_left<M: Machine>(m: &mut M) -> Result<Vec<String>, String> {
    let path = hold_path(m)?;
    match live(m, &path)? {
        Some(hold) if hold.holders.is_empty() => settle(m, &path, hold),
        _ => Ok(Vec::new()),
    }
}

/// With no holder left: hands what the file owns to crash dump set up's saved settings when
/// set up is in effect (it keeps the same exclusion, and Put back takes it away), or else
/// puts the value back as it was and removes the keys made for it when empty. Then removes
/// the file.
fn settle<M: Machine>(m: &mut M, path: &Path, mut hold: Hold) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let key = own_key(&hold.exe);
    // Only the 0 this program wrote is its to take away: a value changed since is someone
    // else's, and is left as it is.
    let off = Some(RawValue::dword(0));
    let now = m.read_value(Hive::LocalMachine, &key, OWN_NAME)?;
    if hold.wrote && now != off {
        if now != hold.before {
            lines.push(format!(
                "HKLM\\{key}\\{OWN_NAME} is {}, not the 0 this program wrote: it was changed since, so it is left as it is",
                shown(now.as_ref())
            ));
        }
        hold.wrote = false;
    }
    let ours = m
        .exe_name()
        .is_ok_and(|exe| exe.eq_ignore_ascii_case(&hold.exe));
    if (hold.wrote || !hold.keys_made.is_empty()) && ours && setup::take_over(m, &hold)? {
        lines.push(format!(
            "HKLM\\{key}\\{OWN_NAME} is left at 0: crash dump set up is in effect and keeps it; its Put back takes it away"
        ));
    } else {
        let mut custody = Custody::take(&*m, &hold.keys_made, &hold.key_stamps);
        if hold.wrote {
            match restore_value(
                m,
                &mut custody,
                Hive::LocalMachine,
                &key,
                OWN_NAME,
                &off,
                &hold.before,
            ) {
                PutBack::PutBack => lines.push(line(&key, off.as_ref(), hold.before.as_ref())),
                PutBack::AlreadyBack => {}
                PutBack::LeftChanged { now } => lines.push(format!(
                    "HKLM\\{key}\\{OWN_NAME} is {}, not the 0 this program wrote: it was changed since, so it is left as it is",
                    shown(now.as_ref())
                )),
                PutBack::Unknown { why } | PutBack::Failed { why } => {
                    return Err(format!(
                        "HKLM\\{key}\\{OWN_NAME} could not be put back ({why}); {} is kept for another try",
                        path.display()
                    ))
                }
            }
        }
        for made in hold.keys_made.iter().rev() {
            match remove_key(m, &mut custody, made) {
                None | Some(PutBack::AlreadyBack) => {}
                Some(PutBack::PutBack) => lines.push(format!("Key HKLM\\{made} removed")),
                Some(PutBack::LeftChanged { .. }) => lines.push(format!(
                    "HKLM\\{made} is kept: it was written to since, so it may not be the key this program made"
                )),
                Some(PutBack::Failed { why }) | Some(PutBack::Unknown { why }) => {
                    lines.push(format!("HKLM\\{made} is kept: {why}"))
                }
            }
        }
        lines.append(&mut custody.lost);
    }
    m.remove_state(path)?;
    Ok(lines)
}

/// For Put back: whether a running process relies on the exclusion. When one does, the
/// value and keys Put back would take away are handed to the file instead (`before` is the
/// value as set up found it, `keys` the keys set up made), so the last holder takes them
/// away. Ok(true) when they were handed over.
pub(super) fn hand_to_holders<M: Machine>(
    m: &mut M,
    before: Option<&RawValue>,
    keys: &[String],
) -> Result<bool, String> {
    let path = hold_path(m)?;
    let Some(mut hold) = live(m, &path)? else {
        return Ok(false);
    };
    if hold.holders.is_empty() {
        return Ok(false);
    }
    if !hold.wrote {
        hold.wrote = true;
        hold.before = before.cloned();
    }
    for key in keys {
        if !hold.keys_made.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            if key.eq_ignore_ascii_case(LOCAL_DUMPS.path) {
                hold.keys_made.insert(0, key.clone());
            } else {
                hold.keys_made.push(key.clone());
            }
        }
    }
    save(m, &path, &hold)?;
    Ok(true)
}

/// For Put back, once it has put its values back: when it last wrote to each key it handed
/// to the holders, so the last holder removes only those very keys. A key with no time is
/// kept.
pub(super) fn stamp_keys<M: Machine>(m: &mut M, stamps: &[(String, u64)]) -> Result<(), String> {
    let path = hold_path(m)?;
    let Some(mut hold) = read(m, &path)? else {
        return Ok(());
    };
    for (key, stamp) in stamps {
        if hold.keys_made.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            hold.key_stamps
                .retain(|(k, _)| !k.eq_ignore_ascii_case(key));
            hold.key_stamps.push((key.clone(), *stamp));
        }
    }
    save(m, &path, &hold)
}

/// For crash dump set up's tests and Put back: the exe the running holders keep out, if any.
pub(super) fn held_for<M: Machine>(m: &M) -> Result<Option<String>, String> {
    let path = hold_path(m)?;
    Ok(live(m, &path)?
        .filter(|hold| !hold.holders.is_empty())
        .map(|hold| hold.exe))
}

#[cfg(test)]
mod tests {
    use super::super::fake::Fake;
    use super::super::machine::Key;
    use super::super::{PutBackOptions, SetUpOptions};
    use super::*;
    use std::sync::atomic::AtomicBool;

    const OWN: &str =
        r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\DiagnosticTool.exe";

    /// A PC whose LocalDumps key a vendor made for its own program, which turns application
    /// dumps on for every program.
    fn vendor_dumps() -> Fake {
        let mut m = Fake::windows_default();
        m.dword(
            Key {
                hive: Hive::LocalMachine,
                path: r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\nvcontainer.exe",
            },
            "DumpCount",
            10,
        );
        // As in the registry, the vendor's key has its parent.
        m.keys
            .entry((Hive::LocalMachine, LOCAL_DUMPS.path.to_lowercase()))
            .or_default();
        m.process = (40, 7);
        m
    }

    fn own_value(m: &Fake) -> Option<RawValue> {
        m.read_value(Hive::LocalMachine, OWN, OWN_NAME).unwrap()
    }

    fn file(m: &Fake) -> Option<Hold> {
        read(m, &hold_path(m).unwrap()).unwrap()
    }

    fn set_up(m: &mut Fake) {
        let options = SetUpOptions {
            confirmed: true,
            ..SetUpOptions::default()
        };
        let out = setup::set_up(m, &options, &mut |_| {}, &AtomicBool::new(false));
        assert_eq!(out.outcome, super::super::Outcome::Done, "{out:?}");
    }

    fn put_back(m: &mut Fake) -> super::super::ChangeResult {
        let options = PutBackOptions { confirmed: true };
        setup::put_back(m, &options, &mut |_| {}, &AtomicBool::new(false))
    }

    /// The guard: while application dumps are on, a key comes in only once this program's
    /// own LocalDumps DumpCount reads back 0, under its actual file name, recorded in the
    /// change record; letting go puts back exactly what was there, and with application
    /// dumps off nothing is written.
    #[test]
    fn a_key_comes_in_only_with_this_program_kept_out_of_dumps() {
        let mut m = vendor_dumps();
        let before = m.keys.clone();
        let lines = keep_out(&mut m).unwrap();
        assert_eq!(own_value(&m), Some(RawValue::dword(0)));
        assert_eq!(lines, vec![format!("HKLM\\{OWN}\\DumpCount: absent to 0")]);
        let hold = file(&m).unwrap();
        assert_eq!(hold.holders, vec![(40, 7)]);
        assert!(hold.wrote && hold.before.is_none());
        assert_eq!(hold.keys_made, vec![OWN.to_string()]);
        // Asked again while held: nothing more is written.
        let writes = m.writes;
        assert_eq!(keep_out(&mut m).unwrap(), Vec::<String>::new());
        assert_eq!(m.writes, writes);
        let lines = let_go(&mut m).unwrap();
        assert_eq!(m.keys, before, "only what the exclusion made is taken away");
        assert!(file(&m).is_none());
        assert_eq!(lines[0], format!("HKLM\\{OWN}\\DumpCount: 0 to absent"));

        // A renamed program is kept out under the name it runs as.
        let mut m = vendor_dumps();
        m.exe = Some("Rescue-2.exe".into());
        keep_out(&mut m).unwrap();
        let renamed = format!("{}\\Rescue-2.exe", LOCAL_DUMPS.path);
        assert_eq!(
            m.read_value(Hive::LocalMachine, &renamed, OWN_NAME)
                .unwrap(),
            Some(RawValue::dword(0))
        );
        let_go(&mut m).unwrap();
        assert!(!m.key_exists(Hive::LocalMachine, &renamed).unwrap());

        // A value that was there is put back, and its key kept.
        let mut m = vendor_dumps();
        m.put(
            Key {
                hive: Hive::LocalMachine,
                path: OWN,
            },
            OWN_NAME,
            RawValue::dword(5),
        );
        let before = m.keys.clone();
        keep_out(&mut m).unwrap();
        assert_eq!(own_value(&m), Some(RawValue::dword(0)));
        let_go(&mut m).unwrap();
        assert_eq!(m.keys, before);

        // Application dumps off: nothing to keep out of, nothing written.
        let mut m = Fake::windows_default();
        let before = m.keys.clone();
        assert_eq!(keep_out(&mut m).unwrap(), Vec::<String>::new());
        assert_eq!(m.writes, 0);
        let_go(&mut m).unwrap();
        assert_eq!(m.keys, before);
        assert!(file(&m).is_none());
    }

    /// The guard: when the exclusion cannot be written, read back or recorded, no key comes
    /// in, the refusal says why and what to do, and letting go leaves nothing behind.
    #[test]
    fn a_hold_that_cannot_be_made_sure_of_refuses() {
        let own = Key {
            hive: Hive::LocalMachine,
            path: OWN,
        };
        let mut m = vendor_dumps();
        let before = m.keys.clone();
        m.fail_writes(own, OWN_NAME);
        let why = keep_out(&mut m).unwrap_err();
        assert!(why.contains("could not be written"), "{why}");
        assert!(why.contains("no recovery key is taken in"), "{why}");
        assert!(why.contains("administrator rights"), "{why}");
        let_go(&mut m).unwrap();
        assert_eq!(m.keys, before);
        assert!(file(&m).is_none());

        let mut m = vendor_dumps();
        m.fail_reads(own, OWN_NAME);
        let why = keep_out(&mut m).unwrap_err();
        assert!(why.contains("could not be read"), "{why}");

        // A file naming anything but the exclusion is not acted on.
        let mut m = vendor_dumps();
        keep_out(&mut m).unwrap();
        let path = hold_path(&m).unwrap();
        let text = m.read_state(&path).unwrap().unwrap();
        let mut edited: serde_json::Value = serde_json::from_str(&text).unwrap();
        edited["keys_made"] = serde_json::json!([r"SOFTWARE\Unrelated"]);
        m.write_state(&path, &edited.to_string()).unwrap();
        assert!(let_go(&mut m).unwrap_err().contains("never makes"));
        assert_eq!(own_value(&m), Some(RawValue::dword(0)));
    }

    /// The guard: the exclusion stays while any process relying on it runs; the last one
    /// takes it away, and one left by a process that ended is put back at the next start.
    #[test]
    fn the_last_holder_lets_go_and_a_left_hold_is_settled() {
        let mut m = vendor_dumps();
        let before = m.keys.clone();
        m.process = (1, 1);
        m.others.insert((2, 2));
        keep_out(&mut m).unwrap();
        m.process = (2, 2);
        m.others = [(1, 1)].into();
        keep_out(&mut m).unwrap();
        assert_eq!(file(&m).unwrap().holders, vec![(1, 1), (2, 2)]);
        let_go(&mut m).unwrap();
        assert_eq!(
            own_value(&m),
            Some(RawValue::dword(0)),
            "the first still relies on it"
        );
        assert_eq!(file(&m).unwrap().holders, vec![(1, 1)]);
        // The first ends without letting go; the next start settles it.
        m.process = (3, 3);
        m.others.clear();
        let lines = settle_left(&mut m).unwrap();
        assert_eq!(m.keys, before);
        assert!(file(&m).is_none());
        assert!(!lines.is_empty());

        // A running holder's exclusion is not settled.
        let mut m = vendor_dumps();
        keep_out(&mut m).unwrap();
        m.others.insert(m.process);
        m.process = (9, 9);
        assert_eq!(settle_left(&mut m).unwrap(), Vec::<String>::new());
        assert_eq!(own_value(&m), Some(RawValue::dword(0)));
    }

    /// The guard: an exclusion left behind is taken away only while the value is still the
    /// 0 this program wrote; a value someone changed since is left, and the record says so.
    #[test]
    fn a_value_changed_since_is_left_as_it_is() {
        let own = Key {
            hive: Hive::LocalMachine,
            path: OWN,
        };
        let mut m = vendor_dumps();
        keep_out(&mut m).unwrap();
        m.put(own, OWN_NAME, RawValue::dword(3));
        m.process = (41, 8);
        let lines = settle_left(&mut m).unwrap();
        assert_eq!(own_value(&m), Some(RawValue::dword(3)));
        assert!(m.key_exists(Hive::LocalMachine, OWN).unwrap());
        assert!(file(&m).is_none());
        assert!(
            lines
                .iter()
                .any(|l| l.contains("changed since, so it is left as it is")),
            "{lines:?}"
        );

        // Deleted since: nothing is written back.
        let mut m = vendor_dumps();
        m.put(own, OWN_NAME, RawValue::dword(5));
        keep_out(&mut m).unwrap();
        m.delete_value(Hive::LocalMachine, OWN, OWN_NAME).unwrap();
        m.process = (41, 8);
        settle_left(&mut m).unwrap();
        assert_eq!(own_value(&m), None);

        // Handed over to set up only while still 0.
        let mut m = vendor_dumps();
        keep_out(&mut m).unwrap();
        set_up(&mut m);
        m.put(own, OWN_NAME, RawValue::dword(3));
        let_go(&mut m).unwrap();
        let out = put_back(&mut m);
        assert_eq!(out.outcome, super::super::Outcome::Done, "{out:?}");
        assert_eq!(own_value(&m), Some(RawValue::dword(3)));
    }

    /// The guard: crash dump Put back does not take away the exclusion while a recovery
    /// window relies on it, and the window does not take it away while set up keeps it;
    /// each hands it to the other, and the last one puts everything back as it was.
    #[test]
    fn put_back_and_the_recovery_window_hand_the_exclusion_over() {
        // Set up made it; the window relies on it; Put back runs.
        let mut m = Fake::windows_default();
        m.process = (40, 7);
        let before = m.keys.clone();
        set_up(&mut m);
        assert_eq!(keep_out(&mut m).unwrap(), Vec::<String>::new());
        let out = put_back(&mut m);
        assert_eq!(out.outcome, super::super::Outcome::Done, "{out:?}");
        assert_eq!(own_value(&m), Some(RawValue::dword(0)));
        assert!(
            out.notes.iter().any(|n| n.contains("recovery window")),
            "{:?}",
            out.notes
        );
        let hold = file(&m).unwrap();
        assert!(hold.wrote && hold.before.is_none());
        assert_eq!(
            hold.keys_made,
            vec![LOCAL_DUMPS.path.to_string(), OWN.to_string()]
        );
        let_go(&mut m).unwrap();
        assert_eq!(m.keys, before);

        // The window made it; set up runs; the window lets go; Put back runs.
        let mut m = vendor_dumps();
        let before = m.keys.clone();
        keep_out(&mut m).unwrap();
        set_up(&mut m);
        let lines = let_go(&mut m).unwrap();
        assert_eq!(own_value(&m), Some(RawValue::dword(0)), "set up keeps it");
        assert!(lines[0].contains("Put back"), "{lines:?}");
        assert!(file(&m).is_none());
        let out = put_back(&mut m);
        assert_eq!(out.outcome, super::super::Outcome::Done, "{out:?}");
        assert_eq!(m.keys, before);
    }

    /// The guard: a value changed since the exclusion wrote 0 is the one put back, not the
    /// one found before it, so letting go never discards that change.
    #[test]
    fn a_value_changed_since_the_exclusion_wrote_is_the_one_put_back() {
        let mut m = vendor_dumps();
        let own: Key = Key {
            hive: Hive::LocalMachine,
            path: OWN,
        };
        m.dword(own, OWN_NAME, 3);
        keep_out(&mut m).unwrap();
        assert_eq!(own_value(&m), Some(RawValue::dword(0)));
        // Someone sets it to 5; the exclusion, asked again, writes 0 again.
        m.dword(own, OWN_NAME, 5);
        let lines = keep_out(&mut m).unwrap();
        assert!(
            lines.iter().any(|l| l.contains("was changed since")),
            "{lines:?}"
        );
        assert_eq!(file(&m).unwrap().before, Some(RawValue::dword(5)));
        let_go(&mut m).unwrap();
        assert_eq!(own_value(&m), Some(RawValue::dword(5)));
    }

    /// The guard: a process whose start time cannot be read is not recorded as a holder
    /// (it would read as ended, and the exclusion be taken away while it runs): no key.
    #[test]
    fn a_holder_without_a_start_time_is_refused() {
        let mut m = vendor_dumps();
        m.no_start = true;
        let why = keep_out(&mut m).unwrap_err();
        assert!(why.contains("start time could not be read"), "{why}");
        assert!(file(&m).is_none());
        assert_eq!(own_value(&m), None);
    }

    /// The guard: the key the exclusion made is removed only while it is that key; one
    /// removed and made again since is kept.
    #[test]
    fn a_key_the_exclusion_made_and_someone_made_again_is_kept() {
        let mut m = vendor_dumps();
        keep_out(&mut m).unwrap();
        let own = OWN.to_lowercase();
        assert!(m.keys.contains_key(&(Hive::LocalMachine, own.clone())));
        m.keys.remove(&(Hive::LocalMachine, own.clone()));
        m.keys
            .insert((Hive::LocalMachine, own.clone()), Default::default());
        m.touch(Hive::LocalMachine, &own);
        let lines = let_go(&mut m).unwrap();
        assert!(m.keys.contains_key(&(Hive::LocalMachine, own)), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("is kept")), "{lines:?}");
        assert!(file(&m).is_none());
    }
}
