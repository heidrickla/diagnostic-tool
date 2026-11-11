//! The registry places crash dump set up and the recovery window's exclusion put back, each
//! through the program's one compare-and-swap (`crate::restore`): a value is put back only
//! while it holds what this program wrote, and a key this program made is removed only
//! while it is the key it made, known by its last-write time. Each compares and writes as
//! one operation of the machine's: a registry transaction for a value or a key, one handle
//! for a folder.
use std::path::Path;

use super::machine::{Hive, Machine, RawValue};
use crate::restore::{put_back_if_still, Place, PutBack, Swap};

/// One registry value: absent (`None`) or its type and bytes.
struct ValuePlace<'a, M: Machine> {
    m: &'a mut M,
    hive: Hive,
    key: &'a str,
    name: &'a str,
}

impl<M: Machine> Place for ValuePlace<'_, M> {
    type Value = Option<RawValue>;
    fn read(&mut self) -> Result<Option<RawValue>, String> {
        self.m.read_value(self.hive, self.key, self.name)
    }
    fn swap(
        &mut self,
        expect: &Option<RawValue>,
        value: &Option<RawValue>,
    ) -> Result<Swap<Option<RawValue>>, String> {
        self.m
            .swap_value(self.hive, self.key, self.name, expect, value)
    }
}

/// One registry key this program made: its last-write time while it exists, `None` when it
/// does not. Putting it back to `None` removes it only while it is empty.
struct KeyPlace<'a, M: Machine> {
    m: &'a mut M,
    hive: Hive,
    key: &'a str,
}

impl<M: Machine> Place for KeyPlace<'_, M> {
    type Value = Option<u64>;
    fn read(&mut self) -> Result<Option<u64>, String> {
        self.m.key_stamp(self.hive, self.key)
    }
    fn swap(
        &mut self,
        expect: &Option<u64>,
        value: &Option<u64>,
    ) -> Result<Swap<Option<u64>>, String> {
        let (Some(stamp), None) = (expect, value) else {
            return Err("a key is never made by putting back".into());
        };
        self.m.remove_key_if(self.hive, self.key, *stamp)
    }
}

/// The keys this program made and still answers for: each with the last-write time it left
/// the key at, `None` once someone else wrote to it (or it could not be read). Every write
/// this program makes in such a key goes through `restore_value` or `remove_key`, which
/// check the time before and take the new one after, so a change by anyone else between
/// two of them is seen.
#[derive(Clone, Debug, Default)]
pub(super) struct Custody {
    keys: Vec<(String, Option<u64>)>,
    /// Keys that were found changed by someone else, with what was found.
    pub(super) lost: Vec<String>,
}

fn parent(key: &str) -> Option<&str> {
    key.rsplit_once('\\').map(|(p, _)| p)
}

impl Custody {
    /// Custody of `made`, the keys this program made, as `stamps` recorded them when this
    /// program last wrote to them. A key with no stamp recorded, or one that reads
    /// otherwise now, is not this program's to remove.
    pub(super) fn take<M: Machine>(m: &M, made: &[String], stamps: &[(String, u64)]) -> Self {
        let mut custody = Custody::default();
        for key in made {
            let recorded = stamps
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, s)| *s);
            let ours = match (recorded, m.key_stamp(Hive::LocalMachine, key)) {
                (Some(recorded), Ok(Some(now))) if now == recorded => Some(now),
                (_, Ok(None)) => None,
                (None, _) => {
                    custody.lost.push(format!(
                        "HKLM\\{key} is kept: when this program made it, it could not record which key it made, so it cannot tell it from one made since"
                    ));
                    None
                }
                (Some(_), Ok(Some(_))) => {
                    custody.lost.push(format!(
                        "HKLM\\{key} is kept: it was written to since this program last wrote to it, so it may not be the key this program made"
                    ));
                    None
                }
                (Some(_), Err(why)) => {
                    custody.lost.push(format!(
                        "HKLM\\{key} is kept: when it was last written could not be read ({why})"
                    ));
                    None
                }
            };
            custody.keys.push((key.clone(), ours));
        }
        custody
    }

    /// The last-write time this program left `key` at, while it still answers for it.
    pub(super) fn stamp(&self, key: &str) -> Option<u64> {
        self.keys
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .and_then(|(_, s)| *s)
    }

    /// The keys still answered for, with their stamps.
    pub(super) fn held(&self) -> Vec<(String, u64)> {
        self.keys
            .iter()
            .filter_map(|(k, s)| s.map(|s| (k.clone(), s)))
            .collect()
    }

    /// Before this program writes to `key` (not a restore: the exclusion's own write): a
    /// key, or its parent, written to by something else since is no longer answered for.
    pub(super) fn before_write<M: Machine>(&mut self, m: &M, key: &str) {
        self.check(m, key);
        if let Some(up) = parent(key) {
            self.check(m, up);
        }
    }

    /// After this program wrote to `key`: the times it left `key` and its parent at, and
    /// `key` answered for from now when this write `made` it.
    pub(super) fn after_write<M: Machine>(&mut self, m: &M, key: &str, made: bool) {
        if made {
            let stamp = m.key_stamp(Hive::LocalMachine, key).ok().flatten();
            self.keys.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
            self.keys.push((key.to_string(), stamp));
        } else {
            self.renew(m, key);
        }
        if let Some(up) = parent(key) {
            self.renew(m, up);
        }
    }

    fn check<M: Machine>(&mut self, m: &M, key: &str) {
        let Some(at) = self
            .keys
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case(key))
        else {
            return;
        };
        let Some(expected) = self.keys[at].1 else {
            return;
        };
        if m.key_stamp(Hive::LocalMachine, key) != Ok(Some(expected)) {
            self.keys[at].1 = None;
            self.lost.push(format!(
                "HKLM\\{key} is kept: it was written to by something else while the settings were put back"
            ));
        }
    }

    fn renew<M: Machine>(&mut self, m: &M, key: &str) {
        if let Some(entry) = self
            .keys
            .iter_mut()
            .find(|(k, s)| k.eq_ignore_ascii_case(key) && s.is_some())
        {
            entry.1 = m.key_stamp(Hive::LocalMachine, key).ok().flatten();
        }
    }
}

/// Puts one value back to `before` only while it holds `wrote`, what this program wrote,
/// keeping custody of the key it is in.
pub(super) fn restore_value<M: Machine>(
    m: &mut M,
    custody: &mut Custody,
    hive: Hive,
    key: &str,
    name: &str,
    wrote: &Option<RawValue>,
    before: &Option<RawValue>,
) -> PutBack<Option<RawValue>> {
    custody.check(&*m, key);
    let outcome = put_back_if_still(
        &mut ValuePlace {
            m: &mut *m,
            hive,
            key,
            name,
        },
        wrote,
        before,
    );
    custody.renew(&*m, key);
    outcome
}

/// Removes `key`, which this program made, only while custody still holds it and it is
/// empty. `None` when custody had lost it, so it was not touched.
pub(super) fn remove_key<M: Machine>(
    m: &mut M,
    custody: &mut Custody,
    key: &str,
) -> Option<PutBack<Option<u64>>> {
    custody.check(&*m, key);
    if let Some(up) = parent(key) {
        custody.check(&*m, up);
    }
    let stamp = custody.stamp(key)?;
    let outcome = put_back_if_still(
        &mut KeyPlace {
            m: &mut *m,
            hive: Hive::LocalMachine,
            key,
        },
        &Some(stamp),
        &None,
    );
    if let Some(up) = parent(key) {
        custody.renew(&*m, up);
    }
    if let Some(entry) = custody
        .keys
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
    {
        entry.1 = None;
    }
    Some(outcome)
}

/// A folder this program made: its identity while it is there (`Machine::folder_id`),
/// `None` when it is not. Putting it back to `None` removes it only while it is empty.
struct FolderPlace<'a, M: Machine> {
    m: &'a mut M,
    path: &'a Path,
}

impl<M: Machine> Place for FolderPlace<'_, M> {
    type Value = Option<String>;
    fn read(&mut self) -> Result<Option<String>, String> {
        self.m.folder_id(self.path)
    }
    fn swap(
        &mut self,
        expect: &Option<String>,
        value: &Option<String>,
    ) -> Result<Swap<Option<String>>, String> {
        let (Some(id), None) = (expect, value) else {
            return Err("a folder is never made by putting back".into());
        };
        self.m.remove_folder_if(self.path, id)
    }
}

/// Removes `path`, a folder this program made with identity `id`, only while it is still
/// that folder and empty.
pub(super) fn remove_folder<M: Machine>(
    m: &mut M,
    path: &Path,
    id: String,
) -> PutBack<Option<String>> {
    put_back_if_still(&mut FolderPlace { m, path }, &Some(id), &None)
}

/// The value as people read it, "absent" when it is not there.
pub(super) fn shown(value: Option<&RawValue>) -> String {
    value.map_or("absent".to_string(), RawValue::describe)
}

#[cfg(test)]
mod tests {
    use super::super::fake::Fake;
    use super::super::machine::CRASH_CONTROL;
    use super::*;

    /// The guard (cause F): another writer's change, made after the value was read as this
    /// program's and before it is put back, is kept and said: the compare and the write
    /// are one swap of the machine's, never a read and a separate write.
    #[test]
    fn a_change_between_the_read_and_the_write_is_kept() {
        let name = "CrashDumpEnabled";
        let (ours, before) = (Some(RawValue::dword(3)), Some(RawValue::dword(7)));
        let theirs = Some(RawValue::dword(1));
        let mut m = Fake::windows_default();
        m.dword(CRASH_CONTROL, name, 3);
        m.racer = Some((
            Hive::LocalMachine,
            CRASH_CONTROL.path.into(),
            name.into(),
            theirs.clone(),
        ));
        let mut custody = Custody::default();
        let hive = Hive::LocalMachine;
        let outcome = restore_value(
            &mut m,
            &mut custody,
            hive,
            CRASH_CONTROL.path,
            name,
            &ours,
            &before,
        );
        assert_eq!(
            outcome,
            PutBack::LeftChanged {
                now: theirs.clone()
            }
        );
        assert_eq!(
            m.read_value(hive, CRASH_CONTROL.path, name),
            Ok(theirs),
            "the other writer's change was overwritten"
        );
        // With no other writer it is put back.
        m.dword(CRASH_CONTROL, name, 3);
        let outcome = restore_value(
            &mut m,
            &mut custody,
            hive,
            CRASH_CONTROL.path,
            name,
            &ours,
            &before,
        );
        assert_eq!(outcome, PutBack::PutBack);
        assert_eq!(m.read_value(hive, CRASH_CONTROL.path, name), Ok(before));
    }
}
