//! Undoing a change this program made. Every restore is compare-and-swap: a place is put
//! back to what it held before only while it still holds exactly what this program wrote
//! there. A place someone changed since is left as it is and said; a place whose state
//! cannot be read is left and said. Restores write only through `put_back_if_still`, which
//! a source guard below checks for every restore in the program.
//!
//! A place has no plain write: it writes only through `Place::swap`, which compares and
//! writes as one operation wherever Windows offers one (a registry transaction for a
//! registry value or key, one handle for a file or a folder, checked and renamed or removed
//! through it). Where Windows offers none (a BitLocker volume's lock, a drive's read limit,
//! a disk's offline attribute), the place checks again just before it writes and says its
//! residual in a `Residual:` comment on its `swap`.
//!
//! What "the same" means is the place's to say through its `Value`: a registry value's
//! type and bytes, a registry key's last-write time, a volume's lock state with its
//! identity, a file's identity at a path.

/// Something this program changed and may put back.
pub trait Place {
    /// What the place holds, compared whole.
    type Value: Clone + PartialEq;
    /// What the place holds now.
    fn read(&mut self) -> Result<Self::Value, String>;
    /// Puts `value` in the place only while it holds `expect`, the compare and the write as
    /// one operation where Windows offers one; `Changed` with what it holds otherwise, and
    /// nothing written.
    fn swap(
        &mut self,
        expect: &Self::Value,
        value: &Self::Value,
    ) -> Result<Swap<Self::Value>, String>;
}

/// What a swap did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Swap<T> {
    /// It held what was expected, and holds the new value now.
    Done,
    /// It held something else, kept as it is.
    Changed(T),
}

/// What a restore found and did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutBack<T> {
    /// It held what this program wrote; it holds what it held before again, read back.
    PutBack,
    /// It already held what it held before; nothing was written.
    AlreadyBack,
    /// It holds something this program did not write: changed since, so left as it is.
    LeftChanged { now: T },
    /// What it holds could not be read, so nothing was written.
    Unknown { why: String },
    /// The write, or reading it back, failed: what it holds now is not known.
    Failed { why: String },
}

impl<T> PutBack<T> {
    /// Whether the place now holds what it held before.
    pub fn is_back(&self) -> bool {
        matches!(self, PutBack::PutBack | PutBack::AlreadyBack)
    }
}

/// Puts `place` back to `before` only while it still holds `wrote`, what this program put
/// there, and reads it back. The one way a restore writes.
pub fn put_back_if_still<P: Place>(
    place: &mut P,
    wrote: &P::Value,
    before: &P::Value,
) -> PutBack<P::Value> {
    let now = match place.read() {
        Ok(now) => now,
        Err(why) => return PutBack::Unknown { why },
    };
    if now == *before {
        return PutBack::AlreadyBack;
    }
    if now != *wrote {
        return PutBack::LeftChanged { now };
    }
    match place.swap(wrote, before) {
        Ok(Swap::Done) => {}
        Ok(Swap::Changed(now)) => return PutBack::LeftChanged { now },
        Err(why) => return PutBack::Failed { why },
    }
    match place.read() {
        Ok(back) if back == *before => PutBack::PutBack,
        Ok(_) => PutBack::Failed {
            why: "it does not read back as it was".into(),
        },
        Err(why) => PutBack::Failed {
            why: format!("it could not be read back ({why})"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A place that some other writer may change between the read and the write: `racer`
    /// is written by that writer right after the first read.
    struct Cell {
        value: u32,
        reads: usize,
        fail_read: bool,
        fail_write: bool,
        racer: Option<u32>,
    }

    impl Place for Cell {
        type Value = u32;
        fn read(&mut self) -> Result<u32, String> {
            self.reads += 1;
            if self.fail_read {
                return Err("denied".into());
            }
            let now = self.value;
            if let Some(other) = self.racer.take() {
                self.value = other;
            }
            Ok(now)
        }
        fn swap(&mut self, expect: &u32, value: &u32) -> Result<Swap<u32>, String> {
            if self.fail_write {
                return Err("denied".into());
            }
            if self.value != *expect {
                return Ok(Swap::Changed(self.value));
            }
            self.value = *value;
            Ok(Swap::Done)
        }
    }

    fn cell(value: u32) -> Cell {
        Cell {
            value,
            reads: 0,
            fail_read: false,
            fail_write: false,
            racer: None,
        }
    }

    #[test]
    fn only_what_this_program_wrote_is_put_back() {
        let mut ours = cell(7);
        assert_eq!(put_back_if_still(&mut ours, &7, &1), PutBack::PutBack);
        assert_eq!(ours.value, 1);
        assert_eq!(ours.reads, 2, "read, then read back");

        let mut changed = cell(9);
        assert_eq!(
            put_back_if_still(&mut changed, &7, &1),
            PutBack::LeftChanged { now: 9 }
        );
        assert_eq!(changed.value, 9, "a value changed since is left");

        let mut back = cell(1);
        assert_eq!(put_back_if_still(&mut back, &7, &1), PutBack::AlreadyBack);

        let mut unread = cell(7);
        unread.fail_read = true;
        assert!(matches!(
            put_back_if_still(&mut unread, &7, &1),
            PutBack::Unknown { .. }
        ));
        assert_eq!(unread.value, 7, "nothing is written when it cannot be read");

        let mut refused = cell(7);
        refused.fail_write = true;
        assert!(matches!(
            put_back_if_still(&mut refused, &7, &1),
            PutBack::Failed { .. }
        ));

        // Another writer changes it after it was read as this program's: the write is bound
        // to the compare, so the other writer's value is kept and said.
        let mut raced = cell(7);
        raced.racer = Some(9);
        assert_eq!(
            put_back_if_still(&mut raced, &7, &1),
            PutBack::LeftChanged { now: 9 }
        );
        assert_eq!(
            raced.value, 9,
            "a change made after the read was overwritten"
        );
    }

    /// The function bodies of `file` whose signature line starts with `start`, up to the
    /// next item at the same indentation.
    fn body<'a>(file: &'a str, start: &str) -> &'a str {
        let code = file.split("#[cfg(test)]").next().unwrap_or(file);
        let at = code
            .find(start)
            .unwrap_or_else(|| panic!("no {start:?} in the code"));
        let indent = code[..at].rsplit('\n').next().unwrap_or("").len()
            + (start.len() - start.trim_start().len());
        let rest = &code[at..];
        let close = format!("\n{}}}", " ".repeat(indent));
        let end = rest.find(&close).map_or(rest.len(), |e| e + close.len());
        &rest[..end]
    }

    /// The guard: every restore in the program writes only through `put_back_if_still`. A
    /// restore function that writes its place directly (a registry value set or deleted, a
    /// key removed, a volume locked, a file renamed back) turns this red.
    #[test]
    fn every_restore_writes_only_through_compare_and_swap() {
        let setup = include_str!("tools/crash_dumps/setup.rs");
        let hold = include_str!("tools/crash_dumps/hold.rs");
        let places = include_str!("tools/crash_dumps/places.rs");
        let bitlocker = include_str!("recovery/bitlocker.rs");
        let update = include_str!("update.rs");
        let restores = [
            ("setup.rs put_back", body(setup, "pub(crate) fn put_back<")),
            ("hold.rs settle", body(hold, "fn settle<")),
            (
                "places.rs restore_value",
                body(places, "pub(super) fn restore_value<"),
            ),
            (
                "places.rs remove_key",
                body(places, "pub(super) fn remove_key<"),
            ),
            (
                "bitlocker.rs Relock::relock",
                body(bitlocker, "    pub fn relock("),
            ),
            (
                "bitlocker.rs Relock::drop",
                body(bitlocker, "impl Drop for Relock"),
            ),
            ("update.rs install", body(update, "pub fn install(")),
        ];
        let direct = [
            ".write_value(",
            ".delete_value(",
            ".delete_empty_key(",
            " lock(&",
            "(lock(&",
            "lock_volume(",
            "fs::rename(&old",
        ];
        for (name, code) in restores {
            for call in direct {
                assert!(!code.contains(call), "{name} writes directly: {call}");
            }
        }
        for (name, code) in [
            (
                "places.rs restore_value",
                body(places, "pub(super) fn restore_value<"),
            ),
            (
                "places.rs remove_key",
                body(places, "pub(super) fn remove_key<"),
            ),
            (
                "bitlocker.rs Relock::relock",
                body(bitlocker, "    pub fn relock("),
            ),
            ("update.rs install", body(update, "pub fn install(")),
        ] {
            assert!(
                code.contains("put_back_if_still("),
                "{name} restores blindly"
            );
        }
        for (name, code) in [
            ("setup.rs put_back", body(setup, "pub(crate) fn put_back<")),
            ("hold.rs settle", body(hold, "fn settle<")),
        ] {
            assert!(
                code.contains("restore_value(") && code.contains("remove_key("),
                "{name} restores outside the compare-and-swap"
            );
        }
        // The places write only through the machine's swaps, never a write of their own.
        let code = places.split("#[cfg(test)]").next().unwrap_or(places);
        for call in [".write_value(", ".delete_value(", ".delete_empty_key("] {
            assert!(
                !code.contains(call),
                "places.rs writes {call} outside a swap"
            );
        }
    }

    /// The guard (cause F): every place compares and writes as one operation, or says why
    /// Windows offers none in a `Residual:` comment. The registry swaps are transactions that
    /// compare the committed value only once the key is held and commit after; the folder
    /// and the moved-aside program are checked and acted on through one handle.
    #[test]
    fn every_place_compares_and_writes_as_one_operation() {
        let files = [
            ("places.rs", include_str!("tools/crash_dumps/places.rs")),
            ("bitlocker.rs", include_str!("recovery/bitlocker.rs")),
            ("update.rs", include_str!("update.rs")),
        ];
        let mut places = 0;
        for (name, file) in files {
            let code = file.split("#[cfg(test)]").next().unwrap_or(file);
            for (at, _) in code
                .match_indices("restore::Place for ")
                .chain(code.match_indices("\nimpl<M: Machine> Place for "))
            {
                places += 1;
                let block = &code[at..];
                let block = &block[..block.find("\n}\n").unwrap()];
                let swap = &block[block
                    .find("fn swap(")
                    .unwrap_or_else(|| panic!("{name}: a place with no swap"))..];
                let doc = &block[..block.find("fn swap(").unwrap()];
                let doc = &doc[doc.rfind("\n    fn ").map_or(0, |e| e + 1)..];
                let one_step = [
                    "swap_value(",
                    "remove_key_if(",
                    "remove_folder_if(",
                    "lock_if)(",
                ]
                .iter()
                .any(|op| swap.contains(op))
                    || (swap.contains("identity_of(&file)")
                        && swap.contains("rename_open_file(&file"));
                assert!(one_step, "{name}: a place whose swap is not one operation");
                if swap.contains("lock_if)(") {
                    assert!(doc.contains("Residual:"), "{name}: a residual not said");
                }
            }
        }
        assert_eq!(places, 5, "a place this guard does not see");
        let windows = include_str!("tools/crash_dumps/windows.rs");
        let windows = windows.split("#[cfg(test)]").next().unwrap_or(windows);
        let swap = &windows[windows.find("fn swap_value_once(").unwrap()..];
        let swap = &swap[..swap.find("\n    }\n").unwrap()];
        let held = swap.find("RegSetValueExW(").unwrap();
        let compared = swap.find("if now != *expect").unwrap();
        let committed = swap.find("transaction.commit()").unwrap();
        assert!(swap.contains("Transaction::begin()") && swap.contains("RegCreateKeyTransactedW("));
        assert!(
            held < compared && compared < committed,
            "the value is compared before the key is held"
        );
        let remove = &windows[windows.find("fn remove_key_between(").unwrap()..];
        let remove = &remove[..remove.find("\n    }\n").unwrap()];
        assert!(
            remove.find("RegDeleteKeyTransactedW(").unwrap()
                < remove.find("let now = self.key_stamp(").unwrap()
        );
        let folder = &windows[windows.find("fn remove_folder_if(").unwrap()..];
        let folder = &folder[..folder.find("\n    }\n").unwrap()];
        assert!(
            folder.find("file_id(handle.as_raw_handle()").unwrap()
                < folder.find("SetFileInformationByHandle(").unwrap()
        );
        for (name, file, residual) in [
            (
                "read_limit.rs",
                include_str!("recovery/read_limit.rs"),
                "fn put_back_on(",
            ),
            (
                "handles.rs",
                include_str!("handles.rs"),
                "let step = online_step(",
            ),
            (
                "bitlocker.rs",
                include_str!("recovery/bitlocker.rs"),
                "fn lock_if_still(",
            ),
        ] {
            let at = file.find(residual).unwrap();
            let before = &file[at.saturating_sub(900)..at];
            assert!(
                before.contains("Residual:"),
                "{name}: the residual is not said"
            );
        }
    }

    /// The guard (recovery rule: unknown is never fine): on the paths that change something
    /// or report it, in crash dumps, BitLocker, key lookup and the update, a failure is
    /// refused or said, never dropped. Each pattern below is one that dropped a failure.
    #[test]
    fn failures_on_change_and_report_paths_are_said_or_refused() {
        let code = |file: &'static str| file.split("#[cfg(test)]").next().unwrap_or(file);
        let files = [
            ("crash_dumps.rs", code(include_str!("tools/crash_dumps.rs"))),
            ("setup.rs", code(include_str!("tools/crash_dumps/setup.rs"))),
            ("hold.rs", code(include_str!("tools/crash_dumps/hold.rs"))),
            (
                "readiness.rs",
                code(include_str!("tools/crash_dumps/readiness.rs")),
            ),
            (
                "windows.rs",
                code(include_str!("tools/crash_dumps/windows.rs")),
            ),
            ("bitlocker.rs", code(include_str!("recovery/bitlocker.rs"))),
            ("keylookup.rs", code(include_str!("recovery/keylookup.rs"))),
            (
                "webview2.rs",
                code(include_str!("recovery/keylookup/webview2.rs")),
            ),
            (
                "keylookup_view.rs",
                code(include_str!("gui/keylookup_view.rs")),
            ),
            ("update.rs", code(include_str!("update.rs"))),
        ];
        let banned = [
            "if let Ok(lines) = windows::exclusive(",
            "let _ = machine::Machine::record_changes(",
            "let _ = unsafe { CreateMutexW(",
            "\"LockStatus\") == Some(1)",
            "map(|s| s.locked).unwrap_or(true)",
            "let _ = lock_volume(",
            ".is_ok() && is_bitlocker(",
            "process_start(me).unwrap_or(0)",
            ".key_exists(Hive::LocalMachine, key).unwrap_or(false)",
            "if spawned.is_ok()",
            "entries.flatten()",
            ".ok().flatten().unwrap_or(0)",
            "as_strings().unwrap_or_default()",
            "link_on_path(r.m, &path).ok()",
            "navigation.cancel();",
            "let _ = std::fs::rename(&old",
        ];
        for (name, text) in files {
            for pattern in banned {
                assert!(!text.contains(pattern), "{name}: {pattern}");
            }
        }
        // Every refusal sent to the browser is checked for whether it took.
        let webview = files[7].1;
        for line in webview.lines().filter(|l| l.contains(".put_bool(")) {
            assert!(
                line.contains(">= 0") || line.contains("< 0"),
                "a refusal not checked: {line}"
            );
        }
    }
}
