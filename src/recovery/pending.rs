//! The journal of changes not yet put back. Every change job (`timed::owned`) and every
//! holder of a change undone later (an image's footer, a volume this program unlocked, a
//! drive's read limit, a disk taken offline) is entered in
//! `%ProgramData%\DiagnosticTool\recovery-pending.json` with this process's id and start
//! time when it starts, and removed when it and its undo have ended. A recovery process
//! that ends before then, because Windows had not answered by the end of the time each job
//! stated, or because it was killed, leaves its entries; the next recovery window settles
//! them as it starts (`settle_left`): it changes only what it can prove is still exactly
//! what the ended run wrote (this tool's own footer, byte for byte; the drive's own read
//! limit while the identified drive holds that run's), says everything else (a copy left
//! behind with its path and size, a volume left unlocked, a disk left offline), and enters
//! each outcome in the session's change record and on screen. The journal is kept only by a recovery window (`Journal::use_file`); in
//! any other process it is in memory, as nothing outlives the process to settle.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use serde::{Deserialize, Serialize};

use super::bitlocker::VolumeIdentity;

/// Where the journal is kept.
pub const PENDING_FILE: &str = r"%ProgramData%\DiagnosticTool\recovery-pending.json";
const VERSION: u32 = 1;
/// More entries than this is not a file this program wrote.
const MAX_ENTRIES: usize = 512;
/// The change record's heading for what a start settled.
pub const SETTLED: &str = "What an earlier recovery window left when it ended";

/// What the next start does for a change not yet put back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pending {
    /// Nothing it can put back by itself: it says what was under way.
    Said,
    /// This tool's footer on an image, `len` its own length: taken off if it is still there.
    Footer { image: PathBuf, len: u64 },
    /// A repair's copy whose making had not ended: removed if it is there.
    Copy { at: PathBuf },
    /// A volume this program unlocked: locked again if it is still that volume, unlocked.
    Relock {
        device_id: String,
        identity: VolumeIdentity,
    },
    /// A drive's read limit this run set: its own value put back while it holds one of ours.
    ReadLimit {
        number: u32,
        model: String,
        serial: String,
        size: u64,
        original: u16,
        ours: Vec<u16>,
    },
    /// A disk this program took offline: said, by the number it had then and the model and
    /// serial number journalled with it.
    Offline {
        number: u32,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        serial: Option<String>,
    },
}

/// One change not yet put back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The process that made it: id and start time.
    pub pid: u32,
    pub started: u64,
    pub id: u64,
    pub what: String,
    pub pending: Pending,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Book {
    version: u32,
    entries: Vec<Entry>,
}

/// The journal: in memory until `use_file`.
pub struct Journal {
    file: Mutex<Option<PathBuf>>,
    next: AtomicU64,
    /// A write that failed is said once in the change record.
    said: Mutex<bool>,
}

/// The process's journal.
pub static JOURNAL: Journal = Journal::new();

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

/// This process's id and start time, read once.
fn me() -> Option<(u32, u64)> {
    static ME: OnceLock<Option<(u32, u64)>> = OnceLock::new();
    *ME.get_or_init(|| crate::tools::crash_dumps::process_identity().ok())
}

impl Journal {
    pub const fn new() -> Self {
        Self {
            file: Mutex::new(None),
            next: AtomicU64::new(1),
            said: Mutex::new(false),
        }
    }

    /// Keeps the journal in `path` from here on.
    pub fn use_file(&self, path: PathBuf) {
        *self.file.lock().unwrap_or_else(PoisonError::into_inner) = Some(path);
    }

    /// The journal's default place, expanded.
    pub fn default_file() -> Option<PathBuf> {
        let data = std::env::var_os("ProgramData")?;
        Some(PathBuf::from(data).join(r"DiagnosticTool\recovery-pending.json"))
    }

    /// Runs `change` on the journal's entries under the journal's lock, and saves them.
    fn change(&self, change: impl FnOnce(&mut Vec<Entry>)) -> Result<(), String> {
        let file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(path) = file.as_ref() else {
            return Ok(());
        };
        let _across = Across::take()?;
        let mut book = read(path)?;
        change(&mut book.entries);
        write(path, &book)
    }

    fn said(&self, why: String) {
        let mut said = self.said.lock().unwrap_or_else(PoisonError::into_inner);
        if !*said {
            *said = true;
            crate::handles::record_unseen(
                "Recovery journal",
                &format!("The journal of changes not yet put back could not be kept ({why}); a change this window leaves when it ends is not put back by the next start."),
            );
        }
    }

    /// Enters a change; its id.
    pub fn add(&self, what: &str, pending: Pending) -> Option<u64> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let Some((pid, started)) = me() else {
            self.said("this program's start time could not be read".into());
            return Some(id);
        };
        let entry = Entry {
            pid,
            started,
            id,
            what: what.to_string(),
            pending,
        };
        if let Err(why) = self.change(|entries| {
            if entries.len() < MAX_ENTRIES {
                entries.push(entry);
            }
        }) {
            self.said(why);
        }
        Some(id)
    }

    /// What the next start settles for entry `id`, changed.
    pub fn replace(&self, id: u64, what: &str, pending: Pending) {
        let Some((pid, started)) = me() else {
            return;
        };
        if let Err(why) = self.change(|entries| {
            for e in entries.iter_mut() {
                if (e.pid, e.started, e.id) == (pid, started, id) {
                    e.what = what.to_string();
                    e.pending = pending.clone();
                }
            }
        }) {
            self.said(why);
        }
    }

    /// The change has been put back.
    pub fn remove(&self, id: u64) {
        let Some((pid, started)) = me() else {
            return;
        };
        if let Err(why) = self.change(|entries| {
            entries.retain(|e| (e.pid, e.started, e.id) != (pid, started, id));
        }) {
            self.said(why);
        }
    }

    /// Settles every entry of a process no longer `running`: `settle` puts it back and says
    /// how, and whether the entry stays for another try. The texts, for the change record.
    pub fn settle_left(
        &self,
        running: impl Fn(u32, u64) -> bool,
        mut settle: impl FnMut(&Entry) -> (String, bool),
    ) -> Result<Vec<String>, String> {
        let left: Vec<Entry> = {
            let file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(path) = file.as_ref() else {
                return Ok(Vec::new());
            };
            let _across = Across::take()?;
            read(path)?
                .entries
                .into_iter()
                .filter(|e| !running(e.pid, e.started))
                .collect()
        };
        let mut texts = Vec::new();
        let mut settled = Vec::new();
        for entry in &left {
            let (text, keep) = settle(entry);
            texts.push(text);
            if !keep {
                settled.push((entry.pid, entry.started, entry.id));
            }
        }
        self.change(|entries| entries.retain(|e| !settled.contains(&(e.pid, e.started, e.id))))?;
        Ok(texts)
    }
}

fn read(path: &Path) -> Result<Book, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Book {
                version: VERSION,
                entries: Vec::new(),
            })
        }
        Err(e) => return Err(format!("{} could not be read ({e})", path.display())),
    };
    let book: Book = serde_json::from_str(&text).map_err(|e| {
        format!(
            "{} is not a journal this program wrote ({e})",
            path.display()
        )
    })?;
    if book.version != VERSION || book.entries.len() > MAX_ENTRIES {
        return Err(format!(
            "{} is not a journal this version reads",
            path.display()
        ));
    }
    Ok(book)
}

fn write(path: &Path, book: &Book) -> Result<(), String> {
    use std::io::Write;
    let fail = |e: std::io::Error| format!("{} could not be written ({e})", path.display());
    if book.entries.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(fail(e)),
            _ => Ok(()),
        };
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    let text = serde_json::to_string_pretty(&Book {
        version: VERSION,
        entries: book.entries.clone(),
    })
    .map_err(|e| e.to_string())?;
    let scratch = path.with_extension("json.new");
    let mut file = std::fs::File::create(&scratch).map_err(fail)?;
    file.write_all(text.as_bytes()).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    drop(file);
    std::fs::rename(&scratch, path).map_err(fail)
}

/// The machine-wide lock on the journal file, so two recovery windows never write it at
/// the same moment. Waits up to 20 seconds for another.
struct Across(windows_sys::Win32::Foundation::HANDLE);

impl Across {
    fn take() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
        let name: Vec<u16> = "Global\\DiagnosticTool-RecoveryPending"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `name` is NUL-terminated; the handle is closed on drop.
        let lock = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if lock.is_null() {
            return Err(format!(
                "its lock could not be made ({})",
                std::io::Error::last_os_error()
            ));
        }
        let held = Self(lock);
        // SAFETY: `lock` is a mutex handle.
        match unsafe { WaitForSingleObject(lock, 20_000) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(held),
            _ => Err("another recovery window held its lock for 20 s".into()),
        }
    }
}

impl Drop for Across {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        // SAFETY: held by this thread since `take`.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

/// Settles one entry, as the next start does; what it did or found, and whether the entry
/// stays for another try. It changes only what it can prove is still exactly what the
/// ended run wrote: this tool's own footer on an image, byte for byte on one handle
/// (`vdisk::settle_footer`), and a drive's read limit on the drive of that model and serial
/// number while it holds that run's value (`read_limit::settle`). Everything else (a copy
/// left behind, a volume left unlocked, a disk left offline, a job not seen to end) is said
/// and never acted on, since nothing proves it is still the run's.
pub fn settle(entry: &Entry) -> (String, bool) {
    let what = &entry.what;
    // The journal says what the ended run had started and not seen end; whether it ended
    // after all (and only the journal's update was lost) is not known, so nothing here is
    // said as the state now unless it was read now.
    match &entry.pending {
        Pending::Said => (
            format!("An earlier recovery window's journal says it was {what} and did not see that end; whether it finished is not known."),
            false,
        ),
        Pending::Footer { image, len } => match super::vdisk::settle_footer(image, *len) {
            Ok(text) => (text, false),
            Err(text) => (text, true),
        },
        Pending::Copy { at } => (copy_text(at, std::fs::metadata(at)), false),
        Pending::Relock { device_id, .. } => (
            format!("An earlier recovery window's journal says it unlocked BitLocker volume {device_id} and did not see it locked again; its state now was not read. Unlock a BitLocker drive shows whether it is unlocked."),
            false,
        ),
        Pending::ReadLimit {
            number,
            model,
            serial,
            size,
            original,
            ours,
        } => (
            super::read_limit::settle(
                *number,
                super::SourceId {
                    model: model.clone(),
                    serial: serial.clone(),
                    size: *size,
                    // The put back is bound to the drive Windows reports, on the bus it was set on.
                    drive: None,
                    sector: None,
                    scope: None,
                    disk_size: None,
                },
                *original,
                ours.clone(),
            ),
            false,
        ),
        Pending::Offline {
            number,
            model,
            serial,
        } => (
            format!(
                "An earlier recovery window's journal says it took the disk that was Disk {number} then{} offline and did not see it brought online again. Disk numbers change, so which disk that is now, and whether it is still offline, were not read; Disk Management shows each disk's model, serial number and state.",
                drive_named(model.as_deref(), serial.as_deref())
            ),
            false,
        ),
    }
}

/// " (model X, serial number Y)", from what was journalled.
fn drive_named(model: Option<&str>, serial: Option<&str>) -> String {
    match (model, serial) {
        (Some(m), Some(s)) => format!(" ({m}, serial number {s})"),
        (Some(m), None) => format!(" ({m})"),
        (None, Some(s)) => format!(" (serial number {s})"),
        (None, None) => String::new(),
    }
}

/// What a start says of a repair's copy whose making an ended run did not see end, from
/// reading the place now: a file there with its size, none there, or that it could not be
/// read and why. Never acted on.
fn copy_text(at: &Path, read: std::io::Result<std::fs::Metadata>) -> String {
    let start = "An earlier recovery window's journal says it was making a repair's copy and did not see that end";
    match read {
        Ok(m) => format!(
            "{start}; a file is at {} now ({} bytes). Delete it if it is not a copy you kept.",
            at.display(),
            m.len()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("{start}; there is no file at {} now.", at.display())
        }
        Err(e) => format!(
            "{start}; whether a file is at {} now could not be read ({e}).",
            at.display()
        ),
    }
}

/// Settles what earlier recovery windows left, as a recovery window starts, enters it in
/// the session's change record, and returns it for the window to show.
pub fn settle_at_start() -> Vec<String> {
    let Some(path) = Journal::default_file() else {
        return Vec::new();
    };
    JOURNAL.use_file(path);
    let texts = JOURNAL.settle_left(crate::tools::crash_dumps::process_running, settle);
    let lines = match texts {
        Ok(texts) if texts.is_empty() => return Vec::new(),
        Ok(texts) => texts,
        Err(why) => vec![format!(
            "The journal of changes an earlier window left could not be read ({why}), so nothing was put back from it."
        )],
    };
    if crate::change_record::append(SETTLED, &lines).is_err() {
        for line in &lines {
            crate::handles::record_unseen("Recovery journal", line);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pending: Pending) -> Entry {
        Entry {
            pid: 1,
            started: 1,
            id: 1,
            what: "bringing disk 3 online".into(),
            pending,
        }
    }

    /// The guard (cause F): what the start says is only what it read now. A journalled
    /// disk number is the number the disk had then, with its model and serial, never the
    /// disk now, and nothing is asked of a disk by number; a copy's place that could not be
    /// read is said as unread, never as empty; a job not seen to end is not said to have
    /// failed.
    #[test]
    fn the_start_says_only_what_it_read() {
        let (offline, keep) = settle(&entry(Pending::Offline {
            number: 3,
            model: Some("Samsung SSD 870".into()),
            serial: Some("S6PNNX0T".into()),
        }));
        assert!(!keep);
        assert!(
            offline.contains(
                "the disk that was Disk 3 then (Samsung SSD 870, serial number S6PNNX0T)"
            ),
            "{offline}"
        );
        assert!(offline.contains("Disk numbers change"), "{offline}");
        for claim in ["bring it online", "Disk 3 is", "Disk 3 was taken"] {
            assert!(!offline.contains(claim), "{offline}");
        }
        let old = settle(&entry(Pending::Offline {
            number: 3,
            model: None,
            serial: None,
        }))
        .0;
        assert!(
            old.contains("the disk that was Disk 3 then offline"),
            "{old}"
        );
        // A place that cannot be read (a name Windows refuses) is not a place with no file.
        let unread = settle(&entry(Pending::Copy {
            at: PathBuf::from("D:\\out\\a\0b.vhd"),
        }))
        .0;
        assert!(unread.contains("could not be read"), "{unread}");
        assert!(!unread.contains("no file"), "{unread}");
        let missing = copy_text(
            Path::new(r"D:\out\gone.vhd"),
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        );
        assert!(missing.contains("there is no file at"), "{missing}");
        let denied = copy_text(
            Path::new(r"D:\out\kept.vhd"),
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        );
        assert!(
            !denied.contains("no file") && denied.contains("could not be read"),
            "{denied}"
        );
        let said = settle(&entry(Pending::Said)).0;
        assert!(said.contains("whether it finished is not known"), "{said}");
        assert!(!said.contains("before Windows answered"), "{said}");
        let relock = settle(&entry(Pending::Relock {
            device_id: r"\\?\Volume{1}\".into(),
            identity: crate::recovery::bitlocker::VolumeIdentity {
                device_id: r"\\?\VOLUME{1}".into(),
                extents: vec![(3, 0, 1)],
                key_ids: Vec::new(),
            },
        }))
        .0;
        assert!(relock.contains("its state now was not read"), "{relock}");
        assert!(!relock.contains("restart locks"), "{relock}");
    }

    /// The guard (cause F): the next start changes only what it proves is still the ended
    /// run's: this tool's footer by compare-and-swap on one handle, and the read limit on the
    /// identified drive while it holds the run's value. It removes, relocks or brings
    /// online nothing.
    #[test]
    fn settling_changes_only_what_it_proves() {
        let code = include_str!("pending.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let body = &code[code.find("pub fn settle(entry: &Entry)").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let calls: Vec<&str> = body
            .match_indices("super::")
            .map(|(at, _)| {
                let rest = &body[at..];
                &rest[..rest.find(['(', ' ', '{']).unwrap()]
            })
            .filter(|call| *call != "super::SourceId")
            .collect();
        assert_eq!(
            calls,
            ["super::vdisk::settle_footer", "super::read_limit::settle"],
            "settling makes another change"
        );
        for change in [
            "Relock::",
            ".relock(",
            "remove_file",
            "remove_after_detach",
            "set_offline",
            "fs::write",
            "set_len",
        ] {
            assert!(!body.contains(change), "settling does {change}");
        }
        let vdisk = include_str!("vdisk.rs");
        let footer = &vdisk[vdisk.find("pub(crate) fn settle_footer(").unwrap()..];
        let footer = &footer[..footer.find("\n}\n").unwrap()];
        let opened = footer.find("open_for_footer(image)").unwrap();
        let compared = footer.find("if own_footer(&file) != Some(len) {").unwrap();
        let cut = footer.find("file.set_len(len)").unwrap();
        assert!(
            opened < compared && compared < cut,
            "the footer is cut without its compare"
        );
        assert_eq!(footer.matches("set_len(").count(), 1);
        assert!(
            !footer.contains("remove_footer"),
            "a second open between compare and cut"
        );
        let repair = include_str!("repair.rs");
        let bitlocker = include_str!("bitlocker.rs");
        assert!(!repair.contains("fn settle_copy("));
        assert!(!bitlocker.contains("fn settle_relock("));
    }

    fn temp(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "diagtool-pending-{name}-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// The guard: an entry stays in the file from its start until it is removed; the next
    /// start settles only a process that is gone, and keeps what asks to be tried again.
    #[test]
    fn a_left_change_is_settled_by_the_next_start() {
        let path = temp("settle");
        let journal = Journal::new();
        journal.use_file(path.clone());
        let footer = Pending::Footer {
            image: PathBuf::from(r"C:\nowhere\a.img"),
            len: 4096,
        };
        let a = journal.add("detaching a.img", Pending::Said).unwrap();
        let b = journal
            .add("holding a.img's footer", footer.clone())
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("detaching a.img") && text.contains("a.img's footer"));
        journal.remove(a);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("detaching a.img"), "a removed entry stayed");
        // This process is still running: nothing of it is settled.
        let none = journal
            .settle_left(|_, _| true, |_| unreachable!())
            .unwrap();
        assert!(none.is_empty());
        // Gone: settled, and kept when the settle asks to try again.
        let mut seen = Vec::new();
        let texts = journal
            .settle_left(
                |_, _| false,
                |e| {
                    seen.push(e.pending.clone());
                    ("tried".into(), true)
                },
            )
            .unwrap();
        assert_eq!((texts, seen), (vec!["tried".to_string()], vec![footer]));
        let texts = journal
            .settle_left(|_, _| false, |_| ("done".into(), false))
            .unwrap();
        assert_eq!(texts, vec!["done".to_string()]);
        assert!(!path.exists(), "an empty journal is removed");
        let _ = b;
        // A file this program did not write is refused, not settled.
        std::fs::write(&path, "{\"version\":9,\"entries\":[]}").unwrap();
        assert!(journal
            .settle_left(|_, _| false, |_| unreachable!())
            .is_err());
        std::fs::remove_file(&path).unwrap();
    }

    /// Needs administrator rights and DIAGTOOL_PENDING_FILE, the journal a live repair run
    /// that was killed part way left: settles it as the next recovery window does, and
    /// prints what it did. Every entry is settled; none is a running process's.
    #[test]
    #[ignore]
    fn live_settle_what_a_killed_run_left() {
        let path = PathBuf::from(std::env::var("DIAGTOOL_PENDING_FILE").unwrap());
        println!("journal: {}", std::fs::read_to_string(&path).unwrap());
        let journal = Journal::new();
        journal.use_file(path.clone());
        let texts = journal
            .settle_left(crate::tools::crash_dumps::process_running, settle)
            .unwrap();
        for text in &texts {
            println!("settled: {text}");
        }
        assert!(!texts.is_empty(), "the killed run left nothing");
        assert!(
            !path.exists(),
            "an entry was kept: {:?}",
            std::fs::read_to_string(&path)
        );
    }
}
