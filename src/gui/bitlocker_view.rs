//! The BitLocker window. It drives the engine in `recovery::bitlocker` (`scan`,
//! `unlock_held`, `Relock::relock`): it builds their options, shows their events and renders
//! their results. It shows each volume's recovery key ID as Windows' recovery screen does,
//! unlocks one with the 48-digit recovery key, and opens the recovery tools on the unlocked
//! volume. A volume this window unlocked from locked carries the engine's `Relock`; one that
//! was already unlocked carries none and is left unlocked. Lock, and closing the window,
//! lock through the `Relock`, which locks only while the volume is still unlocked and still
//! the same volume, and every outcome other than locked is shown; a forced dismount is asked
//! for first. The key goes from the edit control straight into the engine's zeroing type
//! (recovery rule 7).
//!
//! Find the key looks the key up instead of having it typed: first in saved key files on
//! this PC's drives (`keylookup::search_key_files`), then, if none is found, in the
//! customer's Microsoft account through the sign-in window (`keylookup_view`). A key found
//! goes from the lookup's zeroing type into the unlock's and is dropped; it is never shown,
//! logged, or put in an event or result.
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;

use diagnostics::recovery::bitlocker::{
    self, Found, KeyText, Relock, RelockOutcome, ScanOptions, ScanResult, UnlockOptions,
    UnlockResult, WideSecret,
};
use diagnostics::recovery::keylookup::{
    self, KeyFileSearchOptions, KeyFileSearchResult, SignInOptions, SignInOutcome,
};
use diagnostics::recovery::vdisk::Event;
use diagnostics::recovery::SourceChoice;
use diagnostics::tools::crash_dumps::{self, DumpExclusion};
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{grid, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowTextLengthW, GetWindowTextW, PostMessageW, SendMessageW, SetWindowTextW, WM_CLOSE,
    WM_COMMAND,
};
/// The edit control's notification that its text changed.
const EN_CHANGE: u32 = 0x0300;
/// The edit control's message that empties its undo buffer, which can hold earlier text.
const EM_EMPTYUNDOBUFFER: u32 = 0x00CD;

use crate::dialog::{Dialog, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};
use crate::{keylookup_view, recover_files, vdisk_view};

/// The window's title, the same words as its button in the recovery window.
pub const TITLE: &str = "Unlock a BitLocker drive";

const VOLUMES: usize = 10;
const KEY: usize = 11;
const UNLOCK: usize = 12;
const EXPLORE: usize = 13;
const RECOVER: usize = 14;
const BY_TYPE: usize = 15;
const LOCK: usize = 16;
const CLOSE: usize = 17;
const FIND_KEY: usize = 18;
const DO_UNLOCK: usize = 30;
const DO_FIND_KEY: usize = 31;
/// Posted when no saved key file was found, to offer the sign-in window.
const OFFER_SIGN_IN: usize = 32;
const DO_SIGN_IN: usize = 33;
/// Accepted on closing: lock again, dismounting, the volumes that were in use.
const FORCE_LOCK: usize = 34;
/// Accepted on closing when nothing more can be done: the window closes.
const CLOSE_ANYWAY: usize = 35;

/// Opens the window for disk `disk`. `source_disk` is the drive being recovered, if any:
/// when `disk` is that drive, unlocking asks first and shows the advice to image it.
pub fn open(owner: HWND, disk: u32, source_disk: Option<u32>) {
    toolwin::open(owner, &format!("bitlocker:{disk}"), move || {
        Box::new(BitLockerView::new(disk, source_disk))
    });
}

/// The advice for a drive that may be failing, in plain words.
pub fn advice(is_source: bool) -> &'static str {
    if is_source {
        bitlocker::SOURCE_ADVICE
    } else {
        "This disk is an image attached read-only, so unlocking it writes nothing to the image or to the drive it came from."
    }
}

/// One BitLocker volume, as the scan found it.
#[derive(Clone)]
struct Row {
    found: Found,
    /// Unlocked by this window, so locked again when it closes.
    unlocked_here: bool,
    /// The source the engine gave when this window unlocked it.
    source: Option<SourceChoice>,
}

impl Row {
    fn text(&self) -> String {
        let f = &self.found;
        let place = match &f.letter {
            Some(letter) => format!("{letter}  ·  {}", bytes_text(f.len)),
            None => format!("No drive letter  ·  {}", bytes_text(f.len)),
        };
        if let Some(why) = &f.error {
            return format!("{place}  ·  {why}");
        }
        let state = match f.locked {
            Some(true) => "locked",
            Some(false) => "unlocked",
            None => "not known whether locked",
        };
        let ids = match f.key_ids_short.as_slice() {
            [] => "no recovery key".to_string(),
            [one] => format!("Recovery key ID: {one}"),
            many => format!("Recovery key IDs: {}", many.join(", ")),
        };
        format!("{place}  ·  {state}  ·  {ids}")
    }

    fn locked(&self) -> bool {
        self.found.locked == Some(true)
    }

    fn unlocked(&self) -> bool {
        self.found.locked == Some(false)
    }
}

enum Done {
    Scanned(Result<ScanResult, String>),
    /// The unlock's result with what locks the volume again when this unlock is what
    /// unlocked it: dropped unread (the window closed while the unlock ran), it locks the
    /// volume.
    Unlocked(Result<(UnlockResult, Option<Relock>), String>),
    /// What Lock again found and did, with the volume's `Relock` back while it is still
    /// unlocked.
    Locked(String, RelockOutcome, Relock),
    KeyFiles(Result<KeyFileSearchResult, String>),
}

/// The volume a key is being looked up for, kept while the lookup runs.
struct Lookup {
    device_id: String,
    key_ids: Vec<String>,
    /// The IDs as Windows' recovery screen shows them, for the window's text.
    shown: String,
    /// The answer to the dialog for the drive being recovered itself.
    confirmed: bool,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    strip: crate::condition_strip::Strip,
    advice: HWND,
    volumes: HWND,
    key_label: HWND,
    key: HWND,
    key_form: HWND,
    find_key: HWND,
    unlock: HWND,
    explore: HWND,
    recover: HWND,
    by_type: HWND,
    lock: HWND,
    notice: HWND,
    close: HWND,
}

pub struct BitLockerView {
    disk: u32,
    source_disk: Option<u32>,
    rows: Vec<Row>,
    job: Option<mpsc::Receiver<Done>>,
    notice: Option<(String, Tone)>,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
    /// True once a scan has finished.
    scanned: bool,
    lookup: Option<Lookup>,
    /// Where the key the running unlock uses came from, when it was looked up.
    key_from: Option<String>,
    /// What locks each volume this window unlocked again when the window closes. An
    /// unlock still running then locks its volume when its result finds no window.
    held: Vec<Relock>,
    /// This program kept out of crash dumps while the window is open, since a key can be
    /// typed into it at any time; Err says why it could not be. Declared last, so it is let
    /// go after the volumes are locked again.
    dumps: Result<DumpExclusion, String>,
}

impl Drop for BitLockerView {
    /// Volumes still held here (the window closed without `close_ask`) are locked again by
    /// their `Relock`'s drop, which enters any other outcome in the change record.
    fn drop(&mut self) {
        self.held.clear();
    }
}

/// The edit control's text, read straight into a zeroing buffer.
fn read_key_box(edit: HWND) -> WideSecret {
    // SAFETY: the edit is a window of this thread.
    let len = unsafe { GetWindowTextLengthW(edit) }.max(0) as usize;
    let mut buffer = WideSecret(vec![0u16; len + 1]);
    // SAFETY: the buffer holds len + 1 characters.
    let got = unsafe { GetWindowTextW(edit, buffer.0.as_mut_ptr(), buffer.0.len() as i32) };
    buffer.0.truncate(got.max(0) as usize);
    buffer
}

/// Empties the key box: its text is overwritten with spaces first, then emptied, and its
/// undo buffer, which can hold the text, is emptied too.
fn clear_key(edit: HWND) {
    // SAFETY: the edit is a window of this thread.
    let len = unsafe { GetWindowTextLengthW(edit) }.max(0) as usize;
    let blank: Vec<u16> = std::iter::repeat_n(u16::from(b' '), len)
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both strings are NUL-terminated; the message takes no pointers.
    unsafe {
        SetWindowTextW(edit, blank.as_ptr());
        SetWindowTextW(edit, [0u16].as_ptr());
        SendMessageW(edit, EM_EMPTYUNDOBUFFER, 0, 0);
    }
}

/// The key typed in the key box, decoded straight into the engine's zeroing `KeyText`, and
/// the box emptied: a typed key stays in the control no longer than it must.
fn take_key(edit: HWND) -> KeyText {
    let typed = read_key_box(edit);
    let key = KeyText::from_wide(&typed.0);
    drop(typed);
    clear_key(edit);
    key
}

/// What a key file search could not look in, as a sentence to add, or nothing.
fn not_searched_text(r: &KeyFileSearchResult) -> String {
    let mut text = String::new();
    if !r.roots_not_searched.is_empty() {
        let roots: Vec<PathBuf> = r
            .roots_not_searched
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        text.push_str(&format!(" {} could not be searched.", paths_text(&roots)));
    }
    if r.unreadable_count > 0 {
        text.push_str(&format!(
            " {} {} could not be read, so a key file there would not be found.",
            r.unreadable_count,
            if r.unreadable_count == 1 {
                "folder or file"
            } else {
                "folders or files"
            }
        ));
    }
    text
}

/// Paths for people: "C:\\ and D:\\".
fn paths_text(paths: &[PathBuf]) -> String {
    let names: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
    }
}

impl BitLockerView {
    fn new(disk: u32, source_disk: Option<u32>) -> Self {
        // From here a recovery key can be typed into this process.
        bitlocker::mark_key_held();
        let dumps = crash_dumps::keep_out_of_dumps();
        let mut view = Self {
            disk,
            source_disk,
            rows: Vec::new(),
            job: None,
            notice: None,
            controls: None,
            area: (0, 0, 96),
            natural: None,
            scanned: false,
            lookup: None,
            key_from: None,
            held: Vec::new(),
            dumps,
        };
        view.rescan();
        view
    }

    fn is_source(&self) -> bool {
        self.source_disk == Some(self.disk)
    }

    fn start_job(&mut self, busy: &str, work: impl FnOnce() -> Done + Send + 'static) {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(work());
        });
        self.job = Some(receiver);
        self.notice = Some((busy.to_string(), Tone::Neutral));
    }

    fn rescan(&mut self) {
        let options = ScanOptions { disk: self.disk };
        self.start_job("Looking for BitLocker volumes…", move || {
            Done::Scanned(bitlocker::scan(&options, &|_| {}, &AtomicBool::new(false)))
        });
    }

    /// Whether this program is kept out of crash dumps, trying again when it was not; the
    /// notice says why not.
    fn kept_out(&mut self) -> bool {
        if self.dumps.is_err() {
            self.dumps = crash_dumps::keep_out_of_dumps();
        }
        match &self.dumps {
            Ok(_) => true,
            Err(why) => {
                self.notice = Some((why.clone(), Tone::Flag));
                false
            }
        }
    }

    fn selected(&self) -> Option<&Row> {
        let c = self.controls.as_ref()?;
        self.rows.get(toolwin::selected(c.volumes)?)
    }

    /// The source the recovery tools read for the selected, unlocked volume.
    fn volume_source(&self) -> Option<SourceChoice> {
        let row = self.selected().filter(|r| r.unlocked())?;
        if let Some(source) = &row.source {
            return Some(source.clone());
        }
        let place = row
            .found
            .letter
            .clone()
            .unwrap_or_else(|| "with no drive letter".into());
        Some(SourceChoice::Volume {
            path: row.found.device_id.trim_end_matches('\\').to_string(),
            disk: self.disk,
            name: format!("BitLocker volume {place} on Disk {}", self.disk),
        })
    }

    fn render(&mut self) {
        let rows: Vec<String> = self.rows.iter().map(Row::text).collect();
        let busy = self.job.is_some();
        let selected = self.selected().cloned();
        let Some(c) = &self.controls else {
            return;
        };
        toolwin::set_items(c.volumes, &rows, true);
        toolwin::set_empty(
            c.volumes,
            &if self.scanned {
                format!("No BitLocker volume was found on Disk {}.", self.disk)
            } else {
                format!(
                    "BitLocker volumes on Disk {} appear here, each with the ID of the recovery key that unlocks it.",
                    self.disk
                )
            },
        );
        let locked = selected.as_ref().is_some_and(Row::locked);
        let unlocked = selected.as_ref().is_some_and(Row::unlocked);
        // No key comes in, typed, pasted or looked up, until this program is kept out of
        // crash dumps; a key already in the box is cleared if it is not.
        let protected = self.dumps.is_ok();
        // SAFETY: the edit is a window of this thread.
        if !protected && unsafe { GetWindowTextLengthW(c.key) } > 0 {
            clear_key(c.key);
        }
        ui::enable(c.key, protected && !busy && locked);
        ui::enable(c.unlock, protected && !busy && locked);
        ui::enable(
            c.find_key,
            protected
                && !busy
                && locked
                && selected
                    .as_ref()
                    .is_some_and(|r| !r.found.key_ids.is_empty()),
        );
        ui::enable(
            c.explore,
            unlocked && selected.as_ref().is_some_and(|r| r.found.letter.is_some()),
        );
        ui::enable(c.recover, unlocked);
        ui::enable(c.by_type, unlocked);
        ui::enable(
            c.lock,
            !busy && unlocked && selected.as_ref().is_some_and(|r| r.unlocked_here),
        );
        let (notice, tone) = match &self.dumps {
            Err(why) => (
                format!("{why} Until then the recovery key box and Find the key stay off."),
                Tone::Flag,
            ),
            Ok(_) => self
                .notice
                .clone()
                .unwrap_or((String::new(), Tone::Neutral)),
        };
        ui::set_text(c.notice, &notice);
        ui::set_tone(c.notice, tone);
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    /// A key pasted into the key box leaves the clipboard empty once the box holds it, when
    /// the clipboard still holds that same text.
    fn key_changed(&self, hwnd: HWND) {
        let Some(c) = &self.controls else {
            return;
        };
        let field = read_key_box(c.key);
        bitlocker::clear_clipboard_if_holding(hwnd as isize, &field.0);
    }

    /// The one place a typed key goes: from the control into the engine's zeroing type.
    /// `confirmed` is the answer to the dialog for the drive being recovered itself; the
    /// engine refuses that drive without it.
    fn unlock(&mut self, confirmed: bool) {
        let Some(row) = self.selected().cloned() else {
            return;
        };
        let Some(c) = &self.controls else {
            return;
        };
        self.key_from = None;
        let key = take_key(c.key);
        if !self.kept_out() {
            return;
        }
        self.unlock_with(row.found.device_id.clone(), key, confirmed);
    }

    /// Starts the engine's unlock of `device_id` with `key`, typed or looked up.
    fn unlock_with(&mut self, device_id: String, key: KeyText, confirmed: bool) {
        let options = UnlockOptions {
            device_id,
            recovery_key: key,
            source_disk: self.source_disk,
            unlock_source_drive: confirmed,
        };
        self.start_job("Unlocking…", move || {
            Done::Unlocked(bitlocker::unlock_held(
                options,
                &|_: Event| {},
                &AtomicBool::new(false),
            ))
        });
    }

    /// The dialog for unlocking a volume on the drive being recovered itself.
    fn confirm_source(then: usize) -> Ask {
        Ask {
            dialog: Dialog {
                window_title: TITLE.into(),
                heading: "Unlock the drive itself?".into(),
                intro: advice(true).into(),
                sections: Vec::<Section>::new(),
                accept: "Unlock the drive".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then,
        }
    }

    /// Find the key, step one: saved key files for the selected volume's key IDs.
    fn find_key(&mut self, confirmed: bool) {
        let Some(row) = self.selected().cloned() else {
            return;
        };
        // A key file read, or a key read from the account page, lands in this process.
        if !self.kept_out() {
            return;
        }
        let lookup = Lookup {
            device_id: row.found.device_id.clone(),
            key_ids: row.found.key_ids.clone(),
            shown: row.found.key_ids_short.join(", "),
            confirmed,
        };
        let options = KeyFileSearchOptions {
            key_ids: lookup.key_ids.clone(),
            ..Default::default()
        };
        self.lookup = Some(lookup);
        self.start_job(
            "Looking for a saved recovery key file on this PC's drives…",
            move || {
                Done::KeyFiles(keylookup::search_key_files(
                    &options,
                    &mut |_| {},
                    &AtomicBool::new(false),
                ))
            },
        );
    }

    /// The key file search ended: unlock with a key it found, or offer the sign-in.
    fn key_files_searched(&mut self, hwnd: HWND, result: Result<KeyFileSearchResult, String>) {
        let Some(lookup) = self.lookup.as_ref() else {
            return;
        };
        let found = result.as_ref().ok().and_then(|r| {
            r.keys
                .iter()
                .find(|saved| r.found.iter().any(|f| f.path == saved.path))
        });
        if let Some(saved) = found {
            let key = KeyText::copy_of(saved.key.as_str());
            self.key_from = Some(format!("the key saved in {}", saved.path.display()));
            let (device_id, confirmed) = (lookup.device_id.clone(), lookup.confirmed);
            self.lookup = None;
            self.unlock_with(device_id, key, confirmed);
            return;
        }
        let why = match &result {
            Ok(r) if !r.roots_given_up.is_empty() => format!(
                "No saved key file for key ID {} was found; {} did not answer in time.{}",
                lookup.shown,
                paths_text(&r.roots_given_up),
                not_searched_text(r)
            ),
            Ok(r) => format!(
                "No saved key file for key ID {} was found on this PC's drives.{}",
                lookup.shown,
                not_searched_text(r)
            ),
            Err(why) => why.clone(),
        };
        self.notice = Some((why, Tone::Neutral));
        // Posted, so the offer is asked through the window's command path.
        unsafe {
            PostMessageW(hwnd, WM_COMMAND, OFFER_SIGN_IN, 0);
        }
    }

    /// Find the key, step two: the customer signs in and the key is read from the account.
    /// The sign-in window runs its own message loop until it closes.
    fn sign_in(&mut self, hwnd: HWND) {
        let Some(lookup) = self.lookup.take() else {
            return;
        };
        let options = SignInOptions {
            key_ids: lookup.key_ids.clone(),
            account: None,
        };
        let result = keylookup_view::fetch_recovery_key(
            hwnd,
            &options,
            &mut |_| {},
            &AtomicBool::new(false),
        );
        if let Some(key) = &result.key {
            let key = KeyText::copy_of(key.as_str());
            self.key_from = Some("the key read from the customer's Microsoft account".into());
            self.unlock_with(lookup.device_id, key, lookup.confirmed);
            return;
        }
        let typed = "Type the recovery key in the box instead.";
        self.notice = Some(match result.outcome {
            SignInOutcome::KeyRead => (typed.into(), Tone::Warn),
            SignInOutcome::NoMatch { keys_listed } => (
                format!(
                    "The account lists {keys_listed} recovery {}, none for key ID {}. The key may be in another account, or printed or saved elsewhere. {typed}",
                    if keys_listed == 1 { "key" } else { "keys" },
                    lookup.shown
                ),
                Tone::Warn,
            ),
            SignInOutcome::NotUnderstood => (
                format!("The account's key page could not be read with certainty. {typed}"),
                Tone::Warn,
            ),
            SignInOutcome::Cancelled => (
                format!("The sign-in window was closed before a key was read. {typed}"),
                Tone::Neutral,
            ),
            SignInOutcome::Unavailable { reason } => (format!("{reason} {typed}"), Tone::Warn),
        });
    }

    /// Locks again each volume this window holds, each named for people with its outcome.
    /// Those still unlocked stay held.
    fn relock_all(&mut self, force: bool) -> Vec<(String, RelockOutcome)> {
        let mut outcomes = Vec::new();
        for mut relock in std::mem::take(&mut self.held) {
            let device = relock.device_id().unwrap_or_default().to_string();
            let name = self
                .rows
                .iter()
                .find(|r| r.found.device_id == device)
                .and_then(|r| r.found.letter.clone())
                .map_or_else(
                    || "A volume unlocked here".to_string(),
                    |letter| format!("Volume {letter}"),
                );
            let outcome = relock.relock(force);
            if relock.device_id().is_some() {
                self.held.push(relock);
            }
            outcomes.push((name, outcome));
        }
        outcomes
    }

    fn picked(&mut self, hwnd: HWND, done: Done) {
        match done {
            Done::Scanned(Ok(result)) => {
                self.scanned = true;
                // Volumes this window unlocked stay marked, so closing locks them.
                let mine: Vec<Row> = self.rows.drain(..).filter(|r| r.unlocked_here).collect();
                self.rows = result
                    .volumes
                    .into_iter()
                    .map(|found| {
                        let earlier = mine.iter().find(|r| r.found.device_id == found.device_id);
                        Row {
                            unlocked_here: earlier.is_some(),
                            source: earlier.and_then(|r| r.source.clone()),
                            found,
                        }
                    })
                    .collect();
                if self
                    .notice
                    .as_ref()
                    .is_none_or(|(_, tone)| *tone == Tone::Neutral)
                {
                    // An empty list says itself that nothing was found.
                    self.notice = (!self.rows.is_empty()).then(|| {
                        (
                            "Choose a volume. The recovery key ID tells which key unlocks it: the customer's Microsoft account lists keys by this ID.".into(),
                            Tone::Neutral,
                        )
                    });
                }
            }
            Done::Scanned(Err(why)) => self.notice = Some((why, Tone::Warn)),
            Done::Unlocked(Ok((_, None))) => {
                self.key_from = None;
                self.rescan();
                self.notice = Some((
                    "This volume was already unlocked, so the key was not used. It was not unlocked here, so it stays unlocked when this window closes.".into(),
                    Tone::Neutral,
                ));
            }
            Done::Unlocked(Ok((result, Some(relock)))) => {
                self.held.push(relock);
                for row in self
                    .rows
                    .iter_mut()
                    .filter(|r| r.found.device_id == result.device_id)
                {
                    row.unlocked_here = true;
                    row.source = Some(result.source.clone());
                }
                self.rescan();
                let with = self
                    .key_from
                    .take()
                    .map_or_else(String::new, |from| format!(" with {from}"));
                self.notice = Some((
                    format!("Unlocked{with}. Recover files from it here; it is locked again when this window closes."),
                    Tone::Ok,
                ));
            }
            Done::Unlocked(Err(why)) => {
                let with = self
                    .key_from
                    .take()
                    .map_or_else(String::new, |from| format!(" with {from}"));
                self.notice = Some((
                    if with.is_empty() {
                        why
                    } else {
                        format!("It did not unlock{with}: {why}")
                    },
                    Tone::Warn,
                ));
            }
            Done::Locked(device, outcome, relock) => {
                // Still unlocked: kept, so closing tries again.
                if relock.device_id().is_some() {
                    self.held.push(relock);
                } else {
                    for row in self.rows.iter_mut().filter(|r| r.found.device_id == device) {
                        row.unlocked_here = false;
                        row.source = None;
                    }
                }
                self.rescan();
                let tone = if outcome.locked() {
                    Tone::Ok
                } else {
                    Tone::Warn
                };
                self.notice = Some((outcome.text("The volume"), tone));
            }
            Done::KeyFiles(result) => self.key_files_searched(hwnd, result),
        }
    }
}

impl Page for BitLockerView {
    fn title(&self) -> String {
        TITLE.into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::BITLOCKER)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((720, 560), (560, 480))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let button = |id, kind, caption: &str| ui::button(hwnd, id, kind, caption);
        self.controls = Some(Controls {
            title: text(Kind::Title, TITLE),
            subtitle: text(Kind::Muted, &format!("Disk {}", self.disk)),
            // An attached image is no drive to watch; the drive being recovered is.
            strip: crate::condition_strip::Strip::new(hwnd, self.is_source().then_some(self.disk)),
            advice: ui::text(
                hwnd,
                Kind::Body,
                Tone::Neutral,
                true,
                advice(self.is_source()),
            ),
            volumes: toolwin::list(hwnd, VOLUMES, grid::ROW_H),
            key_label: text(Kind::Body, "Recovery key"),
            key: toolwin::search_box(hwnd, KEY, "000000-000000-000000-000000-000000-000000-000000-000000"),
            key_form: text(
                Kind::Muted,
                "48 digits in eight groups of six, as Windows' recovery screen and the Microsoft account show it. Dashes are optional.",
            ),
            find_key: button(FIND_KEY, Kind::Secondary, "Find the key…"),
            unlock: button(UNLOCK, Kind::Primary, "Unlock"),
            explore: button(EXPLORE, Kind::Secondary, "Open in Explorer"),
            recover: button(RECOVER, Kind::Secondary, "Recover deleted or lost files…"),
            by_type: button(BY_TYPE, Kind::Secondary, "Find files by type…"),
            lock: button(LOCK, Kind::Secondary, "Lock again"),
            notice: text(Kind::Body, ""),
            close: button(CLOSE, Kind::Ghost, "Close"),
        });
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        let (bh, gap) = (f.s(grid::BUTTON_H), f.s(grid::BUTTON_GAP));
        f.header(c.title, c.subtitle);
        c.strip.place(&mut f);
        f.space(2);
        // The advice sits on a card.
        let pad = f.s(grid::CARD_PAD);
        let advice_h = f.text_h(c.advice, f.w - 2 * pad);
        let card = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: advice_h + 2 * pad,
        };
        ui::place(
            c.advice,
            Rect {
                x: f.x + pad,
                y: f.y + pad,
                w: f.w - 2 * pad,
                h: advice_h,
            },
        );
        f.y += card.h;
        f.space(12);
        let rows = toolwin::count(c.volumes).clamp(2, 4) as i32;
        f.block(c.volumes, f.s(grid::ROW_H) * rows + f.s(4));
        f.space(12);
        f.text(c.key_label, 4);
        // The key field, then Find the key and Unlock on its right.
        let unlock_w = ui::button_width(c.unlock, "Unlock");
        let find_w = ui::button_width(c.find_key, &ui::window_text(c.find_key));
        ui::set_font(c.key, ui::fonts(dpi).body);
        let field_w = f.w - unlock_w - find_w - 2 * gap;
        ui::place(
            c.key,
            Rect {
                x: f.x,
                y: f.y + f.s(6),
                w: field_w,
                h: bh - f.s(12),
            },
        );
        let at = |x, b| {
            ui::place(
                b,
                Rect {
                    x,
                    y: f.y,
                    w: ui::button_width(b, &ui::window_text(b)),
                    h: bh,
                },
            )
        };
        at(f.x + field_w + gap, c.find_key);
        at(f.x + f.w - unlock_w, c.unlock);
        f.y += bh;
        f.space(4);
        f.text(c.key_form, 12);
        f.buttons(&[c.explore, c.recover, c.by_type, c.lock], 12);
        f.text(c.notice, 0);
        self.natural = Some(f.y + toolwin::footer_h(dpi));
        toolwin::footer(w, h, dpi, &[], &[c.close]);
        ui::set_cards(hwnd, vec![card]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    /// Locks again every volume this window unlocked, before it closes, and says every
    /// outcome but locked. A volume in use is not dismounted unless the technician says so.
    fn close_ask(&mut self) -> Option<Ask> {
        let outcomes = self.relock_all(false);
        let problems: Vec<String> = outcomes
            .iter()
            .filter(|(_, o)| !o.locked())
            .map(|(name, o)| o.text(name))
            .collect();
        if problems.is_empty() {
            return None;
        }
        let retry = !self.held.is_empty();
        Some(Ask {
            dialog: Dialog {
                window_title: TITLE.into(),
                heading: "Not every volume is locked again".into(),
                intro: if retry {
                    format!(
                        "{} Lock anyway closes the files open on it; nothing is written to it.",
                        problems.join(" ")
                    )
                } else {
                    problems.join(" ")
                },
                sections: Vec::<Section>::new(),
                accept: if retry {
                    "Lock anyway and close".into()
                } else {
                    "Close".into()
                },
                decline: Some("Keep the window open".into()),
                copy: None,
            },
            then: if retry { FORCE_LOCK } else { CLOSE_ANYWAY },
        })
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        let mut ask = None;
        // The exclusion is tried again on each choice in the window until it is held, so a
        // fix made meanwhile (such as running as administrator elsewhere) turns the box on.
        if self.dumps.is_err() && id != CLOSE {
            self.dumps = crash_dumps::keep_out_of_dumps();
        }
        match id {
            KEY if u32::from(code) == EN_CHANGE => self.key_changed(hwnd),
            UNLOCK if self.is_source() => ask = Some(Self::confirm_source(DO_UNLOCK)),
            UNLOCK => self.unlock(false),
            DO_UNLOCK => self.unlock(true),
            FIND_KEY if self.is_source() => ask = Some(Self::confirm_source(DO_FIND_KEY)),
            FIND_KEY => self.find_key(false),
            DO_FIND_KEY => self.find_key(true),
            OFFER_SIGN_IN => {
                if let Some(lookup) = &self.lookup {
                    ask = Some(Ask {
                        dialog: Dialog {
                            window_title: TITLE.into(),
                            heading: "Find the key in the customer's Microsoft account?".into(),
                            intro: format!(
                                "No saved key file for key ID {} was found. Windows usually keeps the recovery key in the Microsoft account the customer signs in to Windows with. The customer signs in on Microsoft's page in the next window; the key is read from it and used to unlock this volume, and it is not shown.",
                                lookup.shown
                            ),
                            sections: Vec::<Section>::new(),
                            accept: "Sign in…".into(),
                            decline: Some("Type the key instead".into()),
                            copy: None,
                        },
                        then: DO_SIGN_IN,
                    });
                }
            }
            DO_SIGN_IN => self.sign_in(hwnd),
            EXPLORE => {
                if let Some(letter) = self.selected().and_then(|r| r.found.letter.clone()) {
                    toolwin::open_path(hwnd, std::path::Path::new(&format!("{letter}\\")));
                }
            }
            RECOVER => {
                if let Some(source) = self.volume_source() {
                    recover_files::open_recover(hwnd, source);
                }
            }
            BY_TYPE => {
                if let Some(source) = self.volume_source() {
                    recover_files::open_by_type(hwnd, source);
                }
            }
            LOCK => {
                let device = self.selected().map(|row| row.found.device_id.clone());
                let at = device.as_ref().and_then(|device| {
                    self.held
                        .iter()
                        .position(|r| r.device_id().is_some_and(|d| d == device))
                });
                if let (Some(device), Some(at)) = (device, at) {
                    let mut relock = self.held.remove(at);
                    self.start_job("Locking…", move || {
                        let outcome = relock.relock(true);
                        Done::Locked(device, outcome, relock)
                    });
                }
            }
            FORCE_LOCK => {
                let outcomes = self.relock_all(true);
                let problems: Vec<String> = outcomes
                    .iter()
                    .filter(|(_, o)| !o.locked())
                    .map(|(name, o)| o.text(name))
                    .collect();
                if !problems.is_empty() {
                    crate::dialog::show(
                        hwnd,
                        &Dialog {
                            window_title: TITLE.into(),
                            heading: "Not every volume is locked again".into(),
                            intro: problems.join(" "),
                            sections: Vec::<Section>::new(),
                            accept: "Close".into(),
                            decline: None,
                            copy: None,
                        },
                    );
                }
            }
            // Posted, so the window closes after this call returns.
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        self.relayout(hwnd);
        ask
    }

    fn tick(&mut self, hwnd: HWND) {
        if let Some(c) = &mut self.controls {
            c.strip.refresh();
        }
        // Changes and relocks that could not be entered in the change record are said here.
        let unsaid: Vec<String> = crash_dumps::unrecorded()
            .into_iter()
            .chain(bitlocker::unsaid_relocks())
            .collect();
        if !unsaid.is_empty() {
            self.notice = Some((unsaid.join(" "), Tone::Warn));
            self.render();
        }
        if let Some(job) = &self.job {
            match job.try_recv() {
                Ok(done) => {
                    self.job = None;
                    self.picked(hwnd, done);
                    self.render();
                    self.relayout(hwnd);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.job = None;
                    self.notice = Some(("The work stopped without an answer.".into(), Tone::Warn));
                    self.render();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        if self
            .controls
            .as_ref()
            .is_some_and(|c| c.strip.draw(list, dc, rect, state.dpi))
        {
            return;
        }
        let text = self.rows.get(index).map(Row::text);
        vdisk_view::draw_line(dc, rect, state, text.as_deref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advice_says_image_first_and_unlock_the_image() {
        let text = advice(true);
        let image = text.find("make a rescue image first").unwrap();
        let unlock = text.find("unlock the image instead").unwrap();
        assert!(image < unlock);
        assert!(text.contains("can write"));
        assert!(advice(false).contains("writes nothing"));
    }

    /// The guard: a key a lookup found is read out only into the unlock's zeroing type, and
    /// no part of it is shown, as the typed key is not.
    #[test]
    fn a_looked_up_key_goes_only_into_the_unlock() {
        let code = include_str!("bitlocker_view.rs");
        let code = code.split("#[cfg(test)]").next().unwrap();
        let reads: Vec<&str> = code.lines().filter(|l| l.contains(".as_str()")).collect();
        assert_eq!(reads.len(), 2, "the key file's key and the account's key");
        for line in reads {
            assert!(
                line.contains("KeyText::copy_of(key.as_str())")
                    || line.contains("KeyText::copy_of(saved.key.as_str())"),
                "{line}"
            );
        }
        assert!(!code.contains("last_group"), "part of a key is shown");
    }

    /// The guard: no plain `String` or unzeroed buffer ever holds the key box's text. It is
    /// read only into the zeroing `WideSecret` and decoded only into `KeyText`'s own
    /// buffer; nothing formats, converts or copies it out, and the box is emptied with its
    /// undo buffer.
    #[test]
    fn the_key_box_text_lives_only_in_zeroing_types() {
        let code = include_str!("bitlocker_view.rs");
        let code = code.split("#[cfg(test)]").next().unwrap();
        for banned in [
            "String::from_utf16",
            "from_utf16_lossy",
            "KeyText::new(",
            "take_text(",
            ".0.to_vec()",
            ".0.clone()",
        ] {
            assert!(!code.contains(banned), "{banned}");
        }
        let reads: Vec<&str> = code
            .lines()
            .filter(|l| l.contains("GetWindowTextW(") && !l.contains("use "))
            .collect();
        assert_eq!(reads.len(), 1, "{reads:?}");
        assert!(reads[0].contains("buffer.0.as_mut_ptr()"));
        let read = &code[code.find("fn read_key_box(").unwrap()..];
        let read = &read[..read.find("\n}\n").unwrap()];
        assert!(read.contains("let mut buffer = WideSecret(vec![0u16; len + 1]);"));
        let take = &code[code.find("fn take_key(").unwrap()..];
        let take = &take[..take.find("\n}\n").unwrap()];
        assert!(take.contains("KeyText::from_wide(&typed.0)") && take.contains("clear_key(edit);"));
        let clear = &code[code.find("fn clear_key(").unwrap()..];
        let clear = &clear[..clear.find("\n}\n").unwrap()];
        assert!(clear.contains("EM_EMPTYUNDOBUFFER"));
        // Every use of the box's text: read into WideSecret, or the box cleared.
        assert_eq!(
            code.matches("read_key_box(").count(),
            3,
            "defined, take_key, key_changed"
        );
    }
}
