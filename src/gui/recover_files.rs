//! Recover deleted or lost files, and find files by type: one window each, reading a disk or
//! an image through `diagnostics::recovery`. Work runs on a background thread that owns the
//! source while it reads and hands it back with its result; the window polls from `tick`.
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Instant;

use diagnostics::recovery::candidates::{self, Kind as VersionKind};
use diagnostics::recovery::carve::{self, Carved, Kind as CarveKind};
use diagnostics::recovery::dest::{Guard, Protected};
use diagnostics::recovery::fs::parts::{self, Search};
use diagnostics::recovery::fs::{self, Found, Listing, Progress, State, Volume};
use diagnostics::recovery::image::{Block, Map, Phase, Status};
use diagnostics::recovery::ledger::files;
use diagnostics::recovery::output::{self, Item, Layout, Outcome, RecoverOptions};
use diagnostics::recovery::pace::Pace;
use diagnostics::recovery::thumbcache;
use diagnostics::recovery::{timed, writer, BlockSource, SourceChoice};
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    InvalidateRect, DT_END_ELLIPSIS, DT_LEFT, DT_PATH_ELLIPSIS, DT_RIGHT, DT_SINGLELINE,
    DT_VCENTER, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow;

use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, wide, Kind, Tone};
use crate::verify_view;

/// Every reader here owns the disk or image it reads.
type Reader = diagnostics::recovery::reader::Reader<'static>;

const FIND_LOST: usize = 10;
const FIND_ALL: usize = 11;
const STOP: usize = 12;
const DELETED: usize = 13;
/// Kind-of-file filters take seven ids from here, in `GROUPS` order.
const GROUP: usize = 14;
const NAME: usize = 22;
const FOLDER: usize = 23;
const SELECT_ALL: usize = 24;
const CLEAR: usize = 25;
const KEEP: usize = 26;
const BY_TYPE: usize = 27;
const RECOVER: usize = 28;
const OPEN: usize = 29;
const CLOSE: usize = 30;
const START: usize = 31;
const THUMBS: usize = 32;
const CHECK: usize = 33;
const SAVE_LIST: usize = 60;
const FIND_GOOD: usize = 61;
const SAVE_GOOD: usize = 62;
const OWN_DAMAGED: usize = 63;
const OWN_DELETED: usize = 64;
/// Carving types take eleven ids from here, in `CarveKind::ALL` order.
const TYPES: usize = 40;
/// Distinct from other pages' lists: toolwin keeps item heights by control id.
const VOLUMES: usize = 71;
const FILES: usize = 72;
const CARVED: usize = 73;
const SUMMARY: usize = 74;
const VERSIONS: usize = 75;
const ITEM_H: i32 = 32;
const VOLUME_H: i32 = 28;
/// One row of the damage table and of the versions list.
const SUMMARY_H: i32 = 22;
const EN_CHANGE: u16 = 0x0300;
/// More rows than this are not put in the list; the filters narrow it.
const MAX_ROWS: usize = 20_000;

const GROUPS: [&str; 7] = [
    "All",
    "Pictures",
    "Documents",
    "Video",
    "Audio",
    "Archives",
    "Other",
];

/// Whether this build has these tools; the recovery window hides them until it does.
pub fn available() -> bool {
    true
}

/// Opens the deleted and lost file recovery for a disk or image.
pub fn open_recover(owner: HWND, source: SourceChoice) {
    let key = format!("recover-files:{source:?}");
    toolwin::open(owner, &key, move || Box::new(RecoverPage::new(source)));
}

/// Opens the scan for files by type for a disk or image.
pub fn open_by_type(owner: HWND, source: SourceChoice) {
    let key = format!("files-by-type:{source:?}");
    toolwin::open(owner, &key, move || Box::new(TypePage::new(source)));
}

/// What a background job hands back with the source.
enum Done {
    Volumes(parts::Finds),
    Listing(u64, Result<Listing, String>),
    /// What the search skipped and why, one line each: the limits it reached.
    Carved(Vec<String>),
    Recovered(Result<Outcome, String>),
    /// The good versions found for the damaged pictures of the volume starting at this byte.
    Candidates(u64, candidates::Search),
    Thumbnails(Result<thumbcache::Outcome, String>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Doing {
    Finding(Search),
    Scanning,
    Carving,
    Recovering,
    Candidates,
    Thumbnails,
}

struct Job {
    doing: Doing,
    cancel: Arc<AtomicBool>,
    progress: Arc<Progress>,
    carve: Arc<carve::Progress>,
    result: mpsc::Receiver<(Reader, Done)>,
    started: Instant,
}

impl Job {
    fn start(
        reader: Reader,
        doing: Doing,
        work: impl FnOnce(&mut Reader, &AtomicBool, &Progress, &carve::Progress) -> Done
            + Send
            + 'static,
    ) -> Job {
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let carve_progress = Arc::new(carve::Progress::default());
        let (sender, result) = mpsc::channel();
        let (c, p, cp) = (cancel.clone(), progress.clone(), carve_progress.clone());
        thread::spawn(move || {
            let mut reader = reader;
            let done = work(&mut reader, &c, &p, &cp);
            let _ = sender.send((reader, done));
        });
        Job {
            doing,
            cancel,
            progress,
            carve: carve_progress,
            result,
            started: Instant::now(),
        }
    }

    fn seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

type Opening = mpsc::Receiver<Result<Box<dyn BlockSource>, String>>;

/// The opening source's answer, once it has come: the reader, or why there is none.
fn opened(opening: &Opening) -> Option<Result<Reader, String>> {
    match opening.try_recv() {
        Ok(result) => Some(result.map(Reader::new)),
        Err(mpsc::TryRecvError::Disconnected) => Some(Err("the source could not be opened".into())),
        Err(mpsc::TryRecvError::Empty) => None,
    }
}

/// Lets the user choose a folder. None when cancelled.
fn pick_folder(owner: HWND, title: &str) -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS,
        BROWSEINFOW,
    };
    let title = wide(title);
    let mut info: BROWSEINFOW = unsafe { std::mem::zeroed() };
    info.hwndOwner = owner;
    info.lpszTitle = title.as_ptr();
    info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    // SAFETY: info and title outlive the call; the returned list is freed below.
    let list = unsafe { SHBrowseForFolderW(&info) };
    if list.is_null() {
        return None;
    }
    let mut path = vec![0u16; 1024];
    let ok = unsafe { SHGetPathFromIDListW(list, path.as_mut_ptr()) } != 0;
    unsafe { CoTaskMemFree(list as *const _) };
    let end = path.iter().position(|c| *c == 0).unwrap_or(0);
    (ok && end > 0).then(|| PathBuf::from(String::from_utf16_lossy(&path[..end])))
}

/// "1 file", "1,204 files".
/// How a search by type ended, for the line that stays after it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Searched {
    /// Bytes read from the start, out of the source's length.
    read: u64,
    total: u64,
    seconds: u64,
    /// Stopped by the person or by the source going away before the end.
    stopped: bool,
    /// Unreadable areas met within what was read: how many, and their bytes.
    unreadable: (usize, u64),
}

impl Searched {
    fn new(progress: &carve::Progress, seconds: u64, stopped: bool, reader: &Reader) -> Self {
        let total = progress.total.load(Ordering::Relaxed);
        let read = progress.done.load(Ordering::Relaxed).min(total);
        let bad: Vec<u64> = reader
            .bad_areas()
            .iter()
            .map(|b| b.end.min(read).saturating_sub(b.start))
            .filter(|n| *n > 0)
            .collect();
        Self {
            read,
            total,
            seconds,
            stopped: stopped || read < total,
            unreadable: (bad.len(), bad.iter().sum()),
        }
    }
}

/// "41 s", "12 min 3 s", "1 h 20 min".
fn took(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {} min", seconds / 3600, (seconds % 3600) / 60),
    }
}

/// "Finished: read 31.0 GB in 41 s; 43 files found, 0 selected.", with any unreadable
/// areas, or "Stopped after …" when it did not reach the end.
fn searched_text(s: &Searched, found: u64, selected: u64) -> String {
    let mut text = if s.stopped {
        format!(
            "Stopped after reading {} of {} in {}",
            bytes_text(s.read),
            bytes_text(s.total),
            took(s.seconds)
        )
    } else {
        format!(
            "Finished: read {} in {}",
            bytes_text(s.read),
            took(s.seconds)
        )
    };
    match s.unreadable {
        (0, _) => {}
        (1, bytes) => text.push_str(&format!(
            ", 1 unreadable area ({}) skipped",
            bytes_text(bytes)
        )),
        (n, bytes) => text.push_str(&format!(
            ", {} unreadable areas ({}) skipped",
            crate::space_view::count(n as u64),
            bytes_text(bytes)
        )),
    }
    format!(
        "{text}; {} found, {} selected.",
        files_text(found),
        crate::space_view::count(selected)
    )
}

fn files_text(n: u64) -> String {
    if n == 1 {
        "1 file".into()
    } else {
        format!("{} files", crate::space_view::count(n))
    }
}

/// The kinds the damage table tells apart, in its rows.
const KINDS: [&str; 4] = ["Photos", "Videos", "Documents", "Other"];

/// The folders of the destination that damaged and deleted files go under when asked, and
/// the one the good versions of damaged pictures are written to.
const DAMAGED_FOLDER: &str = "repair_needed";
const DELETED_FOLDER: &str = "deleted";
const CANDIDATES_FOLDER: &str = "repair_candidates";
/// The text file of the damaged files, written where the person chooses.
const DAMAGED_LIST: &str = "Damaged files.txt";

/// Files of one kind that read whole, and that do not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Condition {
    whole: u64,
    damaged: u64,
}

/// How many of some files would copy whole and how many damaged, by kind (`KINDS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Damage {
    kinds: [Condition; 4],
}

impl Damage {
    fn total(&self) -> Condition {
        self.kinds
            .iter()
            .fold(Condition::default(), |sum, c| Condition {
                whole: sum.whole + c.whole,
                damaged: sum.damaged + c.damaged,
            })
    }
}

/// A map that marks everything rescued, for a source read without one.
fn all_rescued() -> Map {
    Map {
        blocks: vec![Block {
            pos: 0,
            size: u64::MAX,
            status: Status::Rescued,
        }],
        current_pos: 0,
        phase: Phase::Finished,
        pass: 1,
    }
}

/// The parts of `f` the rescue did not read. Without a map every readable part counts as read.
fn unread(f: &Found, map: Option<&Map>) -> Vec<Range<u64>> {
    match map {
        Some(map) => candidates::unrescued(f, map),
        None => candidates::unrescued(f, &all_rescued()),
    }
}

/// A file is damaged when a byte of it was never rescued, or the volume's own record of it
/// is damaged; else it copies whole.
fn is_damaged(f: &Found, map: Option<&Map>) -> bool {
    f.damaged || !unread(f, map).is_empty()
}

fn kind_of(name: &str) -> usize {
    match output::group_of(name) {
        "Pictures" => 0,
        "Video" => 1,
        "Documents" => 2,
        _ => 3,
    }
}

/// Counts `files` whole and damaged by kind, from each file's runs against the rescue map.
fn damage_of<'a>(files: impl IntoIterator<Item = &'a Found>, map: Option<&Map>) -> Damage {
    let mut damage = Damage::default();
    for f in files {
        let count = &mut damage.kinds[kind_of(&f.name)];
        if is_damaged(f, map) {
            count.damaged += 1;
        } else {
            count.whole += 1;
        }
    }
    damage
}

fn path_of(f: &Found) -> String {
    if f.folder.is_empty() {
        format!("\\{}", f.name)
    } else {
        format!("{}\\{}", f.folder_text(), f.name)
    }
}

/// The damaged files among `files`, one row each: path, size and bytes not rescued, with a
/// header row. Tab separated, for a spreadsheet or a person.
fn damaged_list<'a>(files: impl IntoIterator<Item = &'a Found>, map: Option<&Map>) -> String {
    let mut text = String::from("Path\tSize in bytes\tBytes missing\r\n");
    for f in files {
        let missing: u64 = unread(f, map).iter().map(|r| r.end - r.start).sum();
        if f.damaged || missing > 0 {
            text.push_str(&format!("{}\t{}\t{missing}\r\n", path_of(f), f.size));
        }
    }
    text
}

/// Writes `text` as a new file `name` in `folder` through the ledgered writer; the file's
/// path, or why it could not be made or written to its end.
fn write_text(guard: &Guard, folder: &Path, name: &str, text: &str) -> Result<PathBuf, String> {
    let base = guard
        .base(folder)
        .map_err(|e| format!("{} could not be opened: {e}", folder.display()))?;
    let (made, _) = writer::write_lone_report(guard, &base, name, text.as_bytes());
    match (made.path, made.error) {
        (Some(path), None) => Ok(path),
        (_, Some(why)) => Err(format!("{name}: {why}")),
        (None, None) => Err(format!("{name} could not be made")),
    }
}

/// How the options of the window lay a recovery out.
fn recover_options(layout: Layout, damaged_apart: bool, deleted_apart: bool) -> RecoverOptions {
    RecoverOptions {
        layout,
        damaged_folder: damaged_apart.then(|| DAMAGED_FOLDER.to_string()),
        deleted_folder: deleted_apart.then(|| DELETED_FOLDER.to_string()),
        ..RecoverOptions::default()
    }
}

/// "3 whole, 1 near, 2 other" for a damaged picture's versions.
fn versions_text(d: &candidates::Damaged) -> String {
    let count = |kind| d.versions.iter().filter(|v| v.kind == kind).count();
    format!(
        "{} whole, {} near, {} other",
        count(VersionKind::Whole),
        count(VersionKind::Near),
        count(VersionKind::Lesser)
    )
}

/// What the search for good versions found, in one line.
fn found_text(search: &candidates::Search) -> String {
    let with = search
        .damaged
        .iter()
        .filter(|d| !d.versions.is_empty())
        .count();
    let mut text = format!(
        "{} damaged {}, {with} with a good version found.",
        search.damaged.len(),
        if search.damaged.len() == 1 {
            "picture"
        } else {
            "pictures"
        }
    );
    if search.stopped {
        text.push_str(" Stopped before the end.");
    }
    text
}

/// Writes every good version found into `repair_candidates` under `dest`, each under its
/// damaged picture's folders and named after it, with each folder's list of where its
/// versions came from. Nothing replaces a damaged file: a person reviews these.
fn save_versions(
    reader: &mut Reader,
    listing: &Listing,
    search: &candidates::Search,
    dest: &Path,
    disk: &Protected,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Result<Outcome, String> {
    let plan = candidates::plan(&search.damaged);
    let items: Vec<Item> = plan
        .files
        .iter()
        .filter_map(|n| {
            let version = search.damaged.get(n.damaged)?.versions.get(n.version)?;
            let mut item = Item::from_found(listing.files.get(version.file)?);
            item.name = n.name.clone();
            item.folder = n.folder.clone();
            item.deleted = false;
            Some(item)
        })
        .collect();
    let guard = Guard::of(&disk.clone().join(reader.protected()));
    guard.check_folder(dest)?;
    let base = guard
        .base(dest)
        .map_err(|e| format!("{} could not be opened: {e}", dest.display()))?;
    guard
        .folder(&base, OsStr::new(CANDIDATES_FOLDER))
        .map_err(|e| format!("{CANDIDATES_FOLDER} could not be made: {e}"))?;
    let target = dest.join(CANDIDATES_FOLDER);
    let mut outcome = output::recover(
        reader,
        &items,
        &target,
        &RecoverOptions::default(),
        disk,
        cancel,
        progress,
    )?;
    let top = guard
        .base(&target)
        .map_err(|e| format!("{} could not be opened: {e}", target.display()))?;
    for (folder, text) in &plan.lists {
        let made = guard
            .folders(&top, folder.iter().map(|p| output::safe_name(p)))
            .map_err(|e| e.to_string())
            .and_then(|f| {
                let (made, _) =
                    writer::write_lone_report(&guard, &f, candidates::LIST_NAME, text.as_bytes());
                made.error.map_or(Ok(()), Err)
            });
        if let Err(why) = made {
            outcome.failed.push((
                format!("{} for \\{}", candidates::LIST_NAME, folder.join("\\")),
                why,
            ));
        }
    }
    Ok(outcome)
}

/// What the pace of a copy says: the time left and the write rate, or that it is still
/// being measured.
fn pace_text(pace: &Pace) -> String {
    match pace.time_left() {
        Some(left) => format!(
            "about {} left, writing {}/s, {:.1} files/s",
            took(left.as_secs()),
            bytes_text(pace.bytes_per_sec() as u64),
            pace.files_per_sec()
        ),
        None => "measuring the time left".into(),
    }
}

/// A listing's files, for a job that outlives the window's borrow of it.
fn files_of(listing: &Listing) -> Listing {
    Listing {
        files: listing.files.clone(),
        ..Listing::default()
    }
}

fn count_text(n: u64) -> String {
    crate::space_view::count(n)
}

/// What a recovery did, for its result line, from its ledger, and the tone it is shown in:
/// all well is shown as such, anything less as a warning.
fn outcome_text(outcome: &Outcome, dest: &std::path::Path) -> (String, Tone) {
    let mut text = format!(
        "Recovered {} to {}.",
        files(outcome.complete() + outcome.damaged()),
        dest.display()
    );
    if outcome.kept > 0 || outcome.resumed > 0 {
        text.push_str(&format!(
            " Kept {} an earlier run left whole, finished {} it left cut short.",
            files(outcome.kept),
            files(outcome.resumed)
        ));
    }
    if outcome.left_out > 0 {
        text.push_str(&format!(
            " Left out {} under System Volume Information.",
            files(outcome.left_out)
        ));
    }
    let damaged = outcome.damaged();
    if damaged > 0 {
        text.push_str(&format!(
            " {damaged} damaged: unreadable parts written as zeros, or a damaged record on the volume."
        ));
    }
    let partial = outcome.partial();
    if partial > 0 {
        text.push_str(&format!(
            " {} incomplete, marked PARTIAL in the report.",
            files(partial)
        ));
    }
    if !outcome.pictures.is_empty() {
        text.push_str(&format!(
            " {} with missing parts {}, {} built-in previews saved beside them.",
            files(outcome.pictures.len()),
            outcome.pictures_placed(),
            outcome.previews()
        ));
        let stayed = outcome.pictures_stayed();
        if stayed > 0 {
            text.push_str(&format!(
                " {stayed} of them could not be put so; the report says where each is."
            ));
        }
    }
    if !outcome.failed.is_empty() {
        text.push_str(&format!(
            " {} could not be made: {}.",
            files(outcome.failed.len()),
            outcome.failed[0].1
        ));
    }
    if outcome.stopped {
        text.push_str(" Stopped before the end.");
    }
    if let Some(why) = &outcome.gone {
        text.push_str(&format!(" The source stopped: {why}."));
    }
    match (&outcome.log, &outcome.log_error) {
        (Some(path), None) => text.push_str(&format!(
            " The log, {}, is there.",
            path.file_name().unwrap_or_default().to_string_lossy()
        )),
        (Some(path), Some(why)) => text.push_str(&format!(
            " {} could not be written to its end ({why}).",
            path.file_name().unwrap_or_default().to_string_lossy()
        )),
        (None, _) => text.push_str(&format!(
            " The log, {}, could not be made.",
            output::LOG_NAME
        )),
    }
    match (&outcome.report, &outcome.report_error) {
        (Some(path), None) => text.push_str(&format!(
            " The report, {}, is there too.",
            path.file_name().unwrap_or_default().to_string_lossy()
        )),
        (Some(path), Some(why)) => text.push_str(&format!(
            " {} could not be written in full ({why}); it lacks its last line, \"{}\".",
            path.file_name().unwrap_or_default().to_string_lossy(),
            output::END
        )),
        (None, why) => text.push_str(&format!(
            " The report could not be made{}.",
            why.as_ref().map(|w| format!(" ({w})")).unwrap_or_default()
        )),
    }
    let well = damaged == 0
        && partial == 0
        && outcome.failed.is_empty()
        && !outcome.stopped
        && outcome.gone.is_none()
        && outcome.report.is_some()
        && outcome.report_error.is_none()
        && outcome.log.is_some()
        && outcome.log_error.is_none();
    (text, if well { Tone::Ok } else { Tone::Warn })
}

/// What a save of Explorer's thumbnails did, for its result line, and its tone.
fn thumbnails_text(outcome: &thumbcache::Outcome) -> (String, Tone) {
    if outcome.caches.is_empty() {
        let mut text = outcome.notes.join(" ");
        if outcome.stopped {
            text.push_str(" Stopped before the end.");
        }
        return (text, Tone::Warn);
    }
    let caches = match outcome.caches.len() {
        1 => "1 Explorer thumbnail cache".to_string(),
        n => format!("{n} Explorer thumbnail caches"),
    };
    let mut text = format!(
        "Saved {} from {caches} to {}.",
        files(outcome.images() as usize),
        outcome
            .folder
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    );
    if outcome.partial() > 0 {
        text.push_str(&format!(
            " {} more had unreadable parts, written as zeros and named \"(partial)\".",
            outcome.partial()
        ));
    }
    if !outcome.failed.is_empty() {
        text.push_str(&format!(
            " {} could not be made.",
            files(outcome.failed.len())
        ));
    }
    if outcome.stopped {
        text.push_str(" Stopped before the end.");
    }
    if let Some(why) = &outcome.gone {
        text.push_str(&format!(" The source stopped: {why}."));
    }
    match (&outcome.report, &outcome.report_error) {
        (Some(_), None) => text.push_str(" The report is in Thumbnail report.txt there."),
        (_, Some(why)) => text.push_str(&format!(
            " The report could not be written in full ({why})."
        )),
        (None, None) => {}
    }
    let well = outcome.partial() == 0
        && outcome.failed.is_empty()
        && !outcome.stopped
        && outcome.gone.is_none()
        && outcome.report_error.is_none();
    (text, if well { Tone::Ok } else { Tone::Warn })
}

/// A recovery's result line: its text and tone, and what the window shows now.
#[derive(Default)]
struct Result_ {
    text: Option<(String, Tone)>,
    shown: String,
}

impl Result_ {
    fn set(&mut self, result: Option<&(String, Tone)>) {
        self.text = result.cloned();
    }

    /// Puts the result on `hwnd`; says whether its text changed, for the layout.
    fn show(&mut self, hwnd: HWND) -> bool {
        let (text, tone) = self.text.clone().unwrap_or((String::new(), Tone::Neutral));
        ui::set_tone(hwnd, tone);
        if text == self.shown {
            return false;
        }
        ui::set_text(hwnd, &text);
        self.shown = text;
        true
    }
}

/// A checkbox, then text in columns; shared by both lists.
#[allow(clippy::too_many_arguments)]
fn draw_row(
    dc: HDC,
    rect: &RECT,
    state: ItemState,
    checked: bool,
    name: &str,
    middle: &str,
    columns: &[(&str, i32, u32)],
    end: (&str, u32),
) {
    let colors = ui::current();
    let fonts = ui::fonts(state.dpi);
    let s = |v: i32| scale(state.dpi, v);
    ui::fill_rect(dc, rect, colors.card);
    let background = if state.selected {
        colors.raised_hover
    } else if state.hot {
        colors.raised
    } else {
        colors.card
    };
    let canvas = ui::Canvas::new(dc);
    if let Some(canvas) = &canvas {
        if background != colors.card {
            canvas.fill_round(
                (
                    rect.left as f32,
                    (rect.top + s(2)) as f32,
                    (rect.right - rect.left) as f32,
                    (rect.bottom - rect.top - s(4)) as f32,
                ),
                s(6) as f32,
                background,
            );
        }
        let (box_x, box_y, size) = (rect.left + s(8), (rect.top + rect.bottom) / 2 - s(8), s(16));
        let rect_f = (box_x as f32, box_y as f32, size as f32, size as f32);
        if checked {
            canvas.fill_round(rect_f, s(4) as f32, colors.primary);
            ui::check_mark(
                canvas,
                (box_x + size / 2) as f32,
                (box_y + size / 2) as f32,
                s(5) as f32,
                colors.primary_text,
                s(2),
            );
        } else {
            canvas.stroke_round(rect_f, s(4) as f32, colors.muted, s(1).max(1) as f32);
        }
    }
    let line = |left: i32, right: i32| RECT {
        left,
        top: rect.top,
        right,
        bottom: rect.bottom,
    };
    let one = DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS;
    let mut right = rect.right - s(10);
    let end_w = s(150);
    ui::draw_text(
        dc,
        end.0,
        &line(right - end_w, right),
        fonts.body,
        end.1,
        one | DT_RIGHT,
    );
    right -= end_w + s(12);
    for (text, width, color) in columns.iter().rev() {
        let w = s(*width);
        ui::draw_text(
            dc,
            text,
            &line(right - w, right),
            fonts.body,
            *color,
            one | DT_RIGHT,
        );
        right -= w + s(12);
    }
    let left = rect.left + s(34);
    let name_w = ((right - left) * 11 / 20).max(s(80));
    ui::draw_text(
        dc,
        name,
        &line(left, (left + name_w).min(right)),
        fonts.body,
        colors.text,
        one | DT_LEFT,
    );
    if left + name_w + s(12) < right {
        ui::draw_text(
            dc,
            middle,
            &line(left + name_w + s(12), right),
            fonts.body,
            colors.muted,
            DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS | DT_LEFT,
        );
    }
}

/// Places buttons left to right, wrapping at `right`; returns the y below them.
fn flow(buttons: &[(HWND, &str)], x0: i32, right: i32, mut y: i32, bh: i32, gap: i32) -> i32 {
    let mut x = x0;
    for (hwnd, caption) in buttons {
        let bw = ui::button_width(*hwnd, caption);
        if x > x0 && x + bw > right {
            x = x0;
            y += bh + gap;
        }
        ui::place(*hwnd, Rect { x, y, w: bw, h: bh });
        x += bw + gap;
    }
    y + bh
}

/// Replaces one item's text, which screen readers announce, keeping the list's place.
fn replace_item(list: HWND, index: usize, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageW, LB_DELETESTRING, LB_GETTOPINDEX, LB_INSERTSTRING, LB_SETTOPINDEX,
    };
    // SAFETY: list is a list box of this window; the text lives through each call.
    unsafe {
        let top = SendMessageW(list, LB_GETTOPINDEX, 0, 0);
        SendMessageW(list, LB_DELETESTRING, index, 0);
        SendMessageW(list, LB_INSERTSTRING, index, wide(text).as_ptr() as isize);
        SendMessageW(list, LB_SETTOPINDEX, top.max(0) as usize, 0);
    }
    toolwin::select(list, Some(index));
}

/// Adds items to the end of a list.
fn add_items(list: HWND, texts: &[String]) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageW, LB_ADDSTRING};
    for text in texts {
        // SAFETY: as above.
        unsafe { SendMessageW(list, LB_ADDSTRING, 0, wide(text).as_ptr() as isize) };
    }
}

fn toggle(hwnd: HWND, on: bool) {
    ui::set_kind(hwnd, if on { Kind::Secondary } else { Kind::Ghost });
}

// ---- recover deleted or lost files ------------------------------------------------------

#[derive(Clone, Copy)]
struct RecoverControls {
    title: HWND,
    description: HWND,
    volumes: HWND,
    find_lost: HWND,
    find_all: HWND,
    stop: HWND,
    thumbs: HWND,
    status: HWND,
    bar: HWND,
    notice: HWND,
    result: HWND,
    deleted: HWND,
    groups: [HWND; 7],
    name: HWND,
    folder: HWND,
    files: HWND,
    select_all: HWND,
    clear: HWND,
    keep: HWND,
    by_type: HWND,
    recover: HWND,
    open: HWND,
    check: HWND,
    close: HWND,
    summary: HWND,
    save_list: HWND,
    find_good: HWND,
    save_good: HWND,
    good: HWND,
    versions: HWND,
    own_damaged: HWND,
    own_deleted: HWND,
}

pub struct RecoverPage {
    source_disk: diagnostics::recovery::dest::Protected,
    describe: String,
    /// The source while it opens, off the window's thread and with a time limit.
    opening: Option<Opening>,
    reader: Option<Reader>,
    job: Option<Job>,
    failure: Option<String>,
    volumes: Vec<Volume>,
    /// Partitions holding nothing this tool reads, and notes on the search as a whole;
    /// both are rows of the volume list, never the general notice.
    unread: Vec<parts::Unread>,
    search_notes: Vec<String>,
    /// The volume shown, by start offset, and each scanned volume's files.
    chosen: Option<u64>,
    listings: HashMap<u64, Listing>,
    /// Files of the chosen volume shown in the list, by index into its listing.
    view: Vec<usize>,
    checked: HashSet<usize>,
    deleted_only: bool,
    group: usize,
    name: String,
    folder: String,
    layout: Layout,
    /// Damaged and deleted files go in folders of their own (`recover_options`).
    own_damaged: bool,
    own_deleted: bool,
    /// The rescue map the source is read under, kept for judging files while a job holds
    /// the reader.
    map: Option<Map>,
    /// The selected files whole and damaged, by kind; counted when the selection changes.
    damage: Damage,
    /// The good versions found for the damaged pictures of the volume starting at this byte.
    versions: Option<(u64, candidates::Search)>,
    notice: Option<String>,
    last_dest: Option<PathBuf>,
    /// Where the running recovery writes.
    recovering_to: Option<PathBuf>,
    /// The volume being recovered from, by start offset, and its list rows in the order
    /// of the items handed to `recover`; the volume shown may change meanwhile.
    recovering_rows: Option<(u64, Vec<usize>)>,
    controls: Option<RecoverControls>,
    window: Option<(HWND, i32, i32, u32)>,
    shown_notice: String,
    /// The last recovery's outcome, on its own line in its own tone.
    result: Result_,
}

impl Drop for RecoverPage {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }
}

impl RecoverPage {
    fn new(source: SourceChoice) -> Self {
        let source_disk = output::source_disk(&source);
        let describe = source.label();
        Self::new_with(
            describe,
            source_disk,
            Some(timed::open_in_background(source)),
        )
    }

    fn new_with(describe: String, source_disk: Protected, opening: Option<Opening>) -> Self {
        Self {
            source_disk,
            describe,
            opening,
            reader: None,
            job: None,
            failure: None,
            volumes: Vec::new(),
            unread: Vec::new(),
            search_notes: Vec::new(),
            chosen: None,
            listings: HashMap::new(),
            view: Vec::new(),
            checked: HashSet::new(),
            deleted_only: true,
            group: 0,
            name: String::new(),
            folder: String::new(),
            layout: Layout::Folders,
            own_damaged: true,
            own_deleted: true,
            map: None,
            damage: Damage::default(),
            versions: None,
            notice: None,
            last_dest: None,
            recovering_to: None,
            recovering_rows: None,
            controls: None,
            window: None,
            shown_notice: String::new(),
            result: Result_::default(),
        }
    }

    /// Takes the source once it has opened, and reads its partition tables.
    fn take_opened(&mut self) {
        let Some(result) = self.opening.as_ref().and_then(opened) else {
            return;
        };
        self.opening = None;
        match result {
            Ok(reader) => {
                self.describe = reader.describe();
                // The source as it opened says what it protects.
                self.source_disk = reader.protected();
                self.map = reader.map().cloned();
                self.reader = Some(reader);
                self.show_description();
                self.find(Search::Tables);
            }
            Err(why) => self.failure = Some(why),
        }
    }

    fn show_description(&mut self) {
        if let Some(c) = &self.controls {
            ui::set_text(
                c.description,
                &format!(
                    "Reading {}. Nothing is written to it; recovered files go to a folder on another drive.",
                    self.describe
                ),
            );
        }
        // An image's description says what its map shows, and may take more lines.
        if let Some((hwnd, w, h, dpi)) = self.window {
            self.layout(hwnd, w, h, dpi);
            unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
        }
    }

    fn find(&mut self, search: Search) {
        let Some(reader) = self.reader.take() else {
            return;
        };
        self.notice = None;
        self.job = Some(Job::start(
            reader,
            Doing::Finding(search),
            move |r, cancel, progress, _| Done::Volumes(parts::find(r, search, cancel, progress)),
        ));
    }

    fn scan(&mut self, start: u64) {
        let Some(volume) = self.volumes.iter().find(|v| v.start == start).cloned() else {
            return;
        };
        self.chosen = Some(start);
        self.checked.clear();
        if self.listings.contains_key(&start) {
            self.refilter(false);
            return;
        }
        let Some(reader) = self.reader.take() else {
            self.notice = Some("Wait for the current search to finish, or stop it.".into());
            return;
        };
        self.refilter(false);
        self.job = Some(Job::start(
            reader,
            Doing::Scanning,
            move |r, cancel, progress, _| {
                Done::Listing(volume.start, fs::scan(r, &volume, cancel, progress))
            },
        ));
    }

    fn listing(&self) -> Option<&Listing> {
        self.listings.get(&self.chosen?)
    }

    fn keeps(&self, f: &Found) -> bool {
        let lower = |s: &str| s.to_lowercase();
        (!self.deleted_only || f.deleted)
            && (self.group == 0 || output::group_of(&f.name) == GROUPS[self.group])
            && (self.name.is_empty() || lower(&f.name).contains(&lower(&self.name)))
            && (self.folder.is_empty() || lower(&f.folder_text()).contains(&lower(&self.folder)))
    }

    fn refilter(&mut self, keep: bool) {
        self.view = match self.listing() {
            Some(l) => (0..l.files.len())
                .filter(|&i| self.keeps(&l.files[i]))
                .take(MAX_ROWS)
                .collect(),
            None => Vec::new(),
        };
        if let Some(c) = self.controls {
            let texts: Vec<String> = self.view.iter().map(|&i| self.row_text(i)).collect();
            toolwin::set_items(c.files, &texts, keep);
            let rows = self.volume_rows();
            let volume_texts: Vec<String> = rows.iter().map(|r| r.1.clone()).collect();
            toolwin::set_items(c.volumes, &volume_texts, true);
            let at = self
                .chosen
                .and_then(|s| rows.iter().position(|r| r.0 == Some(s)));
            toolwin::select(c.volumes, at);
            let found: Vec<String> = self
                .found()
                .map(|s| s.damaged.iter().map(|d| d.path.clone()).collect())
                .unwrap_or_default();
            toolwin::set_items(c.versions, &found, true);
            toolwin::set_items(c.summary, &[(); 6].map(|()| String::new()), true);
        }
        self.recount();
        self.render();
    }

    /// Counts the selected files whole and damaged, by kind, against the rescue map.
    fn recount(&mut self) {
        let files = self.listing().map(|l| &l.files[..]).unwrap_or_default();
        let chosen = self.checked.iter().filter_map(|&i| files.get(i));
        self.damage = damage_of(chosen, self.map.as_ref());
    }

    /// One row of the damage table: a heading, then each kind, then the total, in columns
    /// at fixed shares of the table's width so no text moves another.
    fn draw_summary(&self, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        ui::fill_rect(dc, rect, colors.card);
        let (label, whole, damaged, color) = match index {
            0 => (
                "Selected files",
                "Whole".into(),
                "Damaged".into(),
                colors.muted,
            ),
            1..=4 => {
                let c = self.damage.kinds[index - 1];
                (
                    KINDS[index - 1],
                    count_text(c.whole),
                    count_text(c.damaged),
                    colors.text,
                )
            }
            _ => {
                let c = self.damage.total();
                (
                    "All",
                    count_text(c.whole),
                    count_text(c.damaged),
                    colors.text,
                )
            }
        };
        let fonts = ui::fonts(state.dpi);
        let width = rect.right - rect.left;
        let pad = scale(state.dpi, 10);
        let cells = [
            (label, rect.left + pad, rect.left + width * 2 / 5, DT_LEFT),
            (
                whole.as_str(),
                rect.left + width * 2 / 5,
                rect.left + width * 7 / 10,
                DT_RIGHT,
            ),
            (
                damaged.as_str(),
                rect.left + width * 7 / 10,
                rect.right - pad,
                DT_RIGHT,
            ),
        ];
        for (text, left, right, align) in cells {
            let cell = RECT {
                left,
                top: rect.top,
                right,
                bottom: rect.bottom,
            };
            ui::draw_text(
                dc,
                text,
                &cell,
                fonts.body,
                color,
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | align,
            );
        }
    }

    /// The damaged pictures found with good versions, when found for the volume shown.
    fn found(&self) -> Option<&candidates::Search> {
        self.versions
            .as_ref()
            .filter(|(start, _)| Some(*start) == self.chosen)
            .map(|(_, search)| search)
    }

    /// Saves the damaged files among those selected as a text list, in a folder chosen.
    fn save_damaged(&mut self, hwnd: HWND) {
        let Some(listing) = self.listing() else {
            return;
        };
        let chosen = self.checked.iter().filter_map(|&i| listing.files.get(i));
        let mut damaged: Vec<&Found> = chosen
            .filter(|f| is_damaged(f, self.map.as_ref()))
            .collect();
        damaged.sort_by_key(|f| path_of(f).to_lowercase());
        let text = damaged_list(damaged, self.map.as_ref());
        let Some(dest) = pick_folder(
            hwnd,
            "Choose a folder on another drive for the damaged list",
        ) else {
            return;
        };
        self.notice = Some(
            match toolwin::confirm_destination(hwnd, &dest, &mut self.source_disk).and_then(|()| {
                write_text(&Guard::of(&self.source_disk), &dest, DAMAGED_LIST, &text)
            }) {
                Ok(path) => format!("The damaged files are listed in {}.", path.display()),
                Err(why) => format!("The damaged list was not saved: {why}."),
            },
        );
        self.render();
    }

    /// Looks for good versions of the damaged pictures of the volume shown, on the job thread.
    fn find_versions(&mut self) {
        let (Some(start), Some(listing)) = (self.chosen, self.listing().map(files_of)) else {
            return;
        };
        let Some(reader) = self.reader.take() else {
            return;
        };
        let map = self.map.clone().unwrap_or_else(all_rescued);
        self.notice = None;
        self.job = Some(Job::start(
            reader,
            Doing::Candidates,
            move |r, cancel, progress, _| {
                Done::Candidates(
                    start,
                    candidates::search(r, &map, &listing, cancel, progress),
                )
            },
        ));
        self.render();
    }

    /// Copies the good versions found into `repair_candidates` under a folder chosen.
    fn save_good(&mut self, hwnd: HWND) {
        let (Some(listing), Some(search)) = (self.listing().map(files_of), self.found().cloned())
        else {
            return;
        };
        if search.damaged.iter().all(|d| d.versions.is_empty()) {
            return;
        }
        let Some(dest) = pick_folder(
            hwnd,
            "Choose a folder on another drive for the good versions",
        ) else {
            return;
        };
        if let Err(why) = toolwin::confirm_destination(hwnd, &dest, &mut self.source_disk) {
            self.notice = Some(format!("{why}."));
            self.render();
            return;
        }
        let Some(reader) = self.reader.take() else {
            return;
        };
        let disk = self.source_disk.clone();
        self.notice = None;
        self.result.set(None);
        self.last_dest = None;
        self.recovering_to = Some(dest.join(CANDIDATES_FOLDER));
        self.recovering_rows = None;
        self.job = Some(Job::start(
            reader,
            Doing::Recovering,
            move |r, cancel, progress, _| {
                Done::Recovered(save_versions(
                    r, &listing, &search, &dest, &disk, cancel, progress,
                ))
            },
        ));
        self.render();
    }

    fn state_text(f: &Found) -> (String, u32) {
        let colors = ui::current();
        if f.damaged {
            return ("damaged by read errors".into(), colors.serious);
        }
        // On a lost volume a file in use may still be overwritten by what replaced it.
        if !f.deleted && f.why.is_none() {
            return ("in use".into(), colors.muted);
        }
        let color = match (f.state, &f.why) {
            (State::Overwritten, _) => colors.serious,
            // A partition now over its area, or a start without its type's marker, puts it at
            // risk, whatever its volume records.
            (State::Partly { .. }, _) | (_, Some(fs::Why::Claimed { .. } | fs::Why::Unlike(_))) => {
                colors.warn
            }
            (State::Intact, _) => colors.ok,
            (State::Unknown, _) => colors.muted,
        };
        (f.state_text(), color)
    }

    fn row_text(&self, index: usize) -> String {
        let Some(f) = self.listing().and_then(|l| l.files.get(index)) else {
            return String::new();
        };
        format!(
            "{}{}, in {}, {}, {}, {}",
            if self.checked.contains(&index) {
                "Selected: "
            } else {
                ""
            },
            f.name,
            f.folder_text(),
            bytes_text(f.size),
            f.modified.map(|m| m.text()).unwrap_or_default(),
            Self::state_text(f).0
        )
    }

    fn status(&self) -> (String, Option<u32>) {
        if let Some(failure) = &self.failure {
            return (format!("The source could not be read: {failure}."), None);
        }
        if self.opening.is_some() {
            return ("Opening the source".into(), None);
        }
        if let Some(job) = &self.job {
            let p = &job.progress;
            let found = p.found.load(Ordering::Relaxed);
            let text = match job.doing {
                Doing::Finding(Search::Tables) => "Reading the partition tables".to_string(),
                Doing::Finding(_) => format!(
                    "Searching for lost partitions: {found} volumes so far ({} s)",
                    job.seconds()
                ),
                Doing::Scanning => format!(
                    "Reading the volume's files: {} found ({} s)",
                    crate::space_view::count(found),
                    job.seconds()
                ),
                Doing::Recovering => format!(
                    "Recovering: {} written, {} of {} ({} s); {}",
                    files_text(found),
                    bytes_text(p.done.load(Ordering::Relaxed)),
                    bytes_text(p.total.load(Ordering::Relaxed)),
                    job.seconds(),
                    pace_text(&p.pace)
                ),
                Doing::Candidates => format!(
                    "Looking for good versions of the damaged pictures: {} of {} read ({} s)",
                    crate::space_view::count(p.done.load(Ordering::Relaxed)),
                    crate::space_view::count(p.total.load(Ordering::Relaxed)),
                    job.seconds()
                ),
                Doing::Thumbnails => format!(
                    "Saving Explorer's thumbnails: {} written, {} of {} read ({} s)",
                    crate::space_view::count(found),
                    bytes_text(p.done.load(Ordering::Relaxed)),
                    bytes_text(p.total.load(Ordering::Relaxed)),
                    job.seconds()
                ),
                Doing::Carving => String::new(),
            };
            let bar = (p.total.load(Ordering::Relaxed) > 0).then(|| p.permille());
            return (text, bar.or(Some(0)));
        }
        let Some(listing) = self.listing() else {
            let text = if self.volumes.is_empty() {
                "No volume was found in the partition tables. Search for lost partitions."
                    .to_string()
            } else {
                "Choose a volume to read its files.".to_string()
            };
            return (text, None);
        };
        let deleted = listing.files.iter().filter(|f| f.deleted).count();
        let mut text = format!(
            "{}, {} of them deleted. {} shown, {} selected.",
            files_text(listing.files.len() as u64),
            crate::space_view::count(deleted as u64),
            crate::space_view::count(self.view.len() as u64),
            crate::space_view::count(self.checked.len() as u64)
        );
        if self.view.len() == MAX_ROWS {
            text.push_str(" The list stops at 20,000; narrow it with the filters.");
        }
        (text, None)
    }

    /// The volume list: each volume (by start) and each partition with nothing readable,
    /// in their order on the source, then the notes on the search.
    fn volume_rows(&self) -> Vec<(Option<u64>, String)> {
        let mut rows: Vec<(u64, Option<u64>, String)> = self
            .volumes
            .iter()
            .map(|v| (v.start, Some(v.start), v.describe()))
            .chain(self.unread.iter().map(|u| (u.start, None, u.describe())))
            .collect();
        rows.sort_by_key(|r| r.0);
        rows.into_iter()
            .map(|(_, volume, text)| (volume, text))
            .chain(self.search_notes.iter().map(|n| (None, n.clone())))
            .collect()
    }

    /// Notes on the volume shown and on what was last done; notes on the search and on
    /// other partitions are in the volume list.
    fn notice_text(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        if let Some(l) = self.listing() {
            lines.extend(l.notes.iter().cloned());
        }
        lines.extend(self.notice.clone());
        lines.join(" ")
    }

    fn render(&mut self) {
        let Some(c) = self.controls else {
            return;
        };
        let busy = self.job.is_some();
        let (status, bar) = self.status();
        ui::set_text(c.status, &status);
        ui::show(c.bar, bar.is_some());
        if let Some(v) = bar {
            ui::set_value(c.bar, v);
        }
        // Stop takes a row beside the volumes only while a search runs.
        let stop_changed = ui::visible(c.stop) != busy;
        ui::show(c.stop, busy);
        for hwnd in [c.find_lost, c.find_all, c.thumbs] {
            ui::enable(hwnd, !busy && self.reader.is_some());
        }
        toggle(c.deleted, self.deleted_only);
        for (i, hwnd) in c.groups.iter().enumerate() {
            toggle(*hwnd, self.group == i);
        }
        toggle(c.keep, self.layout == Layout::Folders);
        toggle(c.by_type, self.layout == Layout::ByType);
        toggle(c.own_damaged, self.own_damaged);
        toggle(c.own_deleted, self.own_deleted);
        ui::enable(c.recover, !busy && !self.checked.is_empty());
        ui::enable(c.save_list, !busy && self.damage.total().damaged > 0);
        ui::enable(
            c.find_good,
            !busy && self.reader.is_some() && self.listing().is_some(),
        );
        let any_good = self
            .found()
            .is_some_and(|s| s.damaged.iter().any(|d| !d.versions.is_empty()));
        ui::enable(c.save_good, !busy && any_good);
        ui::set_text(c.good, &self.found().map_or_else(String::new, found_text));
        ui::show(c.open, self.last_dest.is_some());
        ui::show(c.check, self.last_dest.is_some());
        toolwin::set_empty(
            c.volumes,
            if self.reader.is_none() && self.failure.is_none() {
                "The volumes are listed here once the drive is open."
            } else {
                "No volume this tool reads was found. Search for lost partitions looks for ones whose table entry is gone."
            },
        );
        toolwin::set_empty(
            c.files,
            match self.listing() {
                Some(l) if l.files.is_empty() => {
                    "This volume holds no files this tool can recover."
                }
                Some(_) => "No file matches what is chosen above.",
                None if busy => "The files are listed here once the volume is read.",
                None => "Choose a volume to list the files it holds, deleted ones included.",
            },
        );
        let notice = self.notice_text();
        let result_changed = self.result.show(c.result);
        if notice != self.shown_notice || result_changed || stop_changed {
            ui::set_text(c.notice, &notice);
            self.shown_notice = notice;
            if let Some((hwnd, w, h, dpi)) = self.window {
                self.layout(hwnd, w, h, dpi);
                unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
            }
        }
    }

    fn toggle_file(&mut self, row: usize) {
        let Some(&index) = self.view.get(row) else {
            return;
        };
        if !self.checked.remove(&index) {
            self.checked.insert(index);
        }
        if let Some(c) = self.controls {
            replace_item(c.files, row, &self.row_text(index));
        }
        self.recount();
        self.render();
    }

    fn recover(&mut self, hwnd: HWND) {
        let Some((volume, listing)) = self.chosen.zip(self.listing()) else {
            return;
        };
        let mut indices: Vec<usize> = self.checked.iter().copied().collect();
        indices.sort_unstable();
        indices.retain(|&i| i < listing.files.len());
        let items: Vec<Item> = indices
            .iter()
            .filter_map(|&i| listing.files.get(i))
            .map(Item::from_found)
            .collect();
        if items.is_empty() {
            return;
        }
        let Some(dest) = pick_folder(
            hwnd,
            "Choose a folder on another drive for the recovered files",
        ) else {
            return;
        };
        if let Err(why) = toolwin::confirm_destination(hwnd, &dest, &mut self.source_disk) {
            self.notice = Some(format!("{why}."));
            self.render();
            return;
        }
        let Some(reader) = self.reader.take() else {
            return;
        };
        let options = recover_options(self.layout, self.own_damaged, self.own_deleted);
        let disk = self.source_disk.clone();
        self.notice = None;
        self.result.set(None);
        self.last_dest = None;
        self.recovering_to = Some(dest.clone());
        self.recovering_rows = Some((volume, indices.clone()));
        self.job = Some(Job::start(
            reader,
            Doing::Recovering,
            move |r, cancel, progress, _| {
                Done::Recovered(output::recover(
                    r, &items, &dest, &options, &disk, cancel, progress,
                ))
            },
        ));
        self.render();
    }

    /// Saves the images in Explorer's thumbnail caches on the volume shown (every volume when
    /// none is), deleted caches included, through the thumbnail cache engine.
    fn thumbnails(&mut self, hwnd: HWND) {
        let Some(dest) = pick_folder(
            hwnd,
            "Choose a folder on another drive for the thumbnails from Explorer's caches",
        ) else {
            return;
        };
        if let Err(why) = toolwin::confirm_destination(hwnd, &dest, &mut self.source_disk) {
            self.notice = Some(format!("{why}."));
            self.render();
            return;
        }
        let Some(reader) = self.reader.take() else {
            return;
        };
        let options = thumbcache::Options {
            destination: dest.clone(),
            volumes: self.chosen.into_iter().collect(),
            include_deleted: true,
            files: Vec::new(),
            source_disk: self.source_disk.clone(),
        };
        // Volumes already read are not read again: their caches are handed over.
        let scanned: Vec<(u64, Vec<Found>)> = self
            .listings
            .iter()
            .map(|(start, l)| {
                let caches = l.files.iter().filter(|f| thumbcache::is_cache(&f.name));
                (*start, caches.cloned().collect())
            })
            .collect();
        self.notice = None;
        self.result.set(None);
        self.last_dest = None;
        self.recovering_to = Some(dest);
        self.job = Some(Job::start(
            reader,
            Doing::Thumbnails,
            move |r, cancel, progress, _| {
                let mut events = |e: thumbcache::Event| {
                    if let thumbcache::Event::Progress {
                        done,
                        total,
                        images,
                    } = e
                    {
                        progress.set(done, total);
                        progress.found.store(images, Ordering::Relaxed);
                    }
                };
                Done::Thumbnails(thumbcache::run(
                    Some(r),
                    &options,
                    &scanned,
                    &mut events,
                    cancel,
                ))
            },
        ));
        self.render();
    }

    fn finished(&mut self, reader: Reader, done: Done) {
        self.reader = Some(reader);
        self.job = None;
        match done {
            Done::Thumbnails(Ok(outcome)) => {
                let dest = self.recovering_to.take();
                self.result.set(Some(&thumbnails_text(&outcome)));
                self.last_dest = outcome.folder.clone().or(dest);
                self.render();
            }
            Done::Thumbnails(Err(why)) => {
                self.recovering_to = None;
                self.notice = Some(format!("No thumbnails were saved: {why}."));
                self.render();
            }
            Done::Volumes(finds) => {
                // Keep what was already read of volumes found again.
                self.volumes = finds.volumes;
                self.unread = finds.unread;
                self.search_notes = finds.notes;
                let starts: HashSet<u64> = self.volumes.iter().map(|v| v.start).collect();
                self.listings.retain(|s, _| starts.contains(s));
                match self.chosen.filter(|s| starts.contains(s)) {
                    Some(_) => self.refilter(true),
                    None => match self.volumes.first().map(|v| v.start) {
                        Some(first) => self.scan(first),
                        None => {
                            self.chosen = None;
                            self.refilter(false);
                        }
                    },
                }
            }
            Done::Listing(start, Ok(listing)) => {
                self.listings.insert(start, listing);
                if self.chosen == Some(start) {
                    self.refilter(false);
                }
            }
            Done::Listing(_, Err(why)) => {
                self.notice = Some(format!("The volume could not be read: {why}."));
                self.refilter(false);
            }
            Done::Recovered(Ok(outcome)) => {
                // Files whose copy met unreadable areas are shown as damaged from now on.
                let dest = self.recovering_to.take();
                let rows = self.recovering_rows.take();
                if let Some((indices, listing)) = rows
                    .and_then(|(volume, indices)| Some((indices, self.listings.get_mut(&volume)?)))
                {
                    // Each written file names its own item, so a failed one shifts nothing.
                    for (w, i) in outcome
                        .ledger
                        .outputs()
                        .iter()
                        .filter_map(|w| Some((w, *indices.get(w.tag)?)))
                    {
                        if let Some(f) = listing.files.get_mut(i) {
                            f.damaged |= !w.zeroed.is_empty();
                        }
                    }
                }
                if let Some(dest) = dest {
                    self.result.set(Some(&outcome_text(&outcome, &dest)));
                    self.last_dest = Some(dest);
                }
                self.refilter(true);
            }
            Done::Recovered(Err(why)) => {
                self.notice = Some(format!("Nothing was recovered: {why}."));
                self.render();
            }
            Done::Candidates(start, search) => {
                self.versions = Some((start, search));
                self.refilter(true);
            }
            Done::Carved(_) => {}
        }
    }
}

/// Debug builds only: a reader that stands in for an opened source in the screenshots, so
/// the windows' buttons show as they do with one. Nothing reads it unless one is pressed.
#[cfg(debug_assertions)]
fn stand_in() -> Reader {
    Reader::new(Box::new(diagnostics::recovery::MemDisk::new(vec![0; 4096])))
}

#[cfg(debug_assertions)]
impl RecoverPage {
    /// Debug builds only: the window once `volumes` were found and the first one read as
    /// `listing`, with the files at `checked` selected and `versions` found for its damaged
    /// pictures, for the screenshots. Nothing is read.
    pub fn listed(
        describe: String,
        source_disk: Protected,
        volumes: Vec<Volume>,
        listing: Listing,
        checked: &[usize],
        versions: candidates::Search,
    ) -> Self {
        let mut page = Self::new_with(describe, source_disk, None);
        page.reader = Some(stand_in());
        page.chosen = volumes.first().map(|v| v.start);
        if let Some(start) = page.chosen {
            page.listings.insert(start, listing);
            page.versions = Some((start, versions));
        }
        page.volumes = volumes;
        page.checked = checked.iter().copied().collect();
        page
    }
}

impl Page for RecoverPage {
    fn title(&self) -> String {
        "Recover deleted or lost files".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::RECOVER_FILES)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((980, 900), (720, 760))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, tone, value: &str| ui::text(hwnd, kind, tone, false, value);
        let controls = RecoverControls {
            summary: toolwin::list(hwnd, SUMMARY, SUMMARY_H),
            versions: toolwin::list(hwnd, VERSIONS, SUMMARY_H),
            save_list: ui::button(hwnd, SAVE_LIST, Kind::Secondary, "Save damaged list\u{2026}"),
            find_good: ui::button(hwnd, FIND_GOOD, Kind::Secondary, "Find good versions\u{2026}"),
            save_good: ui::button(hwnd, SAVE_GOOD, Kind::Secondary, "Save good versions\u{2026}"),
            good: text(Kind::Caption, Tone::Neutral, ""),
            own_damaged: ui::button(
                hwnd,
                OWN_DAMAGED,
                Kind::Secondary,
                "Damaged files in their own folder",
            ),
            own_deleted: ui::button(
                hwnd,
                OWN_DELETED,
                Kind::Secondary,
                "Deleted files in their own folder",
            ),
            title: text(Kind::Title, Tone::Neutral, "Recover deleted or lost files"),
            description: text(
                Kind::Muted,
                Tone::Neutral,
                &format!(
                    "Reading {}. Nothing is written to it; recovered files go to a folder on another drive.",
                    self.describe
                ),
            ),
            volumes: toolwin::list(hwnd, VOLUMES, VOLUME_H),
            find_lost: ui::button(hwnd, FIND_LOST, Kind::Secondary, "Search for lost partitions"),
            find_all: ui::button(hwnd, FIND_ALL, Kind::Secondary, "Search every sector"),
            stop: ui::button(hwnd, STOP, Kind::Secondary, "Stop"),
            thumbs: ui::button(hwnd, THUMBS, Kind::Secondary, "Save Explorer thumbnails"),
            status: text(Kind::Caption, Tone::Neutral, ""),
            bar: text(Kind::Progress, Tone::Neutral, ""),
            notice: text(Kind::Muted, Tone::Warn, ""),
            result: text(Kind::Muted, Tone::Ok, ""),
            deleted: ui::button(hwnd, DELETED, Kind::Secondary, "Deleted only"),
            groups: std::array::from_fn(|i| ui::button(hwnd, GROUP + i, Kind::Ghost, GROUPS[i])),
            name: toolwin::search_box(hwnd, NAME, "Search names"),
            folder: toolwin::search_box(hwnd, FOLDER, "Search folders"),
            files: toolwin::list(hwnd, FILES, ITEM_H),
            select_all: ui::button(hwnd, SELECT_ALL, Kind::Secondary, "Select all shown"),
            clear: ui::button(hwnd, CLEAR, Kind::Secondary, "Clear selection"),
            keep: ui::button(hwnd, KEEP, Kind::Secondary, "Keep folders"),
            by_type: ui::button(hwnd, BY_TYPE, Kind::Ghost, "Group by type"),
            recover: ui::button(hwnd, RECOVER, Kind::Primary, "Recover selected"),
            open: ui::button(hwnd, OPEN, Kind::Secondary, "Open folder"),
            check: ui::button(hwnd, CHECK, Kind::Secondary, "Check recovered files"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        self.controls = Some(controls);
        self.refilter(false);
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.window = Some((hwnd, w, h, dpi));
        let Some(c) = self.controls else {
            return;
        };
        let fonts = ui::fonts(dpi);
        for control in [c.files, c.volumes, c.name, c.folder] {
            ui::set_font(control, fonts.body);
        }
        let s = |v: i32| scale(dpi, v);
        let m = s(grid::OUTER);
        let inner = w - 2 * m;
        let right = m + inner;
        let at = |x, y, w, h| Rect { x, y, w, h };
        let (bh, gap) = (s(grid::BUTTON_H), s(grid::BUTTON_GAP));
        let mut cards = Vec::new();
        let mut y = s(16);
        let title_w = inner - diagnostics::ui_layout::help_room(dpi);
        ui::place(c.title, at(m, y, title_w, s(grid::TITLE_H)));
        y += s(grid::TITLE_H) + s(4);
        let description = ui::text_height(hwnd, fonts.body, &ui::window_text(c.description), inner)
            .max(s(grid::BODY_H));
        ui::place(c.description, at(m, y, inner, description));
        y += description + s(10);

        // Volumes: a short list with the searches beside it.
        let vol_h = s(VOLUME_H) * 3 + s(16);
        let buttons_w = ui::button_width(c.find_lost, "Search for lost partitions")
            .max(ui::button_width(c.thumbs, "Save Explorer thumbnails"));
        let list_w = inner - buttons_w - s(12);
        cards.push(at(m, y, list_w, vol_h));
        ui::place(
            c.volumes,
            at(m + s(8), y + s(8), list_w - s(16), vol_h - s(16)),
        );
        let bx = m + list_w + s(12);
        ui::place(c.find_lost, at(bx, y, buttons_w, bh));
        ui::place(c.find_all, at(bx, y + bh + gap, buttons_w, bh));
        ui::place(c.thumbs, at(bx, y + 2 * (bh + gap), buttons_w, bh));
        ui::place(c.stop, at(bx, y + 3 * (bh + gap), buttons_w, bh));
        let rows = if ui::visible(c.stop) { 4 } else { 3 };
        y += vol_h.max(rows * bh + (rows - 1) * gap) + s(12);

        // Filters.
        let mut buttons: Vec<(HWND, &str)> = vec![(c.deleted, "Deleted only")];
        buttons.extend(c.groups.iter().copied().zip(GROUPS));
        y = flow(&buttons, m, right, y, bh, gap) + s(8);
        let half = (inner - s(12)) / 2;
        let edit_h = s(grid::BODY_H);
        for (i, edit) in [c.name, c.folder].into_iter().enumerate() {
            let x = m + i as i32 * (half + s(12));
            cards.push(at(x, y, half, bh));
            ui::place(
                edit,
                at(x + s(12), y + (bh - edit_h) / 2, half - s(24), edit_h),
            );
        }
        y += bh + s(8);
        ui::place(c.status, at(m, y, inner, s(grid::CAPTION_H + 2)));
        y += s(grid::CAPTION_H + 2) + s(4);
        ui::place(c.bar, at(m, y, inner, s(4)));
        y += s(4) + s(8);
        if self.shown_notice.is_empty() {
            ui::show(c.notice, false);
        } else {
            let notice = ui::text_height(hwnd, fonts.body, &self.shown_notice, inner);
            ui::place(c.notice, at(m, y, inner, notice));
            ui::show(c.notice, true);
            y += notice + s(8);
        }
        if self.result.shown.is_empty() {
            ui::show(c.result, false);
        } else {
            let result = ui::text_height(hwnd, fonts.body, &self.result.shown, inner);
            ui::place(c.result, at(m, y, inner, result));
            ui::show(c.result, true);
            y += result + s(8);
        }

        let bottom = h - m - bh;
        // From the bottom up: the options, the good-version buttons and their line, and the
        // damage table beside the versions found; the file list takes what is left.
        let options_y = bottom - bh - gap;
        let good_y = options_y - bh - gap;
        let line_h = s(grid::CAPTION_H + 2);
        let line_y = good_y - line_h - s(4);
        let table_h = s(SUMMARY_H) * 6 + s(16);
        let table_y = line_y - table_h - s(4);
        let list_h = (table_y - s(8) - y).max(s(120));
        cards.push(at(m, y, inner, list_h));
        ui::place(
            c.files,
            at(m + s(8), y + s(8), inner - s(16), list_h - s(16)),
        );
        let table_w = (inner / 2).min(s(380));
        let versions_w = inner - table_w - s(12);
        for (list, x, width) in [
            (c.summary, m, table_w),
            (c.versions, m + table_w + s(12), versions_w),
        ] {
            cards.push(at(x, table_y, width, table_h));
            ui::place(
                list,
                at(x + s(8), table_y + s(8), width - s(16), table_h - s(16)),
            );
        }
        ui::place(c.good, at(m, line_y, inner, line_h));
        ui::set_cards(hwnd, cards);

        let mut x = m;
        for (hwnd, caption) in [
            (c.save_list, "Save damaged list\u{2026}"),
            (c.find_good, "Find good versions\u{2026}"),
            (c.save_good, "Save good versions\u{2026}"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            ui::place(hwnd, at(x, good_y, bw, bh));
            x += bw + gap;
        }
        let mut x = m;
        for (hwnd, caption) in [
            (c.own_damaged, "Damaged files in their own folder"),
            (c.own_deleted, "Deleted files in their own folder"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            ui::place(hwnd, at(x, options_y, bw, bh));
            x += bw + gap;
        }

        let mut x = m;
        for (hwnd, caption) in [
            (c.select_all, "Select all shown"),
            (c.clear, "Clear selection"),
            (c.keep, "Keep folders"),
            (c.by_type, "Group by type"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            ui::place(hwnd, at(x, bottom, bw, bh));
            x += bw + gap;
        }
        let mut x = right;
        for (hwnd, caption) in [
            (c.close, "Close"),
            (c.recover, "Recover selected"),
            (c.open, "Open folder"),
            (c.check, "Check recovered files"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            x -= bw;
            ui::place(hwnd, at(x, bottom, bw, bh));
            x -= gap;
        }
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        match id {
            FIND_LOST => self.find(Search::Aligned),
            FIND_ALL => self.find(Search::Every),
            STOP => {
                if let Some(job) = &self.job {
                    job.cancel.store(true, Ordering::Relaxed);
                }
            }
            DELETED => {
                self.deleted_only = !self.deleted_only;
                self.refilter(false);
            }
            _ if (GROUP..GROUP + GROUPS.len()).contains(&id) => {
                self.group = id - GROUP;
                self.refilter(false);
            }
            NAME | FOLDER if code == EN_CHANGE => {
                if let Some(c) = self.controls {
                    self.name = ui::window_text(c.name);
                    self.folder = ui::window_text(c.folder);
                }
                self.refilter(false);
            }
            VOLUMES if code == toolwin::ACTIVATE => {
                let row = self.controls.and_then(|c| toolwin::selected(c.volumes));
                if let Some(start) = row.and_then(|r| self.volume_rows().get(r)?.0) {
                    if self.chosen != Some(start) {
                        self.scan(start);
                    }
                }
            }
            FILES if code == toolwin::ACTIVATE => {
                if let Some(row) = self.controls.and_then(|c| toolwin::selected(c.files)) {
                    self.toggle_file(row);
                }
            }
            SELECT_ALL => {
                self.checked.extend(self.view.iter().copied());
                self.refilter(true);
            }
            CLEAR => {
                self.checked.clear();
                self.refilter(true);
            }
            KEEP => {
                self.layout = Layout::Folders;
                self.render();
            }
            BY_TYPE => {
                self.layout = Layout::ByType;
                self.render();
            }
            OWN_DAMAGED => {
                self.own_damaged = !self.own_damaged;
                self.render();
            }
            OWN_DELETED => {
                self.own_deleted = !self.own_deleted;
                self.render();
            }
            SAVE_LIST => self.save_damaged(hwnd),
            FIND_GOOD => self.find_versions(),
            SAVE_GOOD => self.save_good(hwnd),
            RECOVER => self.recover(hwnd),
            THUMBS => self.thumbnails(hwnd),
            OPEN => {
                if let Some(dest) = &self.last_dest {
                    if !toolwin::open_path(hwnd, dest) {
                        self.notice = Some("Windows could not open the folder.".into());
                        self.render();
                    }
                }
            }
            CHECK => {
                if let Some(dest) = &self.last_dest {
                    verify_view::open(hwnd, Some(dest.clone()), self.source_disk.clone());
                }
            }
            CLOSE => unsafe {
                DestroyWindow(hwnd);
            },
            _ => {}
        }
        None
    }

    fn tick(&mut self, _hwnd: HWND) {
        self.take_opened();
        let received = self.job.as_ref().map(|job| job.result.try_recv());
        match received {
            Some(Ok((reader, done))) => self.finished(reader, done),
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.job = None;
                self.failure = Some("the reading stopped unexpectedly".into());
                self.render();
            }
            _ => self.render(),
        }
    }

    fn draw_item(&self, list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        if list == VOLUMES {
            let Some((volume, text)) = self.volume_rows().into_iter().nth(index) else {
                return;
            };
            ui::fill_rect(dc, rect, colors.card);
            let chosen = volume.is_some() && self.chosen == volume;
            let fonts = ui::fonts(state.dpi);
            let s = |x: i32| scale(state.dpi, x);
            if let Some(canvas) = ui::Canvas::new(dc) {
                if chosen || (state.hot && volume.is_some()) {
                    canvas.fill_round(
                        (
                            rect.left as f32,
                            (rect.top + s(1)) as f32,
                            (rect.right - rect.left) as f32,
                            (rect.bottom - rect.top - s(2)) as f32,
                        ),
                        s(6) as f32,
                        if chosen {
                            colors.raised_hover
                        } else {
                            colors.raised
                        },
                    );
                }
            }
            let line = RECT {
                left: rect.left + s(10),
                top: rect.top,
                right: rect.right - s(10),
                bottom: rect.bottom,
            };
            let scanned = match volume {
                Some(start) if self.listings.contains_key(&start) => "  ·  read",
                _ => "",
            };
            ui::draw_text(
                dc,
                &format!("{text}{scanned}"),
                &line,
                fonts.body,
                if volume.is_some() {
                    colors.text
                } else {
                    colors.muted
                },
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_LEFT,
            );
            return;
        }
        if list == SUMMARY {
            self.draw_summary(index, dc, rect, state);
            return;
        }
        if list == VERSIONS {
            let Some(d) = self.found().and_then(|s| s.damaged.get(index)) else {
                ui::fill_rect(dc, rect, colors.card);
                return;
            };
            ui::fill_rect(dc, rect, colors.card);
            let s = |x: i32| scale(state.dpi, x);
            let wide_w = (rect.right - rect.left) * 6 / 10;
            let cell = |left: i32, right: i32| RECT {
                left,
                top: rect.top,
                right,
                bottom: rect.bottom,
            };
            let fonts = ui::fonts(state.dpi);
            ui::draw_text(
                dc,
                &d.path,
                &cell(rect.left + s(10), rect.left + wide_w - s(8)),
                fonts.body,
                colors.text,
                DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS | DT_LEFT,
            );
            ui::draw_text(
                dc,
                &versions_text(d),
                &cell(rect.left + wide_w, rect.right - s(10)),
                fonts.body,
                colors.muted,
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_LEFT,
            );
            return;
        }
        let Some(f) = self
            .view
            .get(index)
            .and_then(|&i| Some((i, self.listing()?.files.get(i)?)))
        else {
            ui::fill_rect(dc, rect, colors.card);
            return;
        };
        let (i, f) = f;
        let (state_text, state_color) = Self::state_text(f);
        let modified = f.modified.map(|m| m.text()).unwrap_or_default();
        draw_row(
            dc,
            rect,
            state,
            self.checked.contains(&i),
            &f.name,
            &f.folder_text(),
            &[
                (&bytes_text(f.size), 72, colors.muted),
                (&modified, 116, colors.muted),
            ],
            (&state_text, state_color),
        );
    }
}

// ---- find files by type -------------------------------------------------------------------

#[derive(Clone, Copy)]
struct TypeControls {
    title: HWND,
    description: HWND,
    types: [HWND; 11],
    start: HWND,
    status: HWND,
    bar: HWND,
    counts: HWND,
    notice: HWND,
    result: HWND,
    list: HWND,
    select_all: HWND,
    clear: HWND,
    recover: HWND,
    open: HWND,
    check: HWND,
    close: HWND,
}

pub struct TypePage {
    source_disk: diagnostics::recovery::dest::Protected,
    describe: String,
    /// The source while it opens, off the window's thread and with a time limit.
    opening: Option<Opening>,
    reader: Option<Reader>,
    job: Option<Job>,
    found_rx: Option<mpsc::Receiver<Carved>>,
    failure: Option<String>,
    kinds: [bool; 11],
    found: Vec<Carved>,
    checked: HashSet<usize>,
    /// How the last search ended, once it has.
    searched: Option<Searched>,
    /// Finds already in the list.
    shown: usize,
    notice: Option<String>,
    last_dest: Option<PathBuf>,
    recovering_to: Option<PathBuf>,
    /// The list rows being recovered, in the order of the items handed to `recover`.
    recovering_rows: Vec<usize>,
    controls: Option<TypeControls>,
    window: Option<(HWND, i32, i32, u32)>,
    shown_notice: String,
    /// The last recovery's outcome, on its own line in its own tone.
    result: Result_,
}

impl Drop for TypePage {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }
}

impl TypePage {
    fn new(source: SourceChoice) -> Self {
        let source_disk = output::source_disk(&source);
        let describe = source.label();
        Self::new_with(
            describe,
            source_disk,
            Some(timed::open_in_background(source)),
        )
    }

    fn new_with(describe: String, source_disk: Protected, opening: Option<Opening>) -> Self {
        Self {
            source_disk,
            describe,
            opening,
            reader: None,
            job: None,
            found_rx: None,
            failure: None,
            kinds: [true; 11],
            found: Vec::new(),
            checked: HashSet::new(),
            searched: None,
            shown: 0,
            notice: None,
            last_dest: None,
            recovering_to: None,
            recovering_rows: Vec::new(),
            controls: None,
            window: None,
            shown_notice: String::new(),
            result: Result_::default(),
        }
    }

    /// Takes the source once it has opened.
    fn take_opened(&mut self) {
        let Some(result) = self.opening.as_ref().and_then(opened) else {
            return;
        };
        self.opening = None;
        match result {
            Ok(reader) => {
                self.describe = reader.describe();
                // The source as it opened says what it protects.
                self.source_disk = reader.protected();
                self.reader = Some(reader);
                if let Some(c) = &self.controls {
                    ui::set_text(
                        c.description,
                        &format!(
                            "Reading {}. Files are found by their own contents, so this works where the file system is gone; their names and folders are not known.",
                            self.describe
                        ),
                    );
                }
                // The description now names the source, and may take more lines.
                if let Some((hwnd, w, h, dpi)) = self.window {
                    self.layout(hwnd, w, h, dpi);
                    unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
                }
            }
            Err(why) => self.failure = Some(why),
        }
    }

    fn start(&mut self) {
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
            return;
        }
        let kinds: Vec<CarveKind> = CarveKind::ALL
            .into_iter()
            .filter(|k| self.kinds[k.index()])
            .collect();
        if kinds.is_empty() {
            self.notice = Some("Choose at least one type.".into());
            self.render();
            return;
        }
        let Some(reader) = self.reader.take() else {
            return;
        };
        self.found.clear();
        self.checked.clear();
        self.notice = None;
        self.searched = None;
        let (sender, rx) = mpsc::channel();
        self.found_rx = Some(rx);
        self.job = Some(Job::start(
            reader,
            Doing::Carving,
            move |r, cancel, _, progress| {
                let carving = carve::carve(r, &kinds, cancel, progress, &mut |c| {
                    let _ = sender.send(c);
                });
                Done::Carved(carving.notes())
            },
        ));
        self.refresh(false);
    }

    fn row_text(&self, i: usize) -> String {
        let Some(c) = self.found.get(i) else {
            return String::new();
        };
        format!(
            "{}{}, {}, {}, at byte {}{}",
            if self.checked.contains(&i) {
                "Selected: "
            } else {
                ""
            },
            c.name(),
            c.kind.label(),
            bytes_text(c.len),
            c.offset,
            if c.damaged {
                ", damaged by read errors"
            } else {
                ""
            }
        )
    }

    fn refresh(&mut self, keep: bool) {
        if let Some(c) = self.controls {
            let texts: Vec<String> = (0..self.found.len().min(MAX_ROWS))
                .map(|i| self.row_text(i))
                .collect();
            let selected = toolwin::selected(c.list);
            self.shown = texts.len();
            toolwin::set_items(c.list, &texts, keep);
            if keep {
                toolwin::select(c.list, selected);
            }
        }
        self.render();
    }

    fn counts_text(&self) -> String {
        let counts: Vec<String> = CarveKind::ALL
            .into_iter()
            .filter(|k| self.kinds[k.index()])
            .map(|k| {
                let n = self.found.iter().filter(|c| c.kind == k).count();
                format!("{} {n}", k.label())
            })
            .collect();
        counts.join("  ·  ")
    }

    fn status(&self) -> (String, Option<u32>) {
        if let Some(failure) = &self.failure {
            return (format!("The source could not be read: {failure}."), None);
        }
        if self.opening.is_some() {
            return ("Opening the source".into(), None);
        }
        match &self.job {
            Some(job) if job.doing == Doing::Carving => {
                let p = &job.carve;
                let (done, total) = (
                    p.done.load(Ordering::Relaxed),
                    p.total.load(Ordering::Relaxed).max(1),
                );
                (
                    format!(
                        "Searching: {} of {} read, {} found ({} s)",
                        bytes_text(done),
                        bytes_text(total),
                        files_text(self.found.len() as u64),
                        job.seconds()
                    ),
                    Some((done as u128 * 1000 / total as u128) as u32),
                )
            }
            Some(job) => {
                let p = &job.progress;
                (
                    format!(
                        "Recovering: {} written, {} of {} ({} s)",
                        files_text(p.found.load(Ordering::Relaxed)),
                        bytes_text(p.done.load(Ordering::Relaxed)),
                        bytes_text(p.total.load(Ordering::Relaxed)),
                        job.seconds()
                    ),
                    Some(p.permille()),
                )
            }
            None if self.searched.is_some() => (
                self.searched.as_ref().map_or_else(String::new, |s| {
                    searched_text(s, self.found.len() as u64, self.checked.len() as u64)
                }),
                None,
            ),
            None => (
                "Choose the types to look for, then Start. The whole source is read, every sector."
                    .into(),
                None,
            ),
        }
    }

    fn render(&mut self) {
        let Some(c) = self.controls else {
            return;
        };
        let busy = self.job.is_some();
        let carving = self.job.as_ref().is_some_and(|j| j.doing == Doing::Carving);
        let (status, bar) = self.status();
        ui::set_text(c.status, &status);
        ui::show(c.bar, bar.is_some());
        if let Some(v) = bar {
            ui::set_value(c.bar, v);
        }
        ui::set_text(c.counts, &self.counts_text());
        ui::set_text(c.start, if carving { "Stop" } else { "Start" });
        ui::enable(c.start, carving || (!busy && self.reader.is_some()));
        for (k, hwnd) in CarveKind::ALL.into_iter().zip(c.types) {
            toggle(hwnd, self.kinds[k.index()]);
            ui::enable(hwnd, !busy);
        }
        ui::enable(c.recover, !busy && !self.checked.is_empty());
        ui::show(c.open, self.last_dest.is_some());
        ui::show(c.check, self.last_dest.is_some());
        toolwin::set_empty(
            c.list,
            if carving {
                "Files are listed here as they are found."
            } else if self.searched.is_some() {
                "No file of the chosen types was found."
            } else {
                "The files found are listed here with their type, their size and where each starts."
            },
        );
        let notice = self.notice.clone().unwrap_or_default();
        let result_changed = self.result.show(c.result);
        if notice != self.shown_notice || result_changed {
            ui::set_text(c.notice, &notice);
            self.shown_notice = notice;
            if let Some((hwnd, w, h, dpi)) = self.window {
                self.layout(hwnd, w, h, dpi);
                unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
            }
        }
    }

    fn recover(&mut self, hwnd: HWND) {
        let mut indices: Vec<usize> = self.checked.iter().copied().collect();
        indices.sort_unstable();
        indices.retain(|&i| i < self.found.len());
        let items: Vec<Item> = indices
            .iter()
            .filter_map(|&i| self.found.get(i))
            .map(Item::from_carved)
            .collect();
        if items.is_empty() {
            return;
        }
        let Some(dest) = pick_folder(
            hwnd,
            "Choose a folder on another drive for the recovered files",
        ) else {
            return;
        };
        if let Err(why) = toolwin::confirm_destination(hwnd, &dest, &mut self.source_disk) {
            self.notice = Some(format!("{why}."));
            self.render();
            return;
        }
        let Some(reader) = self.reader.take() else {
            return;
        };
        let disk = self.source_disk.clone();
        self.recovering_to = Some(dest.clone());
        self.recovering_rows = indices.clone();
        self.notice = None;
        self.result.set(None);
        self.last_dest = None;
        self.job = Some(Job::start(
            reader,
            Doing::Recovering,
            move |r, cancel, progress, _| {
                Done::Recovered(output::recover(
                    r,
                    &items,
                    &dest,
                    &output::RecoverOptions {
                        layout: Layout::ByType,
                        ..output::RecoverOptions::default()
                    },
                    &disk,
                    cancel,
                    progress,
                ))
            },
        ));
        self.render();
    }
}

#[cfg(debug_assertions)]
impl TypePage {
    /// Debug builds only: the window once a search of `total` bytes read `read` of them in
    /// `seconds` and found `found`, with the finds at `checked` selected, for the
    /// screenshots. Nothing is read.
    pub fn after_search(
        describe: String,
        source_disk: Protected,
        found: Vec<Carved>,
        checked: &[usize],
        (read, total, seconds): (u64, u64, u64),
        unreadable: (usize, u64),
    ) -> Self {
        let mut page = Self::new_with(describe, source_disk, None);
        page.reader = Some(stand_in());
        page.found = found;
        page.checked = checked.iter().copied().collect();
        page.searched = Some(Searched {
            read,
            total,
            seconds,
            stopped: read < total,
            unreadable,
        });
        page
    }
}

impl Page for TypePage {
    fn title(&self) -> String {
        "Find files by type".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::FILES_BY_TYPE)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((900, 760), (660, 560))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, tone, value: &str| ui::text(hwnd, kind, tone, false, value);
        let controls = TypeControls {
            title: text(Kind::Title, Tone::Neutral, "Find files by type"),
            description: text(
                Kind::Muted,
                Tone::Neutral,
                &format!(
                    "Reading {}. Files are found by their own contents, so this works where the file system is gone; their names and folders are not known.",
                    self.describe
                ),
            ),
            types: std::array::from_fn(|i| {
                ui::button(hwnd, TYPES + i, Kind::Secondary, CarveKind::ALL[i].label())
            }),
            start: ui::button(hwnd, START, Kind::Primary, "Start"),
            status: text(Kind::Caption, Tone::Neutral, ""),
            bar: text(Kind::Progress, Tone::Neutral, ""),
            counts: text(Kind::Caption, Tone::Neutral, ""),
            notice: text(Kind::Muted, Tone::Warn, ""),
            result: text(Kind::Muted, Tone::Ok, ""),
            list: toolwin::list(hwnd, CARVED, ITEM_H),
            select_all: ui::button(hwnd, SELECT_ALL, Kind::Secondary, "Select all"),
            clear: ui::button(hwnd, CLEAR, Kind::Secondary, "Clear selection"),
            recover: ui::button(hwnd, RECOVER, Kind::Primary, "Recover selected"),
            open: ui::button(hwnd, OPEN, Kind::Secondary, "Open folder"),
            check: ui::button(hwnd, CHECK, Kind::Secondary, "Check recovered files"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        self.controls = Some(controls);
        self.refresh(false);
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.window = Some((hwnd, w, h, dpi));
        let Some(c) = self.controls else {
            return;
        };
        let fonts = ui::fonts(dpi);
        ui::set_font(c.list, fonts.body);
        let s = |v: i32| scale(dpi, v);
        let m = s(grid::OUTER);
        let inner = w - 2 * m;
        let right = m + inner;
        let at = |x, y, w, h| Rect { x, y, w, h };
        let (bh, gap) = (s(grid::BUTTON_H), s(grid::BUTTON_GAP));
        let mut y = s(16);
        let title_w = inner - diagnostics::ui_layout::help_room(dpi);
        ui::place(c.title, at(m, y, title_w, s(grid::TITLE_H)));
        y += s(grid::TITLE_H) + s(4);
        let description = ui::text_height(hwnd, fonts.body, &ui::window_text(c.description), inner)
            .max(s(grid::BODY_H));
        ui::place(c.description, at(m, y, inner, description));
        y += description + s(12);
        let mut buttons: Vec<(HWND, &str)> = c
            .types
            .iter()
            .copied()
            .zip(CarveKind::ALL.map(|k| k.label()))
            .collect();
        buttons.push((c.start, "Start"));
        y = flow(&buttons, m, right, y, bh, gap) + s(10);
        ui::place(c.status, at(m, y, inner, s(grid::CAPTION_H + 2)));
        y += s(grid::CAPTION_H + 2) + s(4);
        ui::place(c.bar, at(m, y, inner, s(4)));
        y += s(4) + s(8);
        let counts = ui::text_height(hwnd, fonts.caption, &self.counts_text(), inner)
            .max(s(grid::CAPTION_H + 2));
        ui::place(c.counts, at(m, y, inner, counts));
        y += counts + s(8);
        if self.shown_notice.is_empty() {
            ui::show(c.notice, false);
        } else {
            let notice = ui::text_height(hwnd, fonts.body, &self.shown_notice, inner);
            ui::place(c.notice, at(m, y, inner, notice));
            ui::show(c.notice, true);
            y += notice + s(8);
        }
        if self.result.shown.is_empty() {
            ui::show(c.result, false);
        } else {
            let result = ui::text_height(hwnd, fonts.body, &self.result.shown, inner);
            ui::place(c.result, at(m, y, inner, result));
            ui::show(c.result, true);
            y += result + s(8);
        }
        let bottom = h - m - bh;
        let list_h = (bottom - s(16) - y).max(s(120));
        ui::set_cards(hwnd, vec![at(m, y, inner, list_h)]);
        ui::place(
            c.list,
            at(m + s(8), y + s(8), inner - s(16), list_h - s(16)),
        );
        let mut x = m;
        for (hwnd, caption) in [(c.select_all, "Select all"), (c.clear, "Clear selection")] {
            let bw = ui::button_width(hwnd, caption);
            ui::place(hwnd, at(x, bottom, bw, bh));
            x += bw + gap;
        }
        let mut x = right;
        for (hwnd, caption) in [
            (c.close, "Close"),
            (c.recover, "Recover selected"),
            (c.open, "Open folder"),
            (c.check, "Check recovered files"),
        ] {
            let bw = ui::button_width(hwnd, caption);
            x -= bw;
            ui::place(hwnd, at(x, bottom, bw, bh));
            x -= gap;
        }
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        match id {
            _ if (TYPES..TYPES + CarveKind::ALL.len()).contains(&id) => {
                self.kinds[id - TYPES] = !self.kinds[id - TYPES];
                self.render();
            }
            START => self.start(),
            CARVED if code == toolwin::ACTIVATE => {
                if let Some((c, row)) = self
                    .controls
                    .and_then(|c| Some((c, toolwin::selected(c.list)?)))
                {
                    if !self.checked.remove(&row) {
                        self.checked.insert(row);
                    }
                    replace_item(c.list, row, &self.row_text(row));
                    self.render();
                }
            }
            SELECT_ALL => {
                self.checked.extend(0..self.found.len().min(MAX_ROWS));
                self.refresh(true);
            }
            CLEAR => {
                self.checked.clear();
                self.refresh(true);
            }
            RECOVER => self.recover(hwnd),
            OPEN => {
                if let Some(dest) = &self.last_dest {
                    if !toolwin::open_path(hwnd, dest) {
                        self.notice = Some("Windows could not open the folder.".into());
                        self.render();
                    }
                }
            }
            CHECK => {
                if let Some(dest) = &self.last_dest {
                    verify_view::open(hwnd, Some(dest.clone()), self.source_disk.clone());
                }
            }
            CLOSE => unsafe {
                DestroyWindow(hwnd);
            },
            _ => {}
        }
        None
    }

    fn tick(&mut self, _hwnd: HWND) {
        self.take_opened();
        let mut more = false;
        if let Some(rx) = &self.found_rx {
            while let Ok(c) = rx.try_recv() {
                self.found.push(c);
                more = true;
            }
        }
        let received = self.job.as_ref().map(|job| job.result.try_recv());
        match received {
            Some(Ok((reader, done))) => {
                let job = self.job.take();
                if let Some(job) = job.filter(|j| j.doing == Doing::Carving) {
                    if let Some(rx) = self.found_rx.take() {
                        self.found.extend(rx.try_iter());
                    }
                    let stopped = job.cancel.load(Ordering::Relaxed) || reader.gone().is_some();
                    self.searched =
                        Some(Searched::new(&job.carve, job.seconds(), stopped, &reader));
                    let mut said = Vec::new();
                    if let Some(why) = reader.gone() {
                        said.push(format!("The search stopped: {why}."));
                    }
                    // The limits the search reached are said, never left out silently.
                    if let Done::Carved(notes) = &done {
                        said.extend(notes.iter().cloned());
                    }
                    if !said.is_empty() {
                        self.notice = Some(said.join(" "));
                    }
                }
                self.reader = Some(reader);
                if let Done::Recovered(result) = done {
                    let dest = self.recovering_to.take();
                    match (result, dest) {
                        (Ok(outcome), Some(dest)) => {
                            let indices = std::mem::take(&mut self.recovering_rows);
                            for (w, i) in outcome
                                .ledger
                                .outputs()
                                .iter()
                                .filter_map(|w| Some((w, *indices.get(w.tag)?)))
                            {
                                if !w.zeroed.is_empty() {
                                    if let Some(c) = self.found.get_mut(i) {
                                        c.damaged = true;
                                    }
                                }
                            }
                            self.result.set(Some(&outcome_text(&outcome, &dest)));
                            self.last_dest = Some(dest);
                        }
                        (Err(why), _) => {
                            self.notice = Some(format!("Nothing was recovered: {why}."))
                        }
                        (Ok(_), None) => {}
                    }
                }
                self.refresh(true);
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.job = None;
                self.failure = Some("the reading stopped unexpectedly".into());
                self.render();
            }
            _ if more => {
                // New finds are added to the end; the rest of the list stays as it is.
                if let Some(c) = self.controls {
                    let end = self.found.len().min(MAX_ROWS);
                    let texts: Vec<String> = (self.shown.min(end)..end)
                        .map(|i| self.row_text(i))
                        .collect();
                    add_items(c.list, &texts);
                    self.shown = end;
                }
                self.render();
            }
            _ => self.render(),
        }
    }

    fn draw_item(&self, _list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let colors = ui::current();
        let Some(c) = self.found.get(index) else {
            ui::fill_rect(dc, rect, colors.card);
            return;
        };
        let (end, color) = if c.damaged {
            ("damaged by read errors".to_string(), colors.serious)
        } else {
            (format!("at {}", bytes_text(c.offset)), colors.muted)
        };
        draw_row(
            dc,
            rect,
            state,
            self.checked.contains(&index),
            &c.name(),
            c.kind.label(),
            &[(&bytes_text(c.len), 72, colors.muted)],
            (&end, color),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::recovery::fs::Data;
    use diagnostics::recovery::MemDisk;

    /// The guard: a search by type ends on a line that says it finished, how much it read
    /// in what time and what could not be read, or that it was stopped and how far it got.
    #[test]
    fn a_search_by_type_ends_on_a_line_that_says_how_it_ended() {
        let search = |disk: MemDisk, stop: bool, seconds: u64| {
            let mut reader = Reader::new(Box::new(disk));
            let progress = carve::Progress::default();
            let cancel = AtomicBool::new(stop);
            carve::carve(
                &mut reader,
                &CarveKind::ALL,
                &cancel,
                &progress,
                &mut |_| {},
            );
            Searched::new(&progress, seconds, stop, &reader)
        };
        let mut disk = MemDisk::new(vec![0; 4 << 20]);
        disk.bad.push(1 << 20..(1 << 20) + 4096);
        assert_eq!(
            searched_text(&search(disk, false, 41), 43, 0),
            "Finished: read 4.2 MB in 41 s, 1 unreadable area (4.1 kB) skipped; 43 files found, 0 selected."
        );
        assert_eq!(
            searched_text(&search(MemDisk::new(vec![0; 4 << 20]), false, 75), 1, 1),
            "Finished: read 4.2 MB in 1 min 15 s; 1 file found, 1 selected."
        );
        assert_eq!(
            searched_text(&search(MemDisk::new(vec![0; 4 << 20]), true, 9), 0, 0),
            "Stopped after reading 0 B of 4.2 MB in 9 s; 0 files found, 0 selected."
        );
    }

    /// The guard: a partition with nothing readable is a row of the volume list, by its
    /// place on the source, and never a notice that stays whichever volume is chosen.
    #[test]
    fn a_partition_note_is_a_volume_row_not_a_notice() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/recovery/mbr.img");
        let mut image = std::fs::read(fixture).unwrap();
        // Partition 2: one sector inside the lost NTFS volume at 2 MiB, with no boot sector.
        let entry = &mut image[446 + 16..462 + 16];
        entry[4] = 0x83;
        entry[8..12].copy_from_slice(&6662u32.to_le_bytes());
        entry[12..16].copy_from_slice(&1u32.to_le_bytes());
        let mut reader = Reader::new(Box::new(MemDisk::new(image)));
        let finds = parts::find(
            &mut reader,
            Search::Aligned,
            &AtomicBool::new(false),
            &Progress::default(),
        );
        let mut page = RecoverPage::new(SourceChoice::Image(PathBuf::from(
            r"\\?\nowhere\diagtool-no-such.img",
        )));
        page.finished(reader, Done::Volumes(finds));
        let rows: Vec<String> = page.volume_rows().into_iter().map(|r| r.1).collect();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert!(rows[0].starts_with("Partition 1, FAT12"), "{rows:?}");
        assert!(rows[1].starts_with("Lost NTFS volume"), "{rows:?}");
        assert_eq!(
            rows[2],
            "Partition 2, 512 B at 3.4 MB: no file system this tool reads"
        );
        assert_eq!(
            page.volume_rows()[2].0,
            None,
            "the note row is not a volume"
        );
        for chosen in [1 << 20, 2 << 20] {
            page.chosen = Some(chosen);
            assert!(
                !page.notice_text().contains("file system"),
                "{}",
                page.notice_text()
            );
        }
    }

    fn found(name: &str) -> Found {
        Found {
            name: name.into(),
            folder: Vec::new(),
            size: 10,
            modified: None,
            deleted: true,
            state: State::Intact,
            data: Data::Resident(vec![0; 10]),
            damaged: false,
            note: None,
            why: None,
        }
    }

    /// The guard: a recovery's results mark the volume it read, even when another volume is
    /// shown by the time it ends.
    #[test]
    fn results_mark_the_volume_recovered_from() {
        let mut page = RecoverPage::new(SourceChoice::Image(PathBuf::from(
            r"\\?\nowhere\diagtool-no-such.img",
        )));
        for start in [0, 100] {
            page.listings.insert(
                start,
                Listing {
                    files: vec![found("a"), found("b")],
                    notes: Vec::new(),
                    limit: None,
                },
            );
        }
        page.chosen = Some(0);
        page.checked.insert(1);
        page.recovering_rows = Some((0, vec![1]));
        // The person looks at the other volume while the copy runs.
        page.chosen = Some(100);
        let mut outcome = Outcome::default();
        let id = outcome
            .ledger
            .made(0, "b".into(), "b".into(), "intact".into(), 10);
        outcome.ledger.zeroed(id, std::iter::once(0..5).collect());
        outcome.ledger.whole(id);
        let reader = Reader::new(Box::new(MemDisk::new(vec![0; 4096])));
        page.finished(reader, Done::Recovered(Ok(outcome)));
        let damaged = |start: u64| -> Vec<bool> {
            page.listings[&start]
                .files
                .iter()
                .map(|f| f.damaged)
                .collect()
        };
        assert_eq!(damaged(0), [false, true]);
        assert_eq!(damaged(100), [false, false]);
    }

    /// The guard: a report that could not be written to its end is said so, as a warning.
    #[test]
    fn a_report_cut_short_is_shown_as_such() {
        let dest = std::path::Path::new(r"E:\Recovered");
        let mut outcome = Outcome {
            report: Some(dest.join("Recovery report.txt")),
            report_error: Some("the destination is full".into()),
            ..Outcome::default()
        };
        let a = outcome
            .ledger
            .made(0, dest.join("a"), "a".into(), String::new(), 10);
        outcome.ledger.whole(a);
        let (text, tone) = outcome_text(&outcome, dest);
        assert!(
            text.contains(
                "Recovery report.txt could not be written in full (the destination is full)"
            ),
            "{text}"
        );
        assert_eq!(tone, Tone::Warn);
    }

    /// The guard: a recovery's result has its own line and tone: one whole file reads as
    /// done, in the singular; a damaged one as a warning. A volume note never colours it.
    #[test]
    fn the_thumbnail_result_says_what_was_saved_and_where() {
        let none = thumbcache::Outcome {
            notes: vec!["No Explorer thumbnail cache (thumbcache_*.db) was found.".into()],
            ..thumbcache::Outcome::default()
        };
        let (text, tone) = thumbnails_text(&none);
        assert!(text.starts_with("No Explorer thumbnail cache"), "{text}");
        assert!(tone == Tone::Warn);
        let saved = thumbcache::Outcome {
            folder: Some(PathBuf::from(r"E:\out\Thumbnails 2026-11-06")),
            caches: vec![thumbcache::CacheResult {
                images: 3,
                partial: 1,
                ..thumbcache::CacheResult::default()
            }],
            report: Some(PathBuf::from(
                r"E:\out\Thumbnails 2026-11-06\Thumbnail report.txt",
            )),
            ..thumbcache::Outcome::default()
        };
        let (text, tone) = thumbnails_text(&saved);
        assert_eq!(
            text,
            "Saved 3 files from 1 Explorer thumbnail cache to E:\\out\\Thumbnails 2026-11-06. 1 more had unreadable parts, written as zeros and named \"(partial)\". The report is in Thumbnail report.txt there."
        );
        assert!(tone == Tone::Warn);
    }

    #[test]
    fn the_result_line_has_its_own_tone() {
        let dest = std::path::Path::new(r"E:\Recovered");
        let mut outcome = Outcome {
            report: Some(dest.join("Recovery report.txt")),
            log: Some(dest.join(output::LOG_NAME)),
            ..Outcome::default()
        };
        let a = outcome
            .ledger
            .made(0, dest.join("a"), "a".into(), String::new(), 10);
        outcome.ledger.whole(a);
        let (text, tone) = outcome_text(&outcome, dest);
        assert!(
            text.starts_with(r"Recovered 1 file to E:\Recovered."),
            "{text}"
        );
        assert_eq!(tone, Tone::Ok);
        let b = outcome
            .ledger
            .made(1, dest.join("b"), "b".into(), String::new(), 10);
        outcome.ledger.zeroed(b, std::iter::once(0..5).collect());
        outcome.ledger.whole(b);
        let (text, tone) = outcome_text(&outcome, dest);
        assert!(text.starts_with("Recovered 2 files"), "{text}");
        assert_eq!(tone, Tone::Warn);
        let mut page = RecoverPage::new(SourceChoice::Image(PathBuf::from(
            r"\\?\nowhere\diagtool-no-such.img",
        )));
        page.search_notes = vec!["The search was stopped before the end.".into()];
        page.result.set(Some(&outcome_text(&outcome, dest)));
        assert!(
            !page.notice_text().contains("Recovered"),
            "the result shares the notice"
        );
    }

    /// A file of `size` bytes whose one run lies at `at` on the source.
    fn placed(folder: &str, name: &str, at: u64, size: u64) -> Found {
        use diagnostics::recovery::fs::{Part, Place, Run};
        Found {
            folder: folder
                .split('\\')
                .filter(|p| !p.is_empty())
                .map(|p| Part {
                    name: p.into(),
                    deleted: false,
                })
                .collect(),
            size,
            data: Data::Runs(vec![Run {
                place: Place::At(at),
                len: size,
            }]),
            deleted: false,
            ..found(name)
        }
    }

    /// A map of `len` bytes, all rescued but the `bad` ranges.
    fn map_of(len: u64, bad: impl IntoIterator<Item = Range<u64>>) -> Map {
        let mut map = Map::new(len);
        map.set(0, len, Status::Rescued);
        for b in bad {
            map.set(b.start, b.end - b.start, Status::Bad);
        }
        map
    }

    /// The guard: the table before copying counts a file whole only when every byte of it
    /// was rescued, by kind. A file with one unread byte, one over a part the volume cannot
    /// place and one whose record is damaged are damaged; a source with no map has read all.
    #[test]
    fn the_damage_summary_counts_files_by_kind_from_the_map() {
        use diagnostics::recovery::fs::{Place, Run};
        let files = vec![
            placed("\\DCIM", "whole.jpg", 0, 1000),
            placed("\\DCIM", "cut.jpg", 1000, 1000),
            placed("\\", "clip.mp4", 2000, 1000),
            placed("\\", "letter.pdf", 3000, 1000),
            Found {
                data: Data::Runs(vec![Run {
                    place: Place::Missing,
                    len: 10,
                }]),
                size: 10,
                ..found("lost.zip")
            },
            Found {
                damaged: true,
                ..placed("\\", "flawed.docx", 4000, 100)
            },
            placed("\\", "kept.bin", 5000, 100),
        ];
        // One unread byte inside cut.jpg.
        let map = map_of(8192, std::iter::once(1500..1501));
        let damage = damage_of(&files, Some(&map));
        let kinds: Vec<(u64, u64)> = damage.kinds.iter().map(|c| (c.whole, c.damaged)).collect();
        // Photos, videos, documents, other.
        assert_eq!(kinds, [(1, 1), (1, 0), (1, 1), (1, 1)]);
        assert_eq!(
            damage.total(),
            Condition {
                whole: 4,
                damaged: 3
            }
        );
        let unmapped = damage_of(&files, None);
        assert_eq!(
            unmapped.total(),
            Condition {
                whole: 5,
                damaged: 2
            }
        );
    }

    /// The saved list holds the damaged files only, each with its path, its size and the
    /// bytes not rescued; a file whose record is damaged has none missing.
    #[test]
    fn the_damaged_list_names_each_file_with_its_missing_bytes() {
        let files = vec![
            placed("\\DCIM", "ok.jpg", 0, 1000),
            placed("\\DCIM", "cut.jpg", 1000, 1000),
            Found {
                damaged: true,
                ..placed("\\", "flawed.docx", 4000, 100)
            },
        ];
        let map = map_of(8192, [1500..1510, 1900..1905]);
        let text = damaged_list(&files, Some(&map));
        assert_eq!(
            text,
            "Path\tSize in bytes\tBytes missing\r\n\\DCIM\\cut.jpg\t1000\t15\r\n\\flawed.docx\t100\t0\r\n"
        );
    }

    /// The list goes to its folder through the ledgered writer and is not made twice over
    /// one that is there.
    #[test]
    fn the_damaged_list_is_written_through_the_writer() {
        let dir = std::env::temp_dir().join(format!("diagtool-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let guard = Guard::of(&Protected::default());
        let first = write_text(&guard, &dir, DAMAGED_LIST, "one\r\n").unwrap();
        let second = write_text(&guard, &dir, DAMAGED_LIST, "two\r\n").unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "one\r\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The guard: the window's options become the engine's: both folders by their names when
    /// on, none when off, and the layout as chosen.
    #[test]
    fn the_options_map_to_the_recover_options() {
        let on = recover_options(Layout::Folders, true, true);
        assert_eq!(on.layout, Layout::Folders);
        assert_eq!(on.damaged_folder.as_deref(), Some("repair_needed"));
        assert_eq!(on.deleted_folder.as_deref(), Some("deleted"));
        let some = recover_options(Layout::ByType, false, true);
        assert_eq!(some.layout, Layout::ByType);
        assert_eq!(some.damaged_folder, None);
        assert_eq!(some.deleted_folder.as_deref(), Some("deleted"));
        let none = recover_options(Layout::Folders, false, false);
        assert_eq!((none.damaged_folder, none.deleted_folder), (None, None));
        // A new window starts with both on.
        let page = RecoverPage::new(SourceChoice::Image(PathBuf::from(
            r"\\?\nowhere\diagtool-no-such.img",
        )));
        assert!(page.own_damaged && page.own_deleted);
    }

    /// The good versions are written under repair_candidates in the damaged picture's
    /// folders, named after it, with a list of where each came from in each folder.
    #[test]
    fn good_versions_are_written_under_repair_candidates_with_their_list() {
        let dir = std::env::temp_dir().join(format!("diagtool-good-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut data = vec![0u8; 8192];
        data[4096..4196].fill(7);
        let listing = Listing {
            files: vec![
                placed("\\DCIM", "IMG_1.JPG", 0, 100),
                placed("\\Backup", "IMG_1.JPG", 4096, 100),
            ],
            ..Listing::default()
        };
        let damaged = candidates::Damaged {
            file: 0,
            name: "IMG_1.JPG".into(),
            folder: vec!["DCIM".into()],
            path: "\\DCIM\\IMG_1.JPG".into(),
            size: 100,
            missing: 10,
            format: None,
            captured: None,
            versions: vec![candidates::Version {
                file: 1,
                path: "\\Backup\\IMG_1.JPG".into(),
                size: 100,
                deleted: false,
                kind: VersionKind::Whole,
                format: None,
            }],
        };
        let search = candidates::Search {
            damaged: vec![damaged],
            stopped: false,
        };
        let mut reader = Reader::new(Box::new(MemDisk::new(data)));
        let outcome = save_versions(
            &mut reader,
            &listing,
            &search,
            &dir,
            &Protected::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        let folder = dir.join("repair_candidates").join("DCIM");
        let copy = std::fs::read(folder.join("IMG_1.JPG")).unwrap();
        assert_eq!(copy, vec![7u8; 100]);
        let list = std::fs::read_to_string(folder.join(candidates::LIST_NAME)).unwrap();
        assert!(list.contains("IMG_1.JPG\twhole copy"), "{list}");
        assert!(list.contains("\\Backup\\IMG_1.JPG"), "{list}");
        // Nothing was put among the files the person has: only under repair_candidates.
        let top: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(top, ["repair_candidates"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Each damaged picture's line counts its whole, near and other versions; the summary
    /// line says how many had one.
    #[test]
    fn the_versions_found_are_counted_per_picture() {
        let version = |kind| candidates::Version {
            file: 0,
            path: String::new(),
            size: 1,
            deleted: false,
            kind,
            format: None,
        };
        let d = |versions| candidates::Damaged {
            file: 0,
            name: "a.jpg".into(),
            folder: Vec::new(),
            path: "\\a.jpg".into(),
            size: 1,
            missing: 1,
            format: None,
            captured: None,
            versions,
        };
        let first = d(vec![
            version(VersionKind::Whole),
            version(VersionKind::Lesser),
            version(VersionKind::Lesser),
        ]);
        assert_eq!(versions_text(&first), "1 whole, 0 near, 2 other");
        let search = candidates::Search {
            damaged: vec![first, d(Vec::new())],
            stopped: true,
        };
        assert_eq!(
            found_text(&search),
            "2 damaged pictures, 1 with a good version found. Stopped before the end."
        );
    }

    /// The progress line gives the time left and the write rate once the copy has a figure,
    /// and says it is measuring until then.
    #[test]
    fn the_time_left_shows_once_measured() {
        use diagnostics::recovery::pace::Rate;
        let pace = Pace::default();
        assert_eq!(pace_text(&pace), "measuring the time left");
        let mut rate = Rate::default();
        for _ in 0..10 {
            rate.file(0.5, 1_000_000);
        }
        pace.set(&rate, 120, 120_000_000);
        assert_eq!(
            pace_text(&pace),
            "about 1 min 0 s left, writing 2.0 MB/s, 2.0 files/s"
        );
    }

    /// A run that kept and resumed files, left out System Volume Information and made its
    /// log says so, and names the log and the report.
    #[test]
    fn the_result_names_kept_resumed_left_out_and_the_log() {
        let dest = std::path::Path::new(r"E:\Recovered");
        let outcome = Outcome {
            report: Some(dest.join("Recovery report.txt")),
            log: Some(dest.join(output::LOG_NAME)),
            kept: 5,
            resumed: 1,
            left_out: 12,
            ..Outcome::default()
        };
        let (text, tone) = outcome_text(&outcome, dest);
        assert!(
            text.contains(
                "Kept 5 files an earlier run left whole, finished 1 file it left cut short."
            ),
            "{text}"
        );
        assert!(
            text.contains("Left out 12 files under System Volume Information."),
            "{text}"
        );
        assert!(
            text.contains("The log, Recovery log.txt, is there."),
            "{text}"
        );
        assert!(
            text.contains("The report, Recovery report.txt, is there too."),
            "{text}"
        );
        assert_eq!(tone, Tone::Ok);
        let without = Outcome {
            log: None,
            ..outcome
        };
        let (text, tone) = outcome_text(&without, dest);
        assert!(
            text.contains("The log, Recovery log.txt, could not be made."),
            "{text}"
        );
        assert_eq!(tone, Tone::Warn);
    }

    /// The window says where damaged pictures went as the report does: under the damaged
    /// folder when one was asked for, and how many could not be moved there.
    #[test]
    fn the_result_puts_damaged_pictures_where_the_report_does() {
        let dest = std::path::Path::new(r"E:\Recovered");
        let mut ledger = diagnostics::recovery::ledger::Ledger::default();
        let mut picture =
            |name: &str| ledger.made(0, dest.join(name), PathBuf::from(name), "in use".into(), 10);
        let (moved, stayed) = (picture("a.jpg"), picture("b.jpg"));
        ledger.remark(stayed, "it could not be moved under repair_needed");
        let salvaged = |output| output::Salvaged {
            output,
            preview: output::Preview::None,
        };
        let outcome = Outcome {
            ledger,
            pictures: vec![salvaged(moved), salvaged(stayed)],
            damaged_folder: Some(dest.join("repair_needed")),
            ..Outcome::default()
        };
        let (text, _) = outcome_text(&outcome, dest);
        assert!(
            text.contains(r"2 files with missing parts under E:\Recovered\repair_needed,"),
            "{text}"
        );
        assert!(text.contains(" 1 of them could not be put so;"), "{text}");
        assert!(!text.contains("(partial)"), "{text}");
    }
}
