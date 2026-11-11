//! The recovery window: opened from the drive window's Recovery button in a second copy of
//! the program that Windows starts with administrator rights (one UAC prompt), for one
//! disk or image. It shows the disk and its health, advises imaging first, and opens the
//! recovery tools. The crash dump window's set up and put back are the program's only other
//! elevated copy; the main window and the checks run without administrator rights.
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use diagnostics::recovery::{timed, SourceChoice};
use diagnostics::tools::drives;
use diagnostics::tools::drives::bytes_text;
use diagnostics::tools::drives::details::{self, Grade};
use diagnostics::tools::drives::health::Disk;
use diagnostics::ui_layout::{grid, Rect};
use windows_sys::Win32::Foundation::{GetLastError, HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, SW_SHOWNORMAL, WM_CLOSE};

use crate::condition_strip::{self, Strip};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};
use crate::{
    bitlocker_view, migrate_view, recover_files, rescue_copy_view, rescue_image_view, restore_view,
    vdisk_view, verify_view,
};

const IMAGE: usize = 10;
const COPY: usize = 11;
const RECOVER: usize = 12;
const BY_TYPE: usize = 13;
const READ_FROM: usize = 14;
const CLOSE: usize = 15;
const AS_DRIVE: usize = 16;
const BITLOCKER: usize = 17;
const MIGRATE: usize = 18;
const CHECK: usize = 19;
const WRITE: usize = 20;

/// The key of the recovery window among the tool windows.
pub const KEY: &str = "recovery";
pub const TITLE: &str = "Data recovery";

/// ERROR_CANCELLED: the user said No to the administrator prompt.
const ERROR_CANCELLED: u32 = 1223;

thread_local! {
    /// The image the rescue image tool last finished or stopped, for the recover tools.
    static LAST_IMAGE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Called by the rescue image tool, so the recover tools can read the image just made.
pub fn image_made(path: PathBuf) {
    LAST_IMAGE.with(|last| *last.borrow_mut() = Some(path));
}

/// What `--recovery` on the command line asks for: one source and, when the program started
/// itself elevated, the change record of the window that did.
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    pub source: SourceChoice,
    pub record: Option<PathBuf>,
}

/// The one grammar of a recovery command line, for startup and for a launch handed to the
/// running copy: the program, then `--recovery` and `--disk N` or `--image PATH`, then
/// `--record PATH` (what `elevated_args` adds). Every token is accounted for; one that is
/// not, a second source or a repeat is refused with its reason. None without `--recovery`.
pub fn parse_args(args: &[String]) -> Option<Result<Launch, String>> {
    let at = args.iter().position(|a| a == "--recovery")?;
    if let Some(stray) = args.get(1..at).and_then(<[String]>::first) {
        return Some(Err(format!("{stray:?} comes before --recovery")));
    }
    Some(launch_of(&args[at + 1..]))
}

fn launch_of(rest: &[String]) -> Result<Launch, String> {
    let (mut source, mut record) = (None, None);
    let mut tokens = rest.iter();
    while let Some(flag) = tokens.next() {
        let value = value_of(flag, tokens.next())?;
        match flag.as_str() {
            "--disk" | "--image" if source.is_some() => {
                return Err("--recovery takes one source, --disk N or --image PATH".into())
            }
            "--disk" => source = Some(SourceChoice::Disk(disk_of(value)?)),
            "--image" => source = Some(SourceChoice::Image(image_of(value)?)),
            "--record" if record.is_some() => return Err("--record is given once".into()),
            "--record" => record = Some(record_of(value)?),
            other => return Err(format!("{other:?} is not an argument of --recovery")),
        }
    }
    let source = source.ok_or("--recovery needs --disk N or --image PATH")?;
    Ok(Launch { source, record })
}

/// The token after `flag`, which has to be a value: another flag in its place means the
/// value is missing.
fn value_of<'a>(flag: &str, next: Option<&'a String>) -> Result<&'a str, String> {
    match next {
        Some(value) if !value.starts_with("--") => Ok(value),
        Some(value) => Err(format!("{flag} needs a value, not the flag {value:?}")),
        None => Err(format!("{flag} needs a value")),
    }
}

fn disk_of(value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("--disk needs a disk number, not {value:?}"))
}

fn image_of(value: &str) -> Result<PathBuf, String> {
    if value.trim().is_empty() {
        return Err("--image needs the path of an image, not an empty one".into());
    }
    Ok(PathBuf::from(value))
}

fn record_of(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !diagnostics::change_record::is_record_name(&path) {
        return Err(format!("--record needs a change record, not {value:?}"));
    }
    Ok(path)
}

/// The arguments the elevated copy is started with: the disk, and the change record of
/// the window that started it, so the findings report lists what the copy changes.
pub fn elevated_args(disk: u32, record: Option<&std::path::Path>) -> String {
    match record {
        Some(path) => format!("--recovery --disk {disk} --record \"{}\"", path.display()),
        None => format!("--recovery --disk {disk}"),
    }
}

/// Starts this program again with administrator rights for disk `disk`'s recovery window.
/// Windows shows its administrator prompt; Err says what happened when it did not start.
pub fn launch_elevated(owner: HWND, disk: u32) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW};
    let program = std::env::current_exe()
        .map_err(|e| format!("The program's own path could not be read: {e}"))?;
    let verb = ui::wide("runas");
    let file = ui::wide(&program.to_string_lossy());
    let parameters = ui::wide(&elevated_args(disk, diagnostics::change_record::file()));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC;
    info.hwnd = owner;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    if unsafe { ShellExecuteExW(&mut info) } != 0 {
        return Ok(());
    }
    Err(match unsafe { GetLastError() } {
        ERROR_CANCELLED => "Recovery needs administrator rights, and the Windows prompt was declined, so it did not open.".into(),
        other => format!("Windows did not start the recovery window (error {other})."),
    })
}

/// The tool key of one source's recovery window: opening the same source again raises
/// its window, another source gets a window of its own.
pub fn key_of(choice: &SourceChoice) -> String {
    match choice {
        SourceChoice::Disk(number) => format!("{KEY}:disk {number}"),
        SourceChoice::Image(path) => format!("{KEY}:image {}", path.display()),
        SourceChoice::Volume { path, .. } => format!("{KEY}:volume {path}"),
    }
}

/// Opens the recovery window for `choice` and brings it forward. These are this process's
/// only windows; the process ends with the last of them.
pub fn open_main(choice: SourceChoice) {
    let key = key_of(&choice);
    toolwin::open(std::ptr::null_mut(), &key, || {
        Box::new(RecoveryView::new(choice))
    });
    toolwin::end_process_with(KEY);
    if let Some(window) = toolwin::window_of(&key) {
        toolwin::raise(window);
    }
}

/// The advice shown in the window, in plain words.
pub fn advice(choice: &SourceChoice) -> &'static str {
    match choice {
        SourceChoice::Disk(_) => "If the drive is failing, make a rescue image first: it reads every readable part once, easy areas first, and keeps a map so it can stop and pick up again. Then recover files from the image instead of the drive, so the drive is not worn further. A rescue copy is quicker when only a few folders matter and the drive still mostly reads. Nothing here writes to this drive, and every copy goes to a different drive.",
        SourceChoice::Image(_) | SourceChoice::Volume { .. } => "This window reads an image file made earlier, so the failing drive is not touched. Copy the customer's files, recover deleted or lost files and find files by type from the image, open it as a drive to browse it, or write it to a replacement drive.",
    }
}

enum Header {
    Reading(mpsc::Receiver<Result<Option<Disk>, String>>),
    Ready(Option<Box<Disk>>),
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    strip: Strip,
    badge: HWND,
    verdict: HWND,
    advice: HWND,
    tools: Vec<(usize, HWND, HWND)>,
    read_from_text: HWND,
    read_from: HWND,
    status: HWND,
    close: HWND,
}

pub struct RecoveryView {
    choice: SourceChoice,
    /// What the recover tools read: the disk, or an image file.
    read_from: SourceChoice,
    header: Header,
    elevated: Option<bool>,
    notice: Option<String>,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

fn tone(grade: Grade) -> Tone {
    match grade {
        Grade::Good => Tone::Ok,
        Grade::Flagged => Tone::Warn,
        Grade::Serious => Tone::Serious,
        Grade::Unknown => Tone::Unavailable,
    }
}

/// The recovery tools as (id, caption, what it does), in the order a technician uses them:
/// copy what the drive holds, open it up, get the files out, then check them and put the
/// image on a new drive. `disk` is true when the window reads a drive, not an image.
fn tool_rows(disk: bool) -> Vec<(usize, &'static str, &'static str)> {
    let mut rows = Vec::new();
    if disk {
        rows.push((
            IMAGE,
            "Rescue image…",
            "Copies the whole drive to an image file on another drive, easy areas first, in a form GNU ddrescue can also read and resume.",
        ));
        rows.push((
            COPY,
            "Rescue copy of files…",
            "Copies chosen folders to another drive, readable parts first; unreadable parts become zeros and the log lists every damaged file.",
        ));
    }
    rows.push((
        AS_DRIVE,
        "Open an image as a drive…",
        "Attaches a rescue image read-only so Explorer can open its volumes, unlocks BitLocker on it, and repairs on a copy of it.",
    ));
    if disk {
        rows.push((
            BITLOCKER,
            "Unlock a BitLocker drive…",
            "Unlocks a BitLocker volume on this drive with its recovery key, typed or looked up. A failing drive is better imaged first and the image unlocked.",
        ));
    }
    rows.push((
        MIGRATE,
        "Copy the customer's files…",
        "Copies each person's documents, photos, bookmarks, Outlook files and Sticky Notes from Windows on the drive to another drive, with a handover report.",
    ));
    if recover_files::available() {
        rows.push((
            RECOVER,
            "Recover deleted or lost files…",
            "Finds files that were deleted or whose folders are lost.",
        ));
        rows.push((
            BY_TYPE,
            "Find files by type…",
            "Searches the raw data for photos, documents and other files by their contents.",
        ));
    }
    rows.push((
        CHECK,
        "Check recovered files…",
        "Checks every file in a folder of recovered or copied files and lists which are damaged.",
    ));
    rows.push((
        WRITE,
        "Write image to a replacement drive…",
        "Writes a rescue image to a new drive, erasing it, so it holds what the failing drive held. It never writes to the failing drive.",
    ));
    rows
}

impl RecoveryView {
    pub fn new(choice: SourceChoice) -> Self {
        let header = match &choice {
            SourceChoice::Disk(number) => {
                let number = *number;
                let (sender, receiver) = mpsc::channel();
                thread::spawn(move || {
                    let _ = sender.send(timed::read_disk_within(number, timed::HEALTH_LIMIT));
                });
                Header::Reading(receiver)
            }
            _ => Header::Ready(None),
        };
        Self {
            read_from: choice.clone(),
            choice,
            header,
            elevated: drives::elevated(),
            notice: None,
            controls: None,
            area: (0, 0, 96),
            natural: None,
        }
    }

    fn disk(&self) -> Option<&Disk> {
        match &self.header {
            Header::Ready(disk) => disk.as_deref(),
            Header::Reading(_) => None,
        }
    }

    fn disk_number(&self) -> Option<u32> {
        match self.choice {
            SourceChoice::Disk(number) => Some(number),
            _ => None,
        }
    }

    fn tool_rows(&self) -> Vec<(usize, &'static str, &'static str)> {
        tool_rows(self.disk_number().is_some())
    }

    fn read_from_text(&self) -> String {
        match &self.read_from {
            SourceChoice::Disk(number) => format!("File recovery reads from: Disk {number}"),
            SourceChoice::Image(path) => format!(
                "File recovery reads from: {}",
                path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().into()
                )
            ),
            SourceChoice::Volume { name, .. } => format!("File recovery reads from: {name}"),
        }
    }

    fn status_text(&self) -> String {
        if let Some(notice) = &self.notice {
            return notice.clone();
        }
        match (&self.choice, self.elevated) {
            (SourceChoice::Disk(_), Some(true)) => "Running with administrator rights, for this window only.".into(),
            (SourceChoice::Disk(_), _) => "This window has no administrator rights, so the disk cannot be read. Open it with the Recovery button in the drive window.".into(),
            (SourceChoice::Image(path), _) => format!("Reading {}", path.display()),
            (SourceChoice::Volume { name, .. }, _) => format!("Reading {name}"),
        }
    }

    fn render(&mut self) {
        let status = self.status_text();
        let read_from = self.read_from_text();
        let Some(c) = &self.controls else {
            return;
        };
        match (&self.choice, self.disk()) {
            (_, Some(disk)) => {
                let verdict = details::verdict(disk);
                ui::set_text(c.title, &details::name(disk));
                ui::set_text(c.subtitle, &details::caption(disk));
                ui::set_text(c.badge, verdict.headline);
                ui::set_tone(c.badge, tone(verdict.grade));
                ui::set_text(c.verdict, &details::verdict_text(&verdict));
                ui::show(c.badge, true);
            }
            (SourceChoice::Disk(number), None) => {
                let reading = matches!(self.header, Header::Reading(_));
                ui::set_text(c.title, &format!("Disk {number}"));
                ui::set_text(
                    c.subtitle,
                    if reading {
                        "Reading the drive's identity and health…"
                    } else {
                        "Windows does not list this disk now."
                    },
                );
                ui::set_text(c.verdict, "");
                ui::show(c.badge, false);
            }
            (SourceChoice::Image(path), None) => {
                let size = std::fs::metadata(path)
                    .map(|m| bytes_text(m.len()))
                    .unwrap_or_else(|_| "not readable".into());
                ui::set_text(
                    c.title,
                    &path.file_name().map_or_else(
                        || path.display().to_string(),
                        |n| n.to_string_lossy().into(),
                    ),
                );
                ui::set_text(c.subtitle, &format!("Image file, {size}"));
                ui::set_text(c.verdict, "");
                ui::show(c.badge, false);
            }
            (SourceChoice::Volume { name, .. }, None) => ui::set_text(c.title, name),
        }
        ui::set_text(c.status, &status);
        ui::set_text(c.read_from_text, &read_from);
        let can_read_disk = self.elevated == Some(true);
        for (id, button, _) in &c.tools {
            if *id == IMAGE || *id == WRITE {
                ui::enable(*button, can_read_disk);
            }
        }
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    fn choose_read_from(&mut self, hwnd: HWND) {
        let picked = toolwin::pick_file(
            hwnd,
            "Choose an image file to recover from",
            "Disk images (*.img, *.dd, *.raw, *.bin)\0*.img;*.dd;*.raw;*.bin\0All files\0*.*\0",
        );
        self.read_from = match picked {
            Some(path) => SourceChoice::Image(path),
            None => self.choice.clone(),
        };
        self.notice = None;
    }
}

impl Page for RecoveryView {
    fn title(&self) -> String {
        TITLE.into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(if self.disk_number().is_some() {
            crate::help::RECOVERY_DISK
        } else {
            crate::help::RECOVERY_IMAGE
        })
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        // A drive has nine tools with a line or two each; an image has six.
        if self.disk_number().is_some() {
            ((920, 900), (640, 560))
        } else {
            ((920, 700), (640, 520))
        }
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let tools = self
            .tool_rows()
            .into_iter()
            .map(|(id, caption, about)| {
                (
                    id,
                    ui::button(hwnd, id, Kind::Secondary, caption),
                    text(Kind::Muted, about),
                )
            })
            .collect();
        self.controls = Some(Controls {
            title: text(Kind::Title, ""),
            subtitle: text(Kind::Muted, ""),
            strip: Strip::new(hwnd, self.disk_number()),
            badge: text(Kind::Badge, ""),
            verdict: text(Kind::Body, ""),
            advice: ui::text(hwnd, Kind::Body, Tone::Neutral, true, advice(&self.choice)),
            tools,
            read_from_text: text(Kind::Body, ""),
            read_from: ui::button(hwnd, READ_FROM, Kind::Secondary, "Choose an image file…"),
            status: text(Kind::Muted, ""),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        });
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let has_badge = self.disk().is_some();
        let show_read_from = recover_files::available();
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        let bh = f.s(grid::BUTTON_H);
        f.header(c.title, c.subtitle);
        c.strip.place(&mut f);
        f.space(2);
        // The health badge and its verdict, side by side.
        let badge_w = f.s(132);
        let (verdict_x, verdict_w) = if has_badge {
            (f.x + badge_w + f.s(12), f.w - badge_w - f.s(12))
        } else {
            (f.x, f.w)
        };
        let verdict_h = f.text_h(c.verdict, verdict_w);
        ui::show(c.verdict, verdict_h > 0);
        if has_badge || verdict_h > 0 {
            ui::place(
                c.badge,
                Rect {
                    x: f.x,
                    y: f.y,
                    w: badge_w,
                    h: f.s(grid::BADGE_H),
                },
            );
            ui::place(
                c.verdict,
                Rect {
                    x: verdict_x,
                    y: f.y + f.s(2),
                    w: verdict_w,
                    h: verdict_h,
                },
            );
            let badge_h = if has_badge { f.s(grid::BADGE_H) } else { 0 };
            f.y += verdict_h.max(badge_h);
            f.space(16);
        }
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
        f.space(16);
        // Each tool: its button, and what it does beside it.
        let button_w = c
            .tools
            .iter()
            .map(|(_, button, _)| ui::button_width(*button, &ui::window_text(*button)))
            .max()
            .unwrap_or(0);
        for (_, button, about) in &c.tools {
            ui::place(
                *button,
                Rect {
                    x: f.x,
                    y: f.y,
                    w: button_w,
                    h: bh,
                },
            );
            let about_x = f.x + button_w + f.s(14);
            let about_w = (f.w - button_w - f.s(14)).max(f.s(80));
            let about_h = f.text_h(*about, about_w);
            ui::place(
                *about,
                Rect {
                    x: about_x,
                    y: f.y + f.s(2),
                    w: about_w,
                    h: about_h,
                },
            );
            f.y += about_h.max(bh);
            f.space(12);
        }
        ui::show(c.read_from_text, show_read_from);
        ui::show(c.read_from, show_read_from);
        if show_read_from {
            // What file recovery reads, and the button to read an image file instead.
            let button_w = ui::button_width(c.read_from, &ui::window_text(c.read_from));
            let text_w = f.w - button_w - f.s(14);
            let text_h = f.text_h(c.read_from_text, text_w);
            let row_h = text_h.max(bh);
            ui::place(
                c.read_from_text,
                Rect {
                    x: f.x,
                    y: f.y + (row_h - text_h) / 2,
                    w: text_w,
                    h: text_h,
                },
            );
            ui::place(
                c.read_from,
                Rect {
                    x: f.x + f.w - button_w,
                    y: f.y + (row_h - bh) / 2,
                    w: button_w,
                    h: bh,
                },
            );
            f.y += row_h;
            f.space(12);
        }
        f.text(c.status, 0);
        self.natural = Some(f.y + toolwin::footer_h(dpi));
        toolwin::footer(w, h, dpi, &[], &[c.close]);
        // The advice card.
        ui::set_cards(hwnd, vec![card]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, _code: u16) -> Option<Ask> {
        match id {
            IMAGE => {
                if let Some(disk) = self.disk_number() {
                    rescue_image_view::open(hwnd, disk);
                }
            }
            COPY => {
                if let Some(disk) = self.disk_number() {
                    let letters = self.disk().map(|d| d.volumes.clone()).unwrap_or_default();
                    rescue_copy_view::open(hwnd, disk, letters);
                }
            }
            WRITE => restore_view::open(
                hwnd,
                match &self.read_from {
                    SourceChoice::Image(path) => Some(path.clone()),
                    _ => None,
                },
            ),
            AS_DRIVE => {
                let image = match &self.read_from {
                    SourceChoice::Image(path) => Some(path.clone()),
                    _ => None,
                };
                vdisk_view::open(hwnd, image, self.disk_number());
            }
            BITLOCKER => {
                if let Some(disk) = self.disk_number() {
                    bitlocker_view::open(hwnd, disk, Some(disk));
                }
            }
            RECOVER => recover_files::open_recover(hwnd, self.read_from.clone()),
            BY_TYPE => recover_files::open_by_type(hwnd, self.read_from.clone()),
            CHECK => verify_view::open(
                hwnd,
                None,
                diagnostics::recovery::output::source_disk(&self.read_from),
            ),
            MIGRATE => migrate_view::open(hwnd, self.read_from.clone()),
            READ_FROM => {
                self.choose_read_from(hwnd);
                self.render();
                self.relayout(hwnd);
            }
            // Posted, so the window closes after this call returns.
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        None
    }

    fn tick(&mut self, hwnd: HWND) {
        if let Some(c) = &mut self.controls {
            c.strip.refresh();
        }
        if let Header::Reading(receiver) = &self.header {
            match receiver.try_recv() {
                Ok(read) => {
                    if let Err(why) = &read {
                        self.notice = Some(why.clone());
                    }
                    let read = read.ok().flatten();
                    // The reading made as the window opened is the strip's first.
                    if let (Some(number), Some(disk)) = (self.disk_number(), &read) {
                        let reading =
                            diagnostics::recovery::health_log::Reading::of(Ok(disk), 0, 0);
                        condition_strip::reading(number, &reading, "once, when this window opened");
                    }
                    self.header = Header::Ready(read.map(Box::new));
                    self.render();
                    self.relayout(hwnd);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.header = Header::Ready(None);
                    self.render();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(image) = LAST_IMAGE.with(|last| last.borrow_mut().take()) {
            self.notice = Some(format!(
                "File recovery now reads the rescued image, {}, instead of the drive.",
                image.display()
            ));
            self.read_from = SourceChoice::Image(image);
            self.render();
            self.relayout(hwnd);
        }
    }

    fn draw_item(&self, list: usize, _index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        if let Some(c) = &self.controls {
            c.strip.draw(list, dc, rect, state.dpi);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tool has one row, in the same order for a drive and an image, each caption
    /// ending in "…" and each description a sentence.
    #[test]
    fn each_recovery_tool_has_one_row() {
        let ids = |disk| tool_rows(disk).iter().map(|r| r.0).collect::<Vec<_>>();
        let drive = ids(true);
        assert_eq!(
            drive,
            [IMAGE, COPY, AS_DRIVE, BITLOCKER, MIGRATE, RECOVER, BY_TYPE, CHECK, WRITE]
        );
        let image: Vec<usize> = drive
            .iter()
            .copied()
            .filter(|id| ![IMAGE, COPY, BITLOCKER].contains(id))
            .collect();
        assert_eq!(ids(false), image);
        for (_, caption, what) in tool_rows(true) {
            assert!(caption.ends_with('…'), "{caption}");
            assert!(what.ends_with('.') && !what.contains('!'), "{what}");
        }
    }

    fn args(text: &str) -> Vec<String> {
        text.split(' ').map(String::from).collect()
    }

    fn disk(number: u32) -> Option<Result<Launch, String>> {
        Some(Ok(Launch {
            source: SourceChoice::Disk(number),
            record: None,
        }))
    }

    #[test]
    fn the_command_line_names_a_disk_or_an_image() {
        assert_eq!(parse_args(&args("DiagnosticTool.exe")), None);
        assert_eq!(
            parse_args(&args("DiagnosticTool.exe --recovery --disk 4")),
            disk(4)
        );
        assert_eq!(
            parse_args(&args("x --recovery --image D:\\rescue\\a.img")),
            Some(Ok(Launch {
                source: SourceChoice::Image(PathBuf::from("D:\\rescue\\a.img")),
                record: None,
            }))
        );
        assert!(matches!(
            parse_args(&args("x --recovery --disk four")),
            Some(Err(_))
        ));
        assert!(matches!(parse_args(&args("x --recovery")), Some(Err(_))));
        let built = args(&format!("x {}", elevated_args(7, None)));
        assert_eq!(parse_args(&built), disk(7));
        let record = PathBuf::from(r"C:\Temp\DiagnosticTool-changes-12.txt");
        assert!(elevated_args(7, Some(&record))
            .ends_with(r#"--record "C:\Temp\DiagnosticTool-changes-12.txt""#));
        assert_eq!(
            parse_args(&elevated_line(7, &record)),
            Some(Ok(Launch {
                source: SourceChoice::Disk(7),
                record: Some(record),
            }))
        );
    }

    /// The command line `elevated_args` makes for `record`, as Windows hands it to main:
    /// split at the spaces, the quotes taken off.
    fn elevated_line(number: u32, record: &std::path::Path) -> Vec<String> {
        std::iter::once("x".to_string())
            .chain(
                elevated_args(number, Some(record))
                    .split(' ')
                    .map(|token| token.trim_matches('"').to_string()),
            )
            .collect()
    }

    /// The guard: every token after `--recovery` is accounted for. A source given twice, a
    /// stray or repeated token, a record that is not one of this program's and a token
    /// before `--recovery` are refused with a reason, in place of the rest being ignored.
    #[test]
    fn a_command_line_with_a_token_left_over_or_in_conflict_is_refused() {
        let record = r"C:\Temp\DiagnosticTool-changes-12.txt";
        for bad in [
            "x --recovery --disk 3 --image other.img",
            "x --recovery --image a.img --disk 3",
            "x --recovery --disk 3 --disk 4",
            "x --recovery --image a.img --image b.img",
            "x --recovery --disk 3 extra",
            "x --recovery --disk 3 --record",
            "x --recovery --disk 3 --format 3",
            "x --recovery --disk 3 --recovery",
            r"x --recovery --disk 3 --record C:\Windows\win.ini",
            &format!("x --recovery --disk 3 --record {record} --record {record}"),
            "x stray --recovery --disk 3",
        ] {
            let parsed = parse_args(&args(bad));
            assert!(
                matches!(&parsed, Some(Err(why)) if !why.is_empty()),
                "{bad}: {parsed:?}"
            );
        }
    }

    /// The guard: a flag's value is checked as a value before the launch is built. Another
    /// flag or nothing in its place, and an image with no path, open no window.
    #[test]
    fn a_flag_followed_by_a_flag_or_an_empty_path_is_refused() {
        for bad in [
            vec!["x", "--recovery", "--image", "--disk"],
            vec!["x", "--recovery", "--image", "--disk", "3"],
            vec!["x", "--recovery", "--disk", "--image", "a.img"],
            vec!["x", "--recovery", "--image", ""],
            vec!["x", "--recovery", "--image", "  "],
            vec![
                "x",
                "--recovery",
                "--disk",
                "3",
                "--record",
                "--image",
                "a.img",
            ],
        ] {
            let tokens: Vec<String> = bad.iter().map(|t| t.to_string()).collect();
            let parsed = parse_args(&tokens);
            assert!(
                matches!(&parsed, Some(Err(why)) if !why.is_empty()),
                "{bad:?}: {parsed:?}"
            );
        }
    }

    #[test]
    fn each_source_has_its_own_window_key_in_the_recovery_group() {
        let a = key_of(&SourceChoice::Disk(3));
        let b = key_of(&SourceChoice::Image(PathBuf::from(r"D:\a b.img")));
        assert_ne!(a, b);
        assert_eq!(a, key_of(&SourceChoice::Disk(3)));
        assert!(a.starts_with("recovery:") && b.starts_with("recovery:"));
    }

    #[test]
    fn the_advice_says_image_first_then_recover_from_the_image() {
        let text = advice(&SourceChoice::Disk(1));
        let image = text.find("rescue image first").unwrap();
        let recover = text.find("recover files from the image").unwrap();
        assert!(image < recover);
        assert!(text.contains("Nothing here writes to this drive"));
    }
}
