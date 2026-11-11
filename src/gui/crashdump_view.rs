//! The crash dump window: readiness item by item, and in the copy Windows starts with
//! administrator rights, the technician's choices, Set up and Put back. The engine,
//! `tools::crash_dumps`, holds every rule and limit; this window builds its options,
//! shows its events and renders its results.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use diagnostics::change_record;
use diagnostics::tools::crash_dumps::{
    self, AppDumpType, AppOptions, ChangeResult, CheckOptions, CheckResult, Event, Item,
    KernelDumpType, KernelOptions, Outcome, PutBackOptions, SetUpOptions, Status,
};
use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{DT_WORDBREAK, HDC};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, IsIconic, PostMessageW, SetForegroundWindow, ShowWindow, SW_RESTORE,
    SW_SHOWNORMAL, WM_CLOSE, WM_COMMAND,
};

use crate::dialog::{Dialog, Item as Line, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

/// The command line flag that opens this window alone, with administrator rights.
pub const FLAG: &str = "--crash-dumps";
const RECORD_FLAG: &str = "--record";
pub const KEY: &str = "crash-dumps";
pub const TITLE: &str = "Crash dump readiness";
/// ERROR_CANCELLED: the administrator prompt was declined.
const ERROR_CANCELLED: u32 = 1223;

const SET_UP: usize = 10;
const PUT_BACK: usize = 11;
const CHECK: usize = 12;
const COPY: usize = 13;
const CLOSE: usize = 14;
const AS_ADMIN: usize = 15;
const SIDES: usize = 20;
const KERNEL_TYPE: usize = 21;
const RESTART: usize = 22;
const DUMP_FILE: usize = 23;
const MINIDUMPS: usize = 24;
const APP_FOLDER: usize = 25;
const APP_TYPE: usize = 26;
const APP_COUNT: usize = 27;
const ITEMS: usize = 30;
/// Posted by `tick` when a preview is back, so the confirmation comes from `command`.
const ASK: usize = 40;
const DO_CHANGE: usize = 41;

const LBN_SELCHANGE: u16 = 1;
const COUNTS: [u32; 5] = [5, 10, 20, 50, 100];

/// Opens the window beside the main window, reading without administrator rights.
pub fn open(owner: HWND) {
    toolwin::open(owner, KEY, || Box::new(CrashDumpView::new()));
}

/// Runs the administrator copy when the command line asks for it; true when it did.
pub fn run_if_asked(args: &[String]) -> bool {
    let Some(at) = args.iter().position(|a| a == FLAG) else {
        return false;
    };
    if let [flag, path, ..] = &args[at + 1..] {
        let path = PathBuf::from(path);
        if flag == RECORD_FLAG && change_record::is_record_name(&path) {
            change_record::use_file(path);
        }
    }
    let mutex = unsafe {
        CreateMutexW(
            std::ptr::null(),
            0,
            ui::wide("Local\\DiagnosticTool.CrashDumps").as_ptr(),
        )
    };
    if !mutex.is_null() && unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        let hwnd =
            unsafe { FindWindowW(ui::wide(toolwin::CLASS).as_ptr(), ui::wide(TITLE).as_ptr()) };
        if !hwnd.is_null() {
            unsafe {
                if IsIconic(hwnd) != 0 {
                    ShowWindow(hwnd, SW_RESTORE);
                }
                SetForegroundWindow(hwnd);
            }
        }
        return true;
    }
    ui::start_gdiplus();
    ui::refresh_palette();
    toolwin::open(std::ptr::null_mut(), KEY, || Box::new(CrashDumpView::new()));
    toolwin::end_process_with(KEY);
    if let Some(window) = toolwin::window_of(KEY) {
        crate::message_loop(window);
    }
    true
}

/// The arguments the administrator copy starts with: the flag, and the change record of
/// the window that started it, so the findings report lists its changes.
pub fn elevated_args(record: Option<&std::path::Path>) -> String {
    match record {
        Some(path) => format!("{FLAG} {RECORD_FLAG} \"{}\"", path.display()),
        None => FLAG.into(),
    }
}

fn launch_elevated(owner: HWND) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW};
    let program = std::env::current_exe()
        .map_err(|e| format!("The program's own path could not be read: {e}"))?;
    let verb = ui::wide("runas");
    let file = ui::wide(&program.to_string_lossy());
    let parameters = ui::wide(&elevated_args(change_record::file()));
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
        ERROR_CANCELLED => "Changing crash dump settings needs administrator rights, and the Windows prompt was declined.".into(),
        other => format!("Windows did not start the administrator window (error {other})."),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    SetUp,
    PutBack,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Action::SetUp => "Set up",
            Action::PutBack => "Put back",
        }
    }
}

/// Which sides set up changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sides {
    Both,
    Kernel,
    Applications,
}

enum Done {
    Check(CheckResult),
    Preview(Action, ChangeResult),
    Changed(Action, ChangeResult),
}

enum Message {
    Event(Event),
    Done(Done),
}

struct Running {
    cancel: Arc<AtomicBool>,
    messages: mpsc::Receiver<Message>,
    worker: Option<JoinHandle<()>>,
    /// A set up or put back is waited for when the window closes, so its writes and its
    /// change record end together. A check only reads, and a folder read Windows holds up
    /// cannot be interrupted, so a closing window leaves it to end on its own.
    wait_on_close: bool,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    items: HWND,
    details: HWND,
    options: Vec<(usize, HWND)>,
    status: HWND,
    set_up: HWND,
    put_back: HWND,
    as_admin: HWND,
    check: HWND,
    copy: HWND,
    close: HWND,
}

pub struct CrashDumpView {
    elevated: bool,
    check: Option<CheckResult>,
    /// The items read so far while a check runs.
    live_items: Vec<Item>,
    kernel: KernelOptions,
    apps: AppOptions,
    sides: Sides,
    /// A preview waiting for the technician's confirmation.
    preview: Option<(Action, ChangeResult)>,
    /// The last set up or put back, shown in the details box.
    last: Option<(Action, ChangeResult)>,
    running: Option<Running>,
    status: (String, Tone),
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

impl Drop for CrashDumpView {
    fn drop(&mut self) {
        if let Some(running) = &mut self.running {
            running.cancel.store(true, Ordering::Relaxed);
            if let Some(worker) = running.worker.take() {
                if running.wait_on_close {
                    let _ = worker.join();
                }
            }
        }
    }
}

/// One item as the list and screen readers give it.
pub fn item_text(item: &Item) -> String {
    format!("{}: {}. {}", item.label, item.status.word(), item.summary)
}

/// The details box for one item.
pub fn item_details(item: &Item) -> String {
    let mut lines = vec![format!("{}: {}", item.label, item.status.word())];
    if let Some(reason) = item.status.reason() {
        lines.push(reason.to_string());
    }
    lines.push(String::new());
    lines.push(item.summary.clone());
    lines.extend(item.details.iter().cloned());
    lines.join("\r\n")
}

/// A set up or put back result as the technician reads it.
pub fn result_text(action: &str, result: &ChangeResult) -> String {
    let mut lines = vec![match &result.outcome {
        Outcome::Done => format!("{action}: done."),
        Outcome::NothingToDo => format!("{action}: nothing needed changing."),
        Outcome::NotConfirmed => format!("{action}: not confirmed, so nothing was changed."),
        Outcome::Stopped => format!("{action}: stopped."),
        Outcome::Refused { reasons } => format!(
            "{action} was not done, and nothing was changed:\r\n{}",
            reasons
                .iter()
                .map(|r| format!("  {r}"))
                .collect::<Vec<_>>()
                .join("\r\n")
        ),
        Outcome::Failed { reason } => format!("{action} did not finish: {reason}."),
    }];
    if !result.changed.is_empty() {
        lines.push(String::new());
        lines.push("Changed:".into());
        lines.extend(result.changed.iter().map(|c| format!("  {}", c.text)));
    }
    if matches!(result.outcome, Outcome::Stopped | Outcome::Failed { .. })
        && !result.changed.is_empty()
    {
        lines.push("Put back undoes these changes.".into());
    }
    if !result.notes.is_empty() {
        lines.push(String::new());
        lines.extend(result.notes.iter().cloned());
    }
    lines.join("\r\n")
}

fn tone(status: &Status) -> Tone {
    match status {
        Status::Ready => Tone::Ok,
        Status::NeedsChange { .. } => Tone::Warn,
        Status::CouldNotRead { .. } => Tone::Unavailable,
    }
}

fn type_caption(dump: KernelDumpType) -> String {
    let mut name = dump.name().to_string();
    name[..1].make_ascii_uppercase();
    format!("Kernel dump: {name}")
}

impl CrashDumpView {
    pub fn new() -> Self {
        let mut view = Self {
            elevated: crash_dumps::elevated() == Some(true),
            check: None,
            live_items: Vec::new(),
            kernel: KernelOptions::default(),
            apps: AppOptions::default(),
            sides: Sides::Both,
            preview: None,
            last: None,
            running: None,
            status: (String::new(), Tone::Neutral),
            controls: None,
            area: (0, 0, 96),
            natural: None,
        };
        view.start_check();
        view
    }

    fn options(&self, confirmed: bool) -> SetUpOptions {
        SetUpOptions {
            confirmed,
            kernel: (self.sides != Sides::Applications).then(|| self.kernel.clone()),
            applications: (self.sides != Sides::Kernel).then(|| self.apps.clone()),
        }
    }

    fn start(
        &mut self,
        wait_on_close: bool,
        job: impl FnOnce(&mut dyn FnMut(Event), &AtomicBool) -> Done + Send + 'static,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, messages) = mpsc::channel();
        let flag = cancel.clone();
        let worker = thread::spawn(move || {
            let events = sender.clone();
            let done = job(
                &mut |event| {
                    let _ = events.send(Message::Event(event));
                },
                &flag,
            );
            let _ = sender.send(Message::Done(done));
        });
        self.running = Some(Running {
            cancel,
            messages,
            worker: Some(worker),
            wait_on_close,
        });
    }

    fn start_check(&mut self) {
        self.live_items.clear();
        self.status = ("Reading the crash dump settings.".into(), Tone::Neutral);
        self.start(false, |progress, cancel| {
            Done::Check(crash_dumps::check(
                &CheckOptions::default(),
                progress,
                cancel,
            ))
        });
    }

    fn start_change(&mut self, action: Action, confirmed: bool) {
        let options = self.options(confirmed);
        self.status = (
            if confirmed {
                format!("{}: working.", action.name())
            } else {
                format!("{}: listing what would change.", action.name())
            },
            Tone::Neutral,
        );
        self.start(true, move |progress, cancel| {
            let result = match action {
                Action::SetUp => crash_dumps::set_up(&options, progress, cancel),
                Action::PutBack => {
                    crash_dumps::put_back(&PutBackOptions { confirmed }, progress, cancel)
                }
            };
            if confirmed {
                Done::Changed(action, result)
            } else {
                Done::Preview(action, result)
            }
        });
    }

    fn items(&self) -> &[Item] {
        match &self.check {
            Some(check) if self.running.is_none() => &check.items,
            _ => &self.live_items,
        }
    }

    fn details_text(&self) -> String {
        let selected = self
            .controls
            .as_ref()
            .and_then(|c| toolwin::selected(c.items));
        if let Some(item) = selected.and_then(|i| self.items().get(i)) {
            return item_details(item);
        }
        if let Some((action, result)) = &self.last {
            return result_text(action.name(), result);
        }
        "Select an item to see its values and why it reads as it does.".into()
    }

    fn render(&mut self) {
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_text(
            c.subtitle,
            if self.elevated {
                "Running with administrator rights. Choose the settings, then Set up; Put back restores what was there before."
            } else {
                "Read without administrator rights. Changing the settings opens this window with administrator rights."
            },
        );
        ui::set_text(c.details, &self.details_text());
        ui::set_text(c.status, &self.status.0);
        ui::set_tone(c.status, self.status.1);
        let busy = self.running.is_some();
        for (id, hwnd) in &c.options {
            ui::set_text(*hwnd, &self.option_caption(*id));
            let side = match *id {
                KERNEL_TYPE | RESTART | DUMP_FILE | MINIDUMPS => self.sides != Sides::Applications,
                APP_FOLDER | APP_TYPE | APP_COUNT => self.sides != Sides::Kernel,
                _ => true,
            };
            ui::enable(*hwnd, !busy && side);
        }
        let can_put_back = self.check.as_ref().is_some_and(|c| c.put_back_available);
        ui::enable(c.set_up, !busy);
        ui::enable(c.put_back, !busy && can_put_back);
        ui::enable(c.as_admin, !busy);
        ui::set_text(c.check, if busy { "Stop" } else { "Check again" });
        ui::enable(c.copy, !busy);
    }

    fn option_caption(&self, id: usize) -> String {
        match id {
            SIDES => match self.sides {
                Sides::Both => "Change: kernel and application dumps",
                Sides::Kernel => "Change: kernel dumps only",
                Sides::Applications => "Change: application dumps only",
            }
            .into(),
            KERNEL_TYPE => type_caption(self.kernel.dump_type),
            RESTART => match self.kernel.restart_after_stop {
                None => "Restart after a stop: leave as it is",
                Some(true) => "Restart after a stop: yes",
                Some(false) => "Restart after a stop: no",
            }
            .into(),
            DUMP_FILE => format!("Memory dump file: {}", self.kernel.dump_file),
            MINIDUMPS => format!("Small dumps: {}", self.kernel.minidump_folder),
            APP_FOLDER => format!("Application dumps: {}", self.apps.folder),
            APP_TYPE => match self.apps.dump_type {
                AppDumpType::Mini => "Type: mini dumps (small)",
                AppDumpType::Full => "Type: full dumps (whole program)",
            }
            .into(),
            APP_COUNT => format!("Keep: {}", self.apps.count),
            _ => String::new(),
        }
    }

    fn choose(&mut self, hwnd: HWND, id: usize) {
        match id {
            SIDES => {
                self.sides = match self.sides {
                    Sides::Both => Sides::Kernel,
                    Sides::Kernel => Sides::Applications,
                    Sides::Applications => Sides::Both,
                }
            }
            KERNEL_TYPE => {
                let all = KernelDumpType::ALL;
                let at = all
                    .iter()
                    .position(|t| *t == self.kernel.dump_type)
                    .unwrap_or(0);
                self.kernel.dump_type = all[(at + 1) % all.len()];
            }
            RESTART => {
                self.kernel.restart_after_stop = match self.kernel.restart_after_stop {
                    None => Some(true),
                    Some(true) => Some(false),
                    Some(false) => None,
                }
            }
            DUMP_FILE => {
                if let Some(folder) =
                    toolwin::pick_folder(hwnd, "Choose the folder for the memory dump file")
                {
                    self.kernel.dump_file = folder.join("MEMORY.DMP").display().to_string();
                }
            }
            MINIDUMPS => {
                if let Some(folder) =
                    toolwin::pick_folder(hwnd, "Choose the folder for small memory dumps")
                {
                    self.kernel.minidump_folder = folder.display().to_string();
                }
            }
            APP_FOLDER => {
                if let Some(folder) =
                    toolwin::pick_folder(hwnd, "Choose the folder for application dumps")
                {
                    self.apps.folder = folder.display().to_string();
                }
            }
            APP_TYPE => {
                self.apps.dump_type = match self.apps.dump_type {
                    AppDumpType::Mini => AppDumpType::Full,
                    AppDumpType::Full => AppDumpType::Mini,
                }
            }
            APP_COUNT => {
                let at = COUNTS
                    .iter()
                    .position(|c| *c == self.apps.count)
                    .unwrap_or(0);
                self.apps.count = COUNTS[(at + 1) % COUNTS.len()];
            }
            _ => {}
        }
    }

    /// The confirmation for a preview: every change it lists and what it means.
    fn ask(&mut self) -> Option<Ask> {
        let (action, result) = self.preview.as_ref()?;
        if result.outcome != Outcome::NotConfirmed {
            let (action, result) = self.preview.take()?;
            self.status = match result.outcome {
                Outcome::NothingToDo => (
                    format!("{}: nothing needs changing.", action.name()),
                    Tone::Ok,
                ),
                _ => (
                    format!("{} was not done; the details below say why.", action.name()),
                    Tone::Warn,
                ),
            };
            self.last = Some((action, result));
            if let Some(c) = &self.controls {
                toolwin::select(c.items, None);
            }
            return None;
        }
        let mut items: Vec<Line> = result
            .planned
            .iter()
            .map(|c| Line::Pair(c.target.clone(), format!("{} to {}", c.before, c.after)))
            .collect();
        items.extend(result.notes.iter().map(|n| Line::Para(n.clone())));
        let restart = result.planned.iter().any(|c| c.needs_restart);
        let intro = match action {
            Action::SetUp => format!(
                "The present values are saved to {} first, so Put back can restore them.{}",
                result.backup.display(),
                if restart {
                    " Kernel settings take effect after Windows next restarts; this tool does not restart the PC."
                } else {
                    ""
                }
            ),
            Action::PutBack => "Each value goes back to what it was before set up first ran. Folders set up made are removed only if they are empty.".into(),
        };
        Some(Ask {
            dialog: Dialog {
                window_title: TITLE.into(),
                heading: match action {
                    Action::SetUp => "Make these changes?".into(),
                    Action::PutBack => "Put these values back?".into(),
                },
                intro,
                sections: vec![Section {
                    heading: None,
                    items,
                }],
                accept: action.name().into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_CHANGE,
        })
    }

    fn copy_text(&self) -> String {
        let mut lines: Vec<String> = self.items().iter().map(item_text).collect();
        if let Some((action, result)) = &self.last {
            lines.push(String::new());
            lines.push(result_text(action.name(), result));
        }
        lines.join("\r\n")
    }

    fn finish(&mut self, hwnd: HWND, done: Done) {
        match done {
            Done::Check(check) => {
                self.status = match &check.outcome {
                    Outcome::Stopped => ("Stopped.".into(), Tone::Neutral),
                    _ => {
                        let needs = check
                            .items
                            .iter()
                            .filter(|i| matches!(i.status, Status::NeedsChange { .. }))
                            .count();
                        let unread = check
                            .items
                            .iter()
                            .filter(|i| matches!(i.status, Status::CouldNotRead { .. }))
                            .count();
                        match (needs, unread) {
                            (0, 0) => (
                                "Ready: the next crash leaves a dump to read.".into(),
                                Tone::Ok,
                            ),
                            (0, n) => (
                                format!("Nothing needs a change; {n} could not be read."),
                                Tone::Neutral,
                            ),
                            (n, _) => (
                                format!(
                                    "{n} {} a change.",
                                    if n == 1 { "item needs" } else { "items need" }
                                ),
                                Tone::Warn,
                            ),
                        }
                    }
                };
                self.check = Some(check);
            }
            Done::Preview(action, result) => {
                self.preview = Some((action, result));
                unsafe { PostMessageW(hwnd, WM_COMMAND, ASK, 0) };
            }
            Done::Changed(action, result) => {
                self.status = (
                    match &result.outcome {
                        Outcome::Done if result.restart_needed => format!(
                            "{}: done. Kernel settings take effect after Windows next restarts.",
                            action.name()
                        ),
                        Outcome::Done => format!("{}: done.", action.name()),
                        _ => format!("{}: see the details below.", action.name()),
                    },
                    if result.outcome == Outcome::Done {
                        Tone::Ok
                    } else {
                        Tone::Warn
                    },
                );
                self.last = Some((action, result));
                if let Some(c) = &self.controls {
                    toolwin::select(c.items, None);
                }
                // Read again, so the list shows what is set now.
                self.start_check();
            }
        }
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    /// An item's two parts: its name and state, then its reason or summary.
    fn item_lines(item: &Item) -> (String, &str) {
        (
            format!("{}  ·  {}", item.label, item.status.word()),
            item.status.reason().unwrap_or(&item.summary),
        )
    }

    /// Each item's height at a list `width` pixels wide, its two parts wrapped.
    fn item_heights(&self, list: HWND, width: i32, dpi: u32) -> Vec<i32> {
        let fonts = ui::fonts(dpi);
        let text_w = width - scale(dpi, 28 + 8);
        self.items()
            .iter()
            .map(|item| {
                let (head, about) = Self::item_lines(item);
                ui::text_height(list, fonts.body, &head, text_w)
                    + ui::text_height(list, fonts.caption, about, text_w)
                    + scale(dpi, 10)
            })
            .collect()
    }

    fn refresh_items(&self) {
        if let Some(c) = &self.controls {
            let texts: Vec<String> = self.items().iter().map(item_text).collect();
            toolwin::set_items(c.items, &texts, true);
        }
    }
}

/// Shares `free` pixels between the item list and the details box: the list takes what its
/// items need while the details box keeps `details_min`, and the details box takes the rest.
/// Neither goes below its floor.
fn split(
    free: i32,
    list_pref: i32,
    details_min: i32,
    list_floor: i32,
    details_floor: i32,
) -> (i32, i32) {
    let list_h = list_pref.min(free - details_min).max(list_floor);
    (list_h, (free - list_h).max(details_floor))
}

impl Page for CrashDumpView {
    fn title(&self) -> String {
        TITLE.into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        if self.elevated {
            ((860, 800), (680, 680))
        } else {
            ((760, 640), (600, 520))
        }
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::CRASH_DUMPS)
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let option_ids: &[usize] = if self.elevated {
            &[
                SIDES,
                KERNEL_TYPE,
                RESTART,
                DUMP_FILE,
                MINIDUMPS,
                APP_FOLDER,
                APP_TYPE,
                APP_COUNT,
            ]
        } else {
            &[]
        };
        let controls = Controls {
            title: text(Kind::Title, TITLE),
            subtitle: text(Kind::Muted, ""),
            items: toolwin::list_wrapping(hwnd, ITEMS, 44),
            details: ui::selectable_scrolling(hwnd, ""),
            options: option_ids
                .iter()
                .map(|id| (*id, ui::button(hwnd, *id, Kind::Secondary, "")))
                .collect(),
            status: text(Kind::Body, ""),
            set_up: ui::button(hwnd, SET_UP, Kind::Primary, "Set up…"),
            put_back: ui::button(hwnd, PUT_BACK, Kind::Secondary, "Put back…"),
            as_admin: ui::button(
                hwnd,
                AS_ADMIN,
                Kind::Primary,
                "Change settings as administrator…",
            ),
            check: ui::button(hwnd, CHECK, Kind::Secondary, "Check again"),
            copy: ui::button(hwnd, COPY, Kind::Secondary, "Copy"),
            close: ui::button(hwnd, CLOSE, Kind::Ghost, "Close"),
        };
        ui::show(controls.set_up, self.elevated);
        ui::show(controls.put_back, self.elevated);
        ui::show(controls.as_admin, !self.elevated);
        let body = ui::fonts(ui::dpi_of(hwnd)).body;
        ui::set_font(controls.items, body);
        ui::set_font(controls.details, body);
        self.controls = Some(controls);
        self.render();
    }

    fn layout(&mut self, hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        let (bh, gap) = (f.s(grid::BUTTON_H), f.s(grid::BUTTON_GAP));
        let pad = f.s(6);
        let inset = f.s(grid::CARD_PAD);
        f.header(c.title, c.subtitle);
        f.space(2);
        // Each item wraps to its own height, so no reason is cut short.
        let heights = self.item_heights(c.items, f.w - 2 * pad, dpi);
        toolwin::set_heights(c.items, &heights);
        // Below the two boxes: the options, the status and the footer.
        let options_h = if c.options.is_empty() {
            0
        } else {
            4 * bh + 3 * gap + f.s(12)
        };
        let status_h = f.text_h(c.status, f.w);
        let below = f.s(12) + options_h + status_h + toolwin::footer_h(dpi);
        // The list takes the room its items need, keeping six lines for the details box;
        // the details box takes the rest. When the window opens, both show in full.
        let details_min = f.s(grid::BODY_H) * 6 + f.s(20);
        let list_pref = heights.iter().sum::<i32>().max(f.s(44) * 3) + 2 * pad;
        self.natural = Some(f.y + list_pref + f.s(10) + details_min + below);
        let free = (h - below - f.y - f.s(10)).max(f.s(200));
        let (list_h, details_h) = split(free, list_pref, details_min, f.s(120), f.s(80));
        let list = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: list_h,
        };
        ui::place(
            c.items,
            Rect {
                x: f.x + pad,
                y: f.y + pad,
                w: f.w - 2 * pad,
                h: list_h - 2 * pad,
            },
        );
        f.y += list_h;
        f.space(10);
        let details = Rect {
            x: f.x,
            y: f.y,
            w: f.w,
            h: details_h,
        };
        ui::place(
            c.details,
            Rect {
                x: f.x + inset,
                y: f.y + f.s(10),
                w: f.w - 2 * inset,
                h: details_h - f.s(20),
            },
        );
        f.y += details_h;
        f.space(12);
        if !c.options.is_empty() {
            // Four rows: what to change and the kernel type; restart; the two kernel
            // places; the application folder, type and count.
            let rows: [&[usize]; 4] = [
                &[SIDES, KERNEL_TYPE, RESTART],
                &[DUMP_FILE],
                &[MINIDUMPS],
                &[APP_FOLDER, APP_TYPE, APP_COUNT],
            ];
            for row in rows {
                let buttons: Vec<HWND> = row
                    .iter()
                    .filter_map(|id| c.options.iter().find(|(i, _)| i == id).map(|(_, b)| *b))
                    .collect();
                f.buttons(&buttons, grid::BUTTON_GAP);
            }
            f.space(12 - grid::BUTTON_GAP);
        }
        f.text(c.status, 0);
        toolwin::footer(
            w,
            h,
            dpi,
            &[c.set_up, c.put_back, c.as_admin, c.check, c.copy],
            &[c.close],
        );
        ui::set_cards(hwnd, vec![list, details]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            ITEMS if code == LBN_SELCHANGE || code == toolwin::ACTIVATE => {}
            SIDES | KERNEL_TYPE | RESTART | DUMP_FILE | MINIDUMPS | APP_FOLDER | APP_TYPE
            | APP_COUNT => {
                self.choose(hwnd, id);
            }
            SET_UP if self.running.is_none() => self.start_change(Action::SetUp, false),
            PUT_BACK if self.running.is_none() => self.start_change(Action::PutBack, false),
            ASK => ask = self.ask(),
            DO_CHANGE => {
                if let Some((action, _)) = self.preview.take() {
                    self.start_change(action, true);
                }
            }
            CHECK => match &self.running {
                Some(run) => run.cancel.store(true, Ordering::Relaxed),
                None => self.start_check(),
            },
            AS_ADMIN => {
                self.status = match launch_elevated(hwnd) {
                    Ok(()) => (
                        "The administrator window is open. Check again here once it is closed."
                            .into(),
                        Tone::Neutral,
                    ),
                    Err(why) => (why, Tone::Warn),
                }
            }
            COPY => {
                if !ui::copy_to_clipboard(hwnd, &self.copy_text()) {
                    self.status = ("Windows did not allow copying.".into(), Tone::Warn);
                }
            }
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        // A declined confirmation leaves the preview; it is dropped so a later Set up asks anew.
        if id != ASK && id != DO_CHANGE {
            self.preview = None;
        }
        self.render();
        self.relayout(hwnd);
        ask
    }

    fn tick(&mut self, hwnd: HWND) {
        let mut changed = false;
        let mut finished = None;
        let mut lost = None;
        if let Some(run) = &self.running {
            while let Some(message) = toolwin::poll_result(&run.messages) {
                let message = match message {
                    Ok(message) => message,
                    Err(why) => {
                        lost = Some(why);
                        break;
                    }
                };
                match message {
                    Message::Event(Event::Item { item }) => {
                        self.live_items.push(item);
                        changed = true;
                    }
                    Message::Event(Event::Step { text }) => self.status = (text, Tone::Neutral),
                    Message::Event(Event::Changed { change }) => {
                        self.status = (change.text, Tone::Neutral)
                    }
                    Message::Done(done) => {
                        finished = Some(done);
                        break;
                    }
                }
            }
        }
        if let Some(why) = lost {
            let worker = self.running.take().and_then(|mut run| run.worker.take());
            let why = toolwin::without_result(why, worker);
            self.status = (
                format!(
                    "{why} What it changed is not known: check again to see the settings as they \
                     are now."
                ),
                Tone::Warn,
            );
            changed = true;
        }
        if let Some(done) = finished {
            if let Some(mut run) = self.running.take() {
                if let Some(worker) = run.worker.take() {
                    let _ = worker.join();
                }
            }
            self.finish(hwnd, done);
            changed = true;
        }
        if changed {
            self.refresh_items();
        }
        self.render();
        self.relayout(hwnd);
    }

    fn draw_item(&self, _list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        let Some(item) = self.items().get(index) else {
            return;
        };
        let colors = ui::current();
        let fonts = ui::fonts(state.dpi);
        let s = |v: i32| scale(state.dpi, v);
        ui::fill_rect(dc, rect, colors.card);
        let canvas = ui::Canvas::new(dc);
        let fill = if state.selected {
            colors.raised_hover
        } else if state.hot {
            colors.raised
        } else {
            colors.card
        };
        if let Some(canvas) = &canvas {
            if fill != colors.card {
                canvas.fill_round(
                    (
                        rect.left as f32,
                        (rect.top + s(1)) as f32,
                        (rect.right - rect.left) as f32,
                        (rect.bottom - rect.top - s(2)) as f32,
                    ),
                    s(6) as f32,
                    fill,
                );
            }
            let dot = match tone(&item.status) {
                Tone::Ok => colors.ok,
                Tone::Warn => colors.warn,
                _ => colors.subtle,
            };
            canvas.circle(
                (rect.left + s(14)) as f32,
                (rect.top + s(14)) as f32,
                s(4) as f32,
                dot,
            );
        }
        let left = rect.left + s(28);
        let (head, about) = Self::item_lines(item);
        let width = rect.right - s(8) - left;
        let head_h = ui::text_height(std::ptr::null_mut(), fonts.body, &head, width);
        let top = rect.top + s(5);
        ui::draw_text(
            dc,
            &head,
            &RECT {
                left,
                top,
                right: rect.right - s(8),
                bottom: top + head_h,
            },
            fonts.body,
            colors.text,
            DT_WORDBREAK,
        );
        ui::draw_text(
            dc,
            about,
            &RECT {
                left,
                top: top + head_h,
                right: rect.right - s(8),
                bottom: rect.bottom,
            },
            fonts.caption,
            colors.muted,
            DT_WORDBREAK,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::tools::crash_dumps::Change;

    /// The item list shows every item when there is room, and the details box takes what
    /// is left rather than a fixed share that leaves the list scrolling.
    #[test]
    fn the_item_list_gets_the_room_its_items_need() {
        // Room for both: the list in full, the details box the rest.
        assert_eq!(split(900, 600, 140, 120, 80), (600, 300));
        // Cramped: the details box keeps its six lines, the list scrolls.
        assert_eq!(split(500, 600, 140, 120, 80), (360, 140));
        // Very cramped: neither goes below its floor.
        assert_eq!(split(200, 600, 140, 120, 80), (120, 80));
    }

    fn change(text: &str) -> Change {
        Change {
            target: "HKLM\\x\\y".into(),
            before: "absent".into(),
            after: "1 (on)".into(),
            text: text.into(),
            needs_restart: true,
        }
    }

    #[test]
    fn the_administrator_copy_is_started_with_the_record_and_reads_it_back() {
        let record =
            std::path::Path::new(r"C:\Users\a b\AppData\Local\Temp\DiagnosticTool-changes-12.txt");
        let args = elevated_args(Some(record));
        assert_eq!(
            args,
            r#"--crash-dumps --record "C:\Users\a b\AppData\Local\Temp\DiagnosticTool-changes-12.txt""#
        );
        assert_eq!(elevated_args(None), "--crash-dumps");
        assert!(!run_if_asked(&["DiagnosticTool.exe".into()]));
    }

    #[test]
    fn a_failed_set_up_lists_what_changed_and_how_to_undo_it() {
        let result = ChangeResult {
            outcome: Outcome::Failed {
                reason: "DumpType could not be changed: access denied".into(),
            },
            planned: Vec::new(),
            changed: vec![change(
                "Keep the memory dump when space is low: absent to 1 (on)",
            )],
            notes: vec!["A note.".into()],
            restart_needed: true,
            backup: PathBuf::from(r"C:\ProgramData\DiagnosticTool\crash-dump-settings-before.json"),
        };
        let text = result_text("Set up", &result);
        assert_eq!(
            text,
            "Set up did not finish: DumpType could not be changed: access denied.\r\n\r\nChanged:\r\n  Keep the memory dump when space is low: absent to 1 (on)\r\nPut back undoes these changes.\r\n\r\nA note."
        );
    }

    #[test]
    fn refusals_say_nothing_was_changed() {
        let result = ChangeResult {
            outcome: Outcome::Refused {
                reasons: vec!["One".into(), "Two".into()],
            },
            planned: Vec::new(),
            changed: Vec::new(),
            notes: Vec::new(),
            restart_needed: false,
            backup: PathBuf::new(),
        };
        assert_eq!(
            result_text("Set up", &result),
            "Set up was not done, and nothing was changed:\r\n  One\r\n  Two"
        );
    }

    #[test]
    fn items_read_with_their_status_and_reason() {
        let item = Item {
            id: "kernel.keep".into(),
            label: "Memory dump kept when space is low".into(),
            status: Status::NeedsChange {
                reason: "Windows deletes MEMORY.DMP".into(),
            },
            summary: "AlwaysKeepMemoryDump is not 1".into(),
            details: vec!["Detail".into()],
        };
        assert_eq!(
            item_text(&item),
            "Memory dump kept when space is low: Needs a change. AlwaysKeepMemoryDump is not 1"
        );
        assert_eq!(
            item_details(&item),
            "Memory dump kept when space is low: Needs a change\r\nWindows deletes MEMORY.DMP\r\n\r\nAlwaysKeepMemoryDump is not 1\r\nDetail"
        );
    }
}
