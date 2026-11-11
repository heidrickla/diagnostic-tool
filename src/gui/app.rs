//! The status window: runs the consented session, shows each check, saves the report.
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use diagnostics::checks::{self, Grade, Outcome};
use diagnostics::session::{CheckState, EndReason, Phase, Session};
use diagnostics::ui_layout::{self, grid, main_layout, scale, Rect};
use diagnostics::{change_record, inventory_view, report, site, update};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetStockObject, InvalidateRect, SetBkColor, SetDCBrushColor, SetTextColor, DC_BRUSH, HDC,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::AdjustWindowRectExForDpi;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::dialog::{self, Dialog, Item, Section};
use crate::help_pane;
use crate::remote::{self, RemoteEvent, RemoteLink};
use crate::ui::{self, wide, Kind, Tone};

pub const CLASS: &str = "DiagnosticToolWindow";
const SESSION_TIME: Duration = Duration::from_secs(300);
const STYLE: u32 = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
const EX_STYLE: u32 = WS_EX_CONTROLPARENT;
const TICK: usize = 1;
/// Control ids of rows that open a tool: ROW_BASE plus the row's index.
const ROW_BASE: usize = 1024;
const SPIN: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    // Above IDOK and IDCANCEL, which IsDialogMessage sends for Enter and Escape.
    Pause = 256,
    Stop,
    Open,
    Folder,
    SaveAs,
    Hardware,
    Close,
    Update,
}

const ACTIONS: [Action; 8] = [
    Action::Pause,
    Action::Stop,
    Action::Open,
    Action::Folder,
    Action::SaveAs,
    Action::Hardware,
    Action::Close,
    Action::Update,
];

/// Buttons in one group: action, caption and whether it is enabled.
type ButtonLine = Vec<(Action, String, bool)>;

struct Running {
    id: &'static str,
    cancel: Arc<AtomicBool>,
    result: mpsc::Receiver<Outcome>,
}

/// The self-update: a background check at start, then a download the user asks for.
enum Update {
    Off,
    Checking(mpsc::Receiver<Option<update::Release>>),
    Available(update::Release),
    Installing(mpsc::Receiver<Result<PathBuf, String>>),
}

enum Saved {
    NotStarted,
    Saving(mpsc::Receiver<Result<PathBuf, String>>),
    Done(PathBuf),
    Failed(String),
}

#[derive(Default)]
enum Link {
    #[default]
    Off,
    Starting,
    Code(String),
    Paired,
    Retrying,
}

struct Controls {
    title: HWND,
    badge: HWND,
    subtitle: HWND,
    progress_left: HWND,
    progress_right: HWND,
    progress: HWND,
    rows: Vec<HWND>,
    message: HWND,
    footer: HWND,
    buttons: Vec<(Action, HWND)>,
}

struct App {
    hwnd: HWND,
    session: Session,
    running: Option<Running>,
    saved: Saved,
    remote: Option<RemoteLink>,
    link: Link,
    activity: String,
    /// Why Open report or Show in folder did not work, shown until the next try.
    notice: Option<String>,
    update: Update,
    controls: Controls,
    /// Visible buttons and captions last laid out, to relayout only on change.
    button_plan: Vec<(Action, String)>,
    /// The change record's size when the report was last saved; a larger record saves a
    /// new report, so every change made after the checks is in one.
    recorded: u64,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

/// Runs an action on the app unless a nested message loop already holds it.
fn with_app<T>(action: impl FnOnce(&mut App) -> T) -> Option<T> {
    APP.with(|cell| {
        let mut borrowed = cell.try_borrow_mut().ok()?;
        borrowed.as_mut().map(action)
    })
}

impl App {
    fn connection_text() -> String {
        match site::support_host() {
            Some(host) if remote::remote_enabled() => format!(
                "Support session through {host} with {}'s verified account.",
                site::operator()
            ),
            _ => "Local checks only. Nothing was uploaded or shared.".into(),
        }
    }

    fn start_check(&mut self, id: &'static str) {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, result) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(checks::run_check(id, worker_cancel));
        });
        self.activity = format!("Checking {}.", checks::label(id).to_lowercase());
        self.running = Some(Running { id, cancel, result });
    }

    fn cancel_running(&self) {
        if let Some(running) = &self.running {
            running.cancel.store(true, Ordering::SeqCst);
        }
        if let Some(remote) = &self.remote {
            remote.cancel_current.store(true, Ordering::SeqCst);
        }
    }

    fn end(&mut self, reason: EndReason) {
        if self.session.end(reason) {
            self.cancel_running();
        }
        if let Some(remote) = &self.remote {
            remote.stop.store(true, Ordering::SeqCst);
            remote.cancel_current.store(true, Ordering::SeqCst);
            remote.consent.store(false, Ordering::SeqCst);
        }
    }

    fn save_report(&mut self, destination: Option<PathBuf>) {
        let session = self.session.clone();
        self.recorded = change_record::size();
        let repair = change_record::report_text(change_record::file());
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let details = diagnostics::tools::cpu_memory::details(&Default::default());
            let connection = App::connection_text();
            let report = report::Report {
                session: &session,
                version: env!("CARGO_PKG_VERSION"),
                connection: &connection,
                repair: &repair,
                details: Some(&details),
            };
            let result = match destination {
                Some(path) => report::save_pdf_at(&path, &report),
                None => report_folder().and_then(|folder| report::save_pdf_in(&folder, &report)),
            };
            let _ = sender.send(result.map_err(|error| error.to_string()));
        });
        self.saved = Saved::Saving(receiver);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if let Some(running) = &self.running {
            let outcome = match running.result.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Outcome::Unavailable("stopped unexpectedly".into()))
                }
            };
            if let Some(outcome) = outcome {
                let id = running.id;
                self.activity = match &outcome {
                    Outcome::Unavailable(reason) => {
                        format!("{} could not run: {reason}.", checks::label(id))
                    }
                    _ => String::new(),
                };
                self.session.finish(id, outcome, now);
                self.running = None;
            }
        }
        if self.session.tick(now).is_some() {
            self.cancel_running();
        }
        self.remote_events();
        if self.running.is_none() {
            if let Some(id) = self.session.start_next(now) {
                self.start_check(id);
            }
        }
        if remote::remote_enabled()
            && self.remote.is_none()
            && !self.session.is_ended()
            && self.session.progress().0 == self.session.progress().1
        {
            self.remote = Some(remote::spawn_remote());
            self.link = Link::Starting;
        }
        if self.session.is_ended() && self.running.is_none() {
            if let Saved::NotStarted = self.saved {
                self.save_report(None);
            }
        }
        self.poll_update();
        if let Saved::Saving(receiver) = &self.saved {
            match receiver.try_recv() {
                Ok(Ok(path)) => self.saved = Saved::Done(path),
                Ok(Err(reason)) => self.saved = Saved::Failed(reason),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.saved = Saved::Failed("the report writer stopped unexpectedly".into())
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if matches!(self.saved, Saved::Done(_)) && change_record::size() > self.recorded {
            self.save_report(None);
        }
        self.render();
    }

    fn poll_update(&mut self) {
        match &self.update {
            Update::Checking(receiver) => match receiver.try_recv() {
                Ok(Some(release)) => self.update = Update::Available(release),
                Ok(None) | Err(mpsc::TryRecvError::Disconnected) => self.update = Update::Off,
                Err(mpsc::TryRecvError::Empty) => {}
            },
            Update::Installing(receiver) => match receiver.try_recv() {
                Ok(Ok(program)) => {
                    // The new copy waits for this process to end before it opens.
                    let started = std::process::Command::new(&program)
                        .arg("--after-update")
                        .arg(std::process::id().to_string())
                        .spawn();
                    match started {
                        Ok(_) => unsafe {
                            DestroyWindow(self.hwnd);
                        },
                        Err(error) => {
                            self.notice = Some(format!(
                                "The update is installed. Start the Diagnostic Tool again to use it ({error})."
                            ));
                            self.update = Update::Off;
                        }
                    }
                }
                Ok(Err(reason)) => {
                    self.notice = Some(format!("The update did not install: {reason}."));
                    self.update = Update::Off;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.notice = Some("The update stopped unexpectedly.".into());
                    self.update = Update::Off;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            },
            Update::Off | Update::Available(_) => {}
        }
    }

    /// Downloads, verifies and installs the release in the background.
    fn start_update(&mut self) {
        let (Update::Available(release), Some(source)) = (&self.update, update::SOURCE.as_ref())
        else {
            return;
        };
        let release = release.clone();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = std::env::current_exe()
                .map_err(|error| format!("this program's location is unknown ({error})"))
                .and_then(|program| {
                    let bytes = update::download(source, &release)?;
                    update::install(&program, &bytes, &release)?;
                    Ok(program)
                });
            let _ = sender.send(result);
        });
        self.notice = None;
        self.update = Update::Installing(receiver);
    }

    fn remote_events(&mut self) {
        let events: Vec<_> = self
            .remote
            .as_ref()
            .map(|link| link.events.try_iter().collect())
            .unwrap_or_default();
        for event in events {
            match event {
                RemoteEvent::Started(code) => self.link = Link::Code(code),
                RemoteEvent::Paired | RemoteEvent::Recovered => self.link = Link::Paired,
                RemoteEvent::Retrying => self.link = Link::Retrying,
                RemoteEvent::Activity(message) => self.activity = message,
                RemoteEvent::Ended(reason) => {
                    self.link = Link::Off;
                    self.end(EndReason::ConnectionEnded(reason));
                }
            }
        }
    }

    fn toggle_pause(&mut self) {
        match self.session.phase() {
            Phase::Running => {
                if self.session.pause() {
                    self.cancel_running();
                }
                self.activity =
                    "Paused. The check that was running will start again when you resume.".into();
            }
            Phase::Paused => {
                self.session.resume();
                self.activity.clear();
            }
            Phase::Ended(_) => {}
        }
        if let Some(remote) = &self.remote {
            let paused = *self.session.phase() == Phase::Paused;
            remote.pause.store(paused, Ordering::SeqCst);
        }
        self.render();
    }

    fn status(&self) -> (Tone, String, String) {
        let remote_status = match &self.link {
            Link::Code(code) => Some((
                Tone::Running,
                format!("Waiting for {}", site::operator()),
                format!("Read this code to {}: {code}", site::operator()),
            )),
            Link::Paired => Some((
                Tone::Ok,
                format!("Connected to {}", site::operator()),
                format!(
                    "{} is connected. You can keep using your computer.",
                    site::operator_first()
                ),
            )),
            Link::Retrying => Some((
                Tone::Warn,
                "Reconnecting".into(),
                "The connection was interrupted. No new checks run until it returns.".into(),
            )),
            Link::Starting => Some((
                Tone::Running,
                "Connecting".into(),
                format!("Connecting to {}'s support service.", site::operator()),
            )),
            Link::Off => None,
        };
        match (self.session.phase(), &self.saved) {
            (Phase::Paused, _) => (
                Tone::Warn,
                "Paused".into(),
                "Paused. Nothing new starts until you resume.".into(),
            ),
            (Phase::Running, _) => remote_status.unwrap_or((
                Tone::Running,
                "Checking".into(),
                "Read-only checks are running. You can keep using your computer.".into(),
            )),
            (Phase::Ended(_), Saved::NotStarted | Saved::Saving(_)) => (
                Tone::Running,
                "Saving".into(),
                "Saving your findings report.".into(),
            ),
            (Phase::Ended(reason), Saved::Done(_)) => (
                if *reason == EndReason::Completed {
                    Tone::Ok
                } else {
                    Tone::Neutral
                },
                match reason {
                    EndReason::Completed => "Finished",
                    EndReason::Stopped => "Stopped",
                    _ => "Session ended",
                }
                .into(),
                "Your findings report is saved in Documents.".into(),
            ),
            (Phase::Ended(_), Saved::Failed(_)) => (
                Tone::Warn,
                "Not saved".into(),
                "The findings report could not be saved.".into(),
            ),
        }
    }

    fn message(&self) -> (Tone, String) {
        match &self.saved {
            _ if self.notice.is_some() => (Tone::Warn, self.notice.clone().unwrap_or_default()),
            Saved::Done(path) => (
                Tone::Neutral,
                ui_layout::saved_lines(&path.to_string_lossy(), 60),
            ),
            Saved::Failed(reason) => (
                Tone::Warn,
                format!("{reason}. Choose Save report as to pick another folder."),
            ),
            _ => (Tone::Neutral, self.activity.clone()),
        }
    }

    fn buttons(&self) -> (ButtonLine, ButtonLine) {
        let has_inventory = !self.session.inventory().is_empty();
        let mut right = vec![(Action::Hardware, "View hardware".into(), has_inventory)];
        let left = match (&self.session.phase(), &self.saved) {
            (Phase::Running | Phase::Paused, _) => {
                let pause = if *self.session.phase() == Phase::Paused {
                    "Resume"
                } else {
                    "Pause"
                };
                vec![
                    (Action::Pause, pause.into(), true),
                    (Action::Stop, "Stop".into(), true),
                ]
            }
            (Phase::Ended(_), Saved::Failed(_)) => {
                vec![(Action::SaveAs, "Save report as".into(), true)]
            }
            (Phase::Ended(_), saved) => {
                let ready = matches!(saved, Saved::Done(_));
                vec![
                    (Action::Open, "Open report".into(), ready),
                    (Action::Folder, "Show in folder".into(), ready),
                ]
            }
        };
        if self.session.is_ended() {
            let closable = !matches!(self.saved, Saved::NotStarted | Saved::Saving(_));
            right.push((Action::Close, "Close".into(), closable));
        }
        (left, right)
    }

    fn render(&mut self) {
        let c = &self.controls;
        let (tone, badge, subtitle) = self.status();
        ui::set_tone(c.badge, tone);
        ui::set_text(c.badge, &badge);
        ui::set_text(c.subtitle, &subtitle);
        let (done, total) = self.session.progress();
        ui::set_text(c.progress_left, &format!("{done} of {total} checks"));
        ui::set_value(c.progress, (done * 1000 / total.max(1)) as u32);
        ui::set_text(c.progress, &format!("{done} of {total} checks complete"));
        let remaining = self.session.remaining(Instant::now()).as_secs();
        let right = if self.session.is_ended() {
            String::new()
        } else {
            format!("Session ends in {}:{:02}", remaining / 60, remaining % 60)
        };
        ui::set_text(c.progress_right, &right);
        for (row, hwnd) in self.session.rows().iter().zip(&c.rows) {
            let (tone, brief) = match &row.state {
                CheckState::Waiting => (Tone::Waiting, "Waiting".to_string()),
                CheckState::Running => (Tone::Running, "Checking".to_string()),
                CheckState::NotRun => (Tone::NotRun, "Not run".to_string()),
                CheckState::Done { outcome, .. } => match outcome {
                    Outcome::Found(finding) => (
                        match finding.grade {
                            Grade::Serious => Tone::Serious,
                            Grade::Flagged => Tone::Flag,
                            Grade::Clear => Tone::Ok,
                        },
                        finding.brief.clone(),
                    ),
                    Outcome::Unavailable(_) => (Tone::Unavailable, "Unavailable".to_string()),
                    Outcome::Stopped => (Tone::NotRun, "Not run".to_string()),
                },
            };
            ui::set_tone(*hwnd, tone);
            ui::set_text(*hwnd, &format!("{}: {brief}", row.label));
        }
        let (message_tone, message) = self.message();
        ui::set_tone(c.message, message_tone);
        ui::set_text(c.message, &message);
        let (left, right) = self.buttons();
        let plan: Vec<_> = left
            .iter()
            .chain(&right)
            .map(|(action, caption, _)| (*action, caption.clone()))
            .collect();
        for (action, hwnd) in &c.buttons {
            let entry = left.iter().chain(&right).find(|(a, _, _)| a == action);
            ui::show(*hwnd, entry.is_some());
            if let Some((_, caption, enabled)) = entry {
                ui::set_text(*hwnd, caption);
                ui::enable(*hwnd, *enabled);
                let primary = matches!(action, Action::Open | Action::SaveAs);
                let ghost = *action == Action::Hardware;
                ui::set_kind(
                    *hwnd,
                    if primary {
                        Kind::Primary
                    } else if ghost {
                        Kind::Ghost
                    } else {
                        Kind::Secondary
                    },
                );
            }
        }
        if let Some(hwnd) = self.button(Action::Update) {
            let ended = self.session.is_ended()
                && !matches!(self.saved, Saved::NotStarted | Saved::Saving(_));
            let (visible, caption, enabled) = match &self.update {
                Update::Available(release) => {
                    (true, format!("Update to {}", release.version), ended)
                }
                Update::Installing(_) => (true, "Updating".to_string(), false),
                Update::Off | Update::Checking(_) => (false, String::new(), false),
            };
            ui::show(hwnd, visible);
            if visible {
                ui::set_text(hwnd, &caption);
                ui::enable(hwnd, enabled);
                ui::set_kind(hwnd, Kind::Update);
                self.place_update(hwnd, &caption);
            }
        }
        if plan != self.button_plan {
            self.button_plan = plan;
            self.layout();
            let first = left
                .first()
                .and_then(|(action, _, enabled)| enabled.then(|| self.button(*action)).flatten());
            if let Some(first) = first {
                unsafe { SetFocus(first) };
            }
        }
        let spinning = self.running.is_some() || matches!(self.saved, Saved::Saving(_));
        unsafe {
            if spinning {
                SetTimer(self.hwnd, SPIN, 50, None);
            } else {
                KillTimer(self.hwnd, SPIN);
            }
        }
    }

    fn button(&self, action: Action) -> Option<HWND> {
        self.controls
            .buttons
            .iter()
            .find(|(a, _)| *a == action)
            .map(|(_, hwnd)| *hwnd)
    }

    /// The update button sits right-aligned on the footer line, below Close.
    fn place_update(&self, hwnd: HWND, caption: &str) {
        let dpi = ui::dpi_of(self.hwnd);
        let layout = main_layout(dpi, self.controls.rows.len(), 2);
        let w = ui::button_width(self.hwnd, caption) + scale(dpi, ui::UPDATE_ICON + 8);
        let h = scale(dpi, grid::BUTTON_H);
        ui::place(
            hwnd,
            Rect {
                x: layout.footer.right() - w,
                y: layout.footer.y + (layout.footer.h - h) / 2,
                w,
                h,
            },
        );
    }

    /// Places every control for the window's DPI and fits the client area.
    fn layout(&self) {
        let dpi = ui::dpi_of(self.hwnd);
        let c = &self.controls;
        let layout = main_layout(dpi, c.rows.len(), 2);
        // The open help pane widens the window; the controls above keep their place.
        let client_w = layout.client_w + help_pane::room(self.hwnd, dpi);
        help_pane::place(self.hwnd, client_w, layout.client_h, dpi);
        ui::place(c.title, layout.title);
        let badge_w = ui::text_width(self.hwnd, ui::fonts(dpi).caption, &ui::window_text(c.badge))
            + scale(dpi, 34);
        let badge_w = badge_w.max(scale(dpi, 120));
        ui::place(
            c.badge,
            Rect {
                x: layout.badge_right - badge_w,
                y: layout.badge_y,
                w: badge_w,
                h: scale(dpi, grid::BADGE_H),
            },
        );
        ui::place(c.subtitle, layout.subtitle);
        ui::place(c.progress_left, layout.progress_label);
        ui::place(c.progress_right, layout.progress_label);
        ui::place(c.progress, layout.progress_bar);
        for (hwnd, rect) in c.rows.iter().zip(&layout.rows) {
            ui::place(*hwnd, *rect);
        }
        ui::place(c.message, layout.message);
        ui::place(c.footer, layout.footer);
        let widths = |set: &[(Action, String)]| -> Vec<i32> {
            set.iter()
                .map(|(_, caption)| ui::button_width(self.hwnd, caption))
                .collect()
        };
        let (left, right): (Vec<_>, Vec<_>) =
            self.button_plan.iter().cloned().partition(|(action, _)| {
                matches!(
                    action,
                    Action::Pause | Action::Stop | Action::Open | Action::Folder | Action::SaveAs
                )
            });
        let placed = ui_layout::place_buttons(
            dpi,
            &widths(&left),
            &widths(&right),
            layout.title.x,
            layout.client_w - 2 * layout.title.x,
            layout.buttons_y,
        );
        if let Some((left_rects, right_rects)) = placed {
            for ((action, _), rect) in left
                .iter()
                .zip(left_rects)
                .chain(right.iter().zip(right_rects))
            {
                if let Some(hwnd) = self.button(*action) {
                    ui::place(hwnd, rect);
                }
            }
        }
        if let Some(hwnd) = self.button(Action::Update) {
            self.place_update(hwnd, &ui::window_text(hwnd));
        }
        ui::set_cards(self.hwnd, vec![layout.card]);
        let mut frame = RECT {
            left: 0,
            top: 0,
            right: client_w,
            bottom: layout.client_h,
        };
        unsafe {
            AdjustWindowRectExForDpi(&mut frame, STYLE, 0, EX_STYLE, dpi);
            SetWindowPos(
                self.hwnd,
                std::ptr::null_mut(),
                0,
                0,
                frame.right - frame.left,
                frame.bottom - frame.top,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }

    fn hardware_dialog(&self) -> Dialog {
        let fields = self.session.inventory();
        let pairs = |lines: Vec<String>| -> Vec<Item> {
            lines
                .into_iter()
                .map(|line| match line.split_once(": ") {
                    Some((key, value)) => Item::Pair(key.into(), value.into()),
                    None => Item::Para(line),
                })
                .collect()
        };
        let items = pairs(inventory_view::summary(fields));
        let mut sections = vec![Section {
            heading: None,
            items,
        }];
        let parts = inventory_view::module_details(fields);
        if !parts.is_empty() {
            sections.push(Section {
                heading: Some("Memory modules".into()),
                items: pairs(parts),
            });
        }
        Dialog {
            window_title: "Hardware - Diagnostic Tool".into(),
            heading: "Hardware at a glance".into(),
            intro: "Reported by Windows. Before ordering parts, check the power supply, case size, connectors, cooling and compatibility by hand. Serial numbers are not collected.".into(),
            sections,
            accept: "Done".into(),
            decline: None,
            copy: Some("Copy all".into()),
        }
    }
}

/// Documents, or in debug builds a QA folder fixed at compile time.
fn report_folder() -> std::io::Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(folder) = option_env!("DIAGNOSTIC_QA_REPORT_FOLDER") {
        return Ok(PathBuf::from(folder));
    }
    report::documents_folder()
}

fn save_as_path(owner: HWND) -> Option<PathBuf> {
    use windows_sys::Win32::UI::Controls::Dialogs::{
        GetSaveFileNameW, OFN_NOREADONLYRETURN, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST,
        OPENFILENAMEW,
    };
    let mut file = [0u16; 1024];
    let initial = wide("Diagnostic-Tool-Findings.pdf");
    file[..initial.len()].copy_from_slice(&initial);
    let filter = wide("PDF files\0*.pdf\0");
    let title = wide("Save findings report as");
    let extension = wide("pdf");
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = owner;
    dialog.lpstrFilter = filter.as_ptr();
    dialog.nFilterIndex = 1;
    dialog.lpstrFile = file.as_mut_ptr();
    dialog.nMaxFile = file.len() as u32;
    dialog.lpstrTitle = title.as_ptr();
    dialog.lpstrDefExt = extension.as_ptr();
    dialog.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOREADONLYRETURN;
    if unsafe { GetSaveFileNameW(&mut dialog) } == 0 {
        return None;
    }
    let len = file.iter().position(|value| *value == 0)?;
    Some(PathBuf::from(String::from_utf16_lossy(&file[..len])))
}

/// ShellExecute's answer when no app is set to open the file type.
const SE_ERR_NOASSOC: isize = 31;

/// Opens a file or folder with its usual app; ShellExecute's result code, over 32 on success.
fn shell_open(owner: HWND, path: &std::path::Path) -> isize {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    unsafe {
        ShellExecuteW(
            owner,
            wide("open").as_ptr(),
            wide(&path.to_string_lossy()).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        ) as isize
    }
}

/// What to tell the user when the report could not be opened; `None` when it opened.
/// Starts the background check when this build has an update source.
fn start_update_check() -> Update {
    let Some(source) = update::SOURCE.as_ref() else {
        return Update::Off;
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // A failed check is silent: the tool works the same without it.
        let found = update::check(source, env!("CARGO_PKG_VERSION"))
            .ok()
            .flatten();
        let _ = sender.send(found);
    });
    Update::Checking(receiver)
}

fn open_problem(exists: bool, code: isize) -> Option<String> {
    if !exists {
        return Some(
            "The report is no longer in that folder; it was moved or deleted. Show in folder opens the folder."
                .into(),
        );
    }
    match code {
        33.. => None,
        SE_ERR_NOASSOC => Some(
            "No app on this PC is set to open PDF files. Show in folder finds the report, and a web browser can open it."
                .into(),
        ),
        code => Some(format!("Windows could not open the report (error {code}).")),
    }
}

fn open_report(owner: HWND, path: &std::path::Path) -> Option<String> {
    if !path.is_file() {
        return open_problem(false, 0);
    }
    open_problem(true, shell_open(owner, path))
}

/// Opens Explorer on the report's folder with the file selected, or on the folder alone
/// when the file is gone.
fn show_in_folder(owner: HWND, path: &std::path::Path) -> Option<String> {
    use windows_sys::Win32::UI::Shell::{ILCreateFromPathW, ILFree, SHOpenFolderAndSelectItems};
    let folder = path.parent().unwrap_or(path);
    if !path.is_file() {
        let opened = folder.is_dir() && shell_open(owner, folder) > 32;
        return Some(if opened {
            "The report is no longer in this folder; it was moved or deleted.".into()
        } else {
            format!("The folder {} could not be opened.", folder.display())
        });
    }
    let item = unsafe { ILCreateFromPathW(wide(&path.to_string_lossy()).as_ptr()) };
    let result = if item.is_null() {
        -1
    } else {
        let result = unsafe { SHOpenFolderAndSelectItems(item, 0, std::ptr::null(), 0) };
        unsafe { ILFree(item) };
        result
    };
    if result >= 0 || shell_open(owner, folder) > 32 {
        None
    } else {
        Some(format!(
            "Windows could not show the folder (error 0x{result:08X})."
        ))
    }
}

fn on_command(hwnd: HWND, id: usize) {
    if id >= ROW_BASE {
        let check =
            with_app(|app| app.session.rows().get(id - ROW_BASE).map(|row| row.id)).flatten();
        if let Some(check) = check {
            crate::tools::open(hwnd, check);
        }
        return;
    }
    let Some(action) = ACTIONS.iter().copied().find(|a| *a as usize == id) else {
        return;
    };
    match action {
        Action::Pause => {
            with_app(App::toggle_pause);
        }
        Action::Stop => {
            with_app(|app| {
                app.end(EndReason::Stopped);
                app.activity = "Stopping. The report will include every finished check.".into();
                app.render();
            });
        }
        Action::Open | Action::Folder => {
            let path = with_app(|app| match &app.saved {
                Saved::Done(path) => Some(path.clone()),
                _ => None,
            })
            .flatten();
            if let Some(path) = path {
                let notice = if action == Action::Open {
                    open_report(hwnd, &path)
                } else {
                    show_in_folder(hwnd, &path)
                };
                with_app(|app| {
                    app.notice = notice;
                    app.render();
                });
            }
        }
        Action::SaveAs => {
            if let Some(path) = save_as_path(hwnd) {
                with_app(|app| {
                    app.save_report(Some(path));
                    app.render();
                });
            }
        }
        Action::Hardware => {
            // Build the dialog, release the app, then run the modal loop.
            if let Some(content) = with_app(|app| app.hardware_dialog()) {
                dialog::show(hwnd, &content);
            }
        }
        Action::Close => unsafe {
            DestroyWindow(hwnd);
        },
        Action::Update => {
            with_app(|app| {
                app.start_update();
                app.render();
            });
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            ui::paint_surface(hwnd);
            0
        }
        WM_ERASEBKGND => 1,
        WM_MEASUREITEM => crate::toolwin::measure_item(hwnd, l),
        WM_DRAWITEM => help_pane::draw(hwnd, l).unwrap_or_else(|| ui::draw_item(l)),
        WM_CTLCOLORLISTBOX => {
            let colors = ui::current();
            SetTextColor(w as HDC, colors.text);
            SetBkColor(w as HDC, colors.card);
            SetDCBrushColor(w as HDC, colors.card);
            GetStockObject(DC_BRUSH) as LRESULT
        }
        WM_COMMAND => {
            match w & 0xFFFF {
                help_pane::BUTTON => help_pane::toggle(hwnd, |hwnd| {
                    with_app(|app| app.layout());
                    InvalidateRect(hwnd, std::ptr::null(), 1);
                }),
                // The pane's paragraphs are to read; a click on one does nothing.
                help_pane::LIST => {}
                id => on_command(hwnd, id),
            }
            0
        }
        WM_TIMER if w == TICK => {
            with_app(App::tick);
            0
        }
        WM_TIMER if w == SPIN => {
            ui::SPIN.fetch_add(24, Ordering::Relaxed);
            with_app(|app| {
                let row = app
                    .running
                    .as_ref()
                    .and_then(|r| app.session.rows().iter().position(|row| row.id == r.id));
                if let Some(index) = row {
                    InvalidateRect(app.controls.rows[index], std::ptr::null(), 0);
                }
            });
            0
        }
        WM_CLOSE => {
            // First close stops the session and saves; the window stays until the report exists.
            let close = with_app(|app| {
                if !app.session.is_ended() {
                    app.end(EndReason::Stopped);
                    app.render();
                    false
                } else {
                    !matches!(app.saved, Saved::NotStarted | Saved::Saving(_))
                }
            });
            if close == Some(true) {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DPICHANGED => {
            let suggested = &*(l as *const RECT);
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                suggested.left,
                suggested.top,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
            with_app(|app| app.layout());
            0
        }
        WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
            ui::refresh_palette();
            ui::style_frame(hwnd);
            InvalidateRect(hwnd, std::ptr::null(), 1);
            0
        }
        WM_DESTROY => {
            APP.with(|cell| {
                if let Ok(mut slot) = cell.try_borrow_mut() {
                    if let Some(mut app) = slot.take() {
                        app.end(EndReason::Stopped);
                        if let Some(mut remote) = app.remote.take() {
                            if let Some(worker) = remote.worker.take() {
                                let _ = worker.join();
                            }
                        }
                        if let Some(running) = app.running.take() {
                            let _ = running.result.recv_timeout(Duration::from_secs(2));
                        }
                    }
                }
            });
            crate::toolwin::close_all();
            help_pane::forget(hwnd);
            change_record::finish();
            ui::forget_window(hwnd);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

/// Creates the status window and starts the session. Returns the window handle.
pub fn open() -> Option<HWND> {
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let name = wide(CLASS);
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: crate::app_icon(),
        hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: name.as_ptr(),
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return None;
    }
    let hwnd = unsafe {
        CreateWindowExW(
            EX_STYLE,
            name.as_ptr(),
            wide("Diagnostic Tool").as_ptr(),
            STYLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            400,
            400,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return None;
    }
    ui::style_frame(hwnd);
    // A record that cannot be made leaves the report saying no repair was run, as before.
    let _ = change_record::start_for_this_process();
    let session = Session::new(Instant::now(), SESSION_TIME, remote::remote_enabled());
    let rows: Vec<HWND> = session
        .rows()
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let text = format!("{}: Waiting", row.label);
            if crate::tools::tool_for(row.id).is_some() {
                ui::row_button(hwnd, ROW_BASE + index, &text)
            } else {
                ui::text(hwnd, Kind::Row, Tone::Waiting, true, &text)
            }
        })
        .collect();
    if let Some(first) = rows.first() {
        ui::mark_first(*first);
    }
    let footer = format!(
        "Version {}  ·  {}",
        env!("CARGO_PKG_VERSION"),
        if remote::remote_enabled() {
            format!("Support session with {}", site::operator())
        } else {
            "Local checks only".into()
        }
    );
    let controls = Controls {
        title: ui::text(hwnd, Kind::Title, Tone::Neutral, false, "Diagnostic Tool"),
        badge: ui::text(hwnd, Kind::Badge, Tone::Running, false, "Checking"),
        subtitle: ui::text(hwnd, Kind::Muted, Tone::Neutral, false, ""),
        progress_left: ui::text(hwnd, Kind::Caption, Tone::Neutral, false, ""),
        progress_right: ui::text(hwnd, Kind::Caption, Tone::Waiting, false, ""),
        progress: ui::text(hwnd, Kind::Progress, Tone::Neutral, false, ""),
        rows,
        message: ui::text(hwnd, Kind::Muted, Tone::Neutral, false, ""),
        footer: ui::text(hwnd, Kind::Caption, Tone::Neutral, false, &footer),
        buttons: ACTIONS
            .iter()
            .map(|action| {
                (
                    *action,
                    ui::button(hwnd, *action as usize, Kind::Secondary, ""),
                )
            })
            .collect(),
    };
    help_pane::make(hwnd, crate::help::HUB);
    APP.with(|cell| {
        *cell.borrow_mut() = Some(App {
            hwnd,
            session,
            running: None,
            saved: Saved::NotStarted,
            remote: None,
            link: Link::Off,
            activity: String::new(),
            notice: None,
            update: start_update_check(),
            controls,
            button_plan: Vec::new(),
            recorded: 0,
        })
    });
    with_app(App::tick);
    // Centre on the monitor under the cursor once the DPI-correct size is known.
    let mut frame = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetWindowRect(hwnd, &mut frame) };
    let area = crate::dialog::work_area(hwnd);
    let (fw, fh) = (frame.right - frame.left, frame.bottom - frame.top);
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            area.left + ((area.right - area.left) - fw).max(0) / 2,
            area.top + ((area.bottom - area.top) - fh).max(0) / 2,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER,
        );
        SetTimer(hwnd, TICK, 250, None);
        ShowWindow(hwnd, SW_SHOW);
        // Focus rings appear only once the keyboard is used, as in Windows' own dialogs.
        SendMessageW(hwnd, WM_CHANGEUISTATE, UIS_INITIALIZE as usize, 0);
    }
    Some(hwnd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_that_will_not_open_says_why() {
        assert_eq!(open_problem(true, 42), None);
        let gone = open_problem(false, 42).expect("a moved report must be reported");
        assert!(gone.contains("moved or deleted"), "{gone}");
        let no_app = open_problem(true, SE_ERR_NOASSOC).expect("no PDF app must be reported");
        assert!(no_app.contains("No app on this PC is set to open PDF files"));
        let other = open_problem(true, 2).expect("a shell error must be reported");
        assert_eq!(other, "Windows could not open the report (error 2).");
    }
}
