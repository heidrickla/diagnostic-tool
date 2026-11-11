//! Calls that can block, run on a thread of their own with a time limit: opening a source
//! (its size, alignment and descriptor queries), reading a drive's health, and every
//! blocking call on a path that changes something (a drive's read limit, a BitLocker unlock,
//! lock or relock, a virtual disk made, attached or detached, a volume locked and
//! dismounted, a disk taken offline or brought online). A call that does not come back in
//! time is left to finish on its own thread and reported as not answering, so the window
//! and Stop keep working.
//!
//! A call that changes something is never simply left (`owned`): what undoes it travels
//! with the call, and when the call ends after its caller gave up, its late outcome is
//! handed to the undo on the call's own thread, which puts it back or records and says it.
//! A call that changes nothing (`in_time`) drops a late answer, as nothing needs undoing.
//!
//! Every change job, and every holder of a change undone later, is counted (`DUTIES`) from
//! the moment it starts until it and its whole undo have ended, and journalled
//! (`recovery::pending`): the process's end waits for each as long as it stated (`Job`),
//! and the next start settles what is left.
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::events::{self, Event, Figures, PauseKind};
use super::health_log::{self, Counts, HealthLog, Keep};
use super::image::{
    too_hot, wear_count, Ended, Outcome, Plan, Progress, Rescue, Settings, Watch, WearRate,
};
use super::pending::Pending;
use super::read_limit::{LimitEvent, ReadLimit};
use super::wait::{self, Waiter, Went};
use super::{open_source, BlockSource, SourceChoice};
use crate::tools::drives::device;
use crate::tools::drives::health::Disk;

/// How long opening a disk may take.
pub const OPEN_LIMIT: Duration = Duration::from_secs(30);
/// How long one health reading may take.
pub const HEALTH_LIMIT: Duration = Duration::from_secs(30);
/// How long the health reading after a run may take; Stop no longer cuts it short.
pub const END_LIMIT: Duration = Duration::from_secs(10);

/// How a timed call ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Waited<T> {
    Done(T),
    /// No answer within the limit (or the call failed without one).
    NoAnswer,
    /// Stop was asked for while waiting.
    Stopped,
}

/// Runs `call`, which changes nothing, on a thread of its own and waits up to `limit` for
/// its answer, or until `stop` is set. A call still running then is left to finish on its
/// own thread, and its answer is dropped. It is not counted: the process may end under it.
pub fn in_time<T, F>(limit: Duration, stop: Option<&AtomicBool>, call: F) -> Waited<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    bounded(limit, stop, call, drop, None)
}

/// A blocking call that changes something, as `owned` runs it, with the limits it states:
/// how long its caller waits (`limit`), the longest Windows or the drive is waited for at
/// the process's end (`answer`, never shorter than `limit`), and how long its undo takes
/// once the call has ended, the undo's own calls included (`undo`). `pending` is what the
/// next start puts back if this process ends, or is killed, before the job has ended.
#[derive(Clone, Debug)]
pub struct Job {
    what: String,
    limit: Duration,
    answer: Duration,
    undo: Duration,
    pending: Pending,
}

impl Job {
    /// A job its caller waits `limit` for; Windows is waited for as long at the end, and its
    /// undo takes no time, until said otherwise.
    pub fn new(what: impl Into<String>, limit: Duration) -> Self {
        Self {
            what: what.into(),
            limit,
            answer: limit,
            undo: Duration::ZERO,
            pending: Pending::Said,
        }
    }

    /// The longest the call itself is waited for at the process's end.
    pub fn answered_within(mut self, answer: Duration) -> Self {
        self.answer = answer.max(self.limit);
        self
    }

    /// How long the undo takes once the call has ended.
    pub fn undone_within(mut self, undo: Duration) -> Self {
        self.undo = undo;
        self
    }

    /// What the next start settles when the job has not ended by then.
    pub fn settled_by(mut self, pending: Pending) -> Self {
        self.pending = pending;
        self
    }

    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// The latest the call and its whole undo end, from its start.
    pub fn longest(&self) -> Duration {
        self.answer + self.undo
    }
}

/// When a duty is past waiting for at the process's end.
#[derive(Clone, Copy, Debug)]
enum Ends {
    /// A job counted and journalled whose call has not begun: its answer and undo, which
    /// start when the call does, so nothing before it (the journal's lock) uses them up.
    Starting(Duration),
    /// A job: its call's start, its answer and its undo, stated by the job.
    At(Instant),
    /// A holder: its undo, from when the end began.
    Within(Duration),
}

struct Live {
    id: u64,
    what: String,
    ends: Ends,
}

#[derive(Default)]
struct Book {
    next: u64,
    live: Vec<Live>,
    /// When the process's end began (`Duties::ending`).
    ending: Option<Instant>,
    /// The end is past waiting: a job starting now would be cut off, so it does not start.
    closed: bool,
}

/// Every change call in flight and every change held to be undone, counted from the moment
/// it starts until it and its whole undo have ended, so the process's end waits for them.
pub struct Duties {
    book: Mutex<Option<Book>>,
    changed: Condvar,
}

/// The process's duties: `owned` counts every job here, and the holders of a change that is
/// undone later (an image's footer, an unlocked volume, a drive's read limit, a disk taken
/// offline) count themselves.
pub static DUTIES: Duties = Duties::new();

impl Default for Duties {
    fn default() -> Self {
        Self::new()
    }
}

impl Duties {
    pub const fn new() -> Self {
        Self {
            book: Mutex::new(None),
            changed: Condvar::new(),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Book) -> R) -> R {
        let mut book = self.book.lock().unwrap_or_else(PoisonError::into_inner);
        f(book.get_or_insert_with(Book::default))
    }

    /// Counts a job, and journals it for the next start; `None` once the end is past
    /// waiting, when nothing new may start.
    fn enter(&'static self, what: &str, ends: Ends, pending: Pending) -> Option<Duty> {
        let id = self.with(|book| (!book.closed).then(|| Self::count(book, what, ends)))?;
        Some(Duty {
            duties: self,
            id,
            journal: super::pending::JOURNAL.add(what, pending),
            left: false,
        })
    }

    fn count(book: &mut Book, what: &str, ends: Ends) -> u64 {
        book.next += 1;
        book.live.push(Live {
            id: book.next,
            what: what.to_string(),
            ends,
        });
        book.next
    }

    /// A change held to be undone later: `what` says what holds it, and its undo takes up to
    /// `undo` once it is let go. Counted even once the end is past waiting, so it is never
    /// lost: the next start settles it from the journal.
    pub fn holder(&'static self, what: &str, undo: Duration, pending: Pending) -> Duty {
        let id = self.with(|book| Self::count(book, what, Ends::Within(undo)));
        Duty {
            duties: self,
            id,
            journal: super::pending::JOURNAL.add(what, pending),
            left: false,
        }
    }

    /// What is still being put back.
    pub fn left(&self) -> Vec<String> {
        self.with(|book| book.live.iter().map(|l| l.what.clone()).collect())
    }

    /// The process's end begins: from here the wait for each holder's undo is counted.
    pub fn ending(&self) {
        self.with(|book| {
            book.ending.get_or_insert_with(Instant::now);
        });
    }

    /// The latest any duty still counted is waited for: each job's start, answer and undo,
    /// each holder's undo from the end's start. `None` when none is left.
    fn deadline(book: &Book) -> Option<Instant> {
        let began = book.ending.unwrap_or_else(Instant::now);
        book.live
            .iter()
            .map(|l| match l.ends {
                Ends::Starting(longest) => Instant::now() + longest,
                Ends::At(at) => at,
                Ends::Within(undo) => began + undo,
            })
            .max()
    }

    /// Waits up to `step` for a change; what is still being put back, or `None` when nothing
    /// is left or every duty is past the time it stated.
    pub fn waiting(&self, step: Duration) -> Option<Vec<String>> {
        let mut held = self.book.lock().unwrap_or_else(PoisonError::into_inner);
        let book = held.get_or_insert_with(Book::default);
        book.ending.get_or_insert_with(Instant::now);
        let left = Self::deadline(book)?.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        if !step.is_zero() {
            held = self
                .changed
                .wait_timeout(held, left.min(step))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let book = held.get_or_insert_with(Book::default);
        let deadline = Self::deadline(book)?;
        (deadline > Instant::now()).then(|| book.live.iter().map(|l| l.what.clone()).collect())
    }

    /// Waits for every duty, each up to the time it stated, as the process's end does with no
    /// window; true when none is left.
    pub fn wait_all(&self) -> bool {
        while self.waiting(Duration::from_millis(250)).is_some() {}
        self.left().is_empty()
    }

    /// The end is past waiting: nothing new starts, and what is left is returned. Its journal
    /// entries stay, so the next start settles them.
    pub fn close(&self) -> Vec<String> {
        self.with(|book| {
            book.closed = true;
            book.live.iter().map(|l| l.what.clone()).collect()
        })
    }

    fn leave(&self, id: u64) {
        self.with(|book| book.live.retain(|l| l.id != id));
        self.changed.notify_all();
    }
}

/// One counted duty; dropping it says it has ended, and removes its journal entry. A duty
/// whose undo failed is `left`: its journal entry stays for the next start to settle.
pub struct Duty {
    duties: &'static Duties,
    id: u64,
    journal: Option<u64>,
    left: bool,
}

impl Duty {
    /// A job's call begins: its stated answer and undo are counted from now.
    fn begins(&self) {
        let now = Instant::now();
        self.duties.with(|book| {
            for live in book.live.iter_mut().filter(|l| l.id == self.id) {
                if let Ends::Starting(longest) = live.ends {
                    live.ends = Ends::At(now + longest);
                }
            }
        });
    }

    /// The undo did not put it back: the next start settles it.
    pub fn leave(mut self) {
        self.left = true;
    }

    /// What the next start settles, now that the change holds more (a later read limit).
    pub fn now_settled_by(&self, what: &str, pending: Pending) {
        if let Some(id) = self.journal {
            super::pending::JOURNAL.replace(id, what, pending);
        }
    }
}

impl Drop for Duty {
    fn drop(&mut self) {
        // A call that panicked ended in an unknown state: its entry stays for the next start.
        if let Some(id) = self.journal {
            if !self.left && !std::thread::panicking() {
                super::pending::JOURNAL.remove(id);
            }
        }
        self.duties.leave(self.id);
    }
}

impl std::fmt::Debug for Duty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Duty").field("id", &self.id).finish()
    }
}

/// Who has a bounded call's outcome.
enum Hand<T> {
    /// The call runs and its caller waits.
    Waiting,
    /// The call answered in time; the caller takes it.
    Answered(T),
    /// The caller gave up: the outcome goes to the late handler.
    GivenUp,
}

/// Runs `call`, a blocking call on a path that changes something, on a thread of its own
/// and waits up to the job's limit for it, or until `stop` is set. The job is counted from
/// this moment until the call and its whole undo have ended (`DUTIES`), so the process's
/// end waits for it, and journalled, so the next start settles it if the process ends
/// first. A call still running when its caller gives up keeps what undoes it: when it
/// ends, `late` is given its outcome on the call's thread, to put back what it changed or
/// to record and say it. Exactly one of the caller (`Done`) and `late` gets the outcome,
/// decided under one lock, so a call that ends as its caller gives up is neither lost nor
/// handled twice. A call that panics has no outcome. Once the process's end is past
/// waiting, a job does not start: the call is dropped unrun and `NoAnswer` returned.
pub fn owned<T, F, L>(job: Job, stop: Option<&AtomicBool>, call: F, late: L) -> Waited<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    L: FnOnce(T) + Send + 'static,
{
    owned_in(&DUTIES, job, stop, call, late)
}

/// A job's clock as it is counted: started only when its call begins (`Duty::begins`).
fn job_ends(job: &Job) -> Ends {
    Ends::Starting(job.longest())
}

/// `owned`, counted in `duties`.
fn owned_in<T, F, L>(
    duties: &'static Duties,
    job: Job,
    stop: Option<&AtomicBool>,
    call: F,
    late: L,
) -> Waited<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    L: FnOnce(T) + Send + 'static,
{
    let Some(duty) = duties.enter(&job.what, job_ends(&job), job.pending.clone()) else {
        return Waited::NoAnswer;
    };
    bounded(job.limit, stop, call, late, Some(duty))
}

/// `owned` and `in_time`: `duty` is the job's count, carried by the call's thread to the
/// end of its undo; a call that changes nothing has none.
fn bounded<T, F, L>(
    limit: Duration,
    stop: Option<&AtomicBool>,
    call: F,
    late: L,
    duty: Option<Duty>,
) -> Waited<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    L: FnOnce(T) + Send + 'static,
{
    let hand = Arc::new((Mutex::new(Hand::Waiting), Condvar::new()));
    let theirs = hand.clone();
    let spawned = std::thread::Builder::new()
        .name("bounded call".into())
        .spawn(move || {
            // The job's clock starts here, as its call begins.
            if let Some(duty) = &duty {
                duty.begins();
            }
            let outcome = call();
            let (slot, ready) = &*theirs;
            let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
            if matches!(*slot, Hand::GivenUp) {
                drop(slot);
                late(outcome);
            } else {
                *slot = Hand::Answered(outcome);
                ready.notify_all();
            }
            // Counted until here: the call and its undo have ended.
            drop(duty);
        });
    if spawned.is_err() {
        // The call never ran, so nothing changed; its duty went with the closure.
        return Waited::NoAnswer;
    }
    let deadline = Instant::now() + limit;
    let (slot, ready) = &*hand;
    let mut held = slot.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        if matches!(*held, Hand::Answered(_)) {
            if let Hand::Answered(outcome) = std::mem::replace(&mut *held, Hand::Waiting) {
                return Waited::Done(outcome);
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let gave_up = if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
            Some(Waited::Stopped)
        } else if left.is_zero() {
            Some(Waited::NoAnswer)
        } else {
            None
        };
        if let Some(waited) = gave_up {
            // The call checks under the same lock.
            *held = Hand::GivenUp;
            return waited;
        }
        held = ready
            .wait_timeout(held, left.min(Duration::from_millis(100)))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// Opens a source, waiting at most `limit` for it.
pub fn open_source_within(
    choice: SourceChoice,
    limit: Duration,
) -> Result<Box<dyn BlockSource>, String> {
    let what = choice.label();
    match in_time(limit, None, move || open_source(&choice)) {
        Waited::Done(opened) => opened,
        _ => Err(format!(
            "{what} is not answering: it did not open within {} s. Unplug it and connect it again, then try once more.",
            limit.as_secs()
        )),
    }
}

/// Opens a source off the window's thread; the answer, or why there is none, arrives
/// within `OPEN_LIMIT`.
pub fn open_in_background(
    choice: SourceChoice,
) -> mpsc::Receiver<Result<Box<dyn BlockSource>, String>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(open_source_within(choice, OPEN_LIMIT));
    });
    receiver
}

/// The recovery window's reading of a disk with its lettered volumes, within `limit`.
pub fn read_disk_within(number: u32, limit: Duration) -> Result<Option<Disk>, String> {
    match in_time(limit, None, move || {
        device::read_disk(number, &device::volumes_by_disk())
    }) {
        Waited::Done(disk) => Ok(disk),
        _ => Err(format!(
            "Disk {number} did not answer within {} s.",
            limit.as_secs()
        )),
    }
}

type Reading = Arc<dyn Fn() -> Option<Disk> + Send + Sync>;

/// The first reading of a run, before its image is open: the drive may cool first.
pub(crate) fn first_reading(health: &mut HealthWatch, progress: &Progress) -> Watch {
    loop {
        match health.check() {
            Watch::Cooling => health.note(0, 0, progress),
            other => return other,
        }
    }
}

/// Shows a read limit event, and logs one that says the limit could not be set.
pub(crate) fn limit_said(event: LimitEvent, health: &mut HealthWatch, progress: &Progress) {
    if let Some(text) = event.not_set() {
        health.log_note("read limit", None, text);
    }
    if let Ok(mut shown) = progress.read_limit.lock() {
        *shown = Some(event);
    }
}

/// A rescue image run as the window starts it: a first timed health reading, then the
/// image and map opened, then the passes, each with the drive's read limit `limit` sets
/// for it (put back at the end). When the drive stops answering, the run pauses with the map
/// saved and waits for it (`waiter`), then carries on from the same pass and place, past the
/// drop skip, with the drive under whatever number it came back as; the source the run ended
/// with is left in `waiter.source` when it changed. Returns how it ended and whether a map
/// was saved, which is what its end text is built from; `progress` holds photos first's
/// figures, the read limit's last word and the waiting.
#[allow(clippy::too_many_arguments)]
pub fn rescue(
    plan: Plan,
    source: &mut dyn BlockSource,
    settings: &Settings,
    stop: &AtomicBool,
    progress: &Progress,
    health: &mut HealthWatch,
    limit: &mut ReadLimit,
    waiter: &mut Waiter,
) -> Ended {
    let early = |outcome| Ended {
        outcome,
        map_saved: false,
        zones_left: 0,
    };
    if let Err(why) = health.throttle.check() {
        return early(Outcome::Paused(format!("Not started: {why}.")));
    }
    match first_reading(health, progress) {
        Watch::Fine | Watch::Cooling => {}
        Watch::Pause(why) => return early(Outcome::Paused(why)),
        Watch::Gone(why) => return early(Outcome::Gone(why)),
        Watch::Stop => return early(Outcome::Stopped),
    }
    let log_path = health_log::path_for(&plan.image);
    let events_path = events::path_for(&plan.image);
    let given = source.identity();
    let sector = u64::from(source.sector_size().max(1));
    let disk_number = source.disk_number();
    let mut rescue = match Rescue::open(plan, source) {
        Ok(rescue) => rescue,
        Err(why) => return early(Outcome::Failed(why)),
    };
    // The drive waited for after a drop: as the map names it, with the drive's own identity
    // kept from the map when the drive did not give it at the start.
    let meant = rescue.source_id().cloned().or(given.clone());
    let opened = rescue.beside(events_path.file_name().unwrap_or_default());
    progress.events.start(events_path, opened);
    rescue.events = progress.events.clone();
    rescue.publish(progress);
    progress.events.write(
        &events::started(
            "rescue image",
            disk_number,
            given.as_ref(),
            serde_json::json!({
                "retries": settings.retries,
                "photos_first": settings.photos_first.enabled,
                "cluster": settings.cluster,
                "drop_skip": settings.drop_skip,
                "health_every_seconds": settings.health_every.as_secs(),
                "heat_pause": health.throttle,
                "error_pause": health.wear_rate,
                "quick_give_up": limit.options,
            }),
        ),
        Figures::of(&rescue.map),
    );
    let opened = rescue.beside(log_path.file_name().unwrap_or_default());
    health.log = Some(HealthLog::start(log_path, opened).quiet(settings.health_every));
    health.note(rescue.map.current_pos, rescue.map.failed(), progress);
    let settings = Settings {
        health_every: health.every(settings.health_every),
        ..settings.clone()
    };
    let shared = RefCell::new(&mut *health);
    // The drive the run carries on with once it came back under a new number.
    let mut current: Option<Box<dyn BlockSource>> = None;
    let mut waited_out = false;
    let outcome = loop {
        let outcome = {
            let mut watch = || {
                let mut health = shared.borrow_mut();
                let watch = health.check();
                let (pos, bad) = (
                    progress.pos.load(Ordering::Relaxed),
                    progress.failed.load(Ordering::Relaxed),
                );
                if watch != Watch::Stop {
                    health.note(pos, bad, progress);
                }
                watch
            };
            let mut on_pass = |phase| {
                if let Some(event) = limit.for_pass(phase) {
                    limit_said(event, &mut shared.borrow_mut(), progress);
                }
            };
            let reading: &mut dyn BlockSource = match current.as_mut() {
                Some(back) => back.as_mut(),
                None => &mut *source,
            };
            rescue.run_hooked(reading, &settings, stop, progress, &mut watch, &mut on_pass)
        };
        let Outcome::Gone(why) = outcome else {
            break outcome;
        };
        let mut health = shared.borrow_mut();
        let went = wait::pause(
            &mut rescue,
            meant.as_ref(),
            why,
            sector,
            settings.drop_skip,
            waiter,
            stop,
            progress,
            &mut |kind, text| health.log_note(kind, None, text),
            "the rescue",
        );
        health.note(rescue.map.current_pos, rescue.map.failed(), progress);
        match went {
            Went::Back(back) => {
                limit.reconnect(back.as_ref());
                health.moved_to(back.disk_number());
                current = Some(back);
            }
            Went::End(outcome) => {
                waited_out = true;
                break outcome;
            }
        }
    };
    let health = shared.into_inner();
    // The drive's own read limit back, on Stop and every other end.
    if let Some(event) = limit.restore() {
        limit_said(event, health, progress);
    }
    // The end reading, unless the drive stopped answering or the run ended waiting for it,
    // or a reading just paused the run: that reading is the end's, logged once.
    if !waited_out && !matches!(outcome, Outcome::Gone(_) | Outcome::Paused(_)) {
        health.last_reading();
    }
    health.note(rescue.map.current_pos, rescue.map.failed(), progress);
    let ended = Ended {
        outcome,
        map_saved: rescue.map_saved(),
        zones_left: rescue.zones_left(),
    };
    rescue.publish(progress);
    let said = super::image::end_text(&ended, Some(&rescue.map));
    let event = match &ended.outcome {
        Outcome::Finished => Some(Event::Finished {
            reason: said.clone(),
        }),
        Outcome::Stopped => Some(Event::Stopped {
            reason: said.clone(),
        }),
        Outcome::Paused(_) => {
            let (kind, values) = health
                .tripped
                .take()
                .unwrap_or((PauseKind::ErrorRate, serde_json::Value::Null));
            Some(Event::Paused {
                kind,
                reason: said.clone(),
                values,
            })
        }
        // Not when the wait for the drive already said so and the run ended waiting.
        Outcome::Gone(_) if progress.events.state() == Some("paused") => None,
        Outcome::Gone(_) => Some(Event::Paused {
            kind: PauseKind::DriveGone,
            reason: said.clone(),
            values: serde_json::json!({ "waiting": false }),
        }),
        Outcome::Unconfirmed(_) => Some(Event::Paused {
            kind: PauseKind::User,
            reason: said.clone(),
            values: serde_json::json!({
                "found": waiter.source.as_ref().map(|found| found.describe()),
            }),
        }),
        Outcome::Failed(_) => Some(Event::AppError {
            reason: said.clone(),
        }),
    };
    if let Some(event) = event {
        progress.events.write(&event, Figures::of(&rescue.map));
    }
    let said = match progress.events.finish() {
        Some(problem) => format!("{said} {problem}"),
        None => said,
    };
    Progress::say(&progress.ended, Some(said));
    if let Some(back) = current {
        waiter.source.get_or_insert(back);
    }
    ended
}

/// The heat pause: while it is on, the drive's temperature is read every `THROTTLE_EVERY`
/// (one health reading, whose only ATA command is SMART READ DATA), the run pauses with its
/// map saved when it reaches `pause_at`, and carries on by itself from the same pass and
/// place at `resume_at` or below, or at once on Resume now. It applies to any drive whose
/// temperature is read: SMART attribute 194 through either ATA carrier, the NVMe health
/// log, or what Windows reports. For example, it pauses work at 38C and resumes at 30C or below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throttle {
    pub on: bool,
    /// Degrees C at which the run pauses.
    pub pause_at: i32,
    /// Degrees C at or below which it carries on; below `pause_at`.
    pub resume_at: i32,
}

impl Default for Throttle {
    fn default() -> Self {
        Self {
            on: true,
            pause_at: 38,
            resume_at: 30,
        }
    }
}

impl Throttle {
    pub fn off() -> Self {
        Self {
            on: false,
            ..Self::default()
        }
    }

    /// Refuses a resume threshold that is not below the pause threshold.
    pub fn check(&self) -> Result<(), String> {
        if self.resume_at >= self.pause_at {
            return Err(format!(
                "the heat pause carries on at {} C, which must be below where it pauses, {} C",
                self.resume_at, self.pause_at
            ));
        }
        Ok(())
    }
}

/// How often a rescue reads the drive's health: its own schedule `every`, or the heat
/// pause's `throttle_every` while that is on and sooner.
pub fn reading_every(throttle: &Throttle, every: Duration, throttle_every: Duration) -> Duration {
    if throttle.on {
        every.min(throttle_every)
    } else {
        every
    }
}

/// How often the temperature is read while the heat pause is on, during the run and while
/// it cools.
/// Once a minute: the fastest rise seen on a failing drive in an enclosure was about 2 C a
/// minute, and each reading is a SMART command the drive must answer between reads, which
/// waits behind a read it is stuck on.
pub const THROTTLE_EVERY: Duration = Duration::from_secs(60);
/// Cooling this long without reaching the resume threshold, the window says a drive in a
/// warm enclosure may never get there, and that Resume now is for that.
pub const COOLING_LONG: Duration = Duration::from_secs(20 * 60);

/// A heat pause under way.
struct Cooling {
    since: Instant,
    /// The latest temperature, and when it was read.
    celsius: i32,
    at: String,
    next: Instant,
}

/// The health watch of a rescue image: each reading is timed, and compared with the first.
pub struct HealthWatch {
    read: Reading,
    limit: Duration,
    stop: Arc<AtomicBool>,
    /// The disk read by number, which follows the drive to a new number; None for a reader
    /// given (tests).
    disk: Option<u32>,
    /// The error pause, and the counts it judges, when read and how many.
    pub wear_rate: WearRate,
    history: Vec<(Instant, u128)>,
    /// The latest reading, or why it did not come back; None once it is logged.
    latest: Option<Result<Disk, String>>,
    /// The heat pause, and Resume now, which the window sets.
    pub throttle: Throttle,
    /// How often the temperature is read while the heat pause is on, and how long cooling
    /// goes before the window says it may never get there (`THROTTLE_EVERY`, `COOLING_LONG`).
    pub throttle_every: Duration,
    pub cooling_long: Duration,
    resume_now: Arc<AtomicBool>,
    cooling: Option<Cooling>,
    /// Resume now was used: no heat pause until the drive has been below the pause again.
    disarmed: bool,
    /// A temperature was read in this run; else, with the heat pause on, it says it is not
    /// working for this drive.
    heated: bool,
    unheated: Option<String>,
    /// What carries on after a pause, for its texts: "the rescue" or "Fill the gaps".
    pub then: String,
    /// Lines for the log besides readings, kind, temperature and text, written with the
    /// next reading.
    notes: Vec<(String, Option<i32>, String)>,
    /// The last time the run carried on after cooling, said, for the window.
    resumed: Option<String>,
    /// The run's health log, from when its image is open.
    pub log: Option<HealthLog>,
    /// Events for the run's event log, written with the next reading.
    events: Vec<Event>,
    /// What paused the run, for its event: the error pause or the critical temperature,
    /// with the values that tripped it.
    pub tripped: Option<(PauseKind, serde_json::Value)>,
    /// How the latest reading is kept in the log, decided where its outcome is known: every
    /// reading that changes the run's state (a pause, the drive gone, the heat pause
    /// starting or ending, the end) is kept Always; the heat pause's other readings Extra.
    latest_keep: Keep,
}

impl HealthWatch {
    /// Watches disk `number`; its descriptor queries need no access right, and SMART goes
    /// through the device module's ATA reader on a handle of its own.
    pub fn for_disk(number: u32, stop: Arc<AtomicBool>) -> Self {
        let mut watch = Self::with_reader(Self::disk_reader(number), HEALTH_LIMIT, stop);
        watch.disk = Some(number);
        watch
    }

    fn disk_reader(number: u32) -> Reading {
        Arc::new(move || device::read_disk(number, &Default::default()))
    }

    pub fn with_reader(read: Reading, limit: Duration, stop: Arc<AtomicBool>) -> Self {
        Self {
            read,
            limit,
            stop,
            disk: None,
            wear_rate: WearRate::off(),
            history: Vec::new(),
            latest: None,
            throttle: Throttle::off(),
            throttle_every: THROTTLE_EVERY,
            cooling_long: COOLING_LONG,
            resume_now: Arc::new(AtomicBool::new(false)),
            cooling: None,
            disarmed: false,
            heated: false,
            unheated: None,
            then: "the rescue".into(),
            notes: Vec::new(),
            resumed: None,
            log: None,
            events: Vec::new(),
            tripped: None,
            latest_keep: Keep::Scheduled,
        }
    }

    /// The heat pause as the window set it, with its Resume now.
    pub fn with_throttle(mut self, throttle: Throttle, resume_now: Arc<AtomicBool>) -> Self {
        self.throttle = throttle;
        self.resume_now = resume_now;
        self
    }

    /// The drive is read under its new disk number from now on; nothing assumes the old one.
    pub fn moved_to(&mut self, number: Option<u32>) {
        if let (Some(_), Some(number)) = (self.disk, number) {
            self.read = Self::disk_reader(number);
            self.disk = Some(number);
        }
    }

    /// How often the run asks for a reading: `every`, or the heat pause's interval while it
    /// is on.
    pub fn every(&self, every: Duration) -> Duration {
        reading_every(&self.throttle, every, self.throttle_every)
    }

    /// A line for the log besides the readings, written with the next one.
    pub(crate) fn log_note(&mut self, kind: &str, celsius: Option<i32>, text: String) {
        self.notes.push((kind.into(), celsius, text));
    }

    /// Adds the latest reading and the notes to the log with the rescue's position and bad
    /// bytes, and shows them in the window, with the heat pause's state.
    pub(crate) fn note(&mut self, pos: u64, bad: u64, progress: &Progress) {
        let figures = Figures {
            position: pos,
            ..progress.figures()
        };
        if let Some(log) = &mut self.log {
            if let Some(latest) = self.latest.take() {
                let reading =
                    health_log::Reading::of(latest.as_ref().map_err(String::as_str), pos, bad);
                let event = reading.event();
                // The event log gets the reading exactly when the health log gets its row.
                // Only the heat pause's extra readings may be left out: without it every
                // reading is on the run's own schedule, and the reading that paused the run
                // and the end's are always written.
                if log.offer(reading, self.latest_keep) {
                    progress.events.write(&event, figures);
                }
            }
            for (kind, celsius, text) in self.notes.drain(..) {
                log.note(&kind, celsius, pos, bad, &text);
            }
            let mut shown = log.live_text();
            if let Some(unheated) = &self.unheated {
                shown = format!("{shown} {unheated}").trim().to_string();
            }
            if let Ok(mut health) = progress.health.lock() {
                *health = shown;
            }
            if let Ok(mut drive) = progress.drive.lock() {
                drive.clone_from(&log.latest().cloned());
            }
        }
        for event in self.events.drain(..) {
            progress.events.write(&event, figures);
        }
        Progress::say(&progress.cooling, self.cooling_text());
        if let Some(resumed) = self.resumed.take() {
            Progress::say(&progress.resumed, Some(resumed));
        }
    }

    /// The window's words while the drive cools.
    fn cooling_text(&self) -> Option<String> {
        let cooling = self.cooling.as_ref()?;
        let Throttle {
            pause_at,
            resume_at,
            ..
        } = self.throttle;
        let mut text = format!(
            "Paused to let the drive cool: it was {} C at {}. {} carries on by itself at {resume_at} C or below (it pauses at {pause_at} C); Resume now carries on at once.",
            cooling.celsius,
            cooling.at,
            capital(&self.then)
        );
        if cooling.since.elapsed() >= self.cooling_long {
            text.push_str(&format!(
                " It has not cooled to {resume_at} C in {} minutes. A drive spinning in a warm enclosure may never get there; Resume now carries on anyway.",
                cooling.since.elapsed().as_secs().div_ceil(60)
            ));
        }
        Some(text)
    }

    /// The reading after a run, which Stop does not cut short.
    fn last_reading(&mut self) {
        let read = self.read.clone();
        self.latest = match in_time(END_LIMIT, None, move || read()) {
            Waited::Done(Some(now)) => Some(Ok(now)),
            Waited::Done(None) => Some(Err("Windows no longer lists the drive".into())),
            _ => Some(Err(format!("no answer within {} s", END_LIMIT.as_secs()))),
        };
        self.latest_keep = Keep::Always;
    }

    /// What the window shows of the latest reading, once one is logged.
    pub(crate) fn shown(&self, progress: &Progress) -> Option<String> {
        progress
            .health
            .lock()
            .ok()
            .map(|text| text.clone())
            .filter(|text| !text.is_empty())
    }

    /// One reading for Fill the gaps: the drive's sector counts, compared by the caller,
    /// not with the rule that pauses a rescue. Kept for the log like every reading.
    pub fn wear(&mut self) -> WearReading {
        let read = self.read.clone();
        let waited = in_time(self.limit, Some(&self.stop), move || read());
        // Kept as scheduled; a reading that ends the step is kept Always (`keep_latest`).
        self.latest_keep = match waited {
            Waited::Done(Some(_)) => Keep::Scheduled,
            _ => Keep::Always,
        };
        match waited {
            Waited::Stopped => WearReading::Stop,
            Waited::NoAnswer => {
                let why = format!("no answer within {} s", self.limit.as_secs());
                self.latest = Some(Err(why.clone()));
                WearReading::Gone(format!(
                    "the drive is not answering: a health reading did not come back within {} s.",
                    self.limit.as_secs()
                ))
            }
            Waited::Done(None) => {
                self.latest = Some(Err("Windows no longer lists the drive".into()));
                WearReading::Gone("Windows no longer lists the drive.".into())
            }
            Waited::Done(Some(now)) => {
                let reading = health_log::Reading::of(Ok(&now), 0, 0);
                self.latest = Some(Ok(now));
                match reading.counts {
                    Counts::Ata {
                        reallocated,
                        pending,
                        ..
                    } => WearReading::Counts(Wear {
                        reallocated,
                        pending,
                        media_errors: None,
                    }),
                    Counts::Nvme { media_errors, .. } => WearReading::Counts(Wear {
                        reallocated: None,
                        pending: None,
                        media_errors: Some(u64::try_from(media_errors).unwrap_or(u64::MAX)),
                    }),
                    Counts::TemperatureOnly(why) | Counts::Nothing(why) | Counts::NoAnswer(why) => {
                        WearReading::NoCounts(why)
                    }
                }
            }
        }
    }

    /// The end of the log: how the drive's health went, for the end text.
    pub fn finish_log(&mut self) -> Option<String> {
        self.log.as_mut().map(HealthLog::finish)
    }

    /// One reading, judged by the error pause (`wear_rate`), the drive's critical
    /// temperature and the heat pause. A drive that answers no health query is still asked
    /// at every reading, so its readings come back, and the heat pause works, once it
    /// answers again. While the drive cools, this first waits for the next reading's time,
    /// hearing Stop and Resume now.
    pub fn check(&mut self) -> Watch {
        self.watch(true)
    }

    /// `check` for Fill the gaps within a pass: the heat pause and a drive gone, without the
    /// rescue's error pause, which Fill the gaps replaces with its own rule on the counts.
    pub fn heat(&mut self) -> Watch {
        self.watch(false)
    }

    /// The latest reading changed the run's state, as the caller decided (Fill the gaps'
    /// own rule on the counts): it is kept in the log whatever came before.
    pub(crate) fn keep_latest(&mut self) {
        self.latest_keep = Keep::Always;
    }

    fn watch(&mut self, compare: bool) -> Watch {
        let was_cooling = self.cooling.is_some();
        let watch = self.watch_once(compare);
        let cooling = self.cooling.is_some();
        self.latest_keep = match &watch {
            Watch::Fine | Watch::Cooling if was_cooling == cooling => {
                if self.throttle.on {
                    Keep::Extra
                } else {
                    Keep::Scheduled
                }
            }
            _ => Keep::Always,
        };
        watch
    }

    fn watch_once(&mut self, compare: bool) -> Watch {
        if let Some(next) = self.cooling.as_ref().map(|c| c.next) {
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return Watch::Stop;
                }
                if self.resume_now.swap(false, Ordering::Relaxed) {
                    let celsius = self.cooling.take().map(|c| c.celsius);
                    self.disarmed = true;
                    let said = format!(
                        "Resume now pressed at {}; {} carries on, and pauses for heat again only once the drive has been below {} C.",
                        super::wait::clock(),
                        self.then,
                        self.throttle.pause_at
                    );
                    self.log_note("heat resume", celsius, said.clone());
                    self.events.push(Event::Resumed {
                        kind: PauseKind::Heat,
                        reason: said.clone(),
                    });
                    self.resumed = Some(said);
                    return Watch::Fine;
                }
                let left = next.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                std::thread::sleep(left.min(Duration::from_millis(100)));
            }
        }
        let read = self.read.clone();
        let waited = in_time(self.limit, Some(&self.stop), move || read());
        self.latest = match &waited {
            Waited::Stopped => None,
            Waited::NoAnswer => Some(Err(format!("no answer within {} s", self.limit.as_secs()))),
            Waited::Done(None) => Some(Err("Windows no longer lists the drive".into())),
            Waited::Done(Some(now)) => Some(Ok(now.clone())),
        };
        let now = match waited {
            Waited::Stopped => return Watch::Stop,
            Waited::NoAnswer => {
                return Watch::Gone(format!(
                    "The drive is not answering: a health reading did not come back within {} s.",
                    self.limit.as_secs()
                ))
            }
            Waited::Done(None) => {
                return Watch::Gone(
                    "The drive stopped answering: Windows no longer lists it.".into(),
                )
            }
            Waited::Done(Some(now)) => now,
        };
        if compare {
            let celsius = super::image::temperature(&now);
            let mut change = too_hot(&now).map(|why| {
                let values = serde_json::json!({ "temperature_c": celsius });
                (why, PauseKind::CriticalTemperature, values)
            });
            if change.is_none() {
                if let Some((count, what)) = wear_count(&now) {
                    let at = Instant::now();
                    let keep = self.wear_rate.keep();
                    self.history
                        .retain(|(then, _)| at.duration_since(*then) <= keep);
                    self.history.push((at, count));
                    change = self
                        .wear_rate
                        .judged(&self.history, what)
                        .map(|(why, values)| (why, PauseKind::ErrorRate, values));
                }
            }
            if let Some((why, kind, values)) = change {
                self.tripped = Some((kind, values));
                return Watch::Pause(why);
            }
        }
        self.heed_heat(super::image::temperature(&now))
    }

    /// The heat pause's step for one reading's temperature.
    fn heed_heat(&mut self, celsius: Option<i32>) -> Watch {
        let Throttle {
            on,
            pause_at,
            resume_at,
        } = self.throttle;
        if !on {
            return Watch::Fine;
        }
        let Some(celsius) = celsius else {
            if !self.heated && self.unheated.is_none() {
                let said =
                    "Heat pause: not working for this drive, as its temperature cannot be read.";
                self.unheated = Some(said.into());
                self.log_note("heat pause", None, said.into());
            }
            // A drive cooling whose temperature is lost waits for a reading, or Resume now.
            return if self.cooling.is_some() {
                self.next_reading();
                Watch::Cooling
            } else {
                Watch::Fine
            };
        };
        self.heated = true;
        self.unheated = None;
        if celsius < pause_at {
            self.disarmed = false;
        }
        match &mut self.cooling {
            None if celsius >= pause_at && !self.disarmed => {
                self.resume_now.store(false, Ordering::Relaxed);
                self.cooling = Some(Cooling {
                    since: Instant::now(),
                    celsius,
                    at: super::wait::clock(),
                    next: Instant::now() + self.throttle_every,
                });
                self.log_note(
                    "heat pause",
                    Some(celsius),
                    format!(
                        "Paused at {celsius} C, at or above the heat pause of {pause_at} C; {} carries on at {resume_at} C or below.",
                        self.then
                    ),
                );
                // The window's message as it is at the pause.
                self.events.push(Event::Paused {
                    kind: PauseKind::Heat,
                    reason: self.cooling_text().unwrap_or_default(),
                    values: serde_json::json!({
                        "temperature_c": celsius,
                        "pause_at": pause_at,
                        "resume_at": resume_at,
                    }),
                });
                Watch::Cooling
            }
            None => Watch::Fine,
            Some(cooling) if celsius <= resume_at => {
                let minutes = cooling.since.elapsed().as_secs().div_ceil(60);
                self.cooling = None;
                let said = format!(
                    "The drive cooled to {celsius} C at {} after {minutes} min; {} carried on.",
                    super::wait::clock(),
                    self.then
                );
                self.log_note("heat resume", Some(celsius), said.clone());
                self.events.push(Event::Resumed {
                    kind: PauseKind::Heat,
                    reason: said.clone(),
                });
                self.resumed = Some(said);
                Watch::Fine
            }
            Some(cooling) => {
                cooling.celsius = celsius;
                cooling.at = super::wait::clock();
                self.next_reading();
                Watch::Cooling
            }
        }
    }

    fn next_reading(&mut self) {
        let every = self.throttle_every;
        if let Some(cooling) = &mut self.cooling {
            cooling.next = Instant::now() + every;
        }
    }
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The sector counts Fill the gaps watches, where the drive keeps them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wear {
    pub reallocated: Option<u64>,
    pub pending: Option<u64>,
    pub media_errors: Option<u64>,
}

/// One reading for Fill the gaps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WearReading {
    Counts(Wear),
    /// The drive keeps no counts this tool reads; says why.
    NoCounts(String),
    /// The drive did not answer; says so.
    Gone(String),
    /// Stop was asked for while the reading waited.
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::image::{end_text, plan_with, Map, Status};
    use crate::recovery::MemDisk;
    use crate::tools::drives::health::{fixtures, parse_smart_attributes, Health};
    use std::sync::Mutex;

    /// A reading that never comes back in time, as a stalled controller gives.
    fn stalled(seconds: u64) -> Reading {
        Arc::new(move || {
            std::thread::sleep(Duration::from_secs(seconds));
            None
        })
    }

    /// The guard: a call that does not return is given up at its limit, or at once on Stop.
    #[test]
    fn a_stalled_call_is_given_up_at_its_limit_or_on_stop() {
        let started = Instant::now();
        let waited = in_time(Duration::from_millis(200), None, || {
            std::thread::sleep(Duration::from_secs(5));
            1
        });
        assert_eq!(waited, Waited::NoAnswer);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "waited for the call"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            flag.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let mut watch = HealthWatch::with_reader(stalled(5), Duration::from_secs(60), stop);
        assert_eq!(watch.check(), Watch::Stop);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "Stop waited for the drive"
        );
        assert_eq!(in_time(Duration::from_secs(5), None, || 7), Waited::Done(7));
    }

    /// A registry of its own for a test, so its end and close touch no other test's jobs.
    fn duties() -> &'static Duties {
        Box::leak(Box::new(Duties::new()))
    }

    fn job(limit: u64) -> Job {
        Job::new("a test change", Duration::from_millis(limit))
    }

    /// The guard (cause H): a change is counted from the moment it starts, before its caller
    /// gives up, until the call and its whole undo have ended; one answered in time stops
    /// counting as it answers.
    #[test]
    fn a_change_is_counted_from_its_start_to_the_end_of_its_undo() {
        let duties = duties();
        let (go, wait) = mpsc::channel::<()>();
        let (in_undo, undoing) = mpsc::channel::<()>();
        let (end_undo, undo_ends) = mpsc::channel::<()>();
        let caller = std::thread::spawn(move || {
            owned_in(
                duties,
                job(400).answered_within(Duration::from_secs(30)),
                None,
                move || {
                    let _ = wait.recv();
                },
                move |()| {
                    in_undo.send(()).unwrap();
                    let _ = undo_ends.recv();
                },
            )
        });
        // Its caller still waits, and it is counted already.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(duties.left(), vec!["a test change".to_string()]);
        assert_eq!(caller.join().unwrap(), Waited::NoAnswer);
        go.send(()).unwrap();
        undoing.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(duties.left().len(), 1, "the undo ran uncounted");
        end_undo.send(()).unwrap();
        let started = Instant::now();
        while !duties.left().is_empty() && started.elapsed() < Duration::from_secs(5) {
            std::thread::yield_now();
        }
        assert!(duties.left().is_empty(), "the undo's end was not counted");
        assert_eq!(
            owned_in(duties, job(5000), None, || 6, drop),
            Waited::Done(6)
        );
        let started = Instant::now();
        while !duties.left().is_empty() && started.elapsed() < Duration::from_secs(5) {
            std::thread::yield_now();
        }
        assert!(duties.left().is_empty());
    }

    /// The guard (cause H): the process's end waits for each job as long as the job stated,
    /// its answer and its undo, and for each holder its undo; past that it stops, says what
    /// is left, and no new job starts.
    #[test]
    fn the_end_waits_as_long_as_each_job_states() {
        let duties = duties();
        let undone = Arc::new(AtomicBool::new(false));
        let seen = undone.clone();
        let waited = owned_in(
            duties,
            job(50)
                .answered_within(Duration::from_secs(20))
                .undone_within(Duration::from_secs(20)),
            None,
            || std::thread::sleep(Duration::from_millis(600)),
            move |()| {
                std::thread::sleep(Duration::from_millis(600));
                seen.store(true, Ordering::SeqCst);
            },
        );
        assert_eq!(waited, Waited::NoAnswer);
        let holder = duties.holder("a test holder", Duration::from_secs(20), Pending::Said);
        let dropper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(holder);
        });
        duties.ending();
        let started = Instant::now();
        assert!(duties.wait_all(), "left: {:?}", duties.left());
        assert!(
            undone.load(Ordering::SeqCst),
            "the wait ended before the undo"
        );
        assert!(started.elapsed() >= Duration::from_millis(900));
        dropper.join().unwrap();
        // A job Windows does not answer within what it stated is left to the next start.
        let (_go, wait) = mpsc::channel::<()>();
        let stuck = job(20).answered_within(Duration::from_millis(400));
        let waited = owned_in(
            duties,
            stuck,
            None,
            move || {
                let _ = wait.recv();
            },
            drop,
        );
        assert_eq!(waited, Waited::NoAnswer);
        let started = Instant::now();
        assert!(!duties.wait_all());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited past its time"
        );
        assert_eq!(duties.close(), vec!["a test change".to_string()]);
        let ran = Arc::new(AtomicBool::new(false));
        let mark = ran.clone();
        let refused = owned_in(
            duties,
            job(1000),
            None,
            move || mark.store(true, Ordering::SeqCst),
            drop,
        );
        assert_eq!(refused, Waited::NoAnswer);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!ran.load(Ordering::SeqCst), "a job started after the end");
    }

    /// The guard (cause H): a job's stated answer and undo are counted from when its call
    /// begins, so time spent before it (the journal's lock, held by another window) does not
    /// use them up.
    #[test]
    fn a_jobs_clock_starts_when_its_call_begins() {
        let duties = duties();
        let job = job(50).answered_within(Duration::from_secs(2));
        let longest = job.longest();
        let duty = duties
            .enter(&job.what, job_ends(&job), Pending::Said)
            .unwrap();
        // As a journal write waiting on another window's lock does.
        std::thread::sleep(Duration::from_millis(400));
        let (began, call_began) = mpsc::channel::<Instant>();
        let (go, wait) = mpsc::channel::<()>();
        let waited = bounded(
            job.limit,
            None,
            move || {
                began.send(Instant::now()).unwrap();
                let _ = wait.recv();
            },
            drop,
            Some(duty),
        );
        assert_eq!(waited, Waited::NoAnswer);
        let call_began = call_began.recv_timeout(Duration::from_secs(5)).unwrap();
        let first = duties.with(|book| Duties::deadline(book)).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let again = duties.with(|book| Duties::deadline(book)).unwrap();
        assert_eq!(first, again, "the deadline moves");
        let off = if first > call_began + longest {
            first - (call_began + longest)
        } else {
            (call_began + longest) - first
        };
        assert!(
            off < Duration::from_millis(100),
            "counted from before the call by {off:?}"
        );
        go.send(()).unwrap();
    }

    /// The guard (cause H): a change that outlives its time limit hands its outcome to what
    /// undoes it once it ends; one answered in time goes to the caller alone.
    #[test]
    fn a_late_change_reaches_its_undo() {
        let (go, wait) = mpsc::channel::<()>();
        let (undone, seen) = mpsc::channel::<u32>();
        let waited = owned(
            job(100),
            None,
            move || {
                let _ = wait.recv();
                5
            },
            move |late| {
                let _ = undone.send(late);
            },
        );
        assert_eq!(waited, Waited::NoAnswer);
        go.send(()).unwrap();
        assert_eq!(seen.recv_timeout(Duration::from_secs(5)), Ok(5));
        let (undone, seen) = mpsc::channel::<u32>();
        let waited = owned(
            job(5000),
            None,
            || 6,
            move |late| {
                let _ = undone.send(late);
            },
        );
        assert_eq!(waited, Waited::Done(6));
        assert!(seen.recv_timeout(Duration::from_millis(200)).is_err());
        let stop = AtomicBool::new(true);
        let (undone, seen) = mpsc::channel::<u32>();
        let waited = owned(
            job(5000),
            Some(&stop),
            || {
                std::thread::sleep(Duration::from_millis(200));
                7
            },
            move |late| {
                let _ = undone.send(late);
            },
        );
        assert_eq!(waited, Waited::Stopped);
        assert_eq!(seen.recv_timeout(Duration::from_secs(5)), Ok(7));
    }

    /// Whether `code[..end]` ends in a call of `name` (such as `owned(`), not of a longer
    /// name ending the same way (`into_owned(`).
    fn called(code: &str, end: usize, name: &str) -> bool {
        code[..end].ends_with(name)
            && !code[..end - name.len()]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
    }

    /// Whether byte `at` of `code` lies inside the argument list of a call to one of
    /// `runners`, such as `owned(`.
    fn inside_call_to(code: &str, at: usize, runners: &[&str]) -> bool {
        let bytes = code.as_bytes();
        let mut depth = 0usize;
        for i in (0..at).rev() {
            match bytes[i] {
                b')' => depth += 1,
                b'(' if depth > 0 => depth -= 1,
                b'(' if runners.iter().any(|r| called(code, i + 1, r)) => return true,
                _ => {}
            }
        }
        false
    }

    /// Every call of `callee` in `code` (its definition left out) lies inside a call to one
    /// of `runners`.
    fn every_call_bounded(file: &str, code: &str, callee: &str, runners: &[&str]) {
        let mut calls = 0;
        for (at, _) in code.match_indices(callee) {
            if code[..at].ends_with("fn ") {
                continue;
            }
            calls += 1;
            assert!(
                inside_call_to(code, at, runners),
                "{file}: {callee} runs outside {runners:?}"
            );
        }
        assert!(calls > 0, "{file}: no call of {callee}");
    }

    /// The guard (cause H): every blocking call on a path that changes something runs
    /// bounded, and a change through `owned`, which keeps what undoes it: the drive's read
    /// limit, every BitLocker call through WMI (a listing waits a bounded time for each
    /// volume), making, attaching and detaching a virtual disk (each carrying the image's
    /// footer to its end), locking and dismounting a volume of the replacement drive or the
    /// repair's copy, and taking the replacement drive offline or online.
    #[test]
    fn every_blocking_change_call_is_bounded_and_owns_its_undo() {
        let cut = |file: &'static str| file.split("#[cfg(test)]").next().unwrap_or(file);
        let read_limit = cut(include_str!("read_limit.rs"));
        every_call_bounded("read_limit.rs", read_limit, ".command(", &["owned("]);
        // The drive's put back is one owned job, read and set together.
        let disk = &read_limit[read_limit
            .find("impl<D: Drive> LimitControl for DiskLimit<D>")
            .unwrap()..];
        let disk = &disk[..disk.find("\n}\n").unwrap()];
        assert!(
            disk.contains("fn put_back("),
            "the drive's put back is two calls"
        );
        every_call_bounded("read_limit.rs", disk, "put_back_on(", &["owned("]);
        assert!(
            !read_limit.contains("in_time("),
            "a read limit change that drops a late answer"
        );
        let bitlocker = cut(include_str!("bitlocker.rs"));
        every_call_bounded(
            "bitlocker.rs",
            bitlocker,
            "Wmi::connect()",
            &["in_time(", "owned("],
        );
        for f in ["fn unlock_parsed(", "fn lock_within("] {
            let body = &bitlocker[bitlocker.find(f).unwrap()..];
            let body = &body[..body.find("\n}\n").unwrap()];
            assert!(body.contains("changing("), "bitlocker.rs: {f} is not owned");
        }
        assert!(
            !bitlocker.contains("WBEM_INFINITE"),
            "a BitLocker listing waits with no end"
        );
        let vdisk = cut(include_str!("vdisk.rs"));
        for callee in ["attach_now(", "detach_now("] {
            every_call_bounded("vdisk.rs", vdisk, callee, &["owned("]);
        }
        for api in ["AttachVirtualDisk(", "DetachVirtualDisk("] {
            assert_eq!(
                vdisk.matches(api).count(),
                1,
                "vdisk.rs: {api} outside its one place"
            );
        }
        // Making a repair's copy opens the image; it is owned too.
        let repair = cut(include_str!("repair.rs"));
        every_call_bounded("repair.rs", repair, "CreateVirtualDisk(", &["owned("]);
        assert_eq!(repair.matches("CreateVirtualDisk(").count(), 1);
        // Each call that may hold the image carries its footer to the call's real end.
        for (file, f) in [
            (vdisk, "fn attach("),
            (vdisk, "fn detach_holding<"),
            (repair, "fn make_copy("),
        ] {
            let body = &file[file.find(f).unwrap()..];
            let body = &body[..body.find("\n}\n").unwrap()];
            assert!(
                body.contains("footed.keep()") && body.contains("drop(keep)"),
                "{f} lets the image's footer go before Windows lets the image go"
            );
        }
        // The replacement drive's and the copy's volumes are locked and dismounted, and the
        // replacement drive taken offline and online, by owned jobs that keep the handle.
        let handles = cut(include_str!("../handles.rs"));
        for callee in [
            "FSCTL_LOCK_VOLUME, &[]",
            "FSCTL_DISMOUNT_VOLUME, &[]",
            "set_offline(&",
        ] {
            every_call_bounded("handles.rs", handles, callee, &["owned("]);
        }
        assert_eq!(
            handles.matches("lock_and_dismount(format!(").count(),
            2,
            "a volume is closed outside lock_and_dismount"
        );
        // Every owned job is counted from its start to the end of its undo, and states its
        // limits: only `owned_in` runs a change, after counting it, and the call's thread
        // carries the count past the undo.
        let timed = cut(include_str!("timed.rs"));
        assert!(timed.contains("bounded(limit, stop, call, drop, None)"));
        let owned_in = &timed[timed.find("fn owned_in<").unwrap()..];
        let owned_in = &owned_in[..owned_in.find("\n}\n").unwrap()];
        let counted = owned_in.find("duties.enter(").unwrap();
        let ran = owned_in
            .find("bounded(job.limit, stop, call, late, Some(duty))")
            .unwrap();
        assert!(counted < ran, "a change runs before it is counted");
        assert_eq!(
            timed.matches("Some(duty))").count(),
            1,
            "a change runs uncounted"
        );
        let thread = &timed[timed.find(".spawn(move || {").unwrap()..];
        let thread = &thread[..thread.find("\n        });").unwrap()];
        let undo = thread.find("late(outcome);").unwrap();
        let ends = thread.find("drop(duty);").unwrap();
        assert!(undo < ends, "the count ends before the undo");
        for (file, code) in [
            ("read_limit.rs", read_limit),
            ("bitlocker.rs", bitlocker),
            ("vdisk.rs", vdisk),
            ("repair.rs", repair),
            ("handles.rs", handles),
        ] {
            for (at, _) in code.match_indices("owned(") {
                if !called(code, at + "owned(".len(), "owned(") {
                    continue;
                }
                let call = &code[at..];
                let first = call["owned(".len()..].trim_start();
                assert!(
                    first.starts_with("Job::new(")
                        || first.starts_with("job,")
                        || first.starts_with("super::timed::Job::new("),
                    "{file}: an owned job that states no limits"
                );
            }
        }
        // A change undone later is counted by its holder from the moment it is made, so the
        // end waits for it and the next start settles it: an image's footer, an unlocked
        // volume (its Relock made on the unlock's own thread), a drive's read limit (before
        // the set is sent), and a disk taken offline (on the offline job's own thread).
        assert!(
            vdisk.contains("DUTIES.holder("),
            "vdisk.rs: a footer uncounted"
        );
        let unlock = &bitlocker[bitlocker.find("fn unlock_parsed(").unwrap()..];
        let unlock = &unlock[..unlock.find("\n}\n").unwrap()];
        every_call_bounded("bitlocker.rs", unlock, "Relock::with(", &["changing("]);
        let relock = &bitlocker[bitlocker.find("    fn with(device_id: String").unwrap()..];
        assert!(relock[..relock.find("\n    }\n").unwrap()].contains("DUTIES.holder("));
        let apply = &read_limit[read_limit.find("pub fn apply(").unwrap()..];
        let holder = apply.find("DUTIES.holder(").unwrap();
        assert!(holder < apply.find("control.send(Request::Set(tenths))").unwrap());
        every_call_bounded(
            "handles.rs",
            handles,
            "online_duty(number, named)",
            &["owned("],
        );
        // A repair's detach holds the closed volumes until Windows has answered it, and a
        // volume that does not close stops the detach (cause D).
        let finish = &repair[repair.find("fn finish(").unwrap()..];
        let finish = &finish[..finish.find("\n    }\n").unwrap()];
        assert!(finish.contains("vdisk::detach_holding(handle, &self.at, &self.footed, closed)"));
        assert!(
            !finish.contains("vdisk::detach("),
            "a detach that lets the volumes go first"
        );
        let refused = finish.find("if !unclosed.is_empty() {").unwrap();
        assert!(refused < finish.find("detach_holding(").unwrap());
        let detach = &vdisk[vdisk.find("fn detach_holding<").unwrap()..];
        let detach = &detach[..detach.find("\n}\n").unwrap()];
        let let_go = detach.find("drop(held);").unwrap();
        assert!(detach.find("detach_now(&handle)").unwrap() < let_go);
        // A read that gates a change is bounded too, and its timeout refuses the change: the
        // list of every volume and where it lies, which the replacement drive's write, a
        // repair's table write and its detach each need whole.
        let target = cut(include_str!("target.rs"));
        every_call_bounded("target.rs", target, "all_volumes_now", &["in_time("]);
        assert_eq!(target.matches("FindFirstVolumeW(").count(), 1);
        let listing = &target[target.find("fn all_volumes() ->").unwrap()..];
        let listing = &listing[..listing.find("\n}\n").unwrap()];
        assert!(
            listing.contains("_ => Err(format!("),
            "a timed-out list taken as read"
        );
        let every = &target[target.find("pub(crate) fn every_volume_on(").unwrap()..];
        assert!(every[..every.find("\n}\n").unwrap()].contains("let all = all_volumes()?;"));
        // The recovery window waits for every duty before it ends, and settles what an
        // earlier one left as it starts.
        let main = include_str!("../gui/main.rs");
        let run = &main[main.find("fn run_recovery(").unwrap()..];
        let run = &run[..run.find("\n}\n").unwrap()];
        let settled = run.find("pending::settle_at_start();").unwrap();
        assert!(settled < run.find("recovery_view::open_main").unwrap());
        assert!(run.contains("ending_view::wait_for_duties(message_loop)"));
    }

    /// A reading that answers healthy `fine` times, then stalls.
    fn fine_then_stalled(fine: usize) -> Reading {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Arc::new(move || {
            if calls.fetch_add(1, Ordering::Relaxed) < fine {
                let ata = Health::Ata(parse_smart_attributes(&fixtures::healthy_smart()).unwrap());
                return Some(fixtures::disk(ata));
            }
            std::thread::sleep(Duration::from_secs(5));
            None
        })
    }

    /// The guard: a rescue whose health reading stalls ends promptly as the drive not
    /// answering, and its end text says the map is saved only when this run saved one:
    /// a stall, a pause or Stop at the first reading leaves no map and says nothing was
    /// read or written.
    #[test]
    fn every_end_text_says_whether_a_map_was_saved() {
        let dir = std::env::temp_dir().join(format!("diagtool-timed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let limit = Duration::from_millis(300);
        let gone: Reading = Arc::new(|| None);
        let stopped = Arc::new(AtomicBool::new(true));
        let early = [
            (
                stalled(5),
                Arc::new(AtomicBool::new(false)),
                "not answering",
            ),
            (gone, Arc::new(AtomicBool::new(false)), "no longer lists"),
            (stalled(5), stopped, "Stopped before"),
        ];
        for (reading, stop, says) in early {
            let mut disk = MemDisk::new(vec![7u8; 1 << 20]);
            let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
            let map = plan.map.clone();
            let mut watch = HealthWatch::with_reader(reading, limit, stop.clone());
            let ended = rescue(
                plan,
                &mut disk,
                &Settings::for_len(1 << 20),
                &stop,
                &Progress::default(),
                &mut watch,
                &mut ReadLimit::none(),
                &mut Waiter::none(),
            );
            assert!(!ended.map_saved, "{ended:?}");
            assert!(!dir.join("image.map").exists() && disk.reads.is_empty());
            let text = end_text(&ended, Some(&map));
            assert!(text.contains(says), "{text}");
            assert!(
                text.contains("Nothing was read or written") && !text.contains("map"),
                "{text}"
            );
        }
        let mut disk = MemDisk::new(vec![7u8; 1 << 20]);
        let plan = plan_with(&disk, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(fine_then_stalled(1), limit, stop.clone());
        let started = Instant::now();
        let ended = rescue(
            plan,
            &mut disk,
            &Settings::for_len(1 << 20),
            &stop,
            &Progress::default(),
            &mut watch,
            &mut ReadLimit::none(),
            &mut Waiter::none(),
        );
        assert!(started.elapsed() < Duration::from_secs(3), "the run waited");
        assert!(ended.map_saved);
        assert!(matches!(&ended.outcome, Outcome::Gone(why) if why.contains("not answering")));
        let saved = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        // Pass 1 ran; the reading before pass 2 stalled, and the map holds pass 1.
        assert_eq!(saved.count(Status::Rescued), 1 << 20);
        let text = end_text(&ended, Some(&saved));
        assert!(
            text.contains("The map is saved") && text.contains("Rescued 1.0 MB"),
            "{text}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a rescue logs the start and end readings beside the image with its
    /// position and bad bytes, and a drive that answers no health query is still read at
    /// every reading and gets one line.
    #[test]
    fn a_rescue_logs_the_drive_health_beside_the_image() {
        let dir = std::env::temp_dir().join(format!("diagtool-healthlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut silent = fixtures::disk(Health::Unread("SMART is not supported".into()));
        silent.temperature = Err("not supported".into());
        let healthy = fixtures::disk(Health::Ata(
            parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
        ));
        for (name, disk) in [("ata", healthy), ("silent", silent)] {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = calls.clone();
            let read: Reading = Arc::new(move || {
                counted.fetch_add(1, Ordering::Relaxed);
                Some(disk.clone())
            });
            let stop = Arc::new(AtomicBool::new(false));
            let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop.clone());
            let mut source = MemDisk::new(vec![7u8; 1 << 20]);
            source.bad.push(4096..4608);
            let plan = plan_with(&source, &dir, name, u64::MAX / 2, "NTFS").unwrap();
            let progress = Progress::default();
            let ended = rescue(
                plan,
                &mut source,
                &Settings::for_len(1 << 20),
                &stop,
                &progress,
                &mut watch,
                &mut ReadLimit::none(),
                &mut Waiter::none(),
            );
            assert_eq!(ended.outcome, Outcome::Finished);
            let summary = watch.finish_log().unwrap();
            let text = std::fs::read_to_string(dir.join(format!("{name}.health.csv"))).unwrap();
            assert!(text.starts_with("time,kind,"), "{text}");
            if name == "silent" {
                // Still asked at every reading, so readings come back once it answers: one
                // line for the streak, and the end's, which is always written.
                assert!(
                    calls.load(Ordering::Relaxed) > 1,
                    "a silent drive was not read again"
                );
                assert_eq!(text.lines().count(), 3, "{text}");
                assert!(summary.contains("answered no health query"), "{summary}");
            } else {
                // The start, before each pass, and the end, which holds the end figures.
                assert!(text.lines().count() > 3, "{text}");
                assert!(
                    text.lines().nth(1).unwrap().ends_with(",0,0,"),
                    "the start line: {text}"
                );
                let last = text.lines().last().unwrap();
                assert!(last.ends_with(",1048576,512,"), "{last}");
                assert!(summary.contains("Drive health at the start"), "{summary}");
                assert!(!progress.health.lock().unwrap().is_empty());
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a rescue sets the drive's read limit to 1.5 s for the copying passes and
    /// 10 s for the reverse pass and retries, and puts the drive's own value back at the
    /// end and on Stop; a drive that refuses it is read as it is, said once.
    #[test]
    fn the_read_limit_follows_the_passes_and_is_put_back() {
        use crate::recovery::read_limit::{FakeLimit, LimitEvent, QuickGiveUp};
        use crate::tools::drives::sct::{Refusal, Request};
        let dir = std::env::temp_dir().join(format!("diagtool-limit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let healthy: Reading = Arc::new(|| {
            Some(fixtures::disk(Health::Ata(
                parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
            )))
        });
        let run = |name: &str, fake: &FakeLimit, stop_now: bool| {
            let mut disk = MemDisk::new(vec![7u8; 1 << 20]);
            disk.bad.push(4096..4608);
            let plan = plan_with(&disk, &dir, name, u64::MAX / 2, "NTFS").unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let mut watch =
                HealthWatch::with_reader(healthy.clone(), Duration::from_secs(5), stop.clone());
            let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
            let progress = Progress::default();
            let mut source = StopAt {
                disk,
                stop: stop.clone(),
                at: if stop_now { 3 } else { usize::MAX },
            };
            let ended = rescue(
                plan,
                &mut source,
                // One retry pass chosen, the reverse pass, which gets the longer limit.
                &Settings {
                    retries: 1,
                    ..Settings::for_len(1 << 20)
                },
                &stop,
                &progress,
                &mut watch,
                &mut limit,
                &mut Waiter::none(),
            );
            let shown = progress.read_limit.lock().unwrap().clone();
            (ended.outcome, shown)
        };
        let fake = FakeLimit::default();
        *fake.value.lock().unwrap() = 70;
        let (outcome, shown) = run("full", &fake, false);
        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(
            *fake.sent.lock().unwrap(),
            vec![
                Request::Read,
                Request::Set(15),
                Request::Set(100),
                Request::Read,
                Request::Set(70)
            ]
        );
        assert_eq!(shown, Some(LimitEvent::Restored { tenths: 70 }));
        let fake = FakeLimit::default();
        *fake.value.lock().unwrap() = 0;
        let (outcome, _) = run("stopped", &fake, true);
        assert_eq!(outcome, Outcome::Stopped);
        assert_eq!(
            *fake.sent.lock().unwrap(),
            vec![
                Request::Read,
                Request::Set(15),
                Request::Read,
                Request::Set(0)
            ],
            "Stop put the drive's own value back"
        );
        let refused = FakeLimit {
            refuse: Some(Refusal::Refused("the driver does not support it".into())),
            ..FakeLimit::default()
        };
        let (outcome, shown) = run("refused", &refused, false);
        assert_eq!(
            outcome,
            Outcome::Finished,
            "a refusal does not stop the rescue"
        );
        assert_eq!(refused.sent.lock().unwrap().len(), 1);
        assert!(shown.unwrap().text().contains("its own time"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A test disk that asks the run to stop at its `at`th read.
    struct StopAt {
        disk: MemDisk,
        stop: Arc<AtomicBool>,
        at: usize,
    }

    impl BlockSource for StopAt {
        fn len(&self) -> u64 {
            self.disk.len()
        }
        fn sector_size(&self) -> u32 {
            self.disk.sector_size()
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), crate::recovery::ReadError> {
            if self.disk.reads.len() + 1 >= self.at {
                self.stop.store(true, Ordering::Relaxed);
            }
            self.disk.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.disk.describe()
        }
    }

    /// The guard: the watch pauses on the error pause's rate, not on any rise, and says
    /// which counts rose by how much; a drive Windows no longer lists is gone, which the run
    /// waits for, not a pause.
    #[test]
    fn readings_are_judged_by_the_error_rate() {
        use crate::recovery::image::WearRate;
        let ata = |raw: &[u8]| Health::Ata(parse_smart_attributes(raw).unwrap());
        for (rule, pauses) in [
            (WearRate::default(), false),
            (
                WearRate {
                    limit: 10,
                    ..WearRate::default()
                },
                true,
            ),
        ] {
            let readings = Arc::new(std::sync::Mutex::new(vec![
                fixtures::disk(ata(&fixtures::pending_smart())),
                fixtures::disk(ata(&fixtures::healthy_smart())),
            ]));
            let read: Reading = Arc::new(move || readings.lock().unwrap().pop());
            let stop = Arc::new(AtomicBool::new(false));
            let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop);
            watch.wear_rate = rule;
            assert_eq!(watch.check(), Watch::Fine);
            let second = watch.check();
            if pauses {
                assert!(
                    matches!(&second, Watch::Pause(why) if why.contains("reallocated plus pending sectors rose by") && why.contains("10 in 30 min")),
                    "{second:?}"
                );
            } else {
                assert_eq!(second, Watch::Fine, "a rise of a few dozen paused the run");
            }
            assert!(matches!(watch.check(), Watch::Gone(why) if why.contains("no longer lists")));
        }
    }

    /// Images a real disk as the window does, with its health read by the device module:
    /// DIAGTOOL_LIVE_DISK names the disk and DIAGTOOL_LIVE_FOLDER a new folder on another
    /// disk. Needs administrator rights. Stops after 0.3 s and resumes to the end, reading the
    /// health every 2 s, prints the health log and the end text, then deletes it all.
    #[test]
    #[ignore = "reads a physical disk; needs administrator rights and two environment variables"]
    fn live_health_log_of_a_disk() {
        let number: u32 = std::env::var("DIAGTOOL_LIVE_DISK")
            .expect("DIAGTOOL_LIVE_DISK")
            .parse()
            .unwrap();
        assert!(number > 2, "disks 0 to 2 are too large to image here");
        let folder = std::path::PathBuf::from(
            std::env::var("DIAGTOOL_LIVE_FOLDER").expect("DIAGTOOL_LIVE_FOLDER"),
        );
        assert!(!folder.exists(), "{} must be new", folder.display());
        std::fs::create_dir(&folder).unwrap();
        let mut source = open_source_within(SourceChoice::Disk(number), OPEN_LIMIT).unwrap();
        let stem = crate::recovery::image::stem_for(&source.describe());
        eprintln!("source: {} ({} bytes)", source.describe(), source.len());
        let settings = Settings {
            health_every: Duration::from_secs(2),
            ..Settings::for_len(source.len())
        };
        let mut ends = Vec::new();
        for run in 0..20 {
            let stop = Arc::new(AtomicBool::new(false));
            if run == 0 {
                let flag = stop.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    flag.store(true, Ordering::Relaxed);
                });
            }
            let mut plan = crate::recovery::image::plan(source.as_ref(), &folder, &stem).unwrap();
            // A virtual disk has no serial number; the window's Resume asks, this confirms.
            plan.confirm();
            let progress = Progress::default();
            let mut watch = HealthWatch::for_disk(number, stop.clone());
            let ended = rescue(
                plan,
                source.as_mut(),
                &settings,
                &stop,
                &progress,
                &mut watch,
                &mut ReadLimit::none(),
                &mut Waiter::none(),
            );
            let summary = watch.finish_log().unwrap_or_default();
            eprintln!("run {}: {:?}", run + 1, ended.outcome);
            eprintln!("  window: {}", progress.health.lock().unwrap());
            eprintln!("  end text: {summary}");
            ends.push(ended.outcome.clone());
            if ended.outcome != Outcome::Stopped {
                break;
            }
        }
        let log = folder.join(format!("{stem}.health.csv"));
        let text = std::fs::read_to_string(&log).unwrap();
        eprintln!("{}:\n{text}", log.display());
        assert_eq!(ends.first(), Some(&Outcome::Stopped));
        assert_eq!(ends.last(), Some(&Outcome::Finished));
        assert!(text.starts_with("time,kind,"));
        assert_eq!(text.matches("time,kind").count(), 1);
        std::fs::remove_dir_all(&folder).unwrap();
        assert!(!folder.exists());
    }

    /// A source that logs every read, for the live test's order check.
    struct Logged {
        inner: Box<dyn BlockSource>,
        reads: Arc<std::sync::Mutex<Vec<(u64, usize)>>>,
    }

    impl BlockSource for Logged {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), crate::recovery::ReadError> {
            self.reads.lock().unwrap().push((offset, buf.len()));
            self.inner.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
        fn disk_number(&self) -> Option<u32> {
            self.inner.disk_number()
        }
        fn identity(&self) -> Option<crate::recovery::SourceId> {
            self.inner.identity()
        }
    }

    /// Photos first, the read limit and Fill the gaps on a virtual disk made for the test:
    /// DIAGTOOL_LIVE_DISK names the disk (a Msft Virtual Disk, never disk 0, 3 or 4) and
    /// DIAGTOOL_LIVE_FOLDER a new folder on another disk. Needs administrator rights. Run A
    /// images it all with photos first and checks every read of a photo comes before any
    /// read of another file's content; run B stops once the photos are read and Fill the
    /// gaps reads the rest, and its image must equal run A's. Deletes its folder at the end.
    #[test]
    #[ignore = "reads a virtual disk made for it; needs administrator rights and two environment variables"]
    fn live_photos_first_and_fill_of_a_virtual_disk() {
        use crate::recovery::fill::{fill_gaps, FillOptions};
        use crate::recovery::image::{PhotosState, Status};
        use crate::recovery::photos::{self, PhotosFirst};
        use crate::recovery::read_limit::QuickGiveUp;
        use crate::recovery::reader::Reader;
        let number: u32 = std::env::var("DIAGTOOL_LIVE_DISK")
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            ![0, 3, 4].contains(&number),
            "disk {number} is not to be read"
        );
        let folder = std::path::PathBuf::from(std::env::var("DIAGTOOL_LIVE_FOLDER").unwrap());
        assert!(!folder.exists(), "{} must be new", folder.display());
        let opened = open_source_within(SourceChoice::Disk(number), OPEN_LIMIT).unwrap();
        let id = opened.identity().expect("the disk says what it is");
        assert!(
            id.model.contains("Virtual Disk"),
            "disk {number} is {}",
            id.model
        );
        eprintln!("source: {} ({} bytes)", opened.describe(), opened.len());
        let len = opened.len();
        let reads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut source = Logged {
            inner: opened,
            reads: reads.clone(),
        };
        let stem = crate::recovery::image::stem_for(&source.describe());
        let settings = Settings {
            photos_first: PhotosFirst::default(),
            ..Settings::for_len(len)
        };
        // Run A: the whole disk, photos first.
        let a = folder.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let mut plan = crate::recovery::image::plan(&source, &a, &stem).unwrap();
        plan.confirm();
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Progress::default();
        let mut watch = HealthWatch::for_disk(number, stop.clone());
        let mut limit = ReadLimit::for_source(&source, QuickGiveUp::default());
        let started = Instant::now();
        let ended = rescue(
            plan,
            &mut source,
            &settings,
            &stop,
            &progress,
            &mut watch,
            &mut limit,
            &mut Waiter::none(),
        );
        eprintln!(
            "run A: {:?} in {:.1} s",
            ended.outcome,
            started.elapsed().as_secs_f64()
        );
        let status = progress.photos.lock().unwrap().clone().unwrap();
        eprintln!("  window: {}", status.text());
        eprintln!(
            "  window: {}",
            progress
                .read_limit
                .lock()
                .unwrap()
                .as_ref()
                .map(|e| e.text())
                .unwrap_or_else(|| "no read limit line".into())
        );
        eprintln!("  read limit events: {:?}", limit.events);
        eprintln!("  health: {}", watch.finish_log().unwrap_or_default());
        assert_eq!(ended.outcome, Outcome::Finished);
        assert_eq!(status.state, PhotosState::Done);
        // The order: from the finished image, where the photos are and where other files are.
        let image_a = a.join(format!("{stem}.img"));
        let mut reader = Reader::new(Box::new(
            crate::recovery::ImageFile::open(&image_a).unwrap(),
        ));
        let never = AtomicBool::new(false);
        let list = photos::list(&mut reader, &never).unwrap();
        let finds = crate::recovery::fs::parts::find(
            &mut reader,
            crate::recovery::fs::parts::Search::Tables,
            &never,
            &Default::default(),
        );
        let mut others = Vec::new();
        for volume in &finds.volumes {
            let listing =
                crate::recovery::fs::scan(&mut reader, volume, &never, &Default::default())
                    .unwrap();
            for file in listing.files.iter().filter(|f| photos::is_photo(&f.name)) {
                let placed: u64 = match &file.data {
                    crate::recovery::fs::Data::Runs(runs) => runs
                        .iter()
                        .filter(|r| matches!(r.place, crate::recovery::fs::Place::At(_)))
                        .map(|r| r.len)
                        .sum(),
                    crate::recovery::fs::Data::Resident(_) => 0,
                };
                if placed < file.size {
                    eprintln!(
                        "  {} (deleted {}): {} bytes, {placed} placed, {:?}, {:?}",
                        file.name, file.deleted, file.size, file.state, file.why
                    );
                }
            }
            for file in listing.files.iter().filter(|f| !photos::is_photo(&f.name)) {
                if let crate::recovery::fs::Data::Runs(runs) = &file.data {
                    for run in runs {
                        if let crate::recovery::fs::Place::At(at) = run.place {
                            others.push((at, at + run.len, file.name.clone()));
                        }
                    }
                }
            }
        }
        let log = reads.lock().unwrap().clone();
        let touches =
            |read: &(u64, usize), s: u64, e: u64| read.0 < e && s < read.0 + read.1 as u64;
        let last_photo = log
            .iter()
            .rposition(|r| list.extents.iter().any(|(s, e)| touches(r, *s, *e)))
            .unwrap();
        let first_other = log
            .iter()
            .position(|r| others.iter().any(|(s, e, _)| touches(r, *s, *e)))
            .unwrap();
        let other_name = &others
            .iter()
            .find(|(s, e, _)| touches(&log[first_other], *s, *e))
            .unwrap()
            .2;
        eprintln!(
            "  {} photo and video files ({} deleted), {} bytes in {} areas; {} other file areas; {} reads",
            list.files, list.deleted, list.bytes, list.extents.len(), others.len(), log.len()
        );
        eprintln!("  last read of a photo area: read {last_photo} at {}; first read of another file's content: read {first_other} at {} ({other_name})", log[last_photo].0, log[first_other].0);
        eprintln!("  first 12 reads: {:?}", &log[..12.min(log.len())]);
        assert!(last_photo < first_other);
        let map = crate::recovery::image::Map::parse(
            &std::fs::read_to_string(a.join(format!("{stem}.map"))).unwrap(),
        )
        .unwrap();
        assert_eq!(map.count(Status::Rescued), len);
        // Run B: stopped once the photos are read, then Fill the gaps reads the rest.
        let b = folder.join("b");
        std::fs::create_dir_all(&b).unwrap();
        let mut plan = crate::recovery::image::plan(&source, &b, &stem).unwrap();
        plan.confirm();
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let (flag, seen) = (stop.clone(), progress.clone());
        let watcher = std::thread::spawn(move || loop {
            let done = seen
                .photos
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|p| p.state == PhotosState::Done);
            if done || flag.load(Ordering::Relaxed) {
                flag.store(true, Ordering::Relaxed);
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        });
        let mut watch = HealthWatch::for_disk(number, stop.clone());
        let mut limit = ReadLimit::for_source(&source, QuickGiveUp::default());
        let ended = rescue(
            plan,
            &mut source,
            &settings,
            &stop,
            &progress,
            &mut watch,
            &mut limit,
            &mut Waiter::none(),
        );
        stop.store(true, Ordering::Relaxed);
        watcher.join().unwrap();
        let plan = crate::recovery::image::plan(&source, &b, &stem).unwrap();
        let unread = plan.map.len() - plan.map.count(Status::Rescued);
        eprintln!(
            "run B: {:?}; {unread} bytes left unread for Fill the gaps",
            ended.outcome
        );
        assert_eq!(ended.outcome, Outcome::Stopped);
        let mut plan = plan;
        plan.confirm();
        let stop = AtomicBool::new(false);
        let mut watch = HealthWatch::for_disk(number, Arc::new(AtomicBool::new(false)));
        let mut limit = ReadLimit::for_source(&source, QuickGiveUp::default());
        let started = Instant::now();
        let options = FillOptions {
            passes: 2,
            rest_secs: 5,
            ..FillOptions::default()
        };
        let mut said = Vec::new();
        let result = fill_gaps(
            plan,
            &mut source,
            &options,
            &mut watch,
            &mut limit,
            &mut Waiter::none(),
            &stop,
            &Progress::default(),
            &mut |event| {
                if !matches!(event, crate::recovery::fill::FillEvent::Progress { .. }) {
                    said.push(event);
                }
            },
        );
        eprintln!(
            "fill: {:?} in {:.1} s",
            result.end,
            started.elapsed().as_secs_f64()
        );
        for event in &said {
            eprintln!("  event: {event:?}");
        }
        eprintln!("  passes: {:?}", result.passes);
        eprintln!("  end text: {}", result.text());
        eprintln!("  health: {:?}", result.health);
        assert_eq!(result.unread_after, 0);
        let image_b = b.join(format!("{stem}.img"));
        let (x, y) = (
            std::fs::read(&image_a).unwrap(),
            std::fs::read(&image_b).unwrap(),
        );
        assert!(x == y, "run B's filled image differs from run A's");
        eprintln!("run B's filled image equals run A's ({} bytes)", x.len());
        drop(reader);
        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// One health reading of a real disk as the log takes it, without imaging it:
    /// DIAGTOOL_LIVE_HEALTH_DISK names the disk. Needs administrator rights for SMART.
    #[test]
    #[ignore = "reads a physical disk's health; needs administrator rights"]
    fn live_health_reading_of_a_disk() {
        let number: u32 = std::env::var("DIAGTOOL_LIVE_HEALTH_DISK")
            .expect("DIAGTOOL_LIVE_HEALTH_DISK")
            .parse()
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::for_disk(number, stop);
        assert_eq!(watch.check(), Watch::Fine);
        let latest = watch.latest.clone().expect("a reading");
        let reading = health_log::Reading::of(latest.as_ref().map_err(String::as_str), 0, 0);
        eprint!("{}{}", health_log::HEADER, reading.line());
        let mut log = HealthLog::start(
            "live.health.csv".into(),
            Err(std::io::Error::other("not written")),
        );
        log.add(reading.clone());
        log.add(reading);
        eprintln!("window: {}", log.live_text());
    }

    // ---- a drive that stops answering, the heat pause, the error pause -------------------

    /// A test disk shared with the test, so its reads can be looked at while a run holds it,
    /// under the disk number it came back as.
    #[derive(Clone)]
    struct Shared(Arc<Mutex<MemDisk>>, Option<u32>);

    impl BlockSource for Shared {
        fn len(&self) -> u64 {
            self.0.lock().unwrap().len()
        }
        fn sector_size(&self) -> u32 {
            self.0.lock().unwrap().sector_size()
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), crate::recovery::ReadError> {
            self.0.lock().unwrap().read_at(offset, buf)
        }
        fn describe(&self) -> String {
            format!("Disk {}, test disk", self.1.unwrap_or(0))
        }
        fn disk_number(&self) -> Option<u32> {
            self.1
        }
        fn identity(&self) -> Option<crate::recovery::SourceId> {
            self.0.lock().unwrap().identity()
        }
        fn answering(&mut self) -> bool {
            self.0.lock().unwrap().answering()
        }
    }

    /// Finds nothing for `after` looks, then offers `back` at every look; at its first look
    /// notes the saved map and what the window says, and sets `stop` at look `stop_at`.
    struct Replug {
        back: Vec<Shared>,
        after: usize,
        looks: usize,
        map: std::path::PathBuf,
        progress: Arc<Progress>,
        seen: Arc<Mutex<Vec<String>>>,
        stop_at: Option<(usize, Arc<AtomicBool>)>,
    }

    impl wait::Finder for Replug {
        fn look(&mut self, _meant: &crate::recovery::SourceId) -> Vec<Box<dyn BlockSource>> {
            self.looks += 1;
            if self.looks == 1 {
                let map = Map::parse(&std::fs::read_to_string(&self.map).unwrap()).unwrap();
                let mut seen = self.seen.lock().unwrap();
                seen.push(format!(
                    "failed {}, rescued {}, at {}",
                    map.failed(),
                    map.count(Status::Rescued),
                    map.current_pos
                ));
                seen.push(Progress::read(&self.progress.waiting).unwrap_or_default());
            }
            if let Some((at, stop)) = &self.stop_at {
                if self.looks >= *at {
                    stop.store(true, Ordering::Relaxed);
                }
            }
            if self.looks > self.after {
                self.back
                    .iter()
                    .map(|b| Box::new(b.clone()) as Box<dyn BlockSource>)
                    .collect()
            } else {
                Vec::new()
            }
        }
    }

    fn drop_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("diagtool-drop-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The run's event log beside the image, each line checked to be whole JSON.
    fn events_in(dir: &std::path::Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(dir.join("image.events.jsonl")).unwrap();
        assert!(text.ends_with('\n'), "{text}");
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
            .collect()
    }

    /// The state events in order: "started", "paused heat", "resumed drive-gone", ...
    fn states(events: &[serde_json::Value]) -> Vec<String> {
        let kinds = [
            "started",
            "paused",
            "resumed",
            "stopped",
            "finished",
            "app_error",
        ];
        events
            .iter()
            .filter(|e| kinds.contains(&e["event"].as_str().unwrap()))
            .map(|e| match e["kind"].as_str() {
                Some(kind) => format!("{} {kind}", e["event"].as_str().unwrap()),
                None => e["event"].as_str().unwrap().to_string(),
            })
            .collect()
    }

    fn named<'a>(events: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
        events.iter().filter(|e| e["event"] == name).collect()
    }

    fn healthy() -> Reading {
        Arc::new(|| {
            Some(fixtures::disk(Health::Ata(
                parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
            )))
        })
    }

    /// 4 KiB reads and an 8 KiB first drop skip, so a 1 MiB disk shows them.
    fn small_steps(len: u64) -> Settings {
        Settings {
            cluster: 4096,
            skip: 4096,
            max_skip: len / 8,
            drop_skip: 8192,
            ..Settings::for_len(len)
        }
    }

    fn replug(
        back: Vec<Shared>,
        after: usize,
        map: &std::path::Path,
        progress: &Arc<Progress>,
    ) -> Replug {
        Replug {
            back,
            after,
            looks: 0,
            map: map.to_path_buf(),
            progress: progress.clone(),
            seen: Arc::new(Mutex::new(Vec::new())),
            stop_at: None,
        }
    }

    /// The guard: a drive that stops answering while Windows keeps its device (every read
    /// fails with 1117, the device still answers to its number) gets nothing marked. The
    /// run pauses with the map saved, tells the technician to replug it, and when the same
    /// drive comes back under another number carries on from the same pass, past the drop
    /// skip, to the end; the skipped span is read by a later pass and the image is whole.
    #[test]
    fn a_drive_that_stops_answering_pauses_and_carries_on_when_it_is_back() {
        let dir = drop_dir("back");
        let len = 1 << 20;
        let data: Vec<u8> = (0..len).map(|i| (i * 7 / 512 + i) as u8).collect();
        let mut stalling = MemDisk::new(data.clone());
        stalling.stalls_after = Some(40);
        // Its own serial, which carrying on unattended needs.
        stalling.drive = Some(crate::tools::drives::ata::DriveId {
            model: "TEST MODEL".into(),
            serial: "DRIVE-0001".into(),
        });
        let back = Arc::new(Mutex::new(stalling.again()));
        let first = Arc::new(Mutex::new(stalling));
        let mut source = Shared(first.clone(), None);
        // As on 2026-11-09, the health query fails too once the drive has stopped, and is
        // answered again once it is back.
        let (gone, came_back) = (first.clone(), back.clone());
        let read: Reading = Arc::new(move || {
            let stopped = gone.lock().unwrap().reads.len() >= 40;
            let returned = !came_back.lock().unwrap().reads.is_empty();
            Some(if stopped && !returned {
                at(None)
            } else {
                fixtures::disk(Health::Ata(
                    parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
                ))
            })
        });
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let progress = Arc::new(Progress::default());
        let finder = replug(
            vec![Shared(back.clone(), Some(3))],
            2,
            &plan.map_path,
            &progress,
        );
        let seen = finder.seen.clone();
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(10));
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop.clone());
        let settings = Settings {
            health_every: Duration::ZERO,
            ..small_steps(len as u64)
        };
        let ended = rescue(
            plan,
            &mut source,
            &settings,
            &stop,
            &progress,
            &mut watch,
            &mut ReadLimit::none(),
            &mut waiter,
        );
        assert_eq!(ended.outcome, Outcome::Finished);
        // The stalled drive: 40 reads, the one in flight, and nothing more.
        assert_eq!(first.lock().unwrap().reads.len(), 41);
        assert!(first.lock().unwrap().probes >= 1);
        // While it waited: the map saved with only the read in flight marked failed, so no
        // pass starts at it again, past the skip, and the window told to replug it.
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0], "failed 4096, rescued 163840, at 172032");
        assert!(
            seen[1].contains("Unplug it, wait 30 seconds and plug it back in; the rescue continues when the same drive is back."),
            "{seen:?}"
        );
        // It carried on past the drop skip, with the drive under its new number.
        assert_eq!(back.lock().unwrap().reads[0], (40 * 4096 + 8192, 4096));
        let resumed = Progress::read(&progress.resumed).unwrap();
        assert!(
            resumed.contains("came back") && resumed.contains("Disk 3"),
            "{resumed}"
        );
        assert!(Progress::read(&progress.waiting).is_none());
        assert_eq!(waiter.take_source().and_then(|s| s.disk_number()), Some(3));
        assert_eq!(std::fs::read(dir.join("image.img")).unwrap(), data);
        let log = std::fs::read_to_string(dir.join("image.health.csv")).unwrap();
        assert!(
            log.contains(",drive stopped answering,") && log.contains(",drive back,"),
            "{log}"
        );
        // The failed health query is logged once, and readings come back with the drive.
        let kinds: Vec<&str> = log.lines().filter_map(|l| l.split(',').nth(1)).collect();
        assert_eq!(kinds.iter().filter(|k| **k == "none").count(), 1, "{log}");
        let back_at = kinds.iter().position(|k| *k == "drive back").unwrap();
        assert!(kinds[back_at..].contains(&"ATA"), "{log}");
        // The event log: one event per change of state, what was seen once each, no pass
        // written twice when it carried on, and the window's messages are the events'.
        let events = events_in(&dir);
        assert_eq!(
            states(&events),
            [
                "started",
                "paused drive-gone",
                "resumed drive-gone",
                "finished"
            ]
        );
        let gone = named(&events, "drive_gone");
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0]["code"], 1117);
        assert_eq!(gone[0]["rescued"], 163_840);
        let back = named(&events, "drive_back");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0]["disk_number"], 3);
        let paused = named(&events, "paused");
        assert_eq!(paused[0]["reason"], seen[1].as_str());
        assert_eq!(paused[0]["state"], "paused");
        assert_eq!(named(&events, "resumed")[0]["reason"], resumed.as_str());
        let phases: Vec<String> = named(&events, "phase")
            .iter()
            .map(|e| format!("{} {}", e["phase"], e["pass"]))
            .collect();
        let mut once = phases.clone();
        once.dedup();
        assert_eq!(phases, once, "a pass was written again when it carried on");
        assert_eq!(phases[0], "\"copying\" 1");
        let health: Vec<&str> = named(&events, "health")
            .iter()
            .map(|e| e["kind"].as_str().unwrap())
            .collect();
        assert_eq!(health.iter().filter(|k| **k == "none").count(), 1);
        let finished = named(&events, "finished");
        assert_eq!(
            finished[0]["reason"].as_str(),
            Progress::read(&progress.ended).as_deref()
        );
        assert_eq!(events.last().unwrap()["event"], "finished");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: while the run waits, another drive is never read, Stop ends the wait at
    /// once with the map saved, and a drive that cannot be told from it (no serial number on
    /// either) ends the run unread, for the technician to confirm on Resume.
    #[test]
    fn only_the_same_drive_is_carried_on_with() {
        let dir = drop_dir("other");
        let len = 1 << 20;
        let mut first = MemDisk::new(vec![7u8; len]);
        first.stalls_after = Some(10);
        first.drive = Some(crate::tools::drives::ata::DriveId {
            model: "TEST MODEL".into(),
            serial: "DRIVE-0001".into(),
        });
        let mut other = first.again();
        other.serial = "OTHER-0002".into();
        // Another drive of the same model and size, told apart by its own serial.
        other.drive = Some(crate::tools::drives::ata::DriveId {
            model: "TEST MODEL".into(),
            serial: "DRIVE-0002".into(),
        });
        let other = Arc::new(Mutex::new(other));
        let plan = plan_with(&first, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let progress = Arc::new(Progress::default());
        let stop = Arc::new(AtomicBool::new(false));
        let mut finder = replug(
            vec![Shared(other.clone(), Some(4))],
            0,
            &plan.map_path,
            &progress,
        );
        finder.stop_at = Some((3, stop.clone()));
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(10));
        let mut watch = HealthWatch::with_reader(healthy(), Duration::from_secs(5), stop.clone());
        let started = Instant::now();
        let ended = rescue(
            plan,
            &mut first,
            &small_steps(len as u64),
            &stop,
            &progress,
            &mut watch,
            &mut ReadLimit::none(),
            &mut waiter,
        );
        assert_eq!(ended.outcome, Outcome::Stopped);
        assert!(ended.map_saved && started.elapsed() < Duration::from_secs(5));
        assert!(
            other.lock().unwrap().reads.is_empty(),
            "another drive was read"
        );
        assert_eq!(first.reads.len(), 11);
        assert!(waiter.take_source().is_none());
        assert!(Progress::read(&progress.waiting).is_none());
        // Stopped while it waited: the log is whole and ends stopped, as the window says.
        let events = events_in(&dir);
        assert_eq!(states(&events), ["started", "paused drive-gone", "stopped"]);
        assert_eq!(
            events.last().unwrap()["reason"].as_str(),
            Progress::read(&progress.ended).as_deref()
        );

        let dir2 = drop_dir("unsure");
        let mut first = MemDisk::new(vec![7u8; len]);
        first.serial = String::new();
        first.stalls_after = Some(10);
        let unsure = Arc::new(Mutex::new(first.again()));
        let plan = plan_with(&first, &dir2, "image", u64::MAX / 2, "NTFS").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let finder = replug(
            vec![Shared(unsure.clone(), Some(5))],
            0,
            &plan.map_path,
            &progress,
        );
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(10))
            .grace(Duration::from_millis(100));
        let mut watch = HealthWatch::with_reader(healthy(), Duration::from_secs(5), stop.clone());
        let ended = rescue(
            plan,
            &mut first,
            &small_steps(len as u64),
            &stop,
            &progress,
            &mut watch,
            &mut ReadLimit::none(),
            &mut waiter,
        );
        assert!(
            matches!(&ended.outcome, Outcome::Unconfirmed(why) if why.contains("cannot be told")),
            "{ended:?}"
        );
        assert!(end_text(&ended, None).contains("Resume asks you to confirm"));
        assert!(
            unsure.lock().unwrap().reads.is_empty(),
            "an unconfirmed drive was read"
        );
        assert_eq!(waiter.take_source().and_then(|s| s.disk_number()), Some(5));
        assert_eq!(
            states(&events_in(&dir2)),
            ["started", "paused drive-gone", "paused user"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    /// The guard: failures the drive gives without a device error (time-outs here) are
    /// recorded only until 64 in a row; then the drive is asked whether it answers, and one
    /// that does not ends the run with nothing more marked.
    #[test]
    fn a_run_of_failures_asks_the_drive_before_marking_more() {
        let dir = drop_dir("runaway");
        let len = 1 << 20;
        let mut first = MemDisk::new(vec![7u8; len]);
        first.stalls_after = Some(40);
        first.stall_error = None;
        let plan = plan_with(&first, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(healthy(), Duration::from_secs(5), stop.clone());
        let ended = rescue(
            plan,
            &mut first,
            &small_steps(len as u64),
            &stop,
            &Progress::default(),
            &mut watch,
            &mut ReadLimit::none(),
            &mut Waiter::none(),
        );
        assert!(
            matches!(&ended.outcome, Outcome::Gone(why) if why.contains("64 times in a row")),
            "{ended:?}"
        );
        assert_eq!(first.reads.len(), 40 + 64);
        assert_eq!(first.probes, 1);
        let saved = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        // 63 failures recorded, and the read that showed the drive gone marked failed too, so
        // no pass starts at it again.
        assert_eq!(saved.failed(), 64 * 4096);
        // Each recorded failure is an event; the one that showed the drive gone is not.
        let events = events_in(&dir);
        assert_eq!(named(&events, "read_error").len(), 63);
        assert_eq!(named(&events, "drive_gone").len(), 1);
        assert_eq!(states(&events), ["started", "paused drive-gone"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: Fill the gaps pauses the same way: only the sector the drive hung on is
    /// marked, bad, and once the drive is back its pass splits what is left, skipping nothing.
    #[test]
    fn fill_the_gaps_pauses_for_the_drive_and_carries_on() {
        use crate::recovery::fill::{fill_gaps, FillEnd, FillOptions};
        let dir = drop_dir("fill");
        let len = 1 << 20;
        let mut first = MemDisk::new(vec![7u8; len]);
        first.stalls_after = Some(100);
        first.drive = Some(crate::tools::drives::ata::DriveId {
            model: "TEST MODEL".into(),
            serial: "DRIVE-0001".into(),
        });
        let back = Arc::new(Mutex::new(first.again()));
        let plan = plan_with(&first, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let progress = Arc::new(Progress::default());
        let finder = replug(
            vec![Shared(back.clone(), Some(6))],
            1,
            &plan.map_path,
            &progress,
        );
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(10));
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(healthy(), Duration::from_secs(5), stop.clone());
        let result = fill_gaps(
            plan,
            &mut first,
            &FillOptions {
                passes: 1,
                rest_secs: 0,
                ..FillOptions::default()
            },
            &mut watch,
            &mut ReadLimit::none(),
            &mut waiter,
            &stop,
            &progress,
            &mut |_| {},
        );
        assert_eq!(result.end, FillEnd::Finished, "{result:?}");
        assert_eq!(first.reads.len(), 101);
        // The pass split the disk at its middle and hung 100 sectors on; nothing is skipped,
        // and the next read is the middle of the longest run left, the first half.
        assert_eq!(first.reads[0].0, len as u64 / 2);
        assert_eq!(back.lock().unwrap().reads[0].0, len as u64 / 4);
        let saved = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        assert_eq!(
            saved.count(Status::Bad),
            512,
            "more than the hung sector was marked"
        );
        assert_eq!(result.unread_after, 512, "only the hung sector is left");
        let events = events_in(&dir);
        assert_eq!(
            states(&events),
            [
                "started",
                "paused drive-gone",
                "resumed drive-gone",
                "finished"
            ]
        );
        assert_eq!(events[0]["run"], "fill the gaps");
        assert_eq!(named(&events, "phase").len(), 1);
        assert_eq!(
            events.last().unwrap()["reason"].as_str(),
            Progress::read(&progress.ended).as_deref()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a Fill the gaps pass cut short (the drive gone, then Stop while waiting)
    /// is counted in the result and its end text, as the map holds what it recovered.
    #[test]
    fn an_interrupted_fill_pass_is_counted() {
        use crate::recovery::fill::{fill_gaps, FillEnd, FillOptions};
        let dir = drop_dir("fill-cut");
        let len = 1 << 20;
        let mut first = MemDisk::new(vec![7u8; len]);
        first.stalls_after = Some(100);
        let plan = plan_with(&first, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let progress = Arc::new(Progress::default());
        let stop = Arc::new(AtomicBool::new(false));
        let mut finder = replug(Vec::new(), 0, &plan.map_path, &progress);
        finder.stop_at = Some((1, stop.clone()));
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(10));
        let mut watch = HealthWatch::with_reader(healthy(), Duration::from_secs(5), stop.clone());
        let result = fill_gaps(
            plan,
            &mut first,
            &FillOptions {
                passes: 1,
                rest_secs: 0,
                ..FillOptions::default()
            },
            &mut watch,
            &mut ReadLimit::none(),
            &mut waiter,
            &stop,
            &progress,
            &mut |_| {},
        );
        assert_eq!(result.end, FillEnd::Stopped, "{result:?}");
        assert_eq!(result.recovered, 100 * 512, "{result:?}");
        assert_eq!(result.passes.len(), 1);
        assert!(result.passes[0].ended_early);
        let saved = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        assert_eq!(saved.count(Status::Rescued), result.recovered);
        assert!(
            result.text().contains("before it ended"),
            "{}",
            result.text()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a read limit that could not be set goes in the health log, besides the
    /// window.
    #[test]
    fn a_limit_not_set_goes_in_the_health_log() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(healthy(), Duration::from_secs(5), stop);
        let progress = Progress::default();
        let event = LimitEvent::Skipped {
            why: "the drive has no read limit setting".into(),
        };
        limit_said(event.clone(), &mut watch, &progress);
        let notes: Vec<(&str, &str)> = watch
            .notes
            .iter()
            .map(|(kind, _, text)| (kind.as_str(), text.as_str()))
            .collect();
        assert_eq!(notes, [("read limit", event.text().as_str())]);
        assert!(event.text().contains("USB adapter to reset it"));
        assert_eq!(*progress.read_limit.lock().unwrap(), Some(event));
    }

    /// A drive at `celsius`, or one whose temperature cannot be read.
    fn at(celsius: Option<i16>) -> Disk {
        let mut disk = fixtures::disk(Health::Unread("no SMART in this test".into()));
        disk.temperature = match celsius {
            Some(c) => Ok(crate::tools::drives::health::Temperature {
                current: Some(c),
                warning: None,
                critical: None,
            }),
            None => Err("not reported".into()),
        };
        disk
    }

    /// Readings in turn; the last is repeated.
    fn temps(list: Vec<Option<i16>>) -> Reading {
        let next = Arc::new(Mutex::new(0usize));
        Arc::new(move || {
            let mut at_now = next.lock().unwrap();
            let celsius = list[(*at_now).min(list.len() - 1)];
            *at_now += 1;
            Some(at(celsius))
        })
    }

    fn throttled(read: Reading, stop: Arc<AtomicBool>, resume_now: Arc<AtomicBool>) -> HealthWatch {
        let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop)
            .with_throttle(Throttle::default(), resume_now);
        watch.throttle_every = Duration::from_millis(20);
        watch
    }

    /// The guard: with the heat pause on, the drive is asked for its health once a minute,
    /// not more (each reading is a SMART command a stalled drive must answer), and the
    /// rescue's own interval still governs when it is off.
    #[test]
    fn the_heat_pause_reads_the_drive_once_a_minute() {
        let stop = Arc::new(AtomicBool::new(false));
        let five = Duration::from_secs(300);
        let on = HealthWatch::with_reader(Arc::new(|| None), HEALTH_LIMIT, stop.clone())
            .with_throttle(Throttle::default(), Arc::new(AtomicBool::new(false)));
        assert_eq!(on.every(five), Duration::from_secs(60));
        let off = HealthWatch::with_reader(Arc::new(|| None), HEALTH_LIMIT, stop);
        assert_eq!(off.every(five), five);
    }

    /// The guard: every reading that changes the run's state is kept Always where it is
    /// taken: the drive gone (also in a run of failed readings), the heat pause starting and
    /// ending; the heat pause's other readings are Extra, and without it Scheduled.
    #[test]
    fn readings_that_change_the_run_are_kept_where_they_are_taken() {
        use crate::tools::drives::health::Temperature;
        let stop = Arc::new(AtomicBool::new(false));
        let mut gone = HealthWatch::with_reader(Arc::new(|| None), HEALTH_LIMIT, stop.clone());
        for _ in 0..2 {
            assert!(matches!(gone.check(), Watch::Gone(_)));
            assert_eq!(gone.latest_keep, Keep::Always, "the drive gone");
        }
        let celsius = Arc::new(Mutex::new(vec![36i16, 38, 37, 30]));
        let next = celsius.clone();
        let read: Reading = Arc::new(move || {
            let c = next.lock().unwrap().remove(0);
            let mut disk = fixtures::disk(Health::Unread("no SMART".into()));
            disk.temperature = Ok(Temperature {
                current: Some(c),
                warning: None,
                critical: None,
            });
            Some(disk)
        });
        let mut heat = HealthWatch::with_reader(read, HEALTH_LIMIT, stop.clone())
            .with_throttle(Throttle::default(), Arc::new(AtomicBool::new(false)));
        heat.throttle_every = Duration::from_millis(10);
        let kept: Vec<(Watch, Keep)> = (0..4)
            .map(|_| {
                let watch = heat.check();
                (watch, heat.latest_keep)
            })
            .collect();
        assert_eq!(
            kept,
            [
                (Watch::Fine, Keep::Extra),
                (Watch::Cooling, Keep::Always),
                (Watch::Cooling, Keep::Extra),
                (Watch::Fine, Keep::Always),
            ]
        );
        let mut plain = HealthWatch::with_reader(healthy(), HEALTH_LIMIT, stop);
        assert_eq!(plain.check(), Watch::Fine);
        assert_eq!(plain.latest_keep, Keep::Scheduled);
    }

    /// The guard: with the heat pause on, its extra readings that change nothing are left
    /// out of the health log, and the start and end rows are still written, the end's with
    /// the end figures.
    #[test]
    fn the_heat_pause_leaves_out_repeats_and_keeps_the_end() {
        let dir = std::env::temp_dir().join(format!("diagtool-quietend-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let healthy = fixtures::disk(Health::Ata(
            parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
        ));
        let read: Reading = Arc::new(move || Some(healthy.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let cool = Throttle {
            on: true,
            pause_at: 90,
            resume_at: 80,
        };
        let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop.clone())
            .with_throttle(cool, Arc::new(AtomicBool::new(false)));
        let mut source = MemDisk::new(vec![7u8; 1 << 20]);
        source.bad.push(4096..4608);
        let plan = plan_with(&source, &dir, "quiet", u64::MAX / 2, "NTFS").unwrap();
        let progress = Progress::default();
        let ended = rescue(
            plan,
            &mut source,
            &Settings::for_len(1 << 20),
            &stop,
            &progress,
            &mut watch,
            &mut ReadLimit::none(),
            &mut Waiter::none(),
        );
        assert_eq!(ended.outcome, Outcome::Finished);
        watch.finish_log().unwrap();
        let text = std::fs::read_to_string(dir.join("quiet.health.csv")).unwrap();
        let rows: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(rows.len(), 2, "the start and the end: {text}");
        assert!(rows[0].ends_with(",0,0,"), "the start: {text}");
        assert!(rows[1].ends_with(",1048576,512,"), "the end: {text}");
        drop(watch);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: under the quiet health log, the reading that pauses the run is written
    /// even when it differs from the last row by less than the log would write on its own
    /// (here 1 C, to the drive's critical limit).
    #[test]
    fn the_reading_that_pauses_is_written_by_the_quiet_log() {
        use crate::tools::drives::health::Temperature;
        let celsius = Arc::new(Mutex::new(68i16));
        let next = celsius.clone();
        let read: Reading = Arc::new(move || {
            let mut c = next.lock().unwrap();
            *c += 1;
            let mut disk = fixtures::disk(Health::Unread("no SMART".into()));
            disk.temperature = Ok(Temperature {
                current: Some(*c),
                warning: None,
                critical: Some(70),
            });
            Some(disk)
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop);
        let path = std::env::temp_dir().join(format!(
            "diagtool-quiet-pause-{}.health.csv",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        watch.log = Some(HealthLog::start(path.clone(), Ok(file)).quiet(Duration::from_secs(300)));
        let progress = Progress::default();
        assert_eq!(watch.check(), Watch::Fine);
        watch.note(0, 0, &progress);
        assert!(matches!(watch.check(), Watch::Pause(_)));
        watch.note(4096, 0, &progress);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3, "{text}");
        assert!(text.lines().last().unwrap().contains(",70,4096,"), "{text}");
        drop(watch);
        std::fs::remove_file(&path).unwrap();
    }

    /// The guard: the heat pause pauses at its threshold, does not carry on between the two
    /// thresholds, carries on at the lower one, and logs both.
    #[test]
    fn the_heat_pause_waits_for_the_drive_to_cool() {
        let stop = Arc::new(AtomicBool::new(false));
        let read = temps(vec![
            Some(30),
            Some(37),
            Some(38),
            Some(35),
            Some(31),
            Some(30),
        ]);
        let mut watch = throttled(read, stop, Arc::new(AtomicBool::new(false)));
        let progress = Progress::default();
        assert_eq!(watch.check(), Watch::Fine);
        assert_eq!(watch.check(), Watch::Fine, "paused below the threshold");
        assert_eq!(watch.check(), Watch::Cooling, "not paused at the threshold");
        watch.note(0, 0, &progress);
        let cooling = Progress::read(&progress.cooling).unwrap();
        assert!(
            cooling.contains("38 C at ")
                && cooling.contains("at 30 C or below")
                && cooling.contains("Resume now"),
            "{cooling}"
        );
        let waited = Instant::now();
        assert_eq!(watch.check(), Watch::Cooling, "carried on at 35 C");
        assert!(
            waited.elapsed() >= Duration::from_millis(15),
            "read again without waiting"
        );
        assert_eq!(watch.check(), Watch::Cooling, "carried on at 31 C");
        assert_eq!(watch.check(), Watch::Fine, "still paused at 30 C");
        let kinds: Vec<&str> = watch
            .notes
            .iter()
            .map(|(kind, _, _)| kind.as_str())
            .collect();
        assert_eq!(kinds, ["heat pause", "heat resume"]);
        watch.note(0, 0, &progress);
        assert!(Progress::read(&progress.cooling).is_none());
        assert!(Progress::read(&progress.resumed)
            .unwrap()
            .contains("cooled to 30 C"));
    }

    /// The guard: Resume now carries on at once, and the pause comes back only after the
    /// drive was below it; Stop while cooling ends the wait at once.
    #[test]
    fn resume_now_and_stop_end_the_cooling() {
        let stop = Arc::new(AtomicBool::new(false));
        let resume_now = Arc::new(AtomicBool::new(false));
        let read = temps(vec![Some(40), Some(40), Some(36), Some(39)]);
        let mut watch = throttled(read, stop.clone(), resume_now.clone());
        watch.throttle_every = Duration::from_secs(60);
        assert_eq!(watch.check(), Watch::Cooling);
        resume_now.store(true, Ordering::Relaxed);
        let pressed = Instant::now();
        assert_eq!(watch.check(), Watch::Fine);
        assert!(
            pressed.elapsed() < Duration::from_secs(2),
            "Resume now waited"
        );
        assert_eq!(watch.check(), Watch::Fine, "paused again at once at 40 C");
        assert_eq!(watch.check(), Watch::Fine);
        assert_eq!(watch.check(), Watch::Cooling, "the pause did not come back");
        let stopping = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            stopping.store(true, Ordering::Relaxed);
        });
        let asked = Instant::now();
        assert_eq!(watch.check(), Watch::Stop);
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "Stop waited for the drive to cool"
        );
    }

    /// The guard: a drive whose temperature cannot be read says the heat pause is not
    /// working for it; and after a reading that got no answer, the next readings are taken,
    /// so the heat pause works again.
    #[test]
    fn the_heat_pause_says_when_it_cannot_work_and_comes_back_after_a_failed_reading() {
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Progress::default();
        let mut watch = throttled(
            temps(vec![None]),
            stop.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        watch.log = Some(HealthLog::start(
            std::path::PathBuf::from("unused.csv"),
            Err(std::io::Error::other("no file in this test")),
        ));
        assert_eq!(watch.check(), Watch::Fine);
        watch.note(0, 0, &progress);
        let shown = progress.health.lock().unwrap().clone();
        assert!(
            shown.contains("Heat pause: not working for this drive"),
            "{shown}"
        );
        let mut silent = at(None);
        silent.health = Health::Unread("SMART is not supported".into());
        let calls = Arc::new(Mutex::new(0usize));
        let counted = calls.clone();
        let read: Reading = Arc::new(move || {
            let mut n = counted.lock().unwrap();
            *n += 1;
            Some(if *n == 1 {
                silent.clone()
            } else {
                at(Some(39))
            })
        });
        let mut watch = throttled(read, stop, Arc::new(AtomicBool::new(false)));
        assert_eq!(watch.check(), Watch::Fine);
        assert_eq!(
            watch.check(),
            Watch::Cooling,
            "no reading after one that failed"
        );
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    /// The guard: a rescue that reaches the heat pause stops reading with the map saved,
    /// reads nothing while it cools, carries on from the same place at the lower threshold
    /// and finishes; the pause and the carrying on are in the health log.
    #[test]
    fn a_rescue_pauses_for_heat_and_carries_on() {
        let dir = drop_dir("heat");
        let len = 1 << 20;
        let disk = Arc::new(Mutex::new(MemDisk::new(vec![7u8; len])));
        let reads_then = Arc::new(Mutex::new(Vec::new()));
        let (watched, noted) = (disk.clone(), reads_then.clone());
        let calls = Arc::new(Mutex::new(0usize));
        let read: Reading = Arc::new(move || {
            let mut n = calls.lock().unwrap();
            *n += 1;
            noted
                .lock()
                .unwrap()
                .push(watched.lock().unwrap().reads.len());
            // The start, the first reading in the pass at 40 C, two while cooling, then 29 C.
            let celsius = match *n {
                1 | 2 => 30,
                3 => 40,
                4 | 5 => 34,
                _ => 29,
            };
            Some(at(Some(celsius)))
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = throttled(read, stop.clone(), Arc::new(AtomicBool::new(false)));
        let mut source = Shared(disk.clone(), None);
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let progress = Progress::default();
        let ended = rescue(
            plan,
            &mut source,
            &Settings {
                health_every: Duration::ZERO,
                ..small_steps(len as u64)
            },
            &stop,
            &progress,
            &mut watch,
            &mut ReadLimit::none(),
            &mut Waiter::none(),
        );
        assert_eq!(ended.outcome, Outcome::Finished);
        let reads_then = reads_then.lock().unwrap().clone();
        assert!(reads_then.len() >= 6, "{reads_then:?}");
        assert_eq!(reads_then[3], reads_then[2], "read while cooling");
        assert_eq!(reads_then[5], reads_then[2], "read while cooling");
        let log = std::fs::read_to_string(dir.join("image.health.csv")).unwrap();
        assert!(
            log.contains(",heat pause,") && log.contains(",heat resume,"),
            "{log}"
        );
        assert_eq!(disk.lock().unwrap().reads.len(), len / 4096, "read twice");
        let events = events_in(&dir);
        assert_eq!(
            states(&events),
            ["started", "paused heat", "resumed heat", "finished"]
        );
        let paused = named(&events, "paused");
        assert_eq!(paused[0]["values"]["temperature_c"], 40);
        assert!(
            paused[0]["reason"]
                .as_str()
                .unwrap()
                .starts_with("Paused to let the drive cool: it was 40 C at"),
            "{}",
            paused[0]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: a rescue paused by the error pause logs the reading that paused it once,
    /// at the run's position when it paused, and reads nothing after the decision. The run
    /// of 2026-11-09 logged it twice, the second from the end reading taken after the pause,
    /// with the first at the position last published a moment before.
    #[test]
    fn a_reading_that_pauses_the_run_is_logged_once_where_it_paused() {
        let dir = drop_dir("paused");
        let len = 1 << 20;
        let disk = Arc::new(Mutex::new(MemDisk::new(vec![7u8; len])));
        let reads_then = Arc::new(Mutex::new(Vec::new()));
        let (watched, noted) = (disk.clone(), reads_then.clone());
        let calls = Arc::new(Mutex::new(0usize));
        let read: Reading = Arc::new(move || {
            let mut n = calls.lock().unwrap();
            *n += 1;
            noted
                .lock()
                .unwrap()
                .push(watched.lock().unwrap().reads.len());
            let raw = if *n < 6 {
                fixtures::healthy_smart()
            } else {
                fixtures::pending_smart()
            };
            Some(fixtures::disk(Health::Ata(
                parse_smart_attributes(&raw).unwrap(),
            )))
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop.clone());
        watch.wear_rate = crate::recovery::image::WearRate {
            limit: 10,
            ..crate::recovery::image::WearRate::default()
        };
        let mut source = Shared(disk.clone(), None);
        let plan = plan_with(&source, &dir, "image", u64::MAX / 2, "NTFS").unwrap();
        let settings = Settings {
            health_every: Duration::ZERO,
            ..small_steps(len as u64)
        };
        let progress = Progress::default();
        let ended = rescue(
            plan,
            &mut source,
            &settings,
            &stop,
            &progress,
            &mut watch,
            &mut ReadLimit::none(),
            &mut Waiter::none(),
        );
        assert!(
            matches!(&ended.outcome, Outcome::Paused(why) if why.contains("rose by")),
            "{ended:?}"
        );
        let reads_then = reads_then.lock().unwrap().clone();
        assert_eq!(reads_then.len(), 6, "a reading was taken after the pause");
        assert_eq!(
            disk.lock().unwrap().reads.len(),
            *reads_then.last().unwrap(),
            "read after the pause"
        );
        let saved = Map::parse(&std::fs::read_to_string(dir.join("image.map")).unwrap()).unwrap();
        let log = std::fs::read_to_string(dir.join("image.health.csv")).unwrap();
        let last = log.lines().last().unwrap();
        let pending: Vec<&str> = log
            .lines()
            .filter(|l| l.split(',').nth(3) != Some("0"))
            .skip(1)
            .collect();
        assert_eq!(pending, vec![last], "{log}");
        assert_eq!(
            last.split(',').nth(8),
            Some(saved.current_pos.to_string().as_str()),
            "{log}"
        );
        // The event log: the pausing reading once, at the same position, then the pause with
        // the values that tripped it and the window's words, and nothing after.
        let events = events_in(&dir);
        assert_eq!(states(&events), ["started", "paused error-rate"]);
        let rising: Vec<&serde_json::Value> = named(&events, "health")
            .into_iter()
            .filter(|e| e["pending"] != 0)
            .collect();
        assert_eq!(rising.len(), 1, "{events:?}");
        assert_eq!(rising[0]["position"], saved.current_pos);
        let n = events.len();
        assert_eq!(&events[n - 2], rising[0]);
        let paused = &events[n - 1];
        assert_eq!(paused["kind"], "error-rate");
        assert_eq!(paused["values"]["rule"], "limit");
        assert_eq!(paused["values"]["limit"], 10);
        assert_eq!(paused["position"], saved.current_pos);
        assert_eq!(
            paused["reason"].as_str(),
            Progress::read(&progress.ended).as_deref()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: the event log gets a health reading exactly when the health log gets its
    /// row: readings in a row that got no answer are one event, as they are one row.
    #[test]
    fn health_events_are_the_health_log_rows() {
        let dir = drop_dir("rows");
        let answers = Arc::new(Mutex::new(vec![true, false, false, false, true]));
        let told = answers.clone();
        let read: Reading = Arc::new(move || {
            let answered = told.lock().unwrap().remove(0);
            Some(if answered {
                fixtures::disk(Health::Ata(
                    parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
                ))
            } else {
                at(None)
            })
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut watch = HealthWatch::with_reader(read, Duration::from_secs(5), stop);
        let progress = Progress::default();
        let open = |name: &str| {
            std::fs::File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(dir.join(name))
        };
        progress
            .events
            .start(dir.join("image.events.jsonl"), open("image.events.jsonl"));
        watch.log = Some(HealthLog::start(
            dir.join("image.health.csv"),
            open("image.health.csv"),
        ));
        for _ in 0..5 {
            assert_eq!(watch.check(), Watch::Fine);
            watch.note(0, 0, &progress);
        }
        assert_eq!(progress.events.finish(), None);
        let rows: Vec<String> = std::fs::read_to_string(dir.join("image.health.csv"))
            .unwrap()
            .lines()
            .skip(1)
            .map(|l| l.split(',').nth(1).unwrap().to_string())
            .collect();
        let events: Vec<String> = named(&events_in(&dir), "health")
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(rows, ["ATA", "none", "ATA"]);
        assert_eq!(events, rows);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
