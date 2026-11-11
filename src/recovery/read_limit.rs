//! Quick give-up: how long the drive itself keeps trying one failing read (SCT Error
//! Recovery Control). A failing ATA drive left to itself can spend a minute or more on each
//! bad sector; the first passes ask it to give up after 1.5 s so the easy areas come off
//! first, the retry passes and Fill the gaps let it try for 10 s, and the drive's own value
//! is put back at the end, on Stop and when the run goes away, but only when the drive still
//! holds the value this run set: the drive is read first, and a value someone changed since
//! is left as it is and said. The drive forgets the setting
//! at its next power cycle anyway. NVMe drives and drives without the setting are sent
//! nothing; an ATA drive behind a USB adapter is sent it through the adapter's SCSI/ATA
//! Translation, and a drive or USB adapter that refuses it is read as it is.
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::image::Phase;
use super::pending::Pending;
use super::timed::{owned, Duty, Job, Waited, DUTIES};
use super::{BlockSource, SourceId};
use crate::tools::drives::device::SctDrive;
use crate::tools::drives::sct::{limit_text, Refusal, Request};

/// The longest one read-limit command may take before the drive is taken as not answering.
pub const COMMAND_LIMIT: Duration = Duration::from_secs(15);

/// The longest the process's end waits for the drive to answer one command, a chosen bound
/// four times the limit (none was measured past it). A put back may wait behind the
/// command before it, so it is given two.
pub const COMMAND_ANSWER: Duration = Duration::from_secs(60);

/// Quick give-up's options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickGiveUp {
    /// Set the drive's read limit for the run. Default on.
    pub enabled: bool,
    /// For copying, trimming and scraping, in tenths of a second, 1 to 600. Default 15.
    pub first_tenths: u16,
    /// For the reverse pass, the retries and Fill the gaps, in tenths of a second, 1 to
    /// 600. Default 100.
    pub retry_tenths: u16,
}

impl Default for QuickGiveUp {
    fn default() -> Self {
        Self {
            enabled: true,
            first_tenths: 15,
            retry_tenths: 100,
        }
    }
}

impl QuickGiveUp {
    pub fn off() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Refuses values outside their bounds.
    pub fn check(&self) -> Result<(), String> {
        for (name, value) in [
            ("first_tenths", self.first_tenths),
            ("retry_tenths", self.retry_tenths),
        ] {
            if !(1..=600).contains(&value) {
                return Err(format!("{name} must be 1 to 600, not {value}"));
            }
        }
        Ok(())
    }

    /// The limit for a pass: the longer one for the reverse pass and the retries.
    pub fn for_pass(&self, phase: Phase) -> u16 {
        match phase {
            Phase::Retrying => self.retry_tenths,
            _ => self.first_tenths,
        }
    }
}

/// What setting the drive's read limit did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitEvent {
    /// The drive took the limit; `was` is its own value, put back at the end.
    Set { tenths: u16, was: u16 },
    /// Nothing was sent: the option is off, or the drive has no such setting; says why.
    Skipped { why: String },
    /// The drive or its adapter refused it; the drive takes its own time.
    Refused { why: String },
    /// The drive's own value was put back.
    Restored { tenths: u16 },
    /// Putting it back failed; the drive keeps the last limit until it is power cycled.
    NotRestored { tenths: u16, why: String },
    /// Not put back: the drive no longer held the value this run set (`set`), but `now`, so
    /// something else changed it since, and it was left.
    ChangedSince { set: u16, now: u16 },
    /// Putting it back waits for the drive to answer a command before it: it is done once the
    /// drive answers, and how it ended goes in the session's change record.
    PutBackPending { tenths: u16 },
}

/// What a drive that takes its own time on a bad sector means for the rescue.
const STALL: &str = "A bad area can then stall the drive long enough for Windows or its USB adapter to reset it; the rescue then pauses until it is plugged back in.";

impl LimitEvent {
    /// The text, when it says the drive's limit could not be set (the drive has no such
    /// setting, is not the drive meant, or refused it), for the health log; None otherwise,
    /// and when quick give-up was turned off.
    pub fn not_set(&self) -> Option<String> {
        match self {
            LimitEvent::Skipped { why } if why == QUICK_OFF => None,
            LimitEvent::Skipped { .. } | LimitEvent::Refused { .. } => Some(self.text()),
            _ => None,
        }
    }

    /// For the window and the end text.
    pub fn text(&self) -> String {
        match self {
            LimitEvent::Set { tenths, was } => format!(
                "Drive read limit: {} per failing read (the drive's own was {}; it is put back at the end, and a power cycle also resets it).",
                limit_text(*tenths),
                limit_text(*was)
            ),
            LimitEvent::Skipped { why } if why == QUICK_OFF => {
                format!("Drive read limit: not set, {why}.")
            }
            LimitEvent::Skipped { why } => format!("Drive read limit: not set, {why}. {STALL}"),
            LimitEvent::Refused { why } => format!(
                "Drive read limit: the drive did not accept it ({why}), so it will take its own time on each bad sector, which can be a minute or more. {STALL}"
            ),
            LimitEvent::Restored { tenths } => format!(
                "Drive read limit: put back to the drive's own {}.",
                limit_text(*tenths)
            ),
            LimitEvent::NotRestored { tenths, why } => format!(
                "Drive read limit: could not be put back to {} ({why}); it resets when the drive is next powered off.",
                limit_text(*tenths)
            ),
            LimitEvent::ChangedSince { set, now } => format!(
                "Drive read limit: left at {}, since the drive no longer held the {} this run set; something else changed it.",
                limit_text(*now),
                limit_text(*set)
            ),
            LimitEvent::PutBackPending { tenths } => format!(
                "Drive read limit: the drive has not answered yet, so its own {} is put back once it does, and the session's change record says how that ended; a power cycle also resets it.",
                limit_text(*tenths)
            ),
        }
    }
}

/// Sends one read-limit command to the drive.
pub trait LimitControl: Send {
    fn send(&mut self, request: Request) -> Result<Option<u16>, Refusal>;

    /// The drive's number and identity, for the next start to put its value back when this
    /// process ends first; `None` when it is not a drive.
    fn settles_as(&self) -> Option<(u32, SourceId)> {
        None
    }

    /// Puts the drive's own value `original` back while it holds one of `ours`, the values
    /// this run set (`set` the last sent). `None` when it did not end within the command
    /// limit: it then still runs once the drive answers, and says how it ended in the
    /// session's change record.
    fn put_back(&mut self, original: u16, set: u16, ours: Vec<u16>) -> Option<LimitEvent> {
        Some(put_back_on(
            &mut |request| self.send(request),
            original,
            set,
            &ours,
        ))
    }
}

/// One drive's read-limit commands, answered one at a time.
pub trait Drive: Send + 'static {
    fn command(&mut self, request: Request) -> Result<Option<u16>, Refusal>;
}

/// The drive the source was opened on: opened on its first command and checked there to be
/// that drive (`SctDrive::open`), then held for every later command.
pub struct Opening {
    number: u32,
    meant: SourceId,
    held: Option<SctDrive>,
}

impl Drive for Opening {
    fn command(&mut self, request: Request) -> Result<Option<u16>, Refusal> {
        if self.held.is_none() {
            self.held = Some(SctDrive::open(
                self.number,
                &self.meant.model,
                &self.meant.serial,
            )?);
        }
        self.held
            .as_ref()
            .map_or(Ok(None), |drive| drive.send(request))
    }
}

/// The read limit of the drive being read, each command on a thread of its own within a
/// time limit (`timed::owned`). Every command goes through one held drive, one at a time,
/// so a command that outlives its time limit is still followed by the next one on the same
/// drive, never another. The put back is one job on the drive, its read and its set
/// together, and it owns what it needs: when it waits behind a command that has not ended,
/// it is not given up but done once the drive answers, and its outcome recorded.
pub struct DiskLimit<D: Drive = Opening> {
    drive: Result<Arc<Mutex<D>>, String>,
    limit: Duration,
    /// Its number and identity, journalled with a put back.
    named: Option<(u32, SourceId)>,
}

impl DiskLimit<Opening> {
    pub fn new(number: u32, meant: Option<SourceId>) -> Self {
        Self {
            named: meant.clone().map(|meant| (number, meant)),
            drive: meant
                .map(|meant| {
                    Arc::new(Mutex::new(Opening {
                        number,
                        meant,
                        held: None,
                    }))
                })
                .ok_or_else(|| {
                    "the drive's model and serial number were not read when it was opened".into()
                }),
            limit: COMMAND_LIMIT,
        }
    }
}

impl<D: Drive> DiskLimit<D> {
    /// A read limit over `drive`, each command given `limit`.
    pub fn with_drive(drive: D, limit: Duration) -> Self {
        Self {
            drive: Ok(Arc::new(Mutex::new(drive))),
            limit,
            named: None,
        }
    }

    fn no_answer(&self) -> Refusal {
        Refusal::NoAnswer(format!("no answer within {} s", self.limit.as_secs()))
    }
}

impl<D: Drive> LimitControl for DiskLimit<D> {
    fn send(&mut self, request: Request) -> Result<Option<u16>, Refusal> {
        let drive = self.drive.clone().map_err(Refusal::NotTheDrive)?;
        // A set that answers late is put back by the holder that counts it (`ReadLimit`).
        let job = Job::new("sending the drive a read limit command", self.limit)
            .answered_within(COMMAND_ANSWER);
        match owned(
            job,
            None,
            move || {
                drive
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .command(request)
            },
            // A set that answers late may have taken effect; the put back, queued behind it
            // on the same drive, reads the drive and puts its own value back.
            drop,
        ) {
            Waited::Done(answer) => answer,
            _ => Err(self.no_answer()),
        }
    }

    fn put_back(&mut self, original: u16, set: u16, ours: Vec<u16>) -> Option<LimitEvent> {
        let drive = match self.drive.clone() {
            Ok(drive) => drive,
            Err(why) => {
                return Some(LimitEvent::NotRestored {
                    tenths: original,
                    why,
                })
            }
        };
        let mut job = Job::new("putting the drive's own read limit back", self.limit)
            .answered_within(2 * COMMAND_ANSWER);
        if let Some(pending) = self
            .named
            .as_ref()
            .map(|(number, id)| read_limit_pending(*number, id, original, &ours))
        {
            job = job.settled_by(pending);
        }
        match owned(
            job,
            None,
            move || {
                let mut drive = drive.lock().unwrap_or_else(PoisonError::into_inner);
                put_back_on(&mut |request| drive.command(request), original, set, &ours)
            },
            |late: LimitEvent| {
                crate::handles::record_unseen(
                    "Quick give-up",
                    &format!("After the drive answered late: {}", late.text()),
                );
            },
        ) {
            Waited::Done(event) => Some(event),
            _ => None,
        }
    }

    fn settles_as(&self) -> Option<(u32, SourceId)> {
        self.named.clone()
    }
}

fn read_limit_pending(number: u32, id: &SourceId, original: u16, ours: &[u16]) -> Pending {
    Pending::ReadLimit {
        number,
        model: id.model.clone(),
        serial: id.serial.clone(),
        size: id.size,
        original,
        ours: ours.to_vec(),
    }
}

/// Puts back a read limit a recovery window set and left when it ended, as the next one
/// starts: on the drive of that model and serial number alone, only while it holds one of
/// `ours`, as a run's own put back does.
pub(crate) fn settle(number: u32, drive: SourceId, original: u16, ours: Vec<u16>) -> String {
    let set = ours.first().copied().unwrap_or(original);
    let named = settle_heading(number, &drive);
    let mut limit = DiskLimit::new(number, Some(drive));
    match limit.put_back(original, set, ours) {
        Some(event) => format!("{named}: {}", event.text()),
        None => format!(
            "{named}: putting its own value back got no answer within {} s, so whether it holds it now is not known; a drive resets it when it is next powered off.",
            COMMAND_LIMIT.as_secs()
        ),
    }
}

/// Names the journalled drive as it was then. The journal entry is written just before the
/// set is sent, so it shows only that the earlier window was about to set the limit.
fn settle_heading(number: u32, drive: &SourceId) -> String {
    format!(
        "For the drive that was Disk {number} then ({}, serial number {}), whose read limit an earlier recovery window was setting, or had set, when it ended",
        drive.model, drive.serial
    )
}

/// Reads the drive and puts `original` back while it holds one of `ours`.
///
/// Residual: SCT Error Recovery Control has no compare-and-set, so the read and the set are
/// two commands. Through `DiskLimit` they are sent back to back on the one held drive under
/// its lock, so no other command of this program comes between them; another program
/// sending the drive a read limit in that moment would be overwritten.
fn put_back_on(
    send: &mut dyn FnMut(Request) -> Result<Option<u16>, Refusal>,
    original: u16,
    set: u16,
    ours: &[u16],
) -> LimitEvent {
    let plain = |refusal: Refusal| match refusal {
        Refusal::Refused(why) | Refusal::NotTheDrive(why) | Refusal::NoAnswer(why) => why,
        other => format!("{other:?}"),
    };
    match restore_step(original, ours, send(Request::Read)) {
        Step::Own => LimitEvent::Restored { tenths: original },
        Step::PutBack => match send(Request::Set(original)) {
            Ok(_) => LimitEvent::Restored { tenths: original },
            Err(refusal) => LimitEvent::NotRestored {
                tenths: original,
                why: plain(refusal),
            },
        },
        Step::Leave(now) => LimitEvent::ChangedSince { set, now },
        Step::Unread(refusal) => LimitEvent::NotRestored {
            tenths: original,
            why: format!(
                "its current value could not be read ({}), so it was left as it is",
                plain(refusal)
            ),
        },
    }
}

/// The read limit over one run: read the drive's value once, set what each pass asks for,
/// and put the drive's value back once at the end.
pub struct ReadLimit {
    control: Option<Box<dyn LimitControl>>,
    pub options: QuickGiveUp,
    /// The drive's own value, once read.
    original: Option<u16>,
    /// What the drive holds now, when this run set it, or may hold: a set that got no answer
    /// in time may still take effect.
    current: Option<u16>,
    /// No more limits are set: a set got no answer in time, or a later set was refused.
    /// Putting the drive's own value back is still sent, through the same drive.
    halted: bool,
    /// The last limit the drive acknowledged; it may still hold it when a later set got no
    /// answer and did not take effect.
    confirmed: Option<u16>,
    /// Every event so far.
    pub events: Vec<LimitEvent>,
    /// The drive came back after it stopped answering: the next set is sent even when it
    /// is the value set before, since a replug may have reset the drive's own.
    resend: bool,
    /// Counted from the first set until the drive's own value is put back, so the process's
    /// end waits for it and the next start puts it back if the end comes first.
    duty: Option<Duty>,
}

impl ReadLimit {
    pub fn new(control: Box<dyn LimitControl>, options: QuickGiveUp) -> Self {
        Self {
            control: Some(control),
            options,
            original: None,
            current: None,
            halted: false,
            confirmed: None,
            events: Vec::new(),
            resend: false,
            duty: None,
        }
    }

    /// The read limit of the drive `source` reads, bound to the drive it was opened on; for
    /// a source that is not a disk, nothing is ever sent.
    pub fn for_source(source: &dyn BlockSource, options: QuickGiveUp) -> Self {
        match control_for(source) {
            Some(control) => Self::new(control, options),
            None => Self::none(),
        }
    }

    /// The drive stopped answering and came back as `source`, perhaps under another number:
    /// what is sent from now on goes to it, bound to it as at the start, and the limit is
    /// tried again. The drive's own value, and what this run set, are kept, so the end
    /// puts it back on this drive if it still holds a value this run set. A run that never
    /// had a control (the option off, no such setting) sends nothing still.
    pub fn reconnect(&mut self, source: &dyn BlockSource) {
        if self.control.is_none() {
            return;
        }
        if let Some(control) = control_for(source) {
            self.control = Some(control);
        }
        self.halted = false;
        self.resend = true;
    }

    /// For a source that is not a disk: nothing is ever sent.
    pub fn none() -> Self {
        Self {
            control: None,
            options: QuickGiveUp::off(),
            original: None,
            current: None,
            halted: false,
            confirmed: None,
            events: Vec::new(),
            resend: false,
            duty: None,
        }
    }

    fn note(&mut self, event: LimitEvent) -> Option<LimitEvent> {
        self.events.push(event.clone());
        Some(event)
    }

    /// Sets the drive's limit to `tenths`, reading its own value first. The first refusal
    /// ends it for the run: nothing more is sent but putting a set value back.
    pub fn apply(&mut self, tenths: u16) -> Option<LimitEvent> {
        if !self.options.enabled {
            if self.events.is_empty() {
                return self.note(LimitEvent::Skipped {
                    why: QUICK_OFF.into(),
                });
            }
            return None;
        }
        if self.halted {
            return None;
        }
        let control = self.control.as_mut()?;
        if self.current == Some(tenths) && !self.resend {
            return None;
        }
        if self.original.is_none() {
            match control.send(Request::Read) {
                Ok(Some(value)) => self.original = Some(value),
                Ok(None) => {
                    self.control = None;
                    return self.note(refused(Refusal::Refused("no value came back".into())));
                }
                Err(refusal) => {
                    self.control = None;
                    return self.note(refused(refusal));
                }
            }
        }
        let was = self.original.unwrap_or(0);
        // Counted before the set is sent, with every value the drive may hold after it.
        if let Some((number, id)) = control.settles_as() {
            let ours: Vec<u16> = [Some(tenths), self.current, self.confirmed]
                .into_iter()
                .flatten()
                .collect();
            let pending = read_limit_pending(number, &id, was, &ours);
            let what = format!("putting disk {number}'s own read limit back");
            match &self.duty {
                Some(duty) => duty.now_settled_by(&what, pending),
                None => self.duty = Some(DUTIES.holder(&what, 2 * COMMAND_ANSWER, pending)),
            }
        }
        self.resend = false;
        match control.send(Request::Set(tenths)) {
            Ok(_) => {
                self.current = Some(tenths);
                self.confirmed = Some(tenths);
                self.note(LimitEvent::Set { tenths, was })
            }
            Err(Refusal::NoAnswer(why)) => {
                // It may yet take effect, so the drive's own value is still put back at the
                // end, on the same drive; nothing else is sent.
                self.current = Some(tenths);
                self.halted = true;
                self.note(LimitEvent::Refused { why })
            }
            // The first set refused: nothing was changed, so nothing is put back.
            Err(refusal) if self.current.is_none() => {
                self.control = None;
                self.duty = None;
                self.note(refused(refusal))
            }
            // A later set refused: the drive still holds the earlier one this run set, so the
            // control is kept to put the drive's own value back; nothing else is set.
            Err(refusal) => {
                self.halted = true;
                self.note(refused(refusal))
            }
        }
    }

    /// The limit for a pass.
    pub fn for_pass(&mut self, phase: Phase) -> Option<LimitEvent> {
        let tenths = self.options.for_pass(phase);
        self.apply(tenths)
    }

    /// Puts the drive's own value back, if this run changed it and the drive still holds
    /// what this run set: the drive is read first, through the same held drive, and a value
    /// that differs is left and said (`ChangedSince`). A drive whose value cannot be read is
    /// not written either. A put back still waiting for the drive when its time is up is not
    /// dropped: it is done once the drive answers (`PutBackPending`).
    pub fn restore(&mut self) -> Option<LimitEvent> {
        let (Some(original), Some(set)) = (self.original, self.current) else {
            return None;
        };
        self.current = None;
        let Some(control) = self.control.as_mut() else {
            return self.note(LimitEvent::NotRestored {
                tenths: original,
                why: "the drive could no longer be reached".into(),
            });
        };
        let ours: Vec<u16> = [Some(set), self.confirmed].into_iter().flatten().collect();
        let event = control.put_back(original, set, ours);
        // Put back, or the put back still running counts and journals itself.
        self.duty = None;
        match event {
            Some(event) => self.note(event),
            None => self.note(LimitEvent::PutBackPending { tenths: original }),
        }
    }
}

/// What a restore does, from the value this run set and what reading the drive gave.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The drive holds its own value already (a set that got no answer did not take).
    Own,
    /// The drive holds a value this run set: put its own value back.
    PutBack,
    /// It holds something else now: leave it.
    Leave(u16),
    /// It could not be read: leave it.
    Unread(Refusal),
}

/// `ours` holds the values this run set that the drive may hold: the last one sent, and the
/// last one it acknowledged.
fn restore_step(original: u16, ours: &[u16], read: Result<Option<u16>, Refusal>) -> Step {
    match read {
        Ok(Some(now)) if now == original => Step::Own,
        Ok(Some(now)) if ours.contains(&now) => Step::PutBack,
        Ok(Some(now)) => Step::Leave(now),
        Ok(None) => Step::Unread(Refusal::Refused("no value came back".into())),
        Err(refusal) => Step::Unread(refusal),
    }
}

impl Drop for ReadLimit {
    fn drop(&mut self) {
        // A run that ends any other way (a panic) still puts the drive's value back, and what
        // could not be is recorded where the report finds it.
        match self.restore() {
            None | Some(LimitEvent::Restored { .. }) => {}
            Some(other) => crate::handles::record_unseen("Quick give-up", &other.text()),
        }
    }
}

/// The control for the drive `source` reads, bound to the drive it was opened on; None for
/// a source that is not a disk.
fn control_for(source: &dyn BlockSource) -> Option<Box<dyn LimitControl>> {
    let number = source.disk_number()?;
    Some(Box::new(DiskLimit::new(number, source.identity())))
}

/// Why nothing was sent when quick give-up is off.
const QUICK_OFF: &str = "quick give-up is off";

fn refused(refusal: Refusal) -> LimitEvent {
    match refusal {
        Refusal::NotAta(bus) => LimitEvent::Skipped {
            why: format!("the drive is on {bus}, which has no such setting; it takes its own time on a bad sector")
        },
        Refusal::NoSetting => LimitEvent::Skipped {
            why: "the drive says it has no such setting; it takes its own time on a bad sector"
                .into(),
        },
        Refusal::NotTheDrive(why) => LimitEvent::Skipped {
            why: format!("{why}; it takes its own time on a bad sector"),
        },
        Refusal::Refused(why) | Refusal::NoAnswer(why) => LimitEvent::Refused { why },
    }
}

/// A drive for tests: holds a limit, records every command, and refuses as told.
#[derive(Clone, Default)]
pub struct FakeLimit {
    pub sent: std::sync::Arc<std::sync::Mutex<Vec<Request>>>,
    pub value: std::sync::Arc<std::sync::Mutex<u16>>,
    pub refuse: Option<Refusal>,
    /// Every set takes effect but gets no answer in time.
    pub set_unanswered: bool,
    /// Sets after this many are refused (and change nothing).
    pub refuse_sets_after: Option<usize>,
    /// Reads after this many are refused.
    pub refuse_reads_after: Option<usize>,
}

impl LimitControl for FakeLimit {
    fn send(&mut self, request: Request) -> Result<Option<u16>, Refusal> {
        self.sent.lock().unwrap().push(request);
        if let Some(refusal) = &self.refuse {
            return Err(refusal.clone());
        }
        let sent = self.sent.lock().unwrap().clone();
        let before =
            |kind: fn(&Request) -> bool| sent[..sent.len() - 1].iter().filter(|r| kind(r)).count();
        let mut value = self.value.lock().unwrap();
        match request {
            Request::Read
                if self
                    .refuse_reads_after
                    .is_some_and(|n| before(|r| *r == Request::Read) >= n) =>
            {
                Err(Refusal::Refused("the drive did not answer the read".into()))
            }
            Request::Set(_)
                if self
                    .refuse_sets_after
                    .is_some_and(|n| before(|r| matches!(r, Request::Set(_))) >= n) =>
            {
                Err(Refusal::Refused("the drive refused the set".into()))
            }
            Request::Read => Ok(Some(*value)),
            Request::Set(tenths) => {
                *value = tenths;
                if self.set_unanswered {
                    return Err(Refusal::NoAnswer("no answer within 15 s".into()));
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_start_names_a_journalled_set_only_as_intended() {
        // The entry is journalled before the Set is sent, so the next start cannot know it was sent.
        let drive = crate::recovery::SourceId {
            model: "M".into(),
            serial: "S".into(),
            size: 1,
            drive: None,
            sector: None,
            scope: None,
            disk_size: None,
        };
        let text = super::settle_heading(3, &drive);
        assert!(text.contains("was setting, or had set"), "{text}");
        assert!(!text.contains("window set"), "{text}");
        assert!(
            text.contains("the drive that was Disk 3 then (M, serial number S)"),
            "{text}"
        );
    }

    use super::*;

    #[test]
    fn the_limit_is_set_per_pass_and_put_back_once() {
        let fake = FakeLimit::default();
        *fake.value.lock().unwrap() = 70;
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        assert!(matches!(
            limit.for_pass(Phase::Copying),
            Some(LimitEvent::Set {
                tenths: 15,
                was: 70
            })
        ));
        assert_eq!(limit.for_pass(Phase::Trimming), None, "already 1.5 s");
        assert!(matches!(
            limit.for_pass(Phase::Retrying),
            Some(LimitEvent::Set { tenths: 100, .. })
        ));
        assert_eq!(limit.restore(), Some(LimitEvent::Restored { tenths: 70 }));
        assert_eq!(limit.restore(), None, "put back once");
        drop(limit);
        assert_eq!(*fake.value.lock().unwrap(), 70);
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
    }

    /// The guard: a set that gets no answer in time may still take effect, so the drive's
    /// own value is put back at the end, and nothing else is set in between.
    #[test]
    fn a_set_with_no_answer_is_still_put_back() {
        let fake = FakeLimit {
            set_unanswered: true,
            ..FakeLimit::default()
        };
        *fake.value.lock().unwrap() = 70;
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        let said = limit.for_pass(Phase::Copying).unwrap();
        assert!(matches!(said, LimitEvent::Refused { .. }), "{said:?}");
        assert_eq!(*fake.value.lock().unwrap(), 15, "the late set took effect");
        assert_eq!(limit.for_pass(Phase::Retrying), None, "set after no answer");
        assert!(matches!(
            limit.restore(),
            Some(LimitEvent::NotRestored { tenths: 70, .. })
        ));
        assert_eq!(*fake.value.lock().unwrap(), 70, "the drive's own value");
        assert_eq!(
            *fake.sent.lock().unwrap(),
            vec![
                Request::Read,
                Request::Set(15),
                Request::Read,
                Request::Set(70)
            ]
        );
    }

    /// The guard: the drive's own value is put back only while the drive still holds the
    /// value this run set. It is read first through the same drive; a value changed since is
    /// left and said, and a value that cannot be read is not written over.
    #[test]
    fn a_limit_changed_since_is_left_and_said() {
        let fake = FakeLimit::default();
        *fake.value.lock().unwrap() = 70;
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        limit.for_pass(Phase::Copying);
        // Another program, or a power cycle, sets it to 3 s.
        *fake.value.lock().unwrap() = 30;
        let said = limit.restore().unwrap();
        assert_eq!(said, LimitEvent::ChangedSince { set: 15, now: 30 });
        assert!(said.text().contains("left at 3 s"), "{}", said.text());
        assert_eq!(
            *fake.value.lock().unwrap(),
            30,
            "a later change was overwritten"
        );
        assert_eq!(
            *fake.sent.lock().unwrap(),
            vec![Request::Read, Request::Set(15), Request::Read]
        );
        let unread = FakeLimit {
            refuse_reads_after: Some(1),
            ..FakeLimit::default()
        };
        *unread.value.lock().unwrap() = 70;
        let mut limit = ReadLimit::new(Box::new(unread.clone()), QuickGiveUp::default());
        limit.for_pass(Phase::Copying);
        let said = limit.restore().unwrap();
        assert!(
            matches!(&said, LimitEvent::NotRestored { tenths: 70, why } if why.contains("could not be read")),
            "{said:?}"
        );
        assert_eq!(*unread.value.lock().unwrap(), 15, "written without a read");
        assert_eq!(
            *unread.sent.lock().unwrap(),
            vec![Request::Read, Request::Set(15), Request::Read]
        );
        assert_eq!(restore_step(70, &[15], Ok(Some(15))), Step::PutBack);
        assert_eq!(restore_step(70, &[15], Ok(Some(30))), Step::Leave(30));
        assert_eq!(restore_step(70, &[15], Ok(Some(70))), Step::Own);
        // A set of 10 s got no answer and did not take: the 1.5 s acknowledged before it is
        // still this run's, and is put back.
        assert_eq!(restore_step(70, &[100, 15], Ok(Some(15))), Step::PutBack);
        assert!(matches!(restore_step(70, &[15], Ok(None)), Step::Unread(_)));
    }

    /// The guard: a set refused after an earlier one took leaves the earlier one on the
    /// drive, so the drive is still sent its own value back at the end (and what happened is
    /// said), never dropped in silence.
    #[test]
    fn a_later_refusal_still_puts_the_earlier_set_back() {
        let fake = FakeLimit {
            refuse_sets_after: Some(1),
            ..FakeLimit::default()
        };
        *fake.value.lock().unwrap() = 70;
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        assert!(matches!(
            limit.for_pass(Phase::Copying),
            Some(LimitEvent::Set { tenths: 15, .. })
        ));
        assert!(matches!(
            limit.for_pass(Phase::Retrying),
            Some(LimitEvent::Refused { .. })
        ));
        assert_eq!(limit.for_pass(Phase::Copying), None, "set after a refusal");
        let said = limit.restore();
        assert!(
            matches!(said, Some(LimitEvent::NotRestored { tenths: 70, .. })),
            "{said:?}"
        );
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
    }

    /// The guard: when the drive comes back after it stopped answering, the read limit is
    /// sent to it again, as a replug resets the drive's own; a run that never had a limit to
    /// send still sends none.
    #[test]
    fn the_read_limit_is_sent_again_when_the_drive_is_back() {
        let fake = FakeLimit::default();
        let sets = || {
            fake.sent
                .lock()
                .unwrap()
                .iter()
                .filter(|r| matches!(r, Request::Set(_)))
                .count()
        };
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        assert!(matches!(
            limit.for_pass(Phase::Copying),
            Some(LimitEvent::Set { .. })
        ));
        assert_eq!(limit.for_pass(Phase::Copying), None);
        assert_eq!(sets(), 1);
        let back = crate::recovery::MemDisk::new(vec![0; 4096]);
        limit.reconnect(&back);
        assert!(matches!(
            limit.for_pass(Phase::Copying),
            Some(LimitEvent::Set { .. })
        ));
        assert_eq!(sets(), 2);
        assert_eq!(limit.for_pass(Phase::Copying), None);
        let mut none = ReadLimit::none();
        none.reconnect(&back);
        assert!(!matches!(
            none.for_pass(Phase::Copying),
            Some(LimitEvent::Set { .. })
        ));
    }

    /// The guard: a read limit that is not set says plainly that a bad area can then stall
    /// the drive until Windows or its USB adapter resets it, and that text is what the health
    /// log gets; quick give-up turned off says only that.
    #[test]
    fn a_limit_not_set_says_a_bad_area_can_stall_the_drive() {
        let stall = "stall the drive long enough for Windows or its USB adapter to reset it";
        for event in [
            LimitEvent::Skipped {
                why: "the drive has no read limit setting".into(),
            },
            LimitEvent::Refused {
                why: "it answered with an error".into(),
            },
        ] {
            assert!(event.text().contains(stall), "{}", event.text());
            assert_eq!(event.not_set(), Some(event.text()));
        }
        let off = LimitEvent::Skipped {
            why: QUICK_OFF.into(),
        };
        assert!(!off.text().contains(stall), "{}", off.text());
        assert_eq!(off.not_set(), None);
        assert_eq!(LimitEvent::Set { tenths: 70, was: 0 }.not_set(), None);
    }

    /// The guard: the drive's read limit is bound to the drive the source was opened on.
    /// Its model and serial number go with every command, the drive is opened once and held,
    /// and a source whose drive was not identified is sent nothing.
    #[test]
    fn the_read_limit_is_sent_only_to_the_drive_being_read() {
        let code = include_str!("read_limit.rs");
        let code = &code[..code.find("#[cfg(test)]").unwrap()];
        assert!(!code.contains("for_disk("), "a limit by disk number alone");
        // The second is the next start's put back, on the model and serial journalled.
        assert_eq!(code.matches("DiskLimit::new(").count(), 2);
        assert!(code.contains("DiskLimit::new(number, source.identity())"));
        assert!(code.contains("DiskLimit::new(number, Some(drive))"));
        assert_eq!(code.matches("SctDrive::open(").count(), 1);
        assert!(code.contains("if self.held.is_none() {"));
        assert!(code.contains(
            "SctDrive::open(\n                self.number,\n                &self.meant.model,\n                &self.meant.serial,"
        ));
        let mut unnamed = DiskLimit::new(u32::MAX, None);
        assert!(matches!(
            unnamed.send(Request::Read),
            Err(Refusal::NotTheDrive(_))
        ));
        let said = refused(Refusal::NotTheDrive("no serial".into())).text();
        assert!(
            said.contains("not set") && said.contains("no serial"),
            "{said}"
        );
    }

    /// A drive whose sets wait until the test lets them go, as a drive stuck on a command
    /// does; reads answer at once once the drive is free.
    struct Stuck {
        value: Arc<Mutex<u16>>,
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl Drive for Stuck {
        fn command(&mut self, request: Request) -> Result<Option<u16>, Refusal> {
            match request {
                Request::Read => Ok(Some(*self.value.lock().unwrap())),
                Request::Set(tenths) => {
                    let (open, opened) = &*self.gate;
                    let mut open = open.lock().unwrap();
                    while !*open {
                        open = opened.wait(open).unwrap();
                    }
                    *self.value.lock().unwrap() = tenths;
                    Ok(None)
                }
            }
        }
    }

    /// The guard (cause H): a set that outlives its time limit, and the put back queued
    /// behind it on the same drive, are not forgotten. The put back owns the drive's own
    /// value and what this run set, waits for the drive, and puts the value back once the
    /// late set has ended; the run says it is pending in the meantime.
    #[test]
    fn a_put_back_behind_a_late_set_is_done_when_the_drive_answers() {
        let value = Arc::new(Mutex::new(70));
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let drive = Stuck {
            value: value.clone(),
            gate: gate.clone(),
        };
        let mut limit = ReadLimit::new(
            Box::new(DiskLimit::with_drive(drive, Duration::from_millis(200))),
            QuickGiveUp::default(),
        );
        assert!(matches!(
            limit.for_pass(Phase::Copying),
            Some(LimitEvent::Refused { .. })
        ));
        assert_eq!(
            limit.restore(),
            Some(LimitEvent::PutBackPending { tenths: 70 })
        );
        assert_eq!(*value.lock().unwrap(), 70, "the set has not ended yet");
        // The run ends; only the drive's commands still running hold it.
        drop(limit);
        let (open, opened) = &*gate;
        *open.lock().unwrap() = true;
        opened.notify_all();
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < until {
            // The late set takes the drive to 1.5 s, then the put back returns it to 7 s.
            if *value.lock().unwrap() == 70 && Arc::strong_count(&value) == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            *value.lock().unwrap(),
            70,
            "the late set was left on the drive"
        );
        assert_eq!(Arc::strong_count(&value), 1, "the put back never ended");
    }

    #[test]
    fn a_refusal_ends_it_and_is_said_once() {
        let fake = FakeLimit {
            refuse: Some(Refusal::Refused("the driver does not support it".into())),
            ..FakeLimit::default()
        };
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        let said = limit.for_pass(Phase::Copying).unwrap();
        assert!(said.text().contains("take its own time"), "{}", said.text());
        assert_eq!(limit.for_pass(Phase::Retrying), None);
        assert_eq!(limit.restore(), None);
        assert_eq!(fake.sent.lock().unwrap().len(), 1, "sent after a refusal");
        let nvme = FakeLimit {
            refuse: Some(Refusal::NotAta("NVMe".into())),
            ..FakeLimit::default()
        };
        let mut limit = ReadLimit::new(Box::new(nvme), QuickGiveUp::default());
        let said = limit.for_pass(Phase::Copying).unwrap().text();
        assert!(said.contains("not set") && said.contains("NVMe"), "{said}");
        // Dropped without a restore: a value set is put back.
        let fake = FakeLimit::default();
        let mut limit = ReadLimit::new(Box::new(fake.clone()), QuickGiveUp::default());
        limit.for_pass(Phase::Copying);
        drop(limit);
        assert_eq!(*fake.value.lock().unwrap(), 0);
        assert!(QuickGiveUp {
            first_tenths: 0,
            ..QuickGiveUp::default()
        }
        .check()
        .is_err());
    }
}
