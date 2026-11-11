//! Waiting for a drive that stopped answering. A USB drive whose adapter reset it can stay
//! listed by Windows while it answers nothing, and only a replug brings it back, often under
//! another disk number. Rescue image and Fill the gaps then pause with the map saved, ask the
//! technician to replug it, look through the disks every few seconds for the same drive, and
//! carry on with it from the same pass and place, past a skip. Only a drive that matches the
//! map as the same one is taken on its own; one that cannot be told from it ends the run for
//! the technician to confirm on Resume, and another drive is never read.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use super::events::{Event, Figures, PauseKind};
use super::image::{match_drive, Match, Outcome, Progress, Rescue};
use super::timed::{open_source_within, OPEN_LIMIT};
use super::{BlockSource, Scope, SourceChoice, SourceId};
use crate::handles::HeldDisk;
use crate::tools::drives::{bytes_text, device};

/// How often the disks are looked through while waiting: soon enough that the run carries on
/// within seconds of the replug, and a look opens only disks of the drive's size.
pub const LOOK_EVERY: Duration = Duration::from_secs(3);
/// How long a drive that came back without its own serial number is asked again before it is
/// judged: right after a replug the bridge can leave IDENTIFY unanswered for a few seconds
/// (2026-11-09: one return gave none, the next a minute later gave it).
pub const IDENTIFY_GRACE: Duration = Duration::from_secs(20);
/// Drops in a row, with no read coming back between them, after which the run stops waiting:
/// a drive that stops again at once after every replug is not helped by another.
pub const STALLS: u32 = 3;

/// Finds the disks that may be the drive `meant`, opened for reading as a source is.
pub trait Finder: Send {
    fn look(&mut self, meant: &SourceId) -> Vec<Box<dyn BlockSource>>;
}

/// The disks Windows lists, looked through by number, none assumed: each disk of the drive's
/// size and sector size is opened as a source (`open_source_within`, which proves the handle
/// on the held disk and reads the drive's identity). A disk whose open did not answer in time
/// is passed over while Windows still holds that device, so a hung device is not opened again
/// every few seconds.
#[derive(Default)]
pub struct Disks {
    stuck: Vec<HeldDisk>,
}

impl Finder for Disks {
    fn look(&mut self, meant: &SourceId) -> Vec<Box<dyn BlockSource>> {
        self.stuck.retain(|held| held.still_held().is_ok());
        let size = meant.disk_size.unwrap_or(meant.size);
        let mut found = Vec::new();
        for number in 0..device::MAX_DISKS {
            if self.stuck.iter().any(|held| held.number() == number) {
                continue;
            }
            let Ok(held) = HeldDisk::open(number) else {
                continue;
            };
            let Ok(id) = held.identity() else {
                continue;
            };
            let other_size = id.size.is_some_and(|bytes| bytes != size);
            let other_sector = matches!((id.sector, meant.sector), (Some(a), Some(b)) if a != b);
            if other_size || other_sector {
                continue;
            }
            match open_source_within(SourceChoice::Disk(number), OPEN_LIMIT) {
                Ok(source) => found.push(source),
                Err(why) if why.contains("is not answering") => self.stuck.push(held),
                Err(_) => {}
            }
        }
        found
    }
}

/// How a wait ended.
pub enum Found {
    /// The same drive is back.
    Same(Box<dyn BlockSource>),
    /// A drive is back that cannot be told from it; says why.
    Unconfirmed(Box<dyn BlockSource>, String),
    Stopped,
}

/// The waiting of one run: how disks are found, and what came of it.
pub struct Waiter {
    finder: Option<Box<dyn Finder>>,
    every: Duration,
    /// The drive the run carried on with after it came back, or one found that could not be
    /// told from it: the caller's source from now on.
    pub source: Option<Box<dyn BlockSource>>,
    stalls: u32,
    reads_at_drop: Option<u64>,
    /// `IDENTIFY_GRACE`, shorter in tests.
    grace: Duration,
}

impl Waiter {
    /// Waits by looking through the disks Windows lists.
    pub fn disks() -> Self {
        Self::with(Box::<Disks>::default(), LOOK_EVERY)
    }

    /// Never waits: a drive that stops answering ends the run, as before.
    pub fn none() -> Self {
        Self {
            finder: None,
            every: LOOK_EVERY,
            source: None,
            stalls: 0,
            reads_at_drop: None,
            grace: IDENTIFY_GRACE,
        }
    }

    /// How long a drive back without its own serial number is asked again (`IDENTIFY_GRACE`).
    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    pub fn with(finder: Box<dyn Finder>, every: Duration) -> Self {
        Self {
            finder: Some(finder),
            ..Self::none()
        }
        .every(every)
    }

    fn every(mut self, every: Duration) -> Self {
        self.every = every;
        self
    }

    /// The source to keep after the run, when it changed.
    pub fn take_source(&mut self) -> Option<Box<dyn BlockSource>> {
        self.source.take()
    }

    /// Looks every `every` until the drive `meant`, which the map at `map_path` names,
    /// comes back, or Stop. One look runs at a time, on its own thread, so Stop is heard
    /// within a tenth of a second. None when there is nothing to look with.
    fn wait(&mut self, map_path: &Path, meant: &SourceId, stop: &AtomicBool) -> Option<Found> {
        // The drives found that cannot be told from the one meant, by where Windows lists
        // them and what they are, and since when that set has stood.
        let mut unsure_since: Option<(Vec<Candidate>, Instant)> = None;
        loop {
            let mut finder = self.finder.take()?;
            let (tell, told) = mpsc::channel();
            let wanted = meant.clone();
            std::thread::spawn(move || {
                let found = finder.look(&wanted);
                let _ = tell.send((finder, found));
            });
            let (finder, found) = loop {
                if stop.load(Ordering::Relaxed) {
                    return Some(Found::Stopped);
                }
                match told.recv_timeout(Duration::from_millis(100)) {
                    Ok(done) => break done,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return None,
                }
            };
            self.finder = Some(finder);
            if stop.load(Ordering::Relaxed) {
                return Some(Found::Stopped);
            }
            let mut unsure = Vec::new();
            for source in found {
                match returned(map_path, meant, source.identity().as_ref()) {
                    Match::Same => return Some(Found::Same(source)),
                    Match::Unconfirmed(why) => unsure.push((source, why)),
                    Match::Other(_) => {}
                }
            }
            // Asked again, within the grace, in case an identity was not ready yet. The grace
            // runs while the same drives stand unsure: one gone, back or newly found starts it
            // over, so every drive found has its whole grace.
            let mut set: Vec<_> = unsure
                .iter()
                .map(|(source, _)| (source.disk_number(), source.describe()))
                .collect();
            set.sort();
            unsure_since = match unsure_since {
                _ if set.is_empty() => None,
                Some((was, since)) if was == set => {
                    if since.elapsed() >= self.grace {
                        let (source, why) = unsure.swap_remove(0);
                        return Some(Found::Unconfirmed(source, why));
                    }
                    Some((was, since))
                }
                _ => Some((set, Instant::now())),
            };
            let until = Instant::now() + self.every;
            loop {
                if stop.load(Ordering::Relaxed) {
                    return Some(Found::Stopped);
                }
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                std::thread::sleep(left.min(Duration::from_millis(100)));
            }
        }
    }
}

/// A drive found, by where Windows lists it and what it is.
type Candidate = (Option<u32>, String);

/// Whether a drive found is the one meant, to carry on with it unattended. Only the drive's
/// own serial number decides, not blank, on both, with the same size, sector size and part
/// of the drive. What Windows reports (the model and serial, often the USB adapter's) never
/// decides either way: a drive that comes back without its own serial, and is the same size
/// and shape, cannot be told from another and ends the run for the technician to confirm;
/// one of another size or shape is another drive.
pub fn returned(map_path: &Path, meant: &SourceId, found: Option<&SourceId>) -> Match {
    let Some(found) = found else {
        return match match_drive(map_path, Some(meant), None) {
            Match::Same => Match::Unconfirmed("the drive found gave no identity".into()),
            other => other,
        };
    };
    let own = |id: &SourceId| {
        id.drive
            .as_ref()
            .map(|drive| drive.serial.trim().to_string())
            .filter(|serial| !serial.is_empty())
    };
    if meant.size != found.size {
        return Match::Other(format!(
            "the drive found reports {} bytes, and the one being read reported {} bytes",
            found.size, meant.size
        ));
    }
    if meant.scope != found.scope {
        return Match::Other(
            "the source found is another part of the drive than the one being read".into(),
        );
    }
    if let (Some(was), Some(now)) = (meant.sector, found.sector) {
        if was != now {
            return Match::Other(format!(
                "the drive found reports {now}-byte sectors, and the one being read reported {was}-byte sectors"
            ));
        }
    }
    let sector_known = meant.sector.is_some() && meant.sector == found.sector;
    match (own(meant), own(found)) {
        (Some(was), Some(now)) if was == now && sector_known => Match::Same,
        (Some(was), Some(now)) if was == now => Match::Unconfirmed(format!(
            "{} has the serial number {now} of the drive being read, but the sector size is not known on both, so it is not carried on with unattended",
            found.text()
        )),
        (Some(was), Some(now)) => Match::Other(format!(
            "the drive found has serial number {now}, and the one being read has {was}"
        )),
        (was, _) => Match::Unconfirmed(format!(
            "{} cannot be told from another drive of its size: {}; without the drive's own serial number on both, it is not carried on with unattended",
            found.text(),
            if was.is_none() {
                "the run has no serial number of the drive itself to compare with"
            } else {
                "the drive found did not give its own serial number (its IDENTIFY was not answered through the adapter)"
            }
        )),
    }
}

/// How a pause for the drive ended.
pub enum Went {
    /// The same drive is back: the run carries on with it.
    Back(Box<dyn BlockSource>),
    /// The run ends so.
    End(Outcome),
}

/// The time of day, "14:02:31".
pub fn clock() -> String {
    let s = crate::clock::local(SystemTime::now());
    format!("{:02}:{:02}:{:02}", s.hour, s.minute, s.second)
}

/// What a run waiting for the drive says, for `then` ("the rescue", "Fill the gaps").
pub fn waiting_text(at: &str, then: &str) -> String {
    format!(
        "The drive stopped answering at {at}. Unplug it, wait 30 seconds and plug it back in; {then} continues when the same drive is back."
    )
}

/// What the pause says of the span a drop set aside: a zone with hangs left is read last in
/// this phase; one whose phase has had its two hangs there is left as it is; a retry pass's
/// or Fill the gaps' skip is read in a later pass.
fn skip_text(skipped: Option<(u64, u64)>, zoned: bool, open: bool) -> String {
    match skipped {
        Some((from, to)) if to > from && zoned && open => format!(
            "; the {} from byte {from} is set aside and read last, from its far side",
            bytes_text(to - from)
        ),
        Some((from, to)) if to > from && zoned => format!(
            "; the {} from byte {from} is set aside and left as it is in this phase, where the drive has now hung twice",
            bytes_text(to - from)
        ),
        Some((from, to)) if to > from => format!(
            "; the {} from byte {from} is skipped for now and read in a later pass",
            bytes_text(to - from)
        ),
        _ => String::new(),
    }
}

/// After the drive `meant` stopped answering (`why`): sets the place aside
/// (`Rescue::skip_drop`), saves the map, and waits for the drive, saying so
/// (`progress.waiting`) and logging it (`log`, kind and text). Only a whole disk with an identity is waited for, and not after
/// `STALLS` drops in a row with nothing read between. `then` names what carries on.
#[allow(clippy::too_many_arguments)]
pub fn pause(
    rescue: &mut Rescue,
    meant: Option<&SourceId>,
    why: String,
    sector: u64,
    first_skip: u64,
    waiter: &mut Waiter,
    stop: &AtomicBool,
    progress: &Progress,
    log: &mut dyn FnMut(&str, String),
    then: &str,
) -> Went {
    let code = rescue.gone_code.take();
    rescue.events.write(
        &Event::DriveGone {
            seen: why.clone(),
            code,
        },
        Figures::of(&rescue.map),
    );
    let hang = rescue.in_flight();
    let zoned = rescue.zoned().is_some();
    let skipped = rescue.skip_drop(sector, first_skip);
    if let Err(failed) = rescue.save_during() {
        return Went::End(Outcome::Failed(failed));
    }
    rescue.publish(progress);
    let meant = match meant {
        Some(id) if id.scope == Some(Scope::Disk) && waiter.finder.is_some() => id,
        _ => return Went::End(Outcome::Gone(why)),
    };
    let reads = rescue.reads_ok();
    waiter.stalls = if waiter.reads_at_drop == Some(reads) {
        waiter.stalls + 1
    } else {
        1
    };
    waiter.reads_at_drop = Some(reads);
    if waiter.stalls >= STALLS {
        log(
            "drive stopped answering",
            format!("{why} It stopped {STALLS} times in a row with nothing read between; no longer waited for."),
        );
        return Went::End(Outcome::Gone(format!(
            "{why} It has stopped answering {STALLS} times in a row with nothing read between, so {then} no longer waits for it."
        )));
    }
    let open = hang.is_some_and(|(at, _)| rescue.zone_open(at));
    let skip = skip_text(skipped, zoned, open);
    let at = clock();
    let waiting = waiting_text(&at, then);
    // The window's message is the event's reason.
    rescue.events.write(
        &Event::Paused {
            kind: PauseKind::DriveGone,
            reason: waiting.clone(),
            values: serde_json::json!({
                "code": code,
                "skipped_from": skipped.map(|(from, _)| from),
                "skipped_to": skipped.map(|(_, to)| to),
                "hang_from": hang.map(|(at, _)| at),
                "hang_to": hang.map(|(at, len)| at + len),
                "zoned": zoned,
                "stalls_in_a_row": waiter.stalls,
            }),
        },
        Figures::of(&rescue.map),
    );
    Progress::say(&progress.waiting, Some(waiting));
    log(
        "drive stopped answering",
        format!("{why} Waiting for it to be plugged back in{skip}."),
    );
    let found = waiter.wait(rescue.map_path(), meant, stop);
    Progress::say(&progress.waiting, None);
    match found {
        None => Went::End(Outcome::Gone(why)),
        Some(Found::Stopped) => {
            log(
                "stopped while waiting",
                "Stop was pressed while the drive was waited for.".into(),
            );
            Went::End(Outcome::Stopped)
        }
        Some(Found::Unconfirmed(source, unsure)) => {
            log(
                "drive back unconfirmed",
                format!(
                    "{} came back, and it cannot be told from the drive being read.",
                    source.describe()
                ),
            );
            waiter.source = Some(source);
            Went::End(Outcome::Unconfirmed(format!(
                "The drive stopped answering, and a drive came back that cannot be told from it: {unsure} {} did not carry on by itself.",
                capital(then)
            )))
        }
        Some(Found::Same(source)) => {
            let said = format!(
                "The drive came back at {} as {}; {then} carried on from where it was{skip}.",
                clock(),
                source.describe()
            );
            log("drive back", said.clone());
            let id = source.identity();
            let figures = Figures::of(&rescue.map);
            rescue.events.write(
                &Event::DriveBack {
                    disk_number: source.disk_number(),
                    serial: id.as_ref().map(|id| id.serial.clone()),
                    drive_serial: id.and_then(|id| id.drive).map(|d| d.serial),
                    source: source.describe(),
                },
                figures,
            );
            rescue.events.write(
                &Event::Resumed {
                    kind: PauseKind::DriveGone,
                    reason: said.clone(),
                },
                figures,
            );
            Progress::say(&progress.resumed, Some(said));
            Progress::say(&progress.source, Some(source.describe()));
            Went::Back(source)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::Scope;
    use crate::tools::drives::ata::DriveId;

    /// The guard (round 10): the pause promises a read last only for a zone with hangs left
    /// in the phase; a zone that has had its two says it is left as it is.
    #[test]
    fn the_pause_says_what_becomes_of_the_span() {
        let span = Some((4096, 8192));
        assert!(skip_text(span, true, true).contains("read last"));
        let spent = skip_text(span, true, false);
        assert!(
            spent.contains("left as it is") && !spent.contains("read last"),
            "{spent}"
        );
        assert!(skip_text(span, false, false).contains("later pass"));
        assert_eq!(skip_text(None, true, true), "");
    }

    fn id(windows_serial: &str, own: Option<&str>) -> SourceId {
        SourceId {
            model: "Seagate Expansion".into(),
            serial: windows_serial.into(),
            size: 2_000_398_934_016,
            drive: own.map(|serial| DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: serial.into(),
            }),
            sector: Some(512),
            scope: Some(Scope::Disk),
            disk_size: Some(2_000_398_934_016),
        }
    }

    /// The guard: carrying on unattended needs the drive's own serial, not blank, on both;
    /// the serial Windows reports, which can be the USB adapter's, is never enough.
    #[test]
    fn only_the_drive_s_own_serial_carries_on_unattended() {
        let map = Path::new("image.map");
        let same = |meant: &SourceId, found: &SourceId| returned(map, meant, Some(found));
        let theirs = id("NA88E0R0", Some("WCC1VNYJ"));
        assert_eq!(same(&theirs, &theirs.clone()), Match::Same);
        // The same drive serial with the sector size unknown on either side: not shown to
        // fit, so not carried on with unattended.
        let unknown = SourceId {
            sector: None,
            ..theirs.clone()
        };
        assert!(matches!(same(&theirs, &unknown), Match::Unconfirmed(_)));
        assert!(matches!(same(&unknown, &theirs), Match::Unconfirmed(_)));
        assert!(matches!(
            same(&theirs, &id("NA88E0R0", Some("WCC1OTHER"))),
            Match::Other(_)
        ));
        let adapter_only = id("NA88E0R0", None);
        assert!(matches!(
            same(&adapter_only, &adapter_only.clone()),
            Match::Unconfirmed(_)
        ));
        let blank = id("NA88E0R0", Some("  "));
        assert!(matches!(
            same(&blank, &blank.clone()),
            Match::Unconfirmed(_)
        ));
        assert!(matches!(
            same(&theirs, &adapter_only),
            Match::Unconfirmed(_)
        ));
        // Back without its own serial, and Windows now names it differently: still the
        // technician's to confirm, never waited past as another drive.
        let renamed = SourceId {
            model: "USB SATA Bridge".into(),
            ..id("000000000001", None)
        };
        assert!(matches!(same(&theirs, &renamed), Match::Unconfirmed(_)));
        let mut bigger = renamed.clone();
        bigger.size += 4096;
        assert!(matches!(same(&theirs, &bigger), Match::Other(_)));
        let mut four_k = theirs.clone();
        four_k.sector = Some(4096);
        assert!(matches!(same(&theirs, &four_k), Match::Other(_)));
        assert!(!matches!(returned(map, &theirs, None), Match::Same));
    }

    /// A disk that says it is `id`, its own identity given only from the `answers_from`th look.
    struct Shown(SourceId);

    impl BlockSource for Shown {
        fn len(&self) -> u64 {
            self.0.size
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), crate::recovery::ReadError> {
            Ok(())
        }
        fn describe(&self) -> String {
            "Disk 3, Seagate Expansion".into()
        }
        fn identity(&self) -> Option<SourceId> {
            Some(self.0.clone())
        }
    }

    struct Slow {
        looks: usize,
        answers_from: usize,
    }

    impl Finder for Slow {
        fn look(&mut self, _: &SourceId) -> Vec<Box<dyn BlockSource>> {
            self.looks += 1;
            let own = (self.looks >= self.answers_from).then_some("WCC1VNYJ");
            vec![Box::new(Shown(id("NA88E0R0", own)))]
        }
    }

    /// Gone on every other look, back without its own serial between, and with it from the
    /// `answers_from`th look.
    struct Flickers {
        looks: usize,
        answers_from: usize,
    }

    impl Finder for Flickers {
        fn look(&mut self, _: &SourceId) -> Vec<Box<dyn BlockSource>> {
            self.looks += 1;
            if self.looks % 2 == 1 {
                return Vec::new();
            }
            let own = (self.looks >= self.answers_from).then_some("WCC1VNYJ");
            vec![Box::new(Shown(id("NA88E0R0", own)))]
        }
    }

    /// `Shown` listed by Windows as disk `.1`.
    struct ShownAt(SourceId, u32);

    impl BlockSource for ShownAt {
        fn len(&self) -> u64 {
            self.0.size
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), crate::recovery::ReadError> {
            Ok(())
        }
        fn describe(&self) -> String {
            format!("Disk {}, Seagate Expansion", self.1)
        }
        fn disk_number(&self) -> Option<u32> {
            Some(self.1)
        }
        fn identity(&self) -> Option<SourceId> {
            Some(self.0.clone())
        }
    }

    /// Back without its own serial as disk 3 and disk 4 in turn, with it from the
    /// `answers_from`th look.
    struct Moves {
        looks: usize,
        answers_from: usize,
    }

    impl Finder for Moves {
        fn look(&mut self, _: &SourceId) -> Vec<Box<dyn BlockSource>> {
            self.looks += 1;
            let own = (self.looks >= self.answers_from).then_some("WCC1VNYJ");
            vec![Box::new(ShownAt(
                id("NA88E0R0", own),
                3 + (self.looks % 2) as u32,
            ))]
        }
    }

    /// Disk 3 unsure from the start; disk 4 beside it, unsure, from `second` on, giving its
    /// own serial from `answers` on (times since the first look).
    struct Two {
        start: Option<Instant>,
        second: Duration,
        answers: Duration,
    }

    impl Finder for Two {
        fn look(&mut self, _: &SourceId) -> Vec<Box<dyn BlockSource>> {
            let since = self.start.get_or_insert_with(Instant::now).elapsed();
            let mut found: Vec<Box<dyn BlockSource>> =
                vec![Box::new(ShownAt(id("NA88E0R0", None), 3))];
            if since >= self.second {
                let own = (since >= self.answers).then_some("WCC1VNYJ");
                found.push(Box::new(ShownAt(id("NA88E0R0", own), 4)));
            }
            found
        }
    }

    /// The guard for the whole class: every drive found has its whole grace, however many
    /// stand unsure together; a drive found late beside another got only what was left of
    /// the first one's.
    #[test]
    fn every_drive_found_has_its_whole_grace() {
        let meant = id("NA88E0R0", Some("WCC1VNYJ"));
        let finder = Two {
            start: None,
            second: Duration::from_millis(300),
            answers: Duration::from_millis(600),
        };
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(5))
            .grace(Duration::from_millis(500));
        assert!(matches!(
            waiter.wait(Path::new("image.map"), &meant, &AtomicBool::new(false)),
            Some(Found::Same(_))
        ));
    }

    /// Finds the drive meant, and Stop is pressed while it looks.
    struct StopWhileLooking(std::sync::Arc<AtomicBool>);

    impl Finder for StopWhileLooking {
        fn look(&mut self, _: &SourceId) -> Vec<Box<dyn BlockSource>> {
            self.0.store(true, Ordering::Relaxed);
            vec![Box::new(Shown(id("NA88E0R0", Some("WCC1VNYJ"))))]
        }
    }

    /// The guard: Stop pressed while a look runs ends the wait, even when the look found the
    /// drive; it carried the run on past the Stop.
    #[test]
    fn stop_during_a_look_ends_the_wait() {
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let mut waiter = Waiter::with(
            Box::new(StopWhileLooking(stop.clone())),
            Duration::from_millis(5),
        );
        let meant = id("NA88E0R0", Some("WCC1VNYJ"));
        assert!(matches!(
            waiter.wait(Path::new("image.map"), &meant, &stop),
            Some(Found::Stopped)
        ));
    }

    /// The guard: the grace belongs to one drive; a drive found under another disk number
    /// starts its own, rather than inheriting one that ran out on the drive before.
    #[test]
    fn the_grace_starts_over_for_another_drive() {
        let meant = id("NA88E0R0", Some("WCC1VNYJ"));
        let finder = Moves {
            looks: 0,
            answers_from: 40,
        };
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(5))
            .grace(Duration::from_millis(50));
        assert!(matches!(
            waiter.wait(Path::new("image.map"), &meant, &AtomicBool::new(false)),
            Some(Found::Same(_))
        ));
    }

    /// The guard: the grace is the drive's own and starts over each time it comes back; a
    /// grace that started at the first unsure look ran out for a drive that went and came
    /// again, and left it for the technician though it later gave its serial.
    #[test]
    fn the_grace_starts_over_when_the_drive_comes_back() {
        let meant = id("NA88E0R0", Some("WCC1VNYJ"));
        let finder = Flickers {
            looks: 0,
            answers_from: 40,
        };
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(5))
            .grace(Duration::from_millis(50));
        assert!(matches!(
            waiter.wait(Path::new("image.map"), &meant, &AtomicBool::new(false)),
            Some(Found::Same(_))
        ));
    }

    /// The guard: a drive back without its own serial is asked again for a while before it
    /// is judged, since right after a replug the adapter may not pass IDENTIFY yet; on
    /// 2026-11-09 one such return paused the rescue for a confirmation.
    #[test]
    fn a_drive_back_without_its_serial_is_asked_again() {
        let meant = id("NA88E0R0", Some("WCC1VNYJ"));
        let stop = AtomicBool::new(false);
        let map = Path::new("image.map");
        let finder = Slow {
            looks: 0,
            answers_from: 3,
        };
        let mut waiter =
            Waiter::with(Box::new(finder), Duration::from_millis(5)).grace(Duration::from_secs(5));
        assert!(matches!(
            waiter.wait(map, &meant, &stop),
            Some(Found::Same(_))
        ));
        // Past the grace it is left for the technician, saying why.
        let finder = Slow {
            looks: 0,
            answers_from: usize::MAX,
        };
        let mut waiter = Waiter::with(Box::new(finder), Duration::from_millis(5))
            .grace(Duration::from_millis(50));
        match waiter.wait(map, &meant, &stop) {
            Some(Found::Unconfirmed(_, why)) => {
                assert!(why.contains("did not give its own serial number"), "{why}")
            }
            _ => panic!("not left for the technician"),
        }
    }
}
