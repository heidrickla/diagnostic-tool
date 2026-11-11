//! One consented diagnostic session: the check queue, pause, stop, expiry and completion.
//! Pure state, no Win32, so every transition is unit-tested.
use std::time::{Duration, Instant, SystemTime};

use crate::checks::{Outcome, CHECKS};

#[derive(Clone, Debug, PartialEq)]
pub enum CheckState {
    Waiting,
    Running,
    Done {
        outcome: Outcome,
        started: SystemTime,
        elapsed: Duration,
    },
    /// The session ended before this check ran.
    NotRun,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub id: &'static str,
    pub label: &'static str,
    pub state: CheckState,
    started: Option<(Instant, SystemTime)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndReason {
    Completed,
    Stopped,
    Expired,
    /// The support connection ended the session; the text says why.
    ConnectionEnded(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Running,
    Paused,
    Ended(EndReason),
}

#[derive(Clone)]
pub struct Session {
    rows: Vec<Row>,
    phase: Phase,
    deadline: Instant,
    started_at: SystemTime,
    ended_at: Option<SystemTime>,
    /// A remote session stays open after the local checks so the operator can request more.
    hold_open: bool,
}

impl Session {
    pub fn new(now: Instant, lifetime: Duration, hold_open: bool) -> Self {
        Self {
            rows: CHECKS
                .iter()
                .map(|spec| Row {
                    id: spec.id,
                    label: spec.label,
                    state: CheckState::Waiting,
                    started: None,
                })
                .collect(),
            phase: Phase::Running,
            deadline: now + lifetime,
            started_at: SystemTime::now(),
            ended_at: None,
            hold_open,
        }
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn is_ended(&self) -> bool {
        matches!(self.phase, Phase::Ended(_))
    }

    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }

    pub fn ended_at(&self) -> Option<SystemTime> {
        self.ended_at
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    pub fn running(&self) -> Option<&'static str> {
        self.rows
            .iter()
            .find(|row| row.state == CheckState::Running)
            .map(|row| row.id)
    }

    /// Completed checks out of all checks, counting unavailable results as completed.
    pub fn progress(&self) -> (usize, usize) {
        let done = self
            .rows
            .iter()
            .filter(|row| matches!(row.state, CheckState::Done { .. }))
            .count();
        (done, self.rows.len())
    }

    /// Advances time-based transitions. Returns the reason when this call ended the session.
    pub fn tick(&mut self, now: Instant) -> Option<EndReason> {
        if self.is_ended() {
            return None;
        }
        if now >= self.deadline {
            self.end(EndReason::Expired);
            return Some(EndReason::Expired);
        }
        let complete = self
            .rows
            .iter()
            .all(|row| matches!(row.state, CheckState::Done { .. }));
        if complete && !self.hold_open {
            self.end(EndReason::Completed);
            return Some(EndReason::Completed);
        }
        None
    }

    /// The next check to start, marked running. One check runs at a time and none while paused.
    pub fn start_next(&mut self, now: Instant) -> Option<&'static str> {
        if self.phase != Phase::Running || now >= self.deadline || self.running().is_some() {
            return None;
        }
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.state == CheckState::Waiting)?;
        row.state = CheckState::Running;
        row.started = Some((now, SystemTime::now()));
        Some(row.id)
    }

    /// Records a result. A check stopped by Pause waits to run again; by Stop it did not run.
    pub fn finish(&mut self, id: &str, outcome: Outcome, now: Instant) {
        let ended = self.is_ended();
        let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.id == id && row.state == CheckState::Running)
        else {
            return;
        };
        let (begun, started) = row.started.take().unwrap_or((now, SystemTime::now()));
        row.state = match outcome {
            Outcome::Stopped if ended => CheckState::NotRun,
            Outcome::Stopped => CheckState::Waiting,
            outcome => CheckState::Done {
                outcome,
                started,
                elapsed: now.saturating_duration_since(begun),
            },
        };
    }

    /// Returns true when a running check must be cancelled.
    pub fn pause(&mut self) -> bool {
        if self.phase != Phase::Running {
            return false;
        }
        self.phase = Phase::Paused;
        self.running().is_some()
    }

    pub fn resume(&mut self) {
        if self.phase == Phase::Paused {
            self.phase = Phase::Running;
        }
    }

    /// Ends the session. Returns true when a running check must be cancelled.
    pub fn end(&mut self, reason: EndReason) -> bool {
        if self.is_ended() {
            return false;
        }
        self.phase = Phase::Ended(reason);
        self.ended_at = Some(SystemTime::now());
        for row in &mut self.rows {
            if row.state == CheckState::Waiting {
                row.state = CheckState::NotRun;
            }
        }
        self.running().is_some()
    }

    /// Hardware fields from the inventory check, empty when it did not complete.
    pub fn inventory(&self) -> &[(String, String)] {
        self.rows
            .iter()
            .find_map(|row| match &row.state {
                CheckState::Done {
                    outcome: Outcome::Found(finding),
                    ..
                } if row.id == "hardware.inventory" => Some(finding.data.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Finding;

    const LIFE: Duration = Duration::from_secs(300);

    fn found() -> Outcome {
        Outcome::Found(Finding::new("ok", "ok", false))
    }

    fn run_all(session: &mut Session, now: Instant) {
        while let Some(id) = session.start_next(now) {
            session.finish(id, found(), now);
        }
    }

    #[test]
    fn checks_run_one_at_a_time_in_registry_order() {
        let now = Instant::now();
        let mut session = Session::new(now, LIFE, false);
        let first = session.start_next(now).unwrap();
        assert_eq!(first, CHECKS[0].id);
        assert_eq!(session.start_next(now), None, "a second check started");
        session.finish(first, found(), now);
        assert_eq!(session.start_next(now), Some(CHECKS[1].id));
    }

    #[test]
    fn pause_stops_the_next_start_and_resume_reruns_the_cancelled_check() {
        let now = Instant::now();
        let mut session = Session::new(now, LIFE, false);
        let id = session.start_next(now).unwrap();
        assert!(session.pause(), "pause must cancel the running check");
        session.finish(id, Outcome::Stopped, now);
        assert_eq!(session.start_next(now), None);
        session.resume();
        assert_eq!(session.start_next(now), Some(id));
    }

    #[test]
    fn stop_cancels_and_leaves_remaining_checks_not_run() {
        let now = Instant::now();
        let mut session = Session::new(now, LIFE, false);
        let id = session.start_next(now).unwrap();
        assert!(session.end(EndReason::Stopped));
        session.finish(id, Outcome::Stopped, now);
        assert_eq!(session.start_next(now), None);
        assert!(session
            .rows()
            .iter()
            .all(|row| row.state == CheckState::NotRun));
        assert_eq!(session.phase(), &Phase::Ended(EndReason::Stopped));
    }

    #[test]
    fn expiry_ends_the_session() {
        let now = Instant::now();
        let mut session = Session::new(now, LIFE, true);
        assert_eq!(session.tick(now + LIFE), Some(EndReason::Expired));
        assert_eq!(session.start_next(now + LIFE), None);
        assert_eq!(session.tick(now + LIFE), None);
    }

    #[test]
    fn local_session_completes_after_the_last_check_and_remote_stays_open() {
        let now = Instant::now();
        let mut local = Session::new(now, LIFE, false);
        run_all(&mut local, now);
        assert_eq!(local.progress(), (CHECKS.len(), CHECKS.len()));
        assert_eq!(local.tick(now), Some(EndReason::Completed));
        let mut remote = Session::new(now, LIFE, true);
        run_all(&mut remote, now);
        assert_eq!(remote.tick(now), None);
    }

    #[test]
    fn unavailable_results_count_as_done_but_keep_their_reason() {
        let now = Instant::now();
        let mut session = Session::new(now, LIFE, false);
        let id = session.start_next(now).unwrap();
        session.finish(id, Outcome::Unavailable("timed out".into()), now);
        assert_eq!(session.progress().0, 1);
        assert!(matches!(
            &session.rows()[0].state,
            CheckState::Done { outcome: Outcome::Unavailable(reason), .. } if reason == "timed out"
        ));
    }

    #[test]
    fn a_result_for_a_check_that_is_not_running_is_ignored() {
        let now = Instant::now();
        let mut session = Session::new(now, LIFE, false);
        session.finish("disk.free", found(), now);
        assert_eq!(session.progress().0, 0);
    }
}
