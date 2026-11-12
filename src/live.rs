//! A switch that forbids reading this PC. The screenshot mode turns it on before it opens
//! any window, and every reader its windows could otherwise reach calls `reading` first, so
//! made-up data cannot be replaced by this PC's without the run failing.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static FORBIDDEN: AtomicBool = AtomicBool::new(false);
static REACHED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

/// From now on, for the rest of the process, every guarded reader panics.
pub fn forbid() {
    FORBIDDEN.store(true, Ordering::SeqCst);
}

/// Called at the start of each reader of this PC. Panics, naming `what`, once readings are
/// forbidden; the name is also kept for `reached`, since a worker thread's panic is quiet.
pub fn reading(what: &'static str) {
    check(&FORBIDDEN, &REACHED, what);
}

/// Whether readings of this PC are forbidden.
pub fn forbidden() -> bool {
    FORBIDDEN.load(Ordering::SeqCst)
}

/// The readers called while readings were forbidden, in order.
pub fn reached() -> Vec<&'static str> {
    REACHED.lock().map(|list| list.clone()).unwrap_or_default()
}

fn check(forbidden: &AtomicBool, reached: &Mutex<Vec<&'static str>>, what: &'static str) {
    if forbidden.load(Ordering::SeqCst) {
        if let Ok(mut list) = reached.lock() {
            list.push(what);
        }
        panic!("{what} was read while readings of this PC are forbidden");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_runs_until_readings_are_forbidden_then_panics_and_is_named() {
        let forbidden = AtomicBool::new(false);
        let reached = Mutex::new(Vec::new());
        check(&forbidden, &reached, "the event log");
        assert!(reached.lock().unwrap().is_empty());
        forbidden.store(true, Ordering::SeqCst);
        let panicked = std::panic::catch_unwind(|| check(&forbidden, &reached, "the event log"));
        assert!(panicked.is_err());
        assert_eq!(*reached.lock().unwrap(), ["the event log"]);
    }

    /// The tests in this process never forbid readings, so the guard costs them nothing.
    #[test]
    fn readings_are_allowed_unless_forbidden() {
        reading("nothing");
        assert!(reached().is_empty());
    }
}
