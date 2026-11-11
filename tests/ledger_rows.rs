//! A rescue copy's ledger is its log: each file's row is written there as the file ends,
//! so the memory it takes does not grow with the number of files. Its own test binary,
//! since it counts this thread's allocations with a global allocator.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use diagnostics::recovery::ledger::Ledger;

struct Counting;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn count(delta: isize) {
    let _ = COUNTING.try_with(|on| {
        if on.get() {
            let live = LIVE.with(|l| {
                l.set(l.get() + delta);
                l.get()
            });
            PEAK.with(|p| p.set(p.get().max(live)));
        }
    });
}

// SAFETY: every call is passed to the system allocator unchanged; only sizes are counted.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The most this thread had allocated at once, beyond what it held before, while `f` ran.
fn peak_of(f: impl FnOnce()) -> isize {
    LIVE.with(|l| l.set(0));
    PEAK.with(|p| p.set(0));
    COUNTING.with(|on| on.set(true));
    f();
    COUNTING.with(|on| on.set(false));
    PEAK.with(Cell::get)
}

/// Takes the log and counts its bytes.
struct Counted(Arc<AtomicUsize>);

impl std::io::Write for Counted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.fetch_add(buf.len(), Ordering::Relaxed);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The guard: a ledger that is a log holds no more at once, while 50,000 files are entered
/// and ended as in a rescue copy, than a few entries take, so a rescue of millions of files
/// does not grow as it copies; every row is in the log.
#[test]
fn a_log_ledger_takes_no_more_memory_as_files_are_added() {
    let written = Arc::new(AtomicUsize::new(0));
    let mut ledger = Ledger::to_log(Box::new(Counted(written.clone())), r"E:\Rescue".into());
    let building = peak_of(|| {
        for i in 0..50_000 {
            let id = ledger.made(
                i,
                format!(r"E:\Rescue\Drive F\Photos\2026\IMG_{i:05}.jpg").into(),
                format!(r"F:\Photos\2026\IMG_{i:05}.jpg").into(),
                String::new(),
                4_000_000,
            );
            ledger.wrote(id, 4_000_000);
            ledger.zeroed(id, vec![0..512, 4096..8192]);
            ledger.whole(id);
        }
    });
    let written = written.load(Ordering::Relaxed);
    assert_eq!(ledger.damaged(), 50_000);
    assert!(written > 5_000_000, "{written} bytes of rows");
    assert_eq!(ledger.log_error(), None);
    assert!(
        building < 64 << 10,
        "{building} bytes held at once while entering 50,000 files"
    );
}
