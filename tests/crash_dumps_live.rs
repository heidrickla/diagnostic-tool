//! The crash dump engine on a real Windows. The check is read only and runs everywhere;
//! the set up and put back steps change the PC, so they are ignored by default and run
//! only on a test machine named by the environment, one step per run, printing JSON.
#![cfg(windows)]
use std::sync::atomic::AtomicBool;

use diagnostics::tools::crash_dumps::{
    self, CheckOptions, Outcome, PutBackOptions, SetUpOptions, Status,
};

#[test]
fn the_check_reads_this_pc_and_changes_nothing() {
    let mut events = 0;
    let result = crash_dumps::check(
        &CheckOptions::default(),
        &mut |_| events += 1,
        &AtomicBool::new(false),
    );
    assert_eq!(result.outcome, Outcome::Done);
    assert!(events >= result.items.len());
    let kind = result
        .items
        .iter()
        .find(|i| i.id == "kernel.type")
        .expect("kernel.type");
    assert!(
        !matches!(kind.status, Status::CouldNotRead { .. }),
        "{kind:?}"
    );
    for id in [
        "kernel.space",
        "kernel.restart",
        "apps.local_dumps",
        "apps.reporting",
        "cleanup.disk_cleanup",
        "dumps.present",
    ] {
        assert!(result.items.iter().any(|i| i.id == id), "{id} missing");
    }
}

/// One live step on a test machine: `DIAGTOOL_CRASHDUMP_STEP` is check, preview, setup,
/// putback-preview, putback, keepout-putback (Put back while this process holds its
/// exclusion, which is let go after), keepout-leave (the exclusion held and the process
/// ended without letting go, as a crash leaves it) or settle (what an ended process left
/// is settled), and `DIAGTOOL_CRASHDUMP_HOST` must name this computer. Lines this program
/// could not enter in a change record are printed after the result.
#[test]
#[ignore = "changes crash dump settings; run on a test machine only"]
fn live_step() {
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let allowed = std::env::var("DIAGTOOL_CRASHDUMP_HOST").unwrap_or_default();
    assert!(
        !host.is_empty() && host.eq_ignore_ascii_case(&allowed),
        "this step runs only on the test machine named by DIAGTOOL_CRASHDUMP_HOST, not {host}"
    );
    let step = std::env::var("DIAGTOOL_CRASHDUMP_STEP").unwrap_or_default();
    let go = AtomicBool::new(false);
    let mut events = Vec::new();
    let mut progress = |e| events.push(e);
    let json = match step.as_str() {
        "check" => serde_json::to_string_pretty(&crash_dumps::check(
            &CheckOptions::default(),
            &mut progress,
            &go,
        )),
        "preview" => serde_json::to_string_pretty(&crash_dumps::set_up(
            &SetUpOptions::default(),
            &mut progress,
            &go,
        )),
        "setup" => serde_json::to_string_pretty(&crash_dumps::set_up(
            &SetUpOptions {
                confirmed: true,
                ..SetUpOptions::default()
            },
            &mut progress,
            &go,
        )),
        "putback-preview" => serde_json::to_string_pretty(&crash_dumps::put_back(
            &PutBackOptions { confirmed: false },
            &mut progress,
            &go,
        )),
        "putback" => serde_json::to_string_pretty(&crash_dumps::put_back(
            &PutBackOptions { confirmed: true },
            &mut progress,
            &go,
        )),
        "keepout-putback" => {
            let held = crash_dumps::keep_out_of_dumps();
            println!("KEEP_OUT {:?}", held.as_ref().err());
            let result =
                crash_dumps::put_back(&PutBackOptions { confirmed: true }, &mut progress, &go);
            drop(held);
            serde_json::to_string_pretty(&result)
        }
        "keepout-leave" => {
            let held = crash_dumps::keep_out_of_dumps();
            println!("KEEP_OUT {:?}", held.as_ref().err());
            // Ends as a crash would: the exclusion is never let go.
            std::mem::forget(held);
            Ok("null".into())
        }
        "settle" => {
            crash_dumps::settle_left_exclusion();
            Ok("null".into())
        }
        other => panic!("unknown step {other:?}"),
    }
    .unwrap();
    println!("EVENTS {}", serde_json::to_string(&events).unwrap());
    println!("RESULT {json}");
    println!("UNRECORDED {:?}", crash_dumps::unrecorded());
}

/// Crashes this test program on purpose, so Windows Error Reporting writes an
/// application dump where LocalDumps points. Same guard as `live_step`.
#[test]
#[ignore = "crashes this test program on purpose; run on a test machine only"]
fn live_crash() {
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let allowed = std::env::var("DIAGTOOL_CRASHDUMP_HOST").unwrap_or_default();
    assert!(!host.is_empty() && host.eq_ignore_ascii_case(&allowed));
    // SAFETY: none; an access violation is the point, and the process ends here.
    unsafe { std::ptr::null_mut::<u8>().write_volatile(1) };
}
