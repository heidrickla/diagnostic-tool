use diagnostics::run_catalog;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn main() {
    for (id, label, unit) in [
        ("memory.total", "Physical memory reported by Windows", "GiB"),
        ("disk.free", "Free space on the Windows drive", "GiB"),
        ("registry.health", "Selected Windows registry signals", ""),
        ("events.recent", "Recent Event Viewer sample", ""),
        ("events.crashes", "Recent application crashes", ""),
        ("services.failures", "Service failures", ""),
        ("updates.local", "Local update history", ""),
        ("resources.snapshot", "Resource snapshot", ""),
        ("storage.provider", "Storage provider status", ""),
        ("hardware.events", "Targeted hardware and driver events", ""),
        ("drives.health", "Drive wear and errors", ""),
        ("crash.dumps", "Crash dump readiness", ""),
    ] {
        match run_catalog(id, Arc::new(AtomicBool::new(false))) {
            Ok(value) => println!("{label}: {} {unit}", value.trim()),
            Err(reason) => println!("{label}: unavailable ({reason})"),
        }
    }
}
