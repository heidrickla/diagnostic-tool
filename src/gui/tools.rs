//! Which result rows open a tool, and opening it.
use windows_sys::Win32::Foundation::HWND;

use crate::{cpumem_view, crashdump_view, drive_view, event_view, space_view, toolwin};

/// The tool a check's row opens, keyed by the check id from `checks::CHECKS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Space,
    Events,
    Drive,
    CrashDumps,
    CpuMemory,
}

pub fn tool_for(check: &str) -> Option<Tool> {
    match check {
        "disk.free" => Some(Tool::Space),
        "events.recent" | "events.crashes" | "services.failures" | "hardware.events" => {
            event_view::available().then_some(Tool::Events)
        }
        "storage.provider" | "drives.health" => drive_view::available().then_some(Tool::Drive),
        "registry.health" | "crash.dumps" => Some(Tool::CrashDumps),
        "resources.snapshot" => cpumem_view::available().then_some(Tool::CpuMemory),
        _ => None,
    }
}

/// Opens the tool for a check's row beside `owner`.
pub fn open(owner: HWND, check: &str) {
    match tool_for(check) {
        Some(Tool::Space) => {
            toolwin::open(owner, "space", || Box::new(space_view::SpaceView::new()))
        }
        Some(Tool::Events) => event_view::open(owner, check),
        Some(Tool::Drive) => drive_view::open(owner, check),
        Some(Tool::CrashDumps) => crashdump_view::open(owner),
        Some(Tool::CpuMemory) => cpumem_view::open(owner),
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_row_names_a_real_check() {
        let ids: Vec<&str> = diagnostics::checks::CHECKS.iter().map(|c| c.id).collect();
        for check in [
            "disk.free",
            "events.recent",
            "events.crashes",
            "services.failures",
            "hardware.events",
            "storage.provider",
            "drives.health",
            "registry.health",
            "crash.dumps",
            "resources.snapshot",
        ] {
            assert!(ids.contains(&check), "{check} is not a check id");
        }
        assert_eq!(tool_for("disk.free"), Some(Tool::Space));
        assert_eq!(tool_for("storage.provider"), Some(Tool::Drive));
        assert_eq!(tool_for("drives.health"), Some(Tool::Drive));
        assert_eq!(tool_for("registry.health"), Some(Tool::CrashDumps));
        assert_eq!(tool_for("crash.dumps"), Some(Tool::CrashDumps));
        assert_eq!(tool_for("resources.snapshot"), Some(Tool::CpuMemory));
        assert_eq!(tool_for("os.version"), None);
    }

    #[test]
    fn every_event_row_opens_the_viewer_with_a_preset() {
        for check in [
            "events.recent",
            "events.crashes",
            "services.failures",
            "hardware.events",
        ] {
            assert_eq!(tool_for(check), Some(Tool::Events), "{check}");
            assert!(diagnostics::event_list::preset(check).is_some(), "{check}");
        }
    }
}
