//! Writes a synthetic findings PDF to output/pdf without reading anything from this computer.
use diagnostics::checks::{Finding, Outcome};
use diagnostics::events::{self, CategoryRead, Event, LogRead, Query, WithData, HARDWARE};
use diagnostics::expanded_probes::{self, DriveSpace};
use diagnostics::report::{save_pdf_in, Report};
use diagnostics::session::Session;
use diagnostics::tools::drives::health::{
    Disk, Health, Identity, NvmeHealth, Temperature, BUS_NVME,
};
use diagnostics::tools::drives::Gathered;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn finding(brief: &str, detail: &str, flagged: bool) -> Outcome {
    Outcome::Found(Finding::new(brief, detail, flagged))
}

fn at(minutes_before: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_793_570_000 - minutes_before * 60)
}

fn event(log: &str, provider: &str, id: u32, level: u8, minutes_before: u64) -> Event {
    Event {
        log: log.into(),
        provider: provider.into(),
        id,
        level,
        time: at(minutes_before),
        message: None,
    }
}

fn read(log: &str, events: usize) -> LogRead {
    LogRead {
        log: log.into(),
        events,
        unreadable: 0,
        limit: None,
        unavailable: None,
    }
}

fn with_data(event: Event, data: &[&str]) -> WithData {
    (
        event,
        data.iter().map(|text| Some(text.to_string())).collect(),
    )
}

/// The three event kind checks' real wording, from synthetic events run through the engine.
fn crashes_outcome() -> Outcome {
    let crash = |minutes: u64, app: &str, module: &str, code: &str| {
        with_data(
            event("Application", "Application Error", 1000, 2, minutes),
            &[app, module, code],
        )
    };
    let list = [
        crash(40, "example.exe", "example.dll", "c0000005"),
        crash(110, "example.exe", "example.dll", "c0000005"),
        crash(60 * 30, "sample.exe", "sample.dll", "c000001d"),
        with_data(
            event("Application", "Application Hang", 1002, 2, 60 * 52),
            &["sample.exe"],
        ),
    ];
    events::crashes_outcome(&list, &[read("Application", 4)], at(0), &[])
}

fn services_outcome() -> Outcome {
    let scm = |id: u32, minutes: u64, data: &[&str]| {
        with_data(
            event("System", "Service Control Manager", id, 2, minutes),
            data,
        )
    };
    let list = [
        scm(7031, 90, &["ExampleService", "1", "5000"]),
        scm(7031, 60 * 40, &["ExampleService", "2", "5000"]),
        scm(7009, 60 * 60, &["30000", "Sample Client Service"]),
    ];
    events::services_outcome(&list, &[read("System", 3)], at(0), &[])
}

fn hardware_outcome() -> Outcome {
    let list = [
        event("System", "Microsoft-Windows-WHEA-Logger", 17, 3, 60 * 3),
        event("System", "Microsoft-Windows-Kernel-PnP", 219, 3, 60 * 20),
        event("System", "Microsoft-Windows-Kernel-PnP", 219, 3, 60 * 44),
    ];
    let reads: Vec<CategoryRead> = HARDWARE
        .iter()
        .map(|category| CategoryRead {
            category,
            events: list
                .iter()
                .filter(|event| category.providers.contains(&event.provider.as_str()))
                .cloned()
                .collect(),
            read: read("System", 0),
        })
        .collect();
    events::hardware_outcome(&reads, at(0))
}

fn drive_outcome() -> Outcome {
    let nvme = Disk {
        number: 0,
        identity: Ok(Identity {
            vendor: String::new(),
            model: "Example 1 TB SSD".into(),
            firmware: "1.0".into(),
            bus: BUS_NVME,
            removable: false,
        }),
        size: Ok(1_000_204_886_016),
        solid_state: Ok(true),
        volumes: vec!['C'],
        temperature: Ok(Temperature {
            current: Some(41),
            warning: Some(82),
            critical: Some(85),
        }),
        predicts_failure: Ok(false),
        health: Health::Nvme(NvmeHealth {
            critical_warning: 0,
            temperature_kelvin: 314,
            available_spare: 100,
            spare_threshold: 10,
            percentage_used: 12,
            data_units_read: 101_562_500,
            data_units_written: 78_125_000,
            host_read_commands: 0,
            host_write_commands: 0,
            controller_busy_minutes: 0,
            power_cycles: 1_204,
            power_on_hours: 8_812,
            unsafe_shutdowns: 61,
            media_errors: 0,
            error_log_entries: 14,
            warning_temperature_minutes: 0,
            critical_temperature_minutes: 0,
            sensors_kelvin: [0; 8],
            thermal_transitions: [0; 2],
            thermal_seconds: [0; 2],
        }),
    };
    expanded_probes::drive_outcome(&Gathered {
        elevated: Some(false),
        disks: vec![nvme],
        cut_short: false,
    })
}

fn events_outcome() -> Outcome {
    let mut list = vec![
        event("System", "Microsoft-Windows-Kernel-Power", 41, 1, 300),
        event("System", "EventLog", 6008, 2, 299),
        event("Application", "Application Error", 1000, 2, 40),
        event("Application", "Application Error", 1000, 2, 110),
        event("System", "Service Control Manager", 7031, 2, 90),
        event("System", "Example-Component", 12, 3, 20),
    ];
    for minutes in 0..100 {
        list.push(event(
            "System",
            "Microsoft-Windows-DistributedCOM",
            10016,
            3,
            minutes * 7,
        ));
    }
    let summary = events::summarize(
        &list,
        at(0),
        false,
        vec![read("System", 104), read("Application", 2)],
    );
    events::survey_outcome(&Query::survey(), &summary)
}

fn main() {
    let folder = Path::new("output/pdf");
    std::fs::create_dir_all(folder).expect("sample folder");
    let inventory = [
        ("collected_at_utc", "2026-11-01T19:45:00Z"),
        ("system.manufacturer", "Example Computers"),
        ("system.model", "Café Workstation - synthetic example"),
        ("board.manufacturer", "Example Components"),
        ("board.model", "EX-B650"),
        ("board.revision", "2.0"),
        ("cpu.model", "Example 8-core processor"),
        ("ram.0.capacity_gib", "16"),
        ("ram.0.speed_mhz", "5600"),
        ("ram.0.part", "EX-16G-5600"),
        ("ram.1.capacity_gib", "16"),
        ("ram.1.speed_mhz", "5600"),
        ("ram.1.part", "EX-16G-5600"),
        ("ram.slots_reported", "4"),
        ("disk.0.model", "Example 1 TB SSD"),
        ("disk.0.capacity_gib", "954"),
        ("disk.0.interface", "NVMe"),
        ("disk.1.model", "Example removable USB drive"),
        ("disk.1.capacity_gib", "0"),
        ("disk.1.interface", "USB"),
        ("gpu.0.model", "Example graphics card"),
        ("gpu.0.memory_gib", "12"),
        ("gpu.0.driver_version", "32.0.15.1234"),
        ("gpu.0.driver_date", "2026-08-01"),
        ("gpu.0.status", "OK"),
        ("gpu.inactive.0.model", "Example integrated graphics"),
        ("bios.version", "EX-1.4"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect::<Vec<_>>();
    let mut hardware = Finding::new("32 GiB memory, 2 drives", "", false);
    hardware.data = inventory;
    let results = [
        finding("Windows 11 (10.0.26100)", "Windows version 10.0.26100.0 (Windows 11)", false),
        Outcome::Found(hardware),
        expanded_probes::drive_space_outcome(Ok(DriveSpace {
            letter: 'C',
            free: 451_500_000_000,
            total: 999_000_000_000,
        })),
        finding("No restart pending", "Windows release 24H2; update reboot flag False; servicing reboot flag False; crash-dump setting 3; automatic restart setting 1 (configuration only)", false),
        events_outcome(),
        crashes_outcome(),
        services_outcome(),
        finding("5 recent, 0 failed", "Local update history: latest 5 entries; failed 0, partial 0; newest recorded 2026-11-01T12:00:00Z UTC, result code 2, KB1234567. This does not check online availability", false),
        finding("CPU 42%, 12.0 GiB memory free", "One-time resource snapshot: CPU 42%, available memory 12.0/32.0 GiB, 240 processes. Active workloads may explain transient pressure", false),
        Outcome::Unavailable("Windows did not return this information".into()),
        hardware_outcome(),
        drive_outcome(),
        finding("1 unclean restart", "System log, past 30 days: stop events (WER-SystemErrorReporting 1001, a blue screen recorded at the next start), unclean restarts (Kernel-Power 41) and crash dump setup failures (volmgr 45, 46, 161).\nStop events (1001) in the past 30 days: 0.\nUnclean restarts (Kernel-Power 41) in the past 30 days: 1; 1 with no stop event within 15 minutes, so no stop was recorded for them (power loss, a hang, a held power button, or a stop that could not be written).\nCrash dump setup failures (volmgr 45, 46, 161): none in the past 30 days.\nNot flagged: one unclean restart alone can be a power cut.\nDump files and the page file were not examined here; toolkit crashes lists the dump files and the drivers they name (dump folders usually need administrator rights).", false),
    ];
    let now = Instant::now();
    let mut session = Session::new(now, Duration::from_secs(300), false);
    for outcome in results {
        let id = session.start_next(now).expect("a waiting check");
        session.finish(id, outcome, now + Duration::from_millis(1300));
    }
    session.tick(now);
    let report = Report {
        session: &session,
        version: env!("CARGO_PKG_VERSION"),
        connection: "Synthetic example; nothing was read from this computer.",
        repair: "No repair was run in this session.",
        details: None,
    };
    let path = save_pdf_in(folder, &report).expect("sample PDF generation");
    println!("{}", path.display());
}
