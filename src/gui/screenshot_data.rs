//! Made-up readings for the screenshot mode: a PC named DESKTOP-EXAMPLE used by alex, with
//! ordinary part names and serials like EX0123456789. Each value goes through the parser or
//! outcome builder a live reading would, and nothing here reads this PC.
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use diagnostics::checks::{self, Finding, Outcome};
use diagnostics::event_list::{self, Loaded, PartRead};
use diagnostics::events::{self, CategoryRead, Event, LogRead, Query, WithData, HARDWARE};
use diagnostics::expanded_probes::{self, DriveSpace};
use diagnostics::recovery::candidates::{self, Capture, Format, Kind, Version};
use diagnostics::recovery::carve::{Carved, Kind as CarveKind};
use diagnostics::recovery::dest::Protected;
use diagnostics::recovery::events::{self as rescue_events, Event as RescueEvent};
use diagnostics::recovery::fs::{
    Data, Found, FsKind, Listing, Modified, Origin, Part, Place, Run, State, Volume as FsVolume,
    Why,
};
use diagnostics::recovery::health_log::{Counts, HealthLog, Reading};
use diagnostics::recovery::image::{Map as RescueMap, Status};
use diagnostics::session::Session;
use diagnostics::tools::cpu_memory::cpuid::{self, FeatureGroup};
use diagnostics::tools::cpu_memory::details::{Board, Memory, Processor};
use diagnostics::tools::cpu_memory::monitor::{Event as Sampled, MemorySample, Sample};
use diagnostics::tools::cpu_memory::smbios::Baseboard;
use diagnostics::tools::cpu_memory::topology::{CacheGroup, CoreClass, ProcessorClock, Topology};
use diagnostics::tools::cpu_memory::Details as CpuDetails;
use diagnostics::tools::drives::details::{
    Details, Layout, Link, NvmeIdentify, Partition, SelfTest, SelfTestLog, Style, Volume,
};
use diagnostics::tools::drives::health::{
    Attribute, Disk, Health, Identity, NvmeHealth, Temperature, BUS_NVME, BUS_SATA,
};
use diagnostics::tools::drives::{bytes_text, Gathered};
use diagnostics::tools::space_map::{File, Folder, Map};

/// The moment the made-up checks ran, 2026-11-01, so their wording never depends on today.
fn checked_at(minutes_before: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_793_570_000 - minutes_before * 60)
}

fn event(log: &str, provider: &str, id: u32, level: u8, time: SystemTime) -> Event {
    Event {
        log: log.into(),
        provider: provider.into(),
        id,
        level,
        time,
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

fn parsed(id: &str, script_output: &str) -> Outcome {
    let outcome = checks::parse(id, script_output);
    assert!(matches!(outcome, Outcome::Found(_)), "{id}: {outcome:?}");
    outcome
}

/// What the hardware inventory script prints, one field a line.
const INVENTORY: &str = "collected_at_utc=2026-11-01T19:45:00Z
system.manufacturer=Example Computers
system.model=EX-500 Desktop
board.manufacturer=Example Components
board.model=EX-B650
board.revision=2.0
cpu.model=Example 8-core processor
ram.0.capacity_gib=16
ram.0.speed_mhz=5600
ram.0.part=EX-16G-5600
ram.1.capacity_gib=16
ram.1.speed_mhz=5600
ram.1.part=EX-16G-5600
ram.slots_reported=4
disk.0.model=Example 1 TB NVMe SSD
disk.0.capacity_gib=954
disk.0.interface=NVMe
disk.1.model=Example 512 GB NVMe SSD
disk.1.capacity_gib=477
disk.1.interface=NVMe
gpu.0.model=Example graphics card
gpu.0.memory_gib=12
gpu.0.driver_version=32.0.15.1234
gpu.0.driver_date=2026-08-01
gpu.0.status=OK
gpu.inactive.0.model=Example integrated graphics
bios.version=EX-1.4";

fn survey() -> Outcome {
    let at = |minutes| checked_at(minutes);
    let mut list = vec![
        event("System", "Microsoft-Windows-Kernel-Power", 41, 1, at(300)),
        event("System", "EventLog", 6008, 2, at(299)),
        event("Application", "Application Error", 1000, 2, at(40)),
        event("Application", "Application Error", 1000, 2, at(110)),
        event("System", "Service Control Manager", 7031, 2, at(90)),
        event("System", "Example-Component", 12, 3, at(20)),
    ];
    for minutes in 0..100 {
        list.push(event(
            "System",
            "Microsoft-Windows-DistributedCOM",
            10016,
            3,
            at(minutes * 7),
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

fn crashes() -> Outcome {
    let crash = |minutes, app: &str, module: &str, code: &str| {
        with_data(
            event(
                "Application",
                "Application Error",
                1000,
                2,
                checked_at(minutes),
            ),
            &[app, module, code],
        )
    };
    let list = [
        crash(40, "example.exe", "example.dll", "c0000005"),
        crash(110, "example.exe", "example.dll", "c0000005"),
        crash(60 * 30, "sample.exe", "sample.dll", "c000001d"),
        with_data(
            event(
                "Application",
                "Application Hang",
                1002,
                2,
                checked_at(60 * 52),
            ),
            &["sample.exe"],
        ),
    ];
    events::crashes_outcome(&list, &[read("Application", 4)], checked_at(0), &[])
}

fn services() -> Outcome {
    let scm = |id, minutes, data: &[&str]| {
        with_data(
            event(
                "System",
                "Service Control Manager",
                id,
                2,
                checked_at(minutes),
            ),
            data,
        )
    };
    let list = [
        scm(7031, 90, &["Example", "1", "5000"]),
        scm(7031, 60 * 40, &["Example", "2", "5000"]),
    ];
    events::services_outcome(&list, &[read("System", 2)], checked_at(0), &[])
}

fn hardware_events() -> Outcome {
    let list = [
        event(
            "System",
            "Microsoft-Windows-Kernel-PnP",
            219,
            3,
            checked_at(60 * 20),
        ),
        event(
            "System",
            "Microsoft-Windows-Kernel-PnP",
            219,
            3,
            checked_at(60 * 44),
        ),
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
    events::hardware_outcome(&reads, checked_at(0))
}

/// Every check's outcome in the order of `checks::CHECKS`, finished and saved: clear rows,
/// flagged ones and two serious ones about the second drive.
pub fn session() -> Session {
    let results = [
        parsed("os.version", "10.0.26100.2314"),
        parsed("hardware.inventory", INVENTORY),
        expanded_probes::drive_space_outcome(Ok(DriveSpace {
            letter: 'C',
            free: 182_400_000_000,
            total: 1_000_204_886_016,
        })),
        parsed(
            "registry.health",
            "release=24H2\nupdate=True\nservicing=False\ncrashdump=7\nautoreboot=1",
        ),
        survey(),
        crashes(),
        services(),
        parsed(
            "updates.local",
            "sampled=5\nfailed=0\npartial=0\nlatest.time=2026-10-29T03:12:00Z\nlatest.clock=plausible\nlatest.result=2\nlatest.kb=KB5050001",
        ),
        parsed(
            "resources.snapshot",
            "cpu.percent=9\nprocess.count=214\nmemory.free_gib=21.6\nmemory.total_gib=31.8",
        ),
        parsed(
            "storage.provider",
            "sampled=2\nhealthy=1\nflagged=1\nunknown=0\nflagged.name=Example_512_GB_NVMe_SSD",
        ),
        hardware_events(),
        expanded_probes::drive_outcome(&Gathered {
            elevated: Some(false),
            disks: drives().into_iter().map(|(disk, _)| disk).collect(),
            cut_short: false,
        }),
        Outcome::Found(Finding::new(
            "1 unclean restart",
            "Unclean restarts (Kernel-Power 41) in the past 30 days: 1, with no stop event recorded for it. Not flagged: one unclean restart alone can be a power cut.",
            false,
        )),
    ];
    let now = Instant::now();
    let mut session = Session::new(now, Duration::from_secs(300), false);
    for outcome in results {
        let id = session.start_next(now).expect("a waiting check");
        session.finish(id, outcome, now + Duration::from_millis(1300));
    }
    session.tick(now);
    session
}

/// Where the made-up report was saved.
pub fn report_path() -> PathBuf {
    PathBuf::from(r"C:\Users\alex\Documents\Diagnostic-Tool-20261101-194512.pdf")
}

/// The hardware inventory's fields, for the hardware view.
pub fn inventory() -> Vec<(String, String)> {
    match parsed("hardware.inventory", INVENTORY) {
        Outcome::Found(finding) => finding.data,
        _ => Vec::new(),
    }
}

// ---- the drive space map ---------------------------------------------------------------

const GB: u64 = 1_000_000_000;

/// A folder of the map before its totals are added up: its name, the files directly in it
/// (the largest named) and its subfolders.
struct Node {
    name: &'static str,
    files: Vec<(&'static str, u64)>,
    /// Small files besides the named ones: how many and their bytes together.
    small: (u64, u64),
    children: Vec<Node>,
}

fn node(name: &'static str, files: &[(&'static str, u64)], children: Vec<Node>) -> Node {
    Node {
        name,
        files: files.to_vec(),
        small: (0, 0),
        children,
    }
}

fn bulk(name: &'static str, bytes: u64, count: u64) -> Node {
    Node {
        name,
        files: Vec::new(),
        small: (count, bytes),
        children: Vec::new(),
    }
}

fn add(map: &mut Map, node: Node, parent: usize) -> u64 {
    let index = map.folders.len();
    let own = node.files.iter().map(|(_, bytes)| bytes).sum::<u64>() + node.small.1;
    map.folders.push(Folder {
        name: node.name.into(),
        parent,
        own,
        total: own,
        files: node.files.len() as u64 + node.small.0,
        children: Vec::new(),
        largest: node
            .files
            .iter()
            .map(|(name, bytes)| File {
                name: (*name).into(),
                bytes: *bytes,
            })
            .collect(),
        unreadable: false,
        unfinished: false,
    });
    let mut total = own;
    for child in node.children {
        let at = map.folders.len();
        total += add(map, child, index);
        map.folders[index].children.push(at);
    }
    map.folders[index].total = total;
    total
}

/// The Windows drive as the space window maps it.
pub fn space_map() -> Map {
    let alex = node(
        "alex",
        &[],
        vec![
            node(
                "Videos",
                &[
                    ("Holiday 2025.mp4", 38 * GB),
                    ("Birthday party.mov", 21 * GB),
                ],
                vec![bulk("Clips", 14 * GB, 212)],
            ),
            node(
                "Pictures",
                &[],
                vec![
                    bulk("Camera Roll", 46 * GB, 9_814),
                    bulk("Screenshots", 2 * GB, 1_140),
                ],
            ),
            node(
                "Downloads",
                &[
                    ("example-game-setup.exe", 9 * GB),
                    ("photos-backup.zip", 7 * GB),
                ],
                vec![],
            ),
            bulk("AppData", 31 * GB, 184_220),
            bulk("Documents", 11 * GB, 6_532),
            bulk("Music", 8 * GB, 2_408),
        ],
    );
    let root = node(
        "C:",
        &[
            ("pagefile.sys", 19 * GB),
            ("hiberfil.sys", 13 * GB),
            ("swapfile.sys", GB / 4),
        ],
        vec![
            node("Users", &[], vec![alex, bulk("Public", GB / 2, 120)]),
            bulk("Windows", 41 * GB, 312_408),
            bulk("Program Files", 96 * GB, 141_220),
            bulk("Program Files (x86)", 22 * GB, 61_340),
            bulk("ProgramData", 18 * GB, 52_118),
            bulk("Games", 210 * GB, 48_960),
        ],
    );
    let mut map = Map {
        root: PathBuf::from("C:\\"),
        elapsed: Duration::from_secs(41),
        ..Map::default()
    };
    add(&mut map, root, 0);
    map
}

/// The Windows drive's free and total bytes, matching the map.
pub fn space_disk() -> (u64, u64) {
    (182_400_000_000, 1_000_204_886_016)
}

// ---- the event viewer -----------------------------------------------------------------

/// The check whose events the viewer shows.
pub const EVENTS_CHECK: &str = "events.recent";

/// What reading the recent system events gives, the newest first, hours before now so the
/// viewer's time range keeps them; the details show row `chosen_event()`.
pub fn events() -> Loaded {
    let preset = event_list::preset(EVENTS_CHECK).expect("the recent events preset");
    let filter = preset.default_filter();
    let now = SystemTime::now();
    let ago = |minutes: u64| now - Duration::from_secs(minutes * 60);
    let said = |mut event: Event, message: &str| {
        event.message = Some(message.into());
        event
    };
    let list = [
        said(
            event("System", "Microsoft-Windows-Kernel-Power", 41, 1, ago(300)),
            "The system restarted without shutting down cleanly first. It may have stopped responding, crashed or lost power.",
        ),
        said(
            event("System", "EventLog", 6008, 2, ago(299)),
            "The previous system shutdown at 14:02:11 on 11/01/2026 was unexpected.",
        ),
        said(
            event("Application", "Application Error", 1000, 2, ago(40)),
            "Faulting application name: example.exe, version: 2.4.1.0\nFaulting module name: example.dll, version: 2.4.1.0\nException code: 0xc0000005\nFault offset: 0x000000000001a2b3\nFaulting application path: C:\\Program Files\\Example\\example.exe",
        ),
        said(
            event("System", "Service Control Manager", 7031, 2, ago(90)),
            "The Example service terminated unexpectedly. It has done this 1 time(s). The following corrective action will be taken in 5000 milliseconds: Restart the service.",
        ),
        said(
            event("System", "Microsoft-Windows-DNS-Client", 1014, 3, ago(65)),
            "Name resolution for the name update.example.com timed out after none of the configured DNS servers responded. Client IP address: 192.0.2.24.",
        ),
        said(
            event("System", "Microsoft-Windows-Time-Service", 129, 3, ago(180)),
            "NtpClient was unable to set a domain peer to use as a time source. It will try again in 15 minutes.",
        ),
        said(
            event("System", "Microsoft-Windows-Kernel-PnP", 219, 3, ago(1_200)),
            "The driver \\Driver\\ExampleUsb failed to load for the device USB\\VID_0000&PID_0000\\EX0123456789.",
        ),
        said(
            event("Application", "Example-Updater", 3, 3, ago(1_500)),
            "The update check for DESKTOP-EXAMPLE could not reach the server at 2001:db8::15.",
        ),
    ];
    let mut rows = Vec::new();
    let mut parts = Vec::new();
    for part in &preset.parts {
        let found: Vec<Event> = list
            .iter()
            .filter(|event| part.query.logs.contains(&event.log))
            .cloned()
            .collect();
        parts.push(PartRead {
            label: part.label.clone(),
            read: read(&part.query.logs.join(" and "), found.len()),
            oldest: found.iter().map(|event| event.time).min(),
        });
        rows.extend(
            found
                .into_iter()
                .filter(|event| part.scope.keeps(event))
                .map(|event| event_list::Row::new(event, &part.scope)),
        );
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.event.time));
    Loaded {
        queries: preset.queries(&filter),
        rows,
        parts,
    }
}

/// The row of `events()` shown in the details: the unclean restart.
pub fn chosen_event(loaded: &Loaded) -> usize {
    loaded
        .rows
        .iter()
        .position(|row| row.event.id == 41)
        .unwrap_or(0)
}

// ---- the drive window -----------------------------------------------------------------

fn nvme(model: &str) -> Identity {
    Identity {
        vendor: String::new(),
        model: model.into(),
        firmware: "EX10".into(),
        bus: BUS_NVME,
        removable: false,
    }
}

fn health(used: u8, media_errors: u128, hours: u128, kelvin: u16) -> NvmeHealth {
    NvmeHealth {
        critical_warning: 0,
        temperature_kelvin: kelvin,
        available_spare: 100,
        spare_threshold: 10,
        percentage_used: used,
        data_units_read: 101_562_500,
        data_units_written: 78_125_000,
        host_read_commands: 1_204_331_890,
        host_write_commands: 988_310_442,
        controller_busy_minutes: 2_310,
        power_cycles: 1_204,
        power_on_hours: hours,
        unsafe_shutdowns: 61,
        media_errors,
        error_log_entries: 14,
        warning_temperature_minutes: 0,
        critical_temperature_minutes: 0,
        sensors_kelvin: [kelvin, kelvin + 4, 0, 0, 0, 0, 0, 0],
        thermal_transitions: [0; 2],
        thermal_seconds: [0; 2],
    }
}

fn gpt(size: u64) -> Layout {
    let mib = 1 << 20;
    Layout {
        style: Style::Gpt,
        partitions: vec![
            Partition {
                number: 1,
                offset: mib,
                length: 100 * mib,
                kind: "EFI system".into(),
            },
            Partition {
                number: 2,
                offset: 101 * mib,
                length: 16 * mib,
                kind: "Microsoft reserved".into(),
            },
            Partition {
                number: 3,
                offset: 117 * mib,
                length: size - 117 * mib - 750 * mib,
                kind: "Basic data".into(),
            },
            Partition {
                number: 4,
                offset: size - 750 * mib,
                length: 749 * mib,
                kind: "Windows recovery".into(),
            },
        ],
    }
}

fn details(letter: char, size: u64, free: u64, tests: Vec<SelfTest>) -> Details {
    Details {
        link: Ok(Link {
            speed: Some(4),
            width: Some(4),
            max_speed: Some(4),
            max_width: Some(4),
        }),
        layout: Ok(gpt(size)),
        volumes: vec![Volume {
            letter,
            offsets: vec![117 << 20],
            other_disks: Vec::new(),
            space: Ok((free, size - (867 << 20))),
            file_system: Ok("NTFS".into()),
        }],
        trim: Ok(true),
        windows_trim: Ok(true),
        identify: Ok(NvmeIdentify {
            version: Some((1, 4, 0)),
            self_test: true,
            extended_test_minutes: 12,
            warning_kelvin: 357,
            critical_kelvin: 360,
        }),
        self_test: Ok(SelfTestLog {
            running: None,
            results: tests,
        }),
    }
}

/// Two drives: the Windows drive, healthy, and a second drive with media errors.
pub fn drives() -> Vec<(Disk, Details)> {
    let first = 1_000_204_886_016;
    let second = 512_110_190_592;
    vec![
        (
            Disk {
                number: 0,
                identity: Ok(nvme("Example 1 TB NVMe SSD")),
                size: Ok(first),
                solid_state: Ok(true),
                volumes: vec!['C'],
                temperature: Ok(Temperature {
                    current: Some(41),
                    warning: Some(84),
                    critical: Some(87),
                }),
                predicts_failure: Ok(false),
                health: Health::Nvme(health(12, 0, 8_812, 314)),
            },
            details(
                'C',
                first,
                182_400_000_000,
                vec![SelfTest {
                    kind: "short",
                    outcome: "completed without error",
                    passed: Some(true),
                    power_on_hours: 8_790,
                }],
            ),
        ),
        (
            Disk {
                number: 1,
                identity: Ok(nvme("Example 512 GB NVMe SSD")),
                size: Ok(second),
                solid_state: Ok(true),
                volumes: vec!['D'],
                temperature: Ok(Temperature {
                    current: Some(47),
                    warning: Some(84),
                    critical: Some(87),
                }),
                predicts_failure: Ok(false),
                health: Health::Nvme(health(41, 37, 21_406, 320)),
            },
            details(
                'D',
                second,
                61_800_000_000,
                vec![SelfTest {
                    kind: "short",
                    outcome: "completed with a failed segment",
                    passed: Some(false),
                    power_on_hours: 21_380,
                }],
            ),
        ),
    ]
}

// ---- the processor and memory window ----------------------------------------------------

/// What the details engine reads about the processor, memory and board.
pub fn cpu_details() -> CpuDetails {
    let clocks = (0..16)
        .map(|n| ProcessorClock {
            processor: n,
            base_mhz: 3_800,
            current_mhz: 3_800,
            limit_mhz: 3_800,
        })
        .collect();
    let signature = cpuid::signature(0x00A6_0F12);
    CpuDetails {
        processor: Some(Processor {
            vendor: "ExampleVendor".into(),
            brand: "Example 8-core processor".into(),
            signature,
            design: None,
            instruction_sets: vec![FeatureGroup {
                group: "AVX".into(),
                names: vec!["AVX".into(), "AVX2".into()],
            }],
            hybrid: false,
            hypervisor: false,
            topology: Some(Topology {
                packages: 1,
                cores: 8,
                logical_processors: 16,
                numa_nodes: 1,
                processor_groups: 1,
                core_classes: vec![CoreClass {
                    efficiency_class: 0,
                    cores: 8,
                    threads: 16,
                }],
                caches: vec![CacheGroup {
                    level: 3,
                    kind: "unified".into(),
                    size_bytes: 32 << 20,
                    ways: Some(16),
                    line_bytes: 64,
                    count: 1,
                    shared_by_threads: 16,
                }],
            }),
            cpuid_caches: Vec::new(),
            clocks,
            cpuid_base_mhz: None,
            cpuid_max_mhz: Some(5_100),
            sockets: Vec::new(),
        }),
        memory: Some(Memory {
            installed_bytes: Some(32 << 30),
            usable_bytes: 31 << 30,
            available_bytes: 21 << 30,
            committed_bytes: 15 << 30,
            commit_limit_bytes: 40 << 30,
            arrays: Vec::new(),
            modules: Vec::new(),
            channels: None,
            mapped_bytes: Some(32 << 30),
        }),
        board: Some(Board {
            baseboard: Some(Baseboard {
                manufacturer: Some("Example Components".into()),
                product: Some("EX-B650".into()),
                version: Some("2.0".into()),
            }),
            bios: None,
        }),
        smbios_version: Some("3.5".into()),
        smbios_cut_short: None,
        unread: Vec::new(),
    }
}

/// Two minutes of the sampler at one reading a second, ending now: a quiet desktop with a
/// burst of work in the middle.
pub fn cpu_samples() -> Vec<Sampled> {
    let count: u64 = 120;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let total = 31u64 << 30;
    let mut events = vec![Sampled::Started {
        logical_processors: 16,
        base_mhz: Some(3_800.0),
        unavailable: Vec::new(),
    }];
    for index in 0..count {
        let t = index as f64;
        let burst = (-((t - 70.0) / 9.0).powi(2)).exp();
        let ripple = (t * 0.9).sin() * 2.5 + (t * 0.37).cos() * 1.5;
        let cpu = (7.0 + 58.0 * burst + ripple).clamp(1.0, 100.0);
        let in_use = ((10.2 + 3.1 * burst) * f64::from(1u32 << 30)) as u64;
        events.push(Sampled::Sample(Sample {
            index,
            elapsed_ms: (index + 1) * 1_000,
            unix_ms: now_ms - (count - 1 - index) * 1_000,
            cpu_percent: Some(cpu),
            per_processor_percent: Vec::new(),
            clock_mhz: Some(3_800.0 + 1_100.0 * burst),
            memory: Some(MemorySample {
                total_bytes: total,
                in_use_bytes: in_use,
                available_bytes: total - in_use,
                modified_bytes: Some(310 << 20),
                standby_bytes: Some(9 << 30),
                free_bytes: Some((total - in_use).saturating_sub(9 << 30)),
                cached_bytes: Some((9 << 30) + (310 << 20)),
                committed_bytes: 15 << 30,
                commit_limit_bytes: 40 << 30,
                paged_pool_bytes: 610 << 20,
                nonpaged_pool_bytes: 380 << 20,
            }),
            processes: Some(214),
            threads: Some(2_861),
            handles: Some(98_412),
            uptime_s: Some(2 * 86_400 + 5 * 3_600 + 12 * 60),
        }));
    }
    events
}

// ---- the data recovery windows ----------------------------------------------------------

/// The drive the recovery windows read: disk 4, a failing 1 TB SATA drive with one volume.
pub const RECOVERY_DISK: u32 = 4;
const RECOVERY_SIZE: u64 = 1_000_204_886_016;
const RECOVERY_LETTER: char = 'F';
const RECOVERY_MODEL: &str = "Example 1 TB SATA drive";
/// Where the rescue and the recovered files go, on another drive.
const RECOVERED: &str = r"E:\Recovered";

/// The source as an opened disk describes itself.
fn recovery_about() -> String {
    format!(
        "Disk {RECOVERY_DISK}, {RECOVERY_MODEL}, {}",
        diagnostics::tools::drives::size_text(RECOVERY_SIZE)
    )
}

fn attribute(id: u8, current: u8, raw: u64) -> Attribute {
    let bytes = raw.to_le_bytes();
    Attribute {
        id,
        current,
        worst: current,
        raw: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
    }
}

/// The drive's SMART counts and temperature at one reading.
#[derive(Clone, Copy)]
struct Counted {
    reallocated: u64,
    pending: u64,
    uncorrectable: u64,
    celsius: i32,
}

/// The counts as the rescue began and as they are now.
const AT_START: Counted = Counted {
    reallocated: 121,
    pending: 40,
    uncorrectable: 9,
    celsius: 39,
};
const NOW: Counted = Counted {
    reallocated: 148,
    pending: 32,
    uncorrectable: 12,
    celsius: 44,
};

/// The failing drive as the recovery window reads it when it opens.
pub fn recovery_disk() -> Disk {
    Disk {
        number: RECOVERY_DISK,
        identity: Ok(Identity {
            vendor: String::new(),
            model: RECOVERY_MODEL.into(),
            firmware: "EX01".into(),
            bus: BUS_SATA,
            removable: false,
        }),
        size: Ok(RECOVERY_SIZE),
        solid_state: Ok(false),
        volumes: vec![RECOVERY_LETTER],
        temperature: Ok(Temperature {
            current: Some(NOW.celsius as i16),
            warning: Some(55),
            critical: Some(60),
        }),
        predicts_failure: Ok(true),
        health: Health::Ata(vec![
            attribute(5, 88, NOW.reallocated),
            attribute(9, 74, 23_412),
            attribute(194, NOW.celsius as u8, NOW.celsius as u64),
            attribute(197, 100, NOW.pending),
            attribute(198, 100, NOW.uncorrectable),
        ]),
    }
}

/// A wall-clock time `seconds` before now, as the event and health logs write it.
fn logged_at(seconds: u64) -> String {
    let s = diagnostics::clock::local(SystemTime::now() - Duration::from_secs(seconds));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        s.year, s.month, s.day, s.hour, s.minute, s.second
    )
}

fn reading(seconds_ago: u64, counts: Counted, pos: u64, bad: u64) -> Reading {
    Reading {
        time: logged_at(seconds_ago),
        counts: Counts::Ata {
            reallocated: Some(counts.reallocated),
            pending: Some(counts.pending),
            uncorrectable: Some(counts.uncorrectable),
        },
        celsius: Some(counts.celsius),
        pos,
        bad,
    }
}

/// An event of the rescue's log as a line of it, `seconds` before now.
fn log_line(seconds_ago: u64, event: &RescueEvent) -> String {
    let mut line = serde_json::to_value(event).expect("an event is JSON");
    line["time"] = logged_at(seconds_ago).into();
    line.to_string()
}

/// The counts `share` of the way from the start of the run to now, with a little wobble.
fn counts_between(share: f64, wobble: i64) -> Counted {
    let between = |from: u64, to: u64| {
        let value = from as f64 + (to as f64 - from as f64) * share;
        (value.round() as i64 + wobble).max(0) as u64
    };
    Counted {
        reallocated: between(AT_START.reallocated, NOW.reallocated),
        pending: between(AT_START.pending, NOW.pending),
        uncorrectable: between(AT_START.uncorrectable, NOW.uncorrectable).min(NOW.uncorrectable),
        celsius: AT_START.celsius + ((NOW.celsius - AT_START.celsius) as f64 * share) as i32,
    }
}

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

/// Marks `len` bytes at `at` with `status`, `at` and `len` in whole sectors.
fn mark(map: &mut RescueMap, at: u64, len: u64, status: Status) {
    map.set(at / 4096 * 4096, len.max(4096) / 4096 * 4096, status);
}

/// The rescue's map with everything before `end` read in the first pass: its failed areas,
/// the areas it skipped after them and a few bad sectors, the rest not read yet.
fn rescue_map(end: u64) -> RescueMap {
    let mut map = RescueMap::new(RECOVERY_SIZE);
    mark(&mut map, 0, end, Status::Rescued);
    // (start, failed, skipped after it), in GiB.
    let failed: [(f64, f64, f64); 7] = [
        (88.0, 2.4, 0.0),
        (212.0, 1.2, 6.0),
        (233.0, 0.9, 0.0),
        (305.0, 3.6, 4.0),
        (446.0, 1.1, 0.0),
        (498.0, 2.2, 8.0),
        (577.0, 0.7, 0.0),
    ];
    for (start, len, skipped) in failed {
        let at = (start * GIB as f64) as u64;
        let failed_len = (len * GIB as f64) as u64;
        if at + failed_len + (skipped * GIB as f64) as u64 > end {
            continue;
        }
        mark(&mut map, at, failed_len, Status::NonTrimmed);
        mark(
            &mut map,
            at + failed_len,
            (skipped * GIB as f64) as u64,
            Status::Untried,
        );
    }
    // Single sectors that failed alone are bad already.
    for (gib, sectors) in [
        (141.0, 12),
        (142.5, 30),
        (143.2, 8),
        (389.0, 20),
        (390.1, 44),
    ] {
        if ((gib * GIB as f64) as u64) < end {
            for i in 0..sectors {
                mark(
                    &mut map,
                    (gib * GIB as f64) as u64 + i * 7 * MIB,
                    4096,
                    Status::Bad,
                );
            }
        }
    }
    map.current_pos = end;
    map
}

/// The rescue's pace: now, and on average this run.
const RESCUE_RATE: f64 = 41_300_000.0;
const RESCUE_AVERAGE: f64 = 38_900_000.0;

/// The rescue image of disk 4 partway through its first pass, resumed from where an earlier
/// run stopped. Its event log and health readings are handed to the condition strip.
pub fn rescue_run() -> crate::rescue_image_view::MidRun {
    let before = rescue_map(260 * GIB);
    let map = rescue_map(620 * GIB);
    let gained = map
        .count(Status::Rescued)
        .saturating_sub(before.count(Status::Rescued));
    let running_for = (gained as f64 / RESCUE_AVERAGE) as u64;
    let first = reading(running_for, AT_START, before.current_pos, before.failed());
    let latest = reading(0, NOW, map.current_pos, map.failed());
    let mut log = HealthLog::start(
        PathBuf::from(RECOVERED).join("health.csv"),
        Err(std::io::Error::other("the screenshots write no log")),
    );
    log.add(first);
    log.add(latest.clone());
    // The run's event log: its start, a health reading every ten minutes, its speed every
    // five, and the one time the drive stopped answering.
    let mut lines = vec![log_line(
        running_for,
        &rescue_events::started(
            "rescue image",
            Some(RECOVERY_DISK),
            None,
            serde_json::json!({}),
        ),
    )];
    for minutes in (0..=running_for / 300).rev().map(|n| n * 5) {
        let ago = minutes * 60;
        let share = 1.0 - ago as f64 / running_for as f64;
        if minutes % 10 == 0 {
            let counts = counts_between(share, [0, 1, -1, 0, 2, -2][(minutes / 10 % 6) as usize]);
            let health = reading(ago, counts, 0, 0).event();
            lines.push(log_line(ago, &health));
        }
        let wave = (minutes as f64 * 0.7).sin() * 4_500_000.0;
        let dip = if (48..=56).contains(&minutes) {
            0.4
        } else {
            1.0
        };
        lines.push(log_line(
            ago,
            &RescueEvent::Progress {
                bytes_per_second: ((RESCUE_RATE + wave) * dip) as u64,
            },
        ));
    }
    lines.push(log_line(
        52 * 60,
        &RescueEvent::DriveGone {
            seen: "a read failed with error 1167, the device is not connected".into(),
            code: Some(1167),
        },
    ));
    crate::condition_strip::logged(RECOVERY_DISK, &lines);
    crate::rescue_image_view::MidRun {
        about: recovery_about(),
        folder: PathBuf::from(RECOVERED),
        before,
        map,
        health: log.live_text(),
        drive: Some(latest),
        rate: RESCUE_RATE,
        average: RESCUE_AVERAGE,
        running_for: Duration::from_secs(running_for),
    }
}

// ---- recovering files ------------------------------------------------------------------

/// What file recovery reads: the disk, which protects itself from being written.
pub fn recovery_source() -> (String, Protected) {
    (recovery_about(), Protected::disk(RECOVERY_DISK))
}

const VOLUME_START: u64 = 117 * MIB;

/// The drive's volumes the recover window finds: the large Windows volume first, which
/// is the one read, then the system and recovery partitions.
pub fn recovery_volumes() -> Vec<FsVolume> {
    let volume = |kind, start, len, n| FsVolume {
        kind,
        start,
        len,
        origin: Origin::Gpt(n),
        claims: Vec::new(),
    };
    vec![
        volume(
            FsKind::Ntfs,
            VOLUME_START,
            RECOVERY_SIZE - VOLUME_START - 750 * MIB,
            3,
        ),
        volume(FsKind::Fat32, MIB, 100 * MIB, 1),
        volume(FsKind::Ntfs, RECOVERY_SIZE - 750 * MIB, 749 * MIB, 4),
    ]
}

fn found(
    path: &str,
    size: u64,
    (year, month, day): (u16, u8, u8),
    deleted: bool,
    state: State,
) -> Found {
    let (folder, name) = path.rsplit_once('\\').unwrap_or(("", path));
    let folder = folder
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(|part| match part.strip_suffix('*') {
            Some(name) => Part {
                name: name.into(),
                deleted: true,
            },
            None => Part {
                name: part.into(),
                deleted: false,
            },
        })
        .collect();
    Found {
        name: name.into(),
        folder,
        size,
        modified: Some(Modified::Local {
            year,
            month,
            day,
            hour: 9 + (size % 9) as u8,
            minute: (size % 60) as u8,
        }),
        deleted,
        state,
        data: Data::Runs(vec![Run {
            place: Place::At(VOLUME_START + 40 * GIB + size % (300 * GIB)),
            len: size,
        }]),
        damaged: false,
        note: None,
        why: None,
    }
}

/// The Windows volume's files: deleted ones, some whole, some damaged by the drive's read
/// errors and some overwritten since, then the files still in use.
pub fn recovery_listing() -> Listing {
    let partly = |used, of| State::Partly { used, of };
    let mut files = vec![
        found(
            r"\Users\alex\Pictures\Holiday 2025\Holiday-2025-001.jpg",
            4_212_334,
            (2025, 8, 14),
            true,
            State::Intact,
        ),
        found(
            r"\Users\alex\Pictures\Holiday 2025\Holiday-2025-002.jpg",
            3_980_112,
            (2025, 8, 14),
            true,
            State::Intact,
        ),
        Found {
            damaged: true,
            ..found(
                r"\Users\alex\Pictures\Holiday 2025\Holiday-2025-003.jpg",
                4_506_871,
                (2025, 8, 14),
                true,
                State::Intact,
            )
        },
        found(
            r"\Users\alex\Pictures\Holiday 2025\Holiday-2025-004.jpg",
            4_120_448,
            (2025, 8, 15),
            true,
            partly(3, 10),
        ),
        found(
            r"\Users\alex\Pictures\Holiday 2025\Holiday-2025-005.jpg",
            3_877_019,
            (2025, 8, 15),
            true,
            State::Overwritten,
        ),
        found(
            r"\Users\alex\Documents\Taxes-2024.pdf",
            1_284_552,
            (2025, 4, 2),
            true,
            State::Intact,
        ),
        Found {
            why: Some(Why::Mismatch(None)),
            ..found(
                r"\Users\alex\Documents\Taxes-2023.pdf",
                1_190_310,
                (2024, 4, 11),
                true,
                State::Overwritten,
            )
        },
        found(
            r"\Users\alex\Documents\Budget-2025.xlsx",
            88_412,
            (2025, 1, 6),
            true,
            State::Intact,
        ),
        found(
            r"\Users\alex\Documents\Letters*\Letter-to-school.docx",
            24_118,
            (2025, 9, 3),
            true,
            State::Intact,
        ),
        found(
            r"\Users\alex\Videos\Birthday-party.mp4",
            1_402_331_904,
            (2025, 11, 22),
            true,
            partly(12, 100),
        ),
        Found {
            damaged: true,
            ..found(
                r"\Users\alex\Pictures\Camera Roll\IMG-2041.jpg",
                3_311_904,
                (2026, 6, 30),
                true,
                State::Intact,
            )
        },
        found(
            r"\Users\alex\Desktop\Notes.txt",
            2_310,
            (2026, 10, 27),
            true,
            State::Unknown,
        ),
        found(
            r"\Users\alex\Music\Recital-2026.m4a",
            6_920_771,
            (2026, 5, 18),
            true,
            State::Intact,
        ),
    ];
    for n in 0..1_191u64 {
        let path = match n % 3 {
            0 => format!(r"\Users\alex\Pictures\Camera Roll\IMG-{:04}.jpg", 1_000 + n),
            1 => format!(r"\Users\alex\Documents\Scans\Scan-{:04}.pdf", n),
            _ => format!(r"\Windows\System32\example-{n:04}.dll"),
        };
        files.push(Found {
            damaged: DAMAGED_IN_USE.contains(&n),
            ..found(
                &path,
                200_000 + n * 7_919,
                (2026, 1 + (n % 10) as u8, 1 + (n % 28) as u8),
                false,
                State::Intact,
            )
        });
    }
    Listing {
        files,
        notes: Vec::new(),
        limit: None,
    }
}

/// The deleted files listed before the files in use.
const DELETED_LISTED: usize = 13;
/// The files in use that read damaged, by their number among them: three pictures.
const DAMAGED_IN_USE: [u64; 3] = [0, 3, 6];

/// What Find good versions found for the damaged pictures in use: copies of two of them.
pub fn good_versions() -> candidates::Search {
    let damaged = |n: u64, versions: Vec<(&str, Kind, bool)>| {
        let name = format!("IMG-{:04}.jpg", 1_000 + n);
        let size = 200_000 + n * 7_919;
        candidates::Damaged {
            file: DELETED_LISTED + n as usize,
            folder: ["Users", "alex", "Pictures", "Camera Roll"]
                .map(String::from)
                .to_vec(),
            path: format!(r"\Users\alex\Pictures\Camera Roll\{name}"),
            size,
            missing: 64 << 10,
            format: Some(Format::Jpeg),
            captured: Some(Capture {
                when: format!("2026:0{}:0{} 1{n}:12:44", 1 + n % 9, 1 + n % 9),
                subsec: None,
            }),
            versions: versions
                .into_iter()
                .enumerate()
                .map(|(i, (path, kind, deleted))| Version {
                    file: DELETED_LISTED + 900 + i,
                    path: format!("{path}\\{name}"),
                    size: if kind == Kind::Lesser { size / 3 } else { size },
                    deleted,
                    kind,
                    format: Some(Format::Jpeg),
                })
                .collect(),
            name,
        }
    };
    candidates::Search {
        damaged: vec![
            damaged(
                0,
                vec![(
                    r"\Users\alex\OneDrive (deleted)\Pictures",
                    Kind::Whole,
                    true,
                )],
            ),
            damaged(
                3,
                vec![
                    (r"\Users\alex\Pictures\Backup", Kind::Near, false),
                    (r"\Users\alex\Pictures\Edited", Kind::Lesser, false),
                ],
            ),
            damaged(6, Vec::new()),
        ],
        stopped: false,
    }
}

/// The deleted files selected in the recover window, by their place in the listing.
pub const RECOVER_CHECKED: [usize; 6] = [0, 1, 2, 5, 7, 9];

/// What the search by type found reading the whole drive, in the order it found them.
pub fn carved() -> Vec<Carved> {
    let kinds = [
        (CarveKind::Jpeg, "jpg", 3_400_000),
        (CarveKind::Jpeg, "jpg", 4_100_000),
        (CarveKind::Pdf, "pdf", 1_250_000),
        (CarveKind::Jpeg, "jpg", 2_900_000),
        (CarveKind::Png, "png", 640_000),
        (CarveKind::Zip, "docx", 31_000),
        (CarveKind::Jpeg, "jpg", 3_800_000),
        (CarveKind::Mp4, "mp4", 212_000_000),
        (CarveKind::Zip, "xlsx", 88_000),
    ];
    (0..63u64)
        .map(|n| {
            let (kind, ext, size) = kinds[(n as usize * 5 + n as usize / 3) % kinds.len()];
            Carved {
                kind,
                ext,
                offset: VOLUME_START + 3 * GIB + n * 9 * GIB + (n * 7_919 % 4_096) * 512,
                len: size + n * 13_337,
                damaged: n % 17 == 5,
            }
        })
        .collect()
}

/// The finds selected in the search by type, by their place in the list.
pub const CARVED_CHECKED: [usize; 4] = [0, 1, 3, 6];

/// How the search by type ended: the whole drive read in 7 h 12 min, with the drive's
/// unreadable areas skipped.
pub fn carve_search() -> ((u64, u64, u64), (usize, u64)) {
    (
        (RECOVERY_SIZE, RECOVERY_SIZE, 7 * 3_600 + 12 * 60),
        (14, 11 * GIB + 3 * MIB),
    )
}

// ---- the rescue copy ---------------------------------------------------------------------

/// The rescue copy of two of alex's folders partway through its first pass.
pub fn rescue_copy() -> crate::rescue_copy_view::Copying {
    let on_drive = |rest: &str| format!(r"{RECOVERY_LETTER}:\Users\alex\{rest}");
    // As the copy says a file with unreadable parts.
    let damaged = |rest: &str, unreadable: u64, len: u64| {
        format!(
            "Damaged: {}  ({} of {} unreadable, written as zeros)",
            on_drive(rest),
            bytes_text(unreadable),
            bytes_text(len)
        )
    };
    crate::rescue_copy_view::Copying {
        sources: vec![
            PathBuf::from(on_drive("Documents")),
            PathBuf::from(on_drive("Pictures")),
        ],
        destination: PathBuf::from(RECOVERED),
        figures: [1, 1_284, 21_406_118_912, 3, 1],
        current: on_drive(r"Pictures\Holiday 2025\Holiday-2025-087.jpg"),
        notes: vec![
            damaged(
                r"Pictures\Holiday 2025\Holiday-2025-003.jpg",
                64 << 10,
                4_506_871,
            ),
            format!(
                "Skipped: {}  (could not be opened, error 32)",
                on_drive(r"Documents\Outlook Files\alex.pst")
            ),
            damaged(
                r"Pictures\Birthday 2025\Birthday-party.mp4",
                1 << 20,
                1_402_331_904,
            ),
            damaged(r"Documents\Taxes-2024.pdf", 4 << 10, 1_284_552),
        ],
        rate: 23_800_000.0,
    }
}
