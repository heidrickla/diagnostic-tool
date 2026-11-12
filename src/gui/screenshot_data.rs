//! Made-up readings for the screenshot mode: a PC named DESKTOP-EXAMPLE used by alex, with
//! ordinary part names and serials like EX0123456789. Each value goes through the parser or
//! outcome builder a live reading would, and nothing here reads this PC.
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use diagnostics::checks::{self, Finding, Outcome};
use diagnostics::event_list::{self, Loaded, PartRead};
use diagnostics::events::{self, CategoryRead, Event, LogRead, Query, WithData, HARDWARE};
use diagnostics::expanded_probes::{self, DriveSpace};
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
    Disk, Health, Identity, NvmeHealth, Temperature, BUS_NVME,
};
use diagnostics::tools::drives::Gathered;
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
