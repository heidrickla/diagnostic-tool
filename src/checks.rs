//! The ordered registry of read-only checks, their fixed scripts and bounded parsers.
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::events;
use crate::expanded_probes;
use crate::inventory_view;
use crate::runner::{run_process, RunError, COMMAND_TIME, INVENTORY_TIME};

/// How much a finding needs attention: a green check, an amber or a red exclamation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    /// Nothing found that needs a look. A zero count or missing reading never means this.
    Clear,
    /// Problems worth a look.
    Flagged,
    /// A fault: unclean shutdowns, stop errors, hardware, drive, file system or driver failures.
    Serious,
}

/// A completed check. `brief` fits one row of the window; `detail` is the report text.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub brief: String,
    pub detail: String,
    pub grade: Grade,
    /// Structured fields kept for the report; only the hardware inventory fills it.
    pub data: Vec<(String, String)>,
}

impl Finding {
    pub fn new(brief: impl Into<String>, detail: impl Into<String>, flagged: bool) -> Self {
        let grade = if flagged {
            Grade::Flagged
        } else {
            Grade::Clear
        };
        Self::graded(brief, detail, grade)
    }

    pub fn graded(brief: impl Into<String>, detail: impl Into<String>, grade: Grade) -> Self {
        Self {
            brief: brief.into(),
            detail: detail.into(),
            grade,
            data: Vec::new(),
        }
    }

    /// Worth a closer look: flagged or serious.
    pub fn flagged(&self) -> bool {
        self.grade != Grade::Clear
    }

    pub fn serious(&self) -> bool {
        self.grade == Grade::Serious
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Found(Finding),
    /// The check could not produce a reading; the text says why. Never a passing result.
    Unavailable(String),
    Stopped,
}

impl From<RunError> for Outcome {
    fn from(error: RunError) -> Self {
        match error {
            RunError::Cancelled => Outcome::Stopped,
            other => Outcome::Unavailable(other.reason().into()),
        }
    }
}

pub struct CheckSpec {
    pub id: &'static str,
    /// Short plain-language name for the window, the report and screen readers.
    pub label: &'static str,
}

/// Run order after consent. The GUI queue, the report table and the activity log follow it.
pub const CHECKS: [CheckSpec; 13] = [
    CheckSpec {
        id: "os.version",
        label: "Windows version",
    },
    CheckSpec {
        id: "hardware.inventory",
        label: "Hardware inventory",
    },
    CheckSpec {
        id: "disk.free",
        label: "Windows drive space",
    },
    CheckSpec {
        id: "registry.health",
        label: "Restart and crash settings",
    },
    CheckSpec {
        id: "events.recent",
        label: "Recent system events",
    },
    CheckSpec {
        id: "events.crashes",
        label: "App crashes",
    },
    CheckSpec {
        id: "services.failures",
        label: "Service failures",
    },
    CheckSpec {
        id: "updates.local",
        label: "Update history",
    },
    CheckSpec {
        id: "resources.snapshot",
        label: "CPU and memory",
    },
    CheckSpec {
        id: "storage.provider",
        label: "Drive health status",
    },
    CheckSpec {
        id: "hardware.events",
        label: "Hardware and driver events",
    },
    CheckSpec {
        id: "drives.health",
        label: "Drive wear and errors",
    },
    CheckSpec {
        id: "crash.dumps",
        label: "Crash dump readiness",
    },
];

pub fn label(id: &str) -> &'static str {
    CHECKS
        .iter()
        .find(|spec| spec.id == id)
        .map_or("Check", |spec| spec.label)
}

/// The longest row texts any check can produce, for the window's width test.
pub fn widest_briefs() -> Vec<String> {
    let mut briefs = events::widest_briefs();
    briefs.extend(expanded_probes::widest_briefs());
    briefs
}

#[derive(Clone, Copy)]
struct Diagnostic {
    id: &'static str,
    script: &'static str,
}
const CATALOG: [Diagnostic; 3] = [
    Diagnostic {
        id: "os.version",
        script: "[Environment]::OSVersion.Version.ToString()",
    },
    Diagnostic {
        id: "memory.total",
        script: "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)",
    },
    Diagnostic {
        id: "registry.health",
        script: r#"$release=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion; if($null -eq $release){$release='unknown'}; $update=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; $servicing=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; $control=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue; $dump=[string]$control.CrashDumpEnabled; $reboot=[string]$control.AutoReboot; if(!$dump){$dump='unknown'};if(!$reboot){$reboot='unknown'}; 'release='+$release; 'update='+$update; 'servicing='+$servicing; 'crashdump='+$dump; 'autoreboot='+$reboot"#,
    },
];
const INVENTORY_SCRIPT: &str = r#"
function emit($key,$value) { if ($null -ne $value) { $clean = ([string]$value -replace '[\r\n=]', ' ').Trim(); if ($clean.Length -gt 120) { $clean = $clean.Substring(0,120) }; Write-Output ($key + '=' + $clean) } }
emit 'collected_at_utc' ((Get-Date).ToUniversalTime().ToString('o'))
$computer = Get-CimInstance Win32_ComputerSystem
emit 'system.manufacturer' $computer.Manufacturer
emit 'system.model' $computer.Model
$board = Get-CimInstance Win32_BaseBoard
emit 'board.manufacturer' $board.Manufacturer
emit 'board.model' $board.Product
emit 'board.revision' $board.Version
$cpus = @(Get-CimInstance Win32_Processor)
emit 'cpu.model' $cpus[0].Name
emit 'cpu.count' $cpus.Count
emit 'ram.slots_reported' (@(Get-CimInstance Win32_PhysicalMemoryArray) | Measure-Object -Property MemoryDevices -Sum).Sum
$i = 0
Get-CimInstance Win32_PhysicalMemory | Select-Object -First 8 | ForEach-Object { emit ('ram.' + $i + '.capacity_gib') ([math]::Round($_.Capacity/1GB,1)); emit ('ram.' + $i + '.speed_mhz') $_.Speed; emit ('ram.' + $i + '.part') $_.PartNumber; $i++ }
$i = 0
Get-CimInstance Win32_DiskDrive | Select-Object -First 8 | ForEach-Object { emit ('disk.' + $i + '.model') $_.Model; emit ('disk.' + $i + '.interface') $_.InterfaceType; emit ('disk.' + $i + '.capacity_gib') ([math]::Round($_.Size/1GB,1)); $i++ }
$controllers = @(Get-CimInstance Win32_VideoController)
# Physical adapters only: remote and virtual display adapters are not PCI devices.
$display = try { @(Get-PnpDevice -Class Display -ErrorAction Stop) } catch { @($controllers | ForEach-Object { [pscustomobject]@{ FriendlyName = $_.Name; InstanceId = $_.PNPDeviceID; Present = $true; Status = $_.Status } }) }
$display = @($display | Where-Object { ([string]$_.InstanceId).StartsWith('PCI\') } | Sort-Object -Property @{ Expression = { -not $_.Present } } | Select-Object -First 6)
$i = 0; $off = 0
foreach ($device in $display) {
  if (-not $device.Present) { if ($off -lt 2) { emit ('gpu.inactive.' + $off + '.model') $device.FriendlyName; $off++ }; continue }
  if ($i -ge 4) { continue }
  emit ('gpu.' + $i + '.model') $device.FriendlyName
  emit ('gpu.' + $i + '.status') $device.Status
  $vc = $controllers | Where-Object { $_.PNPDeviceID -eq $device.InstanceId } | Select-Object -First 1
  if ($vc) { emit ('gpu.' + $i + '.driver_version') $vc.DriverVersion; if ($vc.DriverDate) { emit ('gpu.' + $i + '.driver_date') $vc.DriverDate.ToString('yyyy-MM-dd') } }
  try { $class = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_Driver -ErrorAction Stop).Data; $bytes = (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $class) -Name 'HardwareInformation.qwMemorySize' -ErrorAction Stop).'HardwareInformation.qwMemorySize'; if ($bytes -gt 0) { emit ('gpu.' + $i + '.memory_gib') ([math]::Round([double]$bytes/1GB,1)) } } catch { }
  $i++
}
$bios = Get-CimInstance Win32_BIOS
emit 'bios.version' $bios.SMBIOSBIOSVersion
"#;

fn catalog(id: &str) -> Option<Diagnostic> {
    CATALOG.iter().copied().find(|d| d.id == id)
}

fn script(id: &str) -> Option<&'static str> {
    catalog(id)
        .map(|item| item.script)
        .or_else(|| (id == "hardware.inventory").then_some(INVENTORY_SCRIPT))
        .or_else(|| expanded_probes::script(id))
}

/// Checks that read through Windows APIs in-process instead of a script.
const IN_PROCESS: [&str; 7] = [
    "disk.free",
    "events.recent",
    "events.crashes",
    "services.failures",
    "hardware.events",
    "drives.health",
    "crash.dumps",
];

/// How long a check may run: the inventory has its own, longer bound.
pub fn check_time(id: &str) -> Duration {
    if id == "hardware.inventory" {
        INVENTORY_TIME
    } else {
        COMMAND_TIME
    }
}

/// Runs one registered check under its deadline, the output cap and job cleanup.
pub fn run_check(id: &str, cancelled: Arc<AtomicBool>) -> Outcome {
    crate::live::reading("a check");
    let deadline = Instant::now() + check_time(id);
    match id {
        "disk.free" => return expanded_probes::drive_space_outcome(expanded_probes::system_drive()),
        "events.recent" => return events::survey(&cancelled, deadline),
        "events.crashes" => return events::app_crashes(&cancelled, deadline),
        "services.failures" => return events::service_failures(&cancelled, deadline),
        "hardware.events" => return events::hardware_events(&cancelled, deadline),
        "drives.health" => return expanded_probes::drive_health(&cancelled, deadline),
        "crash.dumps" => return expanded_probes::crash_readiness(&cancelled, deadline),
        _ => {}
    }
    let Some(script) = script(id) else {
        return Outcome::Unavailable("not a registered check".into());
    };
    let text = match run_process(script, deadline, cancelled) {
        Ok(text) => text,
        Err(error) => return error.into(),
    };
    parse(id, &text)
}

/// Parses a script's output. Output outside the expected fields is unavailable, never a pass.
pub fn parse(id: &str, text: &str) -> Outcome {
    let parsed = match id {
        "os.version" => parse_os_version(text),
        "memory.total" => parse_memory(text),
        "hardware.inventory" => parse_inventory(text)
            .map(inventory_finding)
            .map(Outcome::Found),
        "registry.health" => parse_registry(text),
        _ => expanded_probes::parse(id, text).map_err(|_| RunError::InvalidOutput),
    };
    parsed.unwrap_or_else(Outcome::from)
}

/// Remote catalog entry point. Single-value checks return the bare value the relay
/// protocol validates, the inventory its key=value lines, the rest their report text.
pub fn run_catalog(id: &str, cancelled: Arc<AtomicBool>) -> Result<String, String> {
    if id == "disk.free" {
        return expanded_probes::system_drive().and_then(|drive| drive.free_gib_text());
    }
    if IN_PROCESS.contains(&id) {
        return match run_check(id, cancelled) {
            Outcome::Found(finding) => Ok(finding.detail),
            Outcome::Unavailable(reason) => Err(reason),
            Outcome::Stopped => Err("Canceled".into()),
        };
    }
    let script = script(id).ok_or("command outside catalog")?;
    let text = run_process(script, Instant::now() + check_time(id), cancelled)
        .map_err(|error| format!("{error:?}"))?;
    if matches!(id, "os.version" | "memory.total") {
        return single_value(&text)
            .map(str::to_owned)
            .map_err(|error| format!("{error:?}"));
    }
    match parse(id, &text) {
        Outcome::Found(finding) if id == "hardware.inventory" => Ok(finding
            .data
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect()),
        Outcome::Found(finding) => Ok(finding.detail),
        Outcome::Unavailable(reason) => Err(reason),
        Outcome::Stopped => Err("Canceled".into()),
    }
}

fn single_value(text: &str) -> Result<&str, RunError> {
    let value = text.trim();
    if value.is_empty()
        || value.len() > 80
        || !value.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Err(RunError::InvalidOutput);
    }
    Ok(value)
}

fn parse_os_version(text: &str) -> Result<Outcome, RunError> {
    let version = single_value(text)?;
    let build = version
        .split('.')
        .nth(2)
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or(RunError::InvalidOutput)?;
    let short = version.split('.').take(3).collect::<Vec<_>>().join(".");
    let family = if build >= 22000 {
        "Windows 11"
    } else {
        "Windows 10"
    };
    Ok(Outcome::Found(Finding::new(
        format!("{family} ({short})"),
        format!("Windows version {version} ({family})"),
        false,
    )))
}

fn parse_memory(text: &str) -> Result<Outcome, RunError> {
    let raw = single_value(text)?;
    raw.parse::<f64>().map_err(|_| RunError::InvalidOutput)?;
    Ok(Outcome::Found(Finding::new(
        format!("{raw} GiB"),
        format!("Physical memory reported by Windows: {raw} GiB"),
        false,
    )))
}

pub(crate) fn parse_inventory(text: &str) -> Result<Vec<(String, String)>, RunError> {
    let mut result = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(RunError::InvalidOutput)?;
        let allowed = matches!(
            key,
            "collected_at_utc"
                | "system.manufacturer"
                | "system.model"
                | "board.manufacturer"
                | "board.model"
                | "board.revision"
                | "cpu.model"
                | "cpu.count"
                | "ram.slots_reported"
                | "bios.version"
        ) || (match key.split('.').collect::<Vec<_>>().as_slice() {
            ["ram", index, field] if index.parse::<u8>().is_ok_and(|number| number < 8) => {
                matches!(*field, "capacity_gib" | "speed_mhz" | "part")
            }
            ["disk", index, field] if index.parse::<u8>().is_ok_and(|number| number < 8) => {
                matches!(*field, "model" | "interface" | "capacity_gib")
            }
            ["gpu", index, field] if index.parse::<u8>().is_ok_and(|number| number < 4) => {
                matches!(
                    *field,
                    "model" | "status" | "driver_version" | "driver_date" | "memory_gib"
                )
            }
            ["gpu", "inactive", index, "model"] if index.parse::<u8>().is_ok_and(|n| n < 2) => true,
            _ => false,
        });
        if !allowed || value.len() > 120 || value.chars().any(|c| c.is_control()) {
            return Err(RunError::InvalidOutput);
        }
        result.push((key.to_string(), value.to_string()));
    }
    if result.is_empty() {
        return Err(RunError::InvalidOutput);
    }
    Ok(result)
}

fn inventory_finding(fields: Vec<(String, String)>) -> Finding {
    let memory: f64 = fields
        .iter()
        .filter(|(key, _)| key.starts_with("ram.") && key.ends_with(".capacity_gib"))
        .filter_map(|(_, value)| value.parse::<f64>().ok())
        .sum();
    let drives = fields
        .iter()
        .filter(|(key, _)| key.starts_with("disk.") && key.ends_with(".model"))
        .count();
    let mut parts = Vec::new();
    if memory > 0.0 {
        parts.push(format!("{memory} GiB memory"));
    }
    parts.push(match drives {
        1 => "1 drive".to_string(),
        n => format!("{n} drives"),
    });
    let mut finding = Finding::new(
        parts.join(", "),
        inventory_view::summary(&fields).join("\n"),
        false,
    );
    finding.data = fields;
    finding
}

pub fn collect_inventory(cancelled: Arc<AtomicBool>) -> Result<Vec<(String, String)>, String> {
    match run_check("hardware.inventory", cancelled) {
        Outcome::Found(finding) => Ok(finding.data),
        Outcome::Unavailable(reason) => Err(reason),
        Outcome::Stopped => Err("Canceled".into()),
    }
}

fn key_values<'a>(
    text: &'a str,
    accept: impl Fn(&str) -> Option<usize>,
    extra_chars: &[char],
) -> Result<BTreeMap<&'a str, &'a str>, RunError> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.trim().split_once('=').ok_or(RunError::InvalidOutput)?;
        let max = accept(key).ok_or(RunError::InvalidOutput)?;
        if value.is_empty()
            || value.len() > max
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || extra_chars.contains(&c))
            || values.insert(key, value).is_some()
        {
            return Err(RunError::InvalidOutput);
        }
    }
    Ok(values)
}

fn parse_registry(text: &str) -> Result<Outcome, RunError> {
    const KEYS: [&str; 5] = ["release", "update", "servicing", "crashdump", "autoreboot"];
    let values = key_values(text, |key| KEYS.contains(&key).then_some(24), &[])?;
    let get = |key: &str| values.get(key).copied().ok_or(RunError::InvalidOutput);
    let (release, update, servicing) = (get("release")?, get("update")?, get("servicing")?);
    let (crashdump, autoreboot) = (get("crashdump")?, get("autoreboot")?);
    let flag = |value: &str| match value {
        "True" => Ok(true),
        "False" => Ok(false),
        _ => Err(RunError::InvalidOutput),
    };
    let (update_flag, servicing_flag) = (flag(update)?, flag(servicing)?);
    if crashdump != "unknown" && !crashdump.parse::<u8>().is_ok_and(|value| value <= 7) {
        return Err(RunError::InvalidOutput);
    }
    if !["0", "1", "unknown"].contains(&autoreboot) {
        return Err(RunError::InvalidOutput);
    }
    let pending = update_flag || servicing_flag;
    Ok(Outcome::Found(Finding::new(
        if pending { "Restart pending" } else { "No restart pending" },
        format!("Windows release {release}; update reboot flag {update}; servicing reboot flag {servicing}; crash-dump setting {crashdump}; automatic restart setting {autoreboot} (configuration only)"),
        pending,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inventory_has_its_own_longer_deadline_and_other_checks_keep_theirs() {
        assert_eq!(check_time("hardware.inventory"), INVENTORY_TIME);
        assert!(INVENTORY_TIME >= Duration::from_secs(30));
        assert_eq!(check_time("os.version"), COMMAND_TIME);
        assert_eq!(check_time("drives.health"), COMMAND_TIME);
    }

    fn found(outcome: Outcome) -> Finding {
        match outcome {
            Outcome::Found(finding) => finding,
            other => panic!("expected a finding, got {other:?}"),
        }
    }

    #[test]
    fn registry_ids_are_unique_and_every_check_can_run() {
        let mut ids = std::collections::BTreeSet::new();
        for spec in &CHECKS {
            assert!(ids.insert(spec.id), "duplicate {}", spec.id);
            assert!(
                script(spec.id).is_some() != IN_PROCESS.contains(&spec.id),
                "{} needs exactly one of a script or an in-process reader",
                spec.id
            );
            assert!(!spec.label.is_empty() && !spec.label.contains(": "));
        }
        for id in expanded_probes::IDS {
            assert!(ids.contains(id), "{id} is not queued");
        }
    }

    #[test]
    fn catalog_denies_unlisted_commands() {
        let cancel = Arc::new(AtomicBool::new(false));
        assert_eq!(
            run_catalog("cmd /c whoami", cancel.clone()),
            Err("command outside catalog".into())
        );
        assert!(script("Get-ChildItem C:\\Users").is_none());
        assert!(script("memory.total").is_some());
    }

    #[test]
    fn os_version_names_the_windows_family() {
        assert_eq!(
            found(parse("os.version", "10.0.26300.0\n")).brief,
            "Windows 11 (10.0.26300)"
        );
        assert_eq!(
            found(parse("os.version", "10.0.19045.0")).brief,
            "Windows 10 (10.0.19045)"
        );
        assert!(matches!(
            parse("os.version", "10.0.x"),
            Outcome::Unavailable(_)
        ));
    }

    #[test]
    fn registry_flags_a_pending_restart() {
        let registry = "release=26H2\nupdate=False\nservicing=True\ncrashdump=3\nautoreboot=1\n";
        let finding = found(parse("registry.health", registry));
        assert!(finding.flagged());
        assert_eq!(finding.brief, "Restart pending");
        assert!(finding.detail.contains("servicing reboot flag True"));
        assert!(matches!(
            parse("registry.health", "release=26H2\npath=C:\\Users\n"),
            Outcome::Unavailable(_)
        ));
    }

    #[test]
    fn inventory_parser_accepts_part_fields_and_rejects_serials() {
        let finding = found(parse(
            "hardware.inventory",
            "system.model=Café PC\nram.0.capacity_gib=16\nram.0.part=ABC-123\ndisk.0.model=SSD\n",
        ));
        assert_eq!(finding.data.len(), 4);
        assert_eq!(finding.brief, "16 GiB memory, 1 drive");
        for bad in [
            "system.serial=PRIVATE\n",
            "disk.secret.model=PRIVATE\n",
            "system.model=Bad\nPath\n",
            "",
        ] {
            assert!(
                matches!(parse("hardware.inventory", bad), Outcome::Unavailable(_)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn real_probe_returns_the_windows_version() {
        let finding = found(run_check("os.version", Arc::new(AtomicBool::new(false))));
        assert!(finding.brief.starts_with("Windows 1"));
    }

    #[test]
    fn inventory_probe_reads_minimized_fields() {
        let fields = collect_inventory(Arc::new(AtomicBool::new(false))).unwrap();
        assert!(fields.iter().any(|(key, _)| key == "collected_at_utc"));
        assert!(!fields.iter().any(|(key, _)| key.contains("serial")));
    }

    #[test]
    fn inventory_lists_physical_display_adapters_only() {
        // Over Remote Desktop, Windows lists its virtual adapter first.
        let fields = collect_inventory(Arc::new(AtomicBool::new(false))).unwrap();
        let graphics: Vec<_> = fields
            .iter()
            .filter(|(key, _)| key.starts_with("gpu.") && key.ends_with(".model"))
            .collect();
        assert!(
            graphics
                .iter()
                .all(|(_, model)| !model.contains("Remote Display")
                    && !model.contains("Indirect Display")),
            "{graphics:?}"
        );
    }

    #[test]
    fn display_adapter_fields_parse_and_unknown_ones_do_not() {
        let fields = parse_inventory(
            "gpu.0.model=GPU A\ngpu.0.memory_gib=16\ngpu.0.driver_version=1.2\ngpu.0.driver_date=2026-08-19\ngpu.0.status=OK\ngpu.1.model=GPU B\ngpu.inactive.0.model=iGPU\ncpu.count=2\n",
        )
        .unwrap();
        assert_eq!(fields.len(), 8);
        for bad in [
            "gpu.4.model=X\n",
            "gpu.0.serial=X\n",
            "gpu.inactive.2.model=X\n",
        ] {
            assert!(parse_inventory(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cancelled_checks_report_stopped() {
        for id in [
            "events.recent",
            "events.crashes",
            "services.failures",
            "hardware.events",
            "drives.health",
            "crash.dumps",
        ] {
            assert_eq!(
                run_check(id, Arc::new(AtomicBool::new(true))),
                Outcome::Stopped,
                "{id}"
            );
        }
    }

    /// Runs every in-process check on this PC; `--nocapture` shows each row and its detail.
    #[test]
    fn in_process_checks_finish_on_this_pc_within_the_session_time() {
        let started = Instant::now();
        for id in IN_PROCESS {
            let check = Instant::now();
            let outcome = run_check(id, Arc::new(AtomicBool::new(false)));
            assert!(
                check.elapsed() < COMMAND_TIME + Duration::from_secs(2),
                "{id}"
            );
            match &outcome {
                Outcome::Found(finding) => {
                    assert!(
                        !finding.brief.is_empty() && !finding.detail.is_empty(),
                        "{id}"
                    );
                    println!(
                        "ROW {}: {} [{}] in {:?}\n{}\n",
                        label(id),
                        finding.brief,
                        match finding.grade {
                            Grade::Serious => "serious",
                            Grade::Flagged => "flagged",
                            Grade::Clear => "not flagged",
                        },
                        check.elapsed(),
                        finding.detail
                    );
                }
                Outcome::Unavailable(reason) => {
                    assert!(!reason.is_empty(), "{id}");
                    println!("ROW {}: Unavailable: {reason}\n", label(id));
                }
                Outcome::Stopped => panic!("{id} stopped without being cancelled"),
            }
        }
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn replaced_scripts_are_gone_and_the_remote_value_is_a_bare_number() {
        for id in [
            "disk.free",
            "events.crashes",
            "services.failures",
            "hardware.events",
        ] {
            assert!(script(id).is_none(), "{id} still has a script");
        }
        let value = run_catalog("disk.free", Arc::new(AtomicBool::new(false))).unwrap();
        assert!(single_value(&value).is_ok(), "{value}");
        assert!(value.parse::<f64>().unwrap() > 0.0);
    }

    #[test]
    fn every_row_text_a_check_can_produce_is_listed_for_the_width_test() {
        let briefs = widest_briefs();
        assert!(briefs.iter().any(|brief| brief == "None in 7 days"));
        assert!(briefs.iter().any(|brief| brief.contains("crashes: W")));
        assert!(briefs.iter().any(|brief| brief.contains("GiB free")));
    }
}
