//! Read-only Windows checks outside the event log: fixed scripts that emit small ASCII
//! key/value fields, and in-process readers for the system drive, drive health and crash
//! dump readiness.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::checks::{Finding, Grade, Outcome};
use crate::clock;
use crate::tools::crashes;
use crate::tools::drives::health::{self, Disk, Health};
use crate::tools::drives::{self};

/// Checks whose scripts and parsers live here; `checks::CHECKS` orders and labels them.
pub const IDS: [&str; 3] = ["updates.local", "resources.snapshot", "storage.provider"];

pub fn script(id: &str) -> Option<&'static str> {
    match id {
        "updates.local" => Some(
            r#"
try {
 $searcher=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
 $total=$searcher.GetTotalHistoryCount(); $take=[math]::Min($total,5)
 if($take -eq 0){'status=none';return}
 $items=@($searcher.QueryHistory(0,$take))
 'sampled='+$items.Count
 $failed=@($items|Where-Object { $_.ResultCode -eq 4 -or $_.ResultCode -eq 5 }).Count
 $partial=@($items|Where-Object { $_.ResultCode -eq 3 }).Count
 'failed='+$failed; 'partial='+$partial
 $first=$items[0]
 # WUA IUpdateHistoryEntry.Date is UTC, though COM may marshal it with an
 # Unspecified DateTime kind. ToUniversalTime would wrongly apply local offset.
 $latest=[DateTime]::SpecifyKind([DateTime]$first.Date,[DateTimeKind]::Utc)
 'latest.time='+$latest.ToString('yyyy-MM-ddTHH:mm:ssZ')
 if($latest -gt [DateTime]::UtcNow.AddMinutes(5)){'latest.clock=future'}else{'latest.clock=plausible'}
 'latest.result='+[int]$first.ResultCode
 $kb=[regex]::Match([string]$first.Title,'KB[0-9]{6,8}').Value; if(!$kb){$kb='unknown'}
 'latest.kb='+$kb
} catch { 'status=unavailable' }
"#,
        ),
        "resources.snapshot" => Some(
            r#"
try {
 $cpu=@(Get-CimInstance Win32_Processor -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average)[0].Average
 $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
 $culture=[Globalization.CultureInfo]::InvariantCulture
 'cpu.percent='+([math]::Round($cpu,0)).ToString($culture)
 'memory.free_gib='+([math]::Round($os.FreePhysicalMemory/1MB,1)).ToString('0.0',$culture)
 'memory.total_gib='+([math]::Round($os.TotalVisibleMemorySize/1MB,1)).ToString('0.0',$culture)
 'process.count='+(Get-Process -ErrorAction Stop).Count
} catch { 'status=unavailable' }
"#,
        ),
        "storage.provider" => Some(
            r#"
try {
 $disks=@(Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.BusType -ne 'USB' } | Select-Object -First 8)
 if($disks.Count -eq 0){'status=unavailable';return}
 $healthy=@($disks|Where-Object HealthStatus -eq Healthy).Count
 $flagged=@($disks|Where-Object { $_.HealthStatus -eq 'Warning' -or $_.HealthStatus -eq 'Unhealthy' }).Count
 $unknown=$disks.Count-$healthy-$flagged
 'sampled='+$disks.Count; 'healthy='+$healthy; 'flagged='+$flagged; 'unknown='+$unknown
 $first=$disks|Where-Object { $_.HealthStatus -eq 'Warning' -or $_.HealthStatus -eq 'Unhealthy' }|Select-Object -First 1
 if($first){$name=([string]$first.FriendlyName -replace '[^A-Za-z0-9_.-]','_'); if($name.Length -gt 48){$name=$name.Substring(0,48)}; if(!$name){$name='unknown'}; 'flagged.name='+$name}
} catch { 'status=unavailable' }
"#,
        ),
        _ => None,
    }
}

fn fields(text: &str, allowed: &[&str]) -> Result<BTreeMap<String, String>, &'static str> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.trim().split_once('=').ok_or("malformed output")?;
        if !allowed.contains(&key)
            || value.is_empty()
            || value.len() > 64
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
            || out.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err("malformed output");
        }
    }
    if out.is_empty() {
        return Err("empty output");
    }
    Ok(out)
}

fn number(map: &BTreeMap<String, String>, key: &str, max: u32) -> Result<u32, &'static str> {
    let value = map.get(key).ok_or("missing field")?;
    let result = value.parse::<u32>().map_err(|_| "invalid number")?;
    if result > max {
        return Err("number outside bound");
    }
    Ok(result)
}

fn status(map: &BTreeMap<String, String>) -> Result<Option<&'static str>, &'static str> {
    match map.get("status").map(String::as_str) {
        None => Ok(None),
        Some("none") if map.len() == 1 => Ok(Some("none")),
        Some("unavailable") if map.len() == 1 => Ok(Some("unavailable")),
        _ => Err("invalid status"),
    }
}

pub fn parse(id: &str, text: &str) -> Result<Outcome, &'static str> {
    let allowed: &[&str] = match id {
        "updates.local" => &[
            "status",
            "sampled",
            "failed",
            "partial",
            "latest.time",
            "latest.clock",
            "latest.result",
            "latest.kb",
        ],
        "resources.snapshot" => &[
            "status",
            "cpu.percent",
            "memory.free_gib",
            "memory.total_gib",
            "process.count",
        ],
        "storage.provider" => &[
            "status",
            "sampled",
            "healthy",
            "flagged",
            "unknown",
            "flagged.name",
        ],
        _ => return Err("unknown check"),
    };
    let map = fields(text, allowed)?;
    if let Some(state) = status(&map)? {
        return Ok(match (id, state) {
            (_, "unavailable") => {
                Outcome::Unavailable("Windows did not return this information".into())
            }
            ("updates.local", _) => found(
                "No history returned",
                "No local update-history entries were returned.",
                false,
            ),
            _ => found("No matching records", "No matching records.", false),
        });
    }
    match id {
        "updates.local" => {
            let sampled = number(&map, "sampled", 5)?;
            let failed = number(&map, "failed", sampled)?;
            let partial = number(&map, "partial", sampled)?;
            let time = map.get("latest.time").ok_or("missing time")?;
            let clock = map.get("latest.clock").ok_or("missing clock status")?;
            let result = number(&map, "latest.result", 5)?;
            let kb = map.get("latest.kb").ok_or("missing KB")?;
            if sampled == 0
                || failed + partial > sampled
                || !valid_time(time)
                || !(1..=5).contains(&result)
            {
                return Err("invalid update history");
            }
            if !["future", "plausible"].contains(&clock.as_str()) {
                return Err("invalid clock status");
            }
            let warning = if clock == "future" {
                " The newest timestamp is later than this check; verify clock/timezone metadata before using it as a timeline event."
            } else {
                ""
            };
            Ok(found(
                format!("{sampled} recent, {failed} failed"),
                format!("Local update history: latest {sampled} entries; failed {failed}, partial {partial}; newest recorded {time} UTC, result code {result}, {kb}.{warning} This does not check online availability"),
                failed + partial > 0,
            ))
        }
        "resources.snapshot" => {
            let cpu = number(&map, "cpu.percent", 100)?;
            let processes = number(&map, "process.count", 100000)?;
            let free = decimal(&map, "memory.free_gib", 4096.0)?;
            let total = decimal(&map, "memory.total_gib", 4096.0)?;
            if total <= 0.0 || free > total {
                return Err("invalid memory reading");
            }
            Ok(found(
                format!("CPU {cpu}%, {free:.1} GiB memory free"),
                format!("One-time resource snapshot: CPU {cpu}%, available memory {free:.1}/{total:.1} GiB, {processes} processes. Active workloads may explain transient pressure"),
                false,
            ))
        }
        "storage.provider" => {
            let sampled = number(&map, "sampled", 8)?;
            let healthy = number(&map, "healthy", sampled)?;
            let flagged = number(&map, "flagged", sampled)?;
            let unknown = number(&map, "unknown", sampled)?;
            if sampled == 0 || healthy + flagged + unknown != sampled {
                return Err("invalid storage counts");
            }
            let name = map.get("flagged.name");
            if flagged == 0 && name.is_some() {
                return Err("unexpected flagged device");
            }
            let brief = if flagged > 0 {
                format!("{flagged} of {sampled} need attention")
            } else if unknown > 0 {
                format!("{healthy} of {sampled} reported healthy, {unknown} unknown")
            } else {
                format!("{healthy} of {sampled} reported healthy")
            };
            Ok(Outcome::Found(Finding::graded(
                brief,
                format!("Storage provider status (non-USB, {sampled} sampled): healthy {healthy}, warning/unhealthy {flagged}, unknown {unknown}{}. This is not a full SMART test. Windows storage gives no health status for USB drives; Drive wear and errors reads a USB drive's own SMART data where its adapter passes it", name.map(|v| format!("; first flagged {v}")).unwrap_or_default()),
                if flagged > 0 { Grade::Serious } else { Grade::Clear },
            )))
        }
        _ => Err("unknown check"),
    }
}

fn found(brief: impl Into<String>, detail: impl Into<String>, flagged: bool) -> Outcome {
    Outcome::Found(Finding::new(brief, detail, flagged))
}

fn valid_time(time: &str) -> bool {
    let b = time.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, byte)| !matches!(i, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit())
    {
        return false;
    }
    let part = |start, end| time[start..end].parse::<u32>().unwrap_or(0);
    (1..=12).contains(&part(5, 7))
        && (1..=31).contains(&part(8, 10))
        && part(11, 13) <= 23
        && part(14, 16) <= 59
        && part(17, 19) <= 59
}

fn decimal(map: &BTreeMap<String, String>, key: &str, max: f64) -> Result<f64, &'static str> {
    let value = map
        .get(key)
        .ok_or("missing field")?
        .parse::<f64>()
        .map_err(|_| "invalid decimal")?;
    if !value.is_finite() || !(0.0..=max).contains(&value) {
        return Err("decimal outside bound");
    }
    Ok(value)
}

/// Free space below this on the Windows drive leaves too little room for updates.
const LOW_FREE_GIB: f64 = 20.0;
const LOW_FREE_PERCENT: f64 = 5.0;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// The Windows drive's letter and its free and total bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct DriveSpace {
    pub letter: char,
    /// Free bytes available to the current user.
    pub free: u64,
    pub total: u64,
}

impl DriveSpace {
    pub fn free_gib(&self) -> f64 {
        self.free as f64 / GIB
    }

    pub fn free_percent(&self) -> f64 {
        self.free as f64 * 100.0 / self.total as f64
    }

    /// The bare number the remote catalog returns: GiB free to one decimal.
    pub fn free_gib_text(&self) -> Result<String, String> {
        Ok(format!("{:.1}", self.free_gib()))
    }
}

/// Reads the Windows drive's free and total space in-process. No folder is walked.
pub fn system_drive() -> Result<DriveSpace, String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut folder = [0u16; 260];
    // SAFETY: the buffer is writable for its stated length.
    let length =
        unsafe { GetSystemWindowsDirectoryW(folder.as_mut_ptr(), folder.len() as u32) } as usize;
    let letter = (length >= 3 && length < folder.len())
        .then(|| char::from_u32(u32::from(folder[0])))
        .flatten()
        .filter(char::is_ascii_alphabetic)
        .ok_or("Windows did not name its own folder")?
        .to_ascii_uppercase();
    let root: Vec<u16> = format!("{letter}:\\").encode_utf16().chain([0]).collect();
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: the root is NUL-terminated and the three out pointers are valid.
    let ok = unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, &mut total, &mut total_free) };
    if ok == 0 {
        // SAFETY: reads this thread's last error right after the failed call.
        let code = unsafe { GetLastError() };
        return Err(format!(
            "Windows could not read the size of drive {letter}: (error {code})"
        ));
    }
    Ok(DriveSpace {
        letter,
        free,
        total,
    })
}

/// The "Windows drive space" check: flagged under 20 GiB or under 5 % free. Updates need
/// about 20 GiB; a percentage alone would flag a large drive with plenty of room.
pub fn drive_space_outcome(reading: Result<DriveSpace, String>) -> Outcome {
    let drive = match reading {
        Ok(drive) if drive.total > 0 => drive,
        Ok(drive) => {
            return Outcome::Unavailable(format!(
                "Windows reported drive {}: as 0 bytes in size",
                drive.letter
            ))
        }
        Err(reason) => return Outcome::Unavailable(reason),
    };
    let (free, percent) = (drive.free_gib(), drive.free_percent());
    let (low_gib, low_percent) = (free < LOW_FREE_GIB, percent < LOW_FREE_PERCENT);
    let reading = format!(
        "Windows drive {}: has {free:.1} GiB free of {:.1} GiB ({percent:.1} % free).",
        drive.letter,
        drive.total as f64 / GIB
    );
    let verdict = match (low_gib, low_percent) {
        (true, true) => {
            format!("Flagged: under {LOW_FREE_GIB} GiB and under {LOW_FREE_PERCENT} % free")
        }
        (true, false) => format!("Flagged: under {LOW_FREE_GIB} GiB free"),
        (false, true) => format!("Flagged: under {LOW_FREE_PERCENT} % free"),
        (false, false) => {
            format!("Not flagged: at least {LOW_FREE_GIB} GiB and {LOW_FREE_PERCENT} % free")
        }
    };
    let detail = format!(
        "{reading} {verdict}; Windows updates and apps may fail to install when the drive is that full. Read with GetDiskFreeSpaceEx as free space available to the current user; no folders were walked (toolkit space lists what takes the room)."
    );
    Outcome::Found(Finding::new(
        drive_space_brief(free, percent),
        detail,
        low_gib || low_percent,
    ))
}

fn drive_space_brief(free_gib: f64, percent: f64) -> String {
    // Rounded down, so a drive just under a threshold never shows the threshold itself.
    format!("{free_gib:.1} GiB free ({} %)", percent.floor())
}

/// Drive health from the drives' own data, read by the toolkit's drives tool.
pub fn drive_health(cancelled: &AtomicBool, deadline: Instant) -> Outcome {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(drives::gather(deadline));
    });
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Outcome::Stopped;
        }
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(gathered) => return drive_outcome(&gathered),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Outcome::Unavailable("the drive reader stopped unexpectedly".into())
            }
        }
    }
}

/// A disk with what was read about it and the tool's judgement.
struct DriveView<'a> {
    disk: &'a Disk,
    assessment: health::Assessment,
    /// A USB or removable disk: it often gives no health data (a flash stick, an adapter
    /// that does not pass SMART), so it is listed, and counted only when its data was read.
    external: bool,
}

fn is_external(disk: &Disk) -> bool {
    disk.identity
        .as_ref()
        .is_ok_and(|identity| identity.removable || identity.bus == health::BUS_USB)
}

/// The first thing wrong with a disk, in the fewest words, for the row.
fn headline(view: &DriveView) -> String {
    let disk = view.disk;
    if disk.predicts_failure == Ok(true) {
        return "failure predicted".into();
    }
    if let Health::Nvme(log) = &disk.health {
        if log.critical_warning != 0 {
            return "critical warning".into();
        }
        if log.media_errors > 0 {
            return "media errors".into();
        }
        if log.percentage_used >= 90 {
            return format!("{} % used", log.percentage_used.min(100));
        }
    }
    let count = view.assessment.problems.len();
    format!(
        "{count} {}",
        if count == 1 { "problem" } else { "problems" }
    )
}

/// Orders disks with problems, worst first: predicted failure, warnings, errors, wear.
fn severity(view: &DriveView) -> (bool, bool, bool, bool, usize) {
    let disk = view.disk;
    let (warning, errors, worn) = match &disk.health {
        Health::Nvme(log) => (
            log.critical_warning != 0,
            log.media_errors > 0,
            log.percentage_used >= 90,
        ),
        _ => (false, false, false),
    };
    (
        disk.predicts_failure == Ok(true),
        warning,
        errors,
        worn,
        view.assessment.problems.len(),
    )
}

fn drive_name(disk: &Disk) -> String {
    match &disk.identity {
        Ok(identity) => {
            let name = if identity.vendor.is_empty()
                || identity.model.starts_with(&identity.vendor)
                || identity.vendor.eq_ignore_ascii_case("NVMe")
            {
                identity.model.clone()
            } else {
                format!("{} {}", identity.vendor, identity.model)
            };
            if name.trim().is_empty() {
                "model not reported".into()
            } else {
                name.trim().into()
            }
        }
        Err(why) => format!("not identified ({why})"),
    }
}

/// One disk as one line: what it is, what its own health data says, Windows' prediction
/// and the judgement.
fn drive_line(view: &DriveView) -> String {
    let disk = view.disk;
    let mut what = vec![drive_name(disk)];
    if let Ok(identity) = &disk.identity {
        what.push(health::bus_name(identity.bus).to_string());
    }
    if let Ok(solid) = &disk.solid_state {
        what.push(if *solid { "SSD" } else { "HDD" }.into());
    }
    if let Ok(bytes) = &disk.size {
        what.push(if *bytes == 0 {
            "no media".into()
        } else {
            format!("{:.0} GB", *bytes as f64 / 1e9)
        });
    }
    if !disk.volumes.is_empty() {
        what.push(
            disk.volumes
                .iter()
                .map(|letter| format!("{letter}:"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    let reading = match &disk.health {
        Health::Nvme(log) => {
            let warnings = health::critical_warning_names(log.critical_warning);
            format!(
                "NVMe log: critical warning {}, {} % of rated endurance used, available spare {} % (threshold {} %), {} media and data integrity errors, {} error log entries, {} unsafe shutdowns, {} power-on hours{}",
                if warnings.is_empty() { "none".to_string() } else { warnings.join(" and ") },
                log.percentage_used,
                log.available_spare,
                log.spare_threshold,
                log.media_errors,
                log.error_log_entries,
                log.unsafe_shutdowns,
                log.power_on_hours,
                log.celsius().map_or_else(String::new, |c| format!(", {c} C")),
            )
        }
        Health::Ata(attributes) => {
            let counted: Vec<String> = [5u8, 197, 198, 187]
                .iter()
                .filter_map(|id| {
                    attributes
                        .iter()
                        .find(|a| a.id == *id)
                        .map(|a| format!("{} {}", health::attribute_name(*id), a.raw_value()))
                })
                .collect();
            format!(
                "SMART: {} attributes read{}",
                attributes.len(),
                if counted.is_empty() {
                    String::new()
                } else {
                    format!("; {}", counted.join(", "))
                }
            )
        }
        Health::Unread(why) => format!("health data not read: {why}"),
    };
    let prediction = match &disk.predicts_failure {
        Ok(true) => "Windows predicts failure".to_string(),
        Ok(false) => "Windows predicts no failure".to_string(),
        Err(why) => format!("Windows failure prediction unavailable ({why})"),
    };
    let verdict = if view.assessment.problems.is_empty() {
        if view.assessment.health_read {
            "no problem found".to_string()
        } else {
            "health not known".to_string()
        }
    } else {
        format!("problems: {}", view.assessment.problems.join("; "))
    };
    format!(
        "Disk {} ({}): {reading}; {prediction}; {verdict}.",
        disk.number,
        what.join(", ")
    )
}

pub fn drive_outcome(gathered: &drives::Gathered) -> Outcome {
    let views: Vec<DriveView> = gathered
        .disks
        .iter()
        .map(|disk| DriveView {
            disk,
            assessment: health::assess(disk),
            external: is_external(disk),
        })
        .collect();
    if views.is_empty() {
        return Outcome::Unavailable(if gathered.cut_short {
            "no drive answered within the time limit".into()
        } else {
            "Windows listed no physical disk".into()
        });
    }
    let counted = views
        .iter()
        .filter(|view| !view.external || view.assessment.health_read)
        .count();
    let read = views
        .iter()
        .filter(|view| view.assessment.health_read)
        .count();
    if read == 0 {
        let mut reasons: Vec<&str> = views
            .iter()
            .filter_map(|view| match &view.disk.health {
                Health::Unread(why) => Some(why.as_str()),
                _ => None,
            })
            .collect();
        reasons.sort_unstable();
        reasons.dedup();
        return Outcome::Unavailable(if counted == 0 {
            format!(
                "only USB or removable drives were found, and none gave health data ({})",
                reasons.join("; ")
            )
        } else {
            format!(
                "no fixed drive's own health data could be read ({})",
                reasons.join("; ")
            )
        });
    }
    let mut bad: Vec<&DriveView> = views
        .iter()
        .filter(|view| !view.assessment.problems.is_empty())
        .collect();
    bad.sort_by_key(|view| std::cmp::Reverse(severity(view)));
    let worst_used = views
        .iter()
        .filter_map(|view| match &view.disk.health {
            Health::Nvme(log) => Some((log.percentage_used, view.disk.number)),
            _ => None,
        })
        .max();
    let headlines: Vec<(u32, String)> = bad
        .iter()
        .map(|view| (view.disk.number, headline(view)))
        .collect();
    let brief = drive_brief(
        read,
        counted,
        worst_used.map(|(used, _)| used),
        &headlines,
        gathered.cut_short,
    );
    let mut lines = vec![format!(
        "Drive health from each drive's own data (NVMe health log; SATA SMART attributes where Windows allows, and a USB drive's where its adapter passes them) and Windows' failure prediction, read as the current user ({}). The toolkit's drives tool prints the full log pages.",
        match gathered.elevated {
            Some(true) => "with administrator rights",
            Some(false) => "without administrator rights, which SATA and USB SMART need",
            None => "administrator rights unknown",
        }
    )];
    lines.push(format!(
        "{} physical {} listed; health data read for {read} of {counted} {} (USB and removable drives count when they gave it).",
        views.len(),
        if views.len() == 1 { "disk" } else { "disks" },
        if counted == 1 { "drive" } else { "drives" },
    ));
    for view in &views {
        lines.push(drive_line(view));
    }
    if let Some((used, number)) = worst_used {
        lines.push(format!(
            "Most worn NVMe drive: disk {number}, {used} % of rated endurance used."
        ));
    }
    lines.push(if bad.is_empty() {
        "Not flagged: no disk has a critical warning, media errors, 90 % or more of its endurance used, spare at its threshold, a failing SMART count, a hot reading or a Windows failure prediction.".to_string()
    } else {
        format!(
            "Serious because of {} (rule: any problem the drives tool finds).",
            bad.iter()
                .map(|view| format!("disk {}: {}", view.disk.number, view.assessment.problems.join(", ")))
                .collect::<Vec<_>>()
                .join("; ")
        )
    });
    if read < counted {
        lines.push(format!(
            "{} fixed {} could not be read; that is not a good result for them.",
            counted - read,
            if counted - read == 1 {
                "drive"
            } else {
                "drives"
            }
        ));
    }
    if gathered.cut_short {
        lines.push("Cut short: the drives did not all answer within the time limit; disks after the last one shown were not read.".into());
    }
    let grade = if bad.is_empty() {
        Grade::Clear
    } else {
        Grade::Serious
    };
    Outcome::Found(Finding::graded(brief, lines.join("\n"), grade))
}

/// The window row for drive health.
fn drive_brief(
    read: usize,
    counted: usize,
    worst_used: Option<u8>,
    bad: &[(u32, String)],
    cut_short: bool,
) -> String {
    if let Some((number, what)) = bad.first() {
        return match bad.len() - 1 {
            0 => format!("Disk {number}: {what}"),
            more => format!("Disk {number}: {what}, {more} more"),
        };
    }
    let reads = if read == counted {
        format!("{read} read")
    } else {
        format!("{read} of {counted} read")
    };
    if cut_short {
        return format!("{reads}, cut short");
    }
    match worst_used {
        Some(used) => format!("{reads}, worst {} % used", used.min(100)),
        None => format!("{reads}, no problem"),
    }
}

/// Days of the System log the crash dump readiness check reads.
const READINESS_DAYS: u64 = 30;

/// The "Crash dump readiness" check: stop events, unclean restarts and crash dump setup
/// failures, read by the toolkit's crashes tool.
pub fn crash_readiness(cancelled: &AtomicBool, deadline: Instant) -> Outcome {
    if cancelled.load(Ordering::Relaxed) {
        return Outcome::Stopped;
    }
    match crashes::read_event_log(READINESS_DAYS, deadline) {
        Ok(reading) => readiness_outcome(&reading),
        Err(reason) => Outcome::Unavailable(reason),
    }
}

pub(crate) fn readiness_outcome(reading: &crashes::EventReading) -> Outcome {
    if reading.reads.iter().all(|read| read.unavailable.is_some()) {
        let reasons: Vec<_> = reading
            .reads
            .iter()
            .map(|read| {
                format!(
                    "{}: {}",
                    read.log,
                    read.unavailable.as_deref().unwrap_or("unread")
                )
            })
            .collect();
        return Outcome::Unavailable(format!(
            "the event log could not be read ({})",
            reasons.join("; ")
        ));
    }
    let (stops, restarts, failures) = (
        reading.stops.len(),
        reading.restarts.len(),
        reading.dump_failures.len(),
    );
    let mut reasons = Vec::new();
    if stops > 0 {
        reasons.push(format!(
            "{stops} stop {}",
            if stops == 1 { "event" } else { "events" }
        ));
    }
    if failures > 0 {
        reasons.push(format!(
            "{failures} crash dump setup {}",
            if failures == 1 { "failure" } else { "failures" }
        ));
    }
    if restarts > 0 {
        reasons.push(format!(
            "{restarts} unclean {}",
            if restarts == 1 { "restart" } else { "restarts" }
        ));
    }
    let mut lines = vec![format!(
        "System log, past {READINESS_DAYS} days: stop events (WER-SystemErrorReporting 1001, a blue screen recorded at the next start), unclean restarts (Kernel-Power 41) and crash dump setup failures (volmgr 45, 46, 161)."
    )];
    if let Some(newest) = reading.stops.iter().max_by_key(|stop| stop.time) {
        let code = newest.stop.map_or_else(
            || "its text could not be read".to_string(),
            |(code, _)| match crashes::codes::find(code) {
                Some(known) => format!("stop code 0x{code:08X} {}", known.name),
                None => format!("stop code 0x{code:08X}"),
            },
        );
        lines.push(format!(
            "Newest stop event: {}, {code}.",
            clock::local(newest.time).long()
        ));
    }
    crashes::describe_events(reading, READINESS_DAYS, &mut lines);
    if failures == 0 {
        lines.push(format!(
            "Crash dump setup failures (volmgr 45, 46, 161): none in the past {READINESS_DAYS} days."
        ));
    }
    let grade = if stops > 0 || restarts > 0 {
        Grade::Serious
    } else if failures > 0 {
        Grade::Flagged
    } else {
        Grade::Clear
    };
    let rule = "rule: a stop event or an unclean restart is serious, a crash dump setup failure is flagged";
    lines.push(match grade {
        Grade::Serious if stops == 0 && restarts == 1 => format!(
            "Serious because of {} ({rule}); one unclean restart alone can be a power cut.",
            reasons.join("; ")
        ),
        Grade::Serious => format!("Serious because of {} ({rule}).", reasons.join("; ")),
        Grade::Flagged => format!("Flagged because of {} ({rule}).", reasons.join("; ")),
        Grade::Clear => {
            "Not flagged: no stop event, unclean restart or crash dump setup failure.".to_string()
        }
    });
    lines.push("Dump files and the page file were not examined here; toolkit crashes lists the dump files and the drivers they name (dump folders usually need administrator rights).".into());
    Outcome::Found(Finding::graded(
        readiness_brief(stops, restarts, failures),
        lines.join("\n"),
        grade,
    ))
}

/// The window row for crash dump readiness.
fn readiness_brief(stops: usize, restarts: usize, failures: usize) -> String {
    let count = |n: usize| {
        if n > 99 {
            "99+".to_string()
        } else {
            n.to_string()
        }
    };
    let mut parts = Vec::new();
    if failures > 0 {
        parts.push("Dump setup failed".to_string());
    }
    if stops > 0 {
        parts.push(format!(
            "{} {}",
            count(stops),
            match (failures > 0, stops) {
                (true, _) => "stops",
                (false, 1) => "blue screen",
                (false, _) => "blue screens",
            }
        ));
    }
    if restarts > 0 {
        parts.push(format!(
            "{} {}",
            count(restarts),
            match (stops > 0 || failures > 0, restarts) {
                (true, _) => "restarts",
                (false, 1) => "unclean restart",
                (false, _) => "unclean restarts",
            }
        ));
    }
    if parts.is_empty() {
        return format!("None in {READINESS_DAYS} days");
    }
    // The short form leaves room in the row for the counts.
    if failures > 0 && parts.len() > 1 {
        parts[0] = "Dump failed".to_string();
    }
    parts.join(", ")
}

/// The longest row texts of the checks in this module, for the window's width test.
pub fn widest_briefs() -> Vec<String> {
    let mut briefs = vec![
        drive_space_brief(99999.9, 100.0),
        drive_space_brief(0.0, 0.0),
        readiness_brief(0, 0, 0),
    ];
    for count in [1, 2, 99, 100] {
        for (stops, restarts, failures) in [
            (count, 0, 0),
            (0, count, 0),
            (count, count, 0),
            (0, 0, count),
            (count, 0, count),
            (0, count, count),
            (count, count, count),
        ] {
            briefs.push(readiness_brief(stops, restarts, failures));
        }
    }
    let bad = |n: usize, what: &str| -> Vec<(u32, String)> {
        (0..n)
            .map(|i| (31 - i as u32 % 2, what.to_string()))
            .collect()
    };
    for what in [
        "failure predicted",
        "critical warning",
        "media errors",
        "100 % used",
        "99 problems",
    ] {
        briefs.push(drive_brief(0, 0, None, &bad(1, what), false));
        briefs.push(drive_brief(0, 0, None, &bad(31, what), false));
    }
    briefs.push(drive_brief(31, 31, Some(100), &[], false));
    briefs.push(drive_brief(30, 31, Some(100), &[], false));
    briefs.push(drive_brief(30, 31, None, &[], true));
    briefs.push(drive_brief(31, 31, None, &[], false));
    briefs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::LogRead;
    use crate::tools::drives::health::fixtures;
    use std::time::SystemTime;

    fn finding(id: &str, text: &str) -> Finding {
        match parse(id, text) {
            Ok(Outcome::Found(finding)) => finding,
            other => panic!("expected a finding, got {other:?}"),
        }
    }

    #[test]
    fn every_id_has_a_script() {
        for id in IDS {
            assert!(script(id).is_some(), "{id}");
        }
    }

    #[test]
    fn resource_snapshot_does_not_infer_fault_from_single_sample() {
        let text =
            "cpu.percent=95\nmemory.free_gib=2.0\nmemory.total_gib=32.0\nprocess.count=200\n";
        let result = finding("resources.snapshot", text);
        assert!(result.detail.contains("Active workloads may explain"));
        assert!(!result.flagged());
        assert!(parse(
            "resources.snapshot",
            &text.replace("cpu.percent=95", "cpu.percent=101")
        )
        .is_err());
    }

    #[test]
    fn missing_permissions_and_malformed_output_stay_unavailable() {
        assert!(matches!(
            parse("storage.provider", "status=unavailable\n"),
            Ok(Outcome::Unavailable(_))
        ));
        assert!(parse("storage.provider", "sampled=3\nsecret=token\n").is_err());
        let storage = finding(
            "storage.provider",
            "sampled=3\nhealthy=3\nflagged=0\nunknown=0\n",
        );
        assert!(storage.detail.contains("not a full SMART test"));
        assert_eq!(storage.brief, "3 of 3 reported healthy");
        assert_eq!(storage.grade, Grade::Clear);
        let unhealthy = finding(
            "storage.provider",
            "sampled=3\nhealthy=2\nflagged=1\nunknown=0\nflagged.name=Disk1\n",
        );
        assert_eq!(unhealthy.brief, "1 of 3 need attention");
        assert_eq!(unhealthy.grade, Grade::Serious);
    }

    #[test]
    fn update_history_distinguishes_failed_and_partial() {
        let text = "sampled=3\nfailed=1\npartial=1\nlatest.time=2026-11-01T20:00:00Z\nlatest.clock=plausible\nlatest.result=4\nlatest.kb=KB1234567\n";
        let result = finding("updates.local", text);
        assert!(result.detail.contains("failed 1, partial 1"));
        assert!(result.flagged());
        assert!(
            finding("updates.local", &text.replace("plausible", "future"))
                .detail
                .contains("later than this check")
        );
        assert!(parse("updates.local", &text.replace("failed=1", "failed=4")).is_err());
    }

    #[test]
    fn update_history_preserves_utc_source_across_dst_boundary() {
        let script = script("updates.local").unwrap();
        assert!(script.contains("SpecifyKind([DateTime]$first.Date,[DateTimeKind]::Utc)"));
        assert!(!script.contains("$first.Date.ToUniversalTime()"));
        for source_utc in [
            "2026-11-01T05:59:00Z",
            "2026-11-01T06:01:00Z",
            "2026-11-01T07:01:00Z",
        ] {
            let text = format!("sampled=1\nfailed=0\npartial=0\nlatest.time={source_utc}\nlatest.clock=plausible\nlatest.result=2\nlatest.kb=KB1234567\n");
            assert!(finding("updates.local", &text).detail.contains(source_utc));
        }
    }

    fn space(free_gib: f64, total_gib: f64) -> Result<DriveSpace, String> {
        Ok(DriveSpace {
            letter: 'C',
            free: (free_gib * GIB) as u64,
            total: (total_gib * GIB) as u64,
        })
    }

    fn found_outcome(outcome: Outcome) -> Finding {
        match outcome {
            Outcome::Found(finding) => finding,
            other => panic!("expected a finding, got {other:?}"),
        }
    }

    #[test]
    fn drive_space_is_flagged_under_20_gib_or_under_5_percent() {
        let roomy = found_outcome(drive_space_outcome(space(212.4, 465.2)));
        assert!(!roomy.flagged());
        assert_eq!(roomy.brief, "212.4 GiB free (45 %)");
        assert!(roomy
            .detail
            .contains("212.4 GiB free of 465.2 GiB (45.7 % free)"));
        assert!(roomy.detail.contains("Not flagged"));
        let small = found_outcome(drive_space_outcome(space(4.2, 20.0)));
        assert!(small.flagged());
        assert!(small.detail.contains("Flagged: under 20 GiB free"));
        let crowded = found_outcome(drive_space_outcome(space(40.0, 1000.0)));
        assert!(crowded.flagged(), "4 % free is low even with 40 GiB");
        assert!(crowded.detail.contains("Flagged: under 5 % free"));
        let both = found_outcome(drive_space_outcome(space(1.0, 50.0)));
        assert!(both.detail.contains("under 20 GiB and under 5 % free"));
        let edge = found_outcome(drive_space_outcome(space(20.0, 400.0)));
        assert!(
            !edge.flagged(),
            "exactly 20 GiB and 5 % is not under either"
        );
        let large = found_outcome(drive_space_outcome(space(185.9, 1863.0)));
        assert!(!large.flagged(), "186 GiB free on a large drive is plenty");
        assert_eq!(
            large.brief, "185.9 GiB free (9 %)",
            "rounded down, never up to a threshold"
        );
    }

    #[test]
    fn drive_space_that_cannot_be_read_is_unavailable_with_its_reason() {
        assert_eq!(
            drive_space_outcome(Err(
                "Windows could not read the size of drive C: (error 5)".into()
            )),
            Outcome::Unavailable("Windows could not read the size of drive C: (error 5)".into())
        );
        assert!(matches!(
            drive_space_outcome(space(0.0, 0.0)),
            Outcome::Unavailable(reason) if reason.contains("0 bytes")
        ));
        assert_eq!(
            space(212.44, 465.0).unwrap().free_gib_text().unwrap(),
            "212.4"
        );
    }

    #[test]
    fn the_windows_drive_is_read_in_process() {
        let drive = system_drive().expect("this PC has a Windows drive");
        assert!(drive.letter.is_ascii_uppercase());
        assert!(drive.total > 0 && drive.free <= drive.total);
        let finding = found_outcome(drive_space_outcome(Ok(drive)));
        assert!(finding.brief.contains("GiB free"));
    }

    fn nvme(bytes: Vec<u8>, number: u32) -> Disk {
        let mut disk = fixtures::disk(Health::Nvme(health::parse_nvme_health(&bytes).unwrap()));
        disk.number = number;
        disk
    }

    fn gathered(disks: Vec<Disk>, cut_short: bool) -> drives::Gathered {
        drives::Gathered {
            elevated: Some(false),
            disks,
            cut_short,
        }
    }

    #[test]
    fn healthy_drives_show_the_worst_wear_and_are_not_flagged() {
        let mut usb = fixtures::disk(Health::Unread("this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)".into()));
        usb.number = 2;
        usb.identity.as_mut().unwrap().bus = health::BUS_USB;
        usb.identity.as_mut().unwrap().removable = true;
        let finding = found_outcome(drive_outcome(&gathered(
            vec![
                nvme(fixtures::healthy_nvme(), 0),
                nvme(fixtures::healthy_nvme(), 1),
                usb,
            ],
            false,
        )));
        assert_eq!(finding.brief, "2 read, worst 3 % used");
        assert!(!finding.flagged());
        assert!(finding
            .detail
            .contains("Disk 0 (Example SSD 1TB, NVMe, SSD, 1000 GB, C:)"));
        assert!(finding.detail.contains("3 % of rated endurance used"));
        assert!(finding.detail.contains("0 media and data integrity errors"));
        assert!(finding.detail.contains("Disk 2 (Example SSD 1TB, USB"));
        assert!(finding
            .detail
            .contains("health data not read: this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)"));
        assert!(finding.detail.contains("Not flagged"));
    }

    /// A USB drive whose adapter passed its SMART data counts as read; one whose adapter did
    /// not is listed and not counted as missing.
    #[test]
    fn a_usb_drive_whose_smart_was_read_counts() {
        let mut read = fixtures::disk(Health::Ata(
            health::parse_smart_attributes(&fixtures::healthy_smart()).unwrap(),
        ));
        read.number = 3;
        read.identity.as_mut().unwrap().bus = health::BUS_USB;
        let mut stick = fixtures::disk(Health::Unread(
            "this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)".into(),
        ));
        stick.number = 4;
        stick.identity.as_mut().unwrap().bus = health::BUS_USB;
        stick.identity.as_mut().unwrap().removable = true;
        let finding = found_outcome(drive_outcome(&gathered(
            vec![nvme(fixtures::healthy_nvme(), 0), read, stick.clone()],
            false,
        )));
        assert!(finding.brief.starts_with("2 read"), "{}", finding.brief);
        assert!(finding
            .detail
            .contains("health data read for 2 of 2 drives"));
        assert!(finding.detail.contains("Disk 3 (Example SSD 1TB, USB"));
        assert!(!finding.detail.contains("could not be read"));
        // Only the stick: unavailable, and said so.
        assert!(matches!(
            drive_outcome(&gathered(vec![stick], false)),
            Outcome::Unavailable(why) if why.starts_with("only USB or removable drives were found")
        ));
    }

    #[test]
    fn a_worn_drive_with_media_errors_is_flagged_by_name_and_reading() {
        let finding = found_outcome(drive_outcome(&gathered(
            vec![
                nvme(fixtures::healthy_nvme(), 0),
                nvme(fixtures::worn_nvme(), 1),
            ],
            false,
        )));
        assert_eq!(finding.brief, "Disk 1: media errors");
        assert_eq!(finding.grade, Grade::Serious);
        assert!(finding
            .detail
            .contains("37 media and data integrity errors"));
        assert!(finding
            .detail
            .contains("95 % of the rated endurance is used"));
        assert!(finding.detail.contains("Serious because of disk 1"));
        assert!(finding
            .detail
            .contains("Most worn NVMe drive: disk 1, 95 %"));
        let critical = found_outcome(drive_outcome(&gathered(
            vec![
                nvme(fixtures::critical_nvme(), 3),
                nvme(fixtures::worn_nvme(), 1),
            ],
            false,
        )));
        assert_eq!(critical.brief, "Disk 3: critical warning, 1 more");
        let mut predicted = nvme(fixtures::healthy_nvme(), 4);
        predicted.predicts_failure = Ok(true);
        let predicted = found_outcome(drive_outcome(&gathered(vec![predicted], false)));
        assert_eq!(predicted.brief, "Disk 4: failure predicted");
        assert_eq!(predicted.grade, Grade::Serious);
    }

    #[test]
    fn sata_drives_without_administrator_rights_are_unavailable_not_healthy() {
        let mut sata = fixtures::disk(Health::Unread(
            "SMART attributes need administrator rights".into(),
        ));
        sata.identity.as_mut().unwrap().bus = health::BUS_SATA;
        let outcome = drive_outcome(&gathered(vec![sata.clone()], false));
        assert_eq!(
            outcome,
            Outcome::Unavailable("no fixed drive's own health data could be read (SMART attributes need administrator rights)".into())
        );
        let mixed = found_outcome(drive_outcome(&gathered(
            vec![nvme(fixtures::healthy_nvme(), 0), sata],
            false,
        )));
        assert_eq!(mixed.brief, "1 of 2 read, worst 3 % used");
        assert!(!mixed.flagged());
        assert!(mixed.detail.contains("1 fixed drive could not be read"));
        assert!(matches!(
            drive_outcome(&gathered(Vec::new(), false)),
            Outcome::Unavailable(reason) if reason.contains("no physical disk")
        ));
        assert!(matches!(
            drive_outcome(&gathered(Vec::new(), true)),
            Outcome::Unavailable(reason) if reason.contains("time limit")
        ));
    }

    #[test]
    fn sata_counts_and_a_cut_short_read_are_reported() {
        let sata = SataFixture::pending();
        let finding = found_outcome(drive_outcome(&gathered(vec![sata], true)));
        assert!(finding.flagged());
        assert_eq!(finding.brief, "Disk 0: 3 problems");
        assert!(finding.detail.contains("current pending sectors 8"));
        assert!(finding.detail.contains("Cut short"));
        let cut = found_outcome(drive_outcome(&gathered(
            vec![nvme(fixtures::healthy_nvme(), 0)],
            true,
        )));
        assert_eq!(cut.brief, "1 read, cut short");
    }

    struct SataFixture;

    impl SataFixture {
        fn pending() -> Disk {
            let mut disk = fixtures::disk(Health::Ata(
                health::parse_smart_attributes(&fixtures::pending_smart()).unwrap(),
            ));
            disk.identity.as_mut().unwrap().bus = health::BUS_SATA;
            disk
        }
    }

    #[test]
    fn drive_health_stops_when_cancelled() {
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            drive_health(&cancelled, Instant::now() + Duration::from_secs(12)),
            Outcome::Stopped
        );
    }

    fn stop(seconds_ago: u64, code: Option<u32>) -> crashes::StopEvent {
        crashes::StopEvent {
            time: SystemTime::now() - Duration::from_secs(seconds_ago),
            stop: code.map(|code| (code, [0; 4])),
            path: None,
        }
    }

    fn reading(
        stops: Vec<crashes::StopEvent>,
        restarts: usize,
        failures: usize,
    ) -> crashes::EventReading {
        let at = |index: usize| SystemTime::now() - Duration::from_secs(3600 * (index as u64 + 1));
        crashes::EventReading {
            days: 30,
            stops,
            restarts: (0..restarts).map(at).collect(),
            dump_failures: (0..failures).map(at).collect(),
            reads: vec![LogRead {
                log: "System".into(),
                events: 7,
                unreadable: 0,
                limit: None,
                unavailable: None,
            }],
        }
    }

    #[test]
    fn a_quiet_month_is_clear_and_one_unclean_restart_is_serious() {
        let quiet = found_outcome(readiness_outcome(&reading(Vec::new(), 0, 0)));
        assert_eq!(quiet.brief, "None in 30 days");
        assert_eq!(quiet.grade, Grade::Clear);
        assert!(quiet
            .detail
            .contains("Crash dump setup failures (volmgr 45, 46, 161): none"));
        assert!(quiet
            .detail
            .contains("Stop events (1001) in the past 30 days: 0."));
        let once = found_outcome(readiness_outcome(&reading(Vec::new(), 1, 0)));
        assert_eq!(once.brief, "1 unclean restart");
        assert_eq!(once.grade, Grade::Serious);
        assert!(once
            .detail
            .contains("one unclean restart alone can be a power cut"));
    }

    #[test]
    fn stops_and_restarts_are_serious_and_failed_dumps_are_flagged_with_the_reading() {
        let stops = found_outcome(readiness_outcome(&reading(
            vec![stop(7200, Some(0x116)), stop(86_400, None)],
            3,
            0,
        )));
        assert_eq!(stops.brief, "2 blue screens, 3 restarts");
        assert_eq!(stops.grade, Grade::Serious);
        assert!(stops
            .detail
            .contains("stop code 0x00000116 VIDEO_TDR_FAILURE"));
        assert!(stops
            .detail
            .contains("Unclean restarts (Kernel-Power 41) in the past 30 days: 3"));
        assert!(stops
            .detail
            .contains("Serious because of 2 stop events; 3 unclean restarts"));
        let dumps = found_outcome(readiness_outcome(&reading(Vec::new(), 0, 4)));
        assert_eq!(dumps.brief, "Dump setup failed");
        assert_eq!(dumps.grade, Grade::Flagged);
        assert!(dumps
            .detail
            .contains("Crash dump setup failed (volmgr 45, 46 or 161) 4 times"));
        assert_eq!(readiness_brief(2, 5, 1), "Dump failed, 2 stops, 5 restarts");
        assert_eq!(readiness_brief(0, 2, 0), "2 unclean restarts");
        let twice = found_outcome(readiness_outcome(&reading(Vec::new(), 2, 0)));
        assert_eq!(twice.grade, Grade::Serious);
    }

    #[test]
    fn an_unreadable_system_log_is_unavailable_with_its_reason() {
        let mut denied = reading(Vec::new(), 0, 0);
        denied.reads[0].unavailable = Some("this account may not read it".into());
        assert_eq!(
            readiness_outcome(&denied),
            Outcome::Unavailable(
                "the event log could not be read (System: this account may not read it)".into()
            )
        );
        let mut capped = reading(Vec::new(), 1, 0);
        capped.reads[0].limit = Some(crate::events::Limit::Count);
        assert!(found_outcome(readiness_outcome(&capped))
            .detail
            .contains("System: newest 7 events read; older ones were not."));
        assert_eq!(
            crash_readiness(&AtomicBool::new(true), Instant::now()),
            Outcome::Stopped
        );
    }

    #[test]
    fn crash_dump_readiness_reads_this_pcs_log() {
        let outcome = crash_readiness(
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(12),
        );
        let finding = found_outcome(outcome);
        assert!(finding
            .detail
            .contains("Unclean restarts (Kernel-Power 41)"));
    }

    #[test]
    fn every_listed_brief_is_short_and_plain() {
        let briefs = widest_briefs();
        assert!(briefs.len() > 30);
        for brief in &briefs {
            assert!(brief.chars().count() <= 40, "{brief:?}");
            assert!(brief.is_ascii(), "{brief:?}");
        }
    }
}
