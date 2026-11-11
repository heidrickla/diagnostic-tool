//! Pure parsing and judging for the drive tool window: the partition table, the PCIe link,
//! NVMe identify data and self-test log, the full health table in plain language, the
//! dashboard figures and the verdict. No Win32 calls here.
use super::health::{self, u32_at, u64_at, Attribute, Disk, Health, NvmeHealth};

/// What the drive window reads beyond the health log. Each `Err` holds why it is missing.
#[derive(Debug, Clone, PartialEq)]
pub struct Details {
    pub link: Result<Link, String>,
    pub layout: Result<Layout, String>,
    pub volumes: Vec<Volume>,
    /// The drive says it accepts TRIM (DEVICE_TRIM_DESCRIPTOR).
    pub trim: Result<bool, String>,
    /// Windows sends TRIM on NTFS (DisableDeleteNotification is 0 or absent).
    pub windows_trim: Result<bool, String>,
    pub identify: Result<NvmeIdentify, String>,
    pub self_test: Result<SelfTestLog, String>,
}

impl Details {
    /// Every reading missing for the same reason, for a disk that could not be read.
    pub fn unread(why: &str) -> Self {
        Self {
            link: Err(why.into()),
            layout: Err(why.into()),
            volumes: Vec::new(),
            trim: Err(why.into()),
            windows_trim: Err(why.into()),
            identify: Err(why.into()),
            self_test: Err(why.into()),
        }
    }
}

// ---- the PCIe link ---------------------------------------------------------------------

/// The PCIe link of an NVMe drive's controller, from the device's PCI properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// Link speed codes as in the PCIe Link Status register: 1 is 2.5 GT/s (PCIe 1.0).
    pub speed: Option<u32>,
    pub width: Option<u32>,
    pub max_speed: Option<u32>,
    pub max_width: Option<u32>,
}

/// The PCIe generation for a link speed code.
pub fn pcie_generation(code: u32) -> Option<&'static str> {
    Some(match code {
        1 => "1.0",
        2 => "2.0",
        3 => "3.0",
        4 => "4.0",
        5 => "5.0",
        6 => "6.0",
        _ => return None,
    })
}

/// "PCIe 4.0 x4", with the drive's own maximum when the link runs below it.
pub fn link_text(link: &Link) -> String {
    let part = |speed: Option<u32>, width: Option<u32>| match (
        speed.and_then(pcie_generation),
        width.filter(|w| *w > 0),
    ) {
        (Some(generation), Some(width)) => Some(format!("PCIe {generation} x{width}")),
        (Some(generation), None) => Some(format!("PCIe {generation}")),
        (None, Some(width)) => Some(format!("PCIe x{width}")),
        (None, None) => None,
    };
    let now = part(link.speed, link.width);
    let max = part(link.max_speed, link.max_width);
    match (now, max) {
        (Some(now), Some(max)) if now != max => format!("{now} (the drive can do {max})"),
        (Some(now), _) => now,
        (None, Some(max)) => format!("current link not reported; the drive can do {max}"),
        (None, None) => "not reported".into(),
    }
}

/// True when the link runs slower or narrower than the drive allows.
pub fn link_below_max(link: &Link) -> bool {
    matches!((link.speed, link.max_speed), (Some(now), Some(max)) if now < max)
        || matches!((link.width, link.max_width), (Some(now), Some(max)) if now < max)
}

// ---- partitions ----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Mbr,
    Gpt,
    Raw,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Partition {
    pub number: u32,
    pub offset: u64,
    pub length: u64,
    /// What the partition is for, in plain words.
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    pub style: Style,
    pub partitions: Vec<Partition>,
}

/// A lettered volume with a part on this disk.
#[derive(Debug, Clone, PartialEq)]
pub struct Volume {
    pub letter: char,
    /// Where its parts start on this disk, in bytes.
    pub offsets: Vec<u64>,
    /// Other disks the volume also lies on (spanned, striped or mirrored).
    pub other_disks: Vec<u32>,
    pub space: Result<(u64, u64), String>,
    pub file_system: Result<String, String>,
}

/// DRIVE_LAYOUT_INFORMATION_EX header size and PARTITION_INFORMATION_EX entry size.
pub const LAYOUT_HEADER: usize = 48;
pub const PARTITION_ENTRY: usize = 144;

/// A GUID as stored (Data1 to Data3 little-endian), in its usual text form.
pub fn guid_text(bytes: &[u8]) -> Option<String> {
    let b: &[u8; 16] = bytes.get(..16)?.try_into().ok()?;
    Some(format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

pub fn gpt_kind(guid: &str) -> &'static str {
    match guid {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI system",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "basic data",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
        "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3" => "dynamic disk metadata",
        "AF9B60A0-1431-4F62-BC68-3311714A69AD" => "dynamic disk data",
        "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D" => "Storage Spaces",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux file system",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        _ => "other",
    }
}

pub fn mbr_kind(code: u8) -> &'static str {
    match code {
        0x07 => "NTFS or exFAT",
        0x0B | 0x0C => "FAT32",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x05 | 0x0F => "extended",
        0x27 => "Windows recovery",
        0x42 => "dynamic disk",
        0x82 => "Linux swap",
        0x83 => "Linux file system",
        0xEE => "GPT protective",
        0xEF => "EFI system",
        _ => "other",
    }
}

/// IOCTL_DISK_GET_DRIVE_LAYOUT_EX: style and count at 0 and 4, entries from 48. An entry has
/// the starting offset at 8, length at 16, number at 24, then the MBR type byte or the GPT
/// type GUID at 32. Unused MBR slots (type 0, length 0) are skipped.
pub fn parse_layout(buf: &[u8]) -> Option<Layout> {
    let style = match u32_at(buf, 0)? {
        0 => Style::Mbr,
        1 => Style::Gpt,
        2 => Style::Raw,
        _ => return None,
    };
    let count = u32_at(buf, 4)? as usize;
    let mut partitions = Vec::new();
    for index in 0..count.min(256) {
        let at = LAYOUT_HEADER + index * PARTITION_ENTRY;
        let Some(entry) = buf.get(at..at + PARTITION_ENTRY) else {
            break;
        };
        let length = u64_at(entry, 16)?;
        let kind = match u32_at(entry, 0)? {
            0 => {
                if entry[32] == 0 || length == 0 {
                    continue;
                }
                mbr_kind(entry[32]).to_string()
            }
            1 => gpt_kind(&guid_text(&entry[32..48])?).to_string(),
            _ => "other".into(),
        };
        partitions.push(Partition {
            number: u32_at(entry, 24)?,
            offset: u64_at(entry, 8)?,
            length,
            kind,
        });
    }
    Some(Layout { style, partitions })
}

/// VOLUME_DISK_EXTENTS: count at 0, then 24-byte extents from 8 (disk number, offset at +8).
pub fn parse_extents(buf: &[u8]) -> Vec<(u32, u64)> {
    let count = u32_at(buf, 0).unwrap_or(0) as usize;
    (0..count.min(64))
        .map_while(|index| {
            let at = 8 + index * 24;
            Some((u32_at(buf, at)?, u64_at(buf, at + 8)?))
        })
        .collect()
}

/// The lettered volume that starts where a partition does.
pub fn volume_for<'a>(volumes: &'a [Volume], partition: &Partition) -> Option<&'a Volume> {
    volumes
        .iter()
        .find(|v| v.offsets.contains(&partition.offset))
}

// ---- NVMe identify and self-test -----------------------------------------------------

/// The few Identify Controller fields the window shows. The serial number (bytes 4 to 23) is
/// never read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeIdentify {
    /// NVMe version major, minor, tertiary; None before NVMe 1.2, which left it 0.
    pub version: Option<(u16, u8, u8)>,
    /// Optional Admin Command Support bit 4: the drive runs device self-tests.
    pub self_test: bool,
    /// Extended self-test time in minutes (EDSTT).
    pub extended_test_minutes: u16,
    /// Warning and critical composite temperature thresholds in kelvin (WCTEMP, CCTEMP).
    pub warning_kelvin: u16,
    pub critical_kelvin: u16,
}

pub const NVME_IDENTIFY_SIZE: usize = 4096;

/// Identify Controller: VER at 80, OACS at 256, WCTEMP at 266, CCTEMP at 268, EDSTT at 316.
pub fn parse_nvme_identify(buf: &[u8]) -> Option<NvmeIdentify> {
    if buf.len() < 512 {
        return None;
    }
    let u16_at = |at: usize| Some(u16::from_le_bytes(buf.get(at..at + 2)?.try_into().ok()?));
    let ver = u32_at(buf, 80)?;
    Some(NvmeIdentify {
        version: (ver != 0).then_some(((ver >> 16) as u16, (ver >> 8) as u8, ver as u8)),
        self_test: u16_at(256)? & (1 << 4) != 0,
        extended_test_minutes: u16_at(316)?,
        warning_kelvin: u16_at(266)?,
        critical_kelvin: u16_at(268)?,
    })
}

pub fn version_text(version: Option<(u16, u8, u8)>) -> String {
    match version {
        Some((major, minor, 0)) => format!("NVMe {major}.{minor}"),
        Some((major, minor, tertiary)) => format!("NVMe {major}.{minor}.{tertiary}"),
        None => "NVMe (version not reported)".into(),
    }
}

/// One result in the drive's self-test log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTest {
    pub kind: &'static str,
    pub outcome: &'static str,
    /// Some(true) passed, Some(false) failed, None aborted.
    pub passed: Option<bool>,
    pub power_on_hours: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestLog {
    /// The test running now and its percent done.
    pub running: Option<(&'static str, u8)>,
    /// Newest first.
    pub results: Vec<SelfTest>,
}

pub const NVME_SELF_TEST_LOG_SIZE: usize = 564;

fn test_kind(code: u8) -> &'static str {
    match code {
        1 => "short",
        2 => "extended",
        0xE => "vendor-specific",
        _ => "unknown",
    }
}

/// Device Self-test log (page 06h): current operation at 0, its percent at 1, then 20 entries
/// of 28 bytes from 4. An entry's byte 0 holds the result (low nibble, Fh unused) and the test
/// code (high nibble); power-on hours are at 4.
pub fn parse_self_test_log(buf: &[u8]) -> Option<SelfTestLog> {
    if buf.len() < NVME_SELF_TEST_LOG_SIZE {
        return None;
    }
    let current = buf[0] & 0x0F;
    let running = (current != 0).then(|| (test_kind(current), (buf[1] & 0x7F).min(100)));
    let mut results = Vec::new();
    for index in 0..20 {
        let entry = &buf[4 + index * 28..4 + (index + 1) * 28];
        let result = entry[0] & 0x0F;
        if result == 0x0F {
            continue;
        }
        let (outcome, passed) = match result {
            0 => ("passed", Some(true)),
            1 => ("stopped by a command", None),
            2 => ("stopped by a controller reset", None),
            3 => ("stopped when a namespace was removed", None),
            4 => ("stopped by a format", None),
            5 => ("failed with a fatal or unknown error", Some(false)),
            6 => ("failed in an unknown segment", Some(false)),
            7 => ("failed in one or more segments", Some(false)),
            8 => ("stopped for an unknown reason", None),
            9 => ("stopped by a sanitize", None),
            _ => ("result code reserved", None),
        };
        results.push(SelfTest {
            kind: test_kind(entry[0] >> 4),
            outcome,
            passed,
            power_on_hours: u64_at(entry, 4)?,
        });
    }
    Some(SelfTestLog { running, results })
}

// ---- units ---------------------------------------------------------------------------

/// One NVMe data unit is a thousand 512-byte units: 512,000 bytes.
pub const NVME_DATA_UNIT: u128 = 512_000;

pub fn data_units_bytes(units: u128) -> u128 {
    units.saturating_mul(NVME_DATA_UNIT)
}

/// Bytes in the decimal units drive makers use: "79.8 TB", "512.0 GB".
pub fn decimal_size(bytes: u128) -> String {
    const UNITS: [&str; 6] = ["kB", "MB", "GB", "TB", "PB", "EB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in UNITS {
        if value < 1000.0 {
            break;
        }
        value /= 1000.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

/// Groups digits in threes: 18792 reads 18,792.
pub fn grouped(n: u128) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Power-on time as hours with the years they make: "18,792 h (2.1 years)".
pub fn hours_text(hours: u128) -> String {
    let years = hours as f64 / (24.0 * 365.25);
    if years >= 0.1 {
        format!("{} h ({years:.1} years)", grouped(hours))
    } else {
        format!("{} h", grouped(hours))
    }
}

pub fn kelvin_text(kelvin: u16) -> String {
    if kelvin == 0 {
        "not reported".into()
    } else {
        format!("{} C", i32::from(kelvin) - 273)
    }
}

// ---- grading -------------------------------------------------------------------------

/// The app's tones: green, amber, red, and grey for unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    Unknown,
    Good,
    Flagged,
    Serious,
}

/// Endurance used at which a drive is worth a look; the check calls 90 % serious.
pub const WEAR_FLAG: u8 = 70;

/// The dashboard's verdict on one disk.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub grade: Grade,
    pub headline: &'static str,
    /// Why, one reason per entry; never empty.
    pub reasons: Vec<String>,
}

/// Things worth a look that the check does not call problems.
fn concerns(disk: &Disk) -> Vec<String> {
    let mut out = Vec::new();
    match &disk.health {
        Health::Nvme(log) => {
            if log.percentage_used >= WEAR_FLAG && log.percentage_used < 90 {
                out.push(format!(
                    "{} % of the rated endurance is used; plan a replacement",
                    log.percentage_used
                ));
            }
            if log.available_spare > log.spare_threshold
                && log.available_spare < log.spare_threshold.saturating_add(10)
            {
                out.push(format!(
                    "available spare {} % is near its threshold of {} %",
                    log.available_spare, log.spare_threshold
                ));
            }
            if log.critical_temperature_minutes > 0 {
                out.push(format!(
                    "it has spent {} minutes above its critical temperature",
                    grouped(log.critical_temperature_minutes.into())
                ));
            } else if log.warning_temperature_minutes > 0 {
                out.push(format!(
                    "it has spent {} minutes above its warning temperature",
                    grouped(log.warning_temperature_minutes.into())
                ));
            }
        }
        Health::Ata(attributes) => {
            for attribute in attributes {
                let raw = attribute.raw_value();
                match attribute.id {
                    188 if raw > 0 => out.push(format!("{raw} command timeouts")),
                    199 if raw > 0 => out.push(format!(
                        "{raw} interface CRC errors; the cable or connector may be loose"
                    )),
                    10 if raw > 0 => out.push(format!("{raw} spin-up retries")),
                    _ => {}
                }
            }
        }
        Health::Unread(_) => {}
    }
    out
}

/// Serious for anything the drives check calls a problem (the same rule as the check), amber
/// for nearer concerns, green when the drive's data was read and holds neither, and unknown
/// when it could not be read.
pub fn verdict(disk: &Disk) -> Verdict {
    let assessment = health::assess(disk);
    if !assessment.problems.is_empty() {
        return Verdict {
            grade: Grade::Serious,
            headline: "Serious",
            reasons: assessment.problems,
        };
    }
    let concerns = concerns(disk);
    if !concerns.is_empty() {
        return Verdict {
            grade: Grade::Flagged,
            headline: "Worth a look",
            reasons: concerns,
        };
    }
    match &disk.health {
        Health::Unread(why) => Verdict {
            grade: Grade::Unknown,
            headline: "Not known",
            reasons: vec![format!("the drive's own health data was not read: {why}")],
        },
        _ => Verdict {
            grade: Grade::Good,
            headline: "Healthy",
            reasons: vec!["no problem in the drive's own health data".into()],
        },
    }
}

// ---- the dashboard figures -----------------------------------------------------------

/// One figure on the dashboard.
#[derive(Debug, Clone, PartialEq)]
pub struct Figure {
    pub label: &'static str,
    pub value: String,
    pub grade: Grade,
}

fn figure(label: &'static str, value: impl Into<String>, grade: Grade) -> Figure {
    Figure {
        label,
        value: value.into(),
        grade,
    }
}

fn ata(attributes: &[Attribute], id: u8) -> Option<&Attribute> {
    attributes.iter().find(|a| a.id == id)
}

/// Temperature, wear, spare, data written and read, power-on hours, power cycles, unsafe
/// shutdowns, media errors and error log entries; a reading that is missing says so.
pub fn figures(disk: &Disk) -> Vec<Figure> {
    let windows_temp = disk
        .temperature
        .as_ref()
        .ok()
        .and_then(|t| t.current)
        .map(i32::from);
    let warning = disk.temperature.as_ref().ok().and_then(|t| t.warning);
    let temp_grade = |c: i32| match warning {
        Some(w) if c >= i32::from(w) => Grade::Serious,
        Some(w) if c + 5 >= i32::from(w) => Grade::Flagged,
        _ => Grade::Good,
    };
    let temp = |c: Option<i32>| match c {
        Some(c) => figure("Temperature", format!("{c} C"), temp_grade(c)),
        None => figure("Temperature", "not reported", Grade::Unknown),
    };
    match &disk.health {
        Health::Nvme(log) => nvme_figures(log, temp(log.celsius().or(windows_temp))),
        Health::Ata(attributes) => {
            let count = |label, id: u8, bad: bool| match ata(attributes, id) {
                Some(a) => {
                    let raw = a.raw_value();
                    let grade = if bad && raw > 0 {
                        Grade::Serious
                    } else {
                        Grade::Good
                    };
                    figure(label, grouped(raw.into()), grade)
                }
                None => figure(label, "not reported", Grade::Unknown),
            };
            let celsius = ata(attributes, 194)
                .map(|a| i32::from(a.raw[0]))
                .filter(|c| *c > 0);
            let life = [231u8, 233, 177, 202]
                .iter()
                .find_map(|id| ata(attributes, *id))
                .map(|a| a.current);
            let hours = ata(attributes, 9).map(|a| a.raw_value() & 0xffff_ffff);
            vec![
                temp(celsius.or(windows_temp)),
                match life {
                    Some(left) => figure(
                        "Life left",
                        format!("{left} %"),
                        if left <= 10 {
                            Grade::Serious
                        } else if left <= 30 {
                            Grade::Flagged
                        } else {
                            Grade::Good
                        },
                    ),
                    None => figure("Life left", "not reported", Grade::Unknown),
                },
                figure(
                    "Power-on hours",
                    hours.map_or("not reported".into(), |h| grouped(h.into())),
                    Grade::Good,
                ),
                count("Power cycles", 12, false),
                count("Reallocated sectors", 5, true),
                count("Pending sectors", 197, true),
                count("Uncorrectable", 198, true),
                count("Interface errors", 199, false),
            ]
        }
        Health::Unread(_) => {
            let missing = |label| figure(label, "not read", Grade::Unknown);
            vec![
                temp(windows_temp),
                missing("Endurance used"),
                missing("Data written"),
                missing("Power-on hours"),
                missing("Media errors"),
            ]
        }
    }
}

fn nvme_figures(log: &NvmeHealth, temperature: Figure) -> Vec<Figure> {
    let used = log.percentage_used;
    vec![
        temperature,
        figure(
            "Endurance used",
            format!("{used} %"),
            if used >= 90 {
                Grade::Serious
            } else if used >= WEAR_FLAG {
                Grade::Flagged
            } else {
                Grade::Good
            },
        ),
        figure(
            "Available spare",
            format!("{} %", log.available_spare),
            if log.available_spare <= log.spare_threshold {
                Grade::Serious
            } else if log.available_spare < log.spare_threshold.saturating_add(10) {
                Grade::Flagged
            } else {
                Grade::Good
            },
        ),
        figure(
            "Data written",
            decimal_size(data_units_bytes(log.data_units_written)),
            Grade::Good,
        ),
        figure(
            "Data read",
            decimal_size(data_units_bytes(log.data_units_read)),
            Grade::Good,
        ),
        figure("Power-on hours", grouped(log.power_on_hours), Grade::Good),
        figure("Power cycles", grouped(log.power_cycles), Grade::Good),
        // The health table names it in full: unsafe shutdowns, power lost without warning.
        figure("Power losses", grouped(log.unsafe_shutdowns), Grade::Good),
        figure(
            "Media errors",
            grouped(log.media_errors),
            if log.media_errors > 0 {
                Grade::Serious
            } else {
                Grade::Good
            },
        ),
        figure(
            "Error log entries",
            grouped(log.error_log_entries),
            Grade::Good,
        ),
    ]
}

// ---- the full health table -----------------------------------------------------------

/// One line of the health table: where it is, what it means, its value and its raw form.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The NVMe log byte range or the ATA attribute id.
    pub key: String,
    pub name: String,
    /// The value in plain units, or for ATA the normalised current and worst values.
    pub value: String,
    pub raw: String,
    pub grade: Grade,
}

fn row(key: &str, name: &str, value: String, raw: String, grade: Grade) -> Row {
    Row {
        key: key.into(),
        name: name.into(),
        value,
        raw,
        grade,
    }
}

/// Every field of the NVMe SMART / Health Information log, in log order.
pub fn nvme_table(log: &NvmeHealth) -> Vec<Row> {
    let warnings = health::critical_warning_names(log.critical_warning);
    let plain = grouped;
    let mut rows = vec![
        row(
            "0",
            "Critical warning",
            if warnings.is_empty() {
                "none".into()
            } else {
                warnings.join("; ")
            },
            format!("0x{:02X}", log.critical_warning),
            if log.critical_warning != 0 {
                Grade::Serious
            } else {
                Grade::Good
            },
        ),
        row(
            "2:1",
            "Composite temperature",
            kelvin_text(log.temperature_kelvin),
            format!("{} K", log.temperature_kelvin),
            Grade::Unknown,
        ),
        row(
            "3",
            "Available spare",
            format!("{} %", log.available_spare),
            log.available_spare.to_string(),
            if log.available_spare <= log.spare_threshold {
                Grade::Serious
            } else {
                Grade::Good
            },
        ),
        row(
            "4",
            "Available spare threshold",
            format!("{} %", log.spare_threshold),
            log.spare_threshold.to_string(),
            Grade::Unknown,
        ),
        row(
            "5",
            "Endurance used (percentage used)",
            format!("{} %", log.percentage_used),
            log.percentage_used.to_string(),
            if log.percentage_used >= 90 {
                Grade::Serious
            } else if log.percentage_used >= WEAR_FLAG {
                Grade::Flagged
            } else {
                Grade::Good
            },
        ),
        row(
            "47:32",
            "Data read (units of 512,000 bytes)",
            decimal_size(data_units_bytes(log.data_units_read)),
            plain(log.data_units_read),
            Grade::Unknown,
        ),
        row(
            "63:48",
            "Data written (units of 512,000 bytes)",
            decimal_size(data_units_bytes(log.data_units_written)),
            plain(log.data_units_written),
            Grade::Unknown,
        ),
        row(
            "79:64",
            "Read commands from the PC",
            plain(log.host_read_commands),
            plain(log.host_read_commands),
            Grade::Unknown,
        ),
        row(
            "95:80",
            "Write commands from the PC",
            plain(log.host_write_commands),
            plain(log.host_write_commands),
            Grade::Unknown,
        ),
        row(
            "111:96",
            "Time busy with commands",
            format!("{} minutes", plain(log.controller_busy_minutes)),
            plain(log.controller_busy_minutes),
            Grade::Unknown,
        ),
        row(
            "127:112",
            "Power cycles",
            plain(log.power_cycles),
            plain(log.power_cycles),
            Grade::Unknown,
        ),
        row(
            "143:128",
            "Power-on hours",
            hours_text(log.power_on_hours),
            plain(log.power_on_hours),
            Grade::Unknown,
        ),
        row(
            "159:144",
            "Unsafe shutdowns (power lost without warning)",
            plain(log.unsafe_shutdowns),
            plain(log.unsafe_shutdowns),
            Grade::Unknown,
        ),
        row(
            "175:160",
            "Media and data integrity errors",
            plain(log.media_errors),
            plain(log.media_errors),
            if log.media_errors > 0 {
                Grade::Serious
            } else {
                Grade::Good
            },
        ),
        row(
            "191:176",
            "Error log entries (all kinds, most harmless)",
            plain(log.error_log_entries),
            plain(log.error_log_entries),
            Grade::Unknown,
        ),
        row(
            "195:192",
            "Minutes above the warning temperature",
            plain(log.warning_temperature_minutes.into()),
            log.warning_temperature_minutes.to_string(),
            if log.warning_temperature_minutes > 0 {
                Grade::Flagged
            } else {
                Grade::Good
            },
        ),
        row(
            "199:196",
            "Minutes above the critical temperature",
            plain(log.critical_temperature_minutes.into()),
            log.critical_temperature_minutes.to_string(),
            if log.critical_temperature_minutes > 0 {
                Grade::Flagged
            } else {
                Grade::Good
            },
        ),
    ];
    for (index, kelvin) in log.sensors_kelvin.iter().enumerate() {
        if *kelvin == 0 {
            continue;
        }
        let at = 200 + 2 * index;
        rows.push(row(
            &format!("{}:{at}", at + 1),
            &format!("Temperature sensor {}", index + 1),
            kelvin_text(*kelvin),
            format!("{kelvin} K"),
            Grade::Unknown,
        ));
    }
    for level in 0..2 {
        let (count_at, time_at) = (216 + 4 * level, 224 + 4 * level);
        rows.push(row(
            &format!("{}:{count_at}", count_at + 3),
            &format!("Times slowed to cool down (level {})", level + 1),
            plain(log.thermal_transitions[level].into()),
            log.thermal_transitions[level].to_string(),
            Grade::Unknown,
        ));
        rows.push(row(
            &format!("{}:{time_at}", time_at + 3),
            &format!("Seconds slowed to cool down (level {})", level + 1),
            plain(log.thermal_seconds[level].into()),
            log.thermal_seconds[level].to_string(),
            Grade::Unknown,
        ));
    }
    rows
}

/// Plain names for ATA SMART attributes. Ids not listed are vendor-defined.
pub fn ata_name(id: u8) -> &'static str {
    match id {
        1 => "read error rate",
        2 => "throughput performance",
        3 => "spin-up time",
        4 => "start and stop count",
        5 => "reallocated sectors",
        7 => "seek error rate",
        8 => "seek time performance",
        9 => "power-on hours",
        10 => "spin-up retries",
        11 => "calibration retries",
        12 => "power cycles",
        13 => "soft read error rate",
        170 => "available reserved space",
        171 => "program failures",
        172 => "erase failures",
        173 => "wear leveling (average erases)",
        174 => "unexpected power losses",
        177 => "wear leveling count",
        179 => "used reserved blocks",
        180 => "unused reserved blocks",
        181 => "program failures",
        182 => "erase failures",
        183 => "SATA speed drops or runtime bad blocks",
        184 => "end-to-end errors",
        187 => "reported uncorrectable errors",
        188 => "command timeouts",
        189 => "high fly writes",
        190 => "airflow temperature",
        191 => "shock events",
        192 => "unsafe shutdowns (power-off retracts)",
        193 => "load and unload cycles",
        194 => "temperature",
        195 => "hardware ECC recovered",
        196 => "reallocation events",
        197 => "current pending sectors",
        198 => "offline uncorrectable sectors",
        199 => "UDMA CRC errors (usually the cable)",
        200 => "write error rate",
        202 => "percentage of life used",
        220 => "disk shift",
        222 => "loaded hours",
        225 => "load and unload cycles",
        226 => "load-in time",
        230 => "head amplitude or life curve status",
        231 => "SSD life left",
        232 => "available reserved space",
        233 => "media wearout indicator",
        234 => "vendor-defined (often total writes)",
        235 => "vendor-defined (often power-loss count)",
        240 => "head flying hours",
        241 => "total writes (unit varies by maker)",
        242 => "total reads (unit varies by maker)",
        _ => "vendor-defined",
    }
}

/// Every ATA attribute read, in id order, with its normalised and raw values.
pub fn ata_table(attributes: &[Attribute]) -> Vec<Row> {
    let mut sorted: Vec<&Attribute> = attributes.iter().collect();
    sorted.sort_by_key(|a| a.id);
    sorted
        .into_iter()
        .map(|a| {
            let raw = a.raw_value();
            let raw_text = match a.id {
                194 | 190 => format!("{} C (raw {raw})", a.raw[0]),
                9 => grouped((raw & 0xffff_ffff).into()),
                _ => grouped(raw.into()),
            };
            let grade = match a.id {
                5 | 197 | 198 | 187 if raw > 0 => Grade::Serious,
                188 | 199 | 10 if raw > 0 => Grade::Flagged,
                5 | 197 | 198 | 187 | 188 | 199 | 10 => Grade::Good,
                _ => Grade::Unknown,
            };
            row(
                &a.id.to_string(),
                ata_name(a.id),
                format!("{} (worst {})", a.current, a.worst),
                raw_text,
                grade,
            )
        })
        .collect()
}

// ---- the window's text ---------------------------------------------------------------

/// One line of the details list.
#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    Heading(String),
    /// Column titles for the rows that follow.
    Columns(Row),
    Row(Row),
}

/// The text a screen reader announces for a line, and what Copy puts on the clipboard.
pub fn line_text(line: &Line) -> String {
    match line {
        Line::Heading(text) => text.clone(),
        Line::Columns(r) => format!("{}, {}, {}, {}", r.key, r.name, r.value, r.raw),
        Line::Row(r) => {
            let mut text = String::new();
            if !r.key.is_empty() {
                text.push_str(&format!("{} ", r.key));
            }
            text.push_str(&format!("{}: {}", r.name, r.value));
            if !r.raw.is_empty() && r.raw != r.value {
                text.push_str(&format!(" ({})", r.raw));
            }
            text
        }
    }
}

/// The drive's name, or why it has none.
pub fn name(disk: &Disk) -> String {
    match &disk.identity {
        Ok(identity) => {
            let name = super::display_name(identity);
            if name.trim().is_empty() {
                "Model not reported".into()
            } else {
                name
            }
        }
        Err(why) => format!("Disk {} (not identified: {why})", disk.number),
    }
}

fn letters(disk: &Disk) -> String {
    disk.volumes
        .iter()
        .map(|letter| format!("{letter}:"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The picker's second line: "Disk 0 · NVMe · 2.00 TB · C:".
pub fn caption(disk: &Disk) -> String {
    let mut parts = vec![format!("Disk {}", disk.number)];
    if let Ok(identity) = &disk.identity {
        parts.push(health::bus_name(identity.bus).to_string());
    }
    if let Ok(bytes) = disk.size {
        parts.push(super::size_text(bytes));
    }
    if !disk.volumes.is_empty() {
        parts.push(letters(disk));
    }
    parts.join("  ·  ")
}

/// The line under the name: bus and protocol version, link, size and media, firmware.
pub fn subtitle(disk: &Disk, details: &Details) -> String {
    let mut parts = vec![format!("Disk {}", disk.number)];
    if let Ok(identity) = &disk.identity {
        parts.push(match (&details.identify, identity.bus) {
            (Ok(id), health::BUS_NVME) => version_text(id.version),
            _ => health::bus_name(identity.bus).to_string(),
        });
    }
    if let Ok(link) = &details.link {
        parts.push(link_text(link));
    }
    if let Ok(bytes) = disk.size {
        let media = match disk.solid_state {
            Ok(true) => " SSD",
            Ok(false) => " HDD",
            Err(_) => "",
        };
        parts.push(format!("{}{media}", super::size_text(bytes)));
    }
    if let Ok(identity) = &disk.identity {
        if !identity.firmware.is_empty() {
            parts.push(format!("firmware {}", identity.firmware));
        }
    }
    parts.join("  ·  ")
}

fn fact(name: &str, value: impl Into<String>, grade: Grade) -> Line {
    Line::Row(row("", name, value.into(), String::new(), grade))
}

fn reading<T>(result: &Result<T, String>, show: impl FnOnce(&T) -> String) -> String {
    match result {
        Ok(value) => show(value),
        Err(why) => format!("unavailable: {why}"),
    }
}

/// Every reading about one disk as the details list shows it: the drive, its partitions,
/// the full health table and the self-test log. Missing readings say why.
pub fn detail_lines(disk: &Disk, details: &Details, elevated: Option<bool>) -> Vec<Line> {
    let mut lines = vec![Line::Heading("Drive".into())];
    let nvme = disk
        .identity
        .as_ref()
        .is_ok_and(|identity| identity.bus == health::BUS_NVME);
    lines.push(fact("Model", name(disk), Grade::Unknown));
    lines.push(fact(
        "Firmware",
        reading(&disk.identity, |i| {
            if i.firmware.is_empty() {
                "not reported".into()
            } else {
                i.firmware.clone()
            }
        }),
        Grade::Unknown,
    ));
    let interface = reading(&disk.identity, |i| match (&details.identify, nvme) {
        (Ok(id), true) => format!("NVMe, {}", version_text(id.version)),
        _ => health::bus_name(i.bus).to_string(),
    });
    lines.push(fact("Interface", interface, Grade::Unknown));
    let link_grade = match &details.link {
        Ok(link) if link_below_max(link) => Grade::Flagged,
        _ => Grade::Unknown,
    };
    lines.push(fact(
        "Link",
        match &details.link {
            Ok(link) if link_below_max(link) => format!(
                "{}; the slot or its settings hold the drive back",
                link_text(link)
            ),
            other => reading(other, link_text),
        },
        link_grade,
    ));
    lines.push(fact(
        "Capacity",
        reading(&disk.size, |&bytes| {
            if bytes == 0 {
                "no media".into()
            } else {
                format!(
                    "{} ({})",
                    super::size_text(bytes),
                    crate::tools::space::format_size(bytes)
                )
            }
        }),
        Grade::Unknown,
    ));
    lines.push(fact(
        "Media",
        reading(&disk.solid_state, |&ssd| {
            if ssd {
                "solid state (SSD)".into()
            } else {
                "spinning disk (HDD)".into()
            }
        }),
        Grade::Unknown,
    ));
    let trim_off = disk.solid_state == Ok(true)
        && details.trim == Ok(true)
        && details.windows_trim == Ok(false);
    lines.push(fact(
        "TRIM",
        format!(
            "{}; {}",
            reading(&details.trim, |&on| if on {
                "the drive accepts TRIM".into()
            } else {
                "the drive does not take TRIM".into()
            }),
            reading(&details.windows_trim, |&on| if on {
                "Windows sends it".into()
            } else {
                "turned off in Windows (DisableDeleteNotification)".into()
            })
        ),
        if trim_off {
            Grade::Flagged
        } else {
            Grade::Unknown
        },
    ));
    let limits = match (&disk.temperature, &details.identify) {
        (Ok(t), _) if t.warning.is_some() || t.critical.is_some() => format!(
            "warning at {}, critical at {}",
            t.warning
                .map_or("not reported".into(), |c| format!("{c} C")),
            t.critical
                .map_or("not reported".into(), |c| format!("{c} C"))
        ),
        (_, Ok(id)) if nvme => format!(
            "warning at {}, critical at {}",
            kelvin_text(id.warning_kelvin),
            kelvin_text(id.critical_kelvin)
        ),
        (Err(why), _) => format!("unavailable: {why}"),
        _ => "not reported".into(),
    };
    lines.push(fact("Temperature limits", limits, Grade::Unknown));
    lines.push(match &disk.predicts_failure {
        Ok(true) => fact(
            "Windows failure prediction",
            "the drive is predicted to fail",
            Grade::Serious,
        ),
        Ok(false) => fact(
            "Windows failure prediction",
            "no failure predicted",
            Grade::Good,
        ),
        Err(why) => fact(
            "Windows failure prediction",
            format!("unavailable: {why}"),
            Grade::Unknown,
        ),
    });
    let self_test = match (&details.identify, nvme) {
        (Ok(id), true) if id.self_test => match elevated {
            Some(true) => format!(
                "the drive runs short and extended ({} min) self-tests; this tool reads their log and does not start them",
                id.extended_test_minutes
            ),
            _ => format!(
                "the drive runs short and extended ({} min) self-tests; starting one needs administrator rights, so this tool shows their log only",
                id.extended_test_minutes
            ),
        },
        (Ok(_), true) => "this drive does not run self-tests".into(),
        _ => reading(&details.self_test, |_| "its log is shown below".into()),
    };
    lines.push(fact("Drive self-test", self_test, Grade::Unknown));
    lines.push(fact(
        "Read as",
        match elevated {
            Some(true) => "an administrator",
            Some(false) => "the current user, without administrator rights",
            None => "the current user (administrator rights unknown)",
        },
        Grade::Unknown,
    ));

    match &details.layout {
        Ok(layout) => {
            lines.push(Line::Heading(format!(
                "Partitions ({})",
                match layout.style {
                    Style::Gpt => "GPT",
                    Style::Mbr => "MBR",
                    Style::Raw => "not partitioned",
                }
            )));
            if layout.partitions.is_empty() {
                lines.push(fact("Partitions", "none", Grade::Unknown));
            }
            for partition in &layout.partitions {
                let volume = volume_for(&details.volumes, partition);
                let name = match volume {
                    Some(v) => format!("{} ({}:)", partition.kind, v.letter),
                    None => partition.kind.clone(),
                };
                let raw = volume.map_or(String::new(), |v| {
                    let mut parts = Vec::new();
                    if let Ok(fs) = &v.file_system {
                        parts.push(fs.clone());
                    }
                    match &v.space {
                        Ok((free, _)) => {
                            parts.push(format!("{} free", crate::tools::space::format_size(*free)))
                        }
                        Err(why) => parts.push(why.clone()),
                    }
                    if !v.other_disks.is_empty() {
                        parts.push(format!(
                            "also on disk {}",
                            v.other_disks
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    parts.join(", ")
                });
                lines.push(Line::Row(row(
                    &partition.number.to_string(),
                    &name,
                    crate::tools::space::format_size(partition.length),
                    raw,
                    Grade::Unknown,
                )));
            }
        }
        Err(why) => {
            lines.push(Line::Heading("Partitions".into()));
            lines.push(fact(
                "Partition table",
                format!("unavailable: {why}"),
                Grade::Unknown,
            ));
        }
    }

    match &disk.health {
        Health::Nvme(log) => {
            lines.push(Line::Heading(
                "NVMe health log (SMART / Health Information, log page 02h)".into(),
            ));
            lines.push(Line::Columns(row(
                "Bytes",
                "Field",
                "Value".into(),
                "Raw".into(),
                Grade::Unknown,
            )));
            lines.extend(nvme_table(log).into_iter().map(Line::Row));
        }
        Health::Ata(attributes) => {
            lines.push(Line::Heading("SMART attributes".into()));
            lines.push(Line::Columns(row(
                "ID",
                "Attribute",
                "Normalized (worst)".into(),
                "Raw".into(),
                Grade::Unknown,
            )));
            lines.extend(ata_table(attributes).into_iter().map(Line::Row));
        }
        Health::Unread(why) => {
            lines.push(Line::Heading("Health data".into()));
            lines.push(fact("Not read", why.clone(), Grade::Unknown));
        }
    }

    if nvme {
        lines.push(Line::Heading("Self-test log (log page 06h)".into()));
        match &details.self_test {
            Ok(log) => {
                if let Some((kind, percent)) = log.running {
                    lines.push(fact(
                        "Running now",
                        format!("{kind} self-test, {percent} % done"),
                        Grade::Unknown,
                    ));
                }
                if log.results.is_empty() {
                    lines.push(fact("Results", "no self-tests recorded", Grade::Unknown));
                }
                for (index, test) in log.results.iter().enumerate() {
                    lines.push(Line::Row(row(
                        &(index + 1).to_string(),
                        &format!("{} self-test", test.kind),
                        test.outcome.into(),
                        format!("at {} h", grouped(test.power_on_hours.into())),
                        match test.passed {
                            Some(true) => Grade::Good,
                            Some(false) => Grade::Serious,
                            None => Grade::Unknown,
                        },
                    )));
                }
            }
            Err(why) => lines.push(fact(
                "Self-test log",
                format!("unavailable: {why}"),
                Grade::Unknown,
            )),
        }
    }
    lines
}

/// The lettered volumes on this disk that a test can use.
pub fn test_volumes(details: &Details) -> Vec<char> {
    details
        .volumes
        .iter()
        .filter(|v| v.space.is_ok())
        .map(|v| v.letter)
        .collect()
}

/// The disk the window opens on: the worst flagged one, else the one holding Windows
/// (`system` is its drive letter), else the first.
pub fn first_shown(disks: &[Disk], system: Option<char>) -> usize {
    let worst = disks
        .iter()
        .enumerate()
        .map(|(index, disk)| (verdict(disk).grade, std::cmp::Reverse(index)))
        .max();
    if let Some((grade, std::cmp::Reverse(index))) = worst {
        if grade >= Grade::Flagged {
            return index;
        }
    }
    system
        .and_then(|letter| disks.iter().position(|d| d.volumes.contains(&letter)))
        .unwrap_or(0)
}

/// The verdict as one sentence: "No problem in the drive's own health data."
pub fn verdict_text(verdict: &Verdict) -> String {
    let joined = verdict.reasons.join("; ");
    let mut chars = joined.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// Everything the window shows about one disk, as plain text for the clipboard.
pub fn copy_text(disk: &Disk, details: &Details, elevated: Option<bool>) -> String {
    let verdict = verdict(disk);
    let mut out = vec![
        name(disk),
        subtitle(disk, details),
        format!("Verdict: {}. {}", verdict.headline, verdict_text(&verdict)),
        String::new(),
    ];
    for figure in figures(disk) {
        out.push(format!("{}: {}", figure.label, figure.value));
    }
    for line in detail_lines(disk, details, elevated) {
        if let Line::Heading(_) = line {
            out.push(String::new());
        }
        out.push(line_text(&line));
    }
    out.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::super::health::fixtures::*;
    use super::super::health::*;
    use super::*;

    fn found() -> Details {
        Details {
            link: Ok(Link {
                speed: Some(4),
                width: Some(4),
                max_speed: Some(4),
                max_width: Some(4),
            }),
            layout: Ok(Layout {
                style: Style::Gpt,
                partitions: vec![
                    Partition {
                        number: 1,
                        offset: 1 << 20,
                        length: 100 << 20,
                        kind: "EFI system".into(),
                    },
                    Partition {
                        number: 2,
                        offset: 101 << 20,
                        length: 900 << 30,
                        kind: "basic data".into(),
                    },
                ],
            }),
            volumes: vec![Volume {
                letter: 'C',
                offsets: vec![101 << 20],
                other_disks: vec![1],
                space: Ok((200 << 30, 900 << 30)),
                file_system: Ok("NTFS".into()),
            }],
            trim: Ok(true),
            windows_trim: Ok(true),
            identify: Ok(NvmeIdentify {
                version: Some((2, 0, 0)),
                self_test: true,
                extended_test_minutes: 21,
                warning_kelvin: 360,
                critical_kelvin: 362,
            }),
            self_test: Ok(SelfTestLog {
                running: None,
                results: vec![SelfTest {
                    kind: "short",
                    outcome: "passed",
                    passed: Some(true),
                    power_on_hours: 18_000,
                }],
            }),
        }
    }

    #[test]
    fn the_details_list_covers_drive_partitions_health_and_self_tests() {
        let nvme = disk(Health::Nvme(parse_nvme_health(&healthy_nvme()).unwrap()));
        let lines = detail_lines(&nvme, &found(), Some(false));
        let text: Vec<String> = lines.iter().map(line_text).collect();
        let all = text.join("\n");
        assert!(all.contains("Interface: NVMe, NVMe 2.0"), "{all}");
        assert!(all.contains("Link: PCIe 4.0 x4"));
        assert!(all.contains("Capacity: 1.00 TB (931.5 GiB)"));
        assert!(all.contains("TRIM: the drive accepts TRIM; Windows sends it"));
        assert!(all.contains("Temperature limits: warning at 82 C, critical at 85 C"));
        assert!(all.contains("starting one needs administrator rights"));
        assert!(all.contains("Read as: the current user, without administrator rights"));
        assert!(all.contains("Partitions (GPT)"));
        assert!(all.contains("2 basic data (C:): 900.0 GiB (NTFS, 200.0 GiB free, also on disk 1)"));
        assert!(all.contains("1 EFI system: 100.0 MiB"));
        assert!(all.contains("63:48 Data written (units of 512,000 bytes): 40.0 TB (78,125,000)"));
        assert!(all.contains("1 short self-test: passed (at 18,000 h)"));
        assert!(lines.iter().any(|l| matches!(l, Line::Columns(_))));
        assert_eq!(test_volumes(&found()), ['C']);
        let subtitle = subtitle(&nvme, &found());
        assert_eq!(
            subtitle,
            "Disk 0  ·  NVMe 2.0  ·  PCIe 4.0 x4  ·  1.00 TB SSD  ·  firmware 1.0"
        );
        assert_eq!(caption(&nvme), "Disk 0  ·  NVMe  ·  1.00 TB  ·  C:");
    }

    #[test]
    fn missing_readings_say_why_and_a_slow_link_is_flagged() {
        let mut sata = disk(Health::Unread(
            "SMART attributes need administrator rights".into(),
        ));
        if let Ok(identity) = &mut sata.identity {
            identity.bus = BUS_SATA;
        }
        let mut details = Details::unread("a SATA drive's link speed needs administrator rights");
        details.layout = Err("the driver does not support it".into());
        let all: String = detail_lines(&sata, &details, Some(false))
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            all.contains("Link: unavailable: a SATA drive's link speed needs administrator rights")
        );
        assert!(all.contains("Not read: SMART attributes need administrator rights"));
        assert!(all.contains("Partition table: unavailable: the driver does not support it"));
        assert!(!all.contains("Self-test log"));
        let mut slow = found();
        slow.link = Ok(Link {
            speed: Some(3),
            width: Some(4),
            max_speed: Some(4),
            max_width: Some(4),
        });
        slow.windows_trim = Ok(false);
        let nvme = disk(Health::Nvme(parse_nvme_health(&healthy_nvme()).unwrap()));
        let lines = detail_lines(&nvme, &slow, Some(false));
        let graded = |name: &str| {
            lines.iter().find_map(|l| match l {
                Line::Row(r) if r.name == name => Some(r.grade),
                _ => None,
            })
        };
        assert_eq!(graded("Link"), Some(Grade::Flagged));
        assert_eq!(graded("TRIM"), Some(Grade::Flagged));
    }

    #[test]
    fn nvme_data_units_are_512000_bytes() {
        assert_eq!(data_units_bytes(1), 512_000);
        assert_eq!(data_units_bytes(78_125_000), 40_000_000_000_000);
        assert_eq!(decimal_size(data_units_bytes(78_125_000)), "40.0 TB");
        assert_eq!(decimal_size(999), "999 B");
        assert_eq!(decimal_size(1_000), "1.0 kB");
        assert_eq!(decimal_size(512_000_000_000), "512.0 GB");
        assert_eq!(data_units_bytes(u128::MAX), u128::MAX);
    }

    #[test]
    fn hours_and_counts_read_plainly() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(18_792), "18,792");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(hours_text(18_792), "18,792 h (2.1 years)");
        assert_eq!(hours_text(5), "5 h");
        assert_eq!(kelvin_text(314), "41 C");
        assert_eq!(kelvin_text(0), "not reported");
    }

    #[test]
    fn a_healthy_drive_is_green_and_a_worn_one_red() {
        let healthy = disk(Health::Nvme(parse_nvme_health(&healthy_nvme()).unwrap()));
        let v = verdict(&healthy);
        assert_eq!(v.grade, Grade::Good);
        assert_eq!(v.headline, "Healthy");
        let worn = disk(Health::Nvme(parse_nvme_health(&worn_nvme()).unwrap()));
        let v = verdict(&worn);
        assert_eq!(v.grade, Grade::Serious);
        assert_eq!(v.reasons, assess(&worn).problems);
    }

    #[test]
    fn nearer_concerns_are_amber_not_red() {
        let mut bytes = healthy_nvme();
        bytes[5] = 75;
        let log = parse_nvme_health(&bytes).unwrap();
        let v = verdict(&disk(Health::Nvme(log)));
        assert_eq!(v.grade, Grade::Flagged);
        assert!(v.reasons[0].contains("75 % of the rated endurance"));
        let mut near = healthy_nvme();
        near[3] = 15;
        let v = verdict(&disk(Health::Nvme(parse_nvme_health(&near).unwrap())));
        assert_eq!(v.grade, Grade::Flagged);
        assert!(v.reasons[0].contains("near its threshold"));
        let cable = parse_smart_attributes(&smart_table(&[(199, 200, 200, 3)])).unwrap();
        let v = verdict(&disk(Health::Ata(cable)));
        assert_eq!(v.grade, Grade::Flagged);
        assert!(v.reasons[0].contains("cable"));
    }

    #[test]
    fn unread_health_is_unknown_with_its_reason() {
        let unread = disk(Health::Unread(
            "SMART attributes need administrator rights".into(),
        ));
        let v = verdict(&unread);
        assert_eq!(v.grade, Grade::Unknown);
        assert!(v.reasons[0].contains("need administrator rights"));
        let figures = figures(&unread);
        assert_eq!(figures[0].value, "41 C");
        assert!(figures[1..].iter().all(|f| f.value == "not read"));
        assert!(figures[1..].iter().all(|f| f.grade == Grade::Unknown));
    }

    #[test]
    fn nvme_figures_and_table_use_the_log() {
        let log = parse_nvme_health(&healthy_nvme()).unwrap();
        let shown = figures(&disk(Health::Nvme(log.clone())));
        let value = |label: &str| {
            shown
                .iter()
                .find(|f| f.label == label)
                .map(|f| f.value.clone())
                .unwrap()
        };
        assert_eq!(value("Temperature"), "41 C");
        assert_eq!(value("Endurance used"), "3 %");
        assert_eq!(value("Data written"), "40.0 TB");
        assert_eq!(value("Data read"), "52.0 TB");
        assert_eq!(value("Power-on hours"), "8,812");
        assert_eq!(value("Error log entries"), "14");
        let table = nvme_table(&log);
        assert!(table.len() >= 17 + 4);
        let written = table.iter().find(|r| r.key == "63:48").unwrap();
        assert_eq!(written.raw, "78,125,000");
        assert_eq!(written.value, "40.0 TB");
        assert!(table
            .iter()
            .all(|r| !r.name.is_empty() && !r.value.is_empty()));
        let worn = parse_nvme_health(&worn_nvme()).unwrap();
        let media = nvme_table(&worn)
            .into_iter()
            .find(|r| r.key == "175:160")
            .unwrap();
        assert_eq!(media.grade, Grade::Serious);
    }

    #[test]
    fn ata_table_names_every_attribute() {
        let attributes = parse_smart_attributes(&healthy_smart()).unwrap();
        let table = ata_table(&attributes);
        assert_eq!(table.len(), attributes.len());
        let temp = table.iter().find(|r| r.key == "194").unwrap();
        assert_eq!(temp.name, "temperature");
        assert_eq!(temp.value, "66 (worst 52)");
        assert!(temp.raw.starts_with("34 C"));
        let pending = parse_smart_attributes(&pending_smart()).unwrap();
        let rows = ata_table(&pending);
        assert_eq!(
            rows.iter().find(|r| r.key == "197").unwrap().grade,
            Grade::Serious
        );
        assert_eq!(
            rows.iter().find(|r| r.key == "188").unwrap().grade,
            Grade::Flagged
        );
        assert_eq!(ata_name(250), "vendor-defined");
    }

    fn gpt_entry(number: u32, offset: u64, length: u64, guid: [u8; 16]) -> Vec<u8> {
        let mut e = vec![0u8; PARTITION_ENTRY];
        e[0..4].copy_from_slice(&1u32.to_le_bytes());
        e[8..16].copy_from_slice(&offset.to_le_bytes());
        e[16..24].copy_from_slice(&length.to_le_bytes());
        e[24..28].copy_from_slice(&number.to_le_bytes());
        e[32..48].copy_from_slice(&guid);
        e
    }

    /// The EFI system partition type GUID as Windows stores it.
    const EFI: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    const BASIC: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    #[test]
    fn gpt_layout_names_partitions_and_finds_volumes() {
        let mut buf = vec![0u8; LAYOUT_HEADER];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[4..8].copy_from_slice(&2u32.to_le_bytes());
        buf.extend(gpt_entry(1, 1 << 20, 100 << 20, EFI));
        buf.extend(gpt_entry(2, 101 << 20, 1 << 40, BASIC));
        let layout = parse_layout(&buf).unwrap();
        assert_eq!(layout.style, Style::Gpt);
        assert_eq!(layout.partitions.len(), 2);
        assert_eq!(layout.partitions[0].kind, "EFI system");
        assert_eq!(layout.partitions[1].kind, "basic data");
        assert_eq!(layout.partitions[1].offset, 101 << 20);
        let volumes = vec![Volume {
            letter: 'C',
            offsets: vec![101 << 20],
            other_disks: vec![],
            space: Ok((1, 2)),
            file_system: Ok("NTFS".into()),
        }];
        assert_eq!(
            volume_for(&volumes, &layout.partitions[1]).map(|v| v.letter),
            Some('C')
        );
        assert!(volume_for(&volumes, &layout.partitions[0]).is_none());
        // A count larger than the buffer stops at what is there.
        buf[4..8].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(parse_layout(&buf).unwrap().partitions.len(), 2);
        assert!(parse_layout(&buf[..4]).is_none());
    }

    #[test]
    fn layout_offsets_match_the_windows_structures() {
        use std::mem::{offset_of, size_of};
        use windows_sys::Win32::System::Ioctl::{
            DRIVE_LAYOUT_INFORMATION_EX, PARTITION_INFORMATION_EX,
        };
        assert_eq!(size_of::<PARTITION_INFORMATION_EX>(), PARTITION_ENTRY);
        assert_eq!(
            offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry),
            LAYOUT_HEADER
        );
        assert_eq!(offset_of!(PARTITION_INFORMATION_EX, StartingOffset), 8);
        assert_eq!(offset_of!(PARTITION_INFORMATION_EX, PartitionLength), 16);
        assert_eq!(offset_of!(PARTITION_INFORMATION_EX, PartitionNumber), 24);
        assert_eq!(offset_of!(PARTITION_INFORMATION_EX, Anonymous), 32);
    }

    #[test]
    fn mbr_layout_skips_empty_slots() {
        let mut buf = vec![0u8; LAYOUT_HEADER + 2 * PARTITION_ENTRY];
        buf[4..8].copy_from_slice(&2u32.to_le_bytes());
        let first = LAYOUT_HEADER;
        buf[first + 16..first + 24].copy_from_slice(&(1u64 << 30).to_le_bytes());
        buf[first + 24] = 1;
        buf[first + 32] = 0x07;
        let layout = parse_layout(&buf).unwrap();
        assert_eq!(layout.style, Style::Mbr);
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].kind, "NTFS or exFAT");
        assert_eq!(mbr_kind(0xEE), "GPT protective");
    }

    #[test]
    fn extents_give_disk_and_offset() {
        let mut buf = vec![0u8; 8 + 48];
        buf[0] = 2;
        buf[8] = 1;
        buf[16..24].copy_from_slice(&4096u64.to_le_bytes());
        buf[32] = 2;
        buf[40..48].copy_from_slice(&8192u64.to_le_bytes());
        assert_eq!(parse_extents(&buf), [(1, 4096), (2, 8192)]);
        assert_eq!(parse_extents(&buf[..30]), [(1, 4096)]);
    }

    #[test]
    fn link_text_names_generation_lanes_and_a_slow_link() {
        let full = Link {
            speed: Some(4),
            width: Some(4),
            max_speed: Some(4),
            max_width: Some(4),
        };
        assert_eq!(link_text(&full), "PCIe 4.0 x4");
        assert!(!link_below_max(&full));
        let slow = Link {
            speed: Some(3),
            width: Some(2),
            ..full
        };
        assert_eq!(
            link_text(&slow),
            "PCIe 3.0 x2 (the drive can do PCIe 4.0 x4)"
        );
        assert!(link_below_max(&slow));
        let none = Link {
            speed: None,
            width: None,
            max_speed: None,
            max_width: None,
        };
        assert_eq!(link_text(&none), "not reported");
        assert_eq!(pcie_generation(9), None);
    }

    #[test]
    fn identify_reads_version_self_test_and_thresholds() {
        let mut buf = vec![0u8; NVME_IDENTIFY_SIZE];
        buf[4..24].copy_from_slice(b"SERIAL-NOT-READ-1234");
        buf[80..84].copy_from_slice(&0x0001_0400u32.to_le_bytes());
        buf[256] = 0x17;
        buf[266..268].copy_from_slice(&355u16.to_le_bytes());
        buf[268..270].copy_from_slice(&358u16.to_le_bytes());
        buf[316..318].copy_from_slice(&15u16.to_le_bytes());
        let id = parse_nvme_identify(&buf).unwrap();
        assert_eq!(id.version, Some((1, 4, 0)));
        assert_eq!(version_text(id.version), "NVMe 1.4");
        assert!(id.self_test);
        assert_eq!(id.warning_kelvin, 355);
        assert_eq!(id.critical_kelvin, 358);
        assert_eq!(id.extended_test_minutes, 15);
        assert!(!format!("{id:?}").contains("SERIAL"));
        buf[80..84].fill(0);
        buf[256] = 0;
        let old = parse_nvme_identify(&buf).unwrap();
        assert_eq!(old.version, None);
        assert!(!old.self_test);
        assert!(parse_nvme_identify(&buf[..100]).is_none());
    }

    #[test]
    fn self_test_log_lists_results_newest_first() {
        let mut buf = vec![0u8; NVME_SELF_TEST_LOG_SIZE];
        buf[0] = 1;
        buf[1] = 40;
        for index in 0..20 {
            buf[4 + index * 28] = 0x0F;
        }
        buf[4] = 0x10;
        buf[8..16].copy_from_slice(&18_000u64.to_le_bytes());
        buf[4 + 28] = 0x27;
        buf[4 + 28 + 4..4 + 28 + 12].copy_from_slice(&9_000u64.to_le_bytes());
        let log = parse_self_test_log(&buf).unwrap();
        assert_eq!(log.running, Some(("short", 40)));
        assert_eq!(log.results.len(), 2);
        assert_eq!(log.results[0].kind, "short");
        assert_eq!(log.results[0].passed, Some(true));
        assert_eq!(log.results[0].power_on_hours, 18_000);
        assert_eq!(log.results[1].kind, "extended");
        assert_eq!(log.results[1].passed, Some(false));
        buf[0] = 0;
        assert_eq!(parse_self_test_log(&buf).unwrap().running, None);
        assert!(parse_self_test_log(&buf[..500]).is_none());
    }

    #[test]
    fn the_window_opens_on_the_worst_drive_else_the_windows_drive() {
        let healthy = || disk(Health::Nvme(parse_nvme_health(&healthy_nvme()).unwrap()));
        let mut data = healthy();
        data.number = 1;
        data.volumes = vec!['D'];
        let system = healthy();
        assert_eq!(first_shown(&[data.clone(), system.clone()], Some('C')), 1);
        assert_eq!(first_shown(&[data.clone(), system.clone()], None), 0);
        let mut worn = disk(Health::Nvme(parse_nvme_health(&worn_nvme()).unwrap()));
        worn.volumes = vec!['E'];
        assert_eq!(first_shown(&[system.clone(), data, worn], Some('C')), 2);
        assert_eq!(first_shown(&[], Some('C')), 0);
    }

    #[test]
    fn copy_text_holds_the_verdict_figures_and_every_line() {
        let nvme = disk(Health::Nvme(parse_nvme_health(&healthy_nvme()).unwrap()));
        let text = copy_text(&nvme, &found(), Some(false));
        assert!(text.starts_with("Example SSD 1TB\r\nDisk 0"));
        assert!(text.contains("Verdict: Healthy. No problem in the drive's own health data."));
        assert!(text.contains("Data written: 40.0 TB"));
        assert!(text.contains("Partitions (GPT)"));
        assert!(text.contains("Critical warning: none (0x00)"));
        assert!(!text.contains("SERIAL"));
    }
}
