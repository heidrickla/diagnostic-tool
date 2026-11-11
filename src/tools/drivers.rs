//! Drivers: the third-party packages in the driver store (provider, class, version, date,
//! signer) and the devices Windows reports a problem code for. Read-only; the instance
//! ids of devices carry serial numbers and are never read into the output.
mod sys;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::hash::sys::Check;
use super::hash::{interpret_status, rfc3339};
use super::{Args, Output, Tool};

pub const TOOL: Tool = Tool {
    name: "drivers",
    summary: "third-party driver packages and devices with a problem code",
    usage: "\
Usage: toolkit drivers [--all]
  --all   also list Microsoft inbox packages and the devices that are not present

Lists the third-party driver packages in the driver store (INF name, provider, class,
version, date, signer), then the devices that are present and report a problem code
(for example 28, drivers not installed) with what the code means, then a count of
devices that are not present but still hold a driver. Finishes within 25 seconds.",
    run,
};

const TIME_LIMIT: Duration = Duration::from_secs(25);
const PACKAGE_LIMIT: usize = 150;
const PACKAGE_LIMIT_ALL: usize = 500;
const DEVICE_LIMIT: usize = 60;
const ABSENT_LIMIT: usize = 40;

/// What an INF file says about its package.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InfFacts {
    pub provider: Option<String>,
    pub class: Option<String>,
    pub version: Option<String>,
    /// `YYYY-MM-DD`.
    pub date: Option<String>,
    pub catalog: Option<String>,
}

/// An INF's text: UTF-16 with a byte order mark, UTF-8 with or without one, or ANSI.
pub fn decode_inf(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&byte| char::from(byte)).collect(),
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
        .trim()
}

/// Replaces each `%name%` with its [Strings] entry; `None` when one has no entry.
fn expand(value: &str, strings: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        if end == 0 {
            out.push('%');
        } else {
            out.push_str(strings.get(&after[..end].to_ascii_lowercase())?);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// `mm/dd/yyyy` as `yyyy-mm-dd`, checked.
fn inf_date(text: &str) -> Option<String> {
    let mut parts = text.trim().split('/');
    let (month, day, year): (u32, u32, u32) = (
        parts.next()?.trim().parse().ok()?,
        parts.next()?.trim().parse().ok()?,
        parts.next()?.trim().parse().ok()?,
    );
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    (1990..=2100)
        .contains(&year)
        .then(|| format!("{year:04}-{month:02}-{day:02}"))
}

/// The [Version] section of an INF, with its provider's `%name%` looked up in [Strings].
/// Anything missing or garbled comes back as `None`, not as a guess.
pub fn parse_inf(text: &str) -> InfFacts {
    let mut version: BTreeMap<String, String> = BTreeMap::new();
    let mut strings: BTreeMap<String, String> = BTreeMap::new();
    let mut localized: BTreeMap<String, String> = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), unquote(value).to_string());
        match section.as_str() {
            "version" => {
                version.entry(key).or_insert(value);
            }
            "strings" => {
                strings.entry(key).or_insert(value);
            }
            s if s.starts_with("strings.") => {
                localized.entry(key).or_insert(value);
            }
            _ => {}
        }
    }
    for (key, value) in localized {
        strings.entry(key).or_insert(value);
    }
    let resolve = |key: &str| -> Option<String> {
        let value = version.get(key)?;
        let value = expand(value, &strings)?;
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    };
    let (date, number) = match version.get("driverver") {
        Some(value) => match value.split_once(',') {
            Some((date, number)) => (inf_date(date), Some(number.trim().to_string())),
            None => (inf_date(value), None),
        },
        None => (None, None),
    };
    let catalog = version
        .keys()
        .filter(|key| key.starts_with("catalogfile"))
        .find_map(|key| resolve(key));
    InfFacts {
        provider: resolve("provider"),
        class: resolve("class"),
        version: number.filter(|n| !n.is_empty()),
        date,
        catalog,
    }
}

/// `oem12.inf`, the name Windows gives a third-party package.
pub fn is_published_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .strip_prefix("oem")
        .and_then(|rest| rest.strip_suffix(".inf"))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// The INF's original name from its driver store folder (`nv_dispi.inf_amd64_1a2b3c`).
pub fn original_name(store_folder: &str) -> Option<String> {
    let name = store_folder.rsplit(['\\', '/']).next()?;
    let end = name.to_ascii_lowercase().find(".inf_")?;
    (end > 0).then(|| format!("{}.inf", &name[..end]))
}

/// The meaning of a Configuration Manager problem code.
pub fn problem_meaning(code: u32) -> &'static str {
    match code {
        1 => "not configured correctly",
        2 => "the device loader failed",
        3 => "out of memory",
        9 => "Windows cannot identify the hardware (invalid data)",
        10 => "the device cannot start",
        12 => "no free resources for the device",
        14 => "the device cannot work until the PC restarts",
        16 => "Windows cannot identify all the resources the device uses",
        18 => "the drivers need to be reinstalled",
        19 => "the device's registry settings are damaged",
        21 => "Windows is removing the device",
        22 => "the device is disabled",
        24 => "the device is not present, not working properly, or lacks drivers",
        28 => "drivers not installed",
        29 => "the device is disabled by the firmware",
        31 => "the device is not working properly; Windows cannot load its drivers",
        32 => "the driver's service is disabled",
        33 => "Windows cannot determine the device's resources",
        37 => "Windows cannot initialize the device driver",
        38 => "the previous instance of the driver is still in memory",
        39 => "the driver is damaged or missing",
        40 => "Windows cannot access the driver's service key",
        41 => "the driver loaded but the device cannot be found",
        42 => "a duplicate device is already running",
        43 => "Windows stopped the device because it reported a problem",
        44 => "an application or service halted the device",
        45 => "the device is not connected",
        46 => "the device is unavailable during shutdown",
        47 => "the device is prepared for safe removal",
        48 => "Windows blocked the driver from starting",
        49 => "the registry is too large to add another device",
        50 => "Windows could not set the device's properties",
        51 => "the device is waiting on another device",
        52 => "Windows cannot verify the driver's digital signature",
        53 => "a kernel debugger is using the device",
        54 => "the device failed and is being reset",
        _ => "no description is known for this code",
    }
}

/// One device worth reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRow {
    pub name: String,
    pub class: String,
    /// The problem code; 0 for none.
    pub problem: u32,
    pub present: bool,
}

/// The devices read: how many are present, and the ones with a problem or a leftover driver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceScan {
    pub present: usize,
    pub rows: Vec<DeviceRow>,
    /// The time limit ended the scan early.
    pub cut_short: bool,
}

/// What a package's signer check came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    Signed(String),
    SignedUnnamed,
    Invalid(String),
    Unavailable(String),
    NotChecked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub inf: String,
    pub original: Option<String>,
    pub facts: Result<InfFacts, String>,
    pub signer: Signer,
}

pub fn signer_from(reading: Check) -> Signer {
    match interpret_status(reading.status) {
        Ok(()) => match reading.signer {
            Some(name) => Signer::Signed(name),
            None => Signer::SignedUnnamed,
        },
        Err(reason) => Signer::Invalid(reason),
    }
}

/// Everything gathered, before any judging.
pub struct Gathered {
    pub third_party: Result<Vec<Package>, String>,
    pub inbox: Result<Vec<Package>, String>,
    pub devices: Result<DeviceScan, String>,
    pub packages_cut: usize,
}

fn run(args: &Args) -> Result<Output, String> {
    let all = args.switch("--all");
    let start = Instant::now();
    let gathered = sys::gather(all, start + TIME_LIMIT);
    Ok(Output {
        text: render(&gathered, all),
        data: to_json(&gathered, all),
    })
}

fn class_name(class: &str) -> &str {
    if class.is_empty() {
        "no class"
    } else {
        class
    }
}

fn package_line(package: &Package) -> String {
    let mut line = format!("  {}", package.inf);
    if let Some(original) = &package.original {
        line.push_str(&format!(" ({original})"));
    }
    match &package.facts {
        Ok(f) => {
            line.push_str(&format!(
                ": {}, class {}, version {}, dated {}",
                f.provider.as_deref().unwrap_or("provider not readable"),
                f.class.as_deref().map(class_name).unwrap_or("not readable"),
                f.version.as_deref().unwrap_or("not readable"),
                f.date.as_deref().unwrap_or("not readable"),
            ));
        }
        Err(reason) => line.push_str(&format!(": INF unreadable, {reason}")),
    }
    match &package.signer {
        Signer::Signed(name) => line.push_str(&format!(", signed by {name}")),
        Signer::SignedUnnamed => line.push_str(", signed (signer name not readable)"),
        Signer::Invalid(reason) => line.push_str(&format!(", signature not valid: {reason}")),
        Signer::Unavailable(reason) => line.push_str(&format!(", signer unavailable: {reason}")),
        Signer::NotChecked => {}
    }
    line
}

fn sorted(packages: &[Package]) -> Vec<&Package> {
    let key = |p: &Package| {
        let facts = p.facts.as_ref().ok();
        (
            facts
                .and_then(|f| f.class.clone())
                .unwrap_or_default()
                .to_ascii_lowercase(),
            facts
                .and_then(|f| f.provider.clone())
                .unwrap_or_default()
                .to_ascii_lowercase(),
            p.inf.len(),
            p.inf.clone(),
        )
    };
    let mut list: Vec<&Package> = packages.iter().collect();
    list.sort_by_key(|p| key(p));
    list
}

fn problem_devices(scan: &DeviceScan) -> Vec<&DeviceRow> {
    let mut rows: Vec<&DeviceRow> = scan
        .rows
        .iter()
        .filter(|r| r.present && r.problem != 0)
        .collect();
    rows.sort_by(|a, b| (a.problem, &a.class, &a.name).cmp(&(b.problem, &b.class, &b.name)));
    rows
}

fn absent_by_class(scan: &DeviceScan) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in scan.rows.iter().filter(|r| !r.present) {
        *counts
            .entry(class_name(&row.class).to_string())
            .or_insert(0) += 1;
    }
    counts
}

pub fn render(gathered: &Gathered, all: bool) -> String {
    let mut lines = Vec::new();
    let limit = if all {
        PACKAGE_LIMIT_ALL
    } else {
        PACKAGE_LIMIT
    };
    match &gathered.third_party {
        Ok(packages) => {
            lines.push(format!(
                "Third-party driver packages in the driver store: {}",
                packages.len()
            ));
            for package in sorted(packages).into_iter().take(limit) {
                lines.push(package_line(package));
            }
            if packages.len() > limit {
                lines.push(format!("  ... {} more not listed", packages.len() - limit));
            }
            if gathered.packages_cut > 0 {
                lines.push(format!(
                    "  The time limit ended signer checks; {} packages have no signer reading.",
                    gathered.packages_cut
                ));
            }
        }
        Err(reason) => lines.push(format!(
            "Third-party driver packages: unavailable, {reason}"
        )),
    }
    if all {
        match &gathered.inbox {
            Ok(packages) => {
                lines.push(format!("Windows inbox packages: {}", packages.len()));
                for package in sorted(packages).into_iter().take(limit) {
                    lines.push(package_line(package));
                }
                if packages.len() > limit {
                    lines.push(format!("  ... {} more not listed", packages.len() - limit));
                }
            }
            Err(reason) => lines.push(format!("Windows inbox packages: unavailable, {reason}")),
        }
    }
    match &gathered.devices {
        Ok(scan) => {
            let problems = problem_devices(scan);
            if problems.is_empty() {
                lines.push(format!(
                    "Devices with a problem code: none among {} present devices",
                    scan.present
                ));
            } else {
                lines.push(format!(
                    "Devices with a problem code: {} of {} present devices",
                    problems.len(),
                    scan.present
                ));
                for row in problems.iter().take(DEVICE_LIMIT) {
                    lines.push(format!(
                        "  {} ({}): code {}, {}",
                        row.name,
                        class_name(&row.class),
                        row.problem,
                        problem_meaning(row.problem)
                    ));
                }
                if problems.len() > DEVICE_LIMIT {
                    lines.push(format!(
                        "  ... {} more not listed",
                        problems.len() - DEVICE_LIMIT
                    ));
                }
            }
            let absent = absent_by_class(scan);
            let total: usize = absent.values().sum();
            if total == 0 {
                lines.push("Devices not present that still hold a driver: none".into());
            } else {
                let mut by_class: Vec<(&String, &usize)> = absent.iter().collect();
                by_class.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                let summary: Vec<String> = by_class
                    .iter()
                    .take(8)
                    .map(|(class, count)| format!("{class} {count}"))
                    .collect();
                lines.push(format!(
                    "Devices not present that still hold a driver: {total} ({})",
                    summary.join(", ")
                ));
                if all {
                    let mut names: Vec<&DeviceRow> =
                        scan.rows.iter().filter(|r| !r.present).collect();
                    names.sort_by(|a, b| (&a.class, &a.name).cmp(&(&b.class, &b.name)));
                    for row in names.iter().take(ABSENT_LIMIT) {
                        lines.push(format!("  {} ({})", row.name, class_name(&row.class)));
                    }
                    if names.len() > ABSENT_LIMIT {
                        lines.push(format!(
                            "  ... {} more not listed",
                            names.len() - ABSENT_LIMIT
                        ));
                    }
                }
            }
            if scan.cut_short {
                lines.push(
                    "The time limit ended the device scan early; the list may be incomplete."
                        .into(),
                );
            }
        }
        Err(reason) => lines.push(format!("Devices: unavailable, {reason}")),
    }
    lines.join("\n")
}

fn signer_json(signer: &Signer) -> Value {
    match signer {
        Signer::Signed(name) => json!({"status": "signed", "signer": name}),
        Signer::SignedUnnamed => json!({"status": "signed", "signer": null}),
        Signer::Invalid(reason) => json!({"status": "invalid", "reason": reason}),
        Signer::Unavailable(reason) => json!({"status": "unavailable", "unavailable": reason}),
        Signer::NotChecked => json!({"status": "not_checked"}),
    }
}

fn package_json(package: &Package) -> Value {
    let facts = match &package.facts {
        Ok(f) => json!({
            "provider": f.provider,
            "class": f.class,
            "version": f.version,
            "date": f.date,
            "catalog_file": f.catalog,
        }),
        Err(reason) => json!({"unavailable": reason}),
    };
    json!({
        "inf": package.inf,
        "original_inf": package.original,
        "details": facts,
        "signature": signer_json(&package.signer),
    })
}

fn packages_json(packages: &Result<Vec<Package>, String>, limit: usize) -> Value {
    match packages {
        Ok(list) => json!({
            "count": list.len(),
            "listed": sorted(list).into_iter().take(limit).map(package_json).collect::<Vec<_>>(),
            "truncated": list.len() > limit,
        }),
        Err(reason) => json!({"unavailable": reason}),
    }
}

pub fn to_json(gathered: &Gathered, all: bool) -> Value {
    let limit = if all {
        PACKAGE_LIMIT_ALL
    } else {
        PACKAGE_LIMIT
    };
    let devices = match &gathered.devices {
        Ok(scan) => {
            let problems = problem_devices(scan);
            let absent = absent_by_class(scan);
            json!({
                "present_count": scan.present,
                "with_problem_count": problems.len(),
                "with_problem": problems.iter().take(DEVICE_LIMIT).map(|r| json!({
                    "name": r.name,
                    "class": r.class,
                    "problem_code": r.problem,
                    "meaning": problem_meaning(r.problem),
                })).collect::<Vec<_>>(),
                "not_present_with_driver_count": absent.values().sum::<usize>(),
                "not_present_by_class": absent,
                "scan_cut_short": scan.cut_short,
            })
        }
        Err(reason) => json!({"unavailable": reason}),
    };
    json!({
        "third_party_packages": packages_json(&gathered.third_party, limit),
        "inbox_packages": if all {
            packages_json(&gathered.inbox, limit)
        } else {
            json!({"unavailable": "listed only with --all"})
        },
        "signer_checks_skipped_by_time_limit": gathered.packages_cut,
        "devices": devices,
        "generated_at": rfc3339(std::time::SystemTime::now()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORMAL: &str = include_str!("../../tests/fixtures/drivers/normal.inf");
    const LOCALIZED: &str = include_str!("../../tests/fixtures/drivers/localized.inf");
    const PARTIAL: &str = include_str!("../../tests/fixtures/drivers/partial.inf");
    const MALFORMED: &str = include_str!("../../tests/fixtures/drivers/malformed.inf");
    const DEVICES: &str = include_str!("../../tests/fixtures/drivers/devices.txt");

    #[test]
    fn a_normal_inf_gives_all_five_facts() {
        let facts = parse_inf(NORMAL);
        assert_eq!(facts.provider.as_deref(), Some("Example Audio Inc."));
        assert_eq!(facts.class.as_deref(), Some("MEDIA"));
        assert_eq!(facts.version.as_deref(), Some("6.0.9500.1"));
        assert_eq!(facts.date.as_deref(), Some("2024-03-05"));
        assert_eq!(facts.catalog.as_deref(), Some("exaudio.cat"));
    }

    #[test]
    fn strings_come_from_the_localized_section_when_the_plain_one_is_absent() {
        let facts = parse_inf(LOCALIZED);
        assert_eq!(facts.provider.as_deref(), Some("Example Net Ltd"));
        assert_eq!(facts.catalog.as_deref(), Some("exnet.cat"));
    }

    #[test]
    fn a_partial_inf_leaves_missing_facts_empty() {
        let facts = parse_inf(PARTIAL);
        assert_eq!(facts.provider, None, "an unresolved %name% is not guessed");
        assert_eq!(facts.class.as_deref(), Some("Net"));
        assert_eq!(facts.version, None);
        assert_eq!(facts.date.as_deref(), Some("2023-12-01"));
    }

    #[test]
    fn a_malformed_inf_gives_nothing_and_does_not_panic() {
        let facts = parse_inf(MALFORMED);
        assert_eq!(facts.date, None);
        assert_eq!(facts.version.as_deref(), Some("1.0"));
        assert_eq!(parse_inf(""), InfFacts::default());
        assert_eq!(parse_inf("\u{0}\u{1}[[[==%%%"), InfFacts::default());
    }

    #[test]
    fn utf16_utf8_and_ansi_inf_files_decode() {
        let utf16: Vec<u8> = [0xFFu8, 0xFE]
            .into_iter()
            .chain(NORMAL.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(parse_inf(&decode_inf(&utf16)), parse_inf(NORMAL));
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(NORMAL.as_bytes());
        assert_eq!(parse_inf(&decode_inf(&bom)), parse_inf(NORMAL));
        let ansi = decode_inf(b"[Version]\nProvider=\"Caf\xE9 Corp\"\n");
        assert_eq!(parse_inf(&ansi).provider.as_deref(), Some("Caf\u{e9} Corp"));
    }

    #[test]
    fn published_and_original_names() {
        assert!(is_published_name("oem12.inf"));
        assert!(is_published_name("OEM3.INF"));
        assert!(!is_published_name("oem.inf"));
        assert!(!is_published_name("usb.inf"));
        assert!(!is_published_name("oem1x.inf"));
        assert_eq!(
            original_name(
                r"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_1a2b3c4d5e6f"
            ),
            Some("nv_dispi.inf".into())
        );
        assert_eq!(original_name(r"C:\x\strange"), None);
    }

    #[test]
    fn problem_codes_have_the_documented_meanings() {
        assert_eq!(problem_meaning(28), "drivers not installed");
        assert!(problem_meaning(10).contains("cannot start"));
        assert!(problem_meaning(43).contains("reported a problem"));
        assert!(problem_meaning(9999).contains("no description"));
    }

    fn rows() -> Vec<DeviceRow> {
        DEVICES
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|line| {
                let f: Vec<&str> = line.split('|').collect();
                assert_eq!(f.len(), 4, "{line}");
                DeviceRow {
                    name: f[0].into(),
                    class: f[1].into(),
                    problem: f[2].parse().unwrap(),
                    present: f[3] == "present",
                }
            })
            .collect()
    }

    fn gathered() -> Gathered {
        let package = |inf: &str, facts: Result<InfFacts, String>, signer| Package {
            inf: inf.into(),
            original: Some("exaudio.inf".into()),
            facts,
            signer,
        };
        Gathered {
            third_party: Ok(vec![
                package(
                    "oem2.inf",
                    Ok(parse_inf(NORMAL)),
                    Signer::Signed("Microsoft Windows Hardware Compatibility Publisher".into()),
                ),
                package(
                    "oem7.inf",
                    Ok(parse_inf(PARTIAL)),
                    Signer::Invalid("the signature does not verify (0x80096004)".into()),
                ),
                package(
                    "oem9.inf",
                    Err("access denied".into()),
                    Signer::Unavailable("access denied".into()),
                ),
            ]),
            inbox: Ok(vec![]),
            devices: Ok(DeviceScan {
                present: 312,
                rows: rows(),
                cut_short: false,
            }),
            packages_cut: 0,
        }
    }

    #[test]
    fn the_text_lists_packages_problems_and_leftovers() {
        let text = render(&gathered(), false);
        assert!(text.contains("Third-party driver packages in the driver store: 3"));
        assert!(text.contains("oem2.inf (exaudio.inf): Example Audio Inc., class MEDIA, version 6.0.9500.1, dated 2024-03-05, signed by Microsoft Windows Hardware"));
        assert!(text.contains("provider not readable"));
        assert!(text.contains("signature not valid"));
        assert!(text.contains("INF unreadable, access denied"));
        assert!(text.contains("Devices with a problem code: 3 of 312 present devices"));
        assert!(text.contains("PCI Device (Other): code 28, drivers not installed"));
        assert!(text.contains("code 10, the device cannot start"));
        assert!(text.contains("Devices not present that still hold a driver: 3 (USB 2, Volume 1)"));
        assert!(
            !text.contains("Old USB Stick"),
            "absent names only with --all"
        );
        let all = render(&gathered(), true);
        assert!(all.contains("Old USB Stick (USB)"));
        assert!(all.contains("Windows inbox packages: 0"));
    }

    #[test]
    fn unavailable_sources_are_said_plainly() {
        let gathered = Gathered {
            third_party: Err("the INF folder could not be read".into()),
            inbox: Err("x".into()),
            devices: Err("Windows did not list the devices".into()),
            packages_cut: 0,
        };
        let text = render(&gathered, false);
        assert!(text.contains("Third-party driver packages: unavailable, the INF folder"));
        assert!(text.contains("Devices: unavailable, Windows did not list"));
        assert!(!text.contains("none among"));
        let data = to_json(&gathered, false);
        assert!(data["devices"]["unavailable"].is_string());
        assert!(data["third_party_packages"]["unavailable"].is_string());
    }

    #[test]
    fn json_output_parses_and_holds_the_readings() {
        let text = serde_json::to_string_pretty(&to_json(&gathered(), false)).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["third_party_packages"]["count"], 3);
        assert_eq!(back["devices"]["with_problem_count"], 3);
        assert_eq!(back["devices"]["with_problem"][0]["problem_code"], 10);
        assert_eq!(back["devices"]["not_present_by_class"]["USB"], 2);
        assert_eq!(
            back["inbox_packages"]["unavailable"],
            "listed only with --all"
        );
    }

    #[test]
    fn no_instance_id_shape_appears_in_output() {
        let text = render(&gathered(), true);
        assert!(
            !text.contains("VEN_") && !text.contains("USB\\VID"),
            "{text}"
        );
    }

    #[test]
    fn the_tool_reads_this_pc() {
        let started = Instant::now();
        let gathered = sys::gather(false, Instant::now() + TIME_LIMIT);
        let packages = gathered.third_party.as_ref().expect("the INF folder reads");
        assert!(packages.iter().all(|p| is_published_name(&p.inf)));
        let scan = gathered.devices.as_ref().expect("devices enumerate");
        assert!(scan.present > 5);
        assert!(started.elapsed() < Duration::from_secs(15));
        let text = render(&gathered, false);
        let data = to_json(&gathered, false);
        assert!(serde_json::from_str::<Value>(&data.to_string()).is_ok());
        assert!(text.contains("Third-party driver packages"));
    }
}
