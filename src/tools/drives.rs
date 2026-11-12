//! Drive health from the drives' own data: the NVMe SMART / Health Information log, ATA
//! SMART attributes where Windows lets them be read (through a USB adapter where it passes
//! them), and Windows' temperature and failure prediction properties. Read-only; never asks
//! for elevation.
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{Args, Output, Tool};

pub mod ata;
pub mod details;
pub mod device;
pub mod health;
pub mod read_check;
pub mod sat;
pub mod sct;
pub mod speed;

use health::{Assessment, Disk, Health};

/// The drive window's further reads of disk `number`; see `details::Details`.
pub fn details(number: u32, bus: Option<i32>) -> details::Details {
    crate::live::reading("a disk");
    device::read_details(number, bus)
}

/// Whether this process runs with administrator rights; None when Windows would not say.
pub fn elevated() -> Option<bool> {
    crate::live::reading("this process's administrator rights");
    device::elevated()
}

pub const TOOL: Tool = Tool {
    name: "drives",
    summary: "drive health from NVMe and SMART data: wear, media errors, temperature",
    usage: "\
Usage: toolkit drives
  Lists each physical disk (bus, model, firmware, size, SSD or HDD, drive letters) with
  the drive's own health data: the NVMe health log, or SMART attributes on SATA drives
  and on USB drives whose adapter passes them (those need administrator rights), Windows'
  temperature reading and failure prediction, and the problems found in them. Finishes
  within 20 seconds.",
    run,
};

const TIME_LIMIT: Duration = Duration::from_secs(20);

/// What a run gathered, and whether the time limit cut it short.
pub struct Gathered {
    pub elevated: Option<bool>,
    pub disks: Vec<Disk>,
    pub cut_short: bool,
}

fn run(_: &Args) -> Result<Output, String> {
    let gathered = gather(Instant::now() + TIME_LIMIT);
    Ok(Output {
        text: report_lines(&gathered).join("\n"),
        data: report_json(&gathered),
    })
}

/// Reads every disk on a worker thread; a disk whose driver hangs is reported as cut short
/// rather than holding the tool past `deadline`.
pub fn gather(deadline: Instant) -> Gathered {
    crate::live::reading("the disks");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let volumes = device::volumes_by_disk();
        for number in 0..device::MAX_DISKS {
            if let Some(disk) = device::read_disk(number, &volumes) {
                if sender.send(Some(disk)).is_err() {
                    return;
                }
            }
        }
        let _ = sender.send(None);
    });
    let mut disks = Vec::new();
    let mut cut_short = true;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(left) {
            Ok(Some(disk)) => disks.push(disk),
            Ok(None) => {
                cut_short = false;
                break;
            }
            Err(_) => break,
        }
    }
    Gathered {
        elevated: device::elevated(),
        disks,
        cut_short,
    }
}

pub fn report_lines(gathered: &Gathered) -> Vec<String> {
    let mut lines = vec![format!(
        "Drive health ({})",
        match gathered.elevated {
            Some(true) => "run as administrator",
            Some(false) => "run without administrator rights; SATA and USB SMART need them",
            None => "administrator rights unknown",
        }
    )];
    if gathered.disks.is_empty() {
        lines.push("No physical disk could be found.".into());
    }
    for disk in &gathered.disks {
        lines.push(String::new());
        disk_lines(disk, &health::assess(disk), &mut lines);
    }
    if gathered.cut_short {
        lines.push(String::new());
        lines.push(format!(
            "Cut short: the disks did not all answer within {} seconds; disks after the last one shown were not read.",
            TIME_LIMIT.as_secs()
        ));
    }
    lines
}

/// The model with its vendor, unless the model already starts with it.
pub fn display_name(identity: &health::Identity) -> String {
    if identity.vendor.is_empty()
        || identity.model.starts_with(&identity.vendor)
        || identity.vendor.eq_ignore_ascii_case("NVMe")
    {
        identity.model.clone()
    } else {
        format!("{} {}", identity.vendor, identity.model)
    }
}

/// An ATA attribute's raw value as the text shows it, with its unit.
fn ata_raw(id: u8, attribute: &health::Attribute) -> (u64, Option<&'static str>) {
    match id {
        194 => (u64::from(attribute.raw[0]), Some("C")),
        9 => (attribute.raw_value() & 0xffff_ffff, None),
        _ => (attribute.raw_value(), None),
    }
}

fn disk_lines(disk: &Disk, assessment: &Assessment, lines: &mut Vec<String>) {
    match &disk.identity {
        Ok(identity) => {
            let name = display_name(identity);
            let name = if name.is_empty() {
                "model not reported".into()
            } else {
                name
            };
            let firmware = if identity.firmware.is_empty() {
                "not reported".into()
            } else {
                identity.firmware.clone()
            };
            lines.push(format!("Disk {}: {name}, firmware {firmware}", disk.number));
        }
        Err(why) => lines.push(format!("Disk {}: not identified ({why})", disk.number)),
    }
    let mut facts = Vec::new();
    if let Ok(identity) = &disk.identity {
        facts.push(format!("bus {}", health::bus_name(identity.bus)));
    }
    facts.push(match &disk.solid_state {
        Ok(true) => "SSD".into(),
        Ok(false) => "HDD (seeks)".into(),
        Err(why) => format!("media type unknown ({why})"),
    });
    facts.push(match &disk.size {
        Ok(bytes) => size_text(*bytes),
        Err(why) => format!("size unknown ({why})"),
    });
    if let Ok(identity) = &disk.identity {
        facts.push(
            if identity.removable {
                "removable"
            } else {
                "fixed"
            }
            .into(),
        );
    }
    lines.push(format!("  {}", facts.join(", ")));
    lines.push(format!(
        "  Drive letters: {}",
        if disk.volumes.is_empty() {
            "none".to_string()
        } else {
            disk.volumes
                .iter()
                .map(|letter| format!("{letter}:"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    ));
    match &disk.health {
        Health::Nvme(log) => nvme_lines(log, lines),
        Health::Ata(attributes) => ata_lines(attributes, lines),
        Health::Unread(why) => lines.push(format!("  Health data: not read: {why}")),
    }
    lines.push(match &disk.temperature {
        Ok(t) => format!(
            "  Windows temperature reading: {}, warning at {}, critical at {}",
            celsius(t.current),
            celsius(t.warning),
            celsius(t.critical)
        ),
        Err(why) => format!("  Windows temperature reading: unavailable ({why})"),
    });
    lines.push(match &disk.predicts_failure {
        Ok(true) => "  Windows failure prediction: the drive is predicted to fail".into(),
        Ok(false) => "  Windows failure prediction: no failure predicted".into(),
        Err(why) => format!("  Windows failure prediction: unavailable ({why})"),
    });
    if !assessment.problems.is_empty() {
        lines.push(format!(
            "  Verdict: {} problem{} found",
            assessment.problems.len(),
            if assessment.problems.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        for problem in &assessment.problems {
            lines.push(format!("    Problem: {problem}"));
        }
    } else if assessment.health_read {
        lines.push("  Verdict: no problem in the health data".into());
    } else {
        lines.push(
            "  Verdict: the drive's health data was not read, so its health is not known".into(),
        );
    }
}

fn nvme_lines(log: &health::NvmeHealth, lines: &mut Vec<String>) {
    let warnings = health::critical_warning_names(log.critical_warning);
    lines.push("  NVMe health log (SMART / Health Information, log page 02h):".into());
    lines.push(format!(
        "    Critical warning: {}",
        if warnings.is_empty() {
            "none".to_string()
        } else {
            warnings.join("; ")
        }
    ));
    lines.push(format!(
        "    Temperature: {}",
        match log.celsius() {
            Some(c) => format!("{c} C"),
            None => "not reported".into(),
        }
    ));
    lines.push(format!(
        "    Available spare: {} % (threshold {} %); endurance used: {} %",
        log.available_spare, log.spare_threshold, log.percentage_used
    ));
    lines.push(format!(
        "    Data read: {}; written: {}",
        amount(health::data_units_tb(log.data_units_read)),
        amount(health::data_units_tb(log.data_units_written))
    ));
    lines.push(format!(
        "    Power-on hours: {}; power cycles: {}; unsafe shutdowns: {}",
        log.power_on_hours, log.power_cycles, log.unsafe_shutdowns
    ));
    lines.push(format!(
        "    Media and data integrity errors: {}; error log entries: {}",
        log.media_errors, log.error_log_entries
    ));
    lines.push(format!(
        "    Minutes above warning temperature: {}; above critical: {}",
        log.warning_temperature_minutes, log.critical_temperature_minutes
    ));
}

fn ata_lines(attributes: &[health::Attribute], lines: &mut Vec<String>) {
    lines.push("  SMART attributes (id, name, current, worst, raw):".into());
    let mut shown = 0;
    for (id, name) in health::WATCHED {
        if let Some(attribute) = attributes.iter().find(|a| a.id == *id) {
            let raw = match ata_raw(*id, attribute) {
                (value, Some(unit)) => format!("{value} {unit}"),
                (value, None) => value.to_string(),
            };
            lines.push(format!(
                "    {id:>3} {name}: {}, {}, {raw}",
                attribute.current, attribute.worst
            ));
            shown += 1;
        }
    }
    if shown == 0 {
        lines.push("    none of the failure-predicting attributes are reported".into());
    }
    if attributes.len() > shown {
        lines.push(format!(
            "    {} other attributes not shown",
            attributes.len() - shown
        ));
    }
}

/// A reading or, when it failed, `{"unavailable": reason}`.
fn reading<T>(result: &Result<T, String>, value: impl FnOnce(&T) -> Value) -> Value {
    match result {
        Ok(found) => value(found),
        Err(why) => super::events::unavailable(why),
    }
}

/// A counter that may exceed what JSON numbers hold exactly is written as a string then.
fn counter(value: u128) -> Value {
    u64::try_from(value).map_or_else(|_| Value::String(value.to_string()), Value::from)
}

pub fn report_json(gathered: &Gathered) -> Value {
    json!({
        "tool": "drives",
        "administrator_rights": gathered.elevated,
        "disks": gathered.disks.iter().map(disk_json).collect::<Vec<_>>(),
        "cut_short": gathered.cut_short.then(|| format!(
            "the disks did not all answer within {} seconds; disks after the last one listed were not read",
            TIME_LIMIT.as_secs()
        )),
    })
}

fn disk_json(disk: &Disk) -> Value {
    let assessment = health::assess(disk);
    let identity = match &disk.identity {
        Ok(identity) => json!({
            "name": display_name(identity),
            "firmware": identity.firmware,
            "bus": health::bus_name(identity.bus),
            "removable": identity.removable,
        }),
        Err(why) => super::events::unavailable(why),
    };
    let health_json = match &disk.health {
        Health::Nvme(log) => nvme_json(log),
        Health::Ata(attributes) => ata_json(attributes),
        Health::Unread(why) => super::events::unavailable(why),
    };
    json!({
        "number": disk.number,
        "identity": identity,
        "solid_state": reading(&disk.solid_state, |&ssd| ssd.into()),
        "size_bytes": reading(&disk.size, |&bytes| bytes.into()),
        "drive_letters": disk.volumes.iter().map(|letter| format!("{letter}:")).collect::<Vec<_>>(),
        "health": health_json,
        "windows_temperature_c": reading(&disk.temperature, |t| json!({
            "current": t.current,
            "warning_at": t.warning,
            "critical_at": t.critical,
        })),
        "windows_failure_predicted": reading(&disk.predicts_failure, |&predicted| predicted.into()),
        "verdict": {
            "health_read": assessment.health_read,
            "problems": assessment.problems,
        },
    })
}

fn nvme_json(log: &health::NvmeHealth) -> Value {
    json!({
        "source": "nvme_health_log",
        "critical_warnings": health::critical_warning_names(log.critical_warning),
        "temperature_c": log.celsius(),
        "available_spare_percent": log.available_spare,
        "spare_threshold_percent": log.spare_threshold,
        "endurance_used_percent": log.percentage_used,
        "data_read_tb": health::data_units_tb(log.data_units_read),
        "data_written_tb": health::data_units_tb(log.data_units_written),
        "power_on_hours": counter(log.power_on_hours),
        "power_cycles": counter(log.power_cycles),
        "unsafe_shutdowns": counter(log.unsafe_shutdowns),
        "media_errors": counter(log.media_errors),
        "error_log_entries": counter(log.error_log_entries),
        "minutes_above_warning_temperature": log.warning_temperature_minutes,
        "minutes_above_critical_temperature": log.critical_temperature_minutes,
    })
}

fn ata_json(attributes: &[health::Attribute]) -> Value {
    let watched: Vec<Value> = health::WATCHED
        .iter()
        .filter_map(|(id, name)| {
            let attribute = attributes.iter().find(|a| a.id == *id)?;
            let (raw, unit) = ata_raw(*id, attribute);
            Some(json!({
                "id": id,
                "name": name,
                "current": attribute.current,
                "worst": attribute.worst,
                "raw": raw,
                "raw_unit": unit,
            }))
        })
        .collect();
    json!({
        "source": "smart_attributes",
        "other_attributes_not_listed": attributes.len() - watched.len(),
        "attributes": watched,
    })
}

fn celsius(value: Option<i16>) -> String {
    value.map_or("not reported".into(), |c| format!("{c} C"))
}

/// Terabytes as TB, or as GB below 1 TB so small amounts do not show as 0.0.
fn amount(tb: f64) -> String {
    if tb >= 1.0 {
        format!("{tb:.1} TB")
    } else {
        format!("{:.1} GB", tb * 1000.0)
    }
}

/// Any size in decimal units, as drive sizes are quoted and as `size_text` gives a drive's:
/// "885 B", "4.1 kB", "512.0 MB", "31.0 GB".
pub fn bytes_text(bytes: u64) -> String {
    let b = bytes as f64;
    // Thresholds a little under each unit, so 999,999 bytes shows as 1.0 MB, not 1000.0 kB.
    if b >= 999.95e6 {
        size_text(bytes)
    } else if b >= 999.95e3 {
        format!("{:.1} MB", b / 1e6)
    } else if bytes >= 1000 {
        format!("{:.1} kB", b / 1e3)
    } else {
        format!("{bytes} B")
    }
}

pub fn size_text(bytes: u64) -> String {
    if bytes == 0 {
        return "no media".into();
    }
    let gb = bytes as f64 / 1e9;
    if gb >= 1000.0 {
        format!("{:.2} TB", gb / 1000.0)
    } else {
        format!("{gb:.1} GB")
    }
}

#[cfg(test)]
mod tests {
    use super::health::fixtures::*;
    use super::health::*;
    use super::*;

    #[test]
    fn sizes_read_in_decimal_units_at_every_scale() {
        assert_eq!(bytes_text(0), "0 B");
        assert_eq!(bytes_text(885), "885 B");
        assert_eq!(bytes_text(4078), "4.1 kB");
        assert_eq!(bytes_text(999_999), "1.0 MB");
        assert_eq!(bytes_text(648_374_272), "648.4 MB");
        assert_eq!(bytes_text(31_029_460_992), "31.0 GB");
        assert_eq!(bytes_text(31_029_460_992), size_text(31_029_460_992));
        assert_eq!(bytes_text(2_000_398_934_016), "2.00 TB");
    }

    #[test]
    fn report_shows_health_and_a_verdict_per_disk() {
        let healthy = disk(Health::Nvme(parse_nvme_health(&healthy_nvme()).unwrap()));
        let mut worn = disk(Health::Nvme(parse_nvme_health(&worn_nvme()).unwrap()));
        worn.number = 1;
        let mut usb = disk(Health::Unread("this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)".into()));
        usb.number = 3;
        usb.size = Ok(0);
        usb.temperature = Err("the driver does not support it".into());
        let mut sata = disk(Health::Ata(
            parse_smart_attributes(&pending_smart()).unwrap(),
        ));
        sata.number = 4;
        let text = report_lines(&Gathered {
            elevated: Some(false),
            disks: vec![healthy, worn, usb, sata],
            cut_short: true,
        })
        .join("\n");
        assert!(text.contains("run without administrator rights"));
        assert!(text.contains("Disk 0: Example SSD 1TB, firmware 1.0"));
        assert!(text.contains("bus NVMe, SSD, 1.00 TB, fixed"));
        assert!(text.contains("Drive letters: C:"));
        assert!(text.contains("Data read: 52.0 TB; written: 40.0 TB"));
        assert!(text.contains("Verdict: no problem in the health data"));
        assert!(text.contains("Verdict: 2 problems found"));
        assert!(text.contains("Problem: 95 % of the rated endurance is used"));
        assert!(text.contains("not read: this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)"));
        assert!(text.contains("no media"));
        assert!(text.contains("health is not known"));
        assert!(text.contains("197 current pending sectors: 100, 100, 8"));
        assert!(text.contains("194 temperature: 60, 45, 41 C"));
        assert!(text.contains("Cut short"));
    }

    #[test]
    fn json_agrees_with_the_text_on_each_disk() {
        let mut worn = disk(Health::Nvme(parse_nvme_health(&worn_nvme()).unwrap()));
        worn.number = 1;
        let mut usb = disk(Health::Unread("this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)".into()));
        usb.number = 3;
        usb.size = Ok(0);
        usb.temperature = Err("the driver does not support it".into());
        let mut sata = disk(Health::Ata(
            parse_smart_attributes(&pending_smart()).unwrap(),
        ));
        sata.number = 4;
        let gathered = Gathered {
            elevated: Some(false),
            disks: vec![worn, usb, sata],
            cut_short: true,
        };
        let text = report_lines(&gathered).join("\n");
        let data = report_json(&gathered);
        assert_eq!(data["administrator_rights"], false);
        let nvme = &data["disks"][0];
        assert_eq!(nvme["number"], 1);
        assert_eq!(nvme["health"]["endurance_used_percent"], 95);
        assert!(text.contains("endurance used: 95 %"));
        assert_eq!(nvme["verdict"]["problems"].as_array().unwrap().len(), 2);
        assert!(text.contains("Verdict: 2 problems found"));
        assert!(text.contains(nvme["verdict"]["problems"][0].as_str().unwrap()));
        assert!(nvme["size_bytes"].as_u64().unwrap() > 0);
        let usb = &data["disks"][1];
        assert_eq!(
            usb["health"]["unavailable"],
            "this USB adapter does not pass SMART commands (the adapter answered ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00)"
        );
        assert_eq!(
            usb["windows_temperature_c"]["unavailable"],
            "the driver does not support it"
        );
        assert_eq!(usb["verdict"]["health_read"], false);
        let sata = &data["disks"][2];
        let pending = sata["health"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"] == 197)
            .unwrap();
        assert_eq!(pending["raw"], 8);
        assert!(text.contains("197 current pending sectors: 100, 100, 8"));
        assert!(data["cut_short"].is_string() && text.contains("Cut short"));
        let again: Value = serde_json::from_str(&data.to_string()).unwrap();
        assert_eq!(again, data);
    }

    #[test]
    fn counters_beyond_json_numbers_become_strings() {
        assert_eq!(counter(7), json!(7));
        assert_eq!(counter(u128::MAX), json!(u128::MAX.to_string()));
    }

    #[test]
    fn no_disks_is_said_plainly() {
        let text = report_lines(&Gathered {
            elevated: None,
            disks: Vec::new(),
            cut_short: false,
        })
        .join("\n");
        assert!(text.contains("No physical disk could be found."));
        assert!(text.contains("administrator rights unknown"));
        assert_eq!(amount(0.0256), "25.6 GB");
        assert_eq!(size_text(0), "no media");
    }

    /// Prints what the drive window reads about each disk on this PC; run with --ignored.
    #[test]
    #[ignore]
    fn live_details_of_this_pc() {
        let gathered = gather(Instant::now() + Duration::from_secs(12));
        println!("elevated: {:?}", elevated());
        for disk in &gathered.disks {
            let bus = disk.identity.as_ref().ok().map(|i| i.bus);
            let found = details(disk.number, bus);
            let verdict = details::verdict(disk);
            println!(
                "disk {}: {:?} {:?}",
                disk.number, verdict.grade, verdict.reasons
            );
            println!("  link: {:?}", found.link.as_ref().map(details::link_text));
            println!(
                "  trim: {:?}, windows trim: {:?}",
                found.trim, found.windows_trim
            );
            println!("  identify: {:?}", found.identify);
            println!("  self-test: {:?}", found.self_test);
            println!("  layout: {:?}", found.layout);
            println!("  volumes: {:?}", found.volumes);
            for figure in details::figures(disk) {
                println!("  {}: {} ({:?})", figure.label, figure.value, figure.grade);
            }
        }
    }

    #[test]
    fn live_read_of_this_pc_finishes_and_reports() {
        let started = Instant::now();
        let gathered = gather(Instant::now() + Duration::from_secs(12));
        let lines = report_lines(&gathered);
        assert!(started.elapsed() < Duration::from_secs(15));
        let data = report_json(&gathered);
        assert_eq!(
            data["disks"].as_array().unwrap().len(),
            gathered.disks.len()
        );
        let parsed: Value = serde_json::from_str(&data.to_string()).unwrap();
        assert_eq!(parsed["tool"], "drives");
        assert!(lines[0].starts_with("Drive health"));
        for disk in &gathered.disks {
            let assessment = health::assess(disk);
            assert!(assessment.health_read || matches!(disk.health, Health::Unread(_)));
        }
    }
}
