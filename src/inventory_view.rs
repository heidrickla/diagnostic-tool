//! Compact human-readable view over the bounded CIM field catalog.
use std::collections::BTreeMap;

fn field<'a>(fields: &'a BTreeMap<&str, &str>, key: &str) -> &'a str {
    fields.get(key).copied().unwrap_or("Unknown")
}

fn usable_revision(value: &str) -> &str {
    if value.trim().is_empty()
        || [
            "default string",
            "to be filled by o.e.m.",
            "unknown",
            "not specified",
        ]
        .iter()
        .any(|placeholder| value.trim().eq_ignore_ascii_case(placeholder))
    {
        "not reported"
    } else {
        value
    }
}

pub fn summary(raw: &[(String, String)]) -> Vec<String> {
    let fields: BTreeMap<&str, &str> = raw
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    if fields.is_empty() {
        return vec!["Hardware inventory was not collected.".into()];
    }
    let mut lines = vec![
        format!(
            "Computer: {} {}",
            field(&fields, "system.manufacturer"),
            field(&fields, "system.model")
        ),
        format!(
            "Motherboard: {} {} (revision {})",
            field(&fields, "board.manufacturer"),
            field(&fields, "board.model"),
            usable_revision(field(&fields, "board.revision"))
        ),
        match fields.get("cpu.count").and_then(|n| n.parse::<u8>().ok()) {
            Some(count) if count > 1 => {
                format!("Processor: {count} x {}", field(&fields, "cpu.model"))
            }
            _ => format!("Processor: {}", field(&fields, "cpu.model")),
        },
    ];
    let modules: Vec<_> = (0..8)
        .filter_map(|index| {
            let capacity = fields
                .get(format!("ram.{index}.capacity_gib").as_str())?
                .parse::<f64>()
                .ok()?;
            let speed = fields
                .get(format!("ram.{index}.speed_mhz").as_str())
                .copied()
                .unwrap_or("speed unknown");
            Some((capacity, speed))
        })
        .collect();
    if modules.is_empty() {
        lines.push("Memory: Not reported".into());
    } else {
        let total: f64 = modules.iter().map(|(size, _)| size).sum();
        let same_capacity = modules.iter().all(|(size, _)| *size == modules[0].0);
        let same_speed = modules.iter().all(|(_, speed)| *speed == modules[0].1);
        let layout = if same_capacity {
            format!("{} x {} GiB", modules.len(), modules[0].0)
        } else {
            modules
                .iter()
                .map(|(size, _)| format!("{size} GiB"))
                .collect::<Vec<_>>()
                .join(" + ")
        };
        let speed = if same_speed {
            format!(" at {} MHz", modules[0].1)
        } else {
            "; mixed or unknown speeds".into()
        };
        let slots = fields
            .get("ram.slots_reported")
            .filter(|value| value.parse::<usize>().is_ok_and(|n| n >= modules.len()))
            .map(|value| format!("; {}/{} reported slots used", modules.len(), value))
            .unwrap_or_default();
        lines.push(format!("Memory: {total} GiB ({layout}{speed}){slots}"));
    }
    for index in 0..8 {
        let model_key = format!("disk.{index}.model");
        if let Some(model) = fields.get(model_key.as_str()) {
            let reported_capacity = field(&fields, &format!("disk.{index}.capacity_gib"));
            let capacity = if reported_capacity
                .parse::<f64>()
                .is_ok_and(|value| value > 0.0)
            {
                format!("{reported_capacity} GiB")
            } else {
                "capacity unavailable".into()
            };
            lines.push(format!(
                "Storage {}: {} - {} (Windows interface: {})",
                index + 1,
                model,
                capacity,
                field(&fields, &format!("disk.{index}.interface"))
            ));
        }
    }
    lines.extend(graphics(&fields));
    lines.push(format!("Firmware: {}", field(&fields, "bios.version")));
    if let Some(time) = fields.get("collected_at_utc") {
        let shown = crate::clock::parse_utc(time).map_or_else(
            || format!("{time} (UTC)"),
            |t| crate::clock::local(t).long(),
        );
        lines.push(format!("Collected: {shown}"));
    }
    lines
}

/// One line per physical display adapter, then adapters Windows knows but cannot see now
/// (an integrated GPU turned off in the firmware settings, or a card that was removed).
fn graphics(fields: &BTreeMap<&str, &str>) -> Vec<String> {
    let mut lines = Vec::new();
    for index in 0..4 {
        let Some(model) = fields.get(format!("gpu.{index}.model").as_str()) else {
            continue;
        };
        let get = |name: &str| fields.get(format!("gpu.{index}.{name}").as_str()).copied();
        let mut details = Vec::new();
        if let Some(memory) = get("memory_gib").filter(|m| m.parse::<f64>().is_ok_and(|v| v > 0.0))
        {
            details.push(format!("{memory} GiB video memory"));
        }
        match (get("driver_version"), get("driver_date")) {
            (Some(version), Some(date)) => details.push(format!("driver {version} ({date})")),
            (Some(version), None) => details.push(format!("driver {version}")),
            _ => {}
        }
        if let Some(status) = get("status").filter(|s| !s.eq_ignore_ascii_case("OK")) {
            details.push(format!("Windows reports {status}"));
        }
        let details = if details.is_empty() {
            String::new()
        } else {
            format!(" - {}", details.join(", "))
        };
        lines.push(format!("Graphics {}: {model}{details}", index + 1));
    }
    if lines.is_empty() {
        lines.push("Graphics: Not reported".into());
    }
    for index in 0..2 {
        if let Some(model) = fields.get(format!("gpu.inactive.{index}.model").as_str()) {
            lines.push(format!(
                "Inactive graphics: {model} - known to Windows but not active now; it may be turned off in the firmware settings or removed"
            ));
        }
    }
    lines
}

/// One `Module N: part number` line per memory module that reported a part number.
pub fn module_details(raw: &[(String, String)]) -> Vec<String> {
    raw.iter()
        .filter_map(|(key, value)| {
            let index: usize = key
                .strip_prefix("ram.")?
                .strip_suffix(".part")?
                .parse()
                .ok()?;
            Some(format!("Module {}: {value}", index + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_is_condensed_without_inventing_type() {
        let raw = [
            ("ram.0.capacity_gib", "16"),
            ("ram.0.speed_mhz", "5600"),
            ("ram.1.capacity_gib", "16"),
            ("ram.1.speed_mhz", "5600"),
            ("ram.slots_reported", "4"),
            ("ram.0.part", "PART-1"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<Vec<_>>();
        let lines = summary(&raw);
        assert!(
            lines
                .iter()
                .any(|line| line
                    == "Memory: 32 GiB (2 x 16 GiB at 5600 MHz); 2/4 reported slots used")
        );
        assert!(!lines.iter().any(|line| line.contains("DDR")));
        assert_eq!(module_details(&raw), vec!["Module 1: PART-1"]);
    }

    fn lines(raw: &[(&str, &str)]) -> Vec<String> {
        let raw: Vec<_> = raw
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        summary(&raw)
    }

    #[test]
    fn every_physical_adapter_is_listed_with_memory_and_driver() {
        let lines = lines(&[
            ("gpu.0.model", "NVIDIA GeForce RTX 4070 Ti SUPER"),
            ("gpu.0.memory_gib", "16"),
            ("gpu.0.driver_version", "32.0.16.1656"),
            ("gpu.0.driver_date", "2026-08-19"),
            ("gpu.0.status", "OK"),
            ("gpu.1.model", "AMD Radeon(TM) Graphics"),
            ("gpu.1.status", "Error"),
            ("gpu.inactive.0.model", "Old card"),
        ]);
        assert!(lines.contains(
            &"Graphics 1: NVIDIA GeForce RTX 4070 Ti SUPER - 16 GiB video memory, driver 32.0.16.1656 (2026-08-19)".to_string()
        ), "{lines:?}");
        assert!(
            lines.contains(
                &"Graphics 2: AMD Radeon(TM) Graphics - Windows reports Error".to_string()
            ),
            "{lines:?}"
        );
        assert!(lines
            .iter()
            .any(|line| line.starts_with("Inactive graphics: Old card - ")));
    }

    #[test]
    fn no_adapter_reads_not_reported_and_two_processors_are_counted() {
        let lines = lines(&[("cpu.model", "Example CPU"), ("cpu.count", "2")]);
        assert!(
            lines.contains(&"Graphics: Not reported".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"Processor: 2 x Example CPU".to_string()),
            "{lines:?}"
        );
    }

    #[test]
    fn collection_time_is_shown_in_local_words() {
        let raw = vec![(
            "collected_at_utc".to_string(),
            "2026-11-04T02:34:44.6528146Z".to_string(),
        )];
        let expected = crate::clock::local(crate::clock::parse_utc(&raw[0].1).unwrap()).long();
        let lines = summary(&raw);
        assert!(
            lines.contains(&format!("Collected: {expected}")),
            "{lines:?}"
        );
    }

    #[test]
    fn placeholders_and_zero_capacity_are_not_presented_as_hardware_facts() {
        let raw = [
            ("board.revision", "Default string"),
            ("disk.0.model", "Example USB device"),
            ("disk.0.capacity_gib", "0"),
            ("disk.0.interface", "USB"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<Vec<_>>();
        let lines = summary(&raw);
        assert!(lines
            .iter()
            .any(|line| line.contains("revision not reported")));
        assert!(lines.iter().any(|line| line
            == "Storage 1: Example USB device - capacity unavailable (Windows interface: USB)"));
    }
}
