//! Laptop battery wear: design against full-charge capacity, cycle count and charge state,
//! read from the battery class driver and the system power status.
use serde_json::{json, Value};

use super::{Args, Output, Tool};
use crate::events;

pub const TOOL: Tool = Tool {
    name: "battery",
    summary: "laptop battery wear: design against full-charge capacity, cycles",
    usage: "Usage: toolkit battery",
    run,
};

const CAPABILITY_RELATIVE: u32 = 0x4000_0000;
const POWER_ON_LINE: u32 = 0x1;
const POWER_DISCHARGING: u32 = 0x2;
const POWER_CHARGING: u32 = 0x4;
const POWER_CRITICAL: u32 = 0x8;
const UNKNOWN: u32 = 0xFFFF_FFFF;
const UNKNOWN_RATE: i32 = i32::MIN;
const WEAR_FLAG_BELOW_PERCENT: u32 = 60;
const CYCLE_FLAG_ABOVE: u32 = 500;

/// What the system reports for the machine as a whole.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SystemPower {
    /// 0 off mains, 1 on mains, 255 unknown.
    pub ac_line: u8,
    /// Bit flags; 128 means the system has no battery, 255 unknown.
    pub battery_flag: u8,
    /// 0 to 100, 255 unknown.
    pub percent: u8,
    /// Seconds of charge left, `u32::MAX` unknown.
    pub seconds_left: u32,
}

/// Raw readings for one battery; a field is `None` when its query failed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reading {
    pub manufacturer: Option<String>,
    pub name: Option<String>,
    pub capabilities: Option<u32>,
    pub chemistry: Option<String>,
    pub designed: Option<u32>,
    pub full: Option<u32>,
    pub cycles: Option<u32>,
    pub power_state: Option<u32>,
    pub remaining: Option<u32>,
    pub rate: Option<i32>,
    pub millivolts: Option<u32>,
    /// Why a query could not be read, for the output.
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Wear {
    Percent(u32),
    /// The full charge is above the design value.
    AboveDesign,
    /// Capacities are relative (percent), so wear cannot be worked out.
    Relative,
    Unknown,
}

fn run(_: &Args) -> Result<Output, String> {
    Ok(output(system_power(), read_batteries()))
}

/// Text and JSON from one set of readings; a battery list that could not be read says so.
fn output(power: SystemPower, batteries: Result<Vec<Reading>, String>) -> Output {
    match batteries {
        Ok(batteries) => Output {
            text: report(power, &batteries).join("\n"),
            data: report_json(power, &batteries),
        },
        Err(reason) => Output {
            text: unavailable_lines(power, &reason).join("\n"),
            data: json!({
                "tool": "battery",
                "system": power_json(power),
                "batteries": super::events::unavailable(&format!("the battery list could not be read ({reason})")),
            }),
        },
    }
}

fn power_json(power: SystemPower) -> Value {
    json!({
        "mains": match power.ac_line {
            0 => Value::from(false),
            1 => Value::from(true),
            _ => Value::Null,
        },
        "charge_percent": (power.percent <= 100).then_some(power.percent),
        "seconds_left": (power.seconds_left != UNKNOWN).then_some(power.seconds_left),
        "system_reports_no_battery": power.battery_flag == 128,
    })
}

/// The same readings and flags as `report`, as JSON. Capacities are in mWh, or in percent
/// when the battery reports them relative.
pub fn report_json(power: SystemPower, batteries: &[Reading]) -> Value {
    let items: Vec<Value> = batteries
        .iter()
        .enumerate()
        .map(|(index, battery)| {
            let relative = is_relative(battery);
            let label = [battery.manufacturer.as_deref(), battery.name.as_deref()]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let wear = match wear(battery) {
                Wear::Percent(p) => json!({ "percent": p }),
                Wear::AboveDesign => {
                    json!({ "percent": 0, "note": "full charge is at or above design" })
                }
                Wear::Relative => {
                    super::events::unavailable("this battery reports capacity in percent only")
                }
                Wear::Unknown => super::events::unavailable("capacity values missing or zero"),
            };
            json!({
                "number": index + 1,
                "model": (!label.is_empty()).then_some(label),
                "chemistry": battery.chemistry.as_deref().filter(|c| !c.is_empty()),
                "capacity_unit": if relative { "percent" } else { "mWh" },
                "designed_capacity": known(battery.designed),
                "full_charge_capacity": known(battery.full),
                "wear": wear,
                "cycle_count": known(battery.cycles).filter(|c| *c != 0),
                "state": battery.power_state.map(power_words),
                "charge_now": known(battery.remaining),
                "rate_mw": battery.rate.filter(|r| *r != UNKNOWN_RATE),
                "voltage_mv": known(battery.millivolts),
                "unavailable": battery.failures,
                "flags": flags(battery),
            })
        })
        .collect();
    json!({
        "tool": "battery",
        "system": power_json(power),
        "battery_count": items.len(),
        "note": (items.is_empty() && power.battery_flag != 128).then_some(
            "the system power status does not say \"no battery\", so a battery the driver does not expose may exist"
        ),
        "batteries": items,
    })
}

fn known(value: Option<u32>) -> Option<u32> {
    value.filter(|v| *v != UNKNOWN)
}

fn is_relative(reading: &Reading) -> bool {
    reading
        .capabilities
        .is_some_and(|c| c & CAPABILITY_RELATIVE != 0)
}

pub fn wear(reading: &Reading) -> Wear {
    if is_relative(reading) {
        return Wear::Relative;
    }
    match (known(reading.designed), known(reading.full)) {
        (Some(design), Some(full)) if design > 0 && full > 0 => {
            if full >= design {
                Wear::AboveDesign
            } else {
                Wear::Percent(100 - (u64::from(full) * 100 / u64::from(design)) as u32)
            }
        }
        _ => Wear::Unknown,
    }
}

/// Problems worth telling the owner about, one line each.
pub fn flags(reading: &Reading) -> Vec<String> {
    let mut found = Vec::new();
    if let (Some(design), Some(full)) = (known(reading.designed), known(reading.full)) {
        if !is_relative(reading) && design > 0 && full > 0 {
            let held = (u64::from(full) * 100 / u64::from(design)) as u32;
            if held < WEAR_FLAG_BELOW_PERCENT {
                found.push(format!(
                    "Holds only {held} % of its design capacity (flagged under {WEAR_FLAG_BELOW_PERCENT} %): the battery is worn out."
                ));
            }
        }
    }
    if let Some(cycles) = known(reading.cycles).filter(|c| *c > CYCLE_FLAG_ABOVE) {
        found.push(format!(
            "{cycles} charge cycles (flagged over {CYCLE_FLAG_ABOVE}): a battery this used is near the end of its life."
        ));
    }
    if reading.power_state.is_some_and(|s| s & POWER_CRITICAL != 0) {
        found.push("The battery reports a critical state.".into());
    }
    found
}

fn power_words(state: u32) -> String {
    let mut words = Vec::new();
    if state & POWER_ON_LINE != 0 {
        words.push("on mains");
    }
    if state & POWER_CHARGING != 0 {
        words.push("charging");
    }
    if state & POWER_DISCHARGING != 0 {
        words.push("discharging");
    }
    if state & POWER_CRITICAL != 0 {
        words.push("critical");
    }
    if words.is_empty() {
        "idle".into()
    } else {
        words.join(", ")
    }
}

fn capacity_text(value: Option<u32>, relative: bool) -> String {
    match known(value) {
        None => "unknown".into(),
        Some(v) if relative => format!("{v} %"),
        Some(v) => format!("{v} mWh"),
    }
}

fn overall_lines(power: SystemPower) -> Vec<String> {
    let mains = match power.ac_line {
        0 => "off (running on battery)",
        1 => "on",
        _ => "unknown",
    };
    let mut line = format!("Mains power: {mains}.");
    if power.percent <= 100 {
        line.push_str(&format!(" Charge: {} %.", power.percent));
    }
    if power.seconds_left != UNKNOWN {
        let minutes = power.seconds_left / 60;
        line.push_str(&format!(
            " About {} h {:02} min left.",
            minutes / 60,
            minutes % 60
        ));
    }
    vec![line]
}

pub fn report(power: SystemPower, batteries: &[Reading]) -> Vec<String> {
    if batteries.is_empty() {
        let mut lines = vec!["No battery: this PC runs on mains power only.".to_string()];
        if power.battery_flag != 128 {
            lines.push(
                "Note: the system power status does not say \"no battery\", so a battery the driver does not expose may exist."
                    .into(),
            );
        }
        return lines;
    }
    let mut lines = overall_lines(power);
    let mut flagged = Vec::new();
    for (index, battery) in batteries.iter().enumerate() {
        let relative = is_relative(battery);
        lines.push(format!("Battery {}:", index + 1));
        let label = [battery.manufacturer.as_deref(), battery.name.as_deref()]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !label.is_empty() {
            lines.push(format!("  Model: {label}"));
        }
        if let Some(chemistry) = battery.chemistry.as_deref().filter(|c| !c.is_empty()) {
            lines.push(format!("  Chemistry: {chemistry}"));
        }
        lines.push(format!(
            "  Designed capacity: {}",
            capacity_text(battery.designed, relative)
        ));
        lines.push(format!(
            "  Full-charge capacity: {}",
            capacity_text(battery.full, relative)
        ));
        lines.push(match wear(battery) {
            Wear::Percent(p) => format!("  Wear: {p} % (full charge against design)"),
            Wear::AboveDesign => "  Wear: none (full charge is at or above design)".into(),
            Wear::Relative => {
                "  Wear: not computable (this battery reports capacity in percent only)".into()
            }
            Wear::Unknown => "  Wear: unknown (capacity values missing or zero)".into(),
        });
        lines.push(match known(battery.cycles) {
            Some(0) | None => "  Cycle count: not reported".into(),
            Some(c) => format!("  Cycle count: {c}"),
        });
        if let Some(state) = battery.power_state {
            lines.push(format!("  State: {}", power_words(state)));
        }
        lines.push(format!(
            "  Charge now: {}",
            capacity_text(battery.remaining, relative)
        ));
        if let Some(rate) = battery.rate.filter(|r| *r != UNKNOWN_RATE) {
            lines.push(format!("  Rate: {rate} mW"));
        }
        if let Some(mv) = known(battery.millivolts) {
            lines.push(format!("  Voltage: {:.2} V", f64::from(mv) / 1000.0));
        }
        for failure in &battery.failures {
            lines.push(format!("  Unavailable: {failure}"));
        }
        for flag in flags(battery) {
            flagged.push(format!("Battery {}: {flag}", index + 1));
        }
    }
    if flagged.is_empty() {
        lines.push("Flags: none.".into());
    } else {
        lines.push("Flags:".into());
        lines.extend(flagged.into_iter().map(|f| format!("  {f}")));
    }
    lines
}

fn unavailable_lines(power: SystemPower, reason: &str) -> Vec<String> {
    let mut lines = vec![format!(
        "Unavailable: the battery list could not be read ({reason})."
    )];
    lines.extend(overall_lines(power));
    lines
}

/// Chemistry bytes as text, for example "LION"; empty or non-printing bytes give `None`.
pub fn chemistry_text(bytes: [u8; 4]) -> Option<String> {
    let text: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    (!text.is_empty() && text.chars().all(|c| c.is_ascii_graphic())).then_some(text)
}

fn system_power() -> SystemPower {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut status = SYSTEM_POWER_STATUS::default();
    // SAFETY: status is a valid out pointer for the call.
    if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
        return SystemPower {
            ac_line: 255,
            battery_flag: 255,
            percent: 255,
            seconds_left: UNKNOWN,
        };
    }
    SystemPower {
        ac_line: status.ACLineStatus,
        battery_flag: status.BatteryFlag,
        percent: status.BatteryLifePercent,
        seconds_left: status.BatteryLifeTime,
    }
}

fn utf16_text(buffer: &[u8]) -> Option<String> {
    let units: Vec<u16> = buffer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|u| *u != 0)
        .collect();
    let text = String::from_utf16_lossy(&units);
    let text = events::redact(text.trim(), &events::local_names());
    let text: String = text.chars().filter(|c| !c.is_control()).take(60).collect();
    (!text.is_empty()).then_some(text)
}

fn read_batteries() -> Result<Vec<Reading>, String> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
        SetupDiGetDeviceInterfaceDetailW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
        SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W,
    };
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Power::GUID_DEVICE_BATTERY;

    // SAFETY: the class GUID is a valid constant and the other arguments are null.
    let set = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVICE_BATTERY,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if set == INVALID_HANDLE_VALUE as isize {
        // SAFETY: reads the calling thread's last error.
        return Err(format!("device list error {}", unsafe { GetLastError() }));
    }
    let mut readings = Vec::new();
    for index in 0..16 {
        // SAFETY: the structure is plain data; cbSize is set before use.
        let mut data: SP_DEVICE_INTERFACE_DATA = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        // SAFETY: set is a live device info set and data is a sized out structure.
        if unsafe {
            SetupDiEnumDeviceInterfaces(
                set,
                std::ptr::null(),
                &GUID_DEVICE_BATTERY,
                index,
                &mut data,
            )
        } == 0
        {
            break;
        }
        let mut needed = 0u32;
        // SAFETY: a null buffer asks only for the required size.
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                set,
                &data,
                std::ptr::null_mut(),
                0,
                &mut needed,
                std::ptr::null_mut(),
            )
        };
        if needed < 8 {
            readings.push(failed("the device path could not be read"));
            continue;
        }
        // u64 backing keeps the buffer aligned for the detail structure.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let detail = buffer.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        // SAFETY: buffer holds at least `needed` bytes; cbSize is the fixed header size.
        let got = unsafe {
            (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            SetupDiGetDeviceInterfaceDetailW(
                set,
                &data,
                detail,
                needed,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if got == 0 {
            readings.push(failed("the device path could not be read"));
            continue;
        }
        // SAFETY: on success DevicePath is a NUL-terminated string inside the buffer.
        let path = unsafe { std::ptr::addr_of!((*detail).DevicePath) as *const u16 };
        readings.push(read_one(path));
    }
    // SAFETY: set came from SetupDiGetClassDevsW and is destroyed once.
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    Ok(readings)
}

fn failed(reason: &str) -> Reading {
    Reading {
        failures: vec![reason.into()],
        ..Default::default()
    }
}

fn ioctl<I, O>(handle: *mut core::ffi::c_void, code: u32, input: &I, output: &mut O) -> bool {
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut returned = 0u32;
    // SAFETY: input and output are plain repr(C) values whose sizes are passed exactly.
    unsafe {
        DeviceIoControl(
            handle,
            code,
            input as *const I as *const _,
            std::mem::size_of::<I>() as u32,
            output as *mut O as *mut _,
            std::mem::size_of::<O>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        ) != 0
    }
}

fn read_one(path: *const u16) -> Reading {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Power::{
        BatteryDeviceName, BatteryInformation, BatteryManufactureName, BATTERY_INFORMATION,
        BATTERY_QUERY_INFORMATION, BATTERY_STATUS, BATTERY_WAIT_STATUS,
        IOCTL_BATTERY_QUERY_INFORMATION, IOCTL_BATTERY_QUERY_STATUS, IOCTL_BATTERY_QUERY_TAG,
    };

    // SAFETY: path is a NUL-terminated wide string from the device interface detail.
    let handle = unsafe {
        CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return failed("the battery device could not be opened");
    }
    let mut reading = Reading::default();
    let mut tag = 0u32;
    if !ioctl(handle, IOCTL_BATTERY_QUERY_TAG, &0u32, &mut tag) || tag == 0 {
        // SAFETY: handle was opened above.
        unsafe { CloseHandle(handle) };
        return failed("the battery reports no tag (it may have been removed)");
    }
    let query = |level| BATTERY_QUERY_INFORMATION {
        BatteryTag: tag,
        InformationLevel: level,
        AtRate: 0,
    };

    let mut info = BATTERY_INFORMATION::default();
    if ioctl(
        handle,
        IOCTL_BATTERY_QUERY_INFORMATION,
        &query(BatteryInformation),
        &mut info,
    ) {
        reading.capabilities = Some(info.Capabilities);
        reading.chemistry = chemistry_text(info.Chemistry);
        reading.designed = Some(info.DesignedCapacity);
        reading.full = Some(info.FullChargedCapacity);
        reading.cycles = Some(info.CycleCount);
    } else {
        reading
            .failures
            .push("capacity and cycle information was refused".into());
    }
    for (level, slot) in [
        (BatteryManufactureName, &mut reading.manufacturer),
        (BatteryDeviceName, &mut reading.name),
    ] {
        let mut text = [0u8; 128];
        if ioctl(
            handle,
            IOCTL_BATTERY_QUERY_INFORMATION,
            &query(level),
            &mut text,
        ) {
            *slot = utf16_text(&text);
        }
    }
    let wait = BATTERY_WAIT_STATUS {
        BatteryTag: tag,
        ..Default::default()
    };
    let mut status = BATTERY_STATUS::default();
    if ioctl(handle, IOCTL_BATTERY_QUERY_STATUS, &wait, &mut status) {
        reading.power_state = Some(status.PowerState);
        reading.remaining = Some(status.Capacity);
        reading.rate = Some(status.Rate);
        reading.millivolts = Some(status.Voltage);
    } else {
        reading.failures.push("charge status was refused".into());
    }
    // SAFETY: handle was opened above and is closed once.
    unsafe { CloseHandle(handle) };
    reading
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINS: SystemPower = SystemPower {
        ac_line: 1,
        battery_flag: 128,
        percent: 255,
        seconds_left: UNKNOWN,
    };

    fn healthy() -> Reading {
        Reading {
            manufacturer: Some("MakerCo".into()),
            name: Some("PackX".into()),
            capabilities: Some(0x8000_0000),
            chemistry: Some("LION".into()),
            designed: Some(50_000),
            full: Some(45_000),
            cycles: Some(120),
            power_state: Some(POWER_ON_LINE | POWER_CHARGING),
            remaining: Some(30_000),
            rate: Some(15_000),
            millivolts: Some(12_300),
            failures: vec![],
        }
    }

    #[test]
    fn wear_is_full_charge_against_design() {
        assert_eq!(wear(&healthy()), Wear::Percent(10));
        let mut b = healthy();
        b.full = Some(55_000);
        assert_eq!(wear(&b), Wear::AboveDesign);
    }

    #[test]
    fn relative_zero_and_unknown_capacities_give_no_wear_number() {
        let mut b = healthy();
        b.capabilities = Some(CAPABILITY_RELATIVE);
        b.designed = Some(100);
        b.full = Some(100);
        assert_eq!(wear(&b), Wear::Relative);
        for (design, full) in [
            (0, 40_000),
            (50_000, 0),
            (UNKNOWN, 40_000),
            (50_000, UNKNOWN),
        ] {
            let mut b = healthy();
            b.designed = Some(design);
            b.full = Some(full);
            assert_eq!(wear(&b), Wear::Unknown);
        }
    }

    #[test]
    fn flags_cover_worn_cycled_and_critical_batteries() {
        assert!(flags(&healthy()).is_empty());
        let mut worn = healthy();
        worn.full = Some(29_000);
        assert!(flags(&worn)[0].contains("58 %"));
        let mut edge = healthy();
        edge.full = Some(30_000);
        assert!(flags(&edge).is_empty());
        let mut old = healthy();
        old.cycles = Some(501);
        assert!(flags(&old)[0].contains("501 charge cycles"));
        old.cycles = Some(500);
        assert!(flags(&old).is_empty());
        old.cycles = Some(UNKNOWN);
        assert!(flags(&old).is_empty());
        let mut critical = healthy();
        critical.power_state = Some(POWER_DISCHARGING | POWER_CRITICAL);
        assert!(flags(&critical)[0].contains("critical"));
    }

    #[test]
    fn no_battery_says_mains_only() {
        assert_eq!(
            report(MAINS, &[]),
            ["No battery: this PC runs on mains power only."]
        );
        let unsure = SystemPower {
            battery_flag: 255,
            ..MAINS
        };
        assert_eq!(report(unsure, &[]).len(), 2);
    }

    #[test]
    fn report_shows_a_normal_battery() {
        let power = SystemPower {
            ac_line: 1,
            battery_flag: 8,
            percent: 60,
            seconds_left: UNKNOWN,
        };
        let text = report(power, &[healthy()]).join("\n");
        assert!(text.contains("Wear: 10 %"));
        assert!(text.contains("Cycle count: 120"));
        assert!(text.contains("State: on mains, charging"));
        assert!(text.contains("Voltage: 12.30 V"));
        assert!(text.contains("Flags: none."));
    }

    #[test]
    fn report_handles_partial_and_relative_batteries() {
        let partial = Reading {
            failures: vec!["capacity and cycle information was refused".into()],
            power_state: Some(POWER_DISCHARGING),
            remaining: Some(UNKNOWN),
            rate: Some(i32::MIN),
            ..Default::default()
        };
        let text = report(MAINS, &[partial]).join("\n");
        assert!(text.contains("Wear: unknown"));
        assert!(text.contains("Charge now: unknown"));
        assert!(text.contains("Unavailable: capacity and cycle"));
        assert!(!text.contains("Rate:"));
        let relative = Reading {
            capabilities: Some(CAPABILITY_RELATIVE),
            designed: Some(100),
            full: Some(97),
            ..Default::default()
        };
        let text = report(MAINS, &[relative]).join("\n");
        assert!(text.contains("not computable"));
        assert!(text.contains("Designed capacity: 100 %"));
    }

    #[test]
    fn chemistry_and_text_decoding() {
        assert_eq!(chemistry_text(*b"LION"), Some("LION".into()));
        assert_eq!(chemistry_text([0, 0, 0, 0]), None);
        assert_eq!(chemistry_text([1, 2, 3, 4]), None);
        let bytes: Vec<u8> = "Pack 1\0junk"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(utf16_text(&bytes), Some("Pack 1".into()));
    }

    #[test]
    fn this_pc_reports_without_error() {
        let output = run(&Args::default()).unwrap();
        assert!(!output.text.is_empty());
        let parsed: Value = serde_json::from_str(&output.data.to_string()).unwrap();
        assert_eq!(parsed["tool"], "battery");
    }

    #[test]
    fn json_agrees_with_the_text_on_wear_cycles_and_flags() {
        let power = SystemPower {
            ac_line: 1,
            battery_flag: 8,
            percent: 60,
            seconds_left: UNKNOWN,
        };
        let mut worn = healthy();
        worn.full = Some(29_000);
        worn.cycles = Some(501);
        let text = report(power, std::slice::from_ref(&worn)).join("\n");
        let data = report_json(power, &[worn]);
        let battery = &data["batteries"][0];
        assert_eq!(battery["wear"]["percent"], 42);
        assert!(text.contains("Wear: 42 %"));
        assert_eq!(battery["cycle_count"], 501);
        assert!(text.contains("Cycle count: 501"));
        assert_eq!(battery["flags"].as_array().unwrap().len(), 2);
        assert!(text.contains(battery["flags"][0].as_str().unwrap()));
        assert_eq!(battery["state"], "on mains, charging");
        assert_eq!(battery["capacity_unit"], "mWh");
        assert_eq!(battery["designed_capacity"], 50_000);
        assert_eq!(data["system"]["mains"], true);
        assert_eq!(data["system"]["charge_percent"], 60);
        assert!(data["system"]["seconds_left"].is_null());
    }

    #[test]
    fn json_says_no_battery_partial_relative_and_unreadable() {
        let data = report_json(MAINS, &[]);
        assert_eq!(data["battery_count"], 0);
        assert!(data["note"].is_null());
        let unsure = SystemPower {
            battery_flag: 255,
            ..MAINS
        };
        assert!(report_json(unsure, &[])["note"].is_string());
        let partial = Reading {
            failures: vec!["capacity and cycle information was refused".into()],
            remaining: Some(UNKNOWN),
            ..Default::default()
        };
        let data = report_json(MAINS, &[partial]);
        assert_eq!(
            data["batteries"][0]["wear"]["unavailable"],
            "capacity values missing or zero"
        );
        assert!(data["batteries"][0]["charge_now"].is_null());
        assert_eq!(
            data["batteries"][0]["unavailable"][0],
            "capacity and cycle information was refused"
        );
        let relative = Reading {
            capabilities: Some(CAPABILITY_RELATIVE),
            designed: Some(100),
            full: Some(97),
            ..Default::default()
        };
        let data = report_json(MAINS, &[relative]);
        assert_eq!(data["batteries"][0]["capacity_unit"], "percent");
        assert!(data["batteries"][0]["wear"]["unavailable"].is_string());
        let failed = output(MAINS, Err("access denied".into()));
        assert!(failed.text.contains("Unavailable: the battery list"));
        assert!(failed.data["batteries"]["unavailable"]
            .as_str()
            .unwrap()
            .contains("access denied"));
    }
}
