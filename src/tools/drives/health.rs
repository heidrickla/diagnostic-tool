//! Pure parsing and judging of what the drives return: descriptors, the NVMe health log,
//! ATA SMART attributes and Windows' temperature property. No Win32 calls here.

/// What the storage driver says the disk is. The serial number is never read.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub vendor: String,
    pub model: String,
    pub firmware: String,
    pub bus: i32,
    pub removable: bool,
}

/// NVMe bus type in STORAGE_BUS_TYPE.
pub const BUS_NVME: i32 = 17;
pub const BUS_USB: i32 = 7;
pub const BUS_ATA: i32 = 3;
pub const BUS_SATA: i32 = 11;
pub const BUS_RAID: i32 = 8;

pub fn bus_name(bus: i32) -> &'static str {
    match bus {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        4 => "IEEE 1394",
        5 => "SSA",
        6 => "Fibre Channel",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD card",
        13 => "MMC",
        14 => "virtual",
        15 => "virtual disk file",
        16 => "Storage Spaces",
        17 => "NVMe",
        18 => "storage class memory",
        19 => "UFS",
        _ => "unknown",
    }
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn i16_at(buf: &[u8], at: usize) -> Option<i16> {
    u16_at(buf, at).map(|value| value as i16)
}

pub(crate) fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

pub(crate) fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(at..at + 8)?.try_into().ok()?))
}

fn u128_at(buf: &[u8], at: usize) -> Option<u128> {
    Some(u128::from_le_bytes(buf.get(at..at + 16)?.try_into().ok()?))
}

/// A NUL-terminated ASCII string at `offset` within the descriptor, printable characters
/// only, trimmed. Offset 0 means the driver gave none.
fn descriptor_string(buf: &[u8], offset: u32) -> String {
    let offset = offset as usize;
    if offset == 0 || offset >= buf.len() {
        return String::new();
    }
    let bytes = &buf[offset..];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text: String = bytes[..end]
        .iter()
        .map(|&b| b as char)
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// STORAGE_DEVICE_DESCRIPTOR from IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceProperty).
/// Layout: RemovableMedia at 10, vendor, product and revision offsets at 12, 16, 20
/// (serial offset at 24 is skipped), BusType at 28.
pub fn parse_device_descriptor(buf: &[u8]) -> Option<Identity> {
    if buf.len() < 36 {
        return None;
    }
    let size = u32_at(buf, 4)? as usize;
    let buf = &buf[..size.clamp(36, buf.len())];
    Some(Identity {
        vendor: descriptor_string(buf, u32_at(buf, 12)?),
        model: descriptor_string(buf, u32_at(buf, 16)?),
        firmware: descriptor_string(buf, u32_at(buf, 20)?),
        bus: u32_at(buf, 28)? as i32,
        removable: buf[10] != 0,
    })
}

/// The serial number in a STORAGE_DEVICE_DESCRIPTOR (its offset is at 24), or empty.
pub fn parse_descriptor_serial(buf: &[u8]) -> String {
    if buf.len() < 36 {
        return String::new();
    }
    let size = u32_at(buf, 4).unwrap_or(0) as usize;
    let buf = &buf[..size.clamp(36, buf.len())];
    descriptor_string(buf, u32_at(buf, 24).unwrap_or(0))
}

/// DEVICE_SEEK_PENALTY_DESCRIPTOR: true when the drive is solid state (no seek penalty).
pub fn parse_seek_penalty(buf: &[u8]) -> Option<bool> {
    if buf.len() < 9 || u32_at(buf, 4)? < 9 {
        return None;
    }
    Some(buf[8] == 0)
}

/// DISK_GEOMETRY_EX: DiskSize follows the 24-byte DISK_GEOMETRY.
pub fn parse_geometry_size(buf: &[u8]) -> Option<u64> {
    u64_at(buf, 24)
}

/// Windows' StorageDeviceTemperatureProperty, in degrees Celsius.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Temperature {
    pub current: Option<i16>,
    pub warning: Option<i16>,
    pub critical: Option<i16>,
}

/// STORAGE_TEMPERATURE_DATA_DESCRIPTOR: CriticalTemperature at 8, WarningTemperature at 10,
/// InfoCount at 12, then 16-byte STORAGE_TEMPERATURE_INFO entries from 24 (Temperature at
/// +2). Zero or below is taken as not reported.
pub fn parse_temperature(buf: &[u8]) -> Option<Temperature> {
    let reported = |value: i16| (value > 0).then_some(value);
    let count = u16_at(buf, 12)?;
    let current = if count > 0 {
        i16_at(buf, 24 + 2).and_then(reported)
    } else {
        None
    };
    Some(Temperature {
        current,
        warning: reported(i16_at(buf, 10)?),
        critical: reported(i16_at(buf, 8)?),
    })
}

/// VOLUME_DISK_EXTENTS: the disk numbers a volume lies on.
pub fn parse_disk_extents(buf: &[u8]) -> Vec<u32> {
    let count = u32_at(buf, 0).unwrap_or(0) as usize;
    (0..count.min(64))
        .map_while(|index| u32_at(buf, 8 + index * 24))
        .collect()
}

/// VOLUME_DISK_EXTENTS with offsets: (disk number, starting offset, length) per extent.
pub fn parse_volume_extents(buf: &[u8]) -> Vec<(u32, u64, u64)> {
    let count = u32_at(buf, 0).unwrap_or(0) as usize;
    (0..count.min(64))
        .map_while(|index| {
            let at = 8 + index * 24;
            Some((
                u32_at(buf, at)?,
                u64_at(buf, at + 8)?,
                u64_at(buf, at + 16)?,
            ))
        })
        .collect()
}

/// STORAGE_PROTOCOL_DATA_DESCRIPTOR returned for a protocol-specific query: the protocol
/// data starts at 8 + ProtocolDataOffset (offset at 24, length at 28).
pub fn protocol_data(buf: &[u8], wanted: usize) -> Result<&[u8], String> {
    let (Some(offset), Some(length)) = (u32_at(buf, 24), u32_at(buf, 28)) else {
        return Err("the driver's reply was too short".into());
    };
    let start = 8 + offset as usize;
    let length = length as usize;
    if length < wanted || start + wanted > buf.len() {
        return Err(format!(
            "the driver returned {length} bytes of log data where {wanted} were expected"
        ));
    }
    Ok(&buf[start..start + wanted])
}

/// The SMART / Health Information log page (Log Page Identifier 02h), as laid out in the
/// NVM Express Base Specification, Get Log Page command, "SMART / Health Information"
/// (section 5.16.1.3 in revision 2.0). Little-endian; counters are 128-bit.
#[derive(Debug, Clone, PartialEq)]
pub struct NvmeHealth {
    pub critical_warning: u8,
    pub temperature_kelvin: u16,
    pub available_spare: u8,
    pub spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_minutes: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub error_log_entries: u128,
    pub warning_temperature_minutes: u32,
    pub critical_temperature_minutes: u32,
    /// Temperature sensors 1 to 8 in kelvin; 0 means the sensor is not implemented.
    pub sensors_kelvin: [u16; 8],
    /// Thermal management temperatures 1 and 2: transition counts and total seconds.
    pub thermal_transitions: [u32; 2],
    pub thermal_seconds: [u32; 2],
}

pub const NVME_HEALTH_LOG_SIZE: usize = 512;

/// Byte 0 critical warning, 2:1 composite temperature (K), 3 available spare, 4 spare
/// threshold, 5 percentage used, 47:32 data units read, 63:48 written, 79:64 and 95:80 host
/// read and write commands, 111:96 busy minutes, 127:112 power cycles, 143:128 power-on hours,
/// 159:144 unsafe shutdowns, 175:160 media errors, 191:176 error log entries, 195:192 and
/// 199:196 warning and critical temp minutes, 215:200 sensors, 231:216 thermal management.
pub fn parse_nvme_health(log: &[u8]) -> Option<NvmeHealth> {
    if log.len() < NVME_HEALTH_LOG_SIZE {
        return None;
    }
    Some(NvmeHealth {
        critical_warning: log[0],
        temperature_kelvin: u16_at(log, 1)?,
        available_spare: log[3],
        spare_threshold: log[4],
        percentage_used: log[5],
        data_units_read: u128_at(log, 32)?,
        data_units_written: u128_at(log, 48)?,
        host_read_commands: u128_at(log, 64)?,
        host_write_commands: u128_at(log, 80)?,
        controller_busy_minutes: u128_at(log, 96)?,
        power_cycles: u128_at(log, 112)?,
        power_on_hours: u128_at(log, 128)?,
        unsafe_shutdowns: u128_at(log, 144)?,
        media_errors: u128_at(log, 160)?,
        error_log_entries: u128_at(log, 176)?,
        warning_temperature_minutes: u32_at(log, 192)?,
        critical_temperature_minutes: u32_at(log, 196)?,
        sensors_kelvin: std::array::from_fn(|i| u16_at(log, 200 + 2 * i).unwrap_or(0)),
        thermal_transitions: [u32_at(log, 216)?, u32_at(log, 220)?],
        thermal_seconds: [u32_at(log, 224)?, u32_at(log, 228)?],
    })
}

impl NvmeHealth {
    /// Composite temperature in Celsius; 0 K means the controller does not report it.
    pub fn celsius(&self) -> Option<i32> {
        (self.temperature_kelvin > 0).then(|| i32::from(self.temperature_kelvin) - 273)
    }
}

/// Critical Warning bits (byte 0 of the health log), each named.
pub fn critical_warning_names(bits: u8) -> Vec<String> {
    (0..8)
        .filter(|bit| bits & (1 << bit) != 0)
        .map(|bit| {
            match bit {
                0 => "available spare has fallen below its threshold",
                1 => "a temperature is past an over- or under-temperature threshold",
                2 => "reliability is degraded by media or internal errors",
                3 => "the media has been placed in read-only mode",
                4 => "the volatile memory backup device has failed",
                5 => "the persistent memory region has become read-only or unreliable",
                _ => "a reserved warning bit is set",
            }
            .to_string()
        })
        .collect()
}

/// Data units are thousands of 512-byte units: one unit is 512,000 bytes.
pub fn data_units_tb(units: u128) -> f64 {
    units as f64 * 512_000.0 / 1e12
}

/// One entry of the ATA SMART attribute table.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Attribute {
    pub id: u8,
    pub current: u8,
    pub worst: u8,
    pub raw: [u8; 6],
}

impl Attribute {
    pub fn raw_value(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes[..6].copy_from_slice(&self.raw);
        u64::from_le_bytes(bytes)
    }
}

/// SMART READ DATA (512 bytes): a 2-byte revision, then 30 entries of 12 bytes: id, 2 flag
/// bytes, current, worst, 6 raw bytes, 1 reserved. Entries with id 0 are empty.
pub fn parse_smart_attributes(data: &[u8]) -> Option<Vec<Attribute>> {
    if data.len() < 2 + 30 * 12 {
        return None;
    }
    let attributes = (0..30)
        .map(|index| &data[2 + index * 12..2 + (index + 1) * 12])
        .filter(|entry| entry[0] != 0)
        .map(|entry| Attribute {
            id: entry[0],
            current: entry[3],
            worst: entry[4],
            raw: entry[5..11].try_into().expect("six bytes"),
        })
        .collect();
    Some(attributes)
}

/// The attributes that predict failure or wear, with their names, in print order.
pub const WATCHED: &[(u8, &str)] = &[
    (5, "reallocated sectors"),
    (197, "current pending sectors"),
    (198, "offline uncorrectable sectors"),
    (187, "reported uncorrectable errors"),
    (188, "command timeouts"),
    (199, "UDMA CRC errors (usually the cable)"),
    (9, "power-on hours"),
    (194, "temperature"),
    (177, "wear leveling count"),
    (231, "SSD life left"),
    (233, "media wearout indicator"),
];

/// Attributes whose raw count above zero is a problem.
const COUNTED: &[u8] = &[5, 197, 198, 187];

/// Health data from the drive itself, or why it was not read.
#[derive(Debug, Clone, PartialEq)]
pub enum Health {
    Nvme(NvmeHealth),
    Ata(Vec<Attribute>),
    Unread(String),
}

/// Everything read about one physical disk; each `Err` holds why that reading is missing.
#[derive(Debug, Clone, PartialEq)]
pub struct Disk {
    pub number: u32,
    pub identity: Result<Identity, String>,
    pub size: Result<u64, String>,
    pub solid_state: Result<bool, String>,
    pub volumes: Vec<char>,
    pub temperature: Result<Temperature, String>,
    pub predicts_failure: Result<bool, String>,
    pub health: Health,
}

/// The judgement on one disk.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub problems: Vec<String>,
    /// True when the drive's own health data (NVMe log or SMART attributes) was read.
    pub health_read: bool,
}

/// Flags critical warning bits, spare at or below threshold, 90 % or more endurance used,
/// media errors, reallocated, pending or uncorrectable counts, temperature at or above the
/// drive's warning threshold, and Windows' failure prediction.
pub fn assess(disk: &Disk) -> Assessment {
    let mut problems = Vec::new();
    let mut current = None;
    match &disk.health {
        Health::Nvme(log) => {
            for name in critical_warning_names(log.critical_warning) {
                problems.push(format!("critical warning: {name}"));
            }
            if log.available_spare <= log.spare_threshold {
                problems.push(format!(
                    "available spare {} % is at or below its threshold of {} %",
                    log.available_spare, log.spare_threshold
                ));
            }
            if log.percentage_used >= 90 {
                problems.push(format!(
                    "{} % of the rated endurance is used",
                    log.percentage_used
                ));
            }
            if log.media_errors > 0 {
                problems.push(format!(
                    "{} media and data integrity errors",
                    log.media_errors
                ));
            }
            current = log.celsius();
        }
        Health::Ata(attributes) => {
            for attribute in attributes {
                if COUNTED.contains(&attribute.id) && attribute.raw_value() > 0 {
                    problems.push(format!(
                        "{} {}",
                        attribute.raw_value(),
                        attribute_name(attribute.id)
                    ));
                }
                if attribute.id == 194 && attribute.raw[0] > 0 {
                    current = Some(i32::from(attribute.raw[0]));
                }
            }
        }
        Health::Unread(_) => {}
    }
    let windows = disk.temperature.as_ref().ok();
    let current = current.or_else(|| windows.and_then(|t| t.current).map(i32::from));
    if let (Some(now), Some(warning)) = (current, windows.and_then(|t| t.warning)) {
        if now >= i32::from(warning) {
            problems.push(format!(
                "temperature {now} C is at or above the drive's warning threshold of {warning} C"
            ));
        }
    }
    if disk.predicts_failure == Ok(true) {
        problems.push("Windows' failure prediction says the drive is going to fail".into());
    }
    Assessment {
        problems,
        health_read: !matches!(disk.health, Health::Unread(_)),
    }
}

pub fn attribute_name(id: u8) -> &'static str {
    WATCHED
        .iter()
        .find(|(watched, _)| *watched == id)
        .map_or("other attribute", |(_, name)| name)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub struct NvmeLog {
        pub warning: u8,
        pub kelvin: u16,
        pub spare: u8,
        pub threshold: u8,
        pub used: u8,
        pub read: u128,
        pub written: u128,
        pub cycles: u128,
        pub hours: u128,
        pub unsafe_shutdowns: u128,
        pub media: u128,
        pub entries: u128,
        pub warn_minutes: u32,
        pub crit_minutes: u32,
    }

    /// A 512-byte health log laid out as the NVMe specification gives it.
    pub fn nvme_log(log: &NvmeLog) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0] = log.warning;
        buf[1..3].copy_from_slice(&log.kelvin.to_le_bytes());
        buf[3] = log.spare;
        buf[4] = log.threshold;
        buf[5] = log.used;
        for (at, value) in [
            (32, log.read),
            (48, log.written),
            (112, log.cycles),
            (128, log.hours),
            (144, log.unsafe_shutdowns),
            (160, log.media),
            (176, log.entries),
        ] {
            buf[at..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        buf[192..196].copy_from_slice(&log.warn_minutes.to_le_bytes());
        buf[196..200].copy_from_slice(&log.crit_minutes.to_le_bytes());
        buf
    }

    pub fn healthy_nvme() -> Vec<u8> {
        nvme_log(&NvmeLog {
            warning: 0,
            kelvin: 314,
            spare: 100,
            threshold: 10,
            used: 3,
            read: 101_562_500,
            written: 78_125_000,
            cycles: 1_204,
            hours: 8_812,
            unsafe_shutdowns: 61,
            media: 0,
            entries: 14,
            warn_minutes: 0,
            crit_minutes: 0,
        })
    }

    pub fn worn_nvme() -> Vec<u8> {
        nvme_log(&NvmeLog {
            warning: 0,
            kelvin: 330,
            spare: 40,
            threshold: 10,
            used: 95,
            read: 400_000_000,
            written: 1_200_000_000,
            cycles: 3_000,
            hours: 41_000,
            unsafe_shutdowns: 210,
            media: 37,
            entries: 900,
            warn_minutes: 12,
            crit_minutes: 0,
        })
    }

    pub fn critical_nvme() -> Vec<u8> {
        nvme_log(&NvmeLog {
            warning: 0b0000_1101,
            kelvin: 360,
            spare: 5,
            threshold: 10,
            used: 100,
            read: 1,
            written: 1,
            cycles: 1,
            hours: 1,
            unsafe_shutdowns: 0,
            media: 2,
            entries: 0,
            warn_minutes: 300,
            crit_minutes: 25,
        })
    }

    /// A 512-byte SMART attribute table from (id, current, worst, raw) entries.
    pub fn smart_table(entries: &[(u8, u8, u8, u64)]) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0] = 0x10;
        for (index, (id, current, worst, raw)) in entries.iter().enumerate() {
            let at = 2 + index * 12;
            buf[at] = *id;
            buf[at + 1] = 0x33;
            buf[at + 3] = *current;
            buf[at + 4] = *worst;
            buf[at + 5..at + 11].copy_from_slice(&raw.to_le_bytes()[..6]);
        }
        buf
    }

    pub fn healthy_smart() -> Vec<u8> {
        smart_table(&[
            (1, 100, 100, 0),
            (5, 100, 100, 0),
            (9, 98, 98, 5_123),
            (12, 99, 99, 840),
            (177, 97, 97, 31),
            (187, 100, 100, 0),
            (194, 66, 52, 0x0030_0012_0022),
            (197, 100, 100, 0),
            (198, 100, 100, 0),
            (199, 200, 200, 0),
        ])
    }

    pub fn pending_smart() -> Vec<u8> {
        smart_table(&[
            (5, 98, 98, 24),
            (9, 40, 40, 52_000),
            (188, 100, 99, 3),
            (194, 60, 45, 41),
            (197, 100, 100, 8),
            (198, 100, 100, 8),
            (199, 200, 200, 2),
        ])
    }

    pub fn disk(health: Health) -> Disk {
        Disk {
            number: 0,
            identity: Ok(Identity {
                vendor: String::new(),
                model: "Example SSD 1TB".into(),
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
            health,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn healthy_nvme_log_decodes_and_raises_nothing() {
        let log = parse_nvme_health(&healthy_nvme()).unwrap();
        assert_eq!(log.celsius(), Some(41));
        assert_eq!(log.available_spare, 100);
        assert_eq!(log.spare_threshold, 10);
        assert_eq!(log.percentage_used, 3);
        assert_eq!(log.power_on_hours, 8_812);
        assert_eq!(log.power_cycles, 1_204);
        assert_eq!(log.unsafe_shutdowns, 61);
        assert_eq!(log.error_log_entries, 14);
        assert!((data_units_tb(log.data_units_read) - 52.0).abs() < 1e-9);
        assert!((data_units_tb(log.data_units_written) - 40.0).abs() < 1e-9);
        let assessment = assess(&disk(Health::Nvme(log)));
        assert!(assessment.health_read);
        assert!(assessment.problems.is_empty(), "{:?}", assessment.problems);
    }

    #[test]
    fn worn_nvme_log_flags_wear_and_media_errors() {
        let log = parse_nvme_health(&worn_nvme()).unwrap();
        assert_eq!(log.media_errors, 37);
        assert_eq!(log.warning_temperature_minutes, 12);
        let problems = assess(&disk(Health::Nvme(log))).problems;
        assert_eq!(
            problems,
            [
                "95 % of the rated endurance is used",
                "37 media and data integrity errors"
            ]
        );
    }

    #[test]
    fn critical_warning_bits_are_each_named() {
        let log = parse_nvme_health(&critical_nvme()).unwrap();
        assert_eq!(log.critical_warning, 0b1101);
        assert_eq!(log.critical_temperature_minutes, 25);
        let problems = assess(&disk(Health::Nvme(log))).problems;
        assert!(problems[0].contains("available spare has fallen below"));
        assert!(problems[1].contains("media or internal errors"));
        assert!(problems[2].contains("read-only mode"));
        assert!(problems.iter().any(|p| p.contains("spare 5 %")));
        assert!(problems.iter().any(|p| p.contains("100 % of the rated")));
        // 360 K is 87 C, past the 82 C warning threshold.
        assert!(problems.iter().any(|p| p.contains("temperature 87 C")));
        assert_eq!(critical_warning_names(0xff).len(), 8);
    }

    #[test]
    fn short_nvme_log_is_not_parsed() {
        assert_eq!(parse_nvme_health(&healthy_nvme()[..200]), None);
    }

    #[test]
    fn healthy_smart_table_decodes_and_raises_nothing() {
        let attributes = parse_smart_attributes(&healthy_smart()).unwrap();
        assert_eq!(attributes.len(), 10);
        let temp = attributes.iter().find(|a| a.id == 194).unwrap();
        assert_eq!(temp.raw[0], 0x22);
        assert_eq!(temp.current, 66);
        assert_eq!(temp.worst, 52);
        let hours = attributes.iter().find(|a| a.id == 9).unwrap();
        assert_eq!(hours.raw_value(), 5_123);
        let assessment = assess(&disk(Health::Ata(attributes)));
        assert!(assessment.problems.is_empty(), "{:?}", assessment.problems);
    }

    #[test]
    fn pending_sectors_are_flagged_with_raw_counts() {
        let attributes = parse_smart_attributes(&pending_smart()).unwrap();
        let problems = assess(&disk(Health::Ata(attributes))).problems;
        assert_eq!(
            problems,
            [
                "24 reallocated sectors",
                "8 current pending sectors",
                "8 offline uncorrectable sectors"
            ]
        );
    }

    #[test]
    fn short_smart_table_is_not_parsed() {
        assert_eq!(parse_smart_attributes(&[0u8; 100]), None);
    }

    #[test]
    fn unread_health_is_never_called_healthy() {
        let mut unread = disk(Health::Unread("needs administrator rights".into()));
        let assessment = assess(&unread);
        assert!(!assessment.health_read);
        assert!(assessment.problems.is_empty());
        unread.predicts_failure = Ok(true);
        assert_eq!(assess(&unread).problems.len(), 1);
    }

    #[test]
    fn windows_temperature_counts_when_the_log_is_unread() {
        let mut hot = disk(Health::Unread("over USB".into()));
        hot.temperature = Ok(Temperature {
            current: Some(70),
            warning: Some(70),
            critical: None,
        });
        assert_eq!(assess(&hot).problems.len(), 1);
        hot.temperature = Err("not reported".into());
        assert!(assess(&hot).problems.is_empty());
    }

    fn descriptor(removable: bool, bus: i32, vendor: &str, model: &str, rev: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 36];
        buf[10] = removable as u8;
        let mut strings = Vec::new();
        for (field, text) in [(12usize, vendor), (16, model), (20, rev), (24, "SERIAL123")] {
            let offset = 36 + strings.len();
            buf[field..field + 4].copy_from_slice(&(offset as u32).to_le_bytes());
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
        }
        buf[28..32].copy_from_slice(&bus.to_le_bytes());
        buf.extend_from_slice(&strings);
        let size = buf.len() as u32;
        buf[4..8].copy_from_slice(&size.to_le_bytes());
        buf
    }

    #[test]
    fn device_descriptor_gives_identity_without_the_serial() {
        let buf = descriptor(false, BUS_NVME, "", "  Example   SSD 1TB ", "FW01\u{7}");
        let identity = parse_device_descriptor(&buf).unwrap();
        assert_eq!(identity.model, "Example SSD 1TB");
        assert_eq!(identity.firmware, "FW01");
        assert_eq!(identity.vendor, "");
        assert_eq!(identity.bus, BUS_NVME);
        assert!(!identity.removable);
        assert!(!format!("{identity:?}").contains("SERIAL"));
        assert_eq!(parse_device_descriptor(&buf[..20]), None);
    }

    #[test]
    fn temperature_property_and_seek_penalty_decode() {
        let mut buf = vec![0u8; 40];
        buf[8..10].copy_from_slice(&85i16.to_le_bytes());
        buf[10..12].copy_from_slice(&82i16.to_le_bytes());
        buf[12..14].copy_from_slice(&1u16.to_le_bytes());
        buf[26..28].copy_from_slice(&41i16.to_le_bytes());
        let temperature = parse_temperature(&buf).unwrap();
        assert_eq!(temperature.current, Some(41));
        assert_eq!(temperature.warning, Some(82));
        assert_eq!(temperature.critical, Some(85));
        buf[12] = 0;
        assert_eq!(parse_temperature(&buf).unwrap().current, None);
        assert_eq!(
            parse_seek_penalty(&[12, 0, 0, 0, 12, 0, 0, 0, 0]),
            Some(true)
        );
        assert_eq!(
            parse_seek_penalty(&[12, 0, 0, 0, 12, 0, 0, 0, 1]),
            Some(false)
        );
        assert_eq!(parse_seek_penalty(&[1, 2]), None);
    }

    #[test]
    fn protocol_reply_and_extents_are_bounds_checked() {
        let mut reply = vec![0u8; 48 + 512];
        reply[24..28].copy_from_slice(&40u32.to_le_bytes());
        reply[28..32].copy_from_slice(&512u32.to_le_bytes());
        reply[48] = 7;
        assert_eq!(protocol_data(&reply, 512).unwrap()[0], 7);
        reply[28..32].copy_from_slice(&100u32.to_le_bytes());
        assert!(protocol_data(&reply, 512).is_err());
        assert!(protocol_data(&reply[..20], 512).is_err());
        let mut extents = vec![0u8; 8 + 48];
        extents[0] = 2;
        extents[8] = 1;
        extents[32] = 3;
        assert_eq!(parse_disk_extents(&extents), [1, 3]);
        assert_eq!(parse_disk_extents(&extents[..20]), [1]);
    }
}
