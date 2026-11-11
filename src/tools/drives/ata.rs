//! One ATA command at the register level, and how Windows' own ATA paths carry it. A command
//! is one of the three data-in reads (`AtaCommand`) or the SCT read limit (`sct::Request`);
//! nothing else can be built. `crate::handles::AtaDisk` sends it through the carrier its bus
//! calls for: Windows' ATA paths on an ATA, SATA or RAID bus, and SCSI/ATA Translation
//! (`sat`) through a USB adapter. This module and `sat` build and read bytes only; the
//! control codes and the sends are `crate::handles`' alone.
use serde::{Deserialize, Serialize};

use super::health::{self, BUS_ATA, BUS_RAID, BUS_SATA, BUS_USB};
use super::sct;

/// The one sector every command moves.
pub const SECTOR: usize = 512;
/// Seconds the driver or adapter waits for the drive to answer one command.
pub const COMMAND_SECONDS: u32 = 10;

/// SMART command, its signature in LBA mid and high, and its features used here.
const SMART: u8 = 0xB0;
const SMART_MID: u8 = 0x4F;
const SMART_HIGH: u8 = 0xC2;
const SMART_READ_DATA: u8 = 0xD0;
const SMART_READ_THRESHOLDS: u8 = 0xD1;
const SMART_WRITE_LOG: u8 = 0xD6;
const IDENTIFY_DEVICE: u8 = 0xEC;
/// The SCT command log's address.
const SCT_COMMAND_LOG: u8 = 0xE0;
/// The device register as this program has always sent it.
const DEVICE: u8 = 0xA0;

/// The only ATA reads this program sends. Each reads 512 bytes and changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaCommand {
    SmartReadData,
    SmartReadThresholds,
    Identify,
}

pub const ATA_COMMANDS: [AtaCommand; 3] = [
    AtaCommand::SmartReadData,
    AtaCommand::SmartReadThresholds,
    AtaCommand::Identify,
];

/// The registers a command is sent with: 28-bit, one sector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Registers {
    pub features: u8,
    pub count: u8,
    pub lba_low: u8,
    pub lba_mid: u8,
    pub lba_high: u8,
    pub device: u8,
    pub command: u8,
}

/// The registers the drive returned, error and status in place of features and command.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Returned {
    pub error: u8,
    pub count: u8,
    pub lba_low: u8,
    pub lba_mid: u8,
    pub lba_high: u8,
    pub device: u8,
    pub status: u8,
}

/// Status bits: BSY (still working), DF (device fault), ERR.
const BSY: u8 = 0x80;
const DF: u8 = 0x20;
const ERR: u8 = 0x01;

impl Returned {
    /// Whether the drive finished the command and reports no error: BSY, DF and ERR clear.
    /// Registers or data are used only from such a command, on every carrier.
    pub fn completed(&self) -> bool {
        self.status & (BSY | DF | ERR) == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The drive sends a sector.
    In,
    /// The drive is sent a sector.
    Out,
}

/// One command: its registers, its direction, and for data out the sector sent. Made only
/// by `read` and `sct`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    registers: Registers,
    direction: Direction,
    sector: [u8; SECTOR],
}

impl Command {
    /// One of the three reads. LBA low is 1, as the Windows path has always sent it; the
    /// drive ignores it for these commands.
    pub fn read(command: AtaCommand) -> Self {
        let (features, lba_mid, lba_high, code) = match command {
            AtaCommand::SmartReadData => (SMART_READ_DATA, SMART_MID, SMART_HIGH, SMART),
            AtaCommand::SmartReadThresholds => {
                (SMART_READ_THRESHOLDS, SMART_MID, SMART_HIGH, SMART)
            }
            AtaCommand::Identify => (0, 0, 0, IDENTIFY_DEVICE),
        };
        Self {
            registers: Registers {
                features,
                count: 1,
                lba_low: 1,
                lba_mid,
                lba_high,
                device: DEVICE,
                command: code,
            },
            direction: Direction::In,
            sector: [0; SECTOR],
        }
    }

    /// The SCT read limit: SMART WRITE LOG of one sector to the SCT command log.
    pub fn sct(request: sct::Request) -> Self {
        Self {
            registers: Registers {
                features: SMART_WRITE_LOG,
                count: 1,
                lba_low: SCT_COMMAND_LOG,
                lba_mid: SMART_MID,
                lba_high: SMART_HIGH,
                device: DEVICE,
                command: SMART,
            },
            direction: Direction::Out,
            sector: sct::command_sector(request),
        }
    }

    pub fn registers(&self) -> Registers {
        self.registers
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// The sector sent with a data-out command; zeros for data in.
    pub fn sector(&self) -> &[u8; SECTOR] {
        &self.sector
    }

    /// Whether its answer is read from the returned registers: the SCT read limit comes
    /// back in them, so a carrier that returns none cannot answer it.
    pub fn needs_registers(&self) -> bool {
        self.direction == Direction::Out
    }
}

/// What a command gave back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The sector a data-in command read; empty for data out.
    pub data: Vec<u8>,
    /// The drive's registers, where the carrier returns them.
    pub returned: Option<Returned>,
}

/// Why a command gave no answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The disk could not be opened for it; says why ("needs administrator rights").
    Open(String),
    /// The driver or the USB adapter did not pass it to the drive; says what it answered.
    NotPassed(String),
    /// The drive took it and reported an error.
    Refused(String),
    /// What came back was short or garbled.
    Malformed(String),
}

impl Failure {
    pub fn text(&self) -> &str {
        match self {
            Failure::Open(why)
            | Failure::NotPassed(why)
            | Failure::Refused(why)
            | Failure::Malformed(why) => why,
        }
    }
}

/// How a disk's ATA commands reach the drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// SMART_RCV_DRIVE_DATA for the reads, IOCTL_ATA_PASS_THROUGH for the SCT command.
    Windows,
    /// ATA PASS-THROUGH (16), or (12) for an adapter that takes only that, inside
    /// IOCTL_SCSI_PASS_THROUGH, which a USB adapter with SCSI/ATA Translation hands to the
    /// drive.
    Sat,
}

/// The carrier for a disk on `bus`; Err names a bus that carries no ATA command.
pub fn carrier(bus: Option<i32>) -> Result<Carrier, String> {
    match bus {
        Some(BUS_ATA | BUS_SATA | BUS_RAID) => Ok(Carrier::Windows),
        Some(BUS_USB) => Ok(Carrier::Sat),
        Some(other) => Err(format!(
            "ATA commands are not sent over {}",
            health::bus_name(other)
        )),
        None => Err("the bus could not be read".into()),
    }
}

/// An answer, refused when the drive's registers say it did not complete the command, and
/// when a command that needs the registers got none.
pub fn checked(command: &Command, answer: Answer) -> Result<Answer, Failure> {
    match answer.returned {
        // A busy drive's other registers are not its answer yet.
        Some(returned) if returned.status & BSY != 0 => Err(Failure::NotPassed(format!(
            "the drive had not finished it (status {:#04x})",
            returned.status
        ))),
        Some(returned) if !returned.completed() => Err(Failure::Refused(format!(
            "the drive refused it (status {:#04x}, error {:#04x})",
            returned.status, returned.error
        ))),
        None if command.needs_registers() => Err(Failure::NotPassed(
            "the drive's registers did not come back, so its answer is not known".into(),
        )),
        _ => Ok(answer),
    }
}

// ---- Windows' own ATA paths ------------------------------------------------------------

/// SENDCMDOUTPARAMS: buffer size, DRIVERSTATUS (12 bytes), then the sector.
pub const SMART_RCV_REPLY: usize = 16 + SECTOR;
/// ATA_PASS_THROUGH_EX on 64-bit Windows: 48 bytes, the data buffer right after it.
pub const PASS_THROUGH_HEADER: usize = 48;

const ATA_FLAGS_DRDY_REQUIRED: u16 = 0x01;
const ATA_FLAGS_DATA_IN: u16 = 0x02;
const ATA_FLAGS_DATA_OUT: u16 = 0x04;

/// SENDCMDINPARAMS without its 1-byte buffer (packed, 32 bytes) for SMART_RCV_DRIVE_DATA:
/// buffer size 512, IDEREGS (features, count, number, cylinder low, cylinder high,
/// drive/head, command), drive number 0.
pub fn smart_rcv_input(command: &Command) -> [u8; 32] {
    let r = command.registers;
    let mut block = [0u8; 32];
    block[..4].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    block[4..11].copy_from_slice(&[
        r.features, r.count, r.lba_low, r.lba_mid, r.lba_high, r.device, r.command,
    ]);
    block
}

/// The sector SMART_RCV_DRIVE_DATA read. It returns no registers, only the driver's and
/// the drive's error bytes.
pub fn smart_rcv_answer(reply: &[u8]) -> Result<Answer, Failure> {
    match reply.get(4..6) {
        Some(&[driver, drive]) if driver != 0 => Err(Failure::Refused(format!(
            "the drive refused it (driver error {driver}, drive error {drive})"
        ))),
        Some(_) if reply.len() >= SMART_RCV_REPLY => Ok(Answer {
            data: reply[16..SMART_RCV_REPLY].to_vec(),
            returned: None,
        }),
        _ => Err(Failure::Malformed("the reply was too short".into())),
    }
}

/// The IOCTL_ATA_PASS_THROUGH input: ATA_PASS_THROUGH_EX (length, flags, path, target and
/// unit 0, data length 512, timeout, data offset 48, the current task file) and the sector.
pub fn pass_through_input(command: &Command) -> Vec<u8> {
    let r = command.registers;
    let direction = match command.direction {
        Direction::In => ATA_FLAGS_DATA_IN,
        Direction::Out => ATA_FLAGS_DATA_OUT,
    };
    let mut buffer = vec![0u8; PASS_THROUGH_HEADER + SECTOR];
    buffer[0..2].copy_from_slice(&(PASS_THROUGH_HEADER as u16).to_le_bytes());
    buffer[2..4].copy_from_slice(&(ATA_FLAGS_DRDY_REQUIRED | direction).to_le_bytes());
    buffer[8..12].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    buffer[12..16].copy_from_slice(&COMMAND_SECONDS.to_le_bytes());
    buffer[24..32].copy_from_slice(&(PASS_THROUGH_HEADER as u64).to_le_bytes());
    buffer[40..48].copy_from_slice(&[
        r.features, r.count, r.lba_low, r.lba_mid, r.lba_high, r.device, r.command, 0,
    ]);
    if command.direction == Direction::Out {
        buffer[PASS_THROUGH_HEADER..].copy_from_slice(&command.sector);
    }
    buffer
}

/// The output task file of an IOCTL_ATA_PASS_THROUGH reply (error, count, LBA low, mid,
/// high, device, status), and for data in the sector after the header.
pub fn pass_through_answer(reply: &[u8], command: &Command) -> Result<Answer, Failure> {
    let file = reply
        .get(40..47)
        .ok_or_else(|| Failure::Malformed("the reply was too short".into()))?;
    let returned = Returned {
        error: file[0],
        count: file[1],
        lba_low: file[2],
        lba_mid: file[3],
        lba_high: file[4],
        device: file[5],
        status: file[6],
    };
    let data = match command.direction {
        Direction::In => reply
            .get(PASS_THROUGH_HEADER..PASS_THROUGH_HEADER + SECTOR)
            .ok_or_else(|| Failure::Malformed("the reply was too short".into()))?
            .to_vec(),
        Direction::Out => Vec::new(),
    };
    Ok(Answer {
        data,
        returned: Some(returned),
    })
}

// ---- the drive's own identity ----------------------------------------------------------

/// The drive's own model and serial number from IDENTIFY DEVICE. Unlike what Windows
/// reports for a disk, they stay the same when the drive moves between a USB adapter and
/// a SATA port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveId {
    pub model: String,
    pub serial: String,
}

/// IDENTIFY words `from..to` as text: each word's two bytes swapped, NULs read as spaces,
/// trimmed. None when a byte is not printable ASCII, which a real drive never sends.
fn identify_text(identify: &[u8], from: usize, to: usize) -> Option<String> {
    let bytes = identify.get(from * 2..to * 2)?;
    let mut text = String::with_capacity(bytes.len());
    for [first, second] in bytes.as_chunks::<2>().0 {
        for byte in [*second, *first] {
            match byte {
                0 => text.push(' '),
                0x20..=0x7E => text.push(char::from(byte)),
                _ => return None,
            }
        }
    }
    Some(text.trim().to_string())
}

/// The drive's identity from IDENTIFY DEVICE data: words 10 to 19 the serial number, 27 to
/// 46 the model. None when the data fails its checksum (word 255, where the drive gives
/// one), is not text, or names no serial number to tell the drive apart.
pub fn drive_id(identify: &[u8]) -> Option<DriveId> {
    let identify = identify.get(..SECTOR)?;
    if identify[510] == 0xA5 && identify.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
        return None;
    }
    let serial = identify_text(identify, 10, 20)?;
    let model = identify_text(identify, 27, 47)?;
    (!serial.is_empty()).then_some(DriveId { model, serial })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// ATA_PASS_THROUGH_EX as windows-sys lays it out on x64, to check the hand-built bytes.
    #[repr(C)]
    struct AtaPassThroughEx {
        length: u16,
        ata_flags: u16,
        path_id: u8,
        target_id: u8,
        lun: u8,
        reserved_as_uchar: u8,
        data_transfer_length: u32,
        time_out_value: u32,
        reserved_as_ulong: u32,
        data_buffer_offset: usize,
        previous_task_file: [u8; 8],
        current_task_file: [u8; 8],
    }

    #[test]
    fn the_pass_through_header_matches_the_windows_layout() {
        use std::mem::offset_of;
        assert_eq!(std::mem::size_of::<AtaPassThroughEx>(), PASS_THROUGH_HEADER);
        assert_eq!(offset_of!(AtaPassThroughEx, ata_flags), 2);
        assert_eq!(offset_of!(AtaPassThroughEx, data_transfer_length), 8);
        assert_eq!(offset_of!(AtaPassThroughEx, time_out_value), 12);
        assert_eq!(offset_of!(AtaPassThroughEx, data_buffer_offset), 24);
        assert_eq!(offset_of!(AtaPassThroughEx, previous_task_file), 32);
        assert_eq!(offset_of!(AtaPassThroughEx, current_task_file), 40);
    }

    /// Every command that can be built, as (registers, direction): the three reads and the
    /// SCT read limit, read or set.
    fn every_command() -> Vec<Command> {
        let mut all: Vec<Command> = ATA_COMMANDS.iter().map(|c| Command::read(*c)).collect();
        for request in [
            sct::Request::Read,
            sct::Request::Set(0),
            sct::Request::Set(15),
            sct::Request::Set(100),
        ] {
            all.push(Command::sct(request));
        }
        all
    }

    /// The guard: the commands are exactly SMART READ DATA, SMART READ THRESHOLDS and
    /// IDENTIFY DEVICE, data in, and SMART WRITE LOG of one sector to the SCT command log,
    /// data out, whose sector is Error Recovery Control of the read timer (sct.rs' guard).
    #[test]
    fn only_the_three_reads_and_the_read_limit_are_built() {
        let reads: [(AtaCommand, [u8; 7]); 3] = [
            (
                AtaCommand::SmartReadData,
                [0xD0, 1, 1, 0x4F, 0xC2, 0xA0, 0xB0],
            ),
            (
                AtaCommand::SmartReadThresholds,
                [0xD1, 1, 1, 0x4F, 0xC2, 0xA0, 0xB0],
            ),
            (AtaCommand::Identify, [0x00, 1, 1, 0x00, 0x00, 0xA0, 0xEC]),
        ];
        assert_eq!(ATA_COMMANDS.len(), reads.len());
        let bytes = |r: Registers| {
            [
                r.features, r.count, r.lba_low, r.lba_mid, r.lba_high, r.device, r.command,
            ]
        };
        for (command, registers) in reads {
            let built = Command::read(command);
            assert_eq!(bytes(built.registers()), registers, "{command:?}");
            assert_eq!(built.direction(), Direction::In);
            assert!(built.sector().iter().all(|b| *b == 0));
            assert!(!built.needs_registers());
        }
        for command in every_command() {
            match command.direction() {
                Direction::In => {
                    assert!(reads.iter().any(|(_, r)| *r == bytes(command.registers())))
                }
                Direction::Out => {
                    assert_eq!(
                        bytes(command.registers()),
                        [0xD6, 1, 0xE0, 0x4F, 0xC2, 0xA0, 0xB0]
                    );
                    let word = |n: usize| {
                        u16::from_le_bytes([command.sector()[n * 2], command.sector()[n * 2 + 1]])
                    };
                    assert_eq!((word(0), word(2)), (3, 1), "action 3, the read timer");
                    assert!(command.needs_registers());
                }
            }
        }
    }

    /// The Windows read path's block is what it has always been: SENDCMDINPARAMS asking for
    /// 512 bytes of drive 0, the registers in IDEREGS order.
    #[test]
    fn the_windows_read_block_carries_the_registers() {
        for command in ATA_COMMANDS {
            let built = Command::read(command);
            let block = smart_rcv_input(&built);
            let r = built.registers();
            assert_eq!(u32::from_le_bytes(block[..4].try_into().unwrap()), 512);
            assert_eq!(
                block[4..11],
                [r.features, r.count, r.lba_low, r.lba_mid, r.lba_high, r.device, r.command]
            );
            assert!(block[11..].iter().all(|b| *b == 0), "{command:?}");
        }
        let mut reply = vec![0u8; SMART_RCV_REPLY];
        reply[16] = 0x10;
        let answer = smart_rcv_answer(&reply).unwrap();
        assert_eq!((answer.data.len(), answer.data[0]), (512, 0x10));
        assert_eq!(answer.returned, None);
        reply[4..6].copy_from_slice(&[1, 4]);
        assert!(
            matches!(smart_rcv_answer(&reply), Err(Failure::Refused(why)) if why.contains("drive error 4"))
        );
        assert!(matches!(
            smart_rcv_answer(&reply[..5]),
            Err(Failure::Malformed(_))
        ));
        let mut short = vec![0u8; 100];
        short[4] = 0;
        assert!(matches!(
            smart_rcv_answer(&short),
            Err(Failure::Malformed(_))
        ));
    }

    #[test]
    fn the_windows_pass_through_carries_the_sct_command_and_reads_its_registers() {
        for request in [sct::Request::Read, sct::Request::Set(15)] {
            let command = Command::sct(request);
            let bytes = pass_through_input(&command);
            assert_eq!(bytes.len(), PASS_THROUGH_HEADER + SECTOR);
            assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 48);
            assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x05, "data out");
            assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 512);
            assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 10);
            assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 48);
            assert_eq!(bytes[32..40], [0; 8], "no 48-bit task file");
            assert_eq!(bytes[40..48], [0xD6, 1, 0xE0, 0x4F, 0xC2, 0xA0, 0xB0, 0]);
            assert_eq!(bytes[PASS_THROUGH_HEADER..], command.sector()[..]);
        }
        let command = Command::sct(sct::Request::Read);
        let mut reply = pass_through_input(&command);
        reply[40..48].copy_from_slice(&[0, 70, 0, 0x4F, 0xC2, 0xA0, 0x50, 0]);
        let answer = checked(&command, pass_through_answer(&reply, &command).unwrap()).unwrap();
        let returned = answer.returned.unwrap();
        assert_eq!(
            (returned.count, returned.lba_low, returned.status),
            (70, 0, 0x50)
        );
        assert!(answer.data.is_empty());
        // ERR with ABRT: the drive does not take it.
        reply[40..48].copy_from_slice(&[0x04, 0, 0, 0, 0, 0xA0, 0x51, 0]);
        let refused = checked(&command, pass_through_answer(&reply, &command).unwrap());
        assert!(matches!(refused, Err(Failure::Refused(why)) if why.contains("0x51")));
        assert!(pass_through_answer(&reply[..40], &command).is_err());
        // A data-in reply carries its sector after the header.
        let identify = Command::read(AtaCommand::Identify);
        assert_eq!(
            u16::from_le_bytes([pass_through_input(&identify)[2], 0]),
            0x03
        );
        let mut reply = vec![0u8; PASS_THROUGH_HEADER + SECTOR];
        reply[46] = 0x50;
        reply[PASS_THROUGH_HEADER] = 7;
        let answer = pass_through_answer(&reply, &identify).unwrap();
        assert_eq!((answer.data.len(), answer.data[0]), (512, 7));
    }

    /// The guard: registers or data are used only from a completed command, BSY, DF and
    /// ERR all clear; a busy drive's registers (a stale read limit) are never taken.
    #[test]
    fn only_a_completed_command_is_answered() {
        let sct = Command::sct(sct::Request::Read);
        let with = |status: u8| Answer {
            data: Vec::new(),
            returned: Some(Returned {
                status,
                count: 70,
                ..Default::default()
            }),
        };
        assert!(checked(&sct, with(0x50)).is_ok(), "ready, seek complete");
        assert!(checked(&sct, with(0x40)).is_ok());
        for (status, busy) in [
            (0x80, true),
            (0xD0, true),
            (0x81, true),
            (0x51, false),
            (0x61, false),
            (0x60, false),
        ] {
            assert!(
                !Returned {
                    status,
                    ..Default::default()
                }
                .completed(),
                "{status:#04x}"
            );
            match checked(&sct, with(status)) {
                Err(Failure::NotPassed(why)) if busy => assert!(why.contains("not finished")),
                Err(Failure::Refused(_)) if !busy => {}
                other => panic!("{status:#04x}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_command_that_needs_registers_is_refused_without_them() {
        let sct = Command::sct(sct::Request::Read);
        let none = Answer {
            data: Vec::new(),
            returned: None,
        };
        assert!(matches!(
            checked(&sct, none.clone()),
            Err(Failure::NotPassed(_))
        ));
        let read = Command::read(AtaCommand::Identify);
        assert!(checked(&read, none).is_ok());
        let fault = Answer {
            data: vec![0; 512],
            returned: Some(Returned {
                status: 0x70,
                ..Default::default()
            }),
        };
        assert!(matches!(checked(&read, fault), Err(Failure::Refused(_))));
    }

    #[test]
    fn the_carrier_follows_the_bus() {
        for bus in [BUS_ATA, BUS_SATA, BUS_RAID] {
            assert_eq!(carrier(Some(bus)), Ok(Carrier::Windows));
        }
        assert_eq!(carrier(Some(BUS_USB)), Ok(Carrier::Sat));
        let nvme = carrier(Some(health::BUS_NVME)).unwrap_err();
        assert!(nvme.contains("NVMe"), "{nvme}");
        assert!(carrier(Some(14)).is_err(), "a virtual disk");
        assert!(carrier(None).is_err());
    }

    /// IDENTIFY data with `serial` and `model` in their words, each word's bytes swapped.
    pub(crate) fn identify_with(serial: &str, model: &str) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        let mut put = |from: usize, len: usize, text: &str| {
            let mut padded = text.as_bytes().to_vec();
            padded.resize(len * 2, b' ');
            for (i, [first, second]) in padded.as_chunks::<2>().0.iter().enumerate() {
                data[(from + i) * 2] = *second;
                data[(from + i) * 2 + 1] = *first;
            }
        };
        put(10, 10, &format!("{serial:>20}"));
        put(27, 20, model);
        data
    }

    #[test]
    fn the_drive_identity_is_read_from_identify() {
        let data = identify_with("WDZ1ABCD", "ST2000LM007-1R8174");
        assert_eq!(
            drive_id(&data),
            Some(DriveId {
                model: "ST2000LM007-1R8174".into(),
                serial: "WDZ1ABCD".into(),
            })
        );
        // With a checksum: right, then wrong.
        let mut signed = data.clone();
        signed[510] = 0xA5;
        let sum = signed[..511].iter().fold(0u8, |s, b| s.wrapping_add(*b));
        signed[511] = 0u8.wrapping_sub(sum);
        assert!(drive_id(&signed).is_some());
        signed[100] ^= 1;
        assert_eq!(drive_id(&signed), None, "a bad checksum");
        assert_eq!(
            drive_id(&identify_with("", "ST2000LM007")),
            None,
            "no serial"
        );
        let mut garbled = data.clone();
        garbled[22] = 0xFF;
        assert_eq!(drive_id(&garbled), None, "not text");
        assert_eq!(drive_id(&data[..300]), None, "too short");
        assert_eq!(drive_id(&[0u8; 512]), None, "all zeros");
    }
}
