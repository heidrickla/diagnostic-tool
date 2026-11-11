//! SCSI/ATA Translation: an ATA command wrapped in the SCSI ATA PASS-THROUGH (16) command,
//! or the 12-byte form for an older adapter that takes only that, which a USB-to-SATA
//! adapter that implements SAT hands to the drive. It goes in a
//! SCSI_PASS_THROUGH with the sense buffer and the sector after it, sent by
//! `crate::handles::AtaDisk`. This module builds and reads those bytes only.
//!
//! What the adapter answers is read strictly: a SCSI status other than good, or sense data
//! saying the command was not done (ILLEGAL REQUEST from an adapter without SAT), is a
//! failure that names what it said, and a read that came back as zeros is not taken for
//! the drive's data.
use std::sync::atomic::{AtomicBool, Ordering};

use super::ata::{Answer, Command, Direction, Failure, Returned, COMMAND_SECONDS, SECTOR};

/// SCSI_PASS_THROUGH on 64-bit Windows.
pub const HEADER: usize = 56;
/// Where the sense buffer starts, and its size: room for the descriptor-format header and
/// the ATA Status Return descriptor, 8-byte aligned.
pub const SENSE_AT: usize = HEADER;
pub const SENSE_LEN: usize = 32;
/// Where the sector starts, 8-byte aligned.
pub const DATA_AT: usize = SENSE_AT + SENSE_LEN;
/// The whole buffer, sent and returned.
pub const LEN: usize = DATA_AT + SECTOR;

/// ATA PASS-THROUGH (16) and (12).
const OPCODE_16: u8 = 0x85;
const OPCODE_12: u8 = 0xA1;

/// Which ATA PASS-THROUGH command carries the ATA command. Every command sent is a 28-bit
/// one, so both forms carry all of its registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Sixteen,
    Twelve,
}

impl Form {
    pub fn name(self) -> &'static str {
        match self {
            Form::Sixteen => "ATA PASS-THROUGH (16)",
            Form::Twelve => "ATA PASS-THROUGH (12)",
        }
    }
}
/// The protocols used: PIO data-in and PIO data-out.
const PIO_IN: u8 = 4;
const PIO_OUT: u8 = 5;
/// Byte 2: return the registers (CK_COND), data from the drive (T_DIR), length in blocks
/// (BYTE_BLOCK), the length in the count field (T_LENGTH 2).
const CK_COND: u8 = 0x20;
const T_DIR_IN: u8 = 0x08;
const BYTE_BLOCK: u8 = 0x04;
const T_LENGTH_COUNT: u8 = 0x02;

/// SCSI_IOCTL_DATA_OUT and SCSI_IOCTL_DATA_IN.
const DATA_OUT: u8 = 0;
const DATA_IN: u8 = 1;

/// SCSI statuses.
const GOOD: u8 = 0x00;
const CHECK_CONDITION: u8 = 0x02;

/// The sense keys an answer that went well may carry with the drive's registers.
const NO_SENSE: u8 = 0x0;
const RECOVERED_ERROR: u8 = 0x1;
/// The sense key of a command block the adapter would not take.
const ILLEGAL_REQUEST: u8 = 0x5;
/// The ATA Status Return descriptor.
const ATA_RETURN: u8 = 0x09;

/// The ATA PASS-THROUGH command block in `form`. Data-in commands read one 512-byte block
/// by PIO; the one data-out command, the SCT read limit, also asks for the drive's
/// registers back, since its answer is in them. Bytes 1 and 2 are the same in both forms;
/// the 12-byte form holds the registers without the extended (47:24) bytes.
pub fn cdb(command: &Command, form: Form) -> Vec<u8> {
    let r = command.registers();
    let (protocol, flags) = match command.direction() {
        Direction::In => (PIO_IN, T_DIR_IN | BYTE_BLOCK | T_LENGTH_COUNT),
        Direction::Out => (PIO_OUT, CK_COND | BYTE_BLOCK | T_LENGTH_COUNT),
    };
    match form {
        Form::Sixteen => {
            let mut cdb = vec![0u8; 16];
            cdb[0] = OPCODE_16;
            cdb[1] = protocol << 1;
            cdb[2] = flags;
            cdb[4] = r.features;
            cdb[6] = r.count;
            cdb[8] = r.lba_low;
            cdb[10] = r.lba_mid;
            cdb[12] = r.lba_high;
            cdb[13] = r.device;
            cdb[14] = r.command;
            cdb
        }
        Form::Twelve => vec![
            OPCODE_12,
            protocol << 1,
            flags,
            r.features,
            r.count,
            r.lba_low,
            r.lba_mid,
            r.lba_high,
            r.device,
            r.command,
            0,
            0,
        ],
    }
}

/// The IOCTL_SCSI_PASS_THROUGH buffer: SCSI_PASS_THROUGH (length, CDB length 16 or 12,
/// sense length and offset, direction, 512 bytes, timeout, data offset, the CDB), the sense
/// buffer, and the sector, which holds the command's data for data out.
pub fn input(command: &Command, form: Form) -> Vec<u8> {
    let cdb = cdb(command, form);
    let mut buffer = vec![0u8; LEN];
    buffer[0..2].copy_from_slice(&(HEADER as u16).to_le_bytes());
    buffer[6] = cdb.len() as u8;
    buffer[7] = SENSE_LEN as u8;
    buffer[8] = match command.direction() {
        Direction::In => DATA_IN,
        Direction::Out => DATA_OUT,
    };
    buffer[12..16].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    buffer[16..20].copy_from_slice(&COMMAND_SECONDS.to_le_bytes());
    buffer[24..32].copy_from_slice(&(DATA_AT as u64).to_le_bytes());
    buffer[32..36].copy_from_slice(&(SENSE_AT as u32).to_le_bytes());
    buffer[36..36 + cdb.len()].copy_from_slice(&cdb);
    if command.direction() == Direction::Out {
        buffer[DATA_AT..].copy_from_slice(command.sector());
    }
    buffer
}

/// What sense data says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sense {
    pub key: u8,
    pub asc: u8,
    pub ascq: u8,
    /// The drive's registers, when the adapter returned them.
    pub returned: Option<Returned>,
    /// Whether every byte it was read from lies within the length it declares and the bytes
    /// given: false when the declared length runs past the bytes given, a descriptor list
    /// ends in part of a descriptor or one runs past the list, or a fixed-format length stops
    /// short of the ASC and ASCQ. Only complete sense shows that no registers came back.
    pub complete: bool,
}

fn key_name(key: u8) -> String {
    match key {
        0x0 => "NO SENSE".into(),
        0x1 => "RECOVERED ERROR".into(),
        0x2 => "NOT READY".into(),
        0x3 => "MEDIUM ERROR".into(),
        0x4 => "HARDWARE ERROR".into(),
        0x5 => "ILLEGAL REQUEST".into(),
        0x6 => "UNIT ATTENTION".into(),
        0x7 => "DATA PROTECT".into(),
        0xB => "ABORTED COMMAND".into(),
        other => format!("sense key {other:#04x}"),
    }
}

impl Sense {
    /// "ILLEGAL REQUEST, ASC 0x20, ASCQ 0x00", for people.
    pub fn text(&self) -> String {
        format!(
            "{}, ASC {:#04x}, ASCQ {:#04x}",
            key_name(self.key),
            self.asc,
            self.ascq
        )
    }
}

/// Reads sense data: descriptor format (response code 0x72 or 0x73), the drive's registers
/// from its ATA Status Return descriptor (code 0x09); or fixed format (0x70 or 0x71), the
/// registers from its information fields when ASC/ASCQ is 00/1D, ATA PASS THROUGH
/// INFORMATION AVAILABLE.
pub fn parse_sense(sense: &[u8]) -> Result<Sense, Failure> {
    let malformed = |why: &str| Failure::Malformed(format!("the adapter's sense data {why}"));
    let code = sense.first().ok_or_else(|| malformed("was empty"))? & 0x7F;
    match code {
        0x72 | 0x73 => {
            if sense.len() < 8 {
                return Err(malformed("was cut short"));
            }
            let declared = 8 + usize::from(sense[7]);
            let mut descriptors = &sense[8..declared.min(sense.len())];
            let mut returned = None;
            let mut complete = declared <= sense.len();
            while !descriptors.is_empty() {
                let [kind, len, rest @ ..] = descriptors else {
                    complete = false;
                    break;
                };
                let len = usize::from(*len);
                if *kind == ATA_RETURN {
                    // EXTEND, ERROR, COUNT (15:8, 7:0), LBA (31:24, 7:0, 39:32, 15:8,
                    // 47:40, 23:16), DEVICE, STATUS.
                    let d = rest
                        .get(..12)
                        .filter(|_| len >= 12)
                        .ok_or_else(|| malformed("held a cut-short ATA return descriptor"))?;
                    returned = Some(Returned {
                        error: d[1],
                        count: d[3],
                        lba_low: d[5],
                        lba_mid: d[7],
                        lba_high: d[9],
                        device: d[10],
                        status: d[11],
                    });
                    break;
                }
                let Some(next) = rest.get(len..) else {
                    complete = false;
                    break;
                };
                descriptors = next;
            }
            Ok(Sense {
                key: sense[1] & 0x0F,
                asc: sense[2],
                ascq: sense[3],
                returned,
                complete,
            })
        }
        0x70 | 0x71 => {
            if sense.len() < 14 {
                return Err(malformed("was cut short"));
            }
            let (asc, ascq) = (sense[12], sense[13]);
            // ASC and ASCQ end at byte 13: an additional length of at least 6.
            let declared = 8 + usize::from(sense[7]);
            let complete = declared >= 14 && declared <= sense.len();
            // INFORMATION: ERROR, STATUS, DEVICE, COUNT (7:0); COMMAND-SPECIFIC: flags,
            // LBA (7:0, 15:8, 23:16).
            let returned = (asc == 0x00 && ascq == 0x1D).then(|| Returned {
                error: sense[3],
                status: sense[4],
                device: sense[5],
                count: sense[6],
                lba_low: sense[9],
                lba_mid: sense[10],
                lba_high: sense[11],
            });
            Ok(Sense {
                key: sense[2] & 0x0F,
                asc,
                ascq,
                returned,
                complete,
            })
        }
        other => Err(malformed(&format!(
            "was not understood (response code {other:#04x})"
        ))),
    }
}

/// How a reply reads: the adapter's answer; a command block the adapter did not take, so
/// the other form is worth sending; or another failure.
enum Read {
    Answered(Answer),
    BlockRefused(Failure),
    Failed(Failure),
}

/// Reads the returned buffer (all of it, unwritten bytes zero) once, for both `answer` and
/// `exchange`. A command block not taken is ILLEGAL REQUEST with INVALID COMMAND OPERATION
/// CODE (0x20) or INVALID FIELD IN CDB (0x24) and no drive registers, which an adapter
/// answers without passing anything to the drive; or a full read answered good with a
/// sector of zeros, which some adapters send for a command block they ignore. Nothing else
/// is: a short transfer is malformed, and a good status for the read limit may mean the
/// drive took it.
fn read(reply: &[u8], command: &Command) -> Read {
    if reply.len() < LEN {
        return Read::Failed(Failure::Malformed(
            "the adapter's reply was too short".into(),
        ));
    }
    let status = reply[2];
    let returned = match status {
        GOOD => None,
        CHECK_CONDITION => {
            let given = usize::from(reply[7]).min(SENSE_LEN);
            let sense = match parse_sense(&reply[SENSE_AT..SENSE_AT + given]) {
                Ok(sense) => sense,
                Err(failure) => return Read::Failed(failure),
            };
            match sense.returned {
                // The drive's own error or an unfinished command, whatever the sense key:
                // `ata::checked` says which.
                Some(returned) if !returned.completed() => {
                    return Read::Answered(Answer {
                        data: Vec::new(),
                        returned: Some(returned),
                    })
                }
                Some(returned) if matches!(sense.key, NO_SENSE | RECOVERED_ERROR) => Some(returned),
                _ => {
                    let failure =
                        Failure::NotPassed(format!("the adapter answered {}", sense.text()));
                    // Only sense read in full shows that no drive registers came back.
                    let unseen = sense.returned.is_none() && sense.complete;
                    let refused = unseen
                        && (sense.key == ILLEGAL_REQUEST && matches!(sense.asc, 0x20 | 0x24)
                            || matches!(sense.key, NO_SENSE | RECOVERED_ERROR)
                                && full_zero_read(reply, command));
                    return if refused {
                        Read::BlockRefused(failure)
                    } else {
                        Read::Failed(failure)
                    };
                }
            }
        }
        other => {
            return Read::Failed(Failure::NotPassed(format!(
                "the adapter answered SCSI status {other:#04x}"
            )))
        }
    };
    let data = match command.direction() {
        Direction::Out => Vec::new(),
        Direction::In => {
            let moved = u32::from_le_bytes(reply[12..16].try_into().unwrap()) as usize;
            if moved != SECTOR {
                return Read::Failed(Failure::Malformed(format!(
                    "the adapter returned {moved} of {SECTOR} bytes"
                )));
            }
            let data = &reply[DATA_AT..DATA_AT + SECTOR];
            // Some adapters without SAT answer good and send nothing back.
            if data.iter().all(|b| *b == 0) {
                let failure = Failure::NotPassed(
                    "the adapter sent back only zeros, so the command did not reach the drive"
                        .into(),
                );
                return if returned.is_none() {
                    Read::BlockRefused(failure)
                } else {
                    Read::Failed(failure)
                };
            }
            data.to_vec()
        }
    };
    Read::Answered(Answer { data, returned })
}

/// Whether `reply` to a read moved the whole sector and it is all zeros.
fn full_zero_read(reply: &[u8], command: &Command) -> bool {
    command.direction() == Direction::In
        && u32::from_le_bytes(reply[12..16].try_into().unwrap()) as usize == SECTOR
        && reply[DATA_AT..DATA_AT + SECTOR].iter().all(|b| *b == 0)
}

/// The adapter's answer from the returned buffer (all of it, unwritten bytes zero).
pub fn answer(reply: &[u8], command: &Command) -> Result<Answer, Failure> {
    match read(reply, command) {
        Read::Answered(answer) => Ok(answer),
        Read::BlockRefused(failure) | Read::Failed(failure) => Err(failure),
    }
}

impl Form {
    fn other(self) -> Self {
        match self {
            Form::Sixteen => Form::Twelve,
            Form::Twelve => Form::Sixteen,
        }
    }
}

/// `failure` with its text replaced, its kind kept.
fn retold(failure: Failure, text: String) -> Failure {
    match failure {
        Failure::Open(_) => Failure::Open(text),
        Failure::NotPassed(_) => Failure::NotPassed(text),
        Failure::Refused(_) => Failure::Refused(text),
        Failure::Malformed(_) => Failure::Malformed(text),
    }
}

/// Sends `command` through `send` in the form this adapter takes and reads the answer.
/// The form last proven goes first (16 bytes until `twelve` is set); when the adapter does
/// not take that command block, the other form is sent once, and when the drive's data or
/// registers come back from it, `twelve` remembers it. When neither is taken, the failure
/// names both answers.
pub fn exchange(
    command: &Command,
    twelve: &AtomicBool,
    mut send: impl FnMut(Form) -> Result<Vec<u8>, Failure>,
) -> Result<Answer, Failure> {
    let first_form = if twelve.load(Ordering::Relaxed) {
        Form::Twelve
    } else {
        Form::Sixteen
    };
    let first = match read(&send(first_form)?, command) {
        Read::Answered(answer) => return Ok(answer),
        Read::Failed(failure) => return Err(failure),
        Read::BlockRefused(failure) => failure,
    };
    let other = first_form.other();
    let second = match send(other).map(|reply| read(&reply, command)) {
        Ok(Read::Answered(taken)) => {
            if taken.returned.is_some() || !taken.data.is_empty() {
                twelve.store(other == Form::Twelve, Ordering::Relaxed);
            }
            return Ok(taken);
        }
        Ok(Read::BlockRefused(failure) | Read::Failed(failure)) | Err(failure) => failure,
    };
    let text = format!(
        "{} to {}, and {} to {}",
        first.text(),
        first_form.name(),
        second.text(),
        other.name()
    );
    Err(retold(second, text))
}

#[cfg(test)]
mod tests {
    use super::super::ata::{self, AtaCommand};
    use super::super::sct;
    use super::*;

    /// SCSI_PASS_THROUGH as ntddscsi.h lays it out on x64.
    #[repr(C)]
    struct ScsiPassThrough {
        length: u16,
        scsi_status: u8,
        path_id: u8,
        target_id: u8,
        lun: u8,
        cdb_length: u8,
        sense_info_length: u8,
        data_in: u8,
        data_transfer_length: u32,
        time_out_value: u32,
        data_buffer_offset: usize,
        sense_info_offset: u32,
        cdb: [u8; 16],
    }

    #[test]
    fn the_pass_through_header_matches_the_windows_layout() {
        use std::mem::offset_of;
        assert_eq!(std::mem::size_of::<ScsiPassThrough>(), HEADER);
        assert_eq!(offset_of!(ScsiPassThrough, scsi_status), 2);
        assert_eq!(offset_of!(ScsiPassThrough, cdb_length), 6);
        assert_eq!(offset_of!(ScsiPassThrough, sense_info_length), 7);
        assert_eq!(offset_of!(ScsiPassThrough, data_in), 8);
        assert_eq!(offset_of!(ScsiPassThrough, data_transfer_length), 12);
        assert_eq!(offset_of!(ScsiPassThrough, time_out_value), 16);
        assert_eq!(offset_of!(ScsiPassThrough, data_buffer_offset), 24);
        assert_eq!(offset_of!(ScsiPassThrough, sense_info_offset), 32);
        assert_eq!(offset_of!(ScsiPassThrough, cdb), 36);
        assert_eq!(SENSE_AT % 8, 0);
        assert_eq!(DATA_AT % 8, 0);
        assert_eq!(LEN, 600);
    }

    /// The guard: each command's CDB is ATA PASS-THROUGH (16) with its registers in place,
    /// PIO data-in for the three reads and PIO data-out with the registers returned for the
    /// read limit, one 512-byte block counted in the count field.
    #[test]
    fn each_command_is_wrapped_in_ata_pass_through_16() {
        let expected: [(ata::Command, [u8; 16]); 4] = [
            (
                ata::Command::read(AtaCommand::SmartReadData),
                [
                    0x85, 0x08, 0x0E, 0, 0xD0, 0, 1, 0, 1, 0, 0x4F, 0, 0xC2, 0xA0, 0xB0, 0,
                ],
            ),
            (
                ata::Command::read(AtaCommand::SmartReadThresholds),
                [
                    0x85, 0x08, 0x0E, 0, 0xD1, 0, 1, 0, 1, 0, 0x4F, 0, 0xC2, 0xA0, 0xB0, 0,
                ],
            ),
            (
                ata::Command::read(AtaCommand::Identify),
                [
                    0x85, 0x08, 0x0E, 0, 0x00, 0, 1, 0, 1, 0, 0x00, 0, 0x00, 0xA0, 0xEC, 0,
                ],
            ),
            (
                ata::Command::sct(sct::Request::Set(15)),
                [
                    0x85, 0x0A, 0x26, 0, 0xD6, 0, 1, 0, 0xE0, 0, 0x4F, 0, 0xC2, 0xA0, 0xB0, 0,
                ],
            ),
        ];
        for (command, bytes) in &expected {
            assert_eq!(
                cdb(command, Form::Sixteen),
                bytes.to_vec(),
                "{:?}",
                command.registers()
            );
        }
        // Byte 1: protocol 4 or 5, no multiple count, not extended. Byte 2: CK_COND only
        // for the read limit; T_DIR only for the reads; BYTE_BLOCK and T_LENGTH 2 always.
        assert_eq!(0x08 >> 1, 4);
        assert_eq!(0x0A >> 1, 5);
    }

    #[test]
    fn the_buffer_holds_the_header_sense_room_and_sector() {
        let read = ata::Command::read(AtaCommand::Identify);
        let bytes = input(&read, Form::Sixteen);
        assert_eq!(bytes.len(), LEN);
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 56);
        assert_eq!((bytes[2], bytes[3], bytes[4], bytes[5]), (0, 0, 0, 0));
        assert_eq!((bytes[6], bytes[7], bytes[8]), (16, 32, 1));
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 512);
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 10);
        assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 88);
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 56);
        assert_eq!(bytes[36..52], cdb(&read, Form::Sixteen)[..]);
        assert!(bytes[52..].iter().all(|b| *b == 0));
        let set = ata::Command::sct(sct::Request::Set(100));
        let bytes = input(&set, Form::Sixteen);
        assert_eq!(bytes[8], 0, "data out");
        assert_eq!(bytes[DATA_AT..], set.sector()[..]);
        assert!(bytes[SENSE_AT..DATA_AT].iter().all(|b| *b == 0));
    }

    /// A reply to `command` with SCSI status `status`, sense `sense`, `moved` bytes and the
    /// sector `data`.
    fn reply(command: &ata::Command, status: u8, sense: &[u8], moved: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = input(command, Form::Sixteen);
        bytes[2] = status;
        bytes[7] = sense.len() as u8;
        bytes[SENSE_AT..SENSE_AT + sense.len()].copy_from_slice(sense);
        bytes[12..16].copy_from_slice(&moved.to_le_bytes());
        bytes[DATA_AT..DATA_AT + data.len()].copy_from_slice(data);
        bytes
    }

    /// Descriptor-format sense with an ATA Status Return descriptor.
    fn descriptor_sense(key: u8, error: u8, count: u8, lba_low: u8, status: u8) -> Vec<u8> {
        let mut sense = vec![0x72, key, 0x00, 0x1D, 0, 0, 0, 14];
        sense.extend_from_slice(&[
            0x09, 0x0C, 0, error, 0, count, 0, lba_low, 0, 0x4F, 0, 0xC2, 0xA0, status,
        ]);
        sense
    }

    #[test]
    fn a_read_returns_its_sector() {
        let read = ata::Command::read(AtaCommand::Identify);
        let mut data = vec![0u8; 512];
        data[20] = b'W';
        let answer = super::answer(&reply(&read, GOOD, &[], 512, &data), &read).unwrap();
        assert_eq!(answer.data, data);
        assert_eq!(answer.returned, None);
        // Some adapters return the registers with a read as well.
        let sense = descriptor_sense(RECOVERED_ERROR, 0, 0, 0, 0x50);
        let answer =
            super::answer(&reply(&read, CHECK_CONDITION, &sense, 512, &data), &read).unwrap();
        assert_eq!(answer.data, data);
        assert_eq!(answer.returned.unwrap().status, 0x50);
    }

    #[test]
    fn the_read_limit_comes_back_in_the_returned_registers() {
        let command = ata::Command::sct(sct::Request::Read);
        // 300 tenths: count 0x2C, LBA low 0x01.
        let sense = descriptor_sense(RECOVERED_ERROR, 0, 0x2C, 0x01, 0x50);
        let answer = ata::checked(
            &command,
            super::answer(
                &reply(&command, CHECK_CONDITION, &sense, 512, &[]),
                &command,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(sct::limit(sct::Request::Read, &answer), Ok(Some(300)));
        // Fixed format, as an adapter with D_SENSE off returns it.
        let mut fixed = vec![0u8; 18];
        fixed[0] = 0x70;
        fixed[2] = RECOVERED_ERROR;
        fixed[3..7].copy_from_slice(&[0, 0x50, 0xA0, 70]);
        fixed[7] = 10;
        fixed[9..12].copy_from_slice(&[0, 0x4F, 0xC2]);
        fixed[12] = 0x00;
        fixed[13] = 0x1D;
        let answer = super::answer(
            &reply(&command, CHECK_CONDITION, &fixed, 512, &[]),
            &command,
        )
        .unwrap();
        assert_eq!(sct::limit(sct::Request::Read, &answer), Ok(Some(70)));
    }

    #[test]
    fn an_adapter_without_sat_is_named_by_what_it_answered() {
        let read = ata::Command::read(AtaCommand::SmartReadData);
        // ILLEGAL REQUEST, INVALID COMMAND OPERATION CODE, fixed format.
        let mut illegal = vec![0u8; 18];
        illegal[0] = 0x70;
        illegal[2] = 0x05;
        illegal[7] = 10;
        illegal[12] = 0x20;
        let refused = super::answer(&reply(&read, CHECK_CONDITION, &illegal, 0, &[]), &read);
        let Err(Failure::NotPassed(why)) = refused else {
            panic!("{refused:?}");
        };
        assert!(
            why.contains("ILLEGAL REQUEST") && why.contains("ASC 0x20"),
            "{why}"
        );
        // Descriptor format without an ATA return descriptor.
        let illegal = [0x72, 0x05, 0x24, 0x00, 0, 0, 0, 0];
        let refused = super::answer(&reply(&read, CHECK_CONDITION, &illegal, 0, &[]), &read);
        assert!(matches!(refused, Err(Failure::NotPassed(why)) if why.contains("ASC 0x24")));
        // A good status with nothing sent back.
        let empty = super::answer(&reply(&read, GOOD, &[], 512, &[]), &read);
        assert!(matches!(empty, Err(Failure::NotPassed(why)) if why.contains("only zeros")));
        // Busy, or anything else but good and check condition.
        let busy = super::answer(&reply(&read, 0x08, &[], 0, &[]), &read);
        assert!(matches!(busy, Err(Failure::NotPassed(why)) if why.contains("0x08")));
        // Not ready, with registers that show no error: the command was not done.
        let not_ready = descriptor_sense(0x02, 0, 0, 0, 0x50);
        let refused = super::answer(&reply(&read, CHECK_CONDITION, &not_ready, 0, &[]), &read);
        assert!(matches!(refused, Err(Failure::NotPassed(why)) if why.contains("NOT READY")));
    }

    #[test]
    fn a_drive_that_refuses_is_said_to() {
        const ABORTED_COMMAND: u8 = 0xB;
        let command = ata::Command::sct(sct::Request::Read);
        // ABORTED COMMAND with ERR and ABRT in the registers.
        let sense = descriptor_sense(ABORTED_COMMAND, 0x04, 0, 0, 0x51);
        let answer =
            super::answer(&reply(&command, CHECK_CONDITION, &sense, 0, &[]), &command).unwrap();
        let refused = ata::checked(&command, answer);
        assert!(matches!(refused, Err(Failure::Refused(why)) if why.contains("0x51")));
        let read = ata::Command::read(AtaCommand::SmartReadData);
        let answer = super::answer(&reply(&read, CHECK_CONDITION, &sense, 0, &[]), &read).unwrap();
        assert!(matches!(
            ata::checked(&read, answer),
            Err(Failure::Refused(_))
        ));
        // A medium error on a read carries the drive's error too.
        let medium = descriptor_sense(0x03, 0x40, 0, 0, 0x51);
        let answer = super::answer(&reply(&read, CHECK_CONDITION, &medium, 0, &[]), &read).unwrap();
        assert!(matches!(
            ata::checked(&read, answer),
            Err(Failure::Refused(_))
        ));
    }

    /// A busy status in the returned registers is not an answer, on SAT as on Windows' path.
    #[test]
    fn a_busy_drive_is_not_answered() {
        let command = ata::Command::sct(sct::Request::Read);
        let sense = descriptor_sense(RECOVERED_ERROR, 0, 0x2C, 0x01, 0xD0);
        let answer = super::answer(
            &reply(&command, CHECK_CONDITION, &sense, 512, &[]),
            &command,
        )
        .unwrap();
        assert!(matches!(
            ata::checked(&command, answer),
            Err(Failure::NotPassed(why)) if why.contains("not finished")
        ));
    }

    #[test]
    fn malformed_replies_are_not_taken() {
        let command = ata::Command::sct(sct::Request::Read);
        // Check condition with no sense data at all.
        let none = super::answer(&reply(&command, CHECK_CONDITION, &[], 0, &[]), &command);
        assert!(matches!(none, Err(Failure::Malformed(why)) if why.contains("empty")));
        // An ATA return descriptor cut short.
        let cut = [0x72, 0x01, 0x00, 0x1D, 0, 0, 0, 6, 0x09, 0x0C, 0, 0, 0, 0];
        let cut = super::answer(&reply(&command, CHECK_CONDITION, &cut, 0, &[]), &command);
        assert!(matches!(cut, Err(Failure::Malformed(why)) if why.contains("cut-short")));
        // A response code that is not sense data.
        let odd = super::answer(
            &reply(&command, CHECK_CONDITION, &[0x11; 8], 0, &[]),
            &command,
        );
        assert!(matches!(odd, Err(Failure::Malformed(why)) if why.contains("0x11")));
        // Fixed format cut short.
        assert!(parse_sense(&[0x70, 0, 0x01]).is_err());
        // A read that moved part of its sector.
        let read = ata::Command::read(AtaCommand::Identify);
        let part = super::answer(&reply(&read, GOOD, &[], 200, &[1; 200]), &read);
        assert!(matches!(part, Err(Failure::Malformed(why)) if why.contains("200 of 512")));
        // A reply shorter than the buffer.
        assert!(super::answer(&[0u8; 40], &read).is_err());
        // The read limit with a good status and no registers: its answer is not known.
        let good = super::answer(&reply(&command, GOOD, &[], 512, &[]), &command).unwrap();
        assert!(matches!(
            ata::checked(&command, good),
            Err(Failure::NotPassed(_))
        ));
        // Sense longer than the buffer's room is read only as far as the room.
        let mut long = input(&command, Form::Sixteen);
        long[2] = CHECK_CONDITION;
        long[7] = 200;
        long[SENSE_AT..SENSE_AT + 22].copy_from_slice(&descriptor_sense(1, 0, 15, 0, 0x50));
        let answer = super::answer(&long, &command).unwrap();
        assert_eq!(answer.returned.unwrap().count, 15);
    }

    /// The guard: the 12-byte form carries the same protocol, flags and 28-bit registers as
    /// the 16-byte form, in the 12-byte layout, and the buffer says the CDB is 12 bytes long.
    #[test]
    fn the_twelve_byte_form_carries_the_same_registers() {
        assert_eq!(
            cdb(&ata::Command::read(AtaCommand::SmartReadData), Form::Twelve),
            [0xA1, 0x08, 0x0E, 0xD0, 1, 1, 0x4F, 0xC2, 0xA0, 0xB0, 0, 0]
        );
        assert_eq!(
            cdb(&ata::Command::sct(sct::Request::Set(15)), Form::Twelve),
            [0xA1, 0x0A, 0x26, 0xD6, 1, 0xE0, 0x4F, 0xC2, 0xA0, 0xB0, 0, 0]
        );
        for command in [
            ata::Command::read(AtaCommand::SmartReadData),
            ata::Command::read(AtaCommand::SmartReadThresholds),
            ata::Command::read(AtaCommand::Identify),
            ata::Command::sct(sct::Request::Read),
            ata::Command::sct(sct::Request::Set(100)),
        ] {
            let (long, short) = (cdb(&command, Form::Sixteen), cdb(&command, Form::Twelve));
            let moved = [
                (1, 1),
                (2, 2),
                (4, 3),
                (6, 4),
                (8, 5),
                (10, 6),
                (12, 7),
                (13, 8),
                (14, 9),
            ];
            for (from, to) in moved {
                assert_eq!(
                    long[from],
                    short[to],
                    "{:?} byte {from}",
                    command.registers()
                );
            }
            // Nothing in the extended bytes the 12-byte form cannot hold.
            assert!([3, 5, 7, 9, 11].iter().all(|at| long[*at] == 0));
            let bytes = input(&command, Form::Twelve);
            assert_eq!(bytes[6], 12);
            assert_eq!(bytes[36..48], short[..]);
            assert!(bytes[48..52].iter().all(|b| *b == 0));
        }
    }

    /// Fixed-format ILLEGAL REQUEST with `asc`, no registers.
    fn illegal(asc: u8) -> Vec<u8> {
        let mut sense = vec![0u8; 18];
        sense[0] = 0x70;
        sense[2] = 0x05;
        sense[7] = 10;
        sense[12] = asc;
        sense
    }

    /// Runs `exchange` against replies given in order, returning its result and the forms sent.
    fn exchanged(
        command: &ata::Command,
        twelve: &AtomicBool,
        replies: Vec<Vec<u8>>,
    ) -> (Result<Answer, Failure>, Vec<Form>) {
        let mut replies = replies.into_iter();
        let mut sent = Vec::new();
        let result = exchange(command, twelve, |form| {
            sent.push(form);
            Ok(replies.next().expect("a reply for each command sent"))
        });
        (result, sent)
    }

    /// The guard: an adapter that refuses the 16-byte command block is sent the 12-byte one,
    /// and once that is answered only the 12-byte form goes to it.
    #[test]
    fn an_adapter_that_takes_only_twelve_bytes_is_sent_twelve() {
        let read = ata::Command::read(AtaCommand::Identify);
        let mut data = vec![0u8; 512];
        data[20] = b'W';
        let twelve = AtomicBool::new(false);
        for asc in [0x20, 0x24] {
            twelve.store(false, Ordering::Relaxed);
            let (result, sent) = exchanged(
                &read,
                &twelve,
                vec![
                    reply(&read, CHECK_CONDITION, &illegal(asc), 0, &[]),
                    reply(&read, GOOD, &[], 512, &data),
                ],
            );
            assert_eq!(result.unwrap().data, data);
            assert_eq!(sent, [Form::Sixteen, Form::Twelve]);
            assert!(twelve.load(Ordering::Relaxed));
        }
        let (result, sent) = exchanged(&read, &twelve, vec![reply(&read, GOOD, &[], 512, &data)]);
        assert_eq!(result.unwrap().data, data);
        assert_eq!(sent, [Form::Twelve]);
        // A read answered good with zeros is tried in the 12-byte form too.
        let twelve = AtomicBool::new(false);
        let (result, sent) = exchanged(
            &read,
            &twelve,
            vec![
                reply(&read, GOOD, &[], 512, &[]),
                reply(&read, GOOD, &[], 512, &data),
            ],
        );
        assert_eq!(result.unwrap().data, data);
        assert_eq!(sent, [Form::Sixteen, Form::Twelve]);
    }

    #[test]
    fn an_adapter_that_takes_neither_is_named_by_both_answers() {
        let read = ata::Command::read(AtaCommand::SmartReadData);
        let twelve = AtomicBool::new(false);
        let (result, sent) = exchanged(
            &read,
            &twelve,
            vec![
                reply(&read, CHECK_CONDITION, &illegal(0x20), 0, &[]),
                reply(&read, CHECK_CONDITION, &illegal(0x20), 0, &[]),
            ],
        );
        let Err(Failure::NotPassed(why)) = result else {
            panic!("{result:?}");
        };
        assert!(
            why.contains("ASCQ 0x00 to ATA PASS-THROUGH (16), and the adapter answered")
                && why.ends_with("to ATA PASS-THROUGH (12)"),
            "{why}"
        );
        assert_eq!(sent, [Form::Sixteen, Form::Twelve]);
        assert!(!twelve.load(Ordering::Relaxed));
    }

    /// What the 16-byte form got to the drive, or what says nothing about the command block,
    /// is answered as it stands: nothing is sent again.
    #[test]
    fn only_a_refused_command_block_is_sent_again() {
        let twelve = AtomicBool::new(false);
        let read = ata::Command::read(AtaCommand::SmartReadData);
        let limit = ata::Command::sct(sct::Request::Set(15));
        let mut data = vec![0u8; 512];
        data[0] = 1;
        let mut seen = descriptor_sense(0x5, 0x04, 0, 0, 0x51);
        seen[2] = 0x24;
        // The same with registers that show no error.
        let mut seen_clean = descriptor_sense(0x5, 0, 0, 0, 0x50);
        seen_clean[2] = 0x24;
        let mut fixed_short = illegal(0x24);
        fixed_short[7] = 0;
        // INVALID FIELD IN CDB under another sense key.
        let mut aborted = illegal(0x24);
        aborted[2] = 0x0B;
        // A read with the drive's registers and a sector of zeros.
        let zeros_seen = descriptor_sense(RECOVERED_ERROR, 0, 0, 0, 0x50);
        // A good status for the read limit, its sector as the adapter left it: zeros.
        let mut limit_good = reply(&limit, GOOD, &[], 512, &[]);
        limit_good[DATA_AT..].fill(0);
        let replies = [
            // Taken.
            (&read, reply(&read, GOOD, &[], 512, &data)),
            // The drive's own refusal, with its registers.
            (
                &read,
                reply(
                    &read,
                    CHECK_CONDITION,
                    &descriptor_sense(0xB, 0x04, 0, 0, 0x51),
                    0,
                    &[],
                ),
            ),
            // ILLEGAL REQUEST, INVALID FIELD IN CDB, with the drive's registers: the drive saw it.
            (&read, reply(&read, CHECK_CONDITION, &seen, 0, &[])),
            (&read, reply(&read, CHECK_CONDITION, &seen_clean, 0, &[])),
            (&read, reply(&read, CHECK_CONDITION, &aborted, 0, &[])),
            (&read, reply(&read, CHECK_CONDITION, &zeros_seen, 512, &[])),
            // Another sense key or ASC.
            (
                &read,
                reply(
                    &read,
                    CHECK_CONDITION,
                    &[0x72, 0x02, 0x04, 0x00, 0, 0, 0, 0],
                    0,
                    &[],
                ),
            ),
            (&read, reply(&read, CHECK_CONDITION, &illegal(0x25), 0, &[])),
            // Another SCSI status.
            (&read, reply(&read, 0x08, &[], 0, &[])),
            // The read limit with a good status: the drive may have taken it.
            (&limit, limit_good),
            // ILLEGAL REQUEST whose descriptor list was not read in full: a list that ends in
            // one byte, one that says it runs past the bytes given, and a descriptor longer
            // than what is left. Its ATA return descriptor may be what is missing.
            (
                &limit,
                reply(
                    &limit,
                    CHECK_CONDITION,
                    &[0x72, 0x05, 0x24, 0, 0, 0, 0, 1, 0x09],
                    0,
                    &[],
                ),
            ),
            (
                &limit,
                reply(
                    &limit,
                    CHECK_CONDITION,
                    &[0x72, 0x05, 0x24, 0, 0, 0, 0, 14],
                    0,
                    &[],
                ),
            ),
            // The same in fixed format: an additional length of 0 stops short of the ASC.
            (&limit, reply(&limit, CHECK_CONDITION, &fixed_short, 0, &[])),
            (
                &limit,
                reply(
                    &limit,
                    CHECK_CONDITION,
                    &[0x72, 0x05, 0x24, 0, 0, 0, 0, 4, 0x02, 0x06, 0, 0],
                    0,
                    &[],
                ),
            ),
        ];
        for (command, reply) in replies {
            let (_, sent) = exchanged(command, &twelve, vec![reply]);
            assert_eq!(sent, [Form::Sixteen]);
        }
        assert!(!twelve.load(Ordering::Relaxed));
        // A failure to send at all is not retried either.
        let mut sent = 0;
        let result = exchange(&read, &twelve, |_| {
            sent += 1;
            Err(Failure::NotPassed("the device is not connected".into()))
        });
        assert!(matches!(result, Err(Failure::NotPassed(why)) if why.contains("not connected")));
        assert_eq!(sent, 1);
    }

    /// A handle that has taken the 12-byte form goes back to the 16-byte form when the
    /// adapter refuses the 12-byte block for a command, and remembers that instead.
    #[test]
    fn the_other_form_is_tried_either_way() {
        let read = ata::Command::read(AtaCommand::Identify);
        let mut data = vec![0u8; 512];
        data[20] = b'W';
        let twelve = AtomicBool::new(true);
        let (result, sent) = exchanged(
            &read,
            &twelve,
            vec![
                reply(&read, CHECK_CONDITION, &illegal(0x24), 0, &[]),
                reply(&read, GOOD, &[], 512, &data),
            ],
        );
        assert_eq!(result.unwrap().data, data);
        assert_eq!(sent, [Form::Twelve, Form::Sixteen]);
        assert!(!twelve.load(Ordering::Relaxed));
    }

    /// A short read is malformed whatever its bytes, and is not sent again.
    #[test]
    fn a_short_read_of_zeros_is_not_sent_again() {
        let read = ata::Command::read(AtaCommand::Identify);
        let twelve = AtomicBool::new(false);
        for moved in [0, 200] {
            let (result, sent) =
                exchanged(&read, &twelve, vec![reply(&read, GOOD, &[], moved, &[])]);
            assert!(
                matches!(&result, Err(Failure::Malformed(why)) if why.contains(&format!("{moved} of 512"))),
                "{result:?}"
            );
            assert_eq!(sent, [Form::Sixteen]);
        }
    }

    /// Only the drive's data or registers prove a form: a good status for the read limit
    /// with nothing back is passed on for `ata::checked` to refuse, and proves nothing.
    #[test]
    fn a_form_is_remembered_only_when_the_drive_answered() {
        let limit = ata::Command::sct(sct::Request::Set(15));
        let twelve = AtomicBool::new(false);
        let (result, sent) = exchanged(
            &limit,
            &twelve,
            vec![
                reply(&limit, CHECK_CONDITION, &illegal(0x20), 0, &[]),
                reply(&limit, GOOD, &[], 512, &[]),
            ],
        );
        assert_eq!(sent, [Form::Sixteen, Form::Twelve]);
        assert!(!twelve.load(Ordering::Relaxed));
        assert!(matches!(
            ata::checked(&limit, result.unwrap()),
            Err(Failure::NotPassed(_))
        ));
        // With the drive's registers back, it is remembered.
        let sense = descriptor_sense(RECOVERED_ERROR, 0, 15, 0, 0x50);
        let (result, _) = exchanged(
            &limit,
            &twelve,
            vec![
                reply(&limit, CHECK_CONDITION, &illegal(0x20), 0, &[]),
                reply(&limit, CHECK_CONDITION, &sense, 512, &[]),
            ],
        );
        assert!(ata::checked(&limit, result.unwrap()).is_ok());
        assert!(twelve.load(Ordering::Relaxed));
    }

    /// A full read of zeros with a check condition that reports nothing wrong and no drive
    /// registers is the same as a good status with zeros: the other form is tried.
    #[test]
    fn a_benign_check_condition_with_zeros_tries_the_other_form() {
        let read = ata::Command::read(AtaCommand::Identify);
        let mut data = vec![0u8; 512];
        data[20] = b'W';
        let mut nothing = vec![0u8; 18];
        nothing[0] = 0x70;
        nothing[7] = 10;
        for key in [NO_SENSE, RECOVERED_ERROR] {
            nothing[2] = key;
            let twelve = AtomicBool::new(false);
            let (result, sent) = exchanged(
                &read,
                &twelve,
                vec![
                    reply(&read, CHECK_CONDITION, &nothing, 512, &[]),
                    reply(&read, GOOD, &[], 512, &data),
                ],
            );
            assert_eq!(result.unwrap().data, data);
            assert_eq!(sent, [Form::Sixteen, Form::Twelve]);
            // With data, or a short transfer, it is not.
            for (moved, sector) in [(512, &data[..]), (0, &[][..])] {
                let (_, sent) = exchanged(
                    &read,
                    &AtomicBool::new(false),
                    vec![reply(&read, CHECK_CONDITION, &nothing, moved, sector)],
                );
                assert_eq!(sent, [Form::Sixteen]);
            }
        }
    }

    /// Sense data says whether its descriptor list was read in full.
    #[test]
    fn sense_says_whether_it_was_read_in_full() {
        let whole = parse_sense(&[0x72, 0x05, 0x24, 0, 0, 0, 0, 4, 0x02, 0x02, 0, 0]).unwrap();
        assert!(whole.complete && whole.returned.is_none());
        assert!(
            parse_sense(&[0x72, 0x05, 0x24, 0, 0, 0, 0, 0])
                .unwrap()
                .complete
        );
        for cut in [
            &[0x72, 0x05, 0x24, 0, 0, 0, 0, 1, 0x09][..],
            &[0x72, 0x05, 0x24, 0, 0, 0, 0, 14],
            &[0x72, 0x05, 0x24, 0, 0, 0, 0, 4, 0x02, 0x06, 0, 0],
        ] {
            assert!(!parse_sense(cut).unwrap().complete, "{cut:?}");
        }
        assert!(parse_sense(&illegal(0x20)).unwrap().complete);
        // Fixed format: a length short of the ASC, or past the bytes given.
        let mut short = illegal(0x24);
        short[7] = 5;
        assert!(!parse_sense(&short).unwrap().complete);
        short[7] = 6;
        assert!(parse_sense(&short).unwrap().complete);
        let mut long = illegal(0x24);
        long[7] = 11;
        assert!(!parse_sense(&long).unwrap().complete);
        assert!(!parse_sense(&illegal(0x24)[..14]).unwrap().complete);
    }
}
