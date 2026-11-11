//! SCT Error Recovery Control: how long an ATA drive keeps trying one failing read before it
//! reports the error. A failing drive left to itself can spend a minute or more on each bad
//! sector; a rescue asks it to give up sooner on the first passes and to try longer on the
//! retries. The setting is volatile: the drive forgets it at its next power cycle.
//!
//! This module builds the SCT command sector and reads the limit from the drive's returned
//! registers; `ata::Command::sct` wraps the sector in SMART WRITE LOG and `handles::SctDrive`
//! sends it through the disk's carrier. The one SCT command built here is action code 3,
//! Error Recovery Control, for the read timer only: return the current value, or set a new
//! one. No other action code can be built (some erase the drive).
use super::ata::Answer;

/// One 512-byte SCT command sector.
pub const SECTOR: usize = 512;

/// SCT action code 3: Error Recovery Control.
const ACTION_ERC: u16 = 3;
/// SCT ERC selection code 1: the read command timer.
const SELECT_READ: u16 = 1;

/// The only two things asked of the drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// Function code 2: return the current read limit.
    Read,
    /// Function code 1: set the read limit, in tenths of a second; 0 turns it off (the
    /// drive takes as long as it likes).
    Set(u16),
}

/// Why a drive's read limit was not read or set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The drive is not an ATA drive (NVMe, virtual, SCSI): nothing was sent. Names its bus.
    NotAta(String),
    /// Its identify data says it has no such setting: nothing was sent.
    NoSetting,
    /// The command was sent and refused, by the drive, its adapter or the driver.
    Refused(String),
    /// The disk at that number is not the drive meant, or cannot be told apart from
    /// another: nothing was sent. Says why.
    NotTheDrive(String),
    /// The command was sent and no answer came in time: it may yet take effect.
    NoAnswer(String),
}

/// The SCT command sector: action code, function code, selection code and value, as
/// little-endian words, then zeros.
pub fn command_sector(request: Request) -> [u8; SECTOR] {
    let (function, value) = match request {
        Request::Read => (2u16, 0u16),
        Request::Set(tenths) => (1, tenths),
    };
    let mut sector = [0u8; SECTOR];
    for (at, word) in [ACTION_ERC, function, SELECT_READ, value]
        .into_iter()
        .enumerate()
    {
        sector[at * 2..at * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
    sector
}

/// The read limit from the drive's answer: for a read, the count register plus LBA low
/// times 256, in tenths of a second; for a set, nothing.
pub fn limit(request: Request, answer: &Answer) -> Result<Option<u16>, String> {
    let returned = answer
        .returned
        .ok_or_else(|| "the drive's registers did not come back".to_string())?;
    Ok(match request {
        Request::Read => Some(u16::from(returned.count) | (u16::from(returned.lba_low) << 8)),
        Request::Set(_) => None,
    })
}

/// Whether IDENTIFY DEVICE data says the drive takes SCT commands and Error Recovery
/// Control: word 206, bits 0 and 3.
pub fn supported(identify: &[u8]) -> bool {
    identify
        .get(412..414)
        .map(|w| u16::from_le_bytes([w[0], w[1]]))
        .is_some_and(|word| word != 0xFFFF && word & 0x0009 == 0x0009)
}

/// "1.5 s", or "off" for 0.
pub fn limit_text(tenths: u16) -> String {
    match tenths {
        0 => "off".into(),
        t if t % 10 == 0 => format!("{} s", t / 10),
        t => format!("{}.{} s", t / 10, t % 10),
    }
}

#[cfg(test)]
mod tests {
    use super::super::ata::Returned;
    use super::*;

    /// The guard: the sector is action code 3 (Error Recovery Control) and the read timer;
    /// a read asks for function 2 and a set for function 1 with the value. How it is sent
    /// is `ata`'s and `sat`'s guards.
    #[test]
    fn only_error_recovery_control_of_the_read_timer_is_built() {
        for (request, function, value) in [
            (Request::Read, 2u16, 0u16),
            (Request::Set(15), 1, 15),
            (Request::Set(100), 1, 100),
            (Request::Set(0), 1, 0),
        ] {
            let sector = command_sector(request);
            let word = |n: usize| u16::from_le_bytes([sector[n * 2], sector[n * 2 + 1]]);
            assert_eq!(
                (word(0), word(1), word(2), word(3)),
                (3, function, 1, value)
            );
            assert!(sector[8..].iter().all(|b| *b == 0), "{request:?}");
        }
    }

    #[test]
    fn the_limit_is_read_from_the_returned_registers() {
        let answer = |count: u8, lba_low: u8| Answer {
            data: Vec::new(),
            returned: Some(Returned {
                count,
                lba_low,
                status: 0x50,
                ..Default::default()
            }),
        };
        assert_eq!(limit(Request::Read, &answer(70, 0)), Ok(Some(70)));
        assert_eq!(limit(Request::Read, &answer(0x2C, 0x01)), Ok(Some(300)));
        assert_eq!(limit(Request::Set(15), &answer(0, 0)), Ok(None));
        let none = Answer {
            data: Vec::new(),
            returned: None,
        };
        assert!(limit(Request::Read, &none).is_err());
    }

    #[test]
    fn identify_data_says_whether_the_drive_takes_it() {
        let mut identify = vec![0u8; 512];
        assert!(!supported(&identify));
        identify[412] = 0x01;
        assert!(!supported(&identify), "SCT without error recovery control");
        identify[412] = 0x3D;
        assert!(supported(&identify));
        identify[412..414].copy_from_slice(&[0xFF, 0xFF]);
        assert!(!supported(&identify), "a word of all ones is not reported");
        assert!(!supported(&identify[..100]));
        assert_eq!(limit_text(15), "1.5 s");
        assert_eq!(limit_text(100), "10 s");
        assert_eq!(limit_text(0), "off");
    }
}
