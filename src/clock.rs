//! Wall-clock stamps for the report and its filename, in the computer's local time zone.
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// Local time minus UTC.
    pub offset_minutes: i32,
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = i64::from(month);
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn minutes(stamp: &SYSTEMTIME) -> i64 {
    days_from_civil(stamp.wYear.into(), stamp.wMonth.into(), stamp.wDay.into()) * 1440
        + i64::from(stamp.wHour) * 60
        + i64::from(stamp.wMinute)
}

/// Reads a UTC instant written as `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, as CIM reports it.
pub fn parse_utc(text: &str) -> Option<SystemTime> {
    let text = text.trim().strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.splitn(3, '-').map(str::parse::<u32>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let time = time.split('.').next()?;
    let mut time = time.splitn(3, ':').map(str::parse::<u64>);
    let (hour, minute, second) = (time.next()?.ok()?, time.next()?.ok()?, time.next()?.ok()?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = u64::try_from(days_from_civil(year as i32, month, day)).ok()?;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + std::time::Duration::from_secs(seconds))
}

/// Converts to local time with the zone offset in force at that instant.
pub fn local(time: SystemTime) -> Stamp {
    let ticks = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() / 100)
        .unwrap_or(0)
        + 116_444_736_000_000_000;
    let file = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // This PC's time zone is one of its readings: while those are forbidden, times are UTC.
    let converted = unsafe {
        FileTimeToSystemTime(&file, &mut utc) != 0
            && !crate::live::forbidden()
            && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0
    };
    if !converted {
        local = utc;
    }
    Stamp {
        year: local.wYear.into(),
        month: local.wMonth.into(),
        day: local.wDay.into(),
        hour: local.wHour.into(),
        minute: local.wMinute.into(),
        second: local.wSecond.into(),
        offset_minutes: (minutes(&local) - minutes(&utc)) as i32,
    }
}

impl Stamp {
    /// "3 November 2026 at 19:42 (UTC-06:00)"
    pub fn long(&self) -> String {
        let month = MONTHS
            .get(self.month.saturating_sub(1) as usize)
            .unwrap_or(&"");
        format!(
            "{} {month} {} at {:02}:{:02} ({})",
            self.day,
            self.year,
            self.hour,
            self.minute,
            self.zone()
        )
    }

    /// "19:42:05"
    pub fn time(&self) -> String {
        format!("{:02}:{:02}:{:02}", self.hour, self.minute, self.second)
    }

    /// "20261103-194205", sortable and safe in a filename.
    pub fn file(&self) -> String {
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    pub fn zone(&self) -> String {
        let sign = if self.offset_minutes < 0 { '-' } else { '+' };
        let offset = self.offset_minutes.unsigned_abs();
        format!("UTC{sign}{:02}:{:02}", offset / 60, offset % 60)
    }

    /// Its wall-clock seconds, on the scale of `local_seconds`.
    pub fn seconds(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

/// Wall-clock seconds of a local time written `YYYY-MM-DD HH:MM:SS`, as the rescue's logs
/// write it, for measuring between two such times; not an instant.
pub fn local_seconds(text: &str) -> Option<i64> {
    let (date, time) = text.trim().split_once(' ')?;
    let mut date = date.splitn(3, '-').map(str::parse::<u32>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.splitn(3, ':').map(str::parse::<i64>);
    let (hour, minute, second) = (time.next()?.ok()?, time.next()?.ok()?, time.next()?.ok()?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let days = days_from_civil(year as i32, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_days_match_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 11, 3), 20_760);
    }

    #[test]
    fn cim_utc_instants_parse_and_nonsense_does_not() {
        let parsed = parse_utc("2026-11-04T02:34:44.6528146Z").unwrap();
        let seconds = parsed.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(seconds, (20_761 * 86_400) + 2 * 3600 + 34 * 60 + 44);
        assert_eq!(
            parse_utc("2026-11-04T02:34:44Z"),
            Some(UNIX_EPOCH + std::time::Duration::from_secs(seconds))
        );
        for bad in [
            "",
            "2026-11-04 02:34:44",
            "2026-13-04T02:34:44Z",
            "yesterdayZ",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn formats_are_stable() {
        let stamp = Stamp {
            year: 2026,
            month: 11,
            day: 3,
            hour: 7,
            minute: 5,
            second: 9,
            offset_minutes: -360,
        };
        assert_eq!(stamp.long(), "3 November 2026 at 07:05 (UTC-06:00)");
        assert_eq!(stamp.time(), "07:05:09");
        assert_eq!(stamp.file(), "20261103-070509");
        let east = Stamp {
            offset_minutes: 330,
            ..stamp
        };
        assert_eq!(east.zone(), "UTC+05:30");
    }

    #[test]
    fn local_conversion_keeps_the_utc_instant() {
        let now = SystemTime::now();
        let stamp = local(now);
        let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let local_minutes = days_from_civil(stamp.year, stamp.month, stamp.day) * 1440
            + i64::from(stamp.hour) * 60
            + i64::from(stamp.minute);
        assert_eq!(local_minutes - i64::from(stamp.offset_minutes), secs / 60);
    }
}
