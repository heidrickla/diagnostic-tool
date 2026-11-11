//! ICMP echo through the IP helper API, many targets at once.
use std::net::Ipv4Addr;
use std::time::Duration;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
};

const TIMEOUT_MS: u32 = 1000;
const INVALID_HANDLE: isize = -1;
const PAYLOAD: &[u8; 32] = b"abcdefghijklmnopqrstuvwabcdefghi";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reach {
    pub sent: u32,
    pub received: u32,
    pub rtts: Vec<u32>,
    /// Why echoes could not be sent or all failed, when that is known.
    pub error: Option<String>,
}

impl Reach {
    pub fn loss_percent(&self) -> Option<f64> {
        (self.sent > 0).then(|| f64::from(self.sent - self.received) * 100.0 / f64::from(self.sent))
    }

    pub fn average(&self) -> Option<f64> {
        (!self.rtts.is_empty())
            .then(|| self.rtts.iter().map(|&v| f64::from(v)).sum::<f64>() / self.rtts.len() as f64)
    }

    pub fn maximum(&self) -> Option<u32> {
        self.rtts.iter().copied().max()
    }
}

fn status_text(code: u32) -> String {
    match code {
        11003 => "destination network unreachable".into(),
        11004 => "destination host unreachable".into(),
        11010 => "timed out".into(),
        11050 => "general failure".into(),
        other => format!("status {other}"),
    }
}

/// Sends `count` echoes one after another, `gap` apart.
pub fn ping(target: Ipv4Addr, count: u32, gap: Duration) -> Reach {
    let mut reach = Reach::default();
    // SAFETY: plain call; the handle is closed below.
    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() || handle as isize == INVALID_HANDLE {
        reach.error = Some("the ICMP handle could not be opened".into());
        return reach;
    }
    let address = u32::from_ne_bytes(target.octets());
    let mut last_status = None;
    for index in 0..count {
        if index > 0 {
            std::thread::sleep(gap);
        }
        let mut buffer = [0u64; 64];
        // SAFETY: the reply buffer is 512 bytes, aligned, and larger than one reply plus data.
        let replies = unsafe {
            IcmpSendEcho(
                handle,
                address,
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                TIMEOUT_MS,
            )
        };
        reach.sent += 1;
        if replies == 0 {
            // SAFETY: reads this thread's last error.
            last_status = Some(unsafe { windows_sys::Win32::Foundation::GetLastError() });
            continue;
        }
        // SAFETY: a successful call wrote at least one ICMP_ECHO_REPLY at the buffer start.
        let reply = unsafe { std::ptr::read(buffer.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
        if reply.Status == 0 {
            reach.received += 1;
            reach.rtts.push(reply.RoundTripTime);
        } else {
            last_status = Some(reply.Status);
        }
    }
    // SAFETY: closes the handle opened above.
    unsafe { IcmpCloseHandle(handle) };
    if reach.received == 0 {
        reach.error = last_status.map(status_text);
    }
    reach
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_and_round_trips() {
        let reach = Reach {
            sent: 10,
            received: 8,
            rtts: vec![1, 1, 2, 2, 2, 3, 3, 14],
            error: None,
        };
        assert_eq!(reach.loss_percent(), Some(20.0));
        assert_eq!(reach.average(), Some(3.5));
        assert_eq!(reach.maximum(), Some(14));
        let none = Reach::default();
        assert_eq!(none.loss_percent(), None);
        assert_eq!(none.average(), None);
    }
}
