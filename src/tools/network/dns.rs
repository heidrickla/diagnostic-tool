//! DNS timing: the system resolver, and a minimal A query sent straight to a server.
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Once;
use std::time::{Duration, Instant};

use windows_sys::Win32::Networking::WinSock::{
    FreeAddrInfoW, GetAddrInfoW, WSAStartup, ADDRINFOW, WSADATA,
};

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq)]
pub struct Parsed {
    pub rcode: u8,
    pub truncated: bool,
    /// A records in the answer section.
    pub answers: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParseError {
    Short,
    WrongId,
    NotAnswer,
}

/// A recursive A query for `name` with the given id.
pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>, String> {
    let mut packet = Vec::with_capacity(32 + name.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(format!("not a usable DNS name: {name}"));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, 1, 0, 1]);
    Ok(packet)
}

/// Offset after a (possibly compressed) name starting at `at`.
fn skip_name(packet: &[u8], mut at: usize) -> Result<usize, ParseError> {
    loop {
        let length = *packet.get(at).ok_or(ParseError::Short)? as usize;
        if length == 0 {
            return Ok(at + 1);
        }
        if length & 0xc0 == 0xc0 {
            packet.get(at + 1).ok_or(ParseError::Short)?;
            return Ok(at + 2);
        }
        at += 1 + length;
    }
}

pub fn parse_answer(id: u16, packet: &[u8]) -> Result<Parsed, ParseError> {
    if packet.len() < 12 {
        return Err(ParseError::Short);
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err(ParseError::WrongId);
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err(ParseError::NotAnswer);
    }
    let truncated = flags & 0x0200 != 0;
    let rcode = (flags & 0xf) as u8;
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(packet, at)? + 4;
        if at > packet.len() {
            return Err(ParseError::Short);
        }
    }
    let mut found = 0;
    for _ in 0..answers {
        at = skip_name(packet, at)?;
        let fixed = packet.get(at..at + 10).ok_or(ParseError::Short)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let length = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        at += 10 + length;
        if at > packet.len() {
            // A cut-off record in a truncated reply is the expected shape of truncation.
            return if truncated {
                Ok(Parsed {
                    rcode,
                    truncated,
                    answers: found,
                })
            } else {
                Err(ParseError::Short)
            };
        }
        if kind == 1 && length == 4 {
            found += 1;
        }
    }
    Ok(Parsed {
        rcode,
        truncated,
        answers: found,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Answered(Parsed),
    NoAnswer,
    Failed(String),
    NotQueried(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerResult {
    pub server: IpAddr,
    pub outcome: Outcome,
    pub millis: f64,
}

impl ServerResult {
    /// The server replied and had an answer for a name that exists.
    pub fn resolved(&self) -> bool {
        matches!(&self.outcome, Outcome::Answered(p) if p.rcode == 0 && p.answers > 0)
    }
}

fn id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    (nanos ^ (nanos >> 16) ^ std::process::id()) as u16
}

pub fn query_server(server: IpAddr, name: &str) -> ServerResult {
    let done = |outcome, start: Instant| ServerResult {
        server,
        outcome,
        millis: start.elapsed().as_secs_f64() * 1000.0,
    };
    let start = Instant::now();
    if let IpAddr::V6(v6) = server {
        if v6.segments()[0] & 0xffc0 == 0xfe80 {
            return done(
                Outcome::NotQueried("link-local IPv6 needs a scope".into()),
                start,
            );
        }
    }
    let local = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let query_id = id();
    let result = (|| -> Result<Outcome, String> {
        let packet = build_query(query_id, name)?;
        let socket = UdpSocket::bind(local).map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(QUERY_TIMEOUT))
            .map_err(|e| e.to_string())?;
        socket
            .connect(SocketAddr::new(server, 53))
            .map_err(|e| e.to_string())?;
        socket.send(&packet).map_err(|e| e.to_string())?;
        let mut reply = [0u8; 1500];
        loop {
            let length = match socket.recv(&mut reply) {
                Ok(length) => length,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(Outcome::NoAnswer);
                }
                Err(e) => return Err(e.to_string()),
            };
            match parse_answer(query_id, &reply[..length]) {
                Ok(parsed) => return Ok(Outcome::Answered(parsed)),
                Err(ParseError::WrongId) => continue,
                Err(_) => return Ok(Outcome::Failed("the reply was malformed".into())),
            }
        }
    })();
    done(result.unwrap_or_else(Outcome::Failed), start)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Resolved {
    pub name: String,
    pub millis: f64,
    /// Number of addresses, or the Winsock error text.
    pub result: Result<usize, String>,
}

fn winsock() {
    static START: Once = Once::new();
    START.call_once(|| {
        // SAFETY: WSADATA is plain data the call fills in.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        unsafe { WSAStartup(0x0202, &mut data) };
    });
}

/// Resolves a name through the system resolver, giving up after `limit`.
pub fn resolve(name: &str, limit: Duration) -> Resolved {
    winsock();
    let start = Instant::now();
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = name.to_string();
    std::thread::spawn(move || {
        let wide: Vec<u16> = owned.encode_utf16().chain(std::iter::once(0)).collect();
        let mut found: *mut ADDRINFOW = std::ptr::null_mut();
        // SAFETY: a NUL-terminated name, no hints, and an out pointer for the result list.
        let code = unsafe {
            GetAddrInfoW(
                wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut found,
            )
        };
        let mut count = 0;
        if code == 0 {
            let mut node = found;
            while !node.is_null() {
                count += 1;
                // SAFETY: nodes of the list GetAddrInfoW returned.
                node = unsafe { (*node).ai_next };
            }
            // SAFETY: frees the list returned above.
            unsafe { FreeAddrInfoW(found) };
        }
        let _ = sender.send(if code == 0 { Ok(count) } else { Err(code) });
    });
    let result = match receiver.recv_timeout(limit) {
        Ok(Ok(count)) => Ok(count),
        Ok(Err(11001)) => Err("the name does not exist (error 11001)".into()),
        Ok(Err(11002)) => {
            Err("temporary failure, no answer from the DNS server (error 11002)".into())
        }
        Ok(Err(code)) => Err(format!("Winsock error {code}")),
        Err(_) => Err(format!("no answer within {} s", limit.as_secs())),
    };
    Resolved {
        name: name.into(),
        millis: start.elapsed().as_secs_f64() * 1000.0,
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply to the query for www.example.com with `rcode` and `answers` A records.
    fn reply(id: u16, flags: u16, answers: u16) -> Vec<u8> {
        let mut packet = id.to_be_bytes().to_vec();
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&[0, 1]);
        packet.extend_from_slice(&answers.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        let question = &build_query(id, "www.example.com").unwrap()[12..];
        packet.extend_from_slice(question);
        for index in 0..answers {
            packet.extend_from_slice(&[
                0xc0,
                0x0c,
                0,
                1,
                0,
                1,
                0,
                0,
                0,
                60,
                0,
                4,
                93,
                184,
                216,
                index as u8,
            ]);
        }
        packet
    }

    #[test]
    fn the_query_has_the_wire_shape() {
        let packet = build_query(0x1234, "www.example.com").unwrap();
        assert_eq!(&packet[..4], [0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&packet[4..6], [0, 1]);
        assert_eq!(packet[12], 3);
        assert_eq!(&packet[13..16], b"www");
        assert_eq!(&packet[packet.len() - 5..], [0, 0, 1, 0, 1]);
        assert!(build_query(1, "bad..name").is_err());
        assert!(build_query(1, &"a".repeat(64)).is_err());
    }

    #[test]
    fn a_normal_answer_counts_records() {
        let parsed = parse_answer(7, &reply(7, 0x8180, 2)).unwrap();
        assert_eq!(
            parsed,
            Parsed {
                rcode: 0,
                truncated: false,
                answers: 2
            }
        );
    }

    #[test]
    fn nxdomain_is_an_answer_with_code_3() {
        let parsed = parse_answer(7, &reply(7, 0x8183, 0)).unwrap();
        assert_eq!(parsed.rcode, 3);
        assert_eq!(parsed.answers, 0);
    }

    #[test]
    fn truncated_packets_are_told_apart() {
        let full = reply(7, 0x8180, 2);
        assert_eq!(
            parse_answer(7, &full[..full.len() - 6]),
            Err(ParseError::Short)
        );
        assert_eq!(parse_answer(7, &full[..8]), Err(ParseError::Short));
        let flagged = parse_answer(7, &reply(7, 0x8380, 0)).unwrap();
        assert!(flagged.truncated);
    }

    #[test]
    fn foreign_and_non_answers_are_refused() {
        assert_eq!(
            parse_answer(8, &reply(7, 0x8180, 1)),
            Err(ParseError::WrongId)
        );
        assert_eq!(
            parse_answer(7, &reply(7, 0x0100, 0)),
            Err(ParseError::NotAnswer)
        );
    }
}
