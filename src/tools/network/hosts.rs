//! The hosts file: active entries and names redirected away from where they belong.
use std::io::Read;

use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

const READ_LIMIT: u64 = 1 << 20;

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub address: String,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hosts {
    pub entries: Vec<Entry>,
    pub cut_short: bool,
}

pub fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("");
            let mut words = line.split_whitespace();
            let address = words.next()?.to_string();
            let names: Vec<String> = words.map(str::to_string).collect();
            (!names.is_empty()).then_some(Entry { address, names })
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq)]
pub struct Odd {
    pub name: String,
    pub address: String,
    pub reason: &'static str,
}

fn is_loopback(address: &str) -> bool {
    address.starts_with("127.") || address == "::1"
}

fn under(name: &str, domain: &str) -> bool {
    name == domain || name.ends_with(&format!(".{domain}"))
}

/// Names that Windows, Microsoft or Google services depend on, or this PC's own name,
/// mapped somewhere unexpected.
pub fn odd(entries: &[Entry], machine: &str) -> Vec<Odd> {
    let machine = machine.to_ascii_lowercase();
    let mut found = Vec::new();
    for entry in entries {
        for name in &entry.names {
            let lower = name.to_ascii_lowercase();
            let reason = if under(&lower, "microsoft.com") {
                "a Microsoft name is redirected"
            } else if under(&lower, "windowsupdate.com") {
                "a Windows Update name is redirected"
            } else if lower.contains("google") {
                "a Google name is redirected"
            } else if !machine.is_empty() && lower == machine && !is_loopback(&entry.address) {
                "this PC's own name points elsewhere"
            } else {
                continue;
            };
            found.push(Odd {
                name: name.clone(),
                address: entry.address.clone(),
                reason,
            });
        }
    }
    found
}

/// Domains whose names are worth printing when a hosts file maps them: Microsoft and
/// Windows Update, Google, Apple, antivirus and browser vendors and the common search
/// engines. A hosts file that redirects or blocks one of these is how malware and
/// "optimizer" tools break updates, protection and browsing. Any other name is the
/// owner's own (a NAS, a game server, a work site) and is counted, never printed, so
/// the output shows hijacks without disclosing the owner's own domains.
pub const WELL_KNOWN_DOMAINS: &[&str] = &[
    "apple.com",
    "avast.com",
    "avg.com",
    "baidu.com",
    "bing.com",
    "bitdefender.com",
    "brave.com",
    "chrome.com",
    "duckduckgo.com",
    "ecosia.org",
    "eset.com",
    "firefox.com",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "icloud.com",
    "kaspersky.com",
    "live.com",
    "malwarebytes.com",
    "mcafee.com",
    "microsoft.com",
    "microsoftonline.com",
    "mozilla.org",
    "msftconnecttest.com",
    "norton.com",
    "office.com",
    "office365.com",
    "opera.com",
    "sophos.com",
    "symantec.com",
    "trendmicro.com",
    "webroot.com",
    "windows.com",
    "windowsupdate.com",
    "yahoo.com",
    "yandex.com",
    "youtube.com",
];

/// Whether `name` is a well-known domain or a name under one.
pub fn is_well_known(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let lower = lower.trim_end_matches('.');
    WELL_KNOWN_DOMAINS.iter().any(|domain| under(lower, domain))
}

/// Whether an address in the hosts file leads off this PC and its network: not loopback,
/// unspecified (the usual way to block a name), private, shared or link-local. A name
/// pointed at such an address is shown whoever owns it.
pub fn is_public_address(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            matches!(
                super::adapters::classify4(ip),
                super::adapters::Class::Public
            )
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
        Err(_) => false,
    }
}

/// A name the output prints: where it points and why it is shown.
#[derive(Clone, Debug, PartialEq)]
pub struct Listed {
    pub name: String,
    pub address: String,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Summary {
    /// Lines with a mapping, as the file has them.
    pub active: usize,
    pub listed: Vec<Listed>,
    /// Other distinct names, counted and not printed.
    pub others: usize,
}

/// Names to print (well-known domains, or names pointed at a public address) and the
/// count of the rest. `shown` turns a name into what may be printed.
pub fn summarize(entries: &[Entry], shown: &dyn Fn(&str) -> String) -> Summary {
    let mut summary = Summary {
        active: entries.len(),
        ..Summary::default()
    };
    let mut seen: Vec<String> = Vec::new();
    for entry in entries {
        for name in &entry.names {
            let lower = name.to_ascii_lowercase();
            if seen.contains(&lower) {
                continue;
            }
            seen.push(lower);
            let reason = match (is_well_known(name), is_public_address(&entry.address)) {
                (true, true) => "well-known domain, public address",
                (true, false) => "well-known domain",
                (false, true) => "public address",
                (false, false) => {
                    summary.others += 1;
                    continue;
                }
            };
            summary.listed.push(Listed {
                name: shown(name),
                address: entry.address.clone(),
                reason,
            });
        }
    }
    summary
}

pub fn path() -> Result<std::path::PathBuf, String> {
    let mut buffer = [0u16; 260];
    // SAFETY: the buffer holds 260 units.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("the system directory could not be found".into());
    }
    let mut path = std::path::PathBuf::from(String::from_utf16_lossy(&buffer[..length]));
    path.extend(["drivers", "etc", "hosts"]);
    Ok(path)
}

pub fn read() -> Result<Hosts, String> {
    let path = path()?;
    let file = std::fs::File::open(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "there is no hosts file".to_string(),
        std::io::ErrorKind::PermissionDenied => "access to the hosts file was denied".into(),
        _ => format!("it could not be opened: {e}"),
    })?;
    let mut bytes = Vec::new();
    file.take(READ_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("it could not be read: {e}"))?;
    let cut_short = bytes.len() as u64 > READ_LIMIT;
    bytes.truncate(READ_LIMIT as usize);
    Ok(Hosts {
        entries: parse(&String::from_utf8_lossy(&bytes)),
        cut_short,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# Copyright\n\n127.0.0.1 localhost\n::1 localhost\n10.0.0.9 nas nas.lan # file server\n0.0.0.0 www.microsoft.com\n  # indented comment\n127.0.0.1 update.windowsupdate.com download.windowsupdate.com\n1.2.3.4 mail.google.com\n10.0.0.4 MYPC\n127.0.0.1 notmicrosoft.com\nlonely\n";

    #[test]
    fn comments_and_blank_lines_are_not_entries() {
        let entries = parse(FILE);
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[2].names, ["nas", "nas.lan"]);
        assert!(parse("# only a comment\n\n").is_empty());
    }

    #[test]
    fn redirected_system_names_are_flagged() {
        let found = odd(&parse(FILE), "mypc");
        let names: Vec<&str> = found.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "www.microsoft.com",
                "update.windowsupdate.com",
                "download.windowsupdate.com",
                "mail.google.com",
                "MYPC"
            ]
        );
        assert!(odd(&parse("127.0.0.1 mypc\n"), "MYPC").is_empty());
        assert!(odd(&parse("1.1.1.1 example.org\n"), "mypc").is_empty());
    }

    #[test]
    fn the_well_known_list_is_lowercase_sorted_and_matches_subdomains_only() {
        for pair in WELL_KNOWN_DOMAINS.windows(2) {
            assert!(pair[0] < pair[1], "{} before {}", pair[0], pair[1]);
        }
        for domain in WELL_KNOWN_DOMAINS {
            assert_eq!(*domain, domain.to_ascii_lowercase());
            assert!(!domain.starts_with('.') && domain.contains('.'));
            assert!(is_well_known(domain), "{domain}");
        }
        assert!(is_well_known("Update.WindowsUpdate.com"));
        assert!(is_well_known("www.google.com."));
        assert!(!is_well_known("notmicrosoft.com"));
        assert!(!is_well_known("nas.lan"));
    }

    #[test]
    fn the_summary_names_hijacks_and_counts_the_owners_own_names() {
        let file = "127.0.0.1 localhost\n::1 localhost\n10.0.0.9 nas nas.lan\n0.0.0.0 www.microsoft.com ads.example.net\n93.184.216.34 shop.example.org\n192.168.1.5 www.google.com\n127.0.0.1 secret-work.example.com\n";
        let summary = summarize(&parse(file), &|name| name.to_string());
        assert_eq!(summary.active, 7);
        let listed: Vec<(&str, &str)> = summary
            .listed
            .iter()
            .map(|l| (l.name.as_str(), l.reason))
            .collect();
        assert_eq!(
            listed,
            [
                ("www.microsoft.com", "well-known domain"),
                ("shop.example.org", "public address"),
                ("www.google.com", "well-known domain"),
            ]
        );
        assert_eq!(summary.others, 5);
        assert!(is_public_address("2606:4700::1111"));
        assert!(!is_public_address("fe80::1") && !is_public_address("::"));
        assert!(!is_public_address("100.64.0.1") && !is_public_address("not an address"));
    }

    #[test]
    fn the_live_hosts_file_is_found() {
        assert!(path().unwrap().ends_with("drivers\\etc\\hosts"));
    }
}
