//! Adapters that are up, read with GetAdaptersAddresses, and address classification.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS;

const SKIP_ANYCAST: u32 = 0x2;
const SKIP_MULTICAST: u32 = 0x4;
const INCLUDE_GATEWAYS: u32 = 0x80;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const OPER_UP: i32 = 1;
const IF_LOOPBACK: u32 = 24;
const DHCP_ENABLED: u32 = 0x4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Ethernet,
    WiFi,
    Virtual,
    Tunnel,
    Mobile,
    Other,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Ethernet => "Ethernet",
            Kind::WiFi => "Wi-Fi",
            Kind::Virtual => "virtual or VPN",
            Kind::Tunnel => "tunnel or VPN",
            Kind::Mobile => "mobile broadband",
            Kind::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Adapter {
    pub name: String,
    pub description: String,
    pub kind: Kind,
    pub speed_mbps: Option<u64>,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub gateways: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub dhcp: bool,
    pub metric4: u32,
    pub metric6: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Class {
    Private,
    Shared,
    LinkLocal,
    Loopback,
    Public,
    Other,
}

pub fn classify4(ip: Ipv4Addr) -> Class {
    let [a, b, ..] = ip.octets();
    if ip.is_loopback() {
        Class::Loopback
    } else if ip.is_link_local() {
        Class::LinkLocal
    } else if ip.is_private() {
        Class::Private
    } else if a == 100 && (64..128).contains(&b) {
        Class::Shared
    } else if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || a >= 240 {
        Class::Other
    } else {
        Class::Public
    }
}

pub fn classify6(ip: Ipv6Addr) -> Class {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        Class::Loopback
    } else if first & 0xffc0 == 0xfe80 {
        Class::LinkLocal
    } else if first & 0xfe00 == 0xfc00 {
        Class::Private
    } else if first & 0xe000 == 0x2000 {
        Class::Public
    } else {
        Class::Other
    }
}

pub fn classify(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(ip) => classify4(ip),
        IpAddr::V6(ip) => classify6(ip),
    }
}

fn class_label(class: Class) -> &'static str {
    match class {
        Class::Private => "private",
        Class::Shared => "carrier-grade NAT range",
        Class::LinkLocal => "link-local",
        Class::Loopback => "loopback",
        Class::Public => "public",
        Class::Other => "special",
    }
}

/// An address for the report; a public one is only said to exist.
pub fn describe_own(ip: IpAddr) -> String {
    match classify(ip) {
        Class::Public => match ip {
            IpAddr::V4(_) => "a public IPv4 address is present".into(),
            IpAddr::V6(_) => "a global IPv6 address is present".into(),
        },
        class => format!("{ip} ({})", class_label(class)),
    }
}

pub fn kind_of(if_type: u32, description: &str) -> Kind {
    let text = description.to_ascii_lowercase();
    let virtual_name = [
        "virtual",
        "hyper-v",
        "vmware",
        "virtualbox",
        "vpn",
        "tap-",
        "wintun",
        "wireguard",
        "tailscale",
        "zerotier",
        "loopback",
    ]
    .iter()
    .any(|word| text.contains(word));
    match if_type {
        71 => Kind::WiFi,
        131 | 23 => Kind::Tunnel,
        243 | 244 => Kind::Mobile,
        53 => Kind::Virtual,
        6 if virtual_name => Kind::Virtual,
        6 => Kind::Ethernet,
        _ => Kind::Other,
    }
}

/// The IPv4 default gateway of the up adapter with the lowest IPv4 metric.
pub fn default_gateway(adapters: &[Adapter]) -> Option<(Ipv4Addr, Kind)> {
    adapters
        .iter()
        .filter_map(|adapter| {
            let gateway = adapter.gateways.iter().find_map(|ip| match ip {
                IpAddr::V4(v4) if !v4.is_unspecified() => Some(*v4),
                _ => None,
            })?;
            Some((adapter.metric4, gateway, adapter.kind))
        })
        .min_by_key(|(metric, ..)| *metric)
        .map(|(_, gateway, kind)| (gateway, kind))
}

/// Reads the raw bytes of a socket address: family at 0, IPv4 at 4..8, IPv6 at 8..24.
fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    let family = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    match family {
        2 if bytes.len() >= 8 => {
            let octets: [u8; 4] = bytes[4..8].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        23 if bytes.len() >= 24 => {
            let octets: [u8; 16] = bytes[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// # Safety
/// `address` must come from a live adapter list.
unsafe fn socket_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() || !(1..=128).contains(&address.iSockaddrLength) {
        return None;
    }
    // SAFETY: the caller's list owns lpSockaddr for iSockaddrLength bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            address.lpSockaddr as *const u8,
            address.iSockaddrLength as usize,
        )
    };
    ip_from_bytes(bytes)
}

/// # Safety
/// `text` must be null or a NUL-terminated wide string.
unsafe fn wide_text(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut units = Vec::new();
    for index in 0..512 {
        // SAFETY: reading up to the terminator, bounded by 512 units.
        let unit = unsafe { *text.add(index) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

pub fn read() -> Result<Vec<Adapter>, String> {
    let flags = SKIP_ANYCAST | SKIP_MULTICAST | INCLUDE_GATEWAYS;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8) + 1];
        let first = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        // SAFETY: the buffer is 8-byte aligned and at least `size` bytes.
        let status = unsafe { GetAdaptersAddresses(0, flags, std::ptr::null(), first, &mut size) };
        match status {
            0 => {
                // SAFETY: the call succeeded, so the list in `buffer` is valid.
                return Ok(unsafe { walk(first) });
            }
            ERROR_BUFFER_OVERFLOW => continue,
            other => return Err(format!("GetAdaptersAddresses returned error {other}")),
        }
    }
    Err("the adapter list kept changing size".into())
}

/// # Safety
/// `first` must head a valid adapter list that outlives the call.
unsafe fn walk(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Adapter> {
    let names = crate::events::local_names();
    let mut adapters = Vec::new();
    let mut current = first;
    while !current.is_null() {
        // SAFETY: non-null list node.
        let item = unsafe { &*current };
        current = item.Next;
        if item.OperStatus != OPER_UP || item.IfType == IF_LOOPBACK {
            continue;
        }
        // SAFETY: the strings and sub-lists belong to the same list.
        let description = unsafe { wide_text(item.Description) };
        let name = unsafe { wide_text(item.FriendlyName) };
        let mut adapter = Adapter {
            name: crate::events::redact(&name, &names),
            kind: kind_of(item.IfType, &description),
            description: crate::events::redact(&description, &names),
            speed_mbps: match item.TransmitLinkSpeed {
                0 | u64::MAX => None,
                bits => Some(bits / 1_000_000),
            },
            v4: Vec::new(),
            v6: Vec::new(),
            gateways: Vec::new(),
            dns: Vec::new(),
            // SAFETY: reading the flags view of the union.
            dhcp: unsafe { item.Anonymous2.Flags } & DHCP_ENABLED != 0,
            metric4: item.Ipv4Metric,
            metric6: item.Ipv6Metric,
        };
        let mut unicast: *const IP_ADAPTER_UNICAST_ADDRESS_LH = item.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: non-null list node.
            let node = unsafe { &*unicast };
            match unsafe { socket_ip(&node.Address) } {
                Some(IpAddr::V4(ip)) => adapter.v4.push(ip),
                Some(IpAddr::V6(ip)) => adapter.v6.push(ip),
                None => {}
            }
            unicast = node.Next;
        }
        let mut gateway: *const IP_ADAPTER_GATEWAY_ADDRESS_LH = item.FirstGatewayAddress;
        while !gateway.is_null() {
            // SAFETY: non-null list node.
            let node = unsafe { &*gateway };
            adapter.gateways.extend(unsafe { socket_ip(&node.Address) });
            gateway = node.Next;
        }
        let mut dns: *const IP_ADAPTER_DNS_SERVER_ADDRESS_XP = item.FirstDnsServerAddress;
        while !dns.is_null() {
            // SAFETY: non-null list node.
            let node = unsafe { &*dns };
            adapter.dns.extend(unsafe { socket_ip(&node.Address) });
            dns = node.Next;
        }
        adapters.push(adapter);
    }
    adapters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_classes() {
        let class = |text: &str| classify4(text.parse().unwrap());
        assert_eq!(class("192.168.1.10"), Class::Private);
        assert_eq!(class("172.20.0.1"), Class::Private);
        assert_eq!(class("172.32.0.1"), Class::Public);
        assert_eq!(class("10.0.0.1"), Class::Private);
        assert_eq!(class("169.254.3.4"), Class::LinkLocal);
        assert_eq!(class("100.64.1.1"), Class::Shared);
        assert_eq!(class("100.128.0.1"), Class::Public);
        assert_eq!(class("127.0.0.1"), Class::Loopback);
        assert_eq!(class("1.1.1.1"), Class::Public);
    }

    #[test]
    fn ipv6_classes() {
        let class = |text: &str| classify6(text.parse().unwrap());
        assert_eq!(class("fe80::1"), Class::LinkLocal);
        assert_eq!(class("fd12:3456::1"), Class::Private);
        assert_eq!(class("2607:f8b0::1"), Class::Public);
        assert_eq!(class("::1"), Class::Loopback);
        assert_eq!(class("ff02::1"), Class::Other);
    }

    #[test]
    fn public_addresses_are_not_printed() {
        let public = describe_own("93.184.216.34".parse().unwrap());
        assert!(!public.contains("93.184"), "{public}");
        assert!(public.contains("public IPv4"));
        let global = describe_own("2607:f8b0::1".parse().unwrap());
        assert!(!global.contains("2607"), "{global}");
        assert_eq!(
            describe_own("10.0.0.5".parse().unwrap()),
            "10.0.0.5 (private)"
        );
    }

    #[test]
    fn socket_bytes_parse() {
        let mut v4 = vec![2, 0, 0, 0, 192, 168, 0, 1];
        v4.extend([0; 8]);
        assert_eq!(ip_from_bytes(&v4), Some("192.168.0.1".parse().unwrap()));
        let mut v6 = vec![23, 0, 0, 0, 0, 0, 0, 0];
        v6.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend([0; 4]);
        assert_eq!(ip_from_bytes(&v6), Some("fe80::1".parse().unwrap()));
        assert_eq!(ip_from_bytes(&v4[..5]), None);
        assert_eq!(ip_from_bytes(&[]), None);
    }

    #[test]
    fn kinds_are_told_from_type_and_description() {
        assert_eq!(
            kind_of(6, "Realtek PCIe 2.5GbE Family Controller"),
            Kind::Ethernet
        );
        assert_eq!(
            kind_of(6, "Hyper-V Virtual Ethernet Adapter"),
            Kind::Virtual
        );
        assert_eq!(kind_of(71, "Intel Wi-Fi 6E AX211"), Kind::WiFi);
        assert_eq!(
            kind_of(131, "Teredo Tunneling Pseudo-Interface"),
            Kind::Tunnel
        );
    }

    #[test]
    fn the_gateway_comes_from_the_lowest_metric() {
        let adapter = |metric4: u32, gateway: &str, kind| Adapter {
            name: String::new(),
            description: String::new(),
            kind,
            speed_mbps: None,
            v4: vec![],
            v6: vec![],
            gateways: vec![gateway.parse().unwrap()],
            dns: vec![],
            dhcp: true,
            metric4,
            metric6: 0,
        };
        let list = [
            adapter(50, "10.0.1.1", Kind::WiFi),
            adapter(25, "10.0.0.1", Kind::Ethernet),
        ];
        assert_eq!(
            default_gateway(&list),
            Some(("10.0.0.1".parse().unwrap(), Kind::Ethernet))
        );
        assert_eq!(default_gateway(&[]), None);
    }
}
