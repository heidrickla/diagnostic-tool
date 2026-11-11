//! Wi-Fi link quality from the WLAN API. Network names and BSSIDs are never kept.
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WiFi::{
    dot11_phy_type_dmg, dot11_phy_type_dsss, dot11_phy_type_eht, dot11_phy_type_erp,
    dot11_phy_type_fhss, dot11_phy_type_he, dot11_phy_type_hrdsss, dot11_phy_type_ht,
    dot11_phy_type_irbaseband, dot11_phy_type_ofdm, dot11_phy_type_vht,
    wlan_interface_state_connected, wlan_intf_opcode_current_connection, wlan_intf_opcode_rssi,
    WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanGetNetworkBssList, WlanOpenHandle,
    WlanQueryInterface, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
};

const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const DOT11_BSS_TYPE_ANY: i32 = 3;

#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    pub quality: u32,
    pub rssi: Option<i32>,
    pub phy: String,
    pub rx_mbps: u32,
    pub tx_mbps: u32,
    pub band: Option<&'static str>,
    pub channel: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Wifi {
    /// Number of Wi-Fi interfaces the WLAN service lists.
    pub interfaces: usize,
    pub links: Vec<Link>,
    /// Why nothing was read, when it could not be.
    pub unavailable: Option<String>,
}

pub fn phy_name(phy: i32) -> String {
    match phy {
        p if p == dot11_phy_type_fhss => "802.11 FHSS",
        p if p == dot11_phy_type_dsss => "802.11b (DSSS)",
        p if p == dot11_phy_type_irbaseband => "802.11 infrared",
        p if p == dot11_phy_type_ofdm => "802.11a (OFDM)",
        p if p == dot11_phy_type_hrdsss => "802.11b (HR-DSSS)",
        p if p == dot11_phy_type_erp => "802.11g (ERP)",
        p if p == dot11_phy_type_ht => "802.11n (Wi-Fi 4)",
        p if p == dot11_phy_type_vht => "802.11ac (Wi-Fi 5)",
        p if p == dot11_phy_type_dmg => "802.11ad (60 GHz)",
        p if p == dot11_phy_type_he => "802.11ax (Wi-Fi 6)",
        p if p == dot11_phy_type_eht => "802.11be (Wi-Fi 7)",
        other => return format!("PHY type {other}"),
    }
    .to_string()
}

/// Band and channel number from a centre frequency in kHz.
pub fn band_and_channel(khz: u32) -> Option<(&'static str, u32)> {
    let mhz = khz / 1000;
    match mhz {
        2412..=2472 => Some(("2.4 GHz", (mhz - 2407) / 5)),
        2484 => Some(("2.4 GHz", 14)),
        5150..=5895 => Some(("5 GHz", (mhz - 5000) / 5)),
        5955..=7115 => Some(("6 GHz", (mhz - 5950) / 5)),
        _ => None,
    }
}

struct Client(HANDLE);

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: closes the handle WlanOpenHandle returned.
        unsafe { WlanCloseHandle(self.0, std::ptr::null()) };
    }
}

pub fn read() -> Wifi {
    let mut wifi = Wifi::default();
    let mut version = 0u32;
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: out parameters for the negotiated version and the client handle.
    let status = unsafe { WlanOpenHandle(2, std::ptr::null(), &mut version, &mut handle) };
    if status == ERROR_SERVICE_NOT_ACTIVE {
        wifi.unavailable = Some("the WLAN service is not running (no Wi-Fi hardware)".into());
        return wifi;
    }
    if status != 0 {
        wifi.unavailable = Some(format!("WlanOpenHandle returned error {status}"));
        return wifi;
    }
    let client = Client(handle);
    let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    // SAFETY: the list is freed with WlanFreeMemory below.
    let status = unsafe { WlanEnumInterfaces(client.0, std::ptr::null(), &mut list) };
    if status != 0 || list.is_null() {
        wifi.unavailable = Some(format!("WlanEnumInterfaces returned error {status}"));
        return wifi;
    }
    // SAFETY: dwNumberOfItems entries follow the header in one allocation.
    let infos = unsafe {
        std::slice::from_raw_parts(
            (*list).InterfaceInfo.as_ptr(),
            (*list).dwNumberOfItems as usize,
        )
    };
    wifi.interfaces = infos.len();
    for info in infos {
        if info.isState == wlan_interface_state_connected {
            if let Some(link) = link(&client, &info.InterfaceGuid) {
                wifi.links.push(link);
            }
        }
    }
    // SAFETY: frees the list allocated above.
    unsafe { WlanFreeMemory(list.cast()) };
    wifi
}

fn link(client: &Client, guid: &windows_sys::core::GUID) -> Option<Link> {
    let mut size = 0u32;
    let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: the returned block is freed below.
    let status = unsafe {
        WlanQueryInterface(
            client.0,
            guid,
            wlan_intf_opcode_current_connection,
            std::ptr::null(),
            &mut size,
            &mut data,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || data.is_null() {
        return None;
    }
    // SAFETY: a successful current_connection query returns a WLAN_CONNECTION_ATTRIBUTES.
    let attributes: WLAN_CONNECTION_ATTRIBUTES = unsafe { std::ptr::read_unaligned(data.cast()) };
    // SAFETY: frees the block above.
    unsafe { WlanFreeMemory(data) };
    let association = attributes.wlanAssociationAttributes;
    let mut link = Link {
        quality: association.wlanSignalQuality,
        rssi: rssi(client, guid),
        phy: phy_name(association.dot11PhyType),
        rx_mbps: association.ulRxRate / 1000,
        tx_mbps: association.ulTxRate / 1000,
        band: None,
        channel: None,
    };
    let mut bss: *mut WLAN_BSS_LIST = std::ptr::null_mut();
    // SAFETY: the list is freed below; the SSID is only used as a filter.
    let status = unsafe {
        WlanGetNetworkBssList(
            client.0,
            guid,
            &association.dot11Ssid,
            DOT11_BSS_TYPE_ANY,
            1,
            std::ptr::null(),
            &mut bss,
        )
    };
    if status == 0 && !bss.is_null() {
        // SAFETY: dwNumberOfItems entries follow the header in one allocation.
        let entries = unsafe {
            std::slice::from_raw_parts(
                (*bss).wlanBssEntries.as_ptr(),
                (*bss).dwNumberOfItems as usize,
            )
        };
        if let Some(entry) = entries
            .iter()
            .find(|e| e.dot11Bssid == association.dot11Bssid)
        {
            if let Some((band, channel)) = band_and_channel(entry.ulChCenterFrequency) {
                link.band = Some(band);
                link.channel = Some(channel);
            }
        }
        // SAFETY: frees the list allocated above.
        unsafe { WlanFreeMemory(bss.cast()) };
    }
    Some(link)
}

fn rssi(client: &Client, guid: &windows_sys::core::GUID) -> Option<i32> {
    let mut size = 0u32;
    let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: the returned block is freed below.
    let status = unsafe {
        WlanQueryInterface(
            client.0,
            guid,
            wlan_intf_opcode_rssi,
            std::ptr::null(),
            &mut size,
            &mut data,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || data.is_null() || size < 4 {
        return None;
    }
    // SAFETY: the rssi opcode returns a 4-byte LONG.
    let value = unsafe { std::ptr::read_unaligned(data.cast::<i32>()) };
    // SAFETY: frees the block above.
    unsafe { WlanFreeMemory(data) };
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequencies_become_bands_and_channels() {
        assert_eq!(band_and_channel(2_437_000), Some(("2.4 GHz", 6)));
        assert_eq!(band_and_channel(2_484_000), Some(("2.4 GHz", 14)));
        assert_eq!(band_and_channel(5_180_000), Some(("5 GHz", 36)));
        assert_eq!(band_and_channel(5_955_000), Some(("6 GHz", 1)));
        assert_eq!(band_and_channel(0), None);
    }

    #[test]
    fn phy_types_have_names() {
        assert_eq!(phy_name(dot11_phy_type_he), "802.11ax (Wi-Fi 6)");
        assert_eq!(phy_name(99), "PHY type 99");
    }
}
