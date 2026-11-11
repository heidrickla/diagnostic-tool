//! Proxy settings: the WinHTTP default and the signed-in user's Internet Settings.
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpGetDefaultProxyConfiguration, WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_PROXY_INFO,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER};

const SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const RRF_RT_REG_SZ: u32 = 0x2;
const RRF_RT_REG_DWORD: u32 = 0x10;
const NOT_FOUND: u32 = 2;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Proxy {
    /// The WinHTTP default: a named proxy, or none; Err when it could not be read.
    pub winhttp: Option<Result<Option<String>, String>>,
    pub enabled: Option<bool>,
    pub server: Option<String>,
    pub pac: Option<String>,
    pub registry_error: Option<String>,
}

impl Proxy {
    /// Each proxy that would carry the user's traffic, for the findings.
    pub fn active(&self) -> Vec<String> {
        let mut found = Vec::new();
        if let Some(Ok(Some(server))) = &self.winhttp {
            found.push(format!("the WinHTTP default proxy is {server}"));
        }
        if self.enabled == Some(true) {
            if let Some(server) = self.server.as_deref().filter(|s| !s.is_empty()) {
                found.push(format!("the user's proxy is turned on: {server}"));
            }
        }
        if let Some(pac) = self.pac.as_deref().filter(|s| !s.is_empty()) {
            found.push(format!(
                "the user's settings use an automatic proxy script at {pac}"
            ));
        }
        found
    }
}

/// Removes any `user:password@` part from each entry of a proxy list.
pub fn clean_server(text: &str) -> String {
    text.split(';')
        .map(|entry| {
            let (scheme, rest) = match entry.split_once("://") {
                Some((scheme, rest)) => (format!("{scheme}://"), rest),
                None => match entry.split_once('=') {
                    Some((kind, rest)) if !rest.contains("//") => (format!("{kind}="), rest),
                    _ => (String::new(), entry),
                },
            };
            let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
            format!("{scheme}{host}")
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Keeps scheme, host and path of a script address; drops credentials, query and fragment.
pub fn clean_url(text: &str) -> String {
    let text = text.split(['?', '#']).next().unwrap_or("");
    match text.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            if path.is_empty() {
                format!("{scheme}://{host}")
            } else {
                format!("{scheme}://{host}/{path}")
            }
        }
        None => text.to_string(),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn registry_text(name: &str) -> Result<Option<String>, String> {
    let (key, value) = (wide(SETTINGS), wide(name));
    let mut bytes = 0u32;
    // SAFETY: a size query with no data buffer.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if status == NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(format!("registry error {status}"));
    }
    let mut buffer = vec![0u16; (bytes as usize / 2) + 1];
    let mut size = (buffer.len() * 2) as u32;
    // SAFETY: the buffer holds `size` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return Err(format!("registry error {status}"));
    }
    let end = buffer.iter().position(|&u| u == 0).unwrap_or(buffer.len());
    Ok(Some(String::from_utf16_lossy(&buffer[..end])))
}

fn registry_number(name: &str) -> Result<Option<u32>, String> {
    let (key, value) = (wide(SETTINGS), wide(name));
    let (mut data, mut size) = (0u32, 4u32);
    // SAFETY: a 4-byte buffer for a DWORD value.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    match status {
        0 => Ok(Some(data)),
        NOT_FOUND => Ok(None),
        other => Err(format!("registry error {other}")),
    }
}

fn winhttp() -> Result<Option<String>, String> {
    let mut info: WINHTTP_PROXY_INFO = Default::default();
    // SAFETY: fills a WINHTTP_PROXY_INFO whose strings are freed below.
    if unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) } == 0 {
        return Err("WinHTTP did not return its proxy configuration".into());
    }
    let text = |ptr: *mut u16| -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut units = Vec::new();
        for index in 0..2048 {
            // SAFETY: reads up to the NUL the API wrote, bounded.
            let unit = unsafe { *ptr.add(index) };
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16_lossy(&units)
    };
    let server = text(info.lpszProxy);
    let named = info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    // SAFETY: both strings were allocated by WinHTTP with GlobalAlloc.
    unsafe {
        if !info.lpszProxy.is_null() {
            windows_sys::Win32::Foundation::GlobalFree(info.lpszProxy.cast());
        }
        if !info.lpszProxyBypass.is_null() {
            windows_sys::Win32::Foundation::GlobalFree(info.lpszProxyBypass.cast());
        }
    }
    Ok((named && !server.is_empty()).then(|| clean_server(&server)))
}

pub fn read() -> Proxy {
    let mut proxy = Proxy {
        winhttp: Some(winhttp()),
        ..Proxy::default()
    };
    let mut errors = Vec::new();
    match registry_number("ProxyEnable") {
        Ok(value) => proxy.enabled = Some(value.unwrap_or(0) != 0),
        Err(e) => errors.push(format!("ProxyEnable: {e}")),
    }
    match registry_text("ProxyServer") {
        Ok(value) => proxy.server = value.map(|v| clean_server(&v)),
        Err(e) => errors.push(format!("ProxyServer: {e}")),
    }
    match registry_text("AutoConfigURL") {
        Ok(value) => proxy.pac = value.map(|v| clean_url(&v)),
        Err(e) => errors.push(format!("AutoConfigURL: {e}")),
    }
    if !errors.is_empty() {
        proxy.registry_error = Some(errors.join("; "));
    }
    proxy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_dropped_from_proxy_lists() {
        assert_eq!(clean_server("proxy.corp:8080"), "proxy.corp:8080");
        assert_eq!(
            clean_server("http=bob:pw@10.0.0.2:3128;https=10.0.0.2:3128"),
            "http=10.0.0.2:3128;https=10.0.0.2:3128"
        );
        assert_eq!(
            clean_server("http://bob:pw@p.example:80"),
            "http://p.example:80"
        );
    }

    #[test]
    fn script_addresses_lose_queries_and_credentials() {
        assert_eq!(
            clean_url("http://u:p@wpad.corp/wpad.dat?token=abc#x"),
            "http://wpad.corp/wpad.dat"
        );
        assert_eq!(clean_url("http://wpad.corp"), "http://wpad.corp");
    }

    #[test]
    fn only_a_set_proxy_is_active() {
        let mut proxy = Proxy {
            winhttp: Some(Ok(None)),
            enabled: Some(false),
            server: Some("p:1".into()),
            ..Proxy::default()
        };
        assert!(proxy.active().is_empty());
        proxy.enabled = Some(true);
        proxy.pac = Some("http://wpad/wpad.dat".into());
        proxy.winhttp = Some(Ok(Some("w:2".into())));
        assert_eq!(proxy.active().len(), 3);
    }
}
