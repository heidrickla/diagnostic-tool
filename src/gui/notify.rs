//! Tells a person outside the window when a run needs one (manual step 25: an agent watched
//! the event log and pushed each drive drop to the technician's phone): a notification from
//! the notification area, which Windows shows as a toast, and the taskbar button flashing
//! until the window is brought forward.
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FlashWindowEx, GetForegroundWindow, FLASHWINFO, FLASHW_ALL, FLASHW_TIMERNOFG,
};

/// The window's one notification-area icon.
const ICON_ID: u32 = 1;

/// Tells the person `title` and `text` from `hwnd`'s notification-area icon, as a warning
/// or not, and flashes its taskbar button until it is brought forward. Nothing when the
/// window is in front: the person is looking at it.
pub fn tell(hwnd: HWND, title: &str, text: &str, warn: bool) {
    if unsafe { GetForegroundWindow() } == hwnd {
        return;
    }
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_ICON | NIF_TIP | NIF_INFO;
    data.hIcon = crate::app_icon();
    copy_into(&mut data.szTip, "Diagnostic Tool");
    copy_into(&mut data.szInfoTitle, title);
    copy_into(&mut data.szInfo, text);
    data.dwInfoFlags = if warn { NIIF_WARNING } else { NIIF_INFO };
    // SAFETY: `data` is a whole NOTIFYICONDATAW for this window's icon.
    unsafe {
        if Shell_NotifyIconW(NIM_MODIFY, &data) == 0 {
            Shell_NotifyIconW(NIM_ADD, &data);
        }
    }
    let flash = FLASHWINFO {
        cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
        hwnd,
        dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
        uCount: 0,
        dwTimeout: 0,
    };
    // SAFETY: a whole FLASHWINFO for a window of this thread.
    unsafe {
        FlashWindowEx(&flash);
    }
}

/// Takes `hwnd`'s notification-area icon away, when it has one.
pub fn forget(hwnd: HWND) {
    let data = icon_data(hwnd);
    // SAFETY: as in `tell`; deleting an icon that is not there fails harmlessly.
    unsafe {
        Shell_NotifyIconW(NIM_DELETE, &data);
    }
}

fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    // SAFETY: NOTIFYICONDATAW is plain data; all zeros is a valid empty one.
    let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = ICON_ID;
    data
}

/// `text` into a fixed wide buffer, cut to fit with its terminating zero.
fn copy_into(buf: &mut [u16], text: &str) {
    let wide: Vec<u16> = text.encode_utf16().take(buf.len() - 1).collect();
    buf[..wide.len()].copy_from_slice(&wide);
    buf[wide.len()] = 0;
}

/// Whether a run's waiting (`Progress::waiting`) is news for a person: the first time it is
/// seen since the run last read, once (`told` remembers). Waiting for the drive needs a
/// person to replug it; the heat pause carries on by itself and is not told.
pub fn waiting_news(told: &mut bool, waiting: Option<&str>) -> Option<String> {
    match waiting {
        Some(text) if !*told => {
            *told = true;
            Some(text.to_string())
        }
        Some(_) => None,
        None => {
            *told = false;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard: a person is told once each time the run starts waiting for them, not at
    /// every look while it waits.
    #[test]
    fn a_wait_is_told_once_each_time_it_starts() {
        let mut told = false;
        assert_eq!(waiting_news(&mut told, None), None);
        assert_eq!(
            waiting_news(&mut told, Some("replug it")).as_deref(),
            Some("replug it")
        );
        assert_eq!(waiting_news(&mut told, Some("replug it")), None);
        assert_eq!(waiting_news(&mut told, None), None);
        assert_eq!(
            waiting_news(&mut told, Some("again")).as_deref(),
            Some("again")
        );
    }

    #[test]
    fn text_is_cut_to_fit_with_its_zero() {
        let mut buf = [7u16; 4];
        copy_into(&mut buf, "abcdef");
        assert_eq!(buf, [97, 98, 99, 0]);
        copy_into(&mut buf, "a");
        assert_eq!(&buf[..2], &[97, 0]);
    }
}
