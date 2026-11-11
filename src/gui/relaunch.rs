//! A second launch of the recovery copy hands its command line to the copy that is
//! already running, which acts on it as if it had started with it: the one handler is
//! `accept`, called with the startup arguments and with every forwarded launch.
//!
//! The arguments travel in a WM_COPYDATA message to a hidden message-only window the
//! running copy keeps. The recovery copy is elevated and a second launch from a normal
//! shell is not, so Windows (UIPI) would drop the message; the receiving window allows
//! this one message with ChangeWindowMessageFilterEx, and no other.
use diagnostics::recovery::SourceChoice;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::recovery_view::parse_args;
use crate::ui::wide;

const CLASS: &str = "DiagnosticToolRelaunch";
/// Tags the message as a forwarded command line ("DRL1").
const TAG: usize = 0x4452_4C31;

/// The command line as UTF-8, each argument ended by a NUL, which no argument holds.
pub fn encode(args: &[String]) -> Vec<u8> {
    args.iter()
        .flat_map(|a| a.bytes().chain(std::iter::once(0)))
        .collect()
}

/// The arguments `encode` made, or none when the bytes are not that.
pub fn decode(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    bytes
        .strip_suffix(&[0])?
        .split(|b| *b == 0)
        .map(|part| String::from_utf8(part.to_vec()).ok())
        .collect()
}

/// What the command line asks for: a source to open, or nothing (a launch without
/// `--recovery` only raises). A malformed request is an error and acts on nothing.
pub fn request(args: &[String]) -> Result<Option<SourceChoice>, String> {
    Ok(parse_args(args).transpose()?.map(|launch| launch.source))
}

/// The handler for a command line, startup or forwarded.
pub fn accept(args: &[String], open: &mut dyn FnMut(SourceChoice)) -> Result<(), String> {
    if let Some(choice) = request(args)? {
        open(choice);
    }
    Ok(())
}

/// A forwarded launch's bytes through the same handler.
pub fn deliver(bytes: &[u8], open: &mut dyn FnMut(SourceChoice)) -> Result<(), String> {
    let args = decode(bytes).ok_or("The forwarded launch was not a command line")?;
    accept(&args, open)
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_COPYDATA {
        let data = unsafe { &*(l as *const COPYDATASTRUCT) };
        if data.dwData != TAG {
            return 0;
        }
        let bytes = if data.cbData == 0 || data.lpData.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data.lpData as *const u8, data.cbData as usize) }
        };
        return deliver(bytes, &mut crate::recovery_view::open_main).is_ok() as LRESULT;
    }
    unsafe { DefWindowProcW(hwnd, msg, w, l) }
}

/// Starts listening for forwarded launches: a hidden window owned by this process's
/// window thread, so its messages arrive in the message loop.
pub fn listen() -> Option<HWND> {
    let name = wide(CLASS);
    let class = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: unsafe { GetModuleHandleW(std::ptr::null()) },
        hIcon: std::ptr::null_mut(),
        hCursor: std::ptr::null_mut(),
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: name.as_ptr(),
    };
    unsafe { RegisterClassW(&class) };
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return None;
    }
    unsafe { ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, MSGFLT_ALLOW, std::ptr::null_mut()) };
    Some(hwnd)
}

/// Hands this launch's command line to the running copy, which opens what it asks for and
/// raises its window. Err says why it could not.
pub fn forward(args: &[String]) -> Result<(), String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::SMTO_ABORTIFHUNG;
    // A bad request is refused here, with the same words the first copy would use.
    request(args)?;
    let name = wide(CLASS);
    // The running copy may still be starting and not yet listening.
    let mut receiver = std::ptr::null_mut();
    for _ in 0..40 {
        receiver = unsafe {
            FindWindowExW(
                HWND_MESSAGE,
                std::ptr::null_mut(),
                name.as_ptr(),
                std::ptr::null(),
            )
        };
        if !receiver.is_null() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if receiver.is_null() {
        return Err("The running recovery window did not answer.".into());
    }
    let mut pid = 0u32;
    unsafe {
        GetWindowThreadProcessId(receiver, &mut pid);
        // This launch was just started by the user; the running copy may take the focus.
        AllowSetForegroundWindow(pid);
    }
    let bytes = encode(args);
    let data = COPYDATASTRUCT {
        dwData: TAG,
        cbData: bytes.len() as u32,
        lpData: bytes.as_ptr() as *mut _,
    };
    let mut result = 0usize;
    let sent = unsafe {
        SendMessageTimeoutW(
            receiver,
            WM_COPYDATA,
            0,
            &data as *const COPYDATASTRUCT as LPARAM,
            SMTO_ABORTIFHUNG,
            10_000,
            &mut result,
        )
    };
    if sent != 0 && result == 1 {
        Ok(())
    } else {
        Err("The running recovery window did not take the request.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn line(items: &[&str]) -> Vec<String> {
        items.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn a_command_line_survives_the_message_with_spaces_and_other_scripts() {
        let args = line(&[
            r"C:\Program Files\Diagnostic Tool\DiagnosticTool.exe",
            "--recovery",
            "--image",
            r"D:\Rescue Päckchen\日本語 ディスク.img",
            "",
        ]);
        assert_eq!(decode(&encode(&args)), Some(args));
        assert_eq!(decode(&encode(&[])), Some(vec![]));
        assert_eq!(decode(&encode(&line(&[""]))), Some(line(&[""])));
        assert_eq!(decode(b"no end"), None);
        assert_eq!(decode(&[0xFF, 0xFE, 0]), None);
    }

    #[test]
    fn an_unknown_or_incomplete_request_is_refused_and_opens_nothing() {
        for bad in [
            line(&["x", "--recovery"]),
            line(&["x", "--recovery", "--disk", "four"]),
            line(&["x", "--recovery", "--format", "3"]),
            line(&["x", "--recovery", "--image"]),
            line(&["x", "--recovery", "--image", "--disk"]),
            line(&["x", "--recovery", "--image", ""]),
        ] {
            let mut opened = Vec::new();
            assert!(accept(&bad, &mut |c| opened.push(c)).is_err(), "{bad:?}");
            assert!(opened.is_empty(), "{bad:?}");
            assert!(deliver(&encode(&bad), &mut |c| opened.push(c)).is_err());
            assert!(opened.is_empty(), "{bad:?}");
        }
        let mut opened = Vec::new();
        assert!(deliver(&[0xFF, 0], &mut |c| opened.push(c)).is_err());
        assert!(opened.is_empty());
    }

    /// The guard: a launch handed to the running copy has every token checked, as at
    /// startup, so a source with another one trailing it opens no window.
    #[test]
    fn a_forwarded_launch_with_a_conflicting_token_opens_nothing() {
        let conflicting = line(&["x", "--recovery", "--disk", "3", "--image", "other.img"]);
        let mut opened = Vec::new();
        assert!(accept(&conflicting, &mut |c| opened.push(c)).is_err());
        assert!(deliver(&encode(&conflicting), &mut |c| opened.push(c)).is_err());
        assert!(request(&conflicting).is_err());
        assert!(opened.is_empty());
        // What an elevated start is given, record and all, is one the grammar takes.
        let record = std::path::Path::new(r"C:\Temp\DiagnosticTool-changes-12.txt");
        let elevated = crate::recovery_view::elevated_args(3, Some(record));
        let mut sent = vec!["x".to_string()];
        sent.extend(elevated.split(' ').map(|t| t.trim_matches('"').to_string()));
        deliver(&encode(&sent), &mut |c| opened.push(c)).unwrap();
        assert_eq!(opened, vec![SourceChoice::Disk(3)]);
    }

    #[test]
    fn a_launch_without_recovery_asks_for_nothing() {
        let mut opened = Vec::new();
        assert_eq!(accept(&line(&["x"]), &mut |c| opened.push(c)), Ok(()));
        assert!(opened.is_empty());
    }

    /// A forwarded launch reaches the handler a startup one does, and opens the same.
    #[test]
    fn a_forwarded_image_launch_opens_what_the_startup_one_does() {
        let image = PathBuf::from(r"D:\Rescue Päckchen\a b.img");
        let args = line(&[
            "DiagnosticTool.exe",
            "--recovery",
            "--image",
            &image.to_string_lossy(),
        ]);
        let mut at_startup = Vec::new();
        accept(&args, &mut |c| at_startup.push(c)).unwrap();
        let mut forwarded = Vec::new();
        deliver(&encode(&args), &mut |c| forwarded.push(c)).unwrap();
        assert_eq!(at_startup, vec![SourceChoice::Image(image)]);
        assert_eq!(forwarded, at_startup);

        let mut disk = Vec::new();
        deliver(
            &encode(&line(&["x", "--recovery", "--disk", "3"])),
            &mut |c| disk.push(c),
        )
        .unwrap();
        assert_eq!(disk, vec![SourceChoice::Disk(3)]);
    }
}
