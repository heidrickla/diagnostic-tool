//! The system side of the updates tool: the pending-restart registry signs, the two
//! services, the fixed PowerShell script for the update agent's history, and the client
//! events. Everything here reads.
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus,
    QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_STATUS,
};

use super::{
    parse_script, ClientEvents, Gathered, RebootSign, ScriptReading, Service, Sign, EVENT_IDS,
    EVENT_LOG, HISTORY_FETCH,
};
use crate::events::{self, Query};
use crate::runner::run_process_limited;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;

/// Fixed script, no double quotes and no input. It prints the update agent's last search and
/// install times and the newest history entries as tab-separated lines (times in UTC).
fn script() -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
$tab = [string][char]9; \
function Fmt($d) {{ if ($d -is [datetime] -and $d.Year -gt 1990) {{ $d.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }} else {{ 'none' }} }}; \
try {{ \
$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); \
$total = [int]$searcher.GetTotalHistoryCount(); \
'COUNT' + $tab + $total; \
try {{ $r = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results; \
'R' + $tab + 'search' + $tab + (Fmt $r.LastSearchSuccessDate); \
'R' + $tab + 'install' + $tab + (Fmt $r.LastInstallationSuccessDate) }} \
catch {{ 'RERR' + $tab + 'search' + $tab + 'the update agent is not available'; \
'RERR' + $tab + 'install' + $tab + 'the update agent is not available' }}; \
$take = [Math]::Min($total, {HISTORY_FETCH}); \
if ($take -gt 0) {{ foreach ($e in $searcher.QueryHistory(0, $take)) {{ \
$title = ([string]$e.Title) -replace '[\\t\\r\\n]+', ' '; \
('H', (Fmt $e.Date), [int]$e.Operation, [int]$e.ResultCode, ('{{0:X8}}' -f $e.HResult), $title) -join $tab }} }} \
}} catch {{ 'ERROR' + $tab + (($_.Exception.Message) -replace '[\\t\\r\\n]+', ' ') }}"
    )
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key came from RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn open(path: &str) -> Result<Key, u32> {
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `path` is nul-terminated and `key` is a valid out pointer.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(path).as_ptr(),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if status == 0 {
        Ok(Key(key))
    } else {
        Err(status)
    }
}

fn sign_from_error(status: u32) -> Sign {
    match status {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Sign::NotSet,
        ERROR_ACCESS_DENIED => Sign::Unreadable("needs administrator rights".into()),
        other => Sign::Unreadable(format!("the registry returned error {other}")),
    }
}

fn key_exists(path: &str) -> Sign {
    match open(path) {
        Ok(_) => Sign::Set,
        Err(status) => sign_from_error(status),
    }
}

fn value_exists(path: &str, name: &str) -> Sign {
    let key = match open(path) {
        Ok(key) => key,
        Err(status) => return sign_from_error(status),
    };
    let mut size = 0u32;
    // SAFETY: `name` is nul-terminated; only the size is asked for.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide(name).as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    match status {
        0 if size > 2 => Sign::Set,
        0 => Sign::NotSet,
        other => sign_from_error(other),
    }
}

const WU: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate";
const CBS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing";

fn reboot_signs() -> Vec<RebootSign> {
    vec![
        RebootSign {
            label: "Windows Update RebootRequired",
            sign: key_exists(&format!(r"{WU}\Auto Update\RebootRequired")),
        },
        RebootSign {
            label: "Component servicing RebootPending",
            sign: key_exists(&format!(r"{CBS}\RebootPending")),
        },
        RebootSign {
            label: "Component servicing PackagesPending",
            sign: key_exists(&format!(r"{CBS}\PackagesPending")),
        },
        RebootSign {
            label: "Pending file renames (installers set this too)",
            sign: value_exists(
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                "PendingFileRenameOperations",
            ),
        },
    ]
}

fn state_word(state: u32) -> String {
    match state {
        1 => "stopped",
        2 => "starting",
        3 => "stopping",
        4 => "running",
        5 => "continuing",
        6 => "pausing",
        7 => "paused",
        _ => "in an unknown state",
    }
    .into()
}

fn start_word(start: u32) -> String {
    match start {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
    .into()
}

fn read_service(name: &str) -> Result<(String, String), String> {
    // SAFETY: null machine and database name select the local active database.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("the service manager would not open".into());
    }
    // SAFETY: `manager` is open and the name is nul-terminated.
    let service = unsafe {
        OpenServiceW(
            manager,
            wide(name).as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    let result = if service.is_null() {
        Err("the service is not installed or may not be read".to_string())
    } else {
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: `service` is open and `status` is writable.
        let have_status = unsafe { QueryServiceStatus(service, &mut status) } != 0;
        // Eight-byte aligned storage for the variable-length config structure.
        let mut buffer = vec![0u64; 1024];
        let mut needed = 0u32;
        // SAFETY: the buffer is writable for the byte length given and aligned for the struct.
        let have_config = unsafe {
            QueryServiceConfigW(
                service,
                buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),
                (buffer.len() * 8) as u32,
                &mut needed,
            )
        } != 0;
        if have_status && have_config {
            // SAFETY: the call succeeded, so the buffer starts with a filled config structure.
            let start = unsafe { (*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>()).dwStartType };
            Ok((state_word(status.dwCurrentState), start_word(start)))
        } else {
            Err("the service's state could not be read".into())
        }
    };
    // SAFETY: both handles are open and closed once.
    unsafe {
        if !service.is_null() {
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
    }
    result
}

fn services() -> Vec<Service> {
    vec![
        Service {
            display: "Windows Update",
            name: "wuauserv",
            reading: read_service("wuauserv"),
        },
        Service {
            display: "Background Intelligent Transfer Service",
            name: "BITS",
            reading: read_service("BITS"),
        },
    ]
}

fn read_script(deadline: Instant) -> Result<ScriptReading, String> {
    let output = run_process_limited(
        &script(),
        deadline,
        Arc::new(AtomicBool::new(false)),
        512 * 1024,
    )
    .map_err(|error| format!("the update history query {}", error.reason()))?;
    parse_script(&output)
}

fn client_events(days: u64, deadline: Instant) -> Result<ClientEvents, String> {
    let query = Query {
        logs: vec![EVENT_LOG.into()],
        levels: Vec::new(),
        providers: Vec::new(),
        ids: EVENT_IDS.to_vec(),
        since: Duration::from_secs(days * 86_400),
        include_noise: true,
        per_log_limit: 60,
        messages: true,
    };
    let (found, reads) = events::read_events(&query, deadline, &AtomicBool::new(false)).map_err(
        |error| match error {
            events::ReadError::Cancelled => "canceled".to_string(),
            events::ReadError::Invalid(reason) | events::ReadError::Unavailable(reason) => reason,
        },
    )?;
    if let Some(reason) = reads.iter().find_map(|read| read.unavailable.clone()) {
        return Err(reason);
    }
    Ok(ClientEvents {
        events: found,
        cut_short: reads.iter().any(|read| read.limit.is_some()),
    })
}

pub fn gather(days: u64, deadline: Instant) -> Gathered {
    let now = SystemTime::now();
    let script_deadline = deadline.min(Instant::now() + Duration::from_secs(20));
    let (script, reboot, services, events) = std::thread::scope(|scope| {
        let history = scope.spawn(move || read_script(script_deadline));
        let reboot = reboot_signs();
        let services = services();
        let events = client_events(days, deadline.min(Instant::now() + Duration::from_secs(12)));
        let script = history
            .join()
            .unwrap_or_else(|_| Err("the history reader stopped unexpectedly".into()));
        (script, reboot, services, events)
    });
    Gathered {
        days,
        now,
        script,
        reboot,
        services,
        events,
    }
}
