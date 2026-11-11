//! Bounded execution of one fixed PowerShell script as a current-user child process.
use std::io::{self, Read};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, BELOW_NORMAL_PRIORITY_CLASS, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    THREAD_SUSPEND_RESUME,
};

pub const COMMAND_TIME: Duration = Duration::from_secs(12);
/// The hardware inventory loads the PnP module: 2.4 s on a current desktop, 5.7 to 8.3 s
/// on a 2014 Xeon VM, past 12 s there under load. Older PCs get room for it.
pub const INVENTORY_TIME: Duration = Duration::from_secs(30);
pub const OUTPUT_LIMIT: usize = 4096;

type Handle = *mut std::ffi::c_void;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(attributes: *const std::ffi::c_void, name: *const u16) -> Handle;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

struct Job(Handle);
impl Job {
    fn new() -> io::Result<Self> {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            Err(io::Error::last_os_error())
        } else {
            // Closing the last job handle also stops descendants if the GUI exits abruptly.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            let configured = unsafe {
                SetInformationJobObject(
                    raw,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const std::ffi::c_void,
                    std::mem::size_of_val(&limits) as u32,
                )
            };
            if configured == 0 {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(raw) };
                Err(error)
            } else {
                Ok(Self(raw))
            }
        }
    }
    fn assign(&self, process: Handle) -> io::Result<()> {
        if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn terminate(&self) {
        unsafe {
            TerminateJobObject(self.0, 1);
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    Spawn,
    Assign,
    Timeout,
    Cancelled,
    OutputLimit,
    Exit,
    InvalidOutput,
}

impl RunError {
    /// Plain-language reason shown in the window and the report.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Spawn | Self::Assign => "could not start",
            Self::Timeout => "timed out",
            Self::Cancelled => "stopped",
            Self::OutputLimit => "output exceeded its limit",
            Self::Exit => "ended with an error",
            Self::InvalidOutput => "returned unexpected output",
        }
    }
}

fn read_bounded<R: Read + Send + 'static>(
    mut stream: R,
    overflow: Arc<AtomicBool>,
    limit: usize,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut data = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if data.len() + n > limit {
                        overflow.store(true, Ordering::SeqCst);
                        break;
                    }
                    data.extend_from_slice(&chunk[..n]);
                }
            }
        }
        data
    })
}

/// Windows PowerShell by absolute path, so a powershell.exe beside a downloaded
/// DiagnosticTool.exe or on PATH is never started instead.
pub fn powershell_path() -> io::Result<PathBuf> {
    let mut buffer = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let system = PathBuf::from(String::from_utf16_lossy(&buffer[..len]));
    Ok(system.join(r"WindowsPowerShell\v1.0\powershell.exe"))
}

/// Resumes the main thread of a process created suspended.
fn resume_process(pid: u32) -> io::Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut resumed = 0;
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !thread.is_null() {
                if unsafe { ResumeThread(thread) } != u32::MAX {
                    resumed += 1;
                }
                unsafe { CloseHandle(thread) };
            }
        }
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    if resumed == 0 {
        Err(io::Error::other(
            "no thread of the child process could be resumed",
        ))
    } else {
        Ok(())
    }
}

pub fn run_process(
    script: &str,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
) -> Result<String, RunError> {
    run_process_limited(script, deadline, cancelled, OUTPUT_LIMIT)
}

/// As `run_process`, with a larger output limit for toolkit tools; at most 1 MiB.
pub fn run_process_limited(
    script: &str,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    limit: usize,
) -> Result<String, RunError> {
    let limit = limit.min(1 << 20);
    let job = Job::new().map_err(|_| RunError::Spawn)?;
    let mut child = Command::new(powershell_path().map_err(|_| RunError::Spawn)?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        // Suspended until it is in the job, so no descendant can start outside it;
        // below-normal priority keeps the foreground app responsive.
        .creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED | BELOW_NORMAL_PRIORITY_CLASS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| RunError::Spawn)?;
    if job.assign(child.as_raw_handle()).is_err() || resume_process(child.id()).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RunError::Assign);
    }
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = read_bounded(
        child.stdout.take().expect("stdout pipe"),
        overflow.clone(),
        limit,
    );
    let stderr = read_bounded(
        child.stderr.take().expect("stderr pipe"),
        overflow.clone(),
        limit,
    );
    let result = loop {
        if cancelled.load(Ordering::SeqCst) {
            break Err(RunError::Cancelled);
        }
        if overflow.load(Ordering::SeqCst) {
            break Err(RunError::OutputLimit);
        }
        if Instant::now() >= deadline {
            break Err(RunError::Timeout);
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) | Err(_) => break Err(RunError::Exit),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
        }
    };
    // Terminate the job on every path, including a direct child that left descendants.
    job.terminate();
    let _ = child.wait();
    let out = stdout.join().map_err(|_| RunError::Exit)?;
    let err = stderr.join().map_err(|_| RunError::Exit)?;
    result?;
    if overflow.load(Ordering::SeqCst) || out.len() + err.len() > limit {
        return Err(RunError::OutputLimit);
    }
    String::from_utf8(out).map_err(|_| RunError::InvalidOutput)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(script: &str, deadline: Instant, cancel: Arc<AtomicBool>) -> Result<String, RunError> {
        run_process(script, deadline, cancel)
    }

    #[test]
    fn timeout_ends_stalled_fixture() {
        let result = run(
            "Start-Sleep -Seconds 10; '1'",
            Instant::now() + Duration::from_millis(500),
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(result, Err(RunError::Timeout));
    }

    #[test]
    fn cancellation_ends_fixture() {
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(250));
            signal.store(true, Ordering::SeqCst);
        });
        let result = run(
            "Start-Sleep -Seconds 10; '1'",
            Instant::now() + COMMAND_TIME,
            cancel,
        );
        assert_eq!(result, Err(RunError::Cancelled));
    }

    /// Removes the planted file even when an assertion fails.
    struct Planted(std::path::PathBuf);
    impl Drop for Planted {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn a_powershell_exe_beside_the_app_is_never_started() {
        let path = powershell_path().unwrap();
        assert!(path.is_absolute(), "{path:?}");
        assert!(path.ends_with(r"WindowsPowerShell\v1.0\powershell.exe"));
        // Windows searches the application directory first for a bare program name.
        let app_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let system = path.ancestors().nth(3).unwrap().to_path_buf();
        let planted = Planted(app_dir.join("powershell.exe"));
        std::fs::copy(system.join("whoami.exe"), &planted.0).unwrap();
        let result = run(
            "'genuine'",
            Instant::now() + COMMAND_TIME,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(result.unwrap().trim(), "genuine");
    }

    #[test]
    fn child_runs_below_normal_priority() {
        let result = run(
            "(Get-Process -Id $PID).PriorityClass.ToString()",
            Instant::now() + COMMAND_TIME,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(result.unwrap().trim(), "BelowNormal");
    }

    #[test]
    fn output_flood_is_rejected() {
        let result = run(
            "'1' * 100000",
            Instant::now() + COMMAND_TIME,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(result, Err(RunError::OutputLimit));
    }
}
