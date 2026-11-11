//! The findings PDF: where it is saved and what goes in it.
use std::ffi::{c_void, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::session::Session;

#[repr(C)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}
const DOCUMENTS: Guid = Guid {
    d1: 0xFDD39AD0,
    d2: 0x238F,
    d3: 0x46AF,
    d4: [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7],
};
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        id: *const Guid,
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(memory: *mut c_void);
}

/// The current user's Documents Known Folder, including a redirected or OneDrive folder.
pub fn documents_folder() -> io::Result<PathBuf> {
    let mut raw = std::ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&DOCUMENTS, 0, std::ptr::null_mut(), &mut raw) } != 0
        || raw.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Documents Known Folder unavailable",
        ));
    }
    let mut len = 0;
    unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    unsafe {
        CoTaskMemFree(raw.cast());
    }
    Ok(path)
}

/// Everything the PDF states. The session supplies every check result and time.
pub struct Report<'a> {
    pub session: &'a Session,
    pub version: &'a str,
    /// How the session reached the computer, e.g. local checks only.
    pub connection: &'a str,
    /// What happened with repairs. No repair is ever claimed to have succeeded.
    pub repair: &'a str,
    /// The processor, memory and board details for the hardware section, when read. Their
    /// serial numbers are never put in the report.
    pub details: Option<&'a crate::tools::cpu_memory::Details>,
}

pub fn save_pdf_in(folder: &Path, report: &Report<'_>) -> io::Result<PathBuf> {
    save_pdf_with_target(folder, None, report)
}

pub fn save_pdf_at(path: &Path, report: &Report<'_>) -> io::Result<PathBuf> {
    let folder = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination has no parent folder",
        )
    })?;
    save_pdf_with_target(folder, Some(path), report)
}

/// Writes a new file only; an existing report is never overwritten.
fn save_pdf_with_target(
    folder: &Path,
    desired: Option<&Path>,
    report: &Report<'_>,
) -> io::Result<PathBuf> {
    if !folder.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "destination folder unavailable",
        ));
    }
    let bytes = crate::pdf_writer::render(report)?;
    let stem = format!(
        "Diagnostic-Tool-{}",
        crate::clock::local(SystemTime::now()).file()
    );
    for n in 0..100 {
        let candidate = desired
            .map(Path::to_path_buf)
            .unwrap_or_else(|| folder.join(format!("{stem}-{}.pdf", n + 1)));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut destination) => {
                if let Err(error) = destination
                    .write_all(&bytes)
                    .and_then(|_| destination.flush())
                {
                    drop(destination);
                    let _ = fs::remove_file(&candidate);
                    return Err(error);
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && desired.is_none() => {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "report filename limit reached",
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::checks::{Finding, Outcome};
    use std::time::{Duration, Instant};

    pub(crate) fn sample_session() -> Session {
        let now = Instant::now();
        let mut session = Session::new(now, Duration::from_secs(300), false);
        let mut index = 0;
        while let Some(id) = session.start_next(now) {
            let outcome = match index {
                1 => {
                    let mut finding = Finding::new("32 GiB memory, 1 drive", "summary", false);
                    finding.data = vec![
                        ("system.model".into(), "Café PC".into()),
                        ("ram.0.capacity_gib".into(), "32".into()),
                    ];
                    Outcome::Found(finding)
                }
                3 => Outcome::Unavailable("timed out".into()),
                5 => Outcome::Found(Finding::new(
                    "2 in 24 hours, latest example.exe",
                    "example.exe faulted",
                    true,
                )),
                _ => Outcome::Found(Finding::new("fine", "detail text", false)),
            };
            session.finish(id, outcome, now);
            index += 1;
        }
        session
    }

    #[test]
    fn documents_known_folder_resolves() {
        assert!(documents_folder().unwrap().is_absolute());
    }

    #[test]
    fn saves_dated_pdfs_without_overwriting() {
        let folder = std::env::temp_dir().join(format!("diag-report-test-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let session = sample_session();
        let report = Report {
            session: &session,
            version: "1.0.0-rc.1",
            connection: "Local checks only.",
            repair: "No repair was run in this session.",
            details: None,
        };
        let first = save_pdf_in(&folder, &report).unwrap();
        let second = save_pdf_in(&folder, &report).unwrap();
        assert_ne!(first, second);
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("Diagnostic-Tool-20") && name.ends_with("-1.pdf"),
            "{name}"
        );
        assert_eq!(&fs::read(&first).unwrap()[..4], b"%PDF");
        let before = fs::read(&first).unwrap();
        assert_eq!(
            save_pdf_at(&first, &report).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&first).unwrap(), before);
        assert_eq!(
            save_pdf_in(&folder.join("missing"), &report)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let _ = fs::remove_dir_all(folder);
    }
}
