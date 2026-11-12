//! The session's change record: each change a tool makes to the PC, kept in a file so the
//! elevated copy of the program can add to the record of the window that started it, and
//! the findings report lists every change.
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

use crate::clock;

static FILE: OnceLock<PathBuf> = OnceLock::new();

const PREFIX: &str = "DiagnosticTool-changes-";

/// The record file for this process: in the temporary folder, named by process id.
pub fn for_this_process() -> PathBuf {
    std::env::temp_dir().join(format!("{PREFIX}{}.txt", std::process::id()))
}

/// Whether `path` is a record file this program names: absolute, `DiagnosticTool-changes-`,
/// digits, `.txt`.
pub fn is_record_name(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let digits = name
        .strip_prefix(PREFIX)
        .and_then(|rest| rest.strip_suffix(".txt"));
    path.is_absolute()
        && digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Sets the file this process records changes in; the first call wins.
pub fn use_file(path: PathBuf) -> bool {
    FILE.set(path).is_ok()
}

/// Starts this window's record: an empty file named by process id. Entries are only ever
/// added to a file that exists, so a record the window removed on closing is not made again.
pub fn start_for_this_process() -> Result<(), String> {
    crate::live::reading("the change record");
    let path = for_this_process();
    std::fs::write(&path, b"")
        .map_err(|e| format!("{} could not be made ({e})", path.display()))?;
    use_file(path);
    Ok(())
}

/// Removes this window's record when it closes.
pub fn finish() {
    if let Some(path) = file() {
        let _ = std::fs::remove_file(path);
    }
}

/// The record's size, which grows with each entry.
pub fn size() -> u64 {
    file()
        .and_then(|path| std::fs::metadata(path).ok())
        .map_or(0, |meta| meta.len())
}

pub fn file() -> Option<&'static Path> {
    FILE.get().map(PathBuf::as_path)
}

/// Adds one dated entry with its lines.
pub fn append(what: &str, lines: &[String]) -> Result<(), String> {
    let path = file().ok_or("no change record is open in this window")?;
    append_to(path, SystemTime::now(), what, lines)
}

pub fn append_to(path: &Path, at: SystemTime, what: &str, lines: &[String]) -> Result<(), String> {
    let mut text = format!("{} {what}:\n", clock::local(at).long());
    for line in lines {
        text.push_str(&format!("  {line}\n"));
    }
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(|e| format!("{} could not be written ({e})", path.display()))
}

/// The record as the report prints it, or `None` when nothing was changed.
pub fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_end().to_string())
        .filter(|text| !text.is_empty())
}

/// The report's "Changes made" text from the record at `path`.
pub fn report_text(path: Option<&Path>) -> String {
    match path.and_then(read) {
        Some(record) => format!("These changes were made in this session:\n{record}"),
        None => "No repair was run in this session.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_names_are_checked() {
        assert!(is_record_name(Path::new(
            r"C:\Temp\DiagnosticTool-changes-42.txt"
        )));
        assert!(!is_record_name(Path::new(r"DiagnosticTool-changes-42.txt")));
        assert!(!is_record_name(Path::new(
            r"C:\Windows\System32\config\SAM"
        )));
        assert!(!is_record_name(Path::new(
            r"C:\Temp\DiagnosticTool-changes-.txt"
        )));
        assert!(!is_record_name(Path::new(
            r"C:\Temp\DiagnosticTool-changes-4x.txt"
        )));
    }

    #[test]
    fn entries_append_and_the_report_lists_them() {
        let path = std::env::temp_dir().join(format!("{PREFIX}9{}.txt", std::process::id()));
        assert!(
            append_to(&path, SystemTime::now(), "x", &[]).is_err(),
            "no file, no entry"
        );
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            report_text(Some(&path)),
            "No repair was run in this session."
        );
        append_to(
            &path,
            SystemTime::now(),
            "Crash dumps set up",
            &["A: 1 to 2".into()],
        )
        .unwrap();
        append_to(
            &path,
            SystemTime::now(),
            "Crash dump settings put back",
            &["A: 2 to 1".into()],
        )
        .unwrap();
        let text = report_text(Some(&path));
        std::fs::remove_file(&path).unwrap();
        assert!(
            text.starts_with("These changes were made in this session:\n"),
            "{text}"
        );
        assert!(
            text.contains("Crash dumps set up:\n  A: 1 to 2\n"),
            "{text}"
        );
        assert!(text.ends_with("put back:\n  A: 2 to 1"), "{text}");
    }
}
