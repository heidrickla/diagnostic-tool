//! Runs the debug build's screenshot mode and checks each window came out as a PNG of the
//! size its layout gives at the fixed screenshot DPI. Release builds have no screenshot mode.
#![cfg(all(windows, debug_assertions))]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Each picture with its pixel width and, where the window's height does not follow its
/// content, its pixel height.
const EXPECTED: [(&str, u32, Option<u32>); 12] = [
    ("start", 720, None),
    ("main", 840, None),
    ("hardware", 720, None),
    ("drive-space", 960, Some(960)),
    ("events", 1290, Some(1140)),
    ("drive", 1410, Some(1170)),
    ("cpu-graph", 1350, Some(1110)),
    ("recovery", 1380, None),
    ("rescue-copy", 1140, None),
    ("rescue-image", 1170, None),
    ("recover-files", 1470, Some(1350)),
    ("files-by-type", 1350, Some(1140)),
];

const MOST_BYTES: u64 = 300 * 1024;

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn png_size(path: &Path) -> (u32, u32) {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert!(
        bytes.len() > 24 && bytes.starts_with(b"\x89PNG\r\n\x1a\n") && &bytes[12..16] == b"IHDR",
        "{} is not a PNG",
        path.display()
    );
    let word = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    (word(16), word(20))
}

#[test]
fn the_screenshot_mode_writes_every_window_as_a_png_of_its_size() {
    let folder = Folder(std::env::temp_dir().join(format!(
        "diagnostic-tool-screenshots-{}",
        std::process::id()
    )));
    let output = Command::new(env!("CARGO_BIN_EXE_DiagnosticTool"))
        .arg("--screenshots")
        .arg(&folder.0)
        .output()
        .expect("DiagnosticTool.exe starts");
    assert!(
        output.status.success(),
        "screenshot mode ended with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let mut written: Vec<String> = std::fs::read_dir(&folder.0)
        .expect("the folder exists")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    written.sort();
    let mut names: Vec<String> = EXPECTED
        .iter()
        .map(|(name, ..)| format!("{name}.png"))
        .collect();
    names.sort();
    assert_eq!(written, names);
    for (name, width, height) in EXPECTED {
        let path = folder.0.join(format!("{name}.png"));
        let (w, h) = png_size(&path);
        assert_eq!(w, width, "{name}.png width");
        match height {
            Some(height) => assert_eq!(h, height, "{name}.png height"),
            None => assert!(h > 300, "{name}.png is only {h} pixels high"),
        }
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert!(bytes < MOST_BYTES, "{name}.png is {bytes} bytes");
    }
}
