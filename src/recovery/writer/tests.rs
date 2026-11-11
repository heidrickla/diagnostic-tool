use super::*;
use std::path::Path;

/// Every recovery source file and recovery window, cut at its tests, by its path below src.
fn recovery_sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut folders = vec![src.join("recovery")];
    let mut found = Vec::new();
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                folders.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.file_name().is_some_and(|n| n == "tests.rs")
            {
                found.push(path);
            }
        }
    }
    for view in [
        "recovery_view",
        "rescue_image_view",
        "rescue_copy_view",
        "recover_files",
        "restore_view",
        "vdisk_view",
        "bitlocker_view",
        "keylookup_view",
        "migrate_view",
    ] {
        found.push(src.join("gui").join(format!("{view}.rs")));
    }
    let files: Vec<(String, String)> = found
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&path).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap().to_string();
            (name, code)
        })
        .collect();
    assert!(files.len() > 40, "only {} files were found", files.len());
    files
}

/// Ways to make or write a file that only the writer and the destination guard may use.
const MAKERS: &[&str] = &[
    ".create_new(",
    ".create_scratch(",
    ".open_existing(",
    ".adopt(",
    "create_unique(",
    "File::create(",
    "fs::write(",
    "fs::copy(",
    ".write(true)",
    ".append(true)",
    "NtCreateFile",
    "BufWriter::new(file)",
];

/// The guard: no recovery file or window makes or opens a file for writing except through
/// this writer, which enters it in a ledger first. The allowances: the footer `vdisk.rs`
/// puts on the technician's own image to attach it and takes off again, which is the image
/// being opened, not an output, written in one function; and the journal of changes not
/// yet put back (`pending.rs`), this program's own state in %ProgramData%, written in one
/// function.
#[test]
fn every_recovery_output_file_is_made_by_the_one_writer() {
    for (name, code) in recovery_sources() {
        if matches!(name.as_str(), "recovery/writer.rs" | "recovery/dest.rs") {
            continue;
        }
        let code = if name == "recovery/pending.rs" {
            let start = code
                .find("fn write(path: &Path, book: &Book)")
                .expect("the journal writer");
            let end = start + code[start..].find("\n}\n").expect("it ends");
            assert_eq!(
                code.matches("File::create(").count(),
                1,
                "the journal is written once"
            );
            format!("{}{}", &code[..start], &code[end + 3..])
        } else if name == "recovery/vdisk.rs" {
            let start = code.find("fn open_for_footer(").expect("the footer opener");
            let end = start + code[start..].find("\n}\n").expect("it ends");
            assert_eq!(
                code[start..end].matches(".write(true)").count(),
                1,
                "the footer is opened once"
            );
            format!("{}{}", &code[..start], &code[end + 3..])
        } else {
            code
        };
        for maker in MAKERS {
            assert!(
                !code.contains(maker),
                "{name} makes or writes a file itself ({maker}), outside the ledgered writer"
            );
        }
    }
}

/// The guard: the customer files report and the write report are written by the writer,
/// entered and ended in a ledger, not by a writer of their own.
#[test]
fn the_migrate_and_write_reports_go_through_the_writer() {
    let migrate = include_str!("../migrate/mod.rs");
    let migrate = migrate.split("#[cfg(test)]").next().unwrap();
    assert!(migrate.contains("writer::write_lone_report("));
    let target = include_str!("../target.rs");
    let target = target.split("#[cfg(test)]").next().unwrap();
    assert!(target.contains("writer::write_lone_report("));
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("diagtool-writer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A file is in the ledger the moment it is made, before a byte is written, and a whole
/// write ends it whole at its size.
#[test]
fn a_file_is_entered_when_made_and_ends_whole() {
    let dir = temp("whole");
    let guard = Guard::new([]);
    let base = guard.base(&dir).unwrap();
    let mut ledger = Ledger::default();
    let entry = Entry {
        tag: 7,
        source: "from".into(),
        note: "a note".into(),
        size: 5,
    };
    let mut made = create(&guard, &base, "a.txt", &mut ledger, entry.clone()).unwrap();
    assert_eq!(ledger.get(made.id).state, super::super::ledger::State::Open);
    write_whole(&mut made, b"hello", &mut ledger).unwrap();
    assert!(ledger.get(made.id).complete());
    let again = create(&guard, &base, "a.txt", &mut ledger, entry).unwrap();
    assert!(
        again.path.ends_with("a (2).txt"),
        "{}",
        again.path.display()
    );
    discard(again, &mut ledger, "not wanted");
    assert!(matches!(
        ledger.get(1).state,
        super::super::ledger::State::Removed(_)
    ));
    assert!(!dir.join("a (2).txt").exists());
    drop((made, base));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A log made beside an image can be read while the run holds it by a reader that shares
/// reading and writing but not delete, as most tail tools and Python's open do.
#[test]
fn a_log_beside_the_image_is_readable_while_held() {
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    let dir = temp("beside");
    let guard = Guard::new([]);
    let base = guard.base(&dir).unwrap();
    for round in ["made", "opened again"] {
        let mut held = open_beside(&guard, &base, OsStr::new("run.events.jsonl")).unwrap();
        held.write_all(b"{}\n").unwrap();
        // FILE_SHARE_READ | FILE_SHARE_WRITE, no FILE_SHARE_DELETE.
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(dir.join("run.events.jsonl"))
            .unwrap_or_else(|e| panic!("{round}: a reader is refused while it is held: {e}"));
        let mut text = String::new();
        reader.read_to_string(&mut text).unwrap();
        assert!(text.starts_with("{}"), "{round}: {text:?}");
        drop((reader, held));
    }
    drop(base);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The guard: a map save refused because another program holds the map without sharing
/// delete is tried again until it is let go, not ended at once.
#[test]
fn a_map_save_waits_for_a_reader_that_holds_the_map() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = temp("held-map");
    let guard = Guard::new([]);
    let base = guard.base(&dir).unwrap();
    let name = OsStr::new("image.map");
    save_map(&guard, &base, name, b"first\n", true).unwrap();
    // FILE_SHARE_READ | FILE_SHARE_WRITE, no FILE_SHARE_DELETE, as Python's open holds it.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(dir.join("image.map"))
        .unwrap();
    let reader = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        drop(held);
    });
    save_map(&guard, &base, name, b"second\n", true).unwrap();
    reader.join().unwrap();
    assert_eq!(std::fs::read(dir.join("image.map")).unwrap(), b"second\n");
    drop(base);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The guard: only a refused rename over the map counts as the map being held; a scratch
/// file that cannot be made is a plain failure, at once, whatever its code.
#[test]
fn only_a_refused_rename_is_a_held_map() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = temp("held-scratch");
    let guard = Guard::new([]);
    let base = guard.base(&dir).unwrap();
    let name = OsStr::new("image.map");
    save_map(&guard, &base, name, b"first\n", true).unwrap();
    std::fs::write(dir.join("image.map.new"), b"left").unwrap();
    // Shares nothing: making the scratch file over it fails with a sharing violation (32).
    let scratch = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(dir.join("image.map.new"))
        .unwrap();
    let started = std::time::Instant::now();
    let failed = save_map(&guard, &base, name, b"second\n", true).unwrap_err();
    assert!(!failed.held, "{failed:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    drop(scratch);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(dir.join("image.map"))
        .unwrap();
    let refused = save_map(&guard, &base, name, b"third\n", false).unwrap_err();
    assert!(refused.held, "{refused:?}");
    drop(held);
    assert_eq!(std::fs::read(dir.join("image.map")).unwrap(), b"first\n");
    drop(base);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A lone report says how it ended, whole or partial, so its result can carry it.
#[test]
fn a_lone_report_says_how_it_ended() {
    let dir = temp("lone");
    let guard = Guard::new([]);
    let base = guard.base(&dir).unwrap();
    let (made, ended) = write_lone_report(&guard, &base, "Report.txt", b"text\r\n");
    assert!(made.error.is_none(), "{:?}", made.error);
    assert_eq!(ended.as_deref(), Some("read in full"));
    assert_eq!(
        std::fs::read(made.path.unwrap()).unwrap(),
        b"text\r\n".to_vec()
    );
    drop(base);
    std::fs::remove_dir_all(&dir).unwrap();
}
