//! Copy the customer's files: the NTFS tree read through the app's own file table reader
//! and copied by the rescue copy, against the NTFS fixture image, and (ignored, run by
//! hand) against a test Windows drive built by `tests/fixtures/migrate/make_drive.ps1`.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use diagnostics::budget::Budget;
use diagnostics::recovery::copy::{self, Job, Settings};
use diagnostics::recovery::dest::Guard;
use diagnostics::recovery::fs::ntfs;
use diagnostics::recovery::fs::{Data, Place, Progress, Vol};
use diagnostics::recovery::migrate::tree::{NtfsTree, Shared, SharedSource};
use diagnostics::recovery::migrate::{self, Ended, Event, Options, Phase};
use diagnostics::recovery::reader::Reader;
use diagnostics::recovery::{BlockSource, ImageFile, MemDisk, SourceChoice};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/recovery")
        .join(name)
}

fn sha(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The live files of the NTFS fixture: path to SHA-256.
fn live_files() -> HashMap<String, String> {
    std::fs::read_to_string(fixture("manifest.txt"))
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("ntfs.img|") && l.ends_with("|live"))
        .map(|l| {
            let f: Vec<&str> = l.split('|').collect();
            (f[2].to_string(), f[4].to_string())
        })
        .collect()
}

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Temp {
        let path = std::env::temp_dir().join(format!(
            "diagtool-migrate-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Temp(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tree_of(source: Box<dyn BlockSource>) -> (NtfsTree, Vec<ntfs::Live>) {
    let shared: SharedSource = Arc::new(Mutex::new(source));
    let mut reader = Reader::new(Box::new(Shared(shared.clone())));
    let len = reader.len();
    let mut vol = Vol::new(&mut reader, 0, len);
    let mut budget = Budget::new(ntfs::LIMITS, None);
    let (records, _) = ntfs::live(&mut vol, &mut budget, &Progress::default()).unwrap();
    (NtfsTree::new(shared, records.clone()), records)
}

fn jobs() -> Vec<Job> {
    vec![
        Job::folder(PathBuf::from(r"\Documents"), vec!["Documents".into()]),
        Job {
            source: PathBuf::from(r"\Pictures"),
            into: vec!["Pictures".into()],
            file: None,
            leave_out: &["holiday"],
        },
        Job {
            source: PathBuf::from(r"\readme.txt"),
            into: vec!["Single".into(), "Deeper".into(), "readme.txt".into()],
            file: Some(54),
            leave_out: &[],
        },
    ]
}

fn run(tree: &mut NtfsTree, into: &Path) -> copy::Report {
    let guard = Guard::new([9999]);
    let folder = guard.base(into).unwrap();
    copy::run_jobs(
        tree,
        &jobs(),
        &folder,
        &guard,
        &Settings {
            chunk: 4096,
            log_name: migrate::LOG,
            ..Settings::default()
        },
        &AtomicBool::new(false),
        &copy::Progress::default(),
    )
}

/// The volume's files in use are copied byte for byte through its own file table, into the
/// places the jobs name; deleted files are not; a folder named to be left out is left out
/// and the log says so.
#[test]
fn an_ntfs_volume_is_copied_through_its_own_file_table() {
    let temp = Temp::new("fixture");
    let (mut tree, _) = tree_of(Box::new(ImageFile::open(&fixture("ntfs.img")).unwrap()));
    let report = run(&mut tree, &temp.0);
    assert_eq!(report.outcome, copy::Outcome::Finished);
    let live = live_files();
    let mut checked = 0;
    for (path, want) in [
        ("/Documents/report.docx", "Documents/report.docx"),
        ("/Documents/notes.txt", "Documents/notes.txt"),
        ("/Documents/fragmented.bin", "Documents/fragmented.bin"),
        ("/Pictures/photo.jpg", "Pictures/photo.jpg"),
        ("/readme.txt", "Single/Deeper/readme.txt"),
    ] {
        let bytes = std::fs::read(temp.0.join(want)).unwrap();
        assert_eq!(sha(&bytes), live[path], "{path}");
        checked += 1;
    }
    assert_eq!(checked, 5);
    let log = std::fs::read_to_string(temp.0.join(migrate::LOG)).unwrap();
    // Documents also holds the fixture's two spacer files.
    assert_eq!(report.copied(), 7, "{log}");
    assert!(
        !temp.0.join("Documents/Old").exists(),
        "a deleted folder was copied"
    );
    assert!(
        !temp.0.join("Pictures/old.gif").exists(),
        "a deleted file was copied"
    );
    assert!(
        !temp.0.join("Pictures/Holiday").exists(),
        "a left-out folder was copied"
    );
    let log = std::fs::read_to_string(temp.0.join(migrate::LOG)).unwrap();
    assert!(log.contains("Left out: \\Pictures\\Holiday"), "{log}");
    assert!(log.ends_with(copy::LOG_END), "{log}");
}

/// The guard: a sector that cannot be read inside a file is skipped, read once more on its
/// own in the second pass, and the file is copied with zeros there and listed as damaged.
#[test]
fn an_unreadable_sector_in_a_file_follows_the_copy_rules() {
    let image = std::fs::read(fixture("ntfs.img")).unwrap();
    let (_, records) = tree_of(Box::new(MemDisk::new(image.clone())));
    let notes = records
        .iter()
        .find(|r| r.name == "notes.txt")
        .expect("notes.txt in the fixture");
    let Data::Runs(runs) = &notes.data else {
        panic!("notes.txt is resident");
    };
    let Place::At(at) = runs[0].place else {
        panic!("notes.txt does not start on the volume");
    };
    let bad = at + 1024..at + 1536;
    let mut disk = MemDisk::new(image.clone());
    disk.bad.push(bad.clone());
    let disk = Arc::new(Mutex::new(disk));
    struct Watched(Arc<Mutex<MemDisk>>);
    impl BlockSource for Watched {
        fn len(&self) -> u64 {
            self.0.lock().unwrap().len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(
            &mut self,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<(), diagnostics::recovery::ReadError> {
            self.0.lock().unwrap().read_at(offset, buf)
        }
        fn describe(&self) -> String {
            "watched".into()
        }
    }
    let (mut tree, _) = tree_of(Box::new(Watched(disk.clone())));
    let temp = Temp::new("bad");
    disk.lock().unwrap().reads.clear();
    let report = run(&mut tree, &temp.0);
    assert_eq!(report.damaged(), 1);
    let copied = std::fs::read(temp.0.join("Documents/notes.txt")).unwrap();
    let mut want = image[at as usize..at as usize + 9000].to_vec();
    want[1024..1536].fill(0);
    assert_eq!(copied, want);
    let reads = disk
        .lock()
        .unwrap()
        .reads
        .iter()
        .filter(|(o, l)| *o < bad.end && bad.start < o + *l as u64)
        .count();
    assert_eq!(reads, 2, "the bad sector was read other than once per pass");
    let log = std::fs::read_to_string(temp.0.join(migrate::LOG)).unwrap();
    assert!(log.contains("DAMAGED: 512 bytes unreadable"), "{log}");
}

/// The test Windows drive made by tests/fixtures/migrate/make_drive.ps1, and where its
/// expectations are.
const QA: &str = r"D:\diagtool-qa\migrate";

/// Needs the test drive VHD that make_drive.ps1 builds under D:\diagtool-qa\migrate (an
/// NTFS volume with a Windows layout, two profiles, browser data with caches, a PST, a
/// SOFTWARE hive saved by `reg save`, Wi-Fi profiles and OneDrive placeholders), read as an
/// image file or, with DIAGTOOL_MIGRATE_DISK=N, as the attached disk N (administrator).
#[test]
#[ignore = "needs the test drive built by make_drive.ps1 under D:\\diagtool-qa\\migrate"]
fn a_test_windows_drive_is_copied_and_reported() {
    // DIAGTOOL_MIGRATE_QA names another folder make_drive.ps1 built the drive in (-Qa).
    let qa = std::env::var("DIAGTOOL_MIGRATE_QA").unwrap_or_else(|_| QA.to_string());
    let qa = Path::new(&qa);
    let source = match std::env::var("DIAGTOOL_MIGRATE_DISK") {
        Ok(n) => SourceChoice::Disk(n.parse().unwrap()),
        Err(_) => SourceChoice::Image(qa.join("drive.vhd")),
    };
    let out = qa.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let events = Mutex::new(Vec::new());
    let sink = |e: Event| events.lock().unwrap().push(e);
    let mut options = Options {
        source,
        destination: Some(out.clone()),
        people: Some(vec!["Nobody".into()]),
        skip_damaged: false,
    };
    // A person the drive does not hold is refused before anything is made.
    let refused = migrate::run(&options, &sink, &AtomicBool::new(false));
    assert!(
        matches!(&refused.ended, Ended::NotStarted(why) if why.contains("Nobody")),
        "{:?}",
        refused.ended
    );
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    events.lock().unwrap().clear();
    options.people = None;
    let outcome = migrate::run(&options, &sink, &AtomicBool::new(false));
    let events = events.into_inner().unwrap();
    let phases: Vec<Phase> = events
        .iter()
        .filter_map(|e| match e {
            Event::Phase { phase, .. } => Some(*phase),
            _ => None,
        })
        .collect();
    println!("phases: {phases:?}; {} events", events.len());
    let last = events
        .iter()
        .rev()
        .find(|e| matches!(e, Event::Copying { .. }));
    println!(
        "last copying event: {}",
        serde_json::to_string(&last).unwrap()
    );
    if let Some(Event::Copying {
        files,
        planned_files,
        bytes,
        planned_bytes,
        ..
    }) = last
    {
        assert_eq!((files, bytes), (planned_files, planned_bytes));
    } else {
        panic!("no copying event");
    }
    let json = serde_json::to_string_pretty(&outcome).unwrap();
    println!("result: {json}");
    assert!(!json.contains("TESTKEYMATERIAL"));
    assert_eq!(outcome.ended, Ended::Finished);
    for line in migrate_lines(outcome.plan.as_ref().unwrap()) {
        println!("plan: {line}");
    }
    let folder = outcome.folder.clone().unwrap();
    let report = std::fs::read_to_string(folder.join(migrate::REPORT)).unwrap();
    println!("{report}");
    assert!(outcome.report_complete, "the report is not complete");
    assert!(report.ends_with(migrate::END));
    // Every expected file hash-equal, every left-out one absent.
    let expected = std::fs::read_to_string(qa.join("expected.txt")).unwrap();
    let (mut same, mut absent) = (0, 0);
    for line in expected.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line
            .trim_start_matches('\u{feff}')
            .trim()
            .split('|')
            .collect();
        let path = folder.join(f[1]);
        match f[0] {
            "copied" => {
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|e| panic!("{} not copied: {e}", path.display()));
                assert_eq!(sha(&bytes), f[2].to_lowercase(), "{}", path.display());
                same += 1;
            }
            "absent" => {
                assert!(!path.exists(), "{} was copied", path.display());
                absent += 1;
            }
            "report" => {
                assert!(report.contains(f[1]), "the report lacks {:?}", f[1]);
            }
            "unreported" => {
                assert!(!report.contains(f[1]), "the report holds {:?}", f[1]);
            }
            other => panic!("unknown expectation {other}"),
        }
    }
    println!("{same} files hash-equal, {absent} left out as expected");
}

fn migrate_lines(plan: &migrate::Plan) -> Vec<String> {
    let mut lines = Vec::new();
    for w in &plan.windows {
        lines.push(w.volume.clone());
        for p in &w.people {
            for part in &p.parts {
                lines.push(format!(
                    "{}: {} {} files {} bytes",
                    p.name, part.label, part.files, part.bytes
                ));
            }
        }
        for skipped in &w.skipped {
            lines.push(format!("skipped {}: {}", skipped.name, skipped.why));
        }
    }
    lines
}
