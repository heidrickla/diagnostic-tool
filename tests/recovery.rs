//! Deleted and lost file recovery and the scan for files by type, against the images in
//! tests/fixtures/recovery (see its README) and against test disks with bad areas.
use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use diagnostics::recovery::carve::{self, Carved, Kind};
use diagnostics::recovery::dest::Protected;
use diagnostics::recovery::fs::parts::{self, Search};
use diagnostics::recovery::fs::{
    self, Data, Found, FsKind, Listing, Origin, Place, Progress, State,
};
use diagnostics::recovery::headless;
use diagnostics::recovery::output::{self, Item, Layout, RecoverOptions};
use diagnostics::recovery::reader;
use diagnostics::recovery::{BlockSource, ImageFile, MemDisk, ReadError};

/// Every reader here owns the image it reads.
type Reader = reader::Reader<'static>;

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

/// A MemDisk the test keeps hold of, to look at its reads afterwards.
struct Shared(Arc<Mutex<MemDisk>>);

impl BlockSource for Shared {
    fn len(&self) -> u64 {
        self.0.lock().unwrap().len()
    }
    fn sector_size(&self) -> u32 {
        self.0.lock().unwrap().sector_size()
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        self.0.lock().unwrap().read_at(offset, buf)
    }
    fn describe(&self) -> String {
        "shared test disk".into()
    }
}

fn shared(disk: MemDisk) -> (Reader, Arc<Mutex<MemDisk>>) {
    let disk = Arc::new(Mutex::new(disk));
    (Reader::new(Box::new(Shared(disk.clone()))), disk)
}

fn reads_over(disk: &Arc<Mutex<MemDisk>>, range: &Range<u64>) -> usize {
    disk.lock()
        .unwrap()
        .reads
        .iter()
        .filter(|(o, l)| *o < range.end && range.start < o + *l as u64)
        .count()
}

/// A temporary folder of this test's own, removed when dropped.
struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Temp {
        Temp::new_in(&std::env::temp_dir(), tag)
    }

    fn new_in(base: &Path, tag: &str) -> Temp {
        let path = base.join(format!(
            "diagtool-recovery-{tag}-{}-{:?}",
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

struct Expect {
    start: u64,
    path: String,
    size: u64,
    sha: String,
    status: String,
}

fn manifest() -> HashMap<String, Vec<Expect>> {
    let text = std::fs::read_to_string(fixture("manifest.txt")).unwrap();
    let mut out: HashMap<String, Vec<Expect>> = HashMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split('|').collect();
        out.entry(f[0].to_string()).or_default().push(Expect {
            start: f[1].parse().unwrap(),
            path: f[2].to_string(),
            size: f[3].parse().unwrap(),
            sha: f[4].to_string(),
            status: f[5].to_string(),
        });
    }
    out
}

fn path_of(f: &Found) -> String {
    let mut p: String = f
        .folder
        .iter()
        .map(|part| format!("/{}", part.name))
        .collect();
    p.push('/');
    p.push_str(&f.name);
    p
}

fn never() -> AtomicBool {
    AtomicBool::new(false)
}

fn open(name: &str) -> Reader {
    Reader::new(Box::new(ImageFile::open(&fixture(name)).unwrap()))
}

fn scan_at(reader: &mut Reader, start: u64) -> (fs::Volume, Listing) {
    let volumes = parts::find(reader, Search::Aligned, &never(), &Progress::default()).volumes;
    let volume = volumes
        .into_iter()
        .find(|v| v.start == start)
        .unwrap_or_else(|| panic!("no volume at {start}"));
    let listing = fs::scan(reader, &volume, &never(), &Progress::default()).unwrap();
    (volume, listing)
}

/// Recovers files into a temporary folder, keeping their folders, and returns each one's
/// bytes by source path.
fn recover_all(reader: &mut Reader, files: &[&Found], temp: &Temp) -> HashMap<String, Vec<u8>> {
    let items: Vec<Item> = files.iter().map(|f| Item::from_found(f)).collect();
    let outcome = output::recover(
        reader,
        &items,
        &temp.0,
        &RecoverOptions::default(),
        &Protected::disk(9999),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    assert!(outcome.report.as_ref().is_some_and(|r| r.exists()));
    // Each output names its item by its tag, whatever order they were copied in.
    outcome
        .ledger
        .outputs()
        .iter()
        .filter_map(|w| Some((path_of(files.get(w.tag)?), std::fs::read(&w.path).unwrap())))
        .collect()
}

#[test]
fn every_fixture_is_found_listed_and_recovered_byte_for_byte() {
    let manifest = manifest();
    assert_eq!(manifest.len(), 6);
    for (image, expects) in &manifest {
        let mut reader = open(image);
        let mut starts: Vec<u64> = expects.iter().map(|e| e.start).collect();
        starts.dedup();
        for start in starts {
            let (_, listing) = scan_at(&mut reader, start);
            let by_path: HashMap<String, &Found> =
                listing.files.iter().map(|f| (path_of(f), f)).collect();
            let wanted: Vec<&Expect> = expects.iter().filter(|e| e.start == start).collect();
            let files: Vec<&Found> = wanted
                .iter()
                .map(|e| {
                    *by_path.get(&e.path).unwrap_or_else(|| {
                        panic!(
                            "{image}: {} not listed; listed: {:?}",
                            e.path,
                            by_path.keys().collect::<Vec<_>>()
                        )
                    })
                })
                .collect();
            let temp = Temp::new(&format!("all-{image}-{start}"));
            let recovered = recover_all(&mut reader, &files, &temp);
            for e in wanted {
                let f = by_path[&e.path];
                let what = format!("{image} {}", e.path);
                assert_eq!(f.size, e.size, "{what} size");
                assert_eq!(f.deleted, e.status != "live", "{what} deleted");
                assert!(!f.damaged, "{what} damaged");
                let bytes = &recovered[&e.path];
                match e.status.as_str() {
                    "live" | "deleted" => {
                        assert_eq!(f.state, State::Intact, "{what} state");
                        assert_eq!(sha(bytes), e.sha, "{what} content");
                    }
                    "deleted-partly" => {
                        assert!(
                            matches!(f.state, State::Partly { .. }),
                            "{what} {:?}",
                            f.state
                        );
                        assert_ne!(sha(bytes), e.sha, "{what} content should have changed");
                    }
                    other => {
                        let by = other.strip_prefix("deleted-overwritten-by:").unwrap();
                        assert_eq!(f.state, State::Overwritten, "{what} state");
                        let new = expects.iter().find(|x| x.path == by).unwrap();
                        assert_eq!(sha(bytes), new.sha, "{what} holds the new file");
                    }
                }
            }
        }
    }
}

#[test]
fn volumes_come_from_tables_scans_and_the_ntfs_backup_boot_sector() {
    let find = |name: &str| {
        let mut reader = open(name);
        parts::find(&mut reader, Search::Aligned, &never(), &Progress::default()).volumes
    };
    for (name, kind) in [
        ("ntfs.img", FsKind::Ntfs),
        ("fat32.img", FsKind::Fat32),
        ("fat16.img", FsKind::Fat16),
        ("exfat.img", FsKind::ExFat),
    ] {
        let v = find(name);
        assert_eq!(v.len(), 1, "{name}: {v:?}");
        assert_eq!(
            (v[0].kind, v[0].start, &v[0].origin),
            (kind, 0, &Origin::Whole)
        );
    }
    let mbr = find("mbr.img");
    let got: Vec<_> = mbr
        .iter()
        .map(|v| (v.kind, v.start, v.origin.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (FsKind::Fat12, 1 << 20, Origin::Mbr(1)),
            (FsKind::Ntfs, 2 << 20, Origin::Backup),
        ]
    );
    let gpt = find("gpt.img");
    let got: Vec<_> = gpt
        .iter()
        .map(|v| (v.kind, v.start, v.origin.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (FsKind::Fat12, 1 << 20, Origin::Gpt(1)),
            (FsKind::Fat12, 2 << 20, Origin::Found),
        ]
    );
    // The tables alone do not show what was deleted from them.
    let mut reader = open("gpt.img");
    let tables = parts::find(&mut reader, Search::Tables, &never(), &Progress::default()).volumes;
    assert_eq!(tables.len(), 1);
    let mut reader = open("mbr.img");
    let every = parts::find(&mut reader, Search::Every, &never(), &Progress::default()).volumes;
    assert_eq!(every.len(), 2);
}

fn find_file<'a>(listing: &'a Listing, path: &str) -> &'a Found {
    listing
        .files
        .iter()
        .find(|f| path_of(f) == path)
        .unwrap_or_else(|| panic!("{path} not listed"))
}

fn disk_runs(f: &Found) -> usize {
    match &f.data {
        Data::Runs(runs) => runs
            .iter()
            .filter(|r| matches!(r.place, Place::At(_)))
            .count(),
        Data::Resident(_) => 0,
    }
}

#[test]
fn fragmented_files_deleted_folders_and_resident_files_are_read_as_such() {
    let mut reader = open("ntfs.img");
    let (_, ntfs) = scan_at(&mut reader, 0);
    assert!(disk_runs(find_file(&ntfs, "/Documents/fragmented.bin")) > 1);
    assert!(disk_runs(find_file(&ntfs, "/Work/fragmented-deleted.bin")) > 1);
    assert!(matches!(
        find_file(&ntfs, "/readme.txt").data,
        Data::Resident(_)
    ));
    let tiny = find_file(&ntfs, "/Documents/Old/tiny.txt");
    assert!(matches!(tiny.data, Data::Resident(_)) && tiny.deleted);
    let letter = find_file(&ntfs, "/Documents/Old/letter.pdf");
    assert!(letter.folder[1].deleted && !letter.folder[0].deleted);
    assert_eq!(letter.folder_text(), "\\Documents\\Old (deleted)");

    let mut reader = open("fat32.img");
    let (_, fat) = scan_at(&mut reader, 0);
    assert!(find_file(&fat, "/Trip/Beach clip.mov").folder[0].deleted);
    assert!(find_file(&fat, "/Docs/Quarterly report.docx").deleted);

    let mut reader = open("exfat.img");
    let (_, exfat) = scan_at(&mut reader, 0);
    assert!(disk_runs(find_file(&exfat, "/Docs/chained.bin")) > 1);
    assert!(disk_runs(find_file(&exfat, "/Work/chained-deleted.bin")) > 1);
    assert!(find_file(&exfat, "/Old/report.docx").folder[0].deleted);
}

/// The NTFS fixture's boot values: cluster size and the file table's byte offset.
fn ntfs_layout(image: &[u8]) -> (u64, u64) {
    let cluster = u64::from(u16::from_le_bytes([image[11], image[12]])) * u64::from(image[13]);
    let mft = u64::from_le_bytes(image[0x30..0x38].try_into().unwrap()) * cluster;
    (cluster, mft)
}

#[test]
fn bad_areas_in_the_file_table_and_in_file_data_are_skipped_and_never_read_again() {
    let image = std::fs::read(fixture("ntfs.img")).unwrap();
    let (_, mft) = ntfs_layout(&image);
    let clean = {
        let (mut reader, _) = shared(MemDisk::new(image.clone()));
        scan_at(&mut reader, 0).1
    };
    let notes = find_file(&clean, "/Documents/notes.txt");
    let Data::Runs(runs) = &notes.data else {
        panic!("notes.txt is not resident")
    };
    let Place::At(data_at) = runs[0].place else {
        panic!("notes.txt has no first cluster")
    };
    assert_eq!(runs.len(), 1, "notes.txt is in one piece");
    let data_bad = data_at + 2048..data_at + 2560;
    // The record that describes photo.jpg.
    let (photo, _, _) = record_run(&image, mft, "photo.jpg");
    let mft_bad = photo as u64..photo as u64 + 1024;
    let mut disk = MemDisk::new(image.clone());
    disk.bad.push(data_bad.clone());
    disk.bad.push(mft_bad.clone());
    let (mut reader, disk) = shared(disk);
    let (_, listing) = scan_at(&mut reader, 0);
    // The reader gives up on the 4 KiB around a bad sector, as a drive with 4 KiB physical
    // sectors does, so photo.jpg's record and its neighbours are lost, and nothing else.
    let lost = clean.files.len() - listing.files.len();
    assert!((1..=4).contains(&lost), "{lost}");
    assert!(!listing.files.iter().any(|f| f.name == "photo.jpg"));
    assert!(
        listing
            .notes
            .iter()
            .any(|n| n.contains("could not be read")),
        "{:?}",
        listing.notes
    );
    let notes = find_file(&listing, "/Documents/notes.txt").clone();
    let temp = Temp::new("bad");
    for round in 0..3 {
        let outcome = output::recover(
            &mut reader,
            &[Item::from_found(&notes)],
            &temp.0,
            &RecoverOptions::default(),
            &Protected::default(),
            &never(),
            &Progress::default(),
        )
        .unwrap();
        // The bad sector costs the 4 KiB piece of the drive around it, and no more.
        let piece = data_bad.start & !4095;
        let (lo, hi) = (
            piece.saturating_sub(data_at),
            (piece + 4096 - data_at).min(9000),
        );
        let (lo, hi) = (lo as usize, hi as usize);
        let w = &outcome.ledger.outputs()[0];
        assert_eq!(w.zeroed, vec![lo as u64..hi as u64], "round {round}");
        let bytes = std::fs::read(&w.path).unwrap();
        let original = std::fs::read(fixture("samples/notes.txt")).unwrap();
        assert!(bytes[lo..hi].iter().all(|b| *b == 0));
        assert_eq!(bytes[..lo], original[..lo]);
        assert_eq!(bytes[hi..], original[hi..]);
        let report = std::fs::read_to_string(outcome.report.unwrap()).unwrap();
        let damaged = format!("DAMAGED: {} bytes unreadable", hi - lo);
        assert!(report.contains(&damaged), "{report}");
    }
    // Each bad area was asked for once in a large read and once in a small one, and never
    // again however many times the files were scanned or copied.
    assert!(
        reads_over(&disk, &data_bad) <= 2,
        "{}",
        reads_over(&disk, &data_bad)
    );
    assert!(
        reads_over(&disk, &mft_bad) <= 2,
        "{}",
        reads_over(&disk, &mft_bad)
    );
    let (_, again) = scan_at(&mut reader, 0);
    assert_eq!(again.files.len(), listing.files.len());
    assert!(reads_over(&disk, &mft_bad) <= 2);
}

/// Finds a file record by the name in its $FILE_NAME, and the offset of its first data run's
/// cluster field with that field's width.
fn record_run(image: &[u8], mft: u64, name: &str) -> (usize, usize, usize) {
    let wanted: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    for rec in (mft as usize..image.len()).step_by(1024).take(256) {
        let r = &image[rec..rec + 1024];
        let file_in_use = r[0x16] & 3 == 1;
        if &r[..4] != b"FILE" || !file_in_use || !r.windows(wanted.len()).any(|w| w == wanted) {
            continue;
        }
        let mut at = u16::from_le_bytes([r[0x14], r[0x15]]) as usize;
        loop {
            let kind = u32::from_le_bytes(r[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(r[at + 4..at + 8].try_into().unwrap()) as usize;
            if kind == 0x80 && r[at + 8] == 1 {
                let runs = at + u16::from_le_bytes([r[at + 0x20], r[at + 0x21]]) as usize;
                let header = r[runs];
                let (len_n, off_n) = ((header & 0xF) as usize, (header >> 4) as usize);
                return (rec, rec + runs + 1 + len_n, off_n);
            }
            assert!(kind != 0xFFFF_FFFF && len > 0, "{name} has no data runs");
            at += len;
        }
    }
    panic!("{name} not found in the file table")
}

#[test]
fn a_runlist_pointing_past_the_volume_never_reads_outside_it() {
    let mut image = std::fs::read(fixture("ntfs.img")).unwrap();
    let volume_len = image.len() as u64;
    let (cluster, mft) = ntfs_layout(&image);
    let (rec, field, width) = record_run(&image, mft, "fragmented.bin");
    // Keep the update-sequence words at each sector's end untouched.
    assert!((field + width - rec) % 512 < 510 && (field - rec) % 512 < 510);
    // Point the first run at a cluster just past the volume's end, inside the next
    // partition: there are readable bytes there that must never be read.
    let target = volume_len / cluster + 8;
    let bytes = target.to_le_bytes();
    assert!(width >= 2 && bytes[width..].iter().all(|b| *b == 0) && bytes[width - 1] < 0x80);
    image[field..field + width].copy_from_slice(&bytes[..width]);
    image.extend(vec![0x5A; 1 << 20]);
    let (mut reader, disk) = shared(MemDisk::new(image));
    let volume = fs::Volume {
        kind: FsKind::Ntfs,
        start: 0,
        len: volume_len,
        origin: Origin::Whole,
        claims: Vec::new(),
    };
    let listing = fs::scan(&mut reader, &volume, &never(), &Progress::default()).unwrap();
    let file = find_file(&listing, "/Documents/fragmented.bin");
    assert!(file.damaged);
    let temp = Temp::new("beyond");
    let outcome = output::recover(
        &mut reader,
        &[Item::from_found(file)],
        &temp.0,
        &RecoverOptions::default(),
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    assert!(!outcome.ledger.outputs()[0].zeroed.is_empty());
    let beyond = volume_len..volume_len + (1 << 20);
    assert_eq!(reads_over(&disk, &beyond), 0, "read outside the volume");
}

#[test]
fn a_destination_on_the_source_disk_is_refused_before_anything_is_written() {
    let temp = Temp::new("refuse");
    let disks = diagnostics::tools::drives::device::disks_of_path(&temp.0).unwrap();
    let mut reader = open("fat16.img");
    let (_, listing) = scan_at(&mut reader, 0);
    let items: Vec<Item> = listing.files.iter().map(Item::from_found).collect();
    let err = output::recover(
        &mut reader,
        &items,
        &temp.0,
        &RecoverOptions {
            layout: Layout::ByType,
            ..RecoverOptions::default()
        },
        &Protected::disk(disks[0]),
        &never(),
        &Progress::default(),
    )
    .unwrap_err();
    assert!(err.contains("the disk being recovered"), "{err}");
    assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 0);
}

/// A junction at `link` to `target`, made with mklink as a user can.
fn junction(link: &Path, target: &Path) {
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "mklink /J failed: {made:?}");
}

/// A destination on a disk other than the temporary folder's, which stands in for the source.
fn other_disk_folder(tag: &str) -> (Temp, Temp, u32) {
    use diagnostics::tools::drives::device::disks_of_path;
    let source_side = Temp::new(tag);
    let elsewhere = Temp::new_in(Path::new(env!("CARGO_TARGET_TMPDIR")), tag);
    let source_disk = disks_of_path(&source_side.0).unwrap()[0];
    let disks = disks_of_path(&elsewhere.0).unwrap();
    assert!(
        !disks.contains(&source_disk),
        "the temporary folder and the target folder share disk {source_disk}; this test needs two disks"
    );
    (elsewhere, source_side, source_disk)
}

/// The guard: a junction inside the destination that leads to the source disk is refused
/// through the handle of what would be written, and nothing reaches the source.
#[test]
fn a_junction_inside_the_destination_never_carries_files_to_the_source() {
    let (dest, source_side, source_disk) = other_disk_folder("junction");
    junction(&dest.0.join("Documents"), &source_side.0);
    let mut reader = open("fat16.img");
    let (_, listing) = scan_at(&mut reader, 0);
    let notes = Item::from_found(find_file(&listing, "/notes.txt"));
    let outcome = output::recover(
        &mut reader,
        &[notes],
        &dest.0,
        &RecoverOptions {
            layout: Layout::ByType,
            ..RecoverOptions::default()
        },
        &Protected::disk(source_disk),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    std::fs::remove_dir(dest.0.join("Documents")).unwrap();
    // The report alone: nothing was made through the junction.
    let made: Vec<_> = outcome.ledger.outputs().iter().map(|o| o.tag).collect();
    assert_eq!(made, [output::REPORT_TAG], "{:?}", outcome.ledger);
    assert_eq!(outcome.failed.len(), 1);
    assert!(
        outcome.failed[0].1.contains("junction or link"),
        "{:?}",
        outcome.failed
    );
    assert_eq!(
        std::fs::read_dir(&source_side.0).unwrap().count(),
        0,
        "a file was written through the junction"
    );
    assert!(outcome.report.is_some_and(|r| r.starts_with(&dest.0)));
}

#[test]
fn names_are_made_safe_and_never_overwrite() {
    let temp = Temp::new("names");
    let mut reader = open("fat16.img");
    let (_, listing) = scan_at(&mut reader, 0);
    let notes = find_file(&listing, "/notes.txt");
    let mut a = Item::from_found(notes);
    a.name = "CON.txt".into();
    let mut b = a.clone();
    b.name = "con.txt".into();
    let mut c = a.clone();
    c.name = "what?<>.txt. ".into();
    let outcome = output::recover(
        &mut reader,
        &[a, b, c],
        &temp.0,
        &RecoverOptions {
            layout: Layout::ByType,
            ..RecoverOptions::default()
        },
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    let names: Vec<String> = outcome
        .ledger
        .outputs()
        .iter()
        .map(|w| w.path.strip_prefix(&temp.0).unwrap().display().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "Documents\\_CON.txt",
            "Documents\\_con (2).txt",
            "Documents\\what___.txt",
            "Recovery report.txt"
        ]
    );
    // A second recovery into the same folder adds files beside the first ones.
    let again = output::recover(
        &mut reader,
        &[Item::from_found(notes)],
        &temp.0,
        &RecoverOptions::default(),
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    assert!(again.report.unwrap().ends_with("Recovery report (2).txt"));
}

/// Pseudo-random bytes with no file header at any sector start.
fn junk(seed: u64, n: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out: Vec<u8> = (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect();
    for s in out.chunks_mut(512) {
        s[0] = 0;
    }
    out
}

/// A sample placed on the carving disk: offset, file name, extension, bytes.
type Placed = (u64, &'static str, &'static str, Vec<u8>);

fn carve_disk() -> (Vec<u8>, Vec<Placed>) {
    let samples: [(&str, &str); 19] = [
        ("photo.jpg", "jpg"),
        ("holiday.jpg", "jpg"),
        ("image.png", "png"),
        ("anim.gif", "gif"),
        ("picture.bmp", "bmp"),
        ("still.webp", "webp"),
        ("letter.pdf", "pdf"),
        ("report.docx", "docx"),
        ("budget.xlsx", "xlsx"),
        ("minutes.odt", "odt"),
        ("bundle.zip", "zip"),
        ("clip.mp4", "mp4"),
        ("clip.mov", "mov"),
        ("clip.avi", "avi"),
        ("tone.wav", "wav"),
        ("contacts.sqlite", "sqlite"),
        ("archive.7z", "7z"),
        ("archive.rar", "rar"),
        ("notes.txt", ""),
    ];
    let mut disk = junk(1, 4096);
    let mut placed = Vec::new();
    for (i, (name, ext)) in samples.into_iter().enumerate() {
        let bytes = std::fs::read(fixture(&format!("samples/{name}"))).unwrap();
        let at = disk.len() as u64;
        disk.extend(&bytes);
        disk.extend(junk(i as u64 + 2, (512 - disk.len() % 512) % 512));
        disk.extend(junk(i as u64 + 100, 512 * (1 + i % 5)));
        if !ext.is_empty() {
            placed.push((at, name, ext, bytes));
        }
    }
    disk.extend(junk(999, 4096));
    (disk, placed)
}

fn run_carve(reader: &mut Reader) -> (Vec<Carved>, carve::Progress) {
    let progress = carve::Progress::default();
    let mut found = Vec::new();
    carve::carve(reader, &Kind::ALL, &never(), &progress, &mut |c| {
        found.push(c)
    });
    (found, progress)
}

#[test]
fn carving_finds_each_file_whole_between_junk() {
    let (disk, placed) = carve_disk();
    let (mut reader, _) = shared(MemDisk::new(disk.clone()));
    let (found, progress) = run_carve(&mut reader);
    let got: Vec<(u64, u64, &str)> = found.iter().map(|c| (c.offset, c.len, c.ext)).collect();
    let want: Vec<(u64, u64, &str)> = placed
        .iter()
        .map(|(at, _, ext, bytes)| (*at, bytes.len() as u64, *ext))
        .collect();
    assert_eq!(got, want);
    assert!(found.iter().all(|c| !c.damaged));
    let counted: u64 = progress
        .counts
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(counted, placed.len() as u64);
    // Recovered by type, each is the original file.
    let temp = Temp::new("carve");
    let items: Vec<Item> = found.iter().map(Item::from_carved).collect();
    let outcome = output::recover(
        &mut reader,
        &items,
        &temp.0,
        &RecoverOptions {
            layout: Layout::ByType,
            ..RecoverOptions::default()
        },
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    for (w, (_, name, _, bytes)) in outcome.ledger.outputs().iter().zip(&placed) {
        assert_eq!(&std::fs::read(&w.path).unwrap(), bytes, "{name}");
    }
    assert!(outcome.ledger.outputs()[0]
        .path
        .starts_with(temp.0.join("Pictures")));
}

#[test]
fn carving_skips_a_bad_area_once_and_marks_the_file_damaged() {
    let (disk, placed) = carve_disk();
    let (at, _, _, bytes) = placed.iter().find(|p| p.1 == "holiday.jpg").unwrap();
    let bad = (at + 4096) & !511..((at + 4096) & !511) + 512;
    assert!(bad.end < at + bytes.len() as u64);
    let mut disk = MemDisk::new(disk);
    disk.bad.push(bad.clone());
    let (mut reader, disk) = shared(disk);
    let (found, _) = run_carve(&mut reader);
    let photo = found.iter().find(|c| c.offset == *at).unwrap();
    assert!(photo.damaged);
    assert!(found.iter().filter(|c| c.offset != *at).all(|c| !c.damaged));
    let (again, _) = run_carve(&mut reader);
    assert_eq!(again.len(), found.len());
    assert!(reads_over(&disk, &bad) <= 2, "{}", reads_over(&disk, &bad));
}

/// Where a fixture's file system structures are: the tables, each volume's first 128 KiB and
/// the NTFS file table's first records.
fn hot_areas(image: &[u8]) -> Vec<Range<usize>> {
    let (mut reader, _) = shared(MemDisk::new(image.to_vec()));
    let volumes = parts::find(&mut reader, Search::Aligned, &never(), &Progress::default()).volumes;
    let clip = |s: usize, n: usize| s..(s + n).min(image.len());
    let mut hot = vec![clip(0, 64 << 10)];
    for v in volumes {
        let s = v.start as usize;
        hot.push(clip(s, 128 << 10));
        if let Some(b) = fs::ntfs::Boot::parse(&image[s..s + 512]) {
            hot.push(clip(s + (b.mft_lcn * b.cluster) as usize, 96 << 10));
        }
    }
    hot
}

/// Damages copies of every fixture at random where their structures are, and reads them every
/// way: nothing may panic, loop for ever or ask for an impossible amount of memory.
#[test]
fn damaged_file_systems_never_panic() {
    use rand08::{Rng, SeedableRng};
    // RECOVERY_FUZZ_ROUNDS and RECOVERY_FUZZ_SEED run a longer or different search by hand.
    let env = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let rounds = env("RECOVERY_FUZZ_ROUNDS", 80);
    let mut rng = rand08::rngs::StdRng::seed_from_u64(env("RECOVERY_FUZZ_SEED", 20261106));
    for name in [
        "ntfs.img",
        "fat32.img",
        "fat16.img",
        "exfat.img",
        "mbr.img",
        "gpt.img",
    ] {
        let image = std::fs::read(fixture(name)).unwrap();
        let hot = hot_areas(&image);
        for round in 0..rounds {
            let mut copy = image.clone();
            for _ in 0..1 + round % 24 {
                let area = &hot[rng.gen_range(0..hot.len())];
                let at = rng.gen_range(area.clone());
                copy[at] = rng.r#gen();
            }
            // A run of 0xFF or zeros over part of a structure, as a torn write leaves.
            let area = &hot[rng.gen_range(0..hot.len())];
            let at = rng.gen_range(area.start..area.end - 512);
            let fill = if round % 2 == 0 { 0xFF } else { 0x00 };
            copy[at..at + rng.gen_range(1..512)].fill(fill);
            let mut disk = MemDisk::new(copy);
            if round % 3 == 0 {
                let s = rng.gen_range(0..disk.data.len() as u64 / 512) * 512;
                disk.bad.push(s..s + 512 * rng.gen_range(1..64));
            }
            let (mut reader, _) = shared(disk);
            let volumes =
                parts::find(&mut reader, Search::Every, &never(), &Progress::default()).volumes;
            for v in volumes.iter().take(6) {
                if let Ok(listing) = fs::scan(&mut reader, v, &never(), &Progress::default()) {
                    for f in &listing.files {
                        let _ = (
                            f.state.label(),
                            f.folder_text(),
                            f.modified.map(|m| m.text()),
                        );
                    }
                }
            }
            if round % 4 == 0 {
                let _ = run_carve(&mut reader);
            }
        }
    }
}

/// An image of a Kingston stick, which now holds a grml live image over a lost NTFS
/// volume. Read only; set DIAGTOOL_KINGSTON_IMAGE to read another copy.
fn kingston_image() -> PathBuf {
    std::env::var_os("DIAGTOOL_KINGSTON_IMAGE")
        .map_or_else(|| PathBuf::from(r"kingston-stick.img"), PathBuf::from)
}

/// The deleted VMware installer on the lost NTFS volume lies where grml's partition 1 now
/// is, so it is overwritten, not intact: by the partition table and by its own first bytes.
#[test]
#[ignore = "reads a 31.0 GB image of a Kingston stick"]
fn the_vmware_iso_on_the_kingston_image_is_shown_overwritten() {
    let mut reader = Reader::new(Box::new(ImageFile::open(&kingston_image()).unwrap()));
    let finds = parts::find(&mut reader, Search::Aligned, &never(), &Progress::default());
    for v in &finds.volumes {
        println!("{}", v.describe());
    }
    for u in &finds.unread {
        println!("{}", u.describe());
    }
    // grml's ISO 9660 partition is a row of its own, not a note left beside every volume.
    assert_eq!(
        finds
            .unread
            .iter()
            .map(|u| (u.start, u.origin.clone()))
            .collect::<Vec<_>>(),
        vec![(0, Origin::Mbr(1))]
    );
    let volumes = finds.volumes;
    let lost = volumes
        .iter()
        .find(|v| v.kind == FsKind::Ntfs && v.is_lost())
        .expect("the lost NTFS volume");
    let listing = fs::scan(&mut reader, lost, &never(), &Progress::default()).unwrap();
    let name = "VMware-VMvisor-Installer-8.0U3e-24677879.x86_64.iso";
    let iso = listing
        .files
        .iter()
        .find(|f| f.name == name)
        .expect("the ISO is listed");
    let text = Item::from_found(iso).state;
    println!("{name}: {text}");
    if let Data::Runs(runs) = &iso.data {
        let at: Vec<(u64, u64)> = runs
            .iter()
            .filter_map(|r| match r.place {
                Place::At(a) => Some((a, r.len)),
                _ => None,
            })
            .collect();
        println!("its runs on the image (offset, length): {at:?}");
    }
    assert_eq!(iso.size, 648_374_272);
    assert_eq!(iso.state, State::Overwritten, "{text}");
    assert_eq!(
        text,
        "deleted, overwritten: contents do not match its type; partition 1 now holds this area"
    );
    // Its own first bytes say the same without the partition table.
    let mut alone = lost.clone();
    alone.claims.clear();
    let listing = fs::scan(&mut reader, &alone, &never(), &Progress::default()).unwrap();
    let iso = listing.files.iter().find(|f| f.name == name).unwrap();
    println!("{name}, by its contents: {}", iso.state_text());
    assert_eq!(
        iso.why,
        Some(fs::Why::Mismatch(None)),
        "{}",
        iso.state_text()
    );
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

fn scan_bytes(bytes: Vec<u8>, start: u64) -> (fs::Volume, Listing) {
    let mut reader = Reader::new(Box::new(MemDisk::new(bytes)));
    scan_at(&mut reader, start)
}

/// The guard: a current partition over a lost volume's file is a risk, not proof: the file
/// is shown at risk while its start is as its type should be, overwritten once it is not,
/// and stays recoverable either way.
#[test]
fn a_partition_over_a_lost_volume_file_is_a_risk_and_its_start_decides() {
    // mbr.img's lost NTFS volume at 2 MiB keeps report.docx (885 bytes) at 3,410,944.
    let (_, clean) = scan_bytes(fixture_bytes("mbr.img"), 2 << 20);
    let docx = find_file(&clean, "/Documents/report.docx");
    assert_eq!(
        docx.data,
        Data::Runs(vec![fs::Run {
            place: Place::At(3_410_944),
            len: 885
        }])
    );
    assert_eq!(docx.state_text(), "intact");
    for (sectors, want) in [
        (
            1u32,
            "at risk: partition 2 now holds 58% of this area; it starts as its type should",
        ),
        (
            2,
            "at risk: partition 2 now holds this area; it starts as its type should",
        ),
    ] {
        let mut image = fixture_bytes("mbr.img");
        let entry = &mut image[446 + 16..462 + 16];
        entry[4] = 0x83;
        entry[8..12].copy_from_slice(&(3_410_944u32 / 512).to_le_bytes());
        entry[12..16].copy_from_slice(&sectors.to_le_bytes());
        let (volume, listing) = scan_bytes(image.clone(), 2 << 20);
        assert!(
            volume
                .describe()
                .ends_with("; partition 2 now lies over part of it"),
            "{}",
            volume.describe()
        );
        let docx = find_file(&listing, "/Documents/report.docx");
        assert_eq!(docx.state, State::Intact);
        assert_eq!(docx.state_text(), want);
        assert_eq!(Item::from_found(docx).state, want);
        let mut reader = Reader::new(Box::new(MemDisk::new(image)));
        let temp = Temp::new("at-risk");
        let got = recover_all(&mut reader, &[docx], &temp);
        assert_eq!(got["/Documents/report.docx"].len(), 885);
    }
    // The same on a lost FAT volume: gpt.img's at 2 MiB, with tone.wav deleted at 2,130,432.
    let mut image = fixture_bytes("gpt.img");
    let table = 512 * u64::from_le_bytes(image[512 + 72..512 + 80].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(image[512 + 84..512 + 88].try_into().unwrap()) as usize;
    let entry = &mut image[table + size..table + 2 * size];
    entry[..16].copy_from_slice(&[0x11; 16]);
    entry[32..40].copy_from_slice(&(2_130_432u64 / 512).to_le_bytes());
    entry[40..48].copy_from_slice(&(2_130_432u64 / 512 + 7).to_le_bytes());
    let (_, listing) = scan_bytes(image.clone(), 2 << 20);
    let wav = find_file(&listing, "/tone.wav");
    assert_eq!(wav.state, State::Intact);
    assert_eq!(
        wav.state_text(),
        "at risk: partition 2 now holds this area; it starts as its type should"
    );
    assert_eq!(find_file(&listing, "/holiday.jpg").state_text(), "intact");
    // Once the new partition has written over its start, it is overwritten.
    image[2_130_432..2_130_432 + 32].copy_from_slice(&[0x5A; 32]);
    let (_, listing) = scan_bytes(image.clone(), 2 << 20);
    let wav = find_file(&listing, "/tone.wav");
    assert_eq!(wav.state, State::Overwritten);
    assert_eq!(
        wav.state_text(),
        "overwritten: contents do not match its type; partition 2 now holds this area"
    );
    let mut reader = Reader::new(Box::new(MemDisk::new(image)));
    let temp = Temp::new("overwritten");
    assert_eq!(
        recover_all(&mut reader, &[wav], &temp)["/tone.wav"].len(),
        4078
    );
}

/// The guard: a deleted file whose first bytes are not what its type starts with is shown
/// overwritten, in the list and the report, though its volume records its space as free.
#[test]
fn a_deleted_file_that_does_not_start_as_its_type_is_overwritten() {
    let (_, clean) = scan_bytes(fixture_bytes("ntfs.img"), 0);
    let at = |path: &str| match &find_file(&clean, path).data {
        Data::Runs(runs) => match runs[0].place {
            Place::At(at) => at as usize,
            _ => panic!("{path} has no first run"),
        },
        Data::Resident(_) => panic!("{path} is resident"),
    };
    let (gif, jpg) = (at("/Pictures/old.gif"), at("/Pictures/photo.jpg"));
    assert_eq!(
        find_file(&clean, "/Pictures/old.gif").state_text(),
        "intact"
    );
    let mut image = fixture_bytes("ntfs.img");
    image[gif..gif + 32].copy_from_slice(&[0x5A; 32]);
    image[jpg..jpg + 32].copy_from_slice(&[0x5A; 32]);
    let (_, listing) = scan_bytes(image, 0);
    let old = find_file(&listing, "/Pictures/old.gif");
    assert_eq!(old.state, State::Overwritten);
    assert_eq!(old.why, Some(fs::Why::Mismatch(None)));
    assert_eq!(
        Item::from_found(old).state,
        "deleted, overwritten: contents do not match its type"
    );
    // A deleted file whose start is as its type says is left as its volume records it, and
    // a file in use on a current volume is not judged by its contents.
    assert_eq!(find_file(&listing, "/Documents/Old/letter.pdf").why, None);
    assert_eq!(find_file(&listing, "/Pictures/photo.jpg").why, None);
}

/// A rescue image held in memory with its GNU ddrescue map: `image` with the bytes of `gap`
/// zeroed, as ddrescue leaves an area it never read, and the map marking `gap` bad.
fn image_with_gap(image: &[u8], gap: &Range<u64>) -> ImageFile {
    let mut data = image.to_vec();
    data[gap.start as usize..gap.end as usize].fill(0);
    let len = data.len() as u64;
    let map = format!(
        "# Rescue image map\n0x00000000     +               1\n0x00000000  0x{:08X}  +\n0x{:08X}  0x{:08X}  -\n0x{:08X}  0x{:08X}  +\n",
        gap.start,
        gap.start,
        gap.end - gap.start,
        gap.end,
        len - gap.end
    );
    ImageFile::over(
        Path::new("D:\\rescue\\fat32.img"),
        Box::new(MemDisk::new(data)),
        Ok((PathBuf::from("D:\\rescue\\fat32.map"), map)),
    )
}

/// The photo on fat32.img whose middle the gap takes, its first byte on the image, and the
/// gap in file offsets: past the first 4 KiB, which assessment reads.
fn photo_and_gap() -> (Found, u64, Range<u64>) {
    let (_, listing) = scan_bytes(fixture_bytes("fat32.img"), 0);
    let photo = find_file(&listing, "/DCIM/Holiday photo.jpg").clone();
    let Data::Runs(runs) = &photo.data else {
        panic!("the photo is not resident")
    };
    let Place::At(at) = runs[0].place else {
        panic!("the photo has no first cluster")
    };
    assert!(runs[0].len >= 6144, "the photo's first run holds the gap");
    (photo, at, 4608..5632)
}

/// The guard: a file recovered from a rescue image over an area its map does not mark
/// rescued is damaged, with that area as its missing range, never whole with zeros in it.
#[test]
fn an_undeleted_file_over_an_unread_area_of_an_image_is_damaged() {
    let (_, at, gap) = photo_and_gap();
    let image = image_with_gap(&fixture_bytes("fat32.img"), &(at + gap.start..at + gap.end));
    assert!(image.describe().contains("never read from the drive"));
    let mut reader = Reader::new(Box::new(image));
    let (_, listing) = scan_at(&mut reader, 0);
    let photo = find_file(&listing, "/DCIM/Holiday photo.jpg");
    let temp = Temp::new("image-gap-undelete");
    let outcome = output::recover(
        &mut reader,
        &[Item::from_found(photo)],
        &temp.0,
        &RecoverOptions::default(),
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    let w = &outcome.ledger.outputs()[0];
    assert!(w.damaged(), "{:?}", w.state);
    assert_eq!(w.zeroed, vec![gap.clone()]);
    assert_eq!(outcome.complete(), 0);
    let report = std::fs::read_to_string(outcome.report.unwrap()).unwrap();
    assert!(
        report.contains(&format!("bytes {}-{}", gap.start, gap.end)),
        "{report}"
    );
    assert!(report.contains("never read from the drive"), "{report}");
}

/// The guard, for files found by type: the same photo carved from the image is marked
/// damaged when found and recovered with the unread area as its missing range.
#[test]
fn a_carved_file_over_an_unread_area_of_an_image_is_damaged() {
    let (_, at, gap) = photo_and_gap();
    let image = image_with_gap(&fixture_bytes("fat32.img"), &(at + gap.start..at + gap.end));
    let mut reader = Reader::new(Box::new(image));
    let (found, _) = run_carve(&mut reader);
    let photo = found
        .iter()
        .find(|c| c.offset == at)
        .expect("the photo is found");
    assert!(photo.damaged);
    let temp = Temp::new("image-gap-carve");
    let outcome = output::recover(
        &mut reader,
        &[Item::from_carved(photo)],
        &temp.0,
        &RecoverOptions {
            layout: Layout::ByType,
            ..RecoverOptions::default()
        },
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    let w = &outcome.ledger.outputs()[0];
    assert!(w.damaged(), "{:?}", w.state);
    assert_eq!(w.zeroed, vec![gap]);
}

/// The live run of the salvage tools on a rescue image made on a test machine: a fixed VHD
/// under D:\diagtool-qa\salvage holding an NTFS volume with camera-style JPEGs in \DCIM (one
/// deleted) and Explorer's real thumbnail cache in a user's folder (a second copy deleted),
/// with sectors in DSC_0002.jpg zeroed and its map marking them bad. Needs those files; see
/// the salvage report for how they were made.
#[test]
#[ignore]
fn live_salvage_from_a_vhd_rescue_image() {
    use diagnostics::recovery::thumbcache;
    let base = Path::new(r"D:\diagtool-qa\salvage");
    let image = ImageFile::open(&base.join("salvage.vhd")).unwrap();
    println!("source: {}", image.describe());
    assert!(image.map().is_some(), "the map beside the VHD is used");
    let mut reader = Reader::new(Box::new(image));
    let volumes = parts::find(&mut reader, Search::Tables, &never(), &Progress::default()).volumes;
    let volume = volumes.first().expect("a volume").clone();
    println!("volume: {}", volume.describe());
    let listing = fs::scan(&mut reader, &volume, &never(), &Progress::default()).unwrap();
    let photos: Vec<&Found> = listing
        .files
        .iter()
        .filter(|f| f.folder.iter().any(|p| p.name == "DCIM"))
        .collect();
    for f in &photos {
        println!(
            "found {} {} deleted={} {}",
            path_of(f),
            f.size,
            f.deleted,
            f.state_text()
        );
    }
    let out = base.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let items: Vec<Item> = photos.iter().map(|f| Item::from_found(f)).collect();
    let outcome = output::recover(
        &mut reader,
        &items,
        &out,
        &RecoverOptions::default(),
        &Protected::default(),
        &never(),
        &Progress::default(),
    )
    .unwrap();
    for o in outcome.ledger.outputs() {
        println!("wrote {} {}", o.path.display(), o.condition());
    }
    let report = std::fs::read_to_string(outcome.report.as_ref().unwrap()).unwrap();
    let section = report
        .split("Pictures with missing parts")
        .nth(1)
        .and_then(|s| s.split("\r\n\r\n").next())
        .unwrap_or("");
    println!("report section:{section}");
    assert!(out.join("DCIM").join("DSC_0002 (partial).jpg").exists());
    assert_eq!(
        std::fs::read(out.join("DCIM").join("DSC_0002 (preview).jpg")).unwrap(),
        std::fs::read(base.join("photos").join("preview_2.jpg")).unwrap()
    );
    assert!(photos.iter().any(|f| f.deleted && f.name == "DSC_0006.jpg"));
    assert_eq!(outcome.pictures.len(), 1);

    for f in listing
        .files
        .iter()
        .filter(|f| thumbcache::is_cache(&f.name))
    {
        println!(
            "cache {} deleted={} size={} state={} runs={:?}",
            path_of(f),
            f.deleted,
            f.size,
            f.state_text(),
            match &f.data {
                Data::Runs(r) => r.clone(),
                Data::Resident(_) => Vec::new(),
            }
        );
    }
    let thumbs = base.join("thumbs");
    let _ = std::fs::remove_dir_all(&thumbs);
    std::fs::create_dir_all(&thumbs).unwrap();
    let options = thumbcache::Options {
        destination: thumbs.clone(),
        volumes: Vec::new(),
        include_deleted: true,
        files: Vec::new(),
        source_disk: Protected::default(),
    };
    let mut events = 0;
    let result = thumbcache::run(
        Some(&mut reader),
        &options,
        &[],
        &mut |_| events += 1,
        &never(),
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&result.caches).unwrap());
    println!("events {events}, report {:?}", result.report);
    assert!(result.caches.iter().any(|c| c.deleted && c.images > 0));
    assert!(result.caches.iter().any(|c| !c.deleted && c.images > 0));
    assert!(std::fs::read_to_string(result.report.unwrap())
        .unwrap()
        .ends_with(output::END));
}

/// A headless recover of `image` into `to`: its exit, what it printed and what it said as
/// an error.
fn headless(args: &[&str], cancel: bool) -> (headless::Exit, String, String) {
    let argv: Vec<String> = std::iter::once("DiagnosticTool.exe")
        .chain(args.iter().copied())
        .map(String::from)
        .collect();
    let Some(Ok(headless::Command::Recover(request))) = headless::parse(&argv) else {
        panic!("not a recover: {args:?}");
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = headless::run(
        &request,
        &AtomicBool::new(cancel),
        std::time::Duration::from_millis(1),
        &mut out,
        &mut err,
    );
    (
        exit,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn the_command_line_recover_writes_the_files_the_report_and_exits_0() {
    let temp = Temp::new("headless");
    let image = fixture("fat32.img");
    let (exit, out, err) = headless(
        &[
            "--recover-files",
            "--image",
            image.to_str().unwrap(),
            "--to",
            temp.0.to_str().unwrap(),
            "--all",
        ],
        false,
    );
    assert_eq!(
        (exit, err.as_str()),
        (headless::Exit::Complete, ""),
        "{out}"
    );
    assert!(out.contains("reading the largest, volume 1"), "{out}");
    let manifest = manifest();
    for e in manifest["fat32.img"]
        .iter()
        .filter(|e| e.status == "live" || e.status == "deleted")
    {
        let made = temp.0.join(e.path.trim_start_matches('/'));
        assert_eq!(sha(&std::fs::read(&made).unwrap()), e.sha, "{}", e.path);
    }
    let report = std::fs::read_to_string(temp.0.join(output::LOG_NAME)).unwrap();
    assert!(report.contains("Holiday photo.jpg"), "{report}");
    let reports: Vec<_> = std::fs::read_dir(&temp.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "txt") && p.file_name().unwrap() != output::LOG_NAME
        })
        .collect();
    assert_eq!(reports.len(), 1, "{reports:?}");
    let text = std::fs::read_to_string(&reports[0]).unwrap();
    assert_eq!(text.lines().last(), Some(output::END), "{text}");
}

#[test]
fn a_stopped_command_line_recover_exits_1_and_a_rerun_finishes_the_rest() {
    let temp = Temp::new("headless-stop");
    let (image, to) = (fixture("fat32.img"), temp.0.clone());
    let args = [
        "--recover-files",
        "--image",
        image.to_str().unwrap(),
        "--to",
        to.to_str().unwrap(),
        "--deleted-only",
        "--deleted-folder",
        "Deleted",
        "--by-type",
    ];
    let (exit, _, err) = headless(&args, true);
    assert_eq!(exit, headless::Exit::Incomplete, "{err}");
    assert!(err.contains("Stopped"), "{err}");
    let (exit, out, err) = headless(&args, false);
    assert_eq!(
        (exit, err.as_str()),
        (headless::Exit::Complete, ""),
        "{out}"
    );
    let deleted = temp.0.join("Deleted");
    let made: usize = walk(&deleted);
    assert!(made >= 4, "{made} files under {}", deleted.display());
}

fn walk(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .map(|p| if p.is_dir() { walk(&p) } else { 1 })
        .sum()
}

#[test]
fn the_command_line_recover_exits_2_for_what_it_cannot_open() {
    let temp = Temp::new("headless-usage");
    let missing = temp.0.join("none.img");
    let (exit, _, err) = headless(
        &[
            "--recover-files",
            "--image",
            missing.to_str().unwrap(),
            "--to",
            temp.0.to_str().unwrap(),
        ],
        false,
    );
    assert_eq!(exit, headless::Exit::Usage);
    assert!(err.contains("could not be opened"), "{err}");
    let image = fixture("fat32.img");
    let nowhere = temp.0.join("nowhere");
    let (exit, _, err) = headless(
        &[
            "--recover-files",
            "--image",
            image.to_str().unwrap(),
            "--to",
            nowhere.to_str().unwrap(),
        ],
        false,
    );
    assert_eq!(exit, headless::Exit::Usage);
    assert!(err.contains("not an existing folder"), "{err}");
    let (exit, _, err) = headless(
        &[
            "--recover-files",
            "--image",
            image.to_str().unwrap(),
            "--to",
            temp.0.to_str().unwrap(),
            "--volume",
            "5",
        ],
        false,
    );
    assert_eq!(exit, headless::Exit::Usage);
    assert!(err.contains("the image has 1 volume"), "{err}");
}
