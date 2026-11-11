//! The files of an NTFS volume as the rescue copy reads them: the folders and files in
//! use, from the volume's file table, and their content read from the source by the
//! volume's own cluster map. Windows never mounts the volume. Junctions and links are not
//! followed, files that are only in OneDrive are not read, and content NTFS stores
//! compressed or encrypted is not copied as if it were the file.
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::recovery::copy::{Entry, Times, Tree};
use crate::recovery::fs::ntfs::{Live, ROOT_RECORD};
use crate::recovery::fs::{Data, Place};
use crate::recovery::{BlockSource, ReadError};

/// The source, shared between the file table's reader and the copy's file reads.
pub type SharedSource = Arc<Mutex<Box<dyn BlockSource>>>;

/// A handle onto the shared source, as a source of its own.
pub struct Shared(pub SharedSource);

impl Shared {
    fn with<T>(&self, f: impl FnOnce(&mut Box<dyn BlockSource>) -> T) -> T {
        let mut source = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut source)
    }
}

impl BlockSource for Shared {
    fn len(&self) -> u64 {
        self.with(|s| s.len())
    }
    fn sector_size(&self) -> u32 {
        self.with(|s| s.sector_size())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        self.with(|s| s.read_at(offset, buf))
    }
    fn describe(&self) -> String {
        self.with(|s| s.describe())
    }
    fn disk_number(&self) -> Option<u32> {
        self.with(|s| s.disk_number())
    }
    fn protected(&self) -> crate::recovery::dest::Protected {
        self.with(|s| s.protected())
    }
}

const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x4_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;
const TAG_MOUNT_POINT: u32 = 0xA000_0003;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_DEDUP: u32 = 0x8000_0013;
const TAG_WOF: u32 = 0x8000_0017;
/// Records below this number are the file system's own.
const FIRST_USER: u64 = 24;
/// A parent mark: in a folder of the file system's own.
const SYSTEM: u64 = u64::MAX - 1;
/// A parent mark: the folder record is gone or is now another file's.
const LOST: u64 = u64::MAX;
/// ERROR_FILE_CORRUPT: the volume's map of the file has a hole.
const ERROR_FILE_CORRUPT: u32 = 1392;

/// Why an entry is not copied, as the copy's log and the report give it.
pub const ONLINE_ONLY: &str = "an online-only OneDrive file, not on this drive";
pub const PARTLY_ONLINE: &str = "a OneDrive file only partly on this drive";
pub const LINK: &str = "a junction or link, not followed";
pub const COMPRESSED: &str = "compressed by NTFS, which this tool does not decompress; not copied";
pub const ENCRYPTED: &str = "encrypted by Windows (EFS) to the old account; not copied";
pub const WOF: &str = "compressed by Windows (CompactOS), which this tool does not read";
pub const DEDUP: &str = "kept in Windows deduplication storage, which this tool does not read";
pub const SPECIAL: &str = "a special file Windows keeps elsewhere (a reparse point), not copied";
pub const SAME_NAME: &str =
    "has the same name as another item in its folder apart from capitals; not copied";

/// Whether a reparse tag is one of the cloud file tags (OneDrive and other sync clients).
fn cloud(tag: u32) -> bool {
    tag & 0xFFFF_0FFF == 0x9000_001A
}

/// What one record is to the copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Folder,
    File,
    /// Listed, never followed or read.
    Not(&'static str),
}

struct Node {
    name: String,
    /// The name in lower case, for lookups.
    key: String,
    parent: u64,
    kind: Kind,
    size: u64,
    data: Data,
    times: Times,
    damaged: bool,
    /// Children by record number, sorted by `key`.
    children: Vec<u64>,
}

fn time(ticks: Option<u64>) -> Option<SystemTime> {
    // NTFS ticks are 100 ns since 1601; 1970 is this many ticks later.
    const EPOCH: u64 = 116_444_736_000_000_000;
    let ticks = ticks?;
    if ticks >= EPOCH {
        let d = ticks - EPOCH;
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(d / 10_000_000, (d % 10_000_000) as u32 * 100))
    } else {
        let d = EPOCH - ticks;
        SystemTime::UNIX_EPOCH
            .checked_sub(Duration::new(d / 10_000_000, (d % 10_000_000) as u32 * 100))
    }
}

/// Whether every byte of a file's content is on the volume (not sparse or missing).
fn all_local(data: &Data) -> bool {
    match data {
        Data::Resident(_) => true,
        Data::Runs(runs) => runs.iter().all(|r| matches!(r.place, Place::At(_))),
    }
}

fn kind_of(r: &Live) -> Kind {
    let online = r.attributes
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0;
    if r.is_dir {
        return match r.reparse {
            // OneDrive's own folders are cloud folders; what they hold is listed as usual.
            None => Kind::Folder,
            Some(tag) if cloud(tag) => Kind::Folder,
            Some(_) => Kind::Not(LINK),
        };
    }
    match r.reparse {
        Some(tag) if cloud(tag) => {
            if (r.size == 0 || all_local(&r.data)) && !online {
                Kind::File
            } else if matches!(&r.data, Data::Runs(runs) if runs.iter().any(|x| matches!(x.place, Place::At(_))))
            {
                Kind::Not(PARTLY_ONLINE)
            } else {
                Kind::Not(ONLINE_ONLY)
            }
        }
        Some(TAG_MOUNT_POINT | TAG_SYMLINK) => Kind::Not(LINK),
        Some(TAG_WOF) => Kind::Not(WOF),
        Some(TAG_DEDUP) => Kind::Not(DEDUP),
        Some(_) => Kind::Not(SPECIAL),
        None if online => Kind::Not(ONLINE_ONLY),
        None if r.encrypted => Kind::Not(ENCRYPTED),
        None if r.compressed => Kind::Not(COMPRESSED),
        None => Kind::File,
    }
}

/// One NTFS volume's files in use.
pub struct NtfsTree {
    source: SharedSource,
    sector: u32,
    nodes: HashMap<u64, Node>,
    /// Files in use whose folder chain does not reach the root: a folder record on the way
    /// could not be read. They cannot be placed, so they are not copied.
    pub unplaced: usize,
}

impl NtfsTree {
    /// Builds the tree from the volume's records in use. `source` is what they were read
    /// from.
    pub fn new(source: SharedSource, records: Vec<Live>) -> NtfsTree {
        let sector = source
            .lock()
            .map(|s| s.sector_size())
            .unwrap_or(512)
            .max(512);
        let seqs: HashMap<u64, (u16, bool)> =
            records.iter().map(|r| (r.no, (r.seq, r.is_dir))).collect();
        let mut nodes: HashMap<u64, Node> = HashMap::with_capacity(records.len());
        for r in records {
            let kind = kind_of(&r);
            nodes.insert(
                r.no,
                Node {
                    key: r.name.to_lowercase(),
                    name: r.name,
                    parent: r.parent,
                    kind,
                    size: r.size,
                    data: r.data,
                    times: Times {
                        created: time(r.created),
                        modified: time(r.modified),
                        accessed: time(r.accessed),
                    },
                    damaged: r.damaged,
                    children: Vec::new(),
                },
            );
            // A parent whose sequence number differs is a later file in a reused record.
            let fits = seqs
                .get(&r.parent)
                .is_some_and(|(seq, dir)| *dir && (r.parent_seq == 0 || *seq == r.parent_seq));
            if !fits {
                // In a folder of the file system's own ($Extend and below), or lost.
                let system = r.parent != ROOT_RECORD && r.parent < FIRST_USER;
                nodes.get_mut(&r.no).expect("just made").parent =
                    if system { SYSTEM } else { LOST };
            }
        }
        let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
        for (no, node) in &nodes {
            if *no != ROOT_RECORD && node.parent != SYSTEM && node.parent != LOST {
                children.entry(node.parent).or_default().push(*no);
            }
        }
        for (parent, mut list) in children {
            list.sort_by(|a, b| nodes[a].key.cmp(&nodes[b].key).then(a.cmp(b)));
            if let Some(node) = nodes.get_mut(&parent) {
                node.children = list;
            }
        }
        // Files the root does not reach.
        let mut reached = HashSet::new();
        let mut stack = vec![ROOT_RECORD];
        while let Some(no) = stack.pop() {
            if reached.insert(no) {
                if let Some(node) = nodes.get(&no) {
                    stack.extend(node.children.iter().copied());
                }
            }
        }
        // Those under the file system's own folders are not the customer's.
        let system = |mut no: u64| {
            for _ in 0..256 {
                match nodes.get(&no).map(|n| n.parent) {
                    Some(SYSTEM) => return true,
                    Some(parent) => no = parent,
                    None => return false,
                }
            }
            false
        };
        let unplaced = nodes
            .iter()
            .filter(|(no, n)| !reached.contains(*no) && n.kind != Kind::Folder && !system(**no))
            .count();
        nodes.retain(|no, _| reached.contains(no));
        NtfsTree {
            source,
            sector,
            nodes,
            unplaced,
        }
    }

    /// Keeps only what lies on or below `paths` (and the folders leading there), so a
    /// volume's other files do not stay in memory.
    pub fn keep(&mut self, paths: &[&Path]) {
        let mut keep = HashSet::new();
        for path in paths {
            let Some(no) = self.find(path) else { continue };
            let mut up = no;
            while keep.insert(up) && up != ROOT_RECORD {
                match self.nodes.get(&up) {
                    Some(node) => up = node.parent,
                    None => break,
                }
            }
            let mut stack = vec![no];
            while let Some(at) = stack.pop() {
                keep.insert(at);
                if let Some(node) = self.nodes.get(&at) {
                    stack.extend(node.children.iter().copied());
                }
            }
        }
        self.nodes.retain(|no, _| keep.contains(no));
        for node in self.nodes.values_mut() {
            node.children.retain(|c| keep.contains(c));
        }
    }

    /// The record at `path` ("\Users\Ann"), names compared without case.
    fn find(&self, path: &Path) -> Option<u64> {
        let mut at = ROOT_RECORD;
        self.nodes.get(&at)?;
        for part in path.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            let key = name.to_string_lossy().to_lowercase();
            let node = self.nodes.get(&at)?;
            let i = node
                .children
                .binary_search_by(|c| self.nodes[c].key.as_str().cmp(key.as_str()))
                .ok()?;
            // The first of any alike in case, as `list` copies it.
            let mut first = i;
            while first > 0 && self.nodes[&node.children[first - 1]].key == key {
                first -= 1;
            }
            at = node.children[first];
        }
        Some(at)
    }

    /// Whether `path` is a folder that is copied into (not a link).
    pub fn is_folder(&self, path: &Path) -> bool {
        self.find(path)
            .and_then(|no| self.nodes.get(&no))
            .is_some_and(|n| n.kind == Kind::Folder)
    }

    /// The size of the file at `path`, when it is a file that is copied.
    pub fn file_len(&self, path: &Path) -> Option<u64> {
        let node = self.nodes.get(&self.find(path)?)?;
        (node.kind == Kind::File).then_some(node.size)
    }
}

impl Tree for NtfsTree {
    fn list(&mut self, folder: &Path) -> Result<Vec<Entry>, String> {
        let no = self
            .find(folder)
            .ok_or_else(|| "it is not in the volume's file table".to_string())?;
        let node = &self.nodes[&no];
        if node.kind != Kind::Folder {
            return Err("it is not a folder".into());
        }
        let mut out = Vec::with_capacity(node.children.len());
        let mut last: Option<&str> = None;
        for c in &node.children {
            let child = &self.nodes[c];
            let name = child.name.clone().into();
            if last == Some(child.key.as_str()) {
                out.push(Entry::Link {
                    name,
                    what: SAME_NAME,
                });
                continue;
            }
            last = Some(child.key.as_str());
            out.push(match child.kind {
                Kind::Folder => Entry::Folder {
                    name,
                    times: child.times,
                },
                Kind::File => Entry::File {
                    name,
                    len: child.size,
                    times: child.times,
                },
                Kind::Not(what) => Entry::Link { name, what },
            });
        }
        Ok(out)
    }

    fn open(&mut self, file: &Path, len: u64) -> Result<Box<dyn BlockSource>, ReadError> {
        let node = self
            .find(file)
            .and_then(|no| self.nodes.get(&no))
            .filter(|n| n.kind == Kind::File)
            .ok_or(ReadError::Bad(2))?; // ERROR_FILE_NOT_FOUND
        Ok(Box::new(FileSource {
            source: self.source.clone(),
            sector: self.sector,
            len: len.min(node.size),
            data: node.data.clone(),
            path: file.display().to_string(),
            scratch: Vec::new(),
        }))
    }

    fn times(&mut self, path: &Path) -> Times {
        self.find(path)
            .and_then(|no| self.nodes.get(&no))
            .map(|n| n.times)
            .unwrap_or_default()
    }

    /// Whether the volume's records of the file at `path` are damaged: its map has holes, or
    /// a record holding part of it is missing or unreadable.
    fn damaged(&mut self, path: &Path) -> bool {
        self.find(path)
            .and_then(|no| self.nodes.get(&no))
            .is_some_and(|n| n.damaged)
    }
}

/// One file's content, read from the source by its cluster runs. Past its length it reads
/// as zeros; a stretch the volume's map cannot place fails as unreadable.
pub struct FileSource {
    source: SharedSource,
    sector: u32,
    len: u64,
    data: Data,
    path: String,
    scratch: Vec<u8>,
}

impl BlockSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        buf.fill(0);
        let end = offset.saturating_add(buf.len() as u64).min(self.len);
        if offset >= end {
            return Ok(());
        }
        let runs = match &self.data {
            Data::Resident(bytes) => {
                let from = (offset as usize).min(bytes.len());
                let to = (end as usize).min(bytes.len());
                buf[..to - from].copy_from_slice(&bytes[from..to]);
                return Ok(());
            }
            Data::Runs(runs) => runs,
        };
        let sector = u64::from(self.sector.max(1));
        let mut pos = 0u64;
        for r in runs {
            let (s, e) = (offset.max(pos), end.min(pos.saturating_add(r.len)));
            if s < e {
                match r.place {
                    Place::Zeros => {}
                    Place::Missing => return Err(ReadError::Bad(ERROR_FILE_CORRUPT)),
                    Place::At(at) => {
                        let from = at + (s - pos);
                        let to = from + (e - s);
                        // Whole sectors around the stretch: runs are whole clusters, so
                        // the sectors read belong to this file.
                        let a0 = from / sector * sector;
                        let a1 = to.div_ceil(sector) * sector;
                        self.scratch.resize((a1 - a0) as usize, 0);
                        let mut source = self.source.lock().unwrap_or_else(|e| e.into_inner());
                        if a1 > source.len() {
                            return Err(ReadError::Bad(ERROR_FILE_CORRUPT));
                        }
                        source.read_at(a0, &mut self.scratch)?;
                        drop(source);
                        let skip = (from - a0) as usize;
                        let dst = (s - offset) as usize;
                        let n = (e - s) as usize;
                        buf[dst..dst + n].copy_from_slice(&self.scratch[skip..skip + n]);
                    }
                }
            }
            pos = pos.saturating_add(r.len);
            if pos >= end {
                break;
            }
        }
        Ok(())
    }

    fn describe(&self) -> String {
        self.path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::fs::Run;
    use crate::recovery::MemDisk;
    use std::path::PathBuf;

    fn live(no: u64, parent: u64, name: &str, is_dir: bool) -> Live {
        Live {
            no,
            seq: 1,
            name: name.into(),
            parent,
            parent_seq: 0,
            is_dir,
            size: 0,
            data: Data::Runs(Vec::new()),
            created: None,
            modified: Some(133_000_000_000_000_000),
            accessed: None,
            attributes: 0,
            reparse: None,
            compressed: false,
            encrypted: false,
            damaged: false,
        }
    }

    fn shared(disk: MemDisk) -> SharedSource {
        Arc::new(Mutex::new(Box::new(disk) as Box<dyn BlockSource>))
    }

    fn names(entries: &[Entry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| match e {
                Entry::Folder { name, .. } => format!("{}\\", name.to_string_lossy()),
                Entry::File { name, len, .. } => format!("{} {len}", name.to_string_lossy()),
                Entry::Link { name, what } => format!("{} ({what})", name.to_string_lossy()),
            })
            .collect()
    }

    /// The guard: links are never followed, OneDrive folders are, an online-only file is
    /// listed and not read, and two names alike but for capitals copy only the first.
    #[test]
    fn links_cloud_files_and_names_alike_are_listed_as_such() {
        let disk: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut records = vec![
            live(ROOT_RECORD, ROOT_RECORD, ".", true),
            live(30, ROOT_RECORD, "Users", true),
            live(31, 30, "Ann", true),
        ];
        let mut junction = live(32, 31, "Application Data", true);
        junction.reparse = Some(TAG_MOUNT_POINT);
        let mut one_drive = live(33, 31, "OneDrive", true);
        one_drive.reparse = Some(0x9000_701A);
        let mut placeholder = live(34, 33, "cloud.docx", false);
        placeholder.reparse = Some(0x9000_701A);
        placeholder.size = 5000;
        placeholder.data = Data::Runs(vec![Run {
            place: Place::Zeros,
            len: 5000,
        }]);
        placeholder.attributes = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        let mut local = live(35, 33, "local.txt", false);
        local.reparse = Some(0x9000_701A);
        local.size = 1000;
        local.data = Data::Runs(vec![Run {
            place: Place::At(1024),
            len: 1000,
        }]);
        let mut a = live(36, 31, "Notes.txt", false);
        a.size = 3;
        a.data = Data::Resident(b"abc".to_vec());
        let mut b = live(37, 31, "notes.TXT", false);
        b.data = Data::Resident(b"xyz".to_vec());
        let mut packed = live(38, 31, "packed.bin", false);
        packed.compressed = true;
        records.extend([junction, one_drive, placeholder, local, a, b, packed]);
        // A file whose folder record is gone, and one in the file system's own $Extend.
        records.push(live(40, 99, "lost.txt", false));
        records.push(live(43, 11, "$Quota", false));
        let mut tree = NtfsTree::new(shared(MemDisk::new(disk.clone())), records);
        assert_eq!(tree.unplaced, 1);
        let ann = names(&tree.list(Path::new(r"\Users\Ann")).unwrap());
        assert_eq!(
            ann,
            [
                format!("Application Data ({LINK})"),
                "Notes.txt 3".into(),
                format!("notes.TXT ({SAME_NAME})"),
                "OneDrive\\".into(),
                format!("packed.bin ({COMPRESSED})"),
            ]
        );
        let cloud = names(&tree.list(Path::new(r"\users\ann\onedrive")).unwrap());
        assert_eq!(
            cloud,
            [
                format!("cloud.docx ({ONLINE_ONLY})"),
                "local.txt 1000".into()
            ]
        );
        assert!(tree
            .list(Path::new(r"\Users\Ann\Application Data"))
            .is_err());
        assert!(tree
            .open(Path::new(r"\Users\Ann\OneDrive\cloud.docx"), 5000)
            .is_err());
        let mut file = tree
            .open(Path::new(r"\Users\Ann\OneDrive\local.txt"), 1000)
            .unwrap();
        let mut buf = vec![0u8; 1024];
        file.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..1000], &disk[1024..2024]);
        assert!(buf[1000..].iter().all(|b| *b == 0));
        let times = tree.times(&PathBuf::from(r"\Users\Ann\Notes.txt"));
        assert!(times.modified.is_some());
        tree.keep(&[Path::new(r"\Users\Ann\OneDrive")]);
        assert!(tree.list(Path::new(r"\Users\Ann\OneDrive")).is_ok());
        assert_eq!(
            names(&tree.list(Path::new(r"\Users\Ann")).unwrap()),
            ["OneDrive\\"]
        );
    }

    /// The guard: a file's content is read by its runs, a sparse run is zeros, and a run the
    /// map cannot place fails as unreadable rather than reading anything.
    #[test]
    fn a_file_reads_by_its_runs() {
        let disk: Vec<u8> = (0..16384u32).map(|i| (i / 512) as u8).collect();
        let mut f = live(41, ROOT_RECORD, "f.bin", false);
        f.size = 3000;
        f.data = Data::Runs(vec![
            Run {
                place: Place::At(4096),
                len: 1024,
            },
            Run {
                place: Place::Zeros,
                len: 1024,
            },
            Run {
                place: Place::At(1024),
                len: 952,
            },
        ]);
        let mut g = live(42, ROOT_RECORD, "g.bin", false);
        g.size = 1024;
        g.data = Data::Runs(vec![Run {
            place: Place::Missing,
            len: 1024,
        }]);
        let records = vec![live(ROOT_RECORD, ROOT_RECORD, ".", true), f, g];
        let mut tree = NtfsTree::new(shared(MemDisk::new(disk.clone())), records);
        let mut file = tree.open(Path::new(r"\f.bin"), 3000).unwrap();
        let mut buf = vec![0u8; 3072];
        file.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..1024], &disk[4096..5120]);
        assert!(buf[1024..2048].iter().all(|b| *b == 0));
        assert_eq!(&buf[2048..3000], &disk[1024..1976]);
        assert!(buf[3000..].iter().all(|b| *b == 0));
        let mut part = vec![0u8; 512];
        file.read_at(2560, &mut part).unwrap();
        assert_eq!(&part[..440], &disk[1536..1976]);
        let mut missing = tree.open(Path::new(r"\g.bin"), 1024).unwrap();
        assert_eq!(
            missing.read_at(0, &mut buf[..1024]),
            Err(ReadError::Bad(ERROR_FILE_CORRUPT))
        );
    }
}
