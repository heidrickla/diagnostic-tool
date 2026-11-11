//! Data recovery from failing drives: rescue imaging, Fill the gaps and the edge check, rescue
//! copies of files, copying the customer's files, deleted and lost file recovery with
//! pictures' own previews and Explorer's thumbnails, file-type scanning, checking recovered
//! files, opening an image as a drive with BitLocker unlock, key lookup and repair on a copy,
//! and writing an image to a replacement drive.
//!
//! The rules every recovery tool keeps:
//! - The source (a physical disk, an image file, or an unlocked volume on either) is opened
//!   for reading only, and shared. Nothing in this module writes to it.
//! - Every write goes to one of three places, each checked through handles, never by path
//!   text: a new output folder on another disk, refused on the source disk before anything
//!   is read (`dest.rs`); the replacement drive the technician picks, written by
//!   `restore.rs` only after it passed every refusal just before, opened through
//!   `target.rs`; or the differencing copy a repair makes over an image (`repair.rs`).
//! - A failing read is recorded and skipped, never retried automatically: a dying drive
//!   loses more with every hard retry, so easy areas come first and bad ones last. Failed
//!   areas are read again only in bounded passes that the technician, or an agent the
//!   technician directs, starts (Fill the gaps, `fill.rs`): each sector once per pass, at
//!   most 5 passes, a rest between them, and a stop when the drive's counts rise. Work that can hang on a failing drive runs under `timed.rs`.
//! - Work can be stopped at any point and resumed from what was saved.
//! - Every output file is entered in the ledger (`ledger.rs`) when made and ends whole,
//!   damaged, partial or removed; a report ends "End of report." only when every write
//!   succeeded. Every output file is made by the one writer (`writer.rs`).
//! - Unknown is never taken as fine: a failed or unreadable result refuses a change, and is
//!   said as not known in a report, never shown as zero, empty or fine (DESIGN.md).
//! - A blocking call that changes something runs within a time limit and keeps what undoes
//!   it (`timed::owned`): one that ends after its caller gave up is put back, or recorded
//!   and said, never forgotten (DESIGN.md).
//! - A BitLocker recovery key, typed or looked up, stays in memory only, in a zeroing type,
//!   and is never shown whole, logged, written to a file, or put in an event or result.
//! - Each tool is an engine with typed, serde options, events and result and no window in
//!   it, so the technician or an agent the technician directs can drive it; confirmations a
//!   window asks a person for are fields in the options, checked by the engine.
use std::fs::File;
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};

pub mod bitlocker;
pub mod candidates;
pub mod carve;
pub mod condition;
pub mod copy;
pub mod dest;
pub mod disk;
pub mod edges;
pub mod events;
pub mod fill;
pub mod fs;
pub mod headless;
pub mod health_log;
pub mod image;
pub mod keylookup;
pub mod ledger;
pub mod migrate;
pub mod output;
pub mod pace;
pub mod pending;
pub mod photos;
pub mod place;
pub mod preview;
pub mod read_limit;
pub mod reader;
pub mod repair;
pub mod restore;
pub mod target;
pub mod thumbcache;
pub mod timed;
pub mod vdisk;
pub mod verify;
pub mod wait;
pub mod writer;
pub mod zones;

/// Why one read failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The drive answered with an error for this area (Win32 error code).
    Bad(u32),
    /// The read did not finish within its time limit and was cancelled.
    TimedOut,
    /// The drive is gone: unplugged, or it stopped answering at all.
    Gone(u32),
}

/// Something that can be read by byte offset: a physical disk, a volume or an image file.
pub trait BlockSource: Send {
    /// Size in bytes.
    fn len(&self) -> u64;
    /// Bytes per sector; offsets and lengths passed to `read_at` are multiples of it.
    fn sector_size(&self) -> u32;
    /// Fills `buf` from `offset`. A failure leaves `buf` unspecified.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError>;
    /// What the source is, for people: "Disk 3, Samsung SSD 860, 500 GB" or a file path.
    fn describe(&self) -> String;
    /// The physical disk number when the source is a disk, for the destination rule.
    fn disk_number(&self) -> Option<u32> {
        None
    }
    /// What output must not be written to while this source is read (`dest::Protected`): a
    /// drive's own disk by its number and by its identity, so it is still refused when it
    /// comes back from a replug under another number; for an image, the drive its map says it
    /// was made from.
    fn protected(&self) -> dest::Protected {
        let disk = self.disk_number();
        dest::Protected {
            disks: disk.into_iter().collect(),
            drives: disk
                .and_then(|_| self.identity())
                .map(|id| dest::Guarded::new(id, None))
                .into_iter()
                .collect(),
            ..dest::Protected::default()
        }
    }
    /// The drive's model, serial number and size, and for an ATA drive its own model and
    /// serial number, recorded in a rescue map so a resumed run reads the same drive. None
    /// when they could not be read.
    fn identity(&self) -> Option<SourceId> {
        None
    }
    /// The rescue map this source is read under, when it has one: a byte is readable only
    /// where the map marks it rescued.
    fn rescue_map(&self) -> Option<&image::Map> {
        None
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Whether a failed area may be narrowed sector by sector at no cost to the drive: an
    /// image, whose failed areas come from its map. A drive is narrowed in 4 KiB pieces, each
    /// read once, so a dying one is not worn by many small reads.
    fn sector_exact(&self) -> bool {
        false
    }
    /// Whether the drive is shown to be answering now, by a read-only query the drive itself
    /// answers within a short limit (a physical disk's size, READ CAPACITY). Asked after a
    /// run of failed reads; a source that is not a drive always answers.
    fn answering(&mut self) -> bool {
        true
    }
}

/// What identifies a drive to a rescue map: the model, serial number and size Windows
/// reports, and for an ATA drive the drive's own model and serial number from IDENTIFY. The
/// first are a USB adapter's while the drive is in its enclosure and the drive's own on a
/// SATA port; the drive's own stay the same across the move.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceId {
    pub model: String,
    pub serial: String,
    pub size: u64,
    /// The drive's own identity; None for a drive that gave none (NVMe, a flash stick, a
    /// drive or adapter that did not answer IDENTIFY) and in maps made before it was kept.
    pub drive: Option<crate::tools::drives::ata::DriveId>,
    /// Bytes per logical sector as Windows reported it; None when not reported.
    pub sector: Option<u32>,
    /// The part of the drive read; None in maps made before it was kept.
    pub scope: Option<Scope>,
    /// The whole drive's size in bytes, which `size` is not for a volume; None when Windows
    /// did not report it and in maps made before it was kept.
    pub disk_size: Option<u64>,
}

/// Which part of a drive a source reads: two volumes of one size on one drive share its
/// identity and size, and only their place on it tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    /// The whole disk.
    Disk,
    /// One volume, starting `offset` bytes into the disk.
    Volume { offset: u64 },
}

impl SourceId {
    /// "Kingston DataTraveler 3.0, serial 0123, 31,042,043,904 bytes", for people, with the
    /// drive's own model and serial number when it gave them.
    pub fn text(&self) -> String {
        let serial = if self.serial.trim().is_empty() {
            "no serial number".to_string()
        } else {
            format!("serial {}", self.serial)
        };
        let drive = self.drive.as_ref().map_or_else(String::new, |drive| {
            format!(
                " (the drive itself {}, serial {})",
                drive.model, drive.serial
            )
        });
        format!("{}, {serial}, {} bytes{drive}", self.model, self.size)
    }
}

/// Where output bytes go by offset: a file, or in tests a writer that fails as told.
pub trait Sink: Send {
    /// One positioned write; it may take fewer bytes than given, as `seek_write` may.
    fn write_at(&mut self, data: &[u8], pos: u64) -> std::io::Result<usize>;
    /// Makes what was written durable.
    fn flush_data(&mut self) -> std::io::Result<()>;
    /// Reads back what was written at `pos`, all of `data`, where the sink can; false when
    /// it cannot, and the caller reads the source instead.
    fn read_back(&mut self, _data: &mut [u8], _pos: u64) -> bool {
        false
    }
}

impl Sink for File {
    fn write_at(&mut self, data: &[u8], pos: u64) -> std::io::Result<usize> {
        self.seek_write(data, pos)
    }

    fn flush_data(&mut self) -> std::io::Result<()> {
        self.sync_data()
    }

    fn read_back(&mut self, data: &mut [u8], pos: u64) -> bool {
        let mut done = 0;
        while done < data.len() {
            match self.seek_read(&mut data[done..], pos + done as u64) {
                Ok(0) | Err(_) => return false,
                Ok(n) => done += n,
            }
        }
        true
    }
}

/// Writes all of `data` at `pos`, write after write, or fails: a write that takes nothing is
/// an error. Nothing is counted as written until this returns Ok.
pub fn write_all_at(sink: &mut dyn Sink, data: &[u8], pos: u64) -> std::io::Result<()> {
    let mut done = 0;
    while done < data.len() {
        match sink.write_at(&data[done..], pos + done as u64)? {
            0 => return Err(std::io::ErrorKind::WriteZero.into()),
            n => done += n,
        }
    }
    Ok(())
}

/// What a recovery tool reads: a physical disk (needs administrator rights) or an image file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SourceChoice {
    Disk(u32),
    Image(PathBuf),
    /// One volume, "\\?\Volume{guid}", on disk `disk`: an unlocked BitLocker volume, read
    /// decrypted. `name` says which for people ("E: on Disk 5").
    Volume {
        path: String,
        disk: u32,
        name: String,
    },
}

impl SourceChoice {
    /// What the source is, for people, before it is opened: "Disk 3", the image's path or
    /// the volume's name.
    pub fn label(&self) -> String {
        match self {
            SourceChoice::Disk(number) => format!("Disk {number}"),
            SourceChoice::Image(path) => path.display().to_string(),
            SourceChoice::Volume { name, .. } => name.clone(),
        }
    }
}

/// Opens what a recovery tool reads. A disk needs administrator rights.
pub fn open_source(choice: &SourceChoice) -> Result<Box<dyn BlockSource>, String> {
    match choice {
        SourceChoice::Image(path) => ImageFile::open(path)
            .map(|image| Box::new(image) as Box<dyn BlockSource>)
            .map_err(|e| format!("{} could not be opened: {e}", path.display())),
        SourceChoice::Disk(number) => {
            disk::PhysicalDisk::open(*number).map(|disk| Box::new(disk) as Box<dyn BlockSource>)
        }
        SourceChoice::Volume { path, disk, name } => {
            disk::PhysicalDisk::open_volume(path, *disk, name.clone())
                .map(|volume| Box::new(volume) as Box<dyn BlockSource>)
        }
    }
}

/// Refuses a destination on the disk being recovered, by its name, before anything is read
/// or written. Every output is checked again through its handle (`dest::Guard`).
/// `protected` is the source's `BlockSource::protected`: an image's own file cannot be
/// overwritten, but the drive it was made from can.
pub fn check_destination(destination: &Path, protected: &dest::Protected) -> Result<(), String> {
    dest::Guard::of(protected).check_folder(destination)
}

/// `check_destination`, with what a person may confirm (`dest::Refusal`).
pub fn destination_refusal(
    destination: &Path,
    protected: &dest::Protected,
) -> Result<(), dest::Refusal> {
    dest::Guard::of(protected).folder_refusal(destination)
}

/// An image file made by the rescue image tool (or any raw `dd` image), read without
/// administrator rights. When the GNU ddrescue map beside it fits it, every area the map does
/// not mark rescued ('+') reads as a failed read, as the drive's own bad areas do, so a file
/// over one is recovered with zeros there and marked damaged rather than passed as whole.
pub struct ImageFile {
    path: PathBuf,
    /// The image's bytes: the file, or in tests a disk in memory.
    store: Box<dyn BlockSource>,
    /// The drive's size: the map's when it fits, else the file's.
    len: u64,
    map: Option<image::Map>,
    /// The drive its map says it was made from, when the map names one.
    made_from: Option<SourceId>,
    /// That drive's partition table ID, from the image's own first sectors.
    table: Option<String>,
    /// That drive's rescued bytes at a few places, for telling it from a look-alike.
    samples: Vec<dest::Sample>,
    /// What is known of the image's unread areas, for people.
    note: String,
}

/// The error a read over an area the map does not mark rescued gives: ERROR_READ_FAULT.
pub const UNREAD_IN_IMAGE: u32 = 30;
/// A map larger than this is not a rescue map.
const MAP_MAX: u64 = 64 << 20;
/// The 512-byte footer a fixed VHD has after the drive's bytes; it is not the drive's.
const VHD_FOOTER: u64 = 512;

/// The map file beside an image, read: its path and text, or why there is none.
pub type MapBeside = Result<(PathBuf, String), String>;

/// The raw bytes of an image file.
struct RawFile {
    file: File,
    len: u64,
}

impl BlockSource for RawFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let mut done = 0;
        while done < buf.len() {
            match self.file.seek_read(&mut buf[done..], offset + done as u64) {
                Ok(0) => return Err(ReadError::Bad(38)), // ERROR_HANDLE_EOF
                Ok(n) => done += n,
                Err(e) => return Err(ReadError::Bad(e.raw_os_error().unwrap_or(0) as u32)),
            }
        }
        Ok(())
    }

    fn describe(&self) -> String {
        String::new()
    }
}

/// Where a map for `image` may be: the name the rescue image tool gives it ("x.map" beside
/// "x.img"), then the image's whole name with ".map" after it ("x.img.map"). Windows names
/// ignore case, so a name that is the image's own in any case is not one.
pub fn map_paths(image: &Path) -> Vec<PathBuf> {
    let mut appended = image.as_os_str().to_owned();
    appended.push(".map");
    let same = |a: &Path, b: &Path| {
        a.as_os_str().to_string_lossy().to_lowercase()
            == b.as_os_str().to_string_lossy().to_lowercase()
    };
    let mut paths = vec![image.with_extension("map"), PathBuf::from(appended)];
    paths.dedup_by(|a, b| same(a, b));
    paths.retain(|p| !same(p, image));
    paths
}

/// The map beside `image`, by either of its names (`map_paths`), held open so it cannot be
/// changed, renamed or replaced while it is read: None when neither name is there. Only a
/// name with nothing there is passed over: one that cannot be opened says why, and two maps
/// that differ are refused, so a map is never put aside for another or for none unsaid.
/// Every reader of an image's map finds it here.
pub fn locate_map(image: &Path) -> Result<Option<(PathBuf, File)>, String> {
    use std::io::{Read, Seek};
    let mut found = Vec::new();
    for path in map_paths(image) {
        match restore::open_held(&path) {
            // One limit for every reader, so two maps compared are compared whole.
            Ok(file) if file.metadata().map_or(true, |m| m.len() > MAP_MAX) => {
                return Err(format!(
                    "{} is too large to be its rescue map, or its size could not be read",
                    path.display()
                ))
            }
            Ok(file) => found.push((path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "its map {} could not be opened ({e})",
                    path.display()
                ))
            }
        }
    }
    let read = |(path, file): &mut (PathBuf, File)| {
        let mut bytes = Vec::new();
        let done = (&*file)
            .take(MAP_MAX + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| file.rewind());
        done.map(|_| bytes)
            .map_err(|e| format!("its map {} could not be read ({e})", path.display()))
    };
    let mut rest = found.split_off(found.len().min(1));
    let Some(mut first) = found.pop() else {
        return Ok(None);
    };
    if !rest.is_empty() {
        let text = read(&mut first)?;
        for other in &mut rest {
            if read(other)? != text {
                return Err(format!(
                    "two different maps lie beside it, {} and {}; move away the one that is not this image's",
                    first.0.display(),
                    other.0.display()
                ));
            }
        }
    }
    Ok(Some(first))
}

/// The bytes of the map beside `image` (`locate_map`), None when there is none; Err when one
/// is there and cannot be read.
fn read_map(image: &Path) -> Result<Option<(PathBuf, Vec<u8>)>, String> {
    use std::io::Read;
    let Some((path, file)) = locate_map(image)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAP_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("its map {} could not be read ({e})", path.display()))?;
    Ok(Some((path, bytes)))
}

/// What was read for a map, as a map's text or why it is not one.
fn as_map_text(read: Option<(PathBuf, Vec<u8>)>) -> MapBeside {
    let Some((path, bytes)) = read else {
        return Err("no rescue map was found beside it".into());
    };
    if bytes.len() as u64 > MAP_MAX {
        return Err(format!(
            "{} is too large to be its rescue map",
            path.display()
        ));
    }
    match String::from_utf8(bytes) {
        Ok(text) => Ok((path, text)),
        Err(_) => Err(format!("{} is not a rescue map", path.display())),
    }
}

/// Reads the map beside `image` (`locate_map`).
pub fn read_map_beside(image: &Path) -> MapBeside {
    as_map_text(read_map(image)?)
}

impl ImageFile {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        // A fixed VHD, or an image still carrying the footer it had while attached, is
        // read without the footer.
        let len = vdisk::data_len(&file)?;
        let store = Box::new(RawFile { file, len });
        // A map that is there and cannot be read is said, never taken for no map.
        let read = read_map(path)
            .map_err(|why| std::io::Error::other(format!("{}: {why}", path.display())))?;
        Ok(Self::over(path, store, as_map_text(read)))
    }

    /// The image `path` whose bytes `store` holds, read under the map `beside` when it fits:
    /// one the size of the image, one a fixed VHD's footer shorter, or one longer than an
    /// image GNU ddrescue left short of an unrescued end. Any other is set aside, and the
    /// image is read as it is, with a note that its unread areas are unknown.
    pub fn over(path: &Path, mut store: Box<dyn BlockSource>, beside: MapBeside) -> Self {
        let have = store.len();
        let unknown = |why: String| {
            format!(
                "{why}, so the parts never read from the drive are unknown: a file lying over one of them may be listed as whole with zeros in it"
            )
        };
        let made_from = beside
            .as_ref()
            .ok()
            .and_then(|(_, text)| image::map_identity(text));
        let parsed = beside.and_then(|(map_path, text)| {
            image::Map::parse(&text)
                .map(|map| (map_path.clone(), map))
                .map_err(|why| format!("its map {} is not understood ({why})", map_path.display()))
        });
        let (map, len, note) = match parsed {
            Err(why) => (None, have, unknown(why)),
            Ok((map_path, map)) => {
                let want = map.len();
                let rescued_to = map
                    .blocks
                    .iter()
                    .filter(|b| b.status == image::Status::Rescued)
                    .map(image::Block::end)
                    .max()
                    .unwrap_or(0);
                let footer = have == want + VHD_FOOTER && {
                    let mut tail = vec![0u8; VHD_FOOTER as usize];
                    store.read_at(want, &mut tail).is_ok() && tail.starts_with(b"conectix")
                };
                let fits =
                    want > 0 && (have == want || footer || (have < want && rescued_to <= have));
                if fits {
                    let unread = want - map.count(image::Status::Rescued);
                    let note = if unread == 0 {
                        format!("its map {} shows every part read", map_path.display())
                    } else {
                        format!(
                            "its map {} shows {} never read from the drive; files over those parts are marked damaged",
                            map_path.display(),
                            crate::tools::drives::bytes_text(unread)
                        )
                    };
                    (Some(map), want, note)
                } else {
                    let why = format!(
                        "its map {} is for a drive of {want} bytes and the image holds {have} bytes",
                        map_path.display()
                    );
                    (None, have, unknown(why))
                }
            }
        };
        let mut image = Self {
            path: path.to_path_buf(),
            store,
            len,
            map,
            made_from,
            table: None,
            samples: Vec::new(),
            note,
        };
        // Through `read_at`, so bytes the map does not mark rescued are never taken for a table.
        let mut head = vec![0u8; 8192];
        if let Some(made_from) = image.made_from.clone() {
            if image.len >= head.len() as u64 && image.read_at(0, &mut head).is_ok() {
                image.table = restore::image_table(&head, &made_from);
            }
            if made_from.scope == Some(Scope::Disk) {
                image.samples = image.samples();
            }
        }
        image
    }

    /// Up to `SAMPLES` places spread over the drive, the first sector first, where the map
    /// marks 4096 bytes rescued and their first 512 are not all one byte (a blank disk holds
    /// those too): what a disk in doubt is compared with (`dest::Sample`).
    fn samples(&mut self) -> Vec<dest::Sample> {
        const SAMPLES: usize = 8;
        const SPREAD: u64 = 16;
        let mut found = Vec::new();
        let mut buf = vec![0u8; 4096];
        for i in 0..SPREAD {
            let pos = (self.len / SPREAD * i) / 4096 * 4096;
            if pos + 4096 > self.len || self.read_at(pos, &mut buf).is_err() {
                continue;
            }
            let bytes = &buf[..512];
            if bytes.iter().any(|b| *b != bytes[0]) {
                found.push(dest::Sample {
                    pos,
                    bytes: bytes.to_vec(),
                });
            }
            if found.len() == SAMPLES {
                break;
            }
        }
        found
    }

    /// Whether the map in use marks every byte of `offset..end` rescued; true without one.
    /// Bytes past the map's end (a VHD footer) are not the drive's and are not judged.
    fn rescued(&self, offset: u64, end: u64) -> bool {
        let Some(map) = &self.map else {
            return true;
        };
        let end = end.min(map.len());
        let first = map.blocks.partition_point(|b| b.end() <= offset);
        map.blocks[first..]
            .iter()
            .take_while(|b| b.pos < end)
            .all(|b| b.status == image::Status::Rescued)
    }

    /// The map in use, if one fits.
    pub fn map(&self) -> Option<&image::Map> {
        self.map.as_ref()
    }
}

impl BlockSource for ImageFile {
    fn rescue_map(&self) -> Option<&image::Map> {
        self.map.as_ref()
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let end = offset.saturating_add(buf.len() as u64);
        // Past the drive's size is a VHD footer or nothing: never the drive's data.
        if end > self.len {
            return Err(ReadError::Bad(38)); // ERROR_HANDLE_EOF
        }
        if !self.rescued(offset, end) {
            return Err(ReadError::Bad(UNREAD_IN_IMAGE));
        }
        self.store.read_at(offset, buf)
    }

    fn describe(&self) -> String {
        format!("{} ({})", self.path.display(), self.note)
    }

    fn protected(&self) -> dest::Protected {
        dest::Protected {
            drives: self
                .made_from
                .iter()
                .map(|id| dest::Guarded {
                    samples: self.samples.clone(),
                    ..dest::Guarded::new(id.clone(), self.table.clone())
                })
                .collect(),
            ..dest::Protected::default()
        }
    }

    fn sector_exact(&self) -> bool {
        true
    }
}

/// An in-memory disk with chosen bad and slow areas, for tests of every recovery tool.
pub struct MemDisk {
    pub data: Vec<u8>,
    pub sector: u32,
    /// Byte ranges whose reads fail.
    pub bad: Vec<std::ops::Range<u64>>,
    /// Byte ranges whose reads time out.
    pub slow: Vec<std::ops::Range<u64>>,
    /// Byte ranges that read only from their far side: a read there fails unless the read
    /// before it began at a higher offset, as some damaged drives behave.
    pub far_side: Vec<std::ops::Range<u64>>,
    /// Every read asked for, as (offset, length), to check how a tool treats the drive.
    pub reads: Vec<(u64, usize)>,
    /// After this many reads every read fails as Gone, like a drive that drops off the bus.
    pub dies_after: Option<usize>,
    /// The serial number it reports, so tests can tell two alike drives apart.
    pub serial: String,
    /// The model it reports.
    pub model: String,
    /// The drive's own identity, as an ATA drive gives it.
    pub drive: Option<crate::tools::drives::ata::DriveId>,
    /// The part of the drive it stands for.
    pub scope: Scope,
    /// The whole drive's size; the data's length unless a test sets it.
    pub disk_size: u64,
    /// After this many reads the drive stops answering while Windows keeps its device, as a
    /// USB drive does after the adapter resets it: every read fails with `stall_error`
    /// (classified as a physical disk classifies it), or times out when that is None, and the
    /// presence probe fails.
    pub stalls_after: Option<usize>,
    pub stall_error: Option<u32>,
    /// Presence probes asked of it.
    pub probes: usize,
}

impl MemDisk {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            disk_size: data.len() as u64,
            data,
            sector: 512,
            bad: Vec::new(),
            slow: Vec::new(),
            far_side: Vec::new(),
            reads: Vec::new(),
            dies_after: None,
            serial: "TEST-0001".into(),
            model: "Test disk".into(),
            drive: None,
            scope: Scope::Disk,
            stalls_after: None,
            stall_error: Some(1117),
            probes: 0,
        }
    }

    /// A drive of the same data, bad areas and identity, as it comes back after a replug.
    pub fn again(&self) -> Self {
        Self {
            data: self.data.clone(),
            bad: self.bad.clone(),
            slow: self.slow.clone(),
            far_side: self.far_side.clone(),
            serial: self.serial.clone(),
            model: self.model.clone(),
            drive: self.drive.clone(),
            scope: self.scope,
            disk_size: self.disk_size,
            sector: self.sector,
            ..Self::new(Vec::new())
        }
    }

    fn stalled(&self) -> bool {
        self.stalls_after.is_some_and(|n| self.reads.len() > n)
    }

    fn overlaps(ranges: &[std::ops::Range<u64>], start: u64, end: u64) -> bool {
        ranges.iter().any(|r| r.start < end && start < r.end)
    }
}

impl BlockSource for MemDisk {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn sector_size(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let backwards = self.reads.last().is_some_and(|(last, _)| *last > offset);
        self.reads.push((offset, buf.len()));
        if self.dies_after.is_some_and(|n| self.reads.len() > n) {
            return Err(ReadError::Gone(1167)); // ERROR_DEVICE_NOT_CONNECTED
        }
        if self.stalled() {
            // Windows still holds the device; the drive answers nothing.
            return Err(match self.stall_error {
                Some(code) => disk::classify(code, || {
                    self.probes += 1;
                    disk::shown_answering(|| true, || false)
                }),
                None => ReadError::TimedOut,
            });
        }
        let end = offset + buf.len() as u64;
        assert!(
            offset.is_multiple_of(u64::from(self.sector))
                && end.is_multiple_of(u64::from(self.sector)),
            "unaligned read at {offset} for {}",
            buf.len()
        );
        if end > self.len() {
            return Err(ReadError::Bad(38));
        }
        if Self::overlaps(&self.slow, offset, end) {
            return Err(ReadError::TimedOut);
        }
        if Self::overlaps(&self.bad, offset, end)
            || (!backwards && Self::overlaps(&self.far_side, offset, end))
        {
            return Err(ReadError::Bad(23)); // ERROR_CRC
        }
        buf.copy_from_slice(&self.data[offset as usize..end as usize]);
        Ok(())
    }

    fn describe(&self) -> String {
        format!("test disk of {} bytes", self.data.len())
    }

    fn identity(&self) -> Option<SourceId> {
        Some(SourceId {
            model: self.model.clone(),
            serial: self.serial.clone(),
            size: self.len(),
            drive: self.drive.clone(),
            sector: Some(self.sector),
            scope: Some(self.scope),
            disk_size: Some(self.disk_size),
        })
    }

    fn answering(&mut self) -> bool {
        self.probes += 1;
        !self.stalled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_disk_fails_where_it_is_told_to() {
        let mut disk = MemDisk::new((0..4096u32).map(|i| i as u8).collect());
        disk.bad.push(1024..1536);
        disk.slow.push(3072..3584);
        let mut buf = vec![0u8; 512];
        assert!(disk.read_at(0, &mut buf).is_ok());
        assert_eq!(buf[1], 1);
        assert_eq!(disk.read_at(1024, &mut buf), Err(ReadError::Bad(23)));
        assert_eq!(disk.read_at(3072, &mut buf), Err(ReadError::TimedOut));
        disk.dies_after = Some(3);
        assert!(matches!(disk.read_at(0, &mut buf), Err(ReadError::Gone(_))));
    }

    #[test]
    fn a_destination_on_the_source_disk_is_refused() {
        let temp = std::env::temp_dir();
        let disks = crate::tools::drives::device::disks_of_path(&temp).unwrap();
        assert!(!disks.is_empty());
        let err = check_destination(&temp, &dest::Protected::disk(disks[0])).unwrap_err();
        assert!(err.contains("the disk being recovered"), "{err}");
        assert!(check_destination(&temp, &dest::Protected::disk(9999)).is_ok());
        assert!(check_destination(&temp, &dest::Protected::default()).is_ok());
        // A drive letter Windows has no drive for now (another test may hold Q:).
        // SAFETY: takes no arguments and reads the current drive letters.
        let taken = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
        let free = (b'K'..=b'Z')
            .find(|l| taken & (1 << (l - b'A')) == 0)
            .unwrap();
        let missing = format!(r"{}:\no\such\drive", char::from(free));
        assert!(check_destination(Path::new(&missing), &dest::Protected::disk(9999)).is_err());
    }

    /// Every recovery source file without its tests, by name.
    fn recovery_code() -> Vec<(&'static str, &'static str)> {
        let files = [
            ("mod.rs", include_str!("mod.rs")),
            ("carve.rs", include_str!("carve.rs")),
            ("condition.rs", include_str!("condition.rs")),
            ("copy.rs", include_str!("copy.rs")),
            ("dest.rs", include_str!("dest.rs")),
            ("disk.rs", include_str!("disk.rs")),
            ("image.rs", include_str!("image.rs")),
            ("output.rs", include_str!("output.rs")),
            ("photos.rs", include_str!("photos.rs")),
            ("read_limit.rs", include_str!("read_limit.rs")),
            ("fill.rs", include_str!("fill.rs")),
            ("health_log.rs", include_str!("health_log.rs")),
            ("ledger.rs", include_str!("ledger.rs")),
            ("verify.rs", include_str!("verify.rs")),
            ("verify/media.rs", include_str!("verify/media.rs")),
            ("verify/pdf.rs", include_str!("verify/pdf.rs")),
            ("verify/zip.rs", include_str!("verify/zip.rs")),
            ("keylookup.rs", include_str!("keylookup.rs")),
            (
                "keylookup/webview2.rs",
                include_str!("keylookup/webview2.rs"),
            ),
            ("gui/verify_view.rs", include_str!("../gui/verify_view.rs")),
            (
                "gui/keylookup_view.rs",
                include_str!("../gui/keylookup_view.rs"),
            ),
            ("preview.rs", include_str!("preview.rs")),
            ("thumbcache.rs", include_str!("thumbcache.rs")),
            ("reader.rs", include_str!("reader.rs")),
            ("restore.rs", include_str!("restore.rs")),
            ("target.rs", include_str!("target.rs")),
            ("timed.rs", include_str!("timed.rs")),
            ("wait.rs", include_str!("wait.rs")),
            ("events.rs", include_str!("events.rs")),
            ("fs/mod.rs", include_str!("fs/mod.rs")),
            ("fs/exfat.rs", include_str!("fs/exfat.rs")),
            ("fs/fat.rs", include_str!("fs/fat.rs")),
            ("fs/ntfs.rs", include_str!("fs/ntfs.rs")),
            ("fs/parts.rs", include_str!("fs/parts.rs")),
            ("migrate/mod.rs", include_str!("migrate/mod.rs")),
            ("migrate/hive.rs", include_str!("migrate/hive.rs")),
            ("migrate/tree.rs", include_str!("migrate/tree.rs")),
            (
                "gui/migrate_view.rs",
                include_str!("../gui/migrate_view.rs"),
            ),
            ("vdisk.rs", include_str!("vdisk.rs")),
            ("bitlocker.rs", include_str!("bitlocker.rs")),
            ("repair.rs", include_str!("repair.rs")),
            ("gui/vdisk_view.rs", include_str!("../gui/vdisk_view.rs")),
            (
                "gui/bitlocker_view.rs",
                include_str!("../gui/bitlocker_view.rs"),
            ),
            (
                "gui/recovery_view.rs",
                include_str!("../gui/recovery_view.rs"),
            ),
            (
                "gui/rescue_image_view.rs",
                include_str!("../gui/rescue_image_view.rs"),
            ),
            (
                "gui/rescue_copy_view.rs",
                include_str!("../gui/rescue_copy_view.rs"),
            ),
            (
                "gui/recover_files.rs",
                include_str!("../gui/recover_files.rs"),
            ),
            (
                "gui/restore_view.rs",
                include_str!("../gui/restore_view.rs"),
            ),
        ];
        files
            .into_iter()
            .map(|(name, all)| (name, all.split("#[cfg(test)]").next().unwrap()))
            .collect()
    }

    /// The guard: the recovery tools open the source only through `disk::open_read` and
    /// the descriptor query, never ask for a write right, and describe a disk without the
    /// drive window's health read; health is read by the timed reader alone, through the
    /// device module's ATA reader.
    #[test]
    fn the_recovery_tools_reach_the_source_only_read_only_and_timed() {
        for (name, code) in recovery_code() {
            // dest.rs opens output only, each handle checked to be off the source disk; a
            // writable disk or volume handle is `crate::handles`' alone (its guard).
            assert!(
                name == "dest.rs" || !code.contains("GENERIC_WRITE"),
                "{name} names a write right"
            );
            if name != "disk.rs" {
                assert!(
                    !code.contains("CreateFileW"),
                    "{name} opens a handle itself"
                );
            }
            // Output is made only through dest.rs, relative to a checked folder handle.
            assert!(
                name == "dest.rs" || !code.contains("NtCreateFile"),
                "{name} creates a file itself"
            );
            // A source is opened, and health read, only by the timed reader, with a limit
            // and off the window's thread.
            assert!(
                matches!(name, "mod.rs" | "timed.rs") || !code.contains("open_source("),
                "{name} opens a source without a time limit"
            );
            assert!(
                name == "timed.rs" || !code.contains("read_disk("),
                "{name} reads the disk's health"
            );
        }
        let disk = include_str!("disk.rs");
        let describe = &disk[disk.find("fn describe_disk(").unwrap()..];
        let describe = &describe[..describe.find("\n}\n").unwrap()];
        assert!(
            !describe.contains("device::"),
            "describing a disk reads the drive"
        );
    }

    /// The guard: the copy's write handle is opened once, at the attach, through
    /// `handles::CopyDisk::open`, which refuses the source disk and the system disk before
    /// it opens anything and checks through the handle that it is the copy this repair made
    /// before returning it (`crate::handles`' tests). repair.rs names no write right itself.
    #[test]
    fn the_only_writable_disk_handle_is_the_repaired_copys() {
        let code = include_str!("repair.rs");
        let code = code.split("#[cfg(test)]").next().unwrap();
        assert!(
            !code.contains("GENERIC_WRITE"),
            "repair.rs names a write right"
        );
        assert_eq!(
            code.matches("CopyDisk::open(").count(),
            1,
            "opened somewhere besides the attach"
        );
        let handles = include_str!("../handles.rs");
        let handles = handles.split("#[cfg(test)]").next().unwrap();
        let body = &handles[handles
            .find("    pub fn open(\n        number: u32,\n        source: &crate::recovery::dest::Protected,")
            .unwrap()..];
        let body = &body[..body.find("\n    }\n").unwrap()];
        let write = body.find("Access::ReadWrite").unwrap();
        for check in ["refuses_disk(number)", "system.contains(&number)"] {
            let at = body
                .find(check)
                .unwrap_or_else(|| panic!("no check {check}"));
            assert!(at < write, "{check} comes after the open");
        }
        assert!(
            body.ends_with("copy.check()?;\n        Ok(copy)"),
            "the handle is not checked to be the copy before it is returned"
        );
    }

    /// The guard (unknown is never taken as fine, DESIGN.md): a window whose worker ends
    /// without sending its result says so, never shows the run as going on; an image's
    /// footer or detach that fails is said or recorded, never dropped; a volume whose first
    /// sector cannot be read is not taken for one without BitLocker; and the search by type
    /// says the limits it reached.
    #[test]
    fn failures_in_the_windows_and_the_image_attach_are_said() {
        for (name, code) in [
            (
                "rescue_image_view.rs",
                include_str!("../gui/rescue_image_view.rs"),
            ),
            ("restore_view.rs", include_str!("../gui/restore_view.rs")),
            (
                "rescue_copy_view.rs",
                include_str!("../gui/rescue_copy_view.rs"),
            ),
            ("verify_view.rs", include_str!("../gui/verify_view.rs")),
            (
                "crashdump_view.rs",
                include_str!("../gui/crashdump_view.rs"),
            ),
            ("migrate_view.rs", include_str!("../gui/migrate_view.rs")),
        ] {
            let code = code.split("#[cfg(test)]").next().unwrap();
            for waits in [".result.try_recv()", ".messages.try_recv()"] {
                assert!(
                    !code.contains(waits),
                    "{name} polls a result with {waits}, which drops a worker that ended"
                );
            }
        }
        let vdisk = include_str!("vdisk.rs");
        let vdisk = vdisk.split("#[cfg(test)]").next().unwrap();
        for dropped in [
            "let _ = self.take_off()",
            "let _ = self.finish()",
            "let _ = self.footed.take_off()",
            "let _ = file.set_len(",
        ] {
            assert!(!vdisk.contains(dropped), "vdisk.rs drops {dropped}");
        }
        let view = include_str!("../gui/vdisk_view.rs");
        assert!(
            !view.contains("bitlocker_offsets("),
            "the copy's BitLocker volumes are looked for without saying the unread ones"
        );
        let files = include_str!("../gui/recover_files.rs");
        assert!(files.contains("Done::Carved(carving.notes())"));
    }

    /// The guard: the recovery window, its pages and both rescue views give sizes in the
    /// decimal units the rest of the app uses for drives, never in binary units.
    #[test]
    fn recovery_sizes_are_in_decimal_units() {
        for (name, code) in recovery_code() {
            assert!(
                !code.contains("format_size"),
                "{name} gives a size in binary units"
            );
        }
    }

    /// The recovery report writes its table through the ledger's row writer, and the rescue
    /// copy's ledger is its log, which gets each row as a file ends; that ledger's memory is
    /// measured in tests/ledger_rows.rs.
    #[test]
    fn report_and_log_rows_come_from_the_ledger() {
        for (name, code) in recovery_code() {
            match name {
                "output.rs" => {
                    assert!(code.contains(".write_rows("), "{name} builds its own table")
                }
                "copy.rs" => assert!(
                    code.contains("Ledger::to_log("),
                    "{name} keeps its own table"
                ),
                _ => {}
            }
        }
    }

    /// A map text in GNU ddrescue's format, from (position, size, status) blocks.
    fn map_text(blocks: &[(u64, u64, char)]) -> String {
        let mut text = String::from("# test map\n0x00000000     +               1\n");
        for (pos, size, status) in blocks {
            text.push_str(&format!("0x{pos:08X}  0x{size:08X}  {status}\n"));
        }
        text
    }

    fn mapped(data: Vec<u8>, map: MapBeside) -> ImageFile {
        ImageFile::over(
            Path::new("D:\\rescue\\x.img"),
            Box::new(MemDisk::new(data)),
            map,
        )
    }

    #[test]
    fn an_image_reads_as_failed_wherever_its_map_is_not_rescued() {
        let text = map_text(&[
            (0, 4096, '+'),
            (4096, 1024, '-'),
            (5120, 512, '?'),
            (5632, 2560, '+'),
        ]);
        let mut image = mapped(vec![7; 8192], Ok((PathBuf::from("x.map"), text)));
        assert_eq!(image.len(), 8192);
        assert!(image.sector_exact());
        assert!(
            image.describe().contains("1.5 kB never read"),
            "{}",
            image.describe()
        );
        let mut buf = vec![0u8; 512];
        assert!(image.read_at(3584, &mut buf).is_ok());
        assert_eq!(
            image.read_at(4096, &mut buf),
            Err(ReadError::Bad(UNREAD_IN_IMAGE))
        );
        assert_eq!(
            image.read_at(5120, &mut buf),
            Err(ReadError::Bad(UNREAD_IN_IMAGE))
        );
        assert!(image.read_at(5632, &mut buf).is_ok());
        let mut big = vec![0u8; 8192];
        assert!(image.read_at(0, &mut big).is_err());
        // Through the reader each unread sector is zeros and reported, and nothing else.
        let mut reader = reader::Reader::new(Box::new(image));
        let lossy = reader.read_lossy(0, 8192);
        assert_eq!(lossy.unreadable, vec![4096..5632]);
        assert!(lossy.data[..4096].iter().all(|b| *b == 7));
        assert!(lossy.data[5632..].iter().all(|b| *b == 7));
    }

    #[test]
    fn a_vhd_footer_or_a_short_ddrescue_image_keeps_its_map() {
        let text = map_text(&[(0, 4096, '+'), (4096, 4096, '-')]);
        let mut vhd = vec![1u8; 8192];
        let mut footer = vec![0u8; 512];
        footer[..8].copy_from_slice(b"conectix");
        vhd.extend(&footer);
        let mut image = mapped(vhd, Ok((PathBuf::from("x.map"), text.clone())));
        assert!(image.map().is_some());
        assert_eq!(image.len(), 8192, "the footer is not the drive's");
        let mut buf = vec![0u8; 512];
        assert!(image.read_at(4096, &mut buf).is_err());
        // GNU ddrescue leaves an image short when its end was never rescued.
        let mut short = mapped(vec![1u8; 4096], Ok((PathBuf::from("x.map"), text.clone())));
        assert!(short.map().is_some());
        assert_eq!(short.len(), 8192);
        assert_eq!(
            short.read_at(6144, &mut buf),
            Err(ReadError::Bad(UNREAD_IN_IMAGE))
        );
        // 512 more bytes that are not a VHD footer, or a map of another size, are set aside.
        for data in [vec![1u8; 8704], vec![1u8; 16384], vec![1u8; 2048]] {
            let image = mapped(data, Ok((PathBuf::from("x.map"), text.clone())));
            assert!(image.map().is_none());
            assert!(
                image.describe().contains("is for a drive of 8192 bytes"),
                "{}",
                image.describe()
            );
            assert!(image.describe().contains("unknown"));
        }
    }

    #[test]
    fn an_image_without_a_usable_map_says_its_unread_areas_are_unknown() {
        for beside in [
            Err("no rescue map was found beside it".to_string()),
            Ok((PathBuf::from("x.map"), "not a map at all".to_string())),
            Ok((PathBuf::from("x.map"), String::new())),
        ] {
            let mut image = mapped(vec![3u8; 4096], beside);
            assert!(image.map().is_none());
            assert_eq!(image.len(), 4096);
            assert!(
                image.describe().contains("are unknown"),
                "{}",
                image.describe()
            );
            let mut buf = vec![0u8; 4096];
            assert!(image.read_at(0, &mut buf).is_ok());
        }
    }

    /// A drive source with a number and an identity, as a disk reads.
    struct Numbered(u32, SourceId);

    impl BlockSource for Numbered {
        fn len(&self) -> u64 {
            4096
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), ReadError> {
            Ok(())
        }
        fn describe(&self) -> String {
            String::new()
        }
        fn disk_number(&self) -> Option<u32> {
            Some(self.0)
        }
        fn identity(&self) -> Option<SourceId> {
            Some(self.1.clone())
        }
    }

    /// The guard (round 12): a drive source is guarded by its identity as well as its
    /// number, so output is refused on it when it comes back from a replug under another
    /// number. A disk source was guarded by its number alone.
    /// The guard: an image protects the drive it was made from with that drive's partition
    /// table, read from the image's first sectors only where the map marks them rescued.
    #[test]
    fn an_image_carries_its_drive_s_partition_table() {
        let mut data = vec![0u8; 16384];
        data[440..444].copy_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        data[446 + 4] = 0x07;
        data[510] = 0x55;
        data[511] = 0xAA;
        let id = SourceId {
            model: "Samsung SSD 870".into(),
            serial: String::new(),
            size: 16384,
            drive: None,
            sector: Some(512),
            scope: Some(Scope::Disk),
            disk_size: Some(16384),
        };
        let named = |blocks: &[(u64, u64, char)]| {
            let lines: String = image::identity_lines(&id)
                .iter()
                .map(|l| format!("# {l}\n"))
                .collect();
            Ok((PathBuf::from("x.map"), lines + &map_text(blocks)))
        };
        let read = mapped(data.clone(), named(&[(0, 16384, '+')]));
        let drives = read.protected().drives;
        assert_eq!(drives.len(), 1);
        assert_eq!(drives[0].table.as_deref(), Some("1A2B3C4D"));
        // Its table never read: nothing is taken from the image's bytes there.
        let unread = mapped(data, named(&[(0, 512, '-'), (512, 15872, '+')]));
        assert_eq!(unread.protected().drives[0].table, None);
    }

    /// The guard: an image samples its drive's bytes only where the map marks them rescued
    /// and they are not blank, and only for an image of a whole drive.
    #[test]
    fn an_image_samples_its_drive_only_where_rescued() {
        let len = 16 * 4096u64;
        let mut data = vec![0u8; len as usize];
        for i in [0u64, 3, 5, 9] {
            let at = (i * 4096) as usize;
            for (k, b) in data[at..at + 512].iter_mut().enumerate() {
                *b = (k as u8).wrapping_mul(7).wrapping_add(i as u8);
            }
        }
        let mut id = SourceId {
            model: "Samsung SSD 870".into(),
            serial: String::new(),
            size: len,
            drive: None,
            sector: Some(512),
            scope: Some(Scope::Disk),
            disk_size: Some(len),
        };
        let named = |id: &SourceId, blocks: &[(u64, u64, char)]| {
            let lines: String = image::identity_lines(id)
                .iter()
                .map(|l| format!("# {l}\n"))
                .collect();
            Ok((PathBuf::from("x.map"), lines + &map_text(blocks)))
        };
        // Block 5 never read; blocks 1, 2, 4 and the rest are blank.
        let blocks = [
            (0, 5 * 4096, '+'),
            (5 * 4096, 4096, '-'),
            (6 * 4096, 10 * 4096, '+'),
        ];
        let image = mapped(data.clone(), named(&id, &blocks));
        let drives = image.protected().drives;
        let places: Vec<u64> = drives[0].samples.iter().map(|s| s.pos).collect();
        assert_eq!(places, [0, 3 * 4096, 9 * 4096]);
        assert_eq!(drives[0].samples[1].bytes, data[3 * 4096..3 * 4096 + 512]);
        id.scope = Some(Scope::Volume { offset: 1 << 20 });
        let volume = mapped(data, named(&id, &blocks));
        assert!(volume.protected().drives[0].samples.is_empty());
    }

    /// A sector of bytes that no blank disk holds, as a test disk's first 4096 bytes.
    fn patterned() -> Vec<u8> {
        (0..4096u32)
            .map(|k| (k.wrapping_mul(31) % 251) as u8)
            .collect()
    }

    /// The guard: a disk in doubt is read where the image holds its drive's data: the same
    /// bytes refuse it outright, other bytes clear it, no samples or no read leave the doubt.
    #[test]
    fn a_disk_in_doubt_is_told_apart_by_its_bytes() {
        let dir = std::env::temp_dir();
        let on = crate::tools::drives::device::disks_of_path(&dir).unwrap()[0];
        let disk = target::list_disks()
            .unwrap()
            .into_iter()
            .find(|d| d.number == on)
            .expect("the temporary folder's disk");
        dest::OPEN_RAW.with(|o| {
            o.set(Some(|_| {
                let mut data = patterned();
                data.resize(1 << 20, 0);
                Some(Box::new(MemDisk::new(data)) as Box<dyn BlockSource>)
            }))
        });
        let look_alike = SourceId {
            model: disk.model.clone(),
            serial: String::new(),
            size: disk.size,
            drive: None,
            sector: Some(disk.sector),
            scope: Some(Scope::Disk),
            disk_size: Some(disk.size),
        };
        let with = |bytes: Vec<u8>| dest::Protected {
            drives: vec![dest::Guarded {
                samples: vec![dest::Sample { pos: 0, bytes }],
                ..dest::Guarded::new(look_alike.clone(), None)
            }],
            ..dest::Protected::default()
        };
        let same = dest::Guard::of(&with(patterned()[..512].to_vec()))
            .refuses_disk(on)
            .expect("the same bytes");
        assert!(
            same.firm && same.reason.contains(dest::SAME_DATA),
            "{same:?}"
        );
        let mut other = patterned()[..512].to_vec();
        other[100] ^= 0xFF;
        assert_eq!(dest::Guard::of(&with(other)).refuses_disk(on), None);
        let without = dest::Protected {
            drives: vec![dest::Guarded::new(look_alike.clone(), None)],
            ..dest::Protected::default()
        };
        assert!(dest::Guard::of(&without)
            .refuses_disk(on)
            .is_some_and(|r| !r.firm));
        // A disk that cannot be opened raw (no administrator rights), or not read where the
        // sample is, stays a doubt.
        dest::OPEN_RAW.with(|o| o.set(Some(|_| None)));
        let mut unread = patterned()[..512].to_vec();
        unread[7] ^= 0x55;
        assert!(dest::Guard::of(&with(unread.clone()))
            .refuses_disk(on)
            .is_some_and(|r| !r.firm));
        dest::OPEN_RAW.with(|o| {
            o.set(Some(|_| {
                let mut disk = MemDisk::new(vec![0u8; 1 << 20]);
                disk.bad.push(0..4096);
                Some(Box::new(disk) as Box<dyn BlockSource>)
            }))
        });
        unread[8] ^= 0x55;
        assert!(dest::Guard::of(&with(unread))
            .refuses_disk(on)
            .is_some_and(|r| !r.firm));
        dest::OPEN_RAW.with(|o| o.set(None));
    }

    /// What the temporary folder's real disk holds at its first sector, compared as a disk in
    /// doubt is: the same bytes match, one byte changed does not.
    #[test]
    #[ignore = "reads a physical disk; needs administrator rights"]
    fn a_real_disk_is_compared_with_samples() {
        let dir = std::env::temp_dir();
        let on = crate::tools::drives::device::disks_of_path(&dir).unwrap()[0];
        let mut disk = crate::recovery::disk::PhysicalDisk::open(on).expect("administrator rights");
        let mut first = vec![0u8; 4096];
        disk.read_at(0, &mut first).unwrap();
        let mut sample = dest::Sample {
            pos: 0,
            bytes: first[..512].to_vec(),
        };
        assert_eq!(
            dest::compare_samples(&mut disk, &[sample.clone()]),
            Some(true)
        );
        sample.bytes[100] ^= 0xFF;
        assert_eq!(dest::compare_samples(&mut disk, &[sample]), Some(false));
    }

    /// The guard: a doubt about a disk is set aside once a person confirms it is not the
    /// drive being recovered; a disk that is that drive, by number or serial number, is
    /// refused whatever was confirmed.
    #[test]
    fn a_doubt_is_confirmed_and_the_source_is_refused_still() {
        let dir = std::env::temp_dir();
        let on = crate::tools::drives::device::disks_of_path(&dir).unwrap()[0];
        let disk = target::list_disks()
            .unwrap()
            .into_iter()
            .find(|d| d.number == on && !d.serial.trim().is_empty() && !d.disk_id.is_empty())
            .expect("the temporary folder's disk, with a serial number and a partition table");
        // An image of a drive of this one's model and size whose serial number is not known.
        let look_alike = SourceId {
            model: disk.model.clone(),
            serial: String::new(),
            size: disk.size,
            drive: None,
            sector: Some(disk.sector),
            scope: Some(Scope::Disk),
            disk_size: Some(disk.size),
        };
        let mut protected = dest::Protected {
            drives: vec![dest::Guarded::new(look_alike.clone(), None)],
            ..dest::Protected::default()
        };
        let doubt = dest::Guard::of(&protected)
            .refuses_disk(on)
            .expect("a doubt");
        assert!(!doubt.firm, "{doubt:?}");
        let refused = destination_refusal(&dir, &protected).unwrap_err();
        assert_eq!(refused.key, doubt.key);
        protected.granted.push(doubt.key.clone());
        assert_eq!(dest::Guard::of(&protected).refuses_disk(on), None);
        assert!(check_destination(&dir, &protected).is_ok());
        // Its own partition table differs from the image's: no doubt to confirm.
        let other = dest::Protected {
            drives: vec![dest::Guarded::new(
                look_alike.clone(),
                Some("{00000000-0000-4000-8000-0000000000FF}".into()),
            )],
            ..dest::Protected::default()
        };
        assert!(check_destination(&dir, &other).is_ok());
        // The same drive guarded again without its table (by a reader of it) takes the table
        // the other entry has.
        let lent = other.clone().join(dest::Protected {
            drives: vec![dest::Guarded::new(look_alike.clone(), None)],
            ..dest::Protected::default()
        });
        assert!(check_destination(&dir, &lent).is_ok());
        let same = dest::Protected {
            drives: vec![dest::Guarded::new(look_alike, Some(disk.disk_id.clone()))],
            ..dest::Protected::default()
        };
        assert!(check_destination(&dir, &same).is_err());
        // The drive being recovered, by its number or its serial number, is never confirmed.
        let mut by_number = dest::Protected::disk(on);
        by_number.granted = vec![doubt.key.clone(), format!("disk {on}")];
        let firm = dest::Guard::of(&by_number).refuses_disk(on).unwrap();
        assert!(firm.firm, "{firm:?}");
        assert!(destination_refusal(&dir, &by_number).unwrap_err().firm);
        let own = SourceId {
            model: disk.model.clone(),
            serial: disk.serial.clone(),
            size: disk.size,
            drive: disk.drive.clone(),
            sector: Some(disk.sector),
            scope: Some(Scope::Disk),
            disk_size: Some(disk.size),
        };
        let by_serial = dest::Protected {
            drives: vec![dest::Guarded::new(
                own,
                Some("{00000000-0000-4000-8000-0000000000FF}".into()),
            )],
            granted: vec![doubt.key],
            ..dest::Protected::default()
        };
        assert!(dest::Guard::of(&by_serial).refuses_disk(on).unwrap().firm);
    }

    #[test]
    fn a_drive_source_is_refused_under_a_new_number() {
        let dir = std::env::temp_dir();
        let on = crate::tools::drives::device::disks_of_path(&dir).unwrap()[0];
        let disk = target::list_disks()
            .unwrap()
            .into_iter()
            .find(|d| d.number == on && !d.serial.trim().is_empty())
            .expect("the temporary folder's disk, with a serial number");
        let id = SourceId {
            model: disk.model.clone(),
            serial: disk.serial.clone(),
            size: disk.size,
            drive: disk.drive.clone(),
            sector: Some(disk.sector),
            scope: Some(Scope::Disk),
            disk_size: Some(disk.size),
        };
        // Opened as disk 9999; it is now disk `on`.
        let protected = Numbered(9999, id.clone()).protected();
        assert_eq!(protected.disks, [9999]);
        assert_eq!(protected.drives, [dest::Guarded::new(id, None)]);
        let why = check_destination(&dir, &protected).unwrap_err();
        assert!(why.contains("made from") || why.contains("disk"), "{why}");
        // A source that is no drive guards nothing of its own.
        assert_eq!(
            MemDisk::new(vec![0; 512]).protected(),
            dest::Protected::default()
        );
        // Every writer that reads a source guards by that source's own protection, and a
        // repair by its own open of the image (round 12).
        let code = |text: &'static str| text.split("#[cfg(test)]").next().unwrap();
        for (name, text, join) in [
            (
                "output.rs",
                code(include_str!("output.rs")),
                ".join(reader.protected())",
            ),
            (
                "thumbcache.rs",
                code(include_str!("thumbcache.rs")),
                ".join(reader.protected())",
            ),
            (
                "repair.rs",
                code(include_str!("repair.rs")),
                "BlockSource::protected(&made)",
            ),
        ] {
            assert!(text.contains(join), "{name} does not guard by its source");
        }
    }

    /// The guard (review F1, F3): a map is passed over only where nothing is there; one that
    /// cannot be read is not swapped for the other name or for none, two that differ are
    /// refused, and Restore finds a map under either name, keeping its gaps and the drive
    /// it names. Restore looked only for "x.map", and every reader skipped a map on any open
    /// error.
    #[test]
    fn a_map_is_never_put_aside_unsaid() {
        let dir = std::env::temp_dir().join(format!("diagtool-locate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("disk.img");
        std::fs::write(&img, vec![5u8; 4096]).unwrap();
        let (short, long) = (dir.join("disk.map"), dir.join("disk.img.map"));
        let gap = "# Source model: Seagate Expansion\n# Source serial: NA88E0R0\n# Source size: 4096 bytes\n0x00000000     /               1\n0x00000000  0x00000800  +\n0x00000800  0x00000800  -\n";
        let found = |img: &Path| locate_map(img).map(|held| held.map(|(path, _)| path));
        assert_eq!(found(&img), Ok(None));
        std::fs::write(&long, gap).unwrap();
        assert_eq!(found(&img), Ok(Some(long.clone())));
        // The map is held while it is used: it cannot be renamed or replaced under the reader.
        let held = locate_map(&img).unwrap().unwrap();
        assert!(std::fs::rename(&long, dir.join("moved.map")).is_err());
        assert!(std::fs::write(&long, "replaced").is_err());
        drop(held);
        let (info, held) = restore::load_image(&img).unwrap();
        assert_eq!(info.map_path.as_deref(), Some(long.as_path()));
        assert_eq!(
            info.not_rescued(),
            std::iter::once(2048..4096).collect::<Vec<_>>()
        );
        assert_eq!(
            info.made_from.as_ref().map(|m| m.serial.as_str()),
            Some("NA88E0R0")
        );
        drop(held);
        std::fs::write(&short, gap).unwrap();
        assert_eq!(found(&img), Ok(Some(short.clone())), "the same map twice");
        std::fs::write(
            &short,
            "0x00000000     +               1\n0x00000000  0x00001000  +\n",
        )
        .unwrap();
        let two = locate_map(&img).unwrap_err();
        assert!(two.contains("two different maps"), "{two}");
        assert!(restore::load_image(&img).is_err());
        assert!(read_map_beside(&img).is_err());
        // A map past the size limit is refused under either name, so maps are compared whole.
        let big = std::fs::File::create(&short).unwrap();
        big.set_len(MAP_MAX + 1).unwrap();
        drop(big);
        let large = locate_map(&img).unwrap_err();
        assert!(large.contains("too large"), "{large}");
        assert!(restore::load_image(&img).is_err());
        // A map that cannot be read is said, not passed over for the other name.
        std::fs::remove_file(&short).unwrap();
        std::fs::create_dir(&short).unwrap();
        let unread = read_map_beside(&img).unwrap_err();
        assert!(unread.contains("disk.map"), "{unread}");
        assert!(restore::load_image(&img).is_err());
        let Err(refused) = ImageFile::open(&img) else {
            panic!("an image whose map is unread");
        };
        assert!(refused.to_string().contains("disk.map"), "{refused}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_map_beside_an_image_is_found_by_either_name() {
        assert_eq!(
            map_paths(Path::new("D:\\r\\disk.img")),
            vec![
                PathBuf::from("D:\\r\\disk.map"),
                PathBuf::from("D:\\r\\disk.img.map")
            ]
        );
        assert_eq!(
            map_paths(Path::new("D:\\r\\disk")),
            vec![PathBuf::from("D:\\r\\disk.map")]
        );
        // An image named like a map is never read as its own map, in any case.
        assert_eq!(
            map_paths(Path::new("D:\\r\\X.MAP")),
            vec![PathBuf::from("D:\\r\\X.MAP.map")]
        );
        let dir = std::env::temp_dir().join(format!("diagtool-mapbeside-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("disk.img");
        std::fs::write(&img, vec![5u8; 4096]).unwrap();
        assert!(ImageFile::open(&img).unwrap().map().is_none());
        std::fs::write(
            dir.join("disk.img.map"),
            map_text(&[(0, 2048, '+'), (2048, 2048, '*')]),
        )
        .unwrap();
        let mut image = ImageFile::open(&img).unwrap();
        assert!(image.map().is_some());
        let mut buf = vec![0u8; 512];
        assert!(image.read_at(2048, &mut buf).is_err());
        drop(image);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The two rules for the 512-byte VHD footer together: an image left with this tool's
    /// footer by an attach is read without it, and its ddrescue map still applies, so the
    /// areas the map leaves unread fail and the footer is never read as the drive's data.
    #[test]
    fn an_image_left_with_its_vhd_footer_is_read_under_its_map_without_the_footer() {
        let dir = std::env::temp_dir().join(format!("diagtool-footmap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("disk.img");
        let mut bytes = vec![9u8; 8192];
        bytes.extend(vdisk::footer_for(8192, 1, [7; 16]));
        std::fs::write(&img, &bytes).unwrap();
        let image = ImageFile::open(&img).unwrap();
        assert_eq!(
            image.len(),
            8192,
            "without a map the footer is not the drive's"
        );
        assert!(image.map().is_none());
        drop(image);
        std::fs::write(
            dir.join("disk.map"),
            map_text(&[(0, 4096, '+'), (4096, 4096, '-')]),
        )
        .unwrap();
        let mut image = ImageFile::open(&img).unwrap();
        assert_eq!(image.len(), 8192);
        assert!(image.map().is_some(), "{}", image.describe());
        let mut buf = vec![0u8; 512];
        assert!(image.read_at(3584, &mut buf).is_ok());
        assert_eq!(
            image.read_at(4096, &mut buf),
            Err(ReadError::Bad(UNREAD_IN_IMAGE))
        );
        assert!(image.read_at(8192, &mut buf).is_err(), "the footer is read");
        drop(image);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_image_file_reads_by_offset() {
        let path = std::env::temp_dir().join(format!("diagtool-image-{}.img", std::process::id()));
        std::fs::write(
            &path,
            (0..2048u32).map(|i| (i / 512) as u8).collect::<Vec<_>>(),
        )
        .unwrap();
        let mut image = ImageFile::open(&path).unwrap();
        let mut buf = vec![0u8; 512];
        image.read_at(1024, &mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 2));
        assert!(image.read_at(2048, &mut buf).is_err());
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}
