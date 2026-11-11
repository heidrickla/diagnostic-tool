//! The drive speed test: sequential and 4 KiB random reads and writes on one test file in a
//! folder the current user owns, opened without Windows' cache (unbuffered, write-through),
//! then a read-back check of everything written. The file is opened delete-on-close, so it
//! goes when the test ends, is stopped, fails or the process dies. Nothing else is written.
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_EXISTS, ERROR_IO_PENDING,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceW, ReadFile, WriteFile, CREATE_NEW, DELETE,
    FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OVERLAPPED,
    FILE_FLAG_WRITE_THROUGH,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
};

/// The test file's default size.
pub const DEFAULT_SIZE: u64 = 1 << 30;
/// Free space the test leaves on the volume beyond its file.
pub const MARGIN: u64 = 2 << 30;
/// Every transfer is a multiple of this and starts on it, which suits 512-byte and 4 KiB
/// sectors alike.
pub const SECTOR: usize = 4096;
pub const SEQ_BLOCK: usize = 1 << 20;
pub const SEQ_DEPTH: usize = 8;
pub const DEEP: usize = 32;
/// Distinct sector contents in the written pattern.
const PATTERN_SECTORS: usize = SEQ_BLOCK / SECTOR;
const FOLDER: &str = "DiagnosticTool-speed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepare,
    SeqRead,
    SeqWrite,
    RandRead,
    RandWrite,
    RandReadDeep,
    RandWriteDeep,
    Verify,
}

impl Phase {
    pub const ALL: [Phase; 8] = [
        Phase::Prepare,
        Phase::SeqRead,
        Phase::SeqWrite,
        Phase::RandRead,
        Phase::RandWrite,
        Phase::RandReadDeep,
        Phase::RandWriteDeep,
        Phase::Verify,
    ];
    /// The phases whose speed is reported.
    pub const MEASURED: [Phase; 6] = [
        Phase::SeqRead,
        Phase::SeqWrite,
        Phase::RandRead,
        Phase::RandWrite,
        Phase::RandReadDeep,
        Phase::RandWriteDeep,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Phase::Prepare => "Writing the test file",
            Phase::SeqRead => "Sequential read",
            Phase::SeqWrite => "Sequential write",
            Phase::RandRead => "Random read, 1 at a time",
            Phase::RandWrite => "Random write, 1 at a time",
            Phase::RandReadDeep => "Random read, 32 at a time",
            Phase::RandWriteDeep => "Random write, 32 at a time",
            Phase::Verify => "Checking what was written",
        }
    }

    /// How the phase reads or writes, for the results.
    pub fn how(self) -> &'static str {
        match self {
            Phase::SeqRead | Phase::SeqWrite | Phase::Prepare | Phase::Verify => {
                "1 MiB blocks, 8 in flight"
            }
            Phase::RandRead | Phase::RandWrite => "4 KiB blocks, queue depth 1",
            Phase::RandReadDeep | Phase::RandWriteDeep => "4 KiB blocks, queue depth 32",
        }
    }

    pub fn random(self) -> bool {
        matches!(
            self,
            Phase::RandRead | Phase::RandWrite | Phase::RandReadDeep | Phase::RandWriteDeep
        )
    }

    pub fn writes(self) -> bool {
        matches!(
            self,
            Phase::Prepare | Phase::SeqWrite | Phase::RandWrite | Phase::RandWriteDeep
        )
    }

    pub fn depth(self) -> usize {
        match self {
            Phase::RandRead | Phase::RandWrite => 1,
            Phase::RandReadDeep | Phase::RandWriteDeep => DEEP,
            _ => SEQ_DEPTH,
        }
    }

    pub fn block(self) -> usize {
        if self.random() {
            SECTOR
        } else {
            SEQ_BLOCK
        }
    }

    fn index(self) -> usize {
        Phase::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub size: u64,
    /// Length of each random phase.
    pub random_seconds: f64,
    /// Longest a sequential pass runs; a slow drive is measured on the part it finished.
    pub seq_seconds: f64,
    /// Longest the test file takes to write; the test then uses the part written.
    pub prepare_seconds: f64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            size: DEFAULT_SIZE,
            random_seconds: 4.0,
            seq_seconds: 20.0,
            prepare_seconds: 120.0,
        }
    }
}

/// One timed phase.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Measure {
    pub phase: Phase,
    pub bytes: u64,
    pub ops: u64,
    pub seconds: f64,
}

impl Measure {
    /// Megabytes (10^6 bytes) per second, as drive makers quote them.
    pub fn mb_per_s(&self) -> f64 {
        if self.seconds > 0.0 {
            self.bytes as f64 / self.seconds / 1e6
        } else {
            0.0
        }
    }

    pub fn iops(&self) -> f64 {
        if self.seconds > 0.0 {
            self.ops as f64 / self.seconds
        } else {
            0.0
        }
    }

    /// Average time for one transfer in microseconds: time times depth over transfers.
    pub fn latency_us(&self) -> f64 {
        if self.ops > 0 {
            self.seconds * 1e6 * self.phase.depth() as f64 / self.ops as f64
        } else {
            0.0
        }
    }
}

/// The read-back of everything written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Verify {
    pub bytes: u64,
    /// 4 KiB sectors that read back different from what was written.
    pub bad_sectors: u64,
}

/// What the window shows while the test runs.
#[derive(Default)]
pub struct Progress {
    /// Phase index plus one; 0 before the first phase.
    phase: AtomicUsize,
    permille: AtomicU32,
    measures: Mutex<Vec<Measure>>,
}

impl Progress {
    pub fn phase(&self) -> Option<Phase> {
        match self.phase.load(Ordering::Relaxed) {
            0 => None,
            n => Phase::ALL.get(n - 1).copied(),
        }
    }

    pub fn permille(&self) -> u32 {
        self.permille.load(Ordering::Relaxed)
    }

    pub fn measures(&self) -> Vec<Measure> {
        self.measures.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub folder: PathBuf,
    pub size: u64,
    /// The part of the file written and tested; below `size` only on a very slow drive.
    pub tested: u64,
    pub measures: Vec<Measure>,
    pub verify: Option<Verify>,
    pub stopped: bool,
    /// Why the test ended early.
    pub error: Option<String>,
    /// Whether the test file and its folder are gone.
    pub cleanup: Result<(), String>,
    pub elapsed: Duration,
}

/// The test size rounded down to whole 1 MiB blocks, at least one block.
pub fn file_size(size: u64) -> u64 {
    (size / SEQ_BLOCK as u64).max(1) * SEQ_BLOCK as u64
}

/// Refuses when the volume lacks room for the file plus the margin.
pub fn check_space(volume: char, free: u64, size: u64) -> Result<(), String> {
    let needed = file_size(size) + MARGIN;
    if free < needed {
        return Err(format!(
            "Drive {volume}: has {} free; the speed test needs {} (its {} test file and {} left over), so it did not start.",
            gib(free),
            gib(needed),
            gib(file_size(size)),
            gib(MARGIN)
        ));
    }
    Ok(())
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64)
}

/// The folder for the test file: under the user's temporary folder when it is on `volume`,
/// otherwise at the volume's root, where Windows lets users make folders they then own.
pub fn folder_for(volume: char) -> PathBuf {
    let temp = std::env::temp_dir();
    let on_volume = temp
        .to_string_lossy()
        .chars()
        .next()
        .is_some_and(|c| c.eq_ignore_ascii_case(&volume));
    if on_volume {
        temp.join(FOLDER)
    } else {
        PathBuf::from(format!("{volume}:\\{FOLDER}"))
    }
}

// ---- the written pattern -------------------------------------------------------------

/// Pattern bytes: PATTERN_SECTORS distinct sectors of pseudo-random data, so the drive gets
/// data it cannot compress.
pub fn pattern(seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed | 1);
    let mut out = vec![0u8; SEQ_BLOCK];
    for chunk in out.as_chunks_mut::<8>().0 {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    out
}

/// The 8-byte stamp at the start of sector `index`: its number mixed with the run's salt.
fn stamp(index: u64, salt: u64) -> [u8; 8] {
    (index ^ salt).to_le_bytes()
}

/// Fills `buf` with what belongs at byte `offset` of the file.
pub fn fill(buf: &mut [u8], offset: u64, base: &[u8], salt: u64) {
    for (i, sector) in buf.as_chunks_mut::<SECTOR>().0.iter_mut().enumerate() {
        let index = offset / SECTOR as u64 + i as u64;
        let from = (index as usize % PATTERN_SECTORS) * SECTOR;
        sector.copy_from_slice(&base[from..from + SECTOR]);
        sector[..8].copy_from_slice(&stamp(index, salt));
    }
}

/// Counts the sectors of `buf`, read from byte `offset`, that differ from what was written.
pub fn count_bad(buf: &[u8], offset: u64, base: &[u8], salt: u64) -> u64 {
    let mut bad = 0;
    for (i, sector) in buf.as_chunks::<SECTOR>().0.iter().enumerate() {
        let index = offset / SECTOR as u64 + i as u64;
        let from = (index as usize % PATTERN_SECTORS) * SECTOR;
        if sector[..8] != stamp(index, salt) || sector[8..] != base[from + 8..from + SECTOR] {
            bad += 1;
        }
    }
    bad
}

/// xorshift64*: fast, and good enough to pick offsets and fill the pattern.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A sector-aligned offset below `region`.
    pub fn offset(&mut self, region: u64) -> u64 {
        let sectors = (region / SECTOR as u64).max(1);
        (self.next_u64() % sectors) * SECTOR as u64
    }
}

// ---- Win32 -------------------------------------------------------------------------

/// Page-aligned memory, which meets every sector alignment.
struct Aligned {
    ptr: *mut u8,
    len: usize,
}

impl Aligned {
    fn new(len: usize) -> Result<Self, String> {
        // SAFETY: a fresh committed allocation; freed once in Drop.
        let ptr = unsafe { VirtualAlloc(null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if ptr.is_null() {
            return Err("Windows could not give the test its memory".into());
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is valid for `len` bytes for the life of self.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for Aligned {
    fn drop(&mut self) {
        // SAFETY: releases the whole allocation made in `new`.
        unsafe { VirtualFree(self.ptr.cast(), 0, MEM_RELEASE) };
    }
}

/// The open test file and its completion port. Closing the file deletes it.
struct TestFile {
    handle: HANDLE,
    port: HANDLE,
}

impl Drop for TestFile {
    fn drop(&mut self) {
        // SAFETY: both handles were opened in `create` and are closed once; no transfer is
        // in flight, since every pass drains its transfers before returning.
        unsafe {
            CloseHandle(self.port);
            CloseHandle(self.handle);
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn create(path: &Path) -> Result<TestFile, String> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; no security attributes or template.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            0,
            null(),
            CREATE_NEW,
            FILE_FLAG_NO_BUFFERING
                | FILE_FLAG_WRITE_THROUGH
                | FILE_FLAG_OVERLAPPED
                | FILE_FLAG_DELETE_ON_CLOSE,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads the calling thread's last-error value.
        let error = unsafe { GetLastError() };
        return Err(match error {
            ERROR_ACCESS_DENIED => format!(
                "Windows did not let the current user create the test file in {}",
                path.parent().unwrap_or(path).display()
            ),
            ERROR_FILE_EXISTS => "a test file of that name already exists".into(),
            other => format!("the test file could not be created (error {other})"),
        });
    }
    // SAFETY: associates the new file handle with a new port.
    let port = unsafe { CreateIoCompletionPort(handle, null_mut(), 0, 1) };
    if port.is_null() {
        // SAFETY: closes the handle opened above, which deletes the file.
        unsafe { CloseHandle(handle) };
        return Err("Windows could not set up the test's transfers".into());
    }
    Ok(TestFile { handle, port })
}

/// Bytes per sector of the volume, from GetDiskFreeSpaceW.
fn sector_size(volume: &Path) -> Result<u32, String> {
    let root = wide(volume);
    let (mut per_cluster, mut per_sector, mut free, mut total) = (0, 0, 0, 0);
    // SAFETY: `root` is NUL-terminated and the four out pointers are valid.
    let ok = unsafe {
        GetDiskFreeSpaceW(
            root.as_ptr(),
            &mut per_cluster,
            &mut per_sector,
            &mut free,
            &mut total,
        )
    };
    if ok == 0 {
        return Err("the volume's sector size could not be read".into());
    }
    Ok(per_sector)
}

/// What one pass needs besides the file.
struct Pass<'a> {
    phase: Phase,
    region: u64,
    limit: Duration,
    base: &'a [u8],
    salt: u64,
}

struct Done {
    measure: Measure,
    /// End of the part written in order, for the prepare pass.
    reached: u64,
    bad_sectors: u64,
    error: Option<String>,
}

/// Runs one phase with `depth` transfers in flight on the completion port, and waits for all
/// of them before returning, whatever happens.
fn pass(
    file: &TestFile,
    p: &Pass,
    cancel: &AtomicBool,
    progress: &Progress,
    rng: &mut Rng,
) -> Result<Done, String> {
    let (depth, block) = (p.phase.depth(), p.phase.block());
    let mut memory = Aligned::new(depth * block)?;
    let buffers = memory.slice();
    // Sequential writes fill each buffer once and then only restamp; random ones refill.
    if p.phase.writes() && !p.phase.random() {
        for slot in buffers.chunks_exact_mut(block) {
            fill(slot, 0, p.base, p.salt);
        }
    }
    let mut overlapped: Box<[OVERLAPPED]> = (0..depth).map(|_| OVERLAPPED::default()).collect();
    let mut offsets = vec![0u64; depth];
    let mut next = 0u64;
    let started = Instant::now();
    let mut finished = started;
    let (mut bytes, mut ops, mut bad) = (0u64, 0u64, 0u64);
    let mut error: Option<String> = None;
    let mut stopping = false;
    let mut outstanding = 0usize;

    // Starts a transfer in `slot`; false when there is nothing more to start or it failed.
    let mut issue = |slot: usize,
                     next: &mut u64,
                     offsets: &mut [u64],
                     overlapped: &mut [OVERLAPPED],
                     buffers: &mut [u8],
                     error: &mut Option<String>|
     -> bool {
        let offset = if p.phase.random() {
            if started.elapsed() >= p.limit {
                return false;
            }
            rng.offset(p.region)
        } else {
            if *next + block as u64 > p.region || started.elapsed() >= p.limit {
                return false;
            }
            let at = *next;
            *next += block as u64;
            at
        };
        offsets[slot] = offset;
        let buf = &mut buffers[slot * block..(slot + 1) * block];
        if p.phase.writes() {
            if p.phase.random() {
                fill(buf, offset, p.base, p.salt);
            } else {
                for (i, sector) in buf.as_chunks_mut::<SECTOR>().0.iter_mut().enumerate() {
                    sector[..8].copy_from_slice(&stamp(offset / SECTOR as u64 + i as u64, p.salt));
                }
            }
        }
        let ov = &mut overlapped[slot];
        *ov = OVERLAPPED::default();
        ov.Anonymous.Anonymous.Offset = offset as u32;
        ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        // SAFETY: the buffer and OVERLAPPED stay alive and unmoved until the completion is
        // taken from the port, which happens before `memory` and `overlapped` drop.
        let ok = unsafe {
            if p.phase.writes() {
                WriteFile(file.handle, buf.as_ptr(), block as u32, null_mut(), ov)
            } else {
                ReadFile(file.handle, buf.as_mut_ptr(), block as u32, null_mut(), ov)
            }
        };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error value.
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                *error = Some(format!(
                    "the drive refused a {} at byte {offset} (error {code})",
                    if p.phase.writes() { "write" } else { "read" }
                ));
                return false;
            }
        }
        true
    };

    for slot in 0..depth {
        if !issue(
            slot,
            &mut next,
            &mut offsets,
            &mut overlapped,
            buffers,
            &mut error,
        ) {
            break;
        }
        outstanding += 1;
    }
    let base_ptr = overlapped.as_ptr() as usize;
    let size = std::mem::size_of::<OVERLAPPED>();
    while outstanding > 0 {
        let (mut transferred, mut key, mut done) = (0u32, 0usize, null_mut());
        // SAFETY: the port is live and the out pointers are valid.
        let ok = unsafe {
            GetQueuedCompletionStatus(file.port, &mut transferred, &mut key, &mut done, 1000)
        };
        if done.is_null() {
            // Nothing finished within a second; keep waiting, but stop starting new ones.
            if cancel.load(Ordering::Relaxed) && !stopping {
                stopping = true;
                // SAFETY: cancels this file's transfers; their completions still arrive.
                unsafe { CancelIoEx(file.handle, null()) };
            }
            continue;
        }
        outstanding -= 1;
        finished = Instant::now();
        let slot = (done as usize - base_ptr) / size;
        if ok == 0 {
            if error.is_none() && !stopping {
                // SAFETY: reads the calling thread's last-error value.
                let code = unsafe { GetLastError() };
                error = Some(format!(
                    "the drive failed a {} at byte {} (error {code})",
                    if p.phase.writes() { "write" } else { "read" },
                    offsets[slot]
                ));
            }
            if !stopping {
                stopping = true;
                // SAFETY: as above.
                unsafe { CancelIoEx(file.handle, null()) };
            }
            continue;
        }
        bytes += u64::from(transferred);
        ops += 1;
        if p.phase == Phase::Verify {
            let buf = &buffers[slot * block..slot * block + transferred as usize];
            bad += count_bad(buf, offsets[slot], p.base, p.salt);
        }
        let share = if p.phase.random() {
            started.elapsed().as_secs_f64() / p.limit.as_secs_f64().max(1e-3)
        } else {
            next as f64 / p.region.max(1) as f64
        };
        progress
            .permille
            .store((share * 1000.0).min(1000.0) as u32, Ordering::Relaxed);
        if cancel.load(Ordering::Relaxed) {
            stopping = true;
        }
        if !stopping
            && issue(
                slot,
                &mut next,
                &mut offsets,
                &mut overlapped,
                buffers,
                &mut error,
            )
        {
            outstanding += 1;
        } else if error.is_some() && !stopping {
            stopping = true;
            // SAFETY: as above.
            unsafe { CancelIoEx(file.handle, null()) };
        }
    }
    Ok(Done {
        measure: Measure {
            phase: p.phase,
            bytes,
            ops,
            seconds: (finished - started).as_secs_f64(),
        },
        reached: next,
        bad_sectors: bad,
        error,
    })
}

/// Runs the test on drive `volume` after checking its free space.
pub fn run(
    volume: char,
    settings: &Settings,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Result<Report, String> {
    let (free, _) = crate::tools::space::disk_space(volume)?;
    check_space(volume, free, settings.size)?;
    run_in(&folder_for(volume), settings, cancel, progress)
}

/// Runs the test with its file in `folder`, which is made if missing and removed if empty
/// afterwards. Err when it could not start; nothing was left behind then.
pub fn run_in(
    folder: &Path,
    settings: &Settings,
    cancel: &AtomicBool,
    progress: &Progress,
) -> Result<Report, String> {
    let started = Instant::now();
    let root = folder
        .ancestors()
        .last()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let sector = sector_size(&root)?;
    if sector == 0 || !(SECTOR as u32).is_multiple_of(sector) {
        return Err(format!(
            "the volume uses {sector}-byte sectors, which this test does not handle"
        ));
    }
    match std::fs::create_dir(folder) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(format!(
                "Windows did not let the current user make the folder {}",
                folder.display()
            ))
        }
        Err(e) => {
            return Err(format!(
                "the folder {} could not be made: {e}",
                folder.display()
            ))
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let path = folder.join(format!("speed-test-{}-{nanos}.tmp", std::process::id()));
    let file = match create(&path) {
        Ok(file) => file,
        Err(why) => {
            let _ = std::fs::remove_dir(folder);
            return Err(why);
        }
    };
    let size = file_size(settings.size);
    let seed = nanos ^ 0x9E37_79B9_7F4A_7C15;
    let base = pattern(seed);
    let salt = Rng(seed.rotate_left(17) | 1).next_u64();
    let mut rng = Rng(seed | 1);
    let mut report = Report {
        folder: folder.to_path_buf(),
        size,
        tested: 0,
        measures: Vec::new(),
        verify: None,
        stopped: false,
        error: None,
        cleanup: Ok(()),
        elapsed: Duration::ZERO,
    };
    let mut region = size;
    for phase in Phase::ALL {
        if cancel.load(Ordering::Relaxed) {
            report.stopped = true;
            break;
        }
        progress.phase.store(phase.index() + 1, Ordering::Relaxed);
        progress.permille.store(0, Ordering::Relaxed);
        let limit = match phase {
            Phase::Prepare => settings.prepare_seconds,
            Phase::Verify => f64::MAX / 4.0,
            p if p.random() => settings.random_seconds,
            _ => settings.seq_seconds,
        };
        let done = match pass(
            &file,
            &Pass {
                phase,
                region,
                limit: Duration::from_secs_f64(limit.min(1e9)),
                base: &base,
                salt,
            },
            cancel,
            progress,
            &mut rng,
        ) {
            Ok(done) => done,
            Err(why) => {
                report.error = Some(why);
                break;
            }
        };
        if let Some(why) = done.error {
            report.error = Some(why);
            break;
        }
        if cancel.load(Ordering::Relaxed) {
            report.stopped = true;
            break;
        }
        match phase {
            Phase::Prepare => {
                region = done.reached;
                report.tested = region;
                if region == 0 {
                    report.error = Some("nothing could be written to the test file".into());
                    break;
                }
            }
            Phase::Verify => {
                report.verify = Some(Verify {
                    bytes: done.measure.bytes,
                    bad_sectors: done.bad_sectors,
                })
            }
            _ => {
                report.measures.push(done.measure);
                if let Ok(mut shown) = progress.measures.lock() {
                    shown.push(done.measure);
                }
            }
        }
    }
    drop(file);
    report.cleanup = if path.exists() {
        Err(format!(
            "the test file {} is still there; delete it by hand",
            path.display()
        ))
    } else {
        Ok(())
    };
    // Removes the folder only when empty, so nothing else in it is touched.
    let _ = std::fs::remove_dir(folder);
    report.elapsed = started.elapsed();
    Ok(report)
}

// ---- text ----------------------------------------------------------------------------

/// "3,512.4 MB/s" for sequential phases; random phases add IOPS and the average latency.
pub fn result_text(m: &Measure) -> String {
    let rate = format!("{} MB/s", decimal(m.mb_per_s(), 1));
    if m.phase.random() {
        format!(
            "{rate}, {} IOPS, {} us each",
            decimal(m.iops(), 0),
            decimal(m.latency_us(), 0)
        )
    } else {
        rate
    }
}

/// A number with its thousands grouped and `places` decimals.
pub fn decimal(value: f64, places: usize) -> String {
    let text = format!("{value:.places$}");
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    let digits = whole.trim_start_matches('-');
    let mut grouped = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    let sign = if whole.starts_with('-') { "-" } else { "" };
    if fraction.is_empty() {
        format!("{sign}{grouped}")
    } else {
        format!("{sign}{grouped}.{fraction}")
    }
}

pub fn verify_text(v: &Verify) -> String {
    if v.bad_sectors == 0 {
        format!(
            "Read back {} of test data; every sector matched what was written.",
            gib(v.bytes)
        )
    } else {
        format!(
            "{} sectors of 4 KiB read back different from what was written: the drive or its connection is corrupting data.",
            v.bad_sectors
        )
    }
}

/// One line on how the run ended and whether its file is gone.
pub fn summary(report: &Report) -> String {
    let mut text = if let Some(why) = &report.error {
        format!("The speed test stopped early: {why}.")
    } else if report.stopped {
        "The speed test was stopped; only the finished phases are shown.".to_string()
    } else {
        format!(
            "Tested a {} file in {} s.",
            gib(report.tested),
            report.elapsed.as_secs()
        )
    };
    if report.tested > 0 && report.tested < report.size {
        text.push_str(&format!(
            " The drive wrote only {} of the {} file in the time allowed, so that part was used.",
            gib(report.tested),
            gib(report.size)
        ));
    }
    match &report.cleanup {
        Ok(()) => text.push_str(" The test file was deleted."),
        Err(why) => text.push_str(&format!(" {why}.")),
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_folder(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("dt-speed-{name}-{}", std::process::id()))
    }

    #[test]
    fn the_maths_gives_mb_per_second_iops_and_latency() {
        let seq = Measure {
            phase: Phase::SeqRead,
            bytes: 1 << 30,
            ops: 1024,
            seconds: 0.5,
        };
        assert!((seq.mb_per_s() - 2147.483648).abs() < 1e-6);
        assert_eq!(result_text(&seq), "2,147.5 MB/s");
        let random = Measure {
            phase: Phase::RandRead,
            bytes: 40_000 * 4096,
            ops: 40_000,
            seconds: 4.0,
        };
        assert!((random.iops() - 10_000.0).abs() < 1e-9);
        assert!((random.latency_us() - 100.0).abs() < 1e-9);
        let deep = Measure {
            phase: Phase::RandReadDeep,
            ..random
        };
        assert!((deep.latency_us() - 3200.0).abs() < 1e-9);
        assert_eq!(result_text(&random), "41.0 MB/s, 10,000 IOPS, 100 us each");
        let empty = Measure {
            phase: Phase::SeqWrite,
            bytes: 0,
            ops: 0,
            seconds: 0.0,
        };
        assert_eq!(empty.mb_per_s(), 0.0);
        assert_eq!(empty.latency_us(), 0.0);
        assert_eq!(decimal(1234567.891, 1), "1,234,567.9");
        assert_eq!(decimal(999.0, 0), "999");
    }

    #[test]
    fn too_little_free_space_is_refused_with_the_numbers() {
        let gib = 1u64 << 30;
        assert!(check_space('C', 4 * gib, gib).is_ok());
        assert!(check_space('C', 3 * gib, gib).is_ok());
        let refused = check_space('D', 3 * gib - 1, gib).unwrap_err();
        assert!(
            refused.starts_with("Drive D: has 3.0 GiB free"),
            "{refused}"
        );
        assert!(refused.contains("needs 3.0 GiB"));
        assert!(refused.contains("did not start"));
        assert_eq!(file_size(5 << 20 | 7), 5 << 20);
        assert_eq!(file_size(1), 1 << 20);
    }

    #[test]
    fn the_pattern_verifies_and_catches_a_changed_sector() {
        let base = pattern(42);
        let mut buf = vec![0u8; 4 * SECTOR];
        fill(&mut buf, 8 * SECTOR as u64, &base, 7);
        assert_eq!(count_bad(&buf, 8 * SECTOR as u64, &base, 7), 0);
        // The same data read back from another place is wrong: stamps carry the position.
        assert_eq!(count_bad(&buf, 12 * SECTOR as u64, &base, 7), 4);
        buf[SECTOR + 100] ^= 1;
        assert_eq!(count_bad(&buf, 8 * SECTOR as u64, &base, 7), 1);
        assert_ne!(pattern(1), pattern(2));
        let mut rng = Rng(5);
        for _ in 0..1000 {
            let offset = rng.offset(1 << 20);
            assert!(offset < 1 << 20 && offset.is_multiple_of(SECTOR as u64));
        }
    }

    #[test]
    fn the_folder_is_under_temp_on_its_own_volume() {
        let temp = std::env::temp_dir();
        let letter = temp.to_string_lossy().chars().next().unwrap();
        assert!(folder_for(letter).starts_with(&temp));
        let other = if letter.eq_ignore_ascii_case(&'Q') {
            'R'
        } else {
            'Q'
        };
        assert_eq!(
            folder_for(other),
            PathBuf::from(format!("{other}:\\DiagnosticTool-speed"))
        );
    }

    fn small() -> Settings {
        Settings {
            size: 16 << 20,
            random_seconds: 0.2,
            seq_seconds: 10.0,
            prepare_seconds: 30.0,
        }
    }

    #[test]
    fn a_small_run_measures_every_phase_verifies_and_leaves_nothing() {
        let folder = temp_folder("run");
        let progress = Progress::default();
        let cancel = AtomicBool::new(false);
        let report = run_in(&folder, &small(), &cancel, &progress).unwrap();
        assert_eq!(report.error, None);
        assert!(!report.stopped);
        assert_eq!(report.tested, 16 << 20);
        let phases: Vec<Phase> = report.measures.iter().map(|m| m.phase).collect();
        assert_eq!(phases, Phase::MEASURED);
        for m in &report.measures {
            assert!(m.ops > 0 && m.bytes > 0 && m.seconds > 0.0, "{m:?}");
            assert_eq!(m.bytes, m.ops * m.phase.block() as u64);
        }
        let seq_read = &report.measures[0];
        assert_eq!(seq_read.bytes, 16 << 20);
        let verify = report.verify.unwrap();
        assert_eq!(verify.bytes, 16 << 20);
        assert_eq!(verify.bad_sectors, 0);
        assert_eq!(report.cleanup, Ok(()));
        assert!(!folder.exists(), "the folder was left behind");
        assert_eq!(progress.measures().len(), 6);
        assert_eq!(progress.phase(), Some(Phase::Verify));
        assert!(summary(&report).contains("The test file was deleted."));
    }

    #[test]
    fn a_stopped_run_still_deletes_its_file() {
        let folder = temp_folder("stop");
        let cancel = AtomicBool::new(true);
        let report = run_in(&folder, &small(), &cancel, &Progress::default()).unwrap();
        assert!(report.stopped);
        assert!(report.measures.is_empty());
        assert_eq!(report.cleanup, Ok(()));
        assert!(!folder.exists());
        assert!(summary(&report).starts_with("The speed test was stopped"));
    }

    #[test]
    fn a_folder_that_cannot_be_made_is_refused_and_nothing_is_left() {
        let parent = temp_folder("missing-parent");
        let err = run_in(
            &parent.join("child"),
            &small(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap_err();
        assert!(err.contains("could not be made"), "{err}");
        assert!(!parent.exists());
    }

    /// Runs the default 1 GiB test on the drive holding the temporary folder and prints the
    /// numbers. Writes about 2.3 GiB; run by hand with --ignored.
    #[test]
    #[ignore]
    fn live_speed_test_on_this_pc() {
        let letter = std::env::temp_dir()
            .to_string_lossy()
            .chars()
            .next()
            .unwrap();
        let report = run(
            letter,
            &Settings::default(),
            &AtomicBool::new(false),
            &Progress::default(),
        )
        .unwrap();
        for m in &report.measures {
            println!("{}: {}", m.phase.name(), result_text(m));
        }
        if let Some(v) = &report.verify {
            println!("{}", verify_text(v));
        }
        println!("{}", summary(&report));
        assert_eq!(report.cleanup, Ok(()));
    }
}
