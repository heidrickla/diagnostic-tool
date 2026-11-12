//! The details engine: `details(&DetailsOptions) -> Details` reads the processor, memory and
//! board once, with no window in it, and `lines`, `copy_text` and `report_rows` turn the
//! result into what people read.
use serde::{Deserialize, Serialize};

use super::cpuid::{self, CpuidCache, Design, FeatureGroup, Signature};
use super::monitor;
use super::smbios::{self, Baseboard, Bios, MemoryArray, MemoryDevice, Socket};
use super::topology::{self, ProcessorClock, Topology};
use crate::tools::drives::details::{decimal_size, grouped};

/// What to read. Every part is on by default except serial numbers, which only the window
/// asks for: the result may travel to the AI model, and serials stay on the PC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailsOptions {
    pub processor: bool,
    pub memory: bool,
    pub board: bool,
    /// Memory module serial numbers.
    pub serials: bool,
}

impl Default for DetailsOptions {
    fn default() -> Self {
        Self {
            processor: true,
            memory: true,
            board: true,
            serials: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Processor {
    pub vendor: String,
    pub brand: String,
    pub signature: Signature,
    pub design: Option<Design>,
    pub instruction_sets: Vec<FeatureGroup>,
    pub hybrid: bool,
    pub hypervisor: bool,
    pub topology: Option<Topology>,
    pub cpuid_caches: Vec<CpuidCache>,
    pub clocks: Vec<ProcessorClock>,
    /// CPUID leaf 16h, Intel only.
    pub cpuid_base_mhz: Option<u32>,
    pub cpuid_max_mhz: Option<u32>,
    /// SMBIOS type 4, one per socket.
    pub sockets: Vec<Socket>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    /// What the firmware reports installed (GetPhysicallyInstalledSystemMemory).
    pub installed_bytes: Option<u64>,
    /// What Windows can use.
    pub usable_bytes: u64,
    pub available_bytes: u64,
    pub committed_bytes: u64,
    pub commit_limit_bytes: u64,
    pub arrays: Vec<MemoryArray>,
    /// Every slot, filled or empty, in table order.
    pub modules: Vec<MemoryDevice>,
    /// Channels with a module in them, when every filled slot's names say its channel.
    pub channels: Option<Vec<String>>,
    /// The memory the firmware maps (SMBIOS type 19).
    pub mapped_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
    pub baseboard: Option<Baseboard>,
    pub bios: Option<Bios>,
}

/// A reading that could not be taken, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unread {
    pub item: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Details {
    pub processor: Option<Processor>,
    pub memory: Option<Memory>,
    pub board: Option<Board>,
    pub smbios_version: Option<String>,
    /// Said when the firmware table was cut short: only what was present is shown.
    #[serde(default)]
    pub smbios_cut_short: Option<String>,
    pub unread: Vec<Unread>,
}

/// Reads the parts `options` asks for. Nothing here needs administrator rights.
pub fn details(options: &DetailsOptions) -> Details {
    crate::live::reading("the processor, memory and firmware tables");
    let mut unread = Vec::new();
    let table = if options.processor || options.memory || options.board {
        match smbios::read() {
            Ok(t) => Some(smbios::decode(&t)),
            Err(reason) => {
                unread.push(Unread {
                    item: "Firmware tables (SMBIOS)".into(),
                    reason,
                });
                None
            }
        }
    } else {
        None
    };
    let processor = options
        .processor
        .then(|| read_processor(table.as_ref(), &mut unread));
    let memory = options
        .memory
        .then(|| read_memory(table.as_ref(), options.serials, &mut unread));
    let board = options.board.then(|| Board {
        baseboard: table.as_ref().and_then(|t| t.baseboard.clone()),
        bios: table.as_ref().and_then(|t| t.bios.clone()),
    });
    let cut_short = table.as_ref().and_then(|t| t.cut_short).map(cut_short_text);
    // A walk of the table that ended early is said where a table cut short is.
    let limit = table.as_ref().and_then(|t| t.limit.clone());
    Details {
        processor,
        memory,
        board,
        smbios_cut_short: cut_short.or(limit),
        smbios_version: table.map(|t| t.version),
        unread,
    }
}

/// What the window and the copy say about a firmware table cut short.
fn cut_short_text((declared, present): (usize, usize)) -> String {
    format!(
        "The firmware table (SMBIOS) was cut short: its header gives {declared} bytes and Windows returned {present}. Only the structures present are shown, so memory slots, sockets or board details may be missing."
    )
}

fn read_processor(table: Option<&smbios::Decoded>, unread: &mut Vec<Unread>) -> Processor {
    let id = cpuid::read(&cpuid::Live);
    let topology = match topology::read() {
        Ok(t) => Some(t),
        Err(reason) => {
            unread.push(Unread {
                item: "Cores and caches".into(),
                reason,
            });
            None
        }
    };
    let processors = topology
        .as_ref()
        .map_or_else(monitor::logical_processors, |t| t.logical_processors.max(1));
    let clocks = match topology::clocks(processors) {
        Ok(c) => c,
        Err(reason) => {
            unread.push(Unread {
                item: "Clocks".into(),
                reason,
            });
            Vec::new()
        }
    };
    Processor {
        design: cpuid::design(&id.vendor, &id.signature),
        vendor: id.vendor,
        brand: id.brand,
        signature: id.signature,
        instruction_sets: id.features,
        hybrid: id.hybrid,
        hypervisor: id.hypervisor,
        topology,
        cpuid_caches: id.caches,
        clocks,
        cpuid_base_mhz: id.base_mhz,
        cpuid_max_mhz: id.max_mhz,
        sockets: table.map(|t| t.sockets.clone()).unwrap_or_default(),
    }
}

fn read_memory(table: Option<&smbios::Decoded>, serials: bool, unread: &mut Vec<Unread>) -> Memory {
    let status = monitor::memory_status();
    if status.is_none() {
        unread.push(Unread {
            item: "Memory in use".into(),
            reason: "Windows did not give its memory figures".into(),
        });
    }
    let status = status.unwrap_or_default();
    let mut installed_kib = 0u64;
    // SAFETY: one valid out pointer.
    let installed = (unsafe {
        windows_sys::Win32::System::SystemInformation::GetPhysicallyInstalledSystemMemory(
            &mut installed_kib,
        )
    } != 0)
        .then_some(installed_kib.saturating_mul(1024));
    let mut modules: Vec<MemoryDevice> = table.map(|t| t.devices.clone()).unwrap_or_default();
    if !serials {
        for m in &mut modules {
            m.serial = None;
        }
    }
    let arrays: Vec<MemoryArray> = table.map(|t| t.arrays.clone()).unwrap_or_default();
    // Only arrays used for system memory count; video memory arrays are left out.
    let system: Vec<u16> = arrays
        .iter()
        .filter(|a| a.used_for == "system memory")
        .map(|a| a.handle)
        .collect();
    if !system.is_empty() {
        modules.retain(|m| m.array_handle.is_none_or(|h| system.contains(&h)));
    }
    let mapped = table
        .map(|t| t.ranges.iter().map(smbios::MappedRange::bytes).sum::<u64>())
        .filter(|b| *b > 0);
    Memory {
        installed_bytes: installed,
        usable_bytes: status.total_bytes,
        available_bytes: status.available_bytes,
        committed_bytes: status.committed_bytes,
        commit_limit_bytes: status.commit_limit_bytes,
        channels: channels(&modules),
        arrays: arrays
            .into_iter()
            .filter(|a| system.is_empty() || system.contains(&a.handle))
            .collect(),
        modules,
        mapped_bytes: mapped,
    }
}

/// The channel a slot's names state: the word "channel" followed by a letter or number, as
/// in "P0 CHANNEL A" or "ChannelB-DIMM1". None when the names do not say.
pub fn channel_of(names: &[&str]) -> Option<String> {
    for name in names {
        let lower = name.to_ascii_lowercase();
        let Some(at) = lower.find("channel") else {
            continue;
        };
        let rest = &name[at + "channel".len()..];
        let token: String = rest
            .trim_start_matches([' ', '_', '-'])
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        // A single letter, or a number; a longer word is not a channel name.
        let plain =
            token.len() == 1 || (!token.is_empty() && token.chars().all(|c| c.is_ascii_digit()));
        if plain {
            return Some(token.to_ascii_uppercase());
        }
    }
    None
}

/// The populated channels, only when every filled slot names its channel.
pub fn channels(modules: &[MemoryDevice]) -> Option<Vec<String>> {
    let filled: Vec<&MemoryDevice> = modules.iter().filter(|m| m.size_bytes.is_some()).collect();
    if filled.is_empty() {
        return None;
    }
    let mut found = Vec::new();
    for m in filled {
        let names = [
            m.bank.as_deref().unwrap_or(""),
            m.locator.as_deref().unwrap_or(""),
        ];
        let channel = channel_of(&names)?;
        if !found.contains(&channel) {
            found.push(channel);
        }
    }
    found.sort();
    Some(found)
}

// ---- words -------------------------------------------------------------------------------

/// One line of a section as the window shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    Heading(String),
    Fact(String, String),
    Note(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Processor,
    Memory,
    Board,
}

/// Sizes the way caches and modules are built: whole KiB, MiB or GiB, with up to two
/// decimals where needed ("1.25 MiB").
pub fn binary_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (unit, size) in UNITS {
        if bytes >= size {
            let value = bytes as f64 / size as f64;
            let text = format!("{value:.2}");
            let text = text.trim_end_matches('0').trim_end_matches('.');
            return format!("{text} {unit}");
        }
    }
    format!("{bytes} B")
}

/// A memory amount in decimal units, with the binary figure modules are sold by when it is
/// a whole number of GiB: "17.2 GB (16 GiB)".
pub fn memory_size(bytes: u64) -> String {
    let decimal = decimal_size(u128::from(bytes));
    if bytes >= 1 << 30 && bytes.is_multiple_of(1 << 30) {
        format!("{decimal} ({} GiB)", bytes >> 30)
    } else {
        decimal
    }
}

pub fn mhz(v: u32) -> String {
    format!("{} MHz", grouped(u128::from(v)))
}

fn mts(v: u32) -> String {
    format!("{} MT/s", grouped(u128::from(v)))
}

fn vendor_name(vendor: &str) -> String {
    match vendor {
        "AuthenticAMD" => "AMD (AuthenticAMD)".into(),
        "GenuineIntel" => "Intel (GenuineIntel)".into(),
        "" => "not given".into(),
        other => other.into(),
    }
}

fn plural(n: u32, one: &str, many: &str) -> String {
    format!(
        "{} {}",
        grouped(u128::from(n)),
        if n == 1 { one } else { many }
    )
}

fn cache_name(level: u8, kind: &str) -> String {
    match kind {
        "unified" => format!("Level {level}"),
        other => format!("Level {level} {other}"),
    }
}

/// The clocks, folding runs of processors that read the same.
fn clock_rows(clocks: &[ProcessorClock]) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut i = 0;
    while i < clocks.len() {
        let c = &clocks[i];
        let same = |o: &ProcessorClock| {
            (o.base_mhz, o.current_mhz, o.limit_mhz) == (c.base_mhz, c.current_mhz, c.limit_mhz)
        };
        let run = clocks[i..].iter().take_while(|o| same(o)).count();
        let last = &clocks[i + run - 1];
        let name = if run == 1 {
            format!("Processor {}", c.processor)
        } else {
            format!("Processors {} to {}", c.processor, last.processor)
        };
        rows.push((
            name,
            format!(
                "{} now, base {}, allowed up to {}",
                mhz(c.current_mhz),
                mhz(c.base_mhz),
                mhz(c.limit_mhz)
            ),
        ));
        i += run;
    }
    rows
}

/// The highest clock a source gives, with the source named.
pub fn max_clock(p: &Processor) -> Option<(u32, &'static str)> {
    if let Some(v) = p.cpuid_max_mhz {
        return Some((v, "from the processor (CPUID)"));
    }
    p.sockets
        .iter()
        .filter_map(|s| s.max_speed_mhz)
        .max()
        .map(|v| (u32::from(v), "as the firmware states it"))
}

/// The base clock: Windows' power report, else CPUID.
pub fn base_clock(p: &Processor) -> Option<u32> {
    p.clocks
        .iter()
        .map(|c| c.base_mhz)
        .max()
        .filter(|v| *v > 0)
        .or(p.cpuid_base_mhz)
}

pub fn core_summary(t: &Topology, hybrid: bool) -> Vec<(String, String)> {
    let mut rows = vec![
        ("Cores".into(), grouped(u128::from(t.cores))),
        ("Threads".into(), grouped(u128::from(t.logical_processors))),
    ];
    if t.core_classes.len() >= 2 {
        let names = ["Performance cores", "Efficient cores"];
        for (i, class) in t.core_classes.iter().enumerate() {
            let name = names.get(i).map_or_else(
                || format!("Cores of class {}", class.efficiency_class),
                |n| (*n).to_string(),
            );
            rows.push((
                name,
                format!(
                    "{}, {}",
                    plural(class.cores, "core", "cores"),
                    plural(class.threads, "thread", "threads")
                ),
            ));
        }
    } else {
        rows.push((
            "Core types".into(),
            if hybrid {
                "the processor says it is hybrid, but Windows lists one core type".into()
            } else {
                "one (not a hybrid processor)".into()
            },
        ));
    }
    rows
}

fn processor_lines(p: &Processor, out: &mut Vec<Line>) {
    let fact =
        |out: &mut Vec<Line>, name: &str, value: String| out.push(Line::Fact(name.into(), value));
    out.push(Line::Heading("Processor".into()));
    fact(
        out,
        "Name",
        if p.brand.is_empty() {
            "not given".into()
        } else {
            p.brand.clone()
        },
    );
    fact(out, "Vendor", vendor_name(&p.vendor));
    if let Some(d) = &p.design {
        fact(
            out,
            if d.kind == "codename" {
                "Codename"
            } else {
                "Microarchitecture"
            },
            format!("{} (from family and model, {})", d.name, d.source),
        );
    }
    let s = &p.signature;
    fact(
        out,
        "Family, model, stepping",
        format!(
            "{} ({:X}h), {} ({:X}h), {}",
            s.family, s.family, s.model, s.model, s.stepping
        ),
    );
    fact(
        out,
        "As the processor gives them",
        format!(
            "family {:X}h + extended {:X}h, model {:X}h + extended {:X}h",
            s.base_family, s.extended_family, s.base_model, s.extended_model
        ),
    );
    let populated = p.sockets.iter().filter(|s| s.populated).count() as u32;
    if let Some(name) = p
        .sockets
        .iter()
        .find(|s| s.populated)
        .and_then(|s| s.designation.clone())
    {
        fact(out, "Socket", name);
    }
    let packages = p.topology.as_ref().map(|t| t.packages);
    let sockets = if p.sockets.is_empty() {
        "not stated by the firmware".to_string()
    } else {
        format!("{} filled of {}", populated, p.sockets.len())
    };
    fact(
        out,
        "Sockets and packages",
        match packages {
            Some(n) => format!("{sockets}; {}", plural(n, "package", "packages")),
            None => sockets,
        },
    );
    if let Some(t) = &p.topology {
        out.push(Line::Heading("Cores".into()));
        for (name, value) in core_summary(t, p.hybrid) {
            fact(out, &name, value);
        }
        if t.numa_nodes > 1 {
            fact(
                out,
                "Memory nodes (NUMA)",
                grouped(u128::from(t.numa_nodes)),
            );
        }
        out.push(Line::Heading("Caches".into()));
        for c in &t.caches {
            let ways = match c.ways {
                Some(w) => format!("{w}-way"),
                None => "fully associative".into(),
            };
            let each = if c.count == 1 { "" } else { "each " };
            fact(
                out,
                &cache_name(c.level, &c.kind),
                format!(
                    "{} × {}, {ways}, {}-byte lines, {each}for {}",
                    c.count,
                    binary_size(c.size_bytes),
                    c.line_bytes,
                    plural(c.shared_by_threads, "thread", "threads")
                ),
            );
        }
    }
    out.push(Line::Heading("Clocks".into()));
    match base_clock(p) {
        Some(v) => fact(out, "Base", mhz(v)),
        None => fact(out, "Base", "not given".into()),
    }
    match max_clock(p) {
        Some((v, source)) => fact(out, "Maximum", format!("{} ({source})", mhz(v))),
        None => fact(
            out,
            "Maximum",
            "not given by the processor or firmware".into(),
        ),
    }
    if let Some(bus) = p.sockets.iter().find_map(|s| s.external_clock_mhz) {
        fact(out, "Reference clock", mhz(u32::from(bus)));
    }
    if let Some(v) = p.sockets.iter().find_map(|s| s.voltage_mv) {
        fact(
            out,
            "Voltage",
            format!("{:.1} V (as the firmware states it)", f64::from(v) / 1000.0),
        );
    }
    for (name, value) in clock_rows(&p.clocks) {
        fact(out, &name, value);
    }
    if !p.clocks.is_empty() {
        out.push(Line::Note("These clocks are Windows' power report, which on many processors stops at the base clock; the CPU activity tab shows the clock measured from the processor's performance counter.".into()));
    }
    out.push(Line::Heading("Instruction sets".into()));
    for g in &p.instruction_sets {
        fact(out, &g.group, g.names.join(", "));
    }
    if p.hypervisor {
        out.push(Line::Note("Windows runs under its own hypervisor here (Hyper-V or virtualization-based security), which can hide the processor's virtualization support from this list.".into()));
    }
}

fn speed_text(m: &MemoryDevice) -> (Option<String>, Option<String>) {
    (m.rated_speed_mts.map(mts), m.configured_speed_mts.map(mts))
}

fn slot_name(m: &MemoryDevice) -> String {
    match (&m.bank, &m.locator) {
        (Some(b), Some(l)) => format!("{b}, {l}"),
        (Some(n), None) | (None, Some(n)) => n.clone(),
        (None, None) => "Slot".into(),
    }
}

fn voltage_text(m: &MemoryDevice) -> Option<String> {
    let v = |mv: u16| format!("{:.2} V", f64::from(mv) / 1000.0);
    match (m.configured_voltage_mv, m.min_voltage_mv, m.max_voltage_mv) {
        (Some(c), Some(lo), Some(hi)) if lo != hi => {
            Some(format!("{} set ({} to {})", v(c), v(lo), v(hi)))
        }
        (Some(c), _, _) => Some(format!("{} set", v(c))),
        (None, Some(lo), _) => Some(format!("{} minimum", v(lo))),
        _ => None,
    }
}

fn memory_lines(m: &Memory, out: &mut Vec<Line>) {
    let fact =
        |out: &mut Vec<Line>, name: &str, value: String| out.push(Line::Fact(name.into(), value));
    out.push(Line::Heading("Memory".into()));
    if let Some(b) = m.installed_bytes {
        fact(out, "Installed", memory_size(b));
    }
    fact(out, "Usable by Windows", memory_size(m.usable_bytes));
    fact(out, "Available now", memory_size(m.available_bytes));
    fact(
        out,
        "Committed",
        format!(
            "{} of a {} limit",
            decimal_size(u128::from(m.committed_bytes)),
            decimal_size(u128::from(m.commit_limit_bytes))
        ),
    );
    let filled: Vec<&MemoryDevice> = m
        .modules
        .iter()
        .filter(|d| d.size_bytes.is_some())
        .collect();
    let slots = m
        .arrays
        .iter()
        .filter_map(|a| a.slots)
        .map(u32::from)
        .sum::<u32>();
    let slots = if slots > 0 {
        slots
    } else {
        m.modules.len() as u32
    };
    if slots > 0 {
        fact(
            out,
            "Slots",
            format!("{} filled of {}", filled.len(), slots),
        );
    }
    let mut kinds: Vec<String> = Vec::new();
    for d in &filled {
        let speed = d.configured_speed_mts.or(d.rated_speed_mts).map(mts);
        let text = match speed {
            Some(s) => format!("{} at {s}", d.memory_type),
            None => d.memory_type.clone(),
        };
        if !kinds.contains(&text) {
            kinds.push(text);
        }
    }
    if !kinds.is_empty() {
        fact(out, "Type and speed", kinds.join("; "));
    }
    fact(
        out,
        "Channels in use",
        match &m.channels {
            Some(c) if c.len() == 1 => format!("{} (single channel)", c[0]),
            Some(c) if c.len() == 2 => format!("{} and {} (dual channel)", c[0], c[1]),
            Some(c) => format!("{} ({} channels)", c.join(", "), c.len()),
            None => "not plain from the slot names".into(),
        },
    );
    for a in &m.arrays {
        if let Some(max) = a.max_capacity_bytes {
            fact(out, "Largest the board takes", memory_size(max));
        }
        fact(out, "Error correction", a.error_correction.clone());
    }
    if let Some(b) = m.mapped_bytes {
        fact(out, "Mapped by the firmware", memory_size(b));
    }
    out.push(Line::Note("Detailed timings (CAS latency and the rest) are not read: that needs a kernel driver, which this tool does not install. The configured speed is what the memory runs at now.".into()));
    for d in &m.modules {
        let Some(size) = d.size_bytes else {
            continue;
        };
        out.push(Line::Heading(slot_name(d)));
        fact(out, "Size", memory_size(size));
        fact(out, "Type", format!("{}, {}", d.memory_type, d.form_factor));
        let (rated, configured) = speed_text(d);
        fact(
            out,
            "Rated speed",
            rated.unwrap_or_else(|| "not given".into()),
        );
        fact(
            out,
            "Configured speed",
            configured.unwrap_or_else(|| "not given".into()),
        );
        fact(
            out,
            "Manufacturer",
            d.manufacturer.clone().unwrap_or_else(|| "not given".into()),
        );
        fact(
            out,
            "Part number",
            d.part_number.clone().unwrap_or_else(|| "not given".into()),
        );
        if let Some(serial) = &d.serial {
            fact(out, "Serial number", serial.clone());
        }
        if let Some(rank) = d.rank {
            let word = match rank {
                1 => " (single rank)",
                2 => " (dual rank)",
                4 => " (quad rank)",
                _ => "",
            };
            fact(out, "Ranks", format!("{rank}{word}"));
        }
        if let Some(v) = voltage_text(d) {
            fact(out, "Voltage", v);
        }
        if let (Some(data), Some(total)) = (d.data_width_bits, d.total_width_bits) {
            let ecc = if total > data {
                ", extra bits for error correction"
            } else {
                ""
            };
            fact(
                out,
                "Width",
                format!("{data}-bit data, {total}-bit total{ecc}"),
            );
        }
    }
    let empty: Vec<String> = m
        .modules
        .iter()
        .filter(|d| d.size_bytes.is_none())
        .map(slot_name)
        .collect();
    if !empty.is_empty() {
        out.push(Line::Heading("Empty slots".into()));
        for name in empty {
            fact(out, &name, "empty".into());
        }
    }
}

fn board_lines(b: &Board, smbios: Option<&str>, out: &mut Vec<Line>) {
    let fact = |out: &mut Vec<Line>, name: &str, value: Option<String>| {
        out.push(Line::Fact(
            name.into(),
            value.unwrap_or_else(|| "not given".into()),
        ))
    };
    out.push(Line::Heading("Board".into()));
    let board = b.baseboard.clone().unwrap_or_default();
    fact(out, "Maker", board.manufacturer);
    fact(out, "Product", board.product);
    if board.version.is_some() {
        fact(out, "Version", board.version);
    }
    out.push(Line::Heading("Firmware".into()));
    let bios = b.bios.clone().unwrap_or_default();
    fact(out, "BIOS vendor", bios.vendor);
    fact(out, "BIOS version", bios.version);
    fact(out, "BIOS date", bios.date);
    if bios.release.is_some() {
        fact(out, "BIOS release", bios.release);
    }
    fact(out, "SMBIOS version", smbios.map(str::to_string));
}

/// The lines of one section, then what could not be read.
pub fn lines(d: &Details, section: Section) -> Vec<Line> {
    let mut out = Vec::new();
    match section {
        Section::Processor => {
            if let Some(p) = &d.processor {
                processor_lines(p, &mut out)
            }
        }
        Section::Memory => {
            if let Some(m) = &d.memory {
                memory_lines(m, &mut out)
            }
        }
        Section::Board => {
            if let Some(b) = &d.board {
                board_lines(b, d.smbios_version.as_deref(), &mut out)
            }
        }
    }
    let items: &[&str] = match section {
        Section::Processor => &["Cores and caches", "Clocks", "Firmware tables (SMBIOS)"],
        Section::Memory => &["Memory in use", "Firmware tables (SMBIOS)"],
        Section::Board => &["Firmware tables (SMBIOS)"],
    };
    for u in d.unread.iter().filter(|u| items.contains(&u.item.as_str())) {
        out.push(Line::Note(format!("{}: not read, {}.", u.item, u.reason)));
    }
    if let Some(cut) = &d.smbios_cut_short {
        out.push(Line::Note(cut.clone()));
    }
    out
}

/// Every section as plain text, for the clipboard.
pub fn copy_text(d: &Details) -> String {
    let mut text = String::new();
    for section in [Section::Processor, Section::Memory, Section::Board] {
        for line in lines(d, section) {
            match line {
                Line::Heading(h) => {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&h);
                    text.push('\n');
                }
                Line::Fact(name, value) => text.push_str(&format!("  {name}: {value}\n")),
                Line::Note(note) => text.push_str(&format!("  {note}\n")),
            }
        }
    }
    text
}

/// Compact rows for the report's hardware section. Serial numbers are never included.
pub fn report_rows(d: &Details) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if let Some(p) = &d.processor {
        let mut cpu = p.brand.clone();
        if let Some(design) = &p.design {
            cpu.push_str(&format!(" ({})", design.name));
        }
        let s = &p.signature;
        cpu.push_str(&format!(
            ", family {:X}h model {:X}h stepping {}",
            s.family, s.model, s.stepping
        ));
        rows.push(("Processor".into(), cpu));
        if let Some(t) = &p.topology {
            let cores: Vec<String> = core_summary(t, p.hybrid)
                .into_iter()
                .filter(|(name, _)| name != "Core types")
                .map(|(name, value)| format!("{name} {value}"))
                .collect();
            rows.push(("Cores".into(), cores.join(", ")));
            let caches: Vec<String> = t
                .caches
                .iter()
                .filter(|c| c.level >= 2)
                .map(|c| format!("L{} {} × {}", c.level, c.count, binary_size(c.size_bytes)))
                .collect();
            if !caches.is_empty() {
                rows.push(("Caches".into(), caches.join(", ")));
            }
        }
        let mut clock = Vec::new();
        if let Some(b) = base_clock(p) {
            clock.push(format!("base {}", mhz(b)));
        }
        if let Some((m, source)) = max_clock(p) {
            clock.push(format!("maximum {} ({source})", mhz(m)));
        }
        if !clock.is_empty() {
            rows.push(("Clocks".into(), clock.join(", ")));
        }
    }
    if let Some(m) = &d.memory {
        let filled: Vec<&MemoryDevice> = m
            .modules
            .iter()
            .filter(|d| d.size_bytes.is_some())
            .collect();
        let slots = m
            .arrays
            .iter()
            .filter_map(|a| a.slots)
            .map(u32::from)
            .sum::<u32>();
        let mut parts = Vec::new();
        for d in &filled {
            let mut text = format!(
                "{} {}",
                d.size_bytes.map(binary_size).unwrap_or_default(),
                d.memory_type
            );
            if let Some(speed) = d.configured_speed_mts.or(d.rated_speed_mts) {
                text.push_str(&format!(" at {}", mts(speed)));
            }
            if let Some(part) = &d.part_number {
                text.push_str(&format!(", {part}"));
            }
            text.push_str(&format!(" in {}", slot_name(d)));
            parts.push(text);
        }
        if !parts.is_empty() {
            let head = if slots > 0 {
                format!("{} of {} slots: ", filled.len(), slots)
            } else {
                String::new()
            };
            rows.push((
                "Memory modules".into(),
                format!("{head}{}", parts.join("; ")),
            ));
        }
        if let Some(c) = &m.channels {
            rows.push(("Memory channels".into(), c.join(", ")));
        }
    }
    if let Some(b) = &d.board {
        if let Some(bios) = &b.bios {
            let text: Vec<String> = [&bios.vendor, &bios.version, &bios.date]
                .into_iter()
                .flatten()
                .cloned()
                .collect();
            if !text.is_empty() {
                rows.push(("BIOS".into(), text.join(", ")));
            }
        }
    }
    if let Some(cut) = &d.smbios_cut_short {
        rows.push(("Firmware table".into(), cut.clone()));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::cpu_memory::smbios::tests::sample;

    fn sample_details() -> Details {
        let decoded = smbios::decode(&smbios::parse_raw(&sample()).unwrap());
        let topology = Topology {
            packages: 1,
            cores: 8,
            logical_processors: 16,
            numa_nodes: 1,
            processor_groups: 1,
            core_classes: vec![topology::CoreClass {
                efficiency_class: 0,
                cores: 8,
                threads: 16,
            }],
            caches: vec![topology::CacheGroup {
                level: 3,
                kind: "unified".into(),
                size_bytes: 96 << 20,
                ways: Some(16),
                line_bytes: 64,
                count: 1,
                shared_by_threads: 16,
            }],
        };
        let clocks = (0..16)
            .map(|n| ProcessorClock {
                processor: n,
                base_mhz: 4201,
                current_mhz: if n == 3 { 3000 } else { 4201 },
                limit_mhz: 4201,
            })
            .collect();
        Details {
            processor: Some(Processor {
                vendor: "AuthenticAMD".into(),
                brand: "AMD Ryzen 7 7800X3D 8-Core Processor".into(),
                signature: cpuid::signature(0x00A6_0F12),
                design: cpuid::design("AuthenticAMD", &cpuid::signature(0x00A6_0F12)),
                instruction_sets: vec![FeatureGroup {
                    group: "AVX".into(),
                    names: vec!["AVX".into(), "AVX2".into()],
                }],
                hybrid: false,
                hypervisor: true,
                topology: Some(topology),
                cpuid_caches: Vec::new(),
                clocks,
                cpuid_base_mhz: None,
                cpuid_max_mhz: None,
                sockets: decoded.sockets.clone(),
            }),
            memory: Some(Memory {
                installed_bytes: Some(32 << 30),
                usable_bytes: 31 << 30,
                available_bytes: 20 << 30,
                committed_bytes: 15 << 30,
                commit_limit_bytes: 40 << 30,
                channels: channels(&decoded.devices),
                arrays: decoded.arrays.clone(),
                modules: decoded.devices.clone(),
                mapped_bytes: Some(32 << 30),
            }),
            board: Some(Board {
                baseboard: decoded.baseboard.clone(),
                bios: decoded.bios.clone(),
            }),
            smbios_version: Some(decoded.version),
            smbios_cut_short: None,
            unread: vec![Unread {
                item: "Clocks".into(),
                reason: "a test said so".into(),
            }],
        }
    }

    #[test]
    fn channels_come_only_from_plain_slot_names() {
        assert_eq!(
            channel_of(&["P0 CHANNEL A", "DIMM 1"]).as_deref(),
            Some("A")
        );
        assert_eq!(
            channel_of(&["BANK 0", "ChannelB-DIMM1"]).as_deref(),
            Some("B")
        );
        assert_eq!(channel_of(&["Channel 2", ""]).as_deref(), Some("2"));
        assert_eq!(channel_of(&["DIMM_A1", "BANK 0"]), None);
        assert_eq!(channel_of(&["Channelized"]), None);
        let d = sample_details();
        assert_eq!(
            d.memory.unwrap().channels,
            Some(vec!["A".into(), "B".into()])
        );
        // One filled slot without a channel name makes the whole answer unknown.
        let mut modules = smbios::decode(&smbios::parse_raw(&sample()).unwrap()).devices;
        modules[1].bank = Some("BANK 0".into());
        modules[1].locator = Some("DIMM_A1".into());
        assert_eq!(channels(&modules), None);
    }

    #[test]
    fn sizes_read_in_the_units_they_are_built_in() {
        assert_eq!(binary_size(32 << 10), "32 KiB");
        assert_eq!(binary_size(1280 << 10), "1.25 MiB");
        assert_eq!(binary_size(96 << 20), "96 MiB");
        assert_eq!(memory_size(16 << 30), "17.2 GB (16 GiB)");
        assert_eq!(memory_size(33_000_000_000), "33.0 GB");
        assert_eq!(mhz(4201), "4,201 MHz");
    }

    #[test]
    fn the_sections_say_what_was_read_and_what_was_not() {
        let d = sample_details();
        let p = lines(&d, Section::Processor);
        let text = |lines: &[Line]| {
            lines
                .iter()
                .map(|l| format!("{l:?}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let pt = text(&p);
        assert!(pt.contains("Zen 4"), "{pt}");
        assert!(pt.contains("25 (19h), 97 (61h), 2"), "{pt}");
        assert!(pt.contains("1 filled of 1; 1 package"), "{pt}");
        assert!(pt.contains("5,050 MHz (as the firmware states it)"), "{pt}");
        assert!(pt.contains("\"Processors 0 to 2\""), "{pt}");
        assert!(pt.contains("\"Processor 3\", \"3,000 MHz now"), "{pt}");
        assert!(pt.contains("\"Processors 4 to 15\""), "{pt}");
        assert!(pt.contains("Clocks: not read, a test said so."), "{pt}");
        assert!(pt.contains("own hypervisor"), "{pt}");
        let mt = text(&lines(&d, Section::Memory));
        assert!(mt.contains("2 filled of 4"), "{mt}");
        assert!(mt.contains("DDR5 at 6,000 MT/s"), "{mt}");
        assert!(mt.contains("A and B (dual channel)"), "{mt}");
        assert!(mt.contains("not read: that needs a kernel driver"), "{mt}");
        assert!(mt.contains("0x0A1B2C3D"), "{mt}");
        assert!(mt.contains("\"P0 CHANNEL A, DIMM 0\", \"empty\""), "{mt}");
        assert!(mt.contains("1.35 V set (1.10 V to 1.35 V)"), "{mt}");
        let bt = text(&lines(&d, Section::Board));
        assert!(
            bt.contains("ROG STRIX B650E-F") && bt.contains("09/12/2024"),
            "{bt}"
        );
        let copied = copy_text(&d);
        assert!(
            copied.starts_with("Processor\n  Name: AMD Ryzen 7 7800X3D"),
            "{copied}"
        );
        assert!(copied.contains("\nBoard\n"));
    }

    #[test]
    fn the_report_never_carries_a_serial_number() {
        let d = sample_details();
        let rows = report_rows(&d);
        let all = format!("{rows:?}");
        assert!(!all.contains("0x0A1B2C3D"), "{all}");
        assert!(
            all.contains(
                "2 of 4 slots: 16 GiB DDR5 at 6,000 MT/s, F5-6000J3238F16G in P0 CHANNEL A, DIMM 1"
            ),
            "{all}"
        );
        assert!(all.contains("L3 1 × 96 MiB"), "{all}");
    }

    #[test]
    fn this_pc_reads_without_serials_unless_asked() {
        let d = details(&DetailsOptions::default());
        let m = d.memory.as_ref().expect("memory");
        assert!(m.modules.iter().all(|m| m.serial.is_none()));
        let p = d.processor.as_ref().expect("processor");
        assert!(!p.brand.is_empty());
        assert!(serde_json::to_string(&d).unwrap().contains("\"brand\""));
    }

    /// The guard: a firmware table whose header gives more bytes than Windows returned is
    /// read only as far as it goes, and the window, the copy and the report say it was cut
    /// short.
    #[test]
    fn a_firmware_table_cut_short_is_said_to_be() {
        let mut raw = smbios::tests::sample();
        let whole = smbios::parse_raw(&raw).unwrap();
        assert_eq!(whole.cut_short, None);
        let present = raw.len() - 8;
        let declared = present + 300;
        raw[4..8].copy_from_slice(&(declared as u32).to_le_bytes());
        let cut = smbios::parse_raw(&raw).unwrap();
        assert_eq!(cut.cut_short, Some((declared, present)));
        assert_eq!(cut.structures, whole.structures);
        let decoded = smbios::decode(&cut);
        let mut d = sample_details();
        d.smbios_cut_short = decoded.cut_short.map(cut_short_text);
        let note = format!("its header gives {declared} bytes and Windows returned {present}");
        for section in [Section::Processor, Section::Memory, Section::Board] {
            let said = lines(&d, section)
                .into_iter()
                .any(|l| matches!(&l, Line::Note(n) if n.contains(&note)));
            assert!(said, "{section:?}");
        }
        assert!(copy_text(&d).contains("was cut short"));
        assert!(report_rows(&d)
            .iter()
            .any(|(k, v)| k == "Firmware table" && v.contains(&note)));
        let code = include_str!("details.rs");
        let read = &code[code.find("pub fn details(").unwrap()..];
        assert!(read[..read.find("\n}\n").unwrap()].contains("t.cut_short).map(cut_short_text)"));
    }
}
