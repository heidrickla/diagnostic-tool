//! A small read-only reader of Windows registry hive files (regf), for the product key in an
//! offline SOFTWARE hive. Every offset and count comes from a file that may be damaged, so
//! each is checked against the bytes there: a damaged hive gives an error, never a panic or
//! a read outside the file.
use std::time::Duration;

use crate::budget::{Budget, Limit, Limits};

/// Where the first hive bin starts; cell offsets count from here.
const BINS: usize = 4096;
/// The most subkey-list levels followed ("ri" lists hold lists); real hives use one or two.
const MAX_LIST_DEPTH: usize = 4;
/// The most entries one key's subkey list or value list may name.
const MAX_ENTRIES: usize = 1 << 20;
/// The most segments of one big value ("db" record).
const MAX_SEGMENTS: usize = 1 << 16;

/// What a read of a hive may spend: 4,194,304 records visited (keys, lists, values), as
/// four lookups through keys of a million subkeys each would take, where a real SOFTWARE
/// hive's lookup of the Windows version key visits a few thousand; 64 MiB of subkey lists
/// and values held, where a big value may claim a gigabyte; 30 seconds. The hive's bytes
/// are already in memory, read by the caller within its own limit. Subkey lists nested
/// more than `MAX_LIST_DEPTH` deep are damage and reported as such.
pub const LIMITS: Limits = Limits {
    what: "the read of the registry",
    unit: "registry records",
    count: 1 << 22,
    bytes: u64::MAX,
    memory: 64 << 20,
    depth: MAX_LIST_DEPTH as u32,
    nested: "subkey lists",
    time: Some(Duration::from_secs(30)),
};

/// Registry value types this reader names.
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;

/// A hive file held in memory, read within a budget.
pub struct Hive<'a, 'b, 'c> {
    bytes: &'a [u8],
    root: u32,
    /// The two sequence numbers in the header differ: the hive was not saved cleanly and
    /// its log files may hold changes this reader does not apply.
    pub dirty: bool,
    minor: u32,
    budget: &'b mut Budget<'c>,
}

/// A key: its cell offset in the hive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key(u32);

/// A value's type and data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub kind: u32,
    pub data: Vec<u8>,
}

impl Value {
    /// A REG_SZ or REG_EXPAND_SZ value as text, without its ending NUL.
    pub fn text(&self) -> Option<String> {
        if self.kind != REG_SZ && self.kind != REG_EXPAND_SZ {
            return None;
        }
        let units: Vec<u16> = self
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|u| *u != 0)
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    pub fn dword(&self) -> Option<u32> {
        (self.kind == REG_DWORD && self.data.len() >= 4)
            .then(|| u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
    }
}

fn damaged(what: &str) -> String {
    format!("the registry file is damaged: {what}")
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    at.checked_add(2)
        .and_then(|end| b.get(at..end))
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| damaged("a record runs past its end"))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    at.checked_add(4)
        .and_then(|end| b.get(at..end))
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| damaged("a record runs past its end"))
}

/// A key or value name: Latin-1 when stored compressed, else UTF-16LE.
fn name_text(raw: &[u8], compressed: bool) -> String {
    if compressed {
        raw.iter().map(|b| char::from(*b)).collect()
    } else {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

impl<'a, 'b, 'c> Hive<'a, 'b, 'c> {
    /// Checks the header and finds the root key; every record visited after is charged to
    /// `budget` (made from `LIMITS`), and a read that passes it ends with an error saying
    /// which limit it reached.
    pub fn parse(bytes: &'a [u8], budget: &'b mut Budget<'c>) -> Result<Self, String> {
        if bytes.len() < BINS {
            return Err(damaged("it is shorter than its header"));
        }
        if &bytes[0..4] != b"regf" {
            return Err("this is not a registry file (no regf signature)".into());
        }
        let (seq1, seq2) = (u32_at(bytes, 4)?, u32_at(bytes, 8)?);
        let minor = u32_at(bytes, 0x18)?;
        let root = u32_at(bytes, 0x24)?;
        let mut hive = Hive {
            bytes,
            root,
            dirty: seq1 != seq2,
            minor,
            budget,
        };
        let key = hive.cell(root)?;
        if key.get(0..2) != Some(b"nk") {
            return Err(damaged("its root key record is not a key"));
        }
        Ok(hive)
    }

    pub fn root(&self) -> Key {
        Key(self.root)
    }

    /// The words for a limit of the budget reached.
    fn limited(&self, limit: Limit) -> String {
        self.budget
            .said()
            .unwrap_or_else(|| format!("the read of the registry stopped at {limit:?}"))
    }

    /// Charges `n` bytes held.
    fn hold(&mut self, n: usize) -> Result<(), String> {
        self.budget.hold(n as u64).map_err(|l| self.limited(l))
    }

    /// The data of the allocated cell at `offset`, without its size field, counted as one
    /// record visited.
    fn cell(&mut self, offset: u32) -> Result<&'a [u8], String> {
        self.budget.item().map_err(|l| self.limited(l))?;
        let at = BINS
            .checked_add(offset as usize)
            .filter(|at| at.checked_add(4).is_some_and(|end| end <= self.bytes.len()))
            .ok_or_else(|| damaged("a record points outside the file"))?;
        let size = u32_at(self.bytes, at)? as i32;
        // A used cell has a negative size, its length including the size field.
        if size >= 0 {
            return Err(damaged("a record points at free space"));
        }
        let len = size.unsigned_abs() as usize;
        if len < 4 {
            return Err(damaged("a record has no room for its data"));
        }
        at.checked_add(len)
            .and_then(|end| self.bytes.get(at + 4..end))
            .ok_or_else(|| damaged("a record runs past the end of the file"))
    }

    /// A key's name.
    pub fn name(&mut self, key: Key) -> Result<String, String> {
        let nk = self.nk(key)?;
        let flags = u16_at(nk, 0x02)?;
        let len = usize::from(u16_at(nk, 0x48)?);
        let raw = nk
            .get(0x4C..0x4C + len)
            .ok_or_else(|| damaged("a key's name runs past its record"))?;
        Ok(name_text(raw, flags & 0x20 != 0))
    }

    fn nk(&mut self, key: Key) -> Result<&'a [u8], String> {
        let nk = self.cell(key.0)?;
        if nk.get(0..2) != Some(b"nk") || nk.len() < 0x4C {
            return Err(damaged("a key record is not a key"));
        }
        Ok(nk)
    }

    /// The subkeys of `key`.
    pub fn subkeys(&mut self, key: Key) -> Result<Vec<Key>, String> {
        let nk = self.nk(key)?;
        let count = u32_at(nk, 0x14)? as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > MAX_ENTRIES {
            return Err(damaged("a key claims too many subkeys"));
        }
        let mut out = Vec::new();
        self.list(u32_at(nk, 0x1C)?, 0, &mut out)?;
        // The list is let go when the caller is done with it.
        self.budget
            .free((out.len() * std::mem::size_of::<Key>()) as u64);
        Ok(out)
    }

    /// Appends the keys a subkey list names: lf and lh (offset and hash), li (offsets),
    /// ri (offsets of other lists).
    fn list(&mut self, offset: u32, depth: usize, out: &mut Vec<Key>) -> Result<(), String> {
        if depth > MAX_LIST_DEPTH {
            return Err(damaged("subkey lists nest too deeply"));
        }
        // Lists that name each other many times over would take forever; each visit is a
        // record charged to the budget, where real ones are visited about once per subkey.
        let list = self.cell(offset)?;
        let kind = list
            .get(0..2)
            .ok_or_else(|| damaged("a subkey list is empty"))?;
        let count = usize::from(u16_at(list, 2)?);
        let stride = match kind {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => return Err(damaged("a subkey list is of no known kind")),
        };
        if 4 + count * stride > list.len() {
            return Err(damaged("a subkey list runs past its record"));
        }
        if kind != b"ri" {
            self.hold(count * std::mem::size_of::<Key>())?;
        }
        for i in 0..count {
            let item = u32_at(list, 4 + i * stride)?;
            if kind == b"ri" {
                self.list(item, depth + 1, out)?;
            } else {
                if out.len() >= MAX_ENTRIES {
                    return Err(damaged("a key holds too many subkeys"));
                }
                out.push(Key(item));
            }
        }
        Ok(())
    }

    /// The subkey of `key` named `name`, ignoring case.
    pub fn subkey(&mut self, key: Key, name: &str) -> Result<Option<Key>, String> {
        for sub in self.subkeys(key)? {
            if self.name(sub)?.to_lowercase() == name.to_lowercase() {
                return Ok(Some(sub));
            }
        }
        Ok(None)
    }

    /// The key at `path` below the root, its parts separated by backslashes.
    pub fn open(&mut self, path: &str) -> Result<Option<Key>, String> {
        let mut key = self.root();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match self.subkey(key, part)? {
                Some(sub) => key = sub,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// The value of `key` named `name`, ignoring case; "" is the default value.
    pub fn value(&mut self, key: Key, name: &str) -> Result<Option<Value>, String> {
        let nk = self.nk(key)?;
        let count = u32_at(nk, 0x24)? as usize;
        if count == 0 {
            return Ok(None);
        }
        if count > MAX_ENTRIES {
            return Err(damaged("a key claims too many values"));
        }
        let list = self.cell(u32_at(nk, 0x28)?)?;
        if count * 4 > list.len() {
            return Err(damaged("a value list runs past its record"));
        }
        for i in 0..count {
            let vk = self.cell(u32_at(list, i * 4)?)?;
            if vk.get(0..2) != Some(b"vk") || vk.len() < 0x14 {
                return Err(damaged("a value record is not a value"));
            }
            let len = usize::from(u16_at(vk, 0x02)?);
            let flags = u16_at(vk, 0x10)?;
            let raw = vk
                .get(0x14..0x14 + len)
                .ok_or_else(|| damaged("a value's name runs past its record"))?;
            let this = name_text(raw, flags & 0x01 != 0);
            if this.to_lowercase() == name.to_lowercase() {
                return self.value_data(vk).map(Some);
            }
        }
        Ok(None)
    }

    fn value_data(&mut self, vk: &[u8]) -> Result<Value, String> {
        let size = u32_at(vk, 0x04)?;
        let offset = u32_at(vk, 0x08)?;
        let kind = u32_at(vk, 0x0C)?;
        // The top bit marks data of up to 4 bytes held in the offset field itself.
        if size & 0x8000_0000 != 0 {
            let len = (size & 0x7FFF_FFFF) as usize;
            if len > 4 {
                return Err(damaged("a value claims more bytes than it can hold"));
            }
            return Ok(Value {
                kind,
                data: offset.to_le_bytes()[..len].to_vec(),
            });
        }
        let len = size as usize;
        self.hold(len)?;
        let cell = self.cell(offset)?;
        // Hives from version 1.4 hold data over 16344 bytes in segments ("db").
        if len > 16344 && self.minor >= 4 && cell.get(0..2) == Some(b"db") {
            return self.big_data(cell, len).map(|data| Value { kind, data });
        }
        let data = cell
            .get(..len)
            .ok_or_else(|| damaged("a value's data runs past its record"))?;
        Ok(Value {
            kind,
            data: data.to_vec(),
        })
    }

    fn big_data(&mut self, db: &[u8], len: usize) -> Result<Vec<u8>, String> {
        let count = usize::from(u16_at(db, 2)?);
        if count == 0 || count > MAX_SEGMENTS {
            return Err(damaged("a large value has no segments"));
        }
        let list = self.cell(u32_at(db, 4)?)?;
        if count * 4 > list.len() {
            return Err(damaged("a large value's segment list runs past its record"));
        }
        let mut data = Vec::new();
        for i in 0..count {
            let segment = self.cell(u32_at(list, i * 4)?)?;
            let take = (len - data.len()).min(16344).min(segment.len());
            data.extend_from_slice(&segment[..take]);
            if data.len() == len {
                break;
            }
        }
        if data.len() < len {
            return Err(damaged("a large value is shorter than it says"));
        }
        Ok(data)
    }
}

/// What the registry says of the Windows installation and its key.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Windows {
    /// "Windows 11 Pro".
    pub product: Option<String>,
    pub edition: Option<String>,
    /// "23H2".
    pub version: Option<String>,
    pub build: Option<String>,
    /// The product ID, which names the licence channel ("...-AAOEM" for a key from the PC's
    /// firmware).
    pub product_id: Option<String>,
    /// The key decoded from DigitalProductId.
    pub key: Option<String>,
    /// Why a key the registry records could not be read, when it could not.
    #[serde(default)]
    pub key_unread: Option<String>,
    /// Whether the hive was saved cleanly.
    pub dirty: bool,
}

/// Reads the installation's name and key from a SOFTWARE hive, within `budget` (made from
/// `LIMITS`).
pub fn windows(bytes: &[u8], budget: &mut Budget) -> Result<Windows, String> {
    let mut hive = Hive::parse(bytes, budget)?;
    let key = hive
        .open(r"Microsoft\Windows NT\CurrentVersion")?
        .ok_or("the registry has no Windows version key (Microsoft\\Windows NT\\CurrentVersion)")?;
    let mut text = |name: &str| -> Result<Option<String>, String> {
        Ok(hive
            .value(key, name)?
            .and_then(|v| v.text())
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty()))
    };
    let build = text("CurrentBuildNumber")?.or(text("CurrentBuild")?);
    let mut product = text("ProductName")?;
    // Windows 11 still names itself Windows 10 here; its build numbers start at 22000.
    if let (Some(name), Some(number)) = (
        &product,
        build.as_deref().and_then(|b| b.parse::<u32>().ok()),
    ) {
        if number >= 22000 && name.contains("Windows 10") {
            product = Some(name.replace("Windows 10", "Windows 11"));
        }
    }
    let edition = text("EditionID")?;
    let version = text("DisplayVersion")?.or(text("ReleaseId")?);
    let product_id = text("ProductId")?;
    let dirty = hive.dirty;
    // A key recorded but too short to hold one is said, not taken for no key at all.
    let (key, key_unread) = match hive.value(key, "DigitalProductId")? {
        None => (None, None),
        Some(v) => match decode_key(&v.data) {
            Some(k) => (Some(k), None),
            None => (
                None,
                Some(format!(
                    "its record (DigitalProductId) is {} bytes, too short to hold a key",
                    v.data.len()
                )),
            ),
        },
    };
    Ok(Windows {
        product,
        edition,
        version,
        build,
        product_id,
        key,
        key_unread,
        dirty,
    })
}

const KEY_DIGITS: &[u8; 24] = b"BCDFGHJKMPQRTVWXY2346789";

/// The product key held in a DigitalProductId value, in the form Windows 8 and later use
/// (with the letter N placed by the last digit) or the older one. None when the value is
/// too short to hold one.
pub fn decode_key(id: &[u8]) -> Option<String> {
    let mut key: [u8; 15] = id.get(52..67)?.try_into().ok()?;
    // Bit 3 of the top byte marks the newer form; a key's own number never reaches it,
    // since 24 to the 25th is below 2 to the 115th.
    let win8 = (key[14] >> 3) & 1;
    key[14] &= 0xF7;
    let mut out = [0u8; 25];
    let mut last = 0usize;
    for i in (0..25).rev() {
        let mut current = 0u32;
        for j in (0..15).rev() {
            current = current * 256 + u32::from(key[j]);
            key[j] = (current / 24) as u8;
            current %= 24;
        }
        out[i] = KEY_DIGITS[current as usize];
        last = current as usize;
    }
    let mut chars: Vec<u8> = out.to_vec();
    if win8 == 1 {
        chars.remove(0);
        chars.insert(last, b'N');
    }
    let text = String::from_utf8(chars).ok()?;
    let groups: Vec<&str> = (0..5).map(|g| &text[g * 5..g * 5 + 5]).collect();
    Some(groups.join("-"))
}

/// What kind of key it is, for the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// A key of the customer's own, which can be used again.
    Own,
    /// All B: Windows holds no key here; it is activated by a digital licence or a key in
    /// the PC's firmware.
    Blank,
    /// The generic key Windows installs for an edition activated by a digital licence.
    Generic(&'static str),
    /// A generic key for activation by an organisation's own activation server (KMS).
    Volume(&'static str),
}

/// The generic keys Windows 10 and 11 install for each edition when the licence is
/// digital (no key of the customer's own).
const GENERIC: &[(&str, &str)] = &[
    ("YTMG3-N6DKC-DKB77-7M9GH-8HVX7", "Home"),
    ("4CPRK-NM3K3-X6XXQ-RXX86-WXCHW", "Home N"),
    ("BT79Q-G7N6G-PGBYW-4YWX6-6F4BT", "Home Single Language"),
    ("N2434-X9D7W-8PF6X-8DV9T-8TYMD", "Home China"),
    ("VK7JG-NPHTM-C97JM-9MPGT-3V66T", "Pro"),
    ("2B87N-8KFHP-DKV6R-Y2C8J-PKCKT", "Pro N"),
    ("DXG7C-N36C4-C4HTG-X4T3X-2YV77", "Pro for Workstations"),
    ("WYPNQ-8C467-V2W6J-TX4WX-WT2RQ", "Pro for Workstations N"),
    ("8PTT6-RNW4C-6V7J2-C2D3X-MHBPB", "Pro Education"),
    ("GJTYN-HDMQY-FRR76-HVGC7-QPF8P", "Pro Education N"),
    ("YNMGQ-8RYV3-4PGQ3-C8XTP-7CFBY", "Education"),
    ("84NGF-MHBT6-FXBX8-QWJK7-DRR8H", "Education N"),
    ("XGVPP-NMH47-7TTHJ-W3FW7-8HV2C", "Enterprise"),
    ("WGGHN-J84D6-QYCPR-T7PJ7-X766F", "Enterprise N"),
];

/// Microsoft's published KMS client keys for Windows 10 and 11, as printed on
/// learn.microsoft.com "Key Management Services (KMS) client activation and product keys"
/// (page dated 2 April 2026).
const VOLUME: &[(&str, &str)] = &[
    ("W269N-WFGWX-YVC9B-4J6C9-T83GX", "Pro"),
    ("MH37W-N47XK-V7XM9-C7227-GCQG9", "Pro N"),
    ("NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J", "Pro for Workstations"),
    ("9FNHH-K3HBT-3W4TD-6383H-6XYWF", "Pro for Workstations N"),
    ("6TP4R-GNPTD-KYYHQ-7B7DP-J447Y", "Pro Education"),
    ("YVWGF-BXNMC-HTQYQ-CPQ99-66QFC", "Pro Education N"),
    ("NW6C2-QMPVW-D7KKK-3GKT6-VCFB2", "Education"),
    ("2WH4N-8QGBV-H22JP-CT43Q-MDWWJ", "Education N"),
    ("NPPR9-FWDCX-D2C8J-H872K-2YT43", "Enterprise"),
    ("DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4", "Enterprise N"),
    ("YYVX9-NTFWV-6MDM3-9PT4T-4M68B", "Enterprise G"),
    ("44RPN-FTY23-9VTTB-MP9BX-T84FV", "Enterprise G N"),
    ("M7XTQ-FN8P6-TTKYV-9D4CC-J462D", "Enterprise LTSC"),
    ("92NFX-8DJQP-P6BBQ-THF9C-7CG2H", "Enterprise N LTSC"),
    ("KBN8V-HFGQ4-MGXVD-347P6-PDQGT", "IoT Enterprise LTSC"),
    ("DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ", "Enterprise LTSB 2016"),
    ("QFFDN-GRT3P-VKWWX-X7T3R-8B639", "Enterprise N LTSB 2016"),
    ("WNMTR-4C88C-JK8YV-HQ7T2-76DF9", "Enterprise LTSB 2015"),
    ("2F77B-TNFGY-69QQF-B8YKP-D69TJ", "Enterprise N LTSB 2015"),
];

pub fn key_kind(key: &str) -> KeyKind {
    if key.chars().all(|c| c == 'B' || c == '-') {
        return KeyKind::Blank;
    }
    if let Some((_, edition)) = GENERIC.iter().find(|(k, _)| *k == key) {
        return KeyKind::Generic(edition);
    }
    if let Some((_, edition)) = VOLUME.iter().find(|(k, _)| *k == key) {
        return KeyKind::Volume(edition);
    }
    KeyKind::Own
}

/// Whether the product ID names the OEM channel, whose key the PC maker put in its
/// firmware ("00330-80000-00000-AAOEM").
pub fn oem(product_id: &str) -> bool {
    product_id.to_ascii_uppercase().contains("OEM")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> Result<Windows, String> {
        windows(bytes, &mut Budget::new(LIMITS, None))
    }

    /// The inverse of `decode_key`, for tests: a key's 25 characters as DigitalProductId
    /// bytes 52 to 66.
    pub(crate) fn encode_key(key: &str) -> Vec<u8> {
        let chars: Vec<u8> = key.bytes().filter(|c| *c != b'-').collect();
        assert_eq!(chars.len(), 25);
        let n_at = chars.iter().position(|c| *c == b'N');
        // Undo the N: it sits at `last`; the digit string is the rest with one digit before.
        let digits: Vec<u8> = match n_at {
            Some(at) => {
                let mut rest = chars.clone();
                rest.remove(at);
                // The first digit is any digit whose value is `at`; it is the one dropped.
                let mut all = vec![KEY_DIGITS[at]];
                all.extend(rest);
                all
            }
            None => chars,
        };
        let mut number = [0u8; 15];
        for d in &digits {
            let value = KEY_DIGITS.iter().position(|k| k == d).unwrap() as u32;
            // number = number * 24 + value, little-endian.
            let mut carry = value;
            for byte in number.iter_mut() {
                let v = u32::from(*byte) * 24 + carry;
                *byte = (v & 0xFF) as u8;
                carry = v >> 8;
            }
            assert_eq!(carry, 0);
        }
        if n_at.is_some() {
            number[14] |= 0x08;
        }
        let mut id = vec![0u8; 164];
        id[52..67].copy_from_slice(&number);
        id
    }

    #[test]
    fn keys_decode_with_and_without_the_n_and_blank_ones_read_as_all_b() {
        for key in [
            "VK7JG-NPHTM-C97JM-9MPGT-3V66T",
            "YTMG3-N6DKC-DKB77-7M9GH-8HVX7",
            "W269N-WFGWX-YVC9B-4J6C9-T83GX",
            "NPPR9-FWDCX-D2C8J-H872K-2YT43",
        ] {
            assert_eq!(decode_key(&encode_key(key)).as_deref(), Some(key));
        }
        assert_eq!(
            decode_key(&[0u8; 164]).as_deref(),
            Some("BBBBB-BBBBB-BBBBB-BBBBB-BBBBB")
        );
        assert_eq!(decode_key(&[0u8; 66]), None);
        assert_eq!(key_kind("BBBBB-BBBBB-BBBBB-BBBBB-BBBBB"), KeyKind::Blank);
        assert_eq!(
            key_kind("VK7JG-NPHTM-C97JM-9MPGT-3V66T"),
            KeyKind::Generic("Pro")
        );
        assert_eq!(
            key_kind("W269N-WFGWX-YVC9B-4J6C9-T83GX"),
            KeyKind::Volume("Pro")
        );
        assert!(oem("00330-80000-00000-AAOEM"));
        assert!(!oem("00330-80000-00000-AA442"));
    }

    /// Reads a SOFTWARE hive saved from a real Windows (`reg save HKLM\SOFTWARE <file>` as
    /// administrator), named by DIAGTOOL_HIVE, within the real budget, and prints what it
    /// spent and what it found; of the key only whether it was read and its length.
    #[test]
    #[ignore = "reads a saved SOFTWARE hive named by DIAGTOOL_HIVE"]
    fn live_a_saved_software_hive_reads_within_its_budget() {
        let bytes = std::fs::read(std::env::var("DIAGTOOL_HIVE").unwrap()).unwrap();
        let started = std::time::Instant::now();
        let mut budget = Budget::new(LIMITS, None);
        let found = windows(&bytes, &mut budget).unwrap();
        println!(
            "hive {} bytes read in {:.3} s; spent {:?}; limit reached: {:?}",
            bytes.len(),
            started.elapsed().as_secs_f64(),
            budget.spent(),
            budget.said()
        );
        println!(
            "product {:?}, version {:?}, build {:?}; key read: {}, its length {}; unread: {:?}",
            found.product,
            found.version,
            found.build,
            found.key.is_some(),
            found.key.as_ref().map_or(0, String::len),
            found.key_unread
        );
        assert_eq!(budget.hit(), None);
        assert!(found.product.is_some());
    }

    /// Needs a Windows PC whose licensing service kept its key in BackupProductKeyDefault:
    /// the key decoded from this PC's own DigitalProductId must equal it. Prints only
    /// whether they match and what kind of key it is, never the key.
    #[test]
    #[ignore = "reads this PC's registry"]
    fn this_pcs_digital_product_id_decodes_to_its_backup_key() {
        let query = |key: &str, value: &str| -> String {
            let out = std::process::Command::new("reg")
                .args(["query", key, "/v", value])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find(|l| l.contains(value))
                .and_then(|l| l.split_whitespace().last())
                .unwrap_or_default()
                .to_string()
        };
        let hex = query(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "DigitalProductId",
        );
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let decoded = decode_key(&bytes).unwrap();
        let backup = query(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
            "BackupProductKeyDefault",
        );
        println!(
            "DigitalProductId {} bytes; decoded key equals BackupProductKeyDefault: {}; kind {:?}",
            bytes.len(),
            decoded == backup,
            key_kind(&decoded)
        );
        // Not assert_eq: a failure must not print either key.
        assert!(
            decoded == backup,
            "the decoded key differs from the backup key"
        );
    }

    /// A hive made by hand: header, one bin, a root key with one subkey path
    /// Microsoft\Windows NT\CurrentVersion holding the values given.
    pub(crate) fn tiny_hive(values: &[(&str, u32, Vec<u8>)]) -> Vec<u8> {
        let mut bin: Vec<u8> = b"hbin".to_vec();
        bin.extend_from_slice(&0u32.to_le_bytes());
        bin.extend_from_slice(&0u32.to_le_bytes()); // size, set below
        bin.resize(32, 0);
        fn cell(bin: &mut Vec<u8>, data: &[u8]) -> u32 {
            let at = bin.len() as u32;
            let len = (4 + data.len()).div_ceil(8) * 8;
            bin.extend_from_slice(&(-(len as i32)).to_le_bytes());
            bin.extend_from_slice(data);
            bin.resize(at as usize + len, 0);
            at
        }
        fn nk(name: &str, subkeys: u32, list: u32, values: u32, value_list: u32) -> Vec<u8> {
            let mut k = vec![0u8; 0x4C];
            k[0..2].copy_from_slice(b"nk");
            k[2..4].copy_from_slice(&0x20u16.to_le_bytes());
            k[0x14..0x18].copy_from_slice(&subkeys.to_le_bytes());
            k[0x1C..0x20].copy_from_slice(&list.to_le_bytes());
            k[0x24..0x28].copy_from_slice(&values.to_le_bytes());
            k[0x28..0x2C].copy_from_slice(&value_list.to_le_bytes());
            k[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
            k.extend_from_slice(name.as_bytes());
            k
        }
        let mut offsets = Vec::new();
        for (name, kind, data) in values {
            let data_at = cell(&mut bin, data);
            let mut vk = vec![0u8; 0x14];
            vk[0..2].copy_from_slice(b"vk");
            vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            vk[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            vk[8..12].copy_from_slice(&data_at.to_le_bytes());
            vk[12..16].copy_from_slice(&kind.to_le_bytes());
            vk[16..18].copy_from_slice(&1u16.to_le_bytes());
            vk.extend_from_slice(name.as_bytes());
            offsets.push(cell(&mut bin, &vk));
        }
        let value_list: Vec<u8> = offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
        let value_list = cell(&mut bin, &value_list);
        let mut child = cell(
            &mut bin,
            &nk("CurrentVersion", 0, 0, offsets.len() as u32, value_list),
        );
        for name in ["Windows NT", "Microsoft"] {
            let mut lf = b"lf".to_vec();
            lf.extend_from_slice(&1u16.to_le_bytes());
            lf.extend_from_slice(&child.to_le_bytes());
            lf.extend_from_slice(&0u32.to_le_bytes());
            let list = cell(&mut bin, &lf);
            child = cell(&mut bin, &nk(name, 1, list, 0, 0));
        }
        let mut li = b"li".to_vec();
        li.extend_from_slice(&1u16.to_le_bytes());
        li.extend_from_slice(&child.to_le_bytes());
        let list = cell(&mut bin, &li);
        let root = cell(&mut bin, &nk("ROOT", 1, list, 0, 0));
        bin.resize(bin.len().div_ceil(4096) * 4096, 0);
        let size = bin.len() as u32;
        bin[8..12].copy_from_slice(&size.to_le_bytes());
        let mut hive = vec![0u8; BINS];
        hive[0..4].copy_from_slice(b"regf");
        hive[4..8].copy_from_slice(&1u32.to_le_bytes());
        hive[8..12].copy_from_slice(&1u32.to_le_bytes());
        hive[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        hive[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
        hive[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        hive[0x28..0x2C].copy_from_slice(&size.to_le_bytes());
        hive.extend(bin);
        hive
    }

    fn sz(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(|u| u.to_le_bytes())
            .collect()
    }

    fn sample() -> Vec<u8> {
        tiny_hive(&[
            ("ProductName", REG_SZ, sz("Windows 10 Pro")),
            ("EditionID", REG_SZ, sz("Professional")),
            ("CurrentBuildNumber", REG_SZ, sz("22631")),
            ("ProductId", REG_SZ, sz("00330-80000-00000-AA442")),
            (
                "DigitalProductId",
                REG_BINARY,
                encode_key("VK7JG-NPHTM-C97JM-9MPGT-3V66T"),
            ),
            ("InstallDate", REG_DWORD, 7u32.to_le_bytes().to_vec()),
        ])
    }

    #[test]
    fn a_hive_gives_the_version_and_key() {
        let bytes = sample();
        let found = read(&bytes).unwrap();
        assert_eq!(found.product.as_deref(), Some("Windows 11 Pro"));
        assert_eq!(found.edition.as_deref(), Some("Professional"));
        assert_eq!(found.key.as_deref(), Some("VK7JG-NPHTM-C97JM-9MPGT-3V66T"));
        assert!(!found.dirty);
        let mut budget = Budget::new(LIMITS, None);
        let mut hive = Hive::parse(&bytes, &mut budget).unwrap();
        let key = hive
            .open(r"microsoft\WINDOWS NT\currentversion")
            .unwrap()
            .unwrap();
        assert_eq!(
            hive.value(key, "installdate").unwrap().unwrap().dword(),
            Some(7)
        );
        assert_eq!(hive.open(r"Microsoft\Nothing").unwrap(), None);
    }

    /// The guard: a product key record too short to hold a key is said, not taken for no
    /// key recorded.
    #[test]
    fn a_short_product_key_record_is_said() {
        let bytes = tiny_hive(&[("DigitalProductId", REG_BINARY, vec![1; 40])]);
        let found = read(&bytes).unwrap();
        assert_eq!(found.key, None);
        assert_eq!(
            found.key_unread.as_deref(),
            Some("its record (DigitalProductId) is 40 bytes, too short to hold a key")
        );
        assert_eq!(read(&tiny_hive(&[])).unwrap().key_unread, None);
    }

    /// The guard: a value claiming a gigabyte of segments, and lists naming each other
    /// millions of times, stop within the hive's budget of memory and records, saying
    /// which limit they reached.
    #[test]
    fn a_hostile_hive_stops_within_its_budget() {
        let started = std::time::Instant::now();
        // A value of 1 GiB, past the 64 MiB the read holds.
        let mut bytes = tiny_hive(&[("DigitalProductId", REG_BINARY, vec![1; 200])]);
        let at = bytes
            .windows(16)
            .position(|w| w == b"DigitalProductId")
            .unwrap();
        // The value record's size field is 0x14 before its name.
        let size_at = at - 0x14 + 4;
        bytes[size_at..size_at + 4].copy_from_slice(&(1u32 << 30).to_le_bytes());
        let err = read(&bytes).unwrap_err();
        assert!(err.contains("memory limit of 67.1 MB"), "{err}");
        let small = Limits { count: 3, ..LIMITS };
        let err = windows(&sample(), &mut Budget::new(small, None)).unwrap_err();
        assert!(err.contains("limit of 3 registry records"), "{err}");
        assert!(started.elapsed().as_secs() < 10);
    }

    /// The guard: a hive cut at any length gives an error or what it holds, never a panic.
    #[test]
    fn a_truncated_hive_never_panics() {
        let bytes = sample();
        for len in 0..bytes.len() {
            let cut = &bytes[..len];
            let result = std::panic::catch_unwind(|| read(cut));
            assert!(result.is_ok(), "a hive cut at {len} bytes panicked");
            if len < bytes.len() - 4096 {
                assert!(
                    result.unwrap().is_err(),
                    "a hive cut at {len} bytes read whole"
                );
            }
        }
    }

    /// The guard: every byte of the hive set to each of a few values gives an error or an
    /// answer, never a panic or a read outside the file.
    #[test]
    fn a_corrupted_hive_never_panics() {
        let bytes = sample();
        for at in 0..bytes.len() {
            for value in [0x00u8, 0x7F, 0x80, 0xFF] {
                let mut broken = bytes.clone();
                broken[at] = value;
                let result = std::panic::catch_unwind(|| read(&broken));
                assert!(result.is_ok(), "byte {at} set to {value:#x} panicked");
            }
        }
        // Offsets pointing at the end of the file, and lists claiming huge counts.
        let mut broken = bytes.clone();
        broken[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read(&broken).is_err());
        assert!(read(b"regf").is_err());
        assert!(read(&[0u8; 8192]).is_err());
    }

    /// The guard: lists that name the next level thousands of times over end with an
    /// error after a bounded number of visits, not after billions.
    #[test]
    fn lists_that_name_each_other_many_times_end() {
        const N: usize = 2000;
        let mut bin = vec![0u8; 32];
        bin[0..4].copy_from_slice(b"hbin");
        fn put(bin: &mut Vec<u8>, data: &[u8]) -> u32 {
            let at = bin.len() as u32;
            let len = (4 + data.len()).div_ceil(8) * 8;
            bin.extend_from_slice(&(-(len as i32)).to_le_bytes());
            bin.extend_from_slice(data);
            bin.resize(at as usize + len, 0);
            at
        }
        let mut next = put(&mut bin, b"lf\0\0");
        for _ in 0..3 {
            let mut ri = b"ri".to_vec();
            ri.extend_from_slice(&(N as u16).to_le_bytes());
            for _ in 0..N {
                ri.extend_from_slice(&next.to_le_bytes());
            }
            next = put(&mut bin, &ri);
        }
        let mut nk = vec![0u8; 0x4C];
        nk[0..2].copy_from_slice(b"nk");
        nk[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        nk[0x1C..0x20].copy_from_slice(&next.to_le_bytes());
        let root = put(&mut bin, &nk);
        bin.resize(bin.len().div_ceil(4096) * 4096, 0);
        let mut hive = vec![0u8; BINS];
        hive[0..4].copy_from_slice(b"regf");
        hive[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        hive.extend(bin);
        let mut budget = Budget::new(LIMITS, None);
        let mut parsed = Hive::parse(&hive, &mut budget).unwrap();
        let started = std::time::Instant::now();
        assert!(parsed.subkeys(parsed.root()).is_err());
        assert!(started.elapsed().as_secs() < 10);
    }

    /// The guard: subkey lists that point at each other end with an error, not a loop.
    #[test]
    fn a_list_that_points_at_itself_ends() {
        let mut bin = vec![0u8; 32];
        bin[0..4].copy_from_slice(b"hbin");
        // An ri list at offset 32 naming itself.
        let mut ri = vec![0u8; 16];
        ri[0..4].copy_from_slice(&(-16i32).to_le_bytes());
        ri[4..6].copy_from_slice(b"ri");
        ri[6..8].copy_from_slice(&1u16.to_le_bytes());
        ri[8..12].copy_from_slice(&32u32.to_le_bytes());
        bin.extend(ri);
        let mut nk = vec![0u8; 0x4C];
        nk[0..2].copy_from_slice(b"nk");
        nk[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        nk[0x1C..0x20].copy_from_slice(&32u32.to_le_bytes());
        let root = bin.len() as u32;
        let len = (4 + nk.len()).div_ceil(8) * 8;
        bin.extend_from_slice(&(-(len as i32)).to_le_bytes());
        bin.extend(nk);
        bin.resize(4096, 0);
        let mut hive = vec![0u8; BINS];
        hive[0..4].copy_from_slice(b"regf");
        hive[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        hive.extend(bin);
        let mut budget = Budget::new(LIMITS, None);
        let mut parsed = Hive::parse(&hive, &mut budget).unwrap();
        assert!(parsed.subkeys(parsed.root()).is_err());
    }
}
