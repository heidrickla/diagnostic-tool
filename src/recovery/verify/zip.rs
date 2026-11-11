//! ZIP and the formats built on it (Word, Excel, PowerPoint, OpenDocument, EPUB): the end
//! record and the central directory found and consistent, every entry's local header where
//! the directory says, every entry decompressed and its CRC-32 checked, and an Office or
//! OpenDocument file's main part present.
use super::{damaged, good, say, unsupported, Data, Fault, Good, Res};

/// The most entries this check reads; a larger archive is not checked, and says so.
const MAX_ENTRIES: u64 = 1_000_000;
/// The most bytes of a part read for its text (the package relationships, the mimetype).
const MAX_PART: usize = 1 << 20;

struct Entry {
    name: Vec<u8>,
    flags: u64,
    method: u64,
    crc: u64,
    packed: u64,
    size: u64,
    local: u64,
}

const OFFICE: [&str; 14] = [
    "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "pptx", "pptm", "potx", "ppsx",
    "ppsm", "vsdx",
];
const OPEN_DOCUMENT: [&str; 7] = ["odt", "ods", "odp", "odg", "ott", "ots", "otp"];

fn text(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// The end of central directory record: (where it is, entries, directory size, directory
/// offset, where the directory must end).
fn end_record(d: &mut Data) -> Res<(u64, u64, u64, u64, u64)> {
    if d.len < 22 {
        return damaged("cut short: it is too small to hold a ZIP table of contents");
    }
    let from = d.len.saturating_sub(22 + 65535);
    let tail = d.upto(from, (d.len - from) as usize)?;
    let found = (0..=tail.len() - 22).rev().find(|&i| {
        tail[i..i + 4] == *b"PK\x05\x06" && {
            let comment = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
            i + 22 + comment <= tail.len()
        }
    });
    let Some(i) = found else {
        return damaged(
            "cut short: its table of contents (the end of central directory) is missing",
        );
    };
    let eocd = from + i as u64;
    let disk = d.le16(eocd + 4, "its end record")?;
    let mut entries = d.le16(eocd + 10, "its end record")?;
    let mut size = d.le32(eocd + 12, "its end record")?;
    let mut offset = d.le32(eocd + 16, "its end record")?;
    let mut cd_end = eocd;
    let zip64 = eocd >= 20 && d.get(eocd - 20, 4, "")? == b"PK\x06\x07";
    if zip64 {
        let at = d.le64(eocd - 12, "its ZIP64 locator")?;
        if !d.has(at, 56) || d.get(at, 4, "")? != b"PK\x06\x06" {
            return damaged("its ZIP64 end record is not where its locator says");
        }
        entries = d.le64(at + 32, "its ZIP64 end record")?;
        size = d.le64(at + 40, "its ZIP64 end record")?;
        offset = d.le64(at + 48, "its ZIP64 end record")?;
        cd_end = at;
    } else if disk != 0 {
        return unsupported("it is one part of an archive split across several files");
    }
    Ok((eocd, entries, size, offset, cd_end))
}

/// The ZIP64 extra field's values for those of `size`, `packed` and `local` that are full.
fn zip64_extra(extra: &[u8], e: &mut Entry) {
    let mut i = 0;
    while i + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[i], extra[i + 1]]);
        let len = u16::from_le_bytes([extra[i + 2], extra[i + 3]]) as usize;
        let body = extra.get(i + 4..i + 4 + len).unwrap_or(&[]);
        if id == 1 {
            let mut at = 0;
            let mut take = |v: &mut u64| {
                if *v == 0xFFFF_FFFF {
                    if let Some(b) = body.get(at..at + 8) {
                        *v = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
                    }
                    at += 8;
                }
            };
            take(&mut e.size);
            take(&mut e.packed);
            take(&mut e.local);
            return;
        }
        i += 4 + len;
    }
}

pub(super) fn check(d: &mut Data, ext: &str) -> Res<Good> {
    let (eocd, count, size, offset, cd_end) = end_record(d)?;
    if offset.saturating_add(size) != cd_end {
        return damaged("its table of contents is not where its end record says");
    }
    if count > MAX_ENTRIES {
        return unsupported("it holds more files than this check reads");
    }
    // Each entry and its name are held, charged to the check's memory: a name is never
    // dropped, so an Office file's parts are always found by name.
    let mut entries: Vec<Entry> = Vec::new();
    let mut pos = offset;
    for n in 0..count {
        d.item()?;
        if pos + 46 > cd_end {
            return damaged(say::zip_contents(n, count));
        }
        if d.get(pos, 4, "its table of contents")? != b"PK\x01\x02" {
            return damaged(format!(
                "entry {} of its table of contents is damaged",
                n + 1
            ));
        }
        let h = d.get(pos, 46, "its table of contents")?.to_vec();
        let le16 = |i: usize| u64::from(u16::from_le_bytes([h[i], h[i + 1]]));
        let le32 = |i: usize| u64::from(u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]));
        let (name_len, extra_len, comment_len) = (le16(28), le16(30), le16(32));
        let end = pos + 46 + name_len + extra_len + comment_len;
        if end > cd_end {
            return damaged(format!(
                "entry {} of its table of contents is damaged",
                n + 1
            ));
        }
        // The entry and its name are charged before the name is copied; the extra field is
        // read where it lies.
        d.hold((std::mem::size_of::<Entry>() + std::mem::size_of::<usize>()) as u64 + name_len)?;
        let name = d.get(pos + 46, name_len as usize, "")?.to_vec();
        let mut e = Entry {
            name: Vec::new(),
            flags: le16(8),
            method: le16(10),
            crc: le32(16),
            packed: le32(20),
            size: le32(24),
            local: le32(42),
        };
        zip64_extra(d.get(pos + 46 + name_len, extra_len as usize, "")?, &mut e);
        e.name = name;
        entries.push(e);
        pos = end;
    }
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| entries[i].local);
    let (mut locked, mut unread, mut checked) = (0u64, 0u64, 0u64);
    let mut rels: Option<Vec<u8>> = None;
    let mut mimetype: Option<Vec<u8>> = None;
    for i in order {
        d.item()?;
        let e = &entries[i];
        let shown = text(&e.name);
        let at = e.local;
        if !d.has(at, 30) || d.get(at, 4, "")? != b"PK\x03\x04" {
            return damaged(format!(
                "the data of {shown} is missing: its header is not where the table of contents says"
            ));
        }
        let name_len = d.le16(at + 26, "a file header")?;
        let extra_len = d.le16(at + 28, "a file header")?;
        if !e.name.is_empty() && d.get(at + 30, name_len as usize, "a file header")? != e.name {
            return damaged(format!(
                "the header of {shown} names a different file than the table of contents"
            ));
        }
        let start = at + 30 + name_len + extra_len;
        if start.saturating_add(e.packed) > offset {
            return damaged(format!(
                "cut short: the data of {shown} runs into its table of contents or past the end"
            ));
        }
        if e.flags & 1 != 0 {
            locked += 1;
            continue;
        }
        let wanted = match e.name.as_slice() {
            b"_rels/.rels" => Some(&mut rels),
            b"mimetype" => Some(&mut mimetype),
            _ => None,
        };
        let mut kept = Vec::new();
        let crc = match e.method {
            0 => {
                if e.packed != e.size {
                    return damaged(format!("{shown} is stored with two different sizes"));
                }
                if wanted.is_some() {
                    kept = d.upto_held(start, (e.size as usize).min(MAX_PART))?;
                }
                // Read for its checksum: taken out of the file as unpacked data is, so
                // entries that share their data cannot have it read without end.
                d.taken(e.size)?;
                d.crc(start, e.size, "a file's data")?
            }
            8 => {
                let keep = wanted.is_some().then_some((&mut kept, MAX_PART));
                let out = d
                    .inflate(start, e.packed, false, e.size, keep)
                    .map_err(|f| match f {
                        Fault::Damaged(why) => Fault::Damaged(format!("{shown} is damaged: {why}")),
                        other => other,
                    })?;
                if out.size != e.size {
                    return damaged(say::zip_size(&shown, out.size, e.size));
                }
                out.crc
            }
            _ => {
                unread += 1;
                continue;
            }
        };
        if u64::from(crc) != e.crc {
            return damaged(format!("{shown} fails its checksum"));
        }
        if let Some(slot) = wanted {
            *slot = Some(kept);
        }
        checked += 1;
    }
    if locked > 0 && checked == 0 {
        return unsupported(
            "it is password-protected: its table of contents is whole, but its contents cannot be checked",
        );
    }
    let has = |want: &str| {
        entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(want.as_bytes()))
    };
    let mut kind = "ZIP archive";
    let office = OFFICE.contains(&ext);
    if office || has("[Content_Types].xml") {
        if !has("[Content_Types].xml") {
            return damaged("its list of parts, [Content_Types].xml, is missing");
        }
        let Some(rels) = rels else {
            return damaged("its package relationships, _rels/.rels, are missing");
        };
        match main_part(&rels) {
            Some(main) => {
                if !has(&main) {
                    return damaged(format!("its main part, {main}, is missing"));
                }
                kind = office_kind(&main);
            }
            None if office => return damaged("it does not name its main document part"),
            None => {}
        }
    }
    let open_document = OPEN_DOCUMENT.contains(&ext);
    if let Some(mime) = &mimetype {
        let mime = String::from_utf8_lossy(mime);
        if let Some(sub) = mime.strip_prefix("application/vnd.oasis.opendocument.") {
            for part in ["content.xml", "META-INF/manifest.xml"] {
                if !has(part) {
                    return damaged(format!("its {part} part is missing"));
                }
            }
            kind = match sub.split('-').next().unwrap_or("") {
                "text" => "OpenDocument text",
                "spreadsheet" => "OpenDocument spreadsheet",
                "presentation" => "OpenDocument presentation",
                "graphics" => "OpenDocument drawing",
                _ => "OpenDocument file",
            };
        } else if mime.trim() == "application/epub+zip" {
            if !has("META-INF/container.xml") {
                return damaged("its META-INF/container.xml part is missing");
            }
            kind = "EPUB book";
        }
    } else if open_document {
        return damaged("its mimetype part, which every OpenDocument file starts with, is missing");
    }
    let (one, many) = if kind == "ZIP archive" {
        ("file", "files")
    } else {
        ("part", "parts")
    };
    let mut note = say::zip(checked, one, many);
    if locked > 0 {
        note.push_str(&say::zip_locked(locked, one, many));
    }
    if unread > 0 {
        note.push_str(&say::zip_unread(unread, one, many));
    }
    let tail = d.le16(eocd + 20, "its end record")?;
    let extra = d.len.saturating_sub(eocd + 22 + tail);
    if extra > 0 {
        note.push_str(&say::more_follow(extra, "its end"));
    }
    good(kind, note)
}

/// The target of the package's officeDocument relationship, as a part name.
fn main_part(rels: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(rels);
    for element in text.split("<Relationship").skip(1) {
        let element = element.split('>').next().unwrap_or("");
        let attr = |name: &str| {
            let at = element.find(&format!("{name}=\""))? + name.len() + 2;
            let rest = &element[at..];
            Some(rest[..rest.find('"')?].to_string())
        };
        if attr("Type").is_some_and(|t| t.ends_with("/officeDocument")) {
            let target = attr("Target")?;
            return Some(target.trim_start_matches('/').to_string());
        }
    }
    None
}

fn office_kind(main: &str) -> &'static str {
    let lower = main.to_ascii_lowercase();
    if lower.starts_with("word/") {
        "Word document"
    } else if lower.starts_with("xl/") {
        "Excel workbook"
    } else if lower.starts_with("ppt/") {
        "PowerPoint presentation"
    } else if lower.starts_with("visio/") {
        "Visio drawing"
    } else {
        "Office document"
    }
}
