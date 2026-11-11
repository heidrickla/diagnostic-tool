//! Pictures, audio, video and text: each walked from its start to its end.
use super::{damaged, good, say, unsupported, Data, Good, Res};

// ---- JPEG ---------------------------------------------------------------------------------

/// A marker walk from the start marker to the end marker: every segment's length in bounds,
/// a frame header before the first scan, each scan's coded data ending at a real marker and
/// holding no long run of zeros.
pub(super) fn jpeg(d: &mut Data) -> Res<Good> {
    if d.be16(0, "its start marker")? != 0xFFD8 {
        return damaged("it does not start with a JPEG start marker");
    }
    let mut pos = 2u64;
    let mut frame: Option<(u64, u64)> = None;
    let mut scans = 0u32;
    loop {
        d.tick()?;
        let b = d.byte(pos, "its markers, before the end marker")?;
        if b != 0xFF {
            return damaged(format!(
                "its structure breaks at byte {pos}: a marker should be there"
            ));
        }
        let mut marker = d.byte(pos + 1, "a marker")?;
        while marker == 0xFF {
            pos += 1;
            marker = d.byte(pos + 1, "a marker")?;
        }
        pos += 2;
        match marker {
            0xD9 => {
                let Some((w, h)) = frame else {
                    return damaged("it ends before any image header");
                };
                if scans == 0 {
                    return damaged("it ends before any image data");
                }
                let extra = d.len - pos;
                let mut note =
                    format!("{w} by {h} pixels; every part present up to its end marker");
                if extra > 0 {
                    note.push_str(&say::more_follow(extra, "its end marker"));
                }
                return good("JPEG image", note);
            }
            0xD8 => {
                return damaged(format!(
                    "a second start marker sits inside it at byte {}",
                    pos - 2
                ))
            }
            0x01 | 0xD0..=0xD7 => {}
            0x00 => {
                return damaged(format!(
                    "its structure breaks at byte {}: a marker should be there",
                    pos - 2
                ))
            }
            _ => {
                let len = d.be16(pos, "a header segment")?;
                if len < 2 {
                    return damaged(format!("a header segment at byte {pos} has no length"));
                }
                let end = pos + len;
                if end > d.len {
                    return damaged("cut short: the file ends inside a header segment");
                }
                let sof = matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC);
                if sof {
                    if len < 8 {
                        return damaged(format!("the image header at byte {pos} is too short"));
                    }
                    let h = d.be16(pos + 3, "the image header")?;
                    let w = d.be16(pos + 5, "the image header")?;
                    if w == 0 {
                        return damaged("its image header gives a width of 0");
                    }
                    frame = Some((w, h));
                }
                pos = end;
                if marker == 0xDA {
                    if frame.is_none() {
                        return damaged("its image data comes before its image header");
                    }
                    scans += 1;
                    let start = pos;
                    pos = scan_end(d, pos)?;
                    if let Some(at) = d.zero_run(start, pos)? {
                        return damaged(zeros_at(at, "image data"));
                    }
                }
            }
        }
    }
}

/// Where a scan's entropy-coded data ends: at the next marker that is not a stuffed zero or a
/// restart marker.
fn scan_end(d: &mut Data, mut pos: u64) -> Res<u64> {
    loop {
        let Some(at) = d.find(&[0xFF], pos, d.len)? else {
            return damaged(
                "cut short: the file ends inside its image data, before its end marker",
            );
        };
        match d.byte(at + 1, "its image data, before its end marker")? {
            0x00 | 0xD0..=0xD7 => pos = at + 2,
            0xFF => pos = at + 1,
            _ => return Ok(at),
        }
    }
}

pub(super) fn zeros_at(at: u64, what: &str) -> String {
    format!(
        "{} or more zero bytes from byte {at} inside its {what}, the way unreadable parts are filled",
        super::ZERO_RUN
    )
}

// ---- PNG ----------------------------------------------------------------------------------

/// Every chunk's length in bounds and its CRC-32 right, the header first and IEND last.
pub(super) fn png(d: &mut Data) -> Res<Good> {
    let mut pos = 8u64;
    let mut chunks = 0u64;
    let mut size = (0, 0);
    let mut data = false;
    loop {
        d.tick()?;
        let len = d.be32(pos, "a chunk header")?;
        if len > 0x7FFF_FFFF {
            return damaged(format!("the chunk at byte {pos} has an impossible length"));
        }
        let kind = d.get(pos + 4, 4, "a chunk header")?.to_vec();
        if !kind.iter().all(|c| c.is_ascii_alphabetic()) {
            return damaged(format!(
                "its structure breaks at byte {pos}: a chunk should start there"
            ));
        }
        let name = String::from_utf8_lossy(&kind).into_owned();
        if chunks == 0 && name != "IHDR" {
            return damaged("its first chunk is not the image header");
        }
        if name == "IHDR" && len >= 8 {
            size = (
                d.be32(pos + 8, "the image header")?,
                d.be32(pos + 12, "the image header")?,
            );
        }
        let end = pos + 12 + len;
        if end > d.len {
            return damaged(format!("cut short: the file ends inside its {name} chunk"));
        }
        let crc = d.crc(pos + 4, 4 + len, "a chunk")?;
        if u64::from(crc) != d.be32(pos + 8 + len, "a chunk's checksum")? {
            return damaged(format!("its {name} chunk at byte {pos} fails its checksum"));
        }
        chunks += 1;
        data |= name == "IDAT";
        pos = end;
        if name == "IEND" {
            if !data {
                return damaged("it holds no image data");
            }
            let mut note = say::png(size.0, size.1, chunks);
            if d.len > pos {
                note.push_str(&say::more_follow(d.len - pos, "its end"));
            }
            return good("PNG image", note);
        }
    }
}

// ---- GIF ----------------------------------------------------------------------------------

fn sub_blocks(d: &mut Data, mut pos: u64) -> Res<u64> {
    loop {
        let n = u64::from(d.byte(pos, "its image data")?);
        pos += 1 + n;
        if n == 0 {
            return Ok(pos);
        }
        if pos > d.len {
            return damaged("cut short: the file ends inside its image data");
        }
    }
}

/// Header, colour tables and every block to the trailer.
pub(super) fn gif(d: &mut Data) -> Res<Good> {
    let (w, h) = (d.le16(6, "its header")?, d.le16(8, "its header")?);
    let flags = d.byte(10, "its header")?;
    let mut pos = 13u64;
    if flags & 0x80 != 0 {
        pos += 3 << ((flags & 7) + 1);
    }
    let mut frames = 0u64;
    loop {
        d.tick()?;
        match d.byte(pos, "its blocks, before its end")? {
            0x21 => pos = sub_blocks(d, pos + 2)?,
            0x2C => {
                let flags = d.byte(pos + 9, "a frame header")?;
                pos += 10;
                if flags & 0x80 != 0 {
                    pos += 3 << ((flags & 7) + 1);
                }
                let code = d.byte(pos, "a frame")?;
                if !(1..=12).contains(&code) {
                    return damaged(format!("the frame at byte {pos} is damaged"));
                }
                pos = sub_blocks(d, pos + 1)?;
                frames += 1;
            }
            0x3B => {
                if frames == 0 {
                    return damaged("it holds no image");
                }
                let mut note = say::gif(w, h, frames);
                let extra = d.len - pos - 1;
                if extra > 0 {
                    note.push_str(&say::more_follow(extra, "its end"));
                }
                return good("GIF image", note);
            }
            _ => {
                return damaged(format!(
                    "its structure breaks at byte {pos}: a block should start there"
                ))
            }
        }
    }
}

// ---- BMP ----------------------------------------------------------------------------------

/// The header, and the pixel data the header describes inside the file.
pub(super) fn bmp(d: &mut Data) -> Res<Good> {
    let stated = d.le32(2, "its header")?;
    let offset = d.le32(10, "its header")?;
    let dib = d.le32(14, "its header")?;
    let (w, h, bpp, compression, image) = if dib == 12 {
        (
            d.le16(18, "its header")? as i64,
            d.le16(20, "its header")? as i64,
            d.le16(24, "its header")?,
            0,
            0,
        )
    } else {
        (
            d.le32(18, "its header")? as u32 as i32 as i64,
            d.le32(22, "its header")? as u32 as i32 as i64,
            d.le16(28, "its header")?,
            d.le32(30, "its header")?,
            d.le32(34, "its header")?,
        )
    };
    let depth_known = matches!(bpp, 1 | 2 | 4 | 8 | 16 | 24 | 32 | 64);
    if w <= 0 || h == 0 || (!depth_known && !matches!(compression, 4 | 5)) {
        return damaged("its header gives an impossible size or color depth");
    }
    if offset < 14 + dib || offset > d.len {
        return damaged("its header points at pixel data outside the file");
    }
    let need = if matches!(compression, 0 | 3 | 6) {
        let stride = (w as u64 * bpp).div_ceil(32) * 4;
        stride.saturating_mul(h.unsigned_abs())
    } else {
        image
    };
    if offset.saturating_add(need) > d.len {
        return damaged(format!(
            "cut short: its pixels need {} but the file holds {} after its header",
            super::bytes_text(need),
            super::bytes_text(d.len - offset)
        ));
    }
    if stated > d.len {
        return damaged(say::header_says(stated, d.len));
    }
    good(
        "BMP image",
        format!(
            "{w} by {} pixels; all its pixel data is present",
            h.unsigned_abs()
        ),
    )
}

// ---- TIFF and camera raw -------------------------------------------------------------------

/// Every image directory in bounds, and every strip or tile of image data inside the file.
pub(super) fn tiff(d: &mut Data) -> Res<Good> {
    let little = d.get(0, 2, "its header")? == b"II";
    let u16_at = |d: &mut Data, p: u64| {
        if little {
            d.le16(p, "an image directory")
        } else {
            d.be16(p, "an image directory")
        }
    };
    let u32_at = |d: &mut Data, p: u64| {
        if little {
            d.le32(p, "an image directory")
        } else {
            d.be32(p, "an image directory")
        }
    };
    // Each offset queued, each directory seen and each list of values read is held.
    d.hold(8)?;
    let mut queue = vec![u32_at(d, 4)?];
    let mut seen = std::collections::BTreeSet::new();
    let mut strips = 0u64;
    while let Some(ifd) = queue.pop() {
        d.free(8);
        d.item()?;
        if ifd == 0 || seen.contains(&ifd) {
            continue;
        }
        d.hold(32)?;
        seen.insert(ifd);
        if seen.len() > 512 {
            return unsupported("it holds more image directories than this check reads");
        }
        if !d.has(ifd, 2) {
            return damaged("cut short: an image directory lies past the end of the file");
        }
        let n = u16_at(d, ifd)?;
        let end = ifd + 2 + 12 * n + 4;
        if end > d.len {
            return damaged("cut short: the file ends inside an image directory");
        }
        let mut offsets: Vec<u64> = Vec::new();
        let mut counts: Vec<u64> = Vec::new();
        let mut compression = 1;
        for i in 0..n {
            d.item()?;
            let e = ifd + 2 + 12 * i;
            let tag = u16_at(d, e)?;
            let kind = u16_at(d, e + 2)?;
            let count = u32_at(d, e + 4)?;
            let unit = match kind {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 | 13 => 4,
                5 | 10 | 12 => 8,
                _ => continue,
            };
            let bytes = count.saturating_mul(unit);
            let at = if bytes <= 4 { e + 8 } else { u32_at(d, e + 8)? };
            if !d.has(at, bytes) {
                return damaged(format!(
                    "cut short: tag {tag} of an image directory points past the end of the file"
                ));
            }
            if tag == 259 && unit == 2 {
                compression = u16_at(d, at)?;
            }
            let wanted = matches!(tag, 273 | 279 | 324 | 325 | 330 | 34665);
            if !wanted || !matches!(unit, 2 | 4) {
                continue;
            }
            if count > 1 << 20 {
                return unsupported("it lists more image parts than this check reads");
            }
            let mut values: Vec<u64> = d.room(count as usize)?;
            for k in 0..count {
                d.item()?;
                let p = at + k * unit;
                values.push(if unit == 2 {
                    u16_at(d, p)?
                } else {
                    u32_at(d, p)?
                });
            }
            let replaced = match tag {
                273 | 324 => std::mem::replace(&mut offsets, values),
                279 | 325 => std::mem::replace(&mut counts, values),
                _ => {
                    queue.extend(values);
                    Vec::new()
                }
            };
            d.free(replaced.len() as u64 * 8);
        }
        for (offset, count) in offsets.iter().zip(&counts) {
            if offset.saturating_add(*count) > d.len {
                return damaged("cut short: part of its image data lies past the end of the file");
            }
            // Compressed image data never holds a long run of zeros; raw pixels may.
            if compression != 1 {
                if let Some(at) = d.zero_run(*offset, offset + count)? {
                    return damaged(zeros_at(at, "image data"));
                }
            }
            strips += 1;
        }
        d.free((offsets.len() + counts.len()) as u64 * 8);
        d.hold(8)?;
        queue.push(u32_at(d, end - 4)?);
    }
    good("TIFF image", say::tiff(seen.len() as u64, strips))
}

// ---- MP4, MOV, HEIC (ISO base media) --------------------------------------------------------

/// Boxes whose payload is only boxes.
const CONTAINERS: [&[u8; 4]; 11] = [
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"mvex", b"moof", b"traf",
    b"mfra",
];
/// Sample formats stored uncompressed, whose silence is runs of zeros.
const RAW_AUDIO: [&[u8; 4]; 10] = [
    b"lpcm", b"sowt", b"twos", b"raw ", b"in24", b"in32", b"fl32", b"fl64", b"NONE", b"ipcm",
];

struct Iso {
    moov: bool,
    mvhd: bool,
    tracks: u64,
    meta: bool,
    raw_audio: bool,
    brand: [u8; 4],
    mdat: Vec<(u64, u64)>,
    fragments: bool,
}

/// One box's header at `pos` inside a parent ending at `end`: (type, payload start, end).
fn iso_box(d: &mut Data, pos: u64, end: u64) -> Res<([u8; 4], u64, u64)> {
    let size = d.be32(pos, "a box header")?;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(d.get(pos + 4, 4, "a box header")?);
    if !kind
        .iter()
        .all(|c| c.is_ascii_graphic() || *c == b' ' || *c == 0xA9)
    {
        return damaged(format!(
            "its structure breaks at byte {pos}: a box should start there"
        ));
    }
    let name = String::from_utf8_lossy(&kind).into_owned();
    let (header, size) = match size {
        0 => (8, end - pos),
        1 => (16, d.be64(pos + 8, "a box header")?),
        n => (8, n),
    };
    if size < header {
        return damaged(format!(
            "the {name} box at byte {pos} has an impossible size"
        ));
    }
    let box_end = pos.saturating_add(size);
    if box_end > end {
        return damaged(if end == d.len {
            format!("cut short: its {name} box runs past the end of the file")
        } else {
            format!("its {name} box at byte {pos} runs past the box holding it")
        });
    }
    Ok((kind, pos + header, box_end))
}

fn iso_walk(d: &mut Data, from: u64, to: u64, depth: u32, iso: &mut Iso) -> Res<()> {
    let mut pos = from;
    while pos < to {
        d.tick()?;
        if to - pos < 8 {
            // Some QuickTime writers end a list of boxes with four zero bytes.
            if depth > 0 && d.get(pos, (to - pos) as usize, "")?.iter().all(|b| *b == 0) {
                break;
            }
            return damaged(say::not_whole(to - pos, pos, "box"));
        }
        let (kind, start, end) = iso_box(d, pos, to)?;
        match &kind {
            b"ftyp" if depth == 0 => iso.brand.copy_from_slice(d.get(start, 4, "its file type")?),
            b"moov" => iso.moov = true,
            b"mvhd" => iso.mvhd = true,
            b"trak" => iso.tracks += 1,
            b"meta" if depth == 0 => iso.meta = true,
            b"moof" => iso.fragments = true,
            b"mdat" if depth == 0 => {
                d.hold(16)?;
                iso.mdat.push((start, end));
            }
            b"stsd" => {
                if end - start >= 16 {
                    let format = d.get(start + 12, 4, "a sample description")?;
                    iso.raw_audio |= RAW_AUDIO.iter().any(|f| f[..] == *format);
                }
            }
            b"stco" | b"co64" => {
                let wide = &kind == b"co64";
                let count = d.be32(start + 4, "a chunk table")?;
                let unit = if wide { 8 } else { 4 };
                if start + 8 + count.saturating_mul(unit) > end {
                    return damaged("its chunk table runs past its box");
                }
                for i in 0..count {
                    if i % 4096 == 0 {
                        d.tick()?;
                    }
                    let p = start + 8 + i * unit;
                    let at = if wide {
                        d.be64(p, "a chunk table")?
                    } else {
                        d.be32(p, "a chunk table")?
                    };
                    if at >= d.len {
                        return damaged(
                            "cut short: its index points at media data past the end of the file",
                        );
                    }
                }
            }
            _ => {}
        }
        if CONTAINERS.iter().any(|c| **c == kind) {
            // Boxes nested deeper than the check follows leave it not checked, never good.
            if !d.budget.within_depth(depth as usize + 1) {
                return unsupported(format!(
                    "its boxes are nested more than {} deep, deeper than this check reads",
                    d.budget.limits().depth
                ));
            }
            iso_walk(d, start, end, depth + 1, iso)?;
        }
        pos = end;
    }
    Ok(())
}

/// The box tree walked to the end of the file with every size in bounds, the movie header
/// and its tracks present (or, for a HEIF picture, its metadata), each chunk offset inside
/// the file, and the media data free of long runs of zeros when it is compressed.
pub(super) fn iso(d: &mut Data) -> Res<Good> {
    let mut iso = Iso {
        moov: false,
        mvhd: false,
        tracks: 0,
        meta: false,
        raw_audio: false,
        brand: *b"    ",
        mdat: Vec::new(),
        fragments: false,
    };
    iso_walk(d, 0, d.len, 0, &mut iso)?;
    let heif = matches!(
        &iso.brand,
        b"heic" | b"heix" | b"mif1" | b"msf1" | b"avif" | b"heim" | b"heis"
    );
    let kind = match &iso.brand {
        b"heic" | b"heix" | b"mif1" | b"msf1" | b"heim" | b"heis" => "HEIC image",
        b"avif" => "AVIF image",
        b"qt  " => "QuickTime video",
        b"M4A " | b"M4B " => "MPEG-4 audio",
        b"crx " => "Canon raw photo",
        b"3gp4" | b"3gp5" | b"3gp6" | b"3g2a" => "3GP video",
        _ => "MP4 video",
    };
    if heif && !iso.moov {
        if !iso.meta {
            return damaged("its picture description (the meta box) is missing");
        }
        return good(
            kind,
            "every box is whole and its picture description is present",
        );
    }
    if !iso.moov {
        return damaged("its index (the moov box) is missing, so players cannot read it");
    }
    if !iso.mvhd || iso.tracks == 0 {
        return damaged("its index (the moov box) lacks its movie header or tracks");
    }
    if iso.mdat.is_empty() && !iso.fragments {
        return damaged("it holds no media data (no mdat box)");
    }
    if !iso.raw_audio {
        for (start, end) in iso.mdat.clone() {
            if let Some(at) = d.zero_run(start, end)? {
                return damaged(zeros_at(at, "media data"));
            }
        }
    }
    good(kind, say::mp4(iso.tracks))
}

// ---- MP3 ----------------------------------------------------------------------------------

/// An MPEG audio frame header's frame length, if `h` is one.
fn mp3_frame(h: &[u8]) -> Option<u64> {
    if h.len() < 4 || h[0] != 0xFF || h[1] & 0xE0 != 0xE0 {
        return None;
    }
    let version = (h[1] >> 3) & 3;
    let layer = (h[1] >> 1) & 3;
    let rate = (h[2] >> 4) as usize;
    let sample = ((h[2] >> 2) & 3) as usize;
    let pad = u64::from((h[2] >> 1) & 1);
    if version == 1 || layer == 0 || rate == 0 || rate == 15 || sample == 3 {
        return None;
    }
    const V1: [[u64; 14]; 3] = [
        [
            32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
        ],
        [
            32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
        ],
        [
            32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
        ],
    ];
    const V2: [[u64; 14]; 2] = [
        [
            32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
        ],
        [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ];
    let v1 = version == 3;
    // layer bits: 3 is layer I, 2 layer II, 1 layer III.
    let li = (3 - layer) as usize;
    let kbps = if v1 {
        V1[li][rate - 1]
    } else {
        V2[li.min(1)][rate - 1]
    };
    let hz: u64 = [
        [11025, 12000, 8000],
        [0, 0, 0],
        [22050, 24000, 16000],
        [44100, 48000, 32000],
    ][version as usize][sample];
    let bps = kbps * 1000;
    Some(match layer {
        3 => (12 * bps / hz + pad) * 4,
        1 if !v1 => 72 * bps / hz + pad,
        _ => 144 * bps / hz + pad,
    })
}

/// Whether `head` starts with two MPEG audio frames in a row.
pub(super) fn mp3_starts(head: &[u8]) -> bool {
    mp3_pair(head, 0)
}

fn mp3_pair(head: &[u8], at: usize) -> bool {
    let Some(len) = head.get(at..).and_then(mp3_frame) else {
        return false;
    };
    let next = at + len as usize;
    head.get(next..).and_then(mp3_frame).is_some()
}

/// Where the first two frames in a row start in `head`, past any ID3 tag.
pub(super) fn mp3_sync(head: &[u8]) -> Option<usize> {
    (0..head.len().saturating_sub(4)).find(|&i| mp3_pair(head, i))
}

/// The frame count a VBR header in the first frame at `pos` states (Xing, Info or VBRI).
fn stated_frames(d: &mut Data, pos: u64) -> Res<Option<u64>> {
    let first = d.upto(pos, 64)?;
    if first.len() < 64 {
        return Ok(None);
    }
    let mpeg1 = (first[1] >> 3) & 3 == 3;
    let mono = first[3] >> 6 == 3;
    let side = match (mpeg1, mono) {
        (true, false) => 32,
        (true, true) | (false, false) => 17,
        (false, true) => 9,
    };
    let x = 4 + side;
    if &first[x..x + 4] == b"Xing" || &first[x..x + 4] == b"Info" {
        let flags = u32::from_be_bytes([first[x + 4], first[x + 5], first[x + 6], first[x + 7]]);
        if flags & 1 != 0 {
            let n = u32::from_be_bytes([first[x + 8], first[x + 9], first[x + 10], first[x + 11]]);
            return Ok(Some(u64::from(n)));
        }
    }
    if &first[36..40] == b"VBRI" {
        let n = u32::from_be_bytes([first[50], first[51], first[52], first[53]]);
        return Ok(Some(u64::from(n)));
    }
    Ok(None)
}

/// Tags and frames walked to the end of the file; a VBR header's frame count, when there is
/// one, must be reached.
pub(super) fn mp3(d: &mut Data) -> Res<Good> {
    let mut pos = 0u64;
    if d.has(0, 10) && d.get(0, 3, "its tag")? == b"ID3" {
        let b = d.get(0, 10, "its tag")?.to_vec();
        if b[6..10].iter().any(|x| x & 0x80 != 0) {
            return damaged("its tag header is damaged");
        }
        let size = b[6..10].iter().fold(0u64, |s, x| (s << 7) | u64::from(*x));
        pos = 10 + size + if b[5] & 0x10 != 0 { 10 } else { 0 };
        if pos > d.len {
            return damaged("cut short: the file ends inside its tag");
        }
    }
    // Some writers leave padding after the tag; the first two frames in a row start it.
    let look = d.upto(pos, super::HEAD)?;
    let Some(skip) = mp3_sync(&look) else {
        return damaged("no audio frames were found after its tag");
    };
    pos += skip as u64;
    let stated = stated_frames(d, pos)?;
    let mut frames = 0u64;
    loop {
        if frames.is_multiple_of(4096) {
            d.tick()?;
        }
        if pos == d.len {
            break;
        }
        let rest = d.len - pos;
        let h = d.upto(pos, 4)?;
        if let Some(len) = mp3_frame(&h) {
            if len > rest {
                return damaged("cut short: the file ends inside its last audio frame");
            }
            pos += len;
            frames += 1;
            continue;
        }
        let tail = d.upto(pos, 11)?;
        let tag = tail.starts_with(b"TAG")
            || tail.starts_with(b"APETAGEX")
            || tail.starts_with(b"LYRICSBEGIN")
            || tail.starts_with(b"ID3");
        if tag {
            break;
        }
        return damaged(format!(
            "its audio frames break off at byte {pos}, {}% of the way in",
            pos * 100 / d.len.max(1)
        ));
    }
    if frames == 0 {
        return damaged("it holds no audio frames");
    }
    if let Some(stated) = stated.filter(|n| frames < *n) {
        return damaged(say::mp3_short(stated, frames));
    }
    good("MP3 audio", say::mp3(frames))
}

// ---- WAV, AVI, WebP (RIFF) ------------------------------------------------------------------

/// The RIFF size against the file, and every chunk to the end of the form.
pub(super) fn riff(d: &mut Data) -> Res<Good> {
    let form = d.get(8, 4, "its header")?.to_vec();
    let total = d.le32(4, "its header")? + 8;
    if total > d.len {
        return damaged(say::header_says(total, d.len));
    }
    let mut pos = 12u64;
    let mut ids: Vec<[u8; 4]> = Vec::new();
    let mut coded: Vec<(u64, u64)> = Vec::new();
    while pos < total {
        d.tick()?;
        if total - pos < 8 {
            if total - pos == 1 {
                break;
            }
            return damaged(say::not_whole(total - pos, pos, "chunk"));
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(d.get(pos, 4, "a chunk header")?);
        if !id.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
            return damaged(format!(
                "its structure breaks at byte {pos}: a chunk should start there"
            ));
        }
        let size = d.le32(pos + 4, "a chunk header")?;
        let end = pos + 8 + size;
        if end > total {
            return damaged(format!(
                "its {} chunk runs past the end of its data",
                String::from_utf8_lossy(&id).trim()
            ));
        }
        if &form[..] == b"WEBP" && (&id == b"VP8 " || &id == b"VP8L") && coded.len() < 16 {
            coded.push((pos + 8, end));
        }
        if ids.len() < 4096 {
            if &id == b"LIST" && size >= 4 {
                let mut list = [0u8; 4];
                list.copy_from_slice(d.get(pos + 8, 4, "a list")?);
                ids.push(list);
            }
            ids.push(id);
        }
        pos = end + (size & 1);
    }
    let has = |id: &[u8; 4]| ids.iter().any(|i| i == id);
    let (kind, needs): (&str, &[&[u8; 4]]) = match &form[..] {
        b"WAVE" => ("WAV audio", &[b"fmt ", b"data"]),
        b"AVI " => ("AVI video", &[b"hdrl", b"movi"]),
        _ => ("WebP image", &[]),
    };
    if let Some(missing) = needs.iter().find(|n| !has(n)) {
        return damaged(format!(
            "its {} part is missing",
            String::from_utf8_lossy(&missing[..]).trim()
        ));
    }
    if kind == "WebP image" && !(has(b"VP8 ") || has(b"VP8L") || has(b"VP8X")) {
        return damaged("its image data is missing");
    }
    for (start, end) in coded {
        if let Some(at) = d.zero_run(start, end)? {
            return damaged(zeros_at(at, "image data"));
        }
    }
    let mut note = say::riff(ids.len() as u64);
    let extra = d.len - total;
    if extra > 1 {
        note.push_str(&say::more_follow(extra, "its end"));
    }
    good(kind, note)
}

// ---- text -----------------------------------------------------------------------------------

/// The fewest zero bytes in a row (zero characters, in UTF-16) that make text damaged; a
/// stray one, such as a closing NUL some writers add, does not.
const TEXT_ZEROS: u64 = 64;

/// Text never holds a run of zero bytes (or zero characters, in UTF-16): such a run is a
/// part that could not be read. When `ends` is given, the last character that is not white
/// space must be one of them: "}" for RTF, ">" for XML and HTML, "}" or "]" for JSON.
pub(super) fn text(d: &mut Data, kind: &'static str, ends: Option<&[u8]>) -> Res<Good> {
    let head = d.upto(0, 4096)?;
    // UTF-16 with a byte order mark, or without one when nine in ten of one byte of each
    // pair are zero, as in UTF-16 text in a Latin script.
    let zeros_at = |first: usize| {
        head.iter()
            .skip(first)
            .step_by(2)
            .filter(|b| **b == 0)
            .count()
    };
    let half = head.len() / 2;
    let utf16 = head.starts_with(&[0xFF, 0xFE])
        || head.starts_with(&[0xFE, 0xFF])
        || (half >= 32 && (zeros_at(0) * 10 >= half * 9 || zeros_at(1) * 10 >= half * 9));
    let unit = if utf16 { 2 } else { 1 };
    let mut pos = 0u64;
    let mut run: Option<u64> = None;
    let mut stray = 0u64;
    while pos < d.len {
        let n = (d.len - pos).min(super::WINDOW as u64) as usize;
        let n = n - n % unit;
        if n == 0 {
            break;
        }
        let piece = d.get(pos, n, "")?;
        for (i, c) in piece.chunks_exact(unit).enumerate() {
            let at = pos + (i * unit) as u64;
            if !c.iter().all(|b| *b == 0) {
                run = None;
                continue;
            }
            stray += 1;
            let start = *run.get_or_insert(at);
            if at + unit as u64 - start >= TEXT_ZEROS {
                return damaged(format!(
                    "it holds {TEXT_ZEROS} or more zero bytes from byte {start}, where text should be: the way unreadable parts are filled"
                ));
            }
        }
        pos += n as u64;
        d.tick()?;
    }
    if let Some(ends) = ends {
        let tail = d.upto(d.len.saturating_sub(256), 256)?;
        let last = tail
            .iter()
            .rev()
            .find(|b| !b.is_ascii_whitespace() && **b != 0);
        if !last.is_some_and(|b| ends.contains(b)) {
            return damaged(format!(
                "cut short: it does not end the way {} ends",
                if kind == "text" {
                    "its kind of text"
                } else {
                    kind
                }
            ));
        }
    }
    let mut note = String::from(if utf16 {
        "UTF-16 text with no run of zero characters"
    } else {
        "text with no run of zero bytes"
    });
    if ends.is_some() {
        note.push_str(", and it ends where it should");
    }
    if stray > 0 {
        note.push_str(&say::stray_zeros(stray));
    }
    good(kind, note)
}
