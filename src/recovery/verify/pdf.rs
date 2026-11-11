//! PDF: the header, the end marker, and the cross-reference chain from `startxref`, tables
//! and streams alike; every object the index lists must be where it says, every stream must
//! end where its length says, and every Flate stream must decompress to its end.
use std::collections::hash_map::Entry as Slot;
use std::collections::{HashMap, HashSet};

use super::{damaged, good, say, unsupported, Data, Fault, Good, Res};

/// The most index entries this check holds; a larger index is not checked.
const MAX_ENTRIES: usize = 4_000_000;
/// The most cross-reference sections followed.
const MAX_SECTIONS: usize = 4096;
/// Held for one index entry (a hash map slot with its key and place) and for one object
/// placed in order.
const ENTRY_HELD: u64 = 40;
const PLACE_HELD: u64 = 16;

/// Enters `number` at `loc` unless a newer section entered it; what is held is charged.
fn enter(d: &mut Data, index: &mut Index, number: u64, loc: Loc) -> Res<()> {
    if let Slot::Vacant(slot) = index.entries.entry(number) {
        d.hold(ENTRY_HELD)?;
        slot.insert(loc);
    }
    Ok(())
}

// ---- tokens and values --------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok<'b> {
    Int(i64),
    Real,
    Name(&'b [u8]),
    Str,
    DictOpen,
    DictClose,
    ArrOpen,
    ArrClose,
    Word(&'b [u8]),
    End,
}

fn white(c: u8) -> bool {
    matches!(c, 0 | 9 | 10 | 12 | 13 | 32)
}

fn delimiter(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

struct Lex<'b> {
    b: &'b [u8],
    i: usize,
}

impl<'b> Lex<'b> {
    fn new(b: &'b [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn skip_white(&mut self) {
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if white(c) {
                self.i += 1;
            } else if c == b'%' {
                while self.i < self.b.len() && !matches!(self.b[self.i], b'\r' | b'\n') {
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }

    fn next(&mut self) -> Tok<'b> {
        self.skip_white();
        let b = self.b;
        let Some(&c) = b.get(self.i) else {
            return Tok::End;
        };
        let start = self.i;
        match c {
            b'<' if b.get(start + 1) == Some(&b'<') => {
                self.i += 2;
                Tok::DictOpen
            }
            b'>' if b.get(start + 1) == Some(&b'>') => {
                self.i += 2;
                Tok::DictClose
            }
            b'<' => match b[start..].iter().position(|c| *c == b'>') {
                Some(n) => {
                    self.i = start + n + 1;
                    Tok::Str
                }
                None => {
                    self.i = b.len();
                    Tok::End
                }
            },
            b'[' => {
                self.i += 1;
                Tok::ArrOpen
            }
            b']' => {
                self.i += 1;
                Tok::ArrClose
            }
            b'(' => {
                let mut depth = 0usize;
                let mut i = start;
                while i < b.len() {
                    match b[i] {
                        b'\\' => i += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                self.i = i + 1;
                                return Tok::Str;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                self.i = b.len();
                Tok::End
            }
            b'/' => {
                let mut i = start + 1;
                while i < b.len() && !white(b[i]) && !delimiter(b[i]) {
                    i += 1;
                }
                self.i = i;
                Tok::Name(&b[start + 1..i])
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                let mut i = start + 1;
                while i < b.len() && matches!(b[i], b'0'..=b'9' | b'.' | b'+' | b'-') {
                    i += 1;
                }
                self.i = i;
                let text = std::str::from_utf8(&b[start..i]).unwrap_or("");
                match text.parse::<i64>() {
                    Ok(n) => Tok::Int(n),
                    Err(_) => Tok::Real,
                }
            }
            _ => {
                let mut i = start + 1;
                while i < b.len() && !white(b[i]) && !delimiter(b[i]) {
                    i += 1;
                }
                self.i = i.max(start + 1);
                Tok::Word(&b[start..self.i])
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum V<'b> {
    Int(i64),
    Ref(i64),
    Name(&'b [u8]),
    Arr(Vec<V<'b>>),
    Dict(Vec<(&'b [u8], V<'b>)>),
    Other,
}

enum Parsed<'b> {
    Value(V<'b>),
    Close,
    Bad,
}

/// One value; integers followed by "G R" become references.
fn value<'b>(lx: &mut Lex<'b>, depth: u32) -> Parsed<'b> {
    if depth > 64 {
        return Parsed::Bad;
    }
    match lx.next() {
        Tok::Int(n) => {
            let save = lx.i;
            if let Tok::Int(_) = lx.next() {
                if lx.next() == Tok::Word(b"R") {
                    return Parsed::Value(V::Ref(n));
                }
            }
            lx.i = save;
            Parsed::Value(V::Int(n))
        }
        Tok::Name(n) => Parsed::Value(V::Name(n)),
        Tok::Real | Tok::Str | Tok::Word(_) => Parsed::Value(V::Other),
        Tok::ArrOpen => {
            let mut items = Vec::new();
            loop {
                match value(lx, depth + 1) {
                    Parsed::Value(v) => items.push(v),
                    Parsed::Close => return Parsed::Value(V::Arr(items)),
                    Parsed::Bad => return Parsed::Bad,
                }
            }
        }
        Tok::DictOpen => {
            let mut items = Vec::new();
            loop {
                match lx.next() {
                    Tok::DictClose => return Parsed::Value(V::Dict(items)),
                    Tok::Name(key) => match value(lx, depth + 1) {
                        Parsed::Value(v) => items.push((key, v)),
                        _ => return Parsed::Bad,
                    },
                    _ => return Parsed::Bad,
                }
            }
        }
        Tok::ArrClose | Tok::DictClose => Parsed::Close,
        Tok::End => Parsed::Bad,
    }
}

fn key<'v, 'b>(dict: &'v [(&'b [u8], V<'b>)], name: &[u8]) -> Option<&'v V<'b>> {
    dict.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
}

fn int(v: Option<&V>) -> Option<i64> {
    match v {
        Some(V::Int(n)) => Some(*n),
        _ => None,
    }
}

/// Whether a stream's filters are exactly Flate.
fn flate_only(v: Option<&V>) -> bool {
    match v {
        Some(V::Name(n)) => *n == b"FlateDecode",
        Some(V::Arr(items)) => items.len() == 1 && items[0] == V::Name(b"FlateDecode"),
        _ => false,
    }
}

// ---- objects ------------------------------------------------------------------------------

/// An object read at an offset: its number, dictionary (if any), and where its stream's
/// data starts (if it has one).
struct Object<'b> {
    number: i64,
    dict: Option<Vec<(&'b [u8], V<'b>)>>,
    stream: Option<u64>,
    /// A plain integer object's value, for an indirect /Length.
    int: Option<i64>,
}

/// Reads the object at `at` from `window`, the bytes from `at` on. None when no
/// "N G obj" header is there.
fn object(window: &[u8], at: u64) -> Option<Object<'_>> {
    let mut lx = Lex::new(window);
    let Tok::Int(number) = lx.next() else {
        return None;
    };
    let Tok::Int(_) = lx.next() else {
        return None;
    };
    if lx.next() != Tok::Word(b"obj") {
        return None;
    }
    let mut obj = Object {
        number,
        dict: None,
        stream: None,
        int: None,
    };
    match value(&mut lx, 0) {
        Parsed::Value(V::Dict(dict)) => {
            if lx.next() == Tok::Word(b"stream") {
                let mut i = lx.i;
                if window.get(i) == Some(&b'\r') {
                    i += 1;
                }
                if window.get(i) == Some(&b'\n') {
                    i += 1;
                }
                obj.stream = Some(at + i as u64);
            }
            obj.dict = Some(dict);
        }
        Parsed::Value(V::Int(n)) => obj.int = Some(n),
        _ => {}
    }
    Some(obj)
}

/// The bytes from `at` for reading an object: a small window, or a larger one when `more`.
fn window(d: &mut Data, at: u64, more: bool) -> Res<Vec<u8>> {
    d.upto(at, if more { 256 * 1024 } else { 4096 })
}

/// Where each object is: in the file at an offset, or inside an object stream.
#[derive(Clone, Copy, Debug)]
enum Loc {
    At(u64),
    In(u64),
}

struct Index {
    /// Object number to where it is, the newest section's entry kept.
    entries: HashMap<u64, Loc>,
    root: Option<i64>,
    encrypted: bool,
    /// What object offsets are counted from: 0, or where "%PDF-" starts.
    shift: u64,
}

/// The integer after `startxref` before the last `%%EOF`, and that marker's end.
fn start_xref(d: &mut Data) -> Res<(u64, u64)> {
    let from = d.len.saturating_sub(2048);
    let tail = d.upto(from, 2048)?;
    let Some(eof) = tail.windows(5).rposition(|w| w == b"%%EOF") else {
        return damaged("cut short: it has no end marker (%%EOF) near its end");
    };
    let before = &tail[..eof];
    let Some(at) = before.windows(9).rposition(|w| w == b"startxref") else {
        return damaged("its pointer to its index (startxref) is missing");
    };
    let mut lx = Lex::new(&before[at + 9..]);
    let Tok::Int(n) = lx.next() else {
        return damaged("its pointer to its index (startxref) is damaged");
    };
    if n < 0 {
        return damaged("its pointer to its index (startxref) is damaged");
    }
    Ok((n as u64, from + eof as u64 + 5))
}

/// Reads one cross-reference section at `at`: a table with its trailer, or a stream.
/// Returns the /Prev and /XRefStm offsets to follow.
fn section(d: &mut Data, at: u64, index: &mut Index) -> Res<Vec<u64>> {
    let head = window(d, at, false)?;
    if head.starts_with(b"xref") {
        table(d, at + 4, index)
    } else if object(&head, at).is_some() {
        xref_stream(d, at, index)
    } else {
        damaged(format!(
            "its index is not at byte {at}, where its pointer says"
        ))
    }
}

fn found_trailer(dict: &[(&[u8], V)], index: &mut Index) -> Vec<u64> {
    if index.root.is_none() {
        if let Some(V::Ref(n)) = key(dict, b"Root") {
            index.root = Some(*n);
        }
    }
    index.encrypted |= key(dict, b"Encrypt").is_some();
    [b"Prev".as_slice(), b"XRefStm"]
        .iter()
        .filter_map(|k| int(key(dict, k)))
        .filter(|n| *n >= 0)
        .map(|n| n as u64)
        .collect()
}

/// A classic table: subsections of "start count" then 20-byte entries, then the trailer.
fn table(d: &mut Data, mut pos: u64, index: &mut Index) -> Res<Vec<u64>> {
    loop {
        d.tick()?;
        let head = window(d, pos, false)?;
        let mut lx = Lex::new(&head);
        match lx.next() {
            Tok::Word(b"trailer") => {
                let more = window(d, pos + lx.i as u64, true)?;
                let mut lx = Lex::new(&more);
                return match value(&mut lx, 0) {
                    Parsed::Value(V::Dict(dict)) => Ok(found_trailer(&dict, index)),
                    _ => damaged("its index's trailer is damaged"),
                };
            }
            Tok::Int(first) => {
                let Tok::Int(count) = lx.next() else {
                    return damaged("its index table is damaged");
                };
                if first < 0 || count < 0 {
                    return damaged("its index table is damaged");
                }
                if index.entries.len().saturating_add(count as usize) > MAX_ENTRIES {
                    return unsupported("its index lists more objects than this check reads");
                }
                pos += lx.i as u64;
                // Entries are 20 bytes; read them as tokens, which also takes writers'
                // 19- and 21-byte lines.
                let mut done = 0i64;
                while done < count {
                    d.tick()?;
                    let block = window(d, pos, true)?;
                    // A window that may end inside an entry is read again from there.
                    let full = block.len() == 256 * 1024;
                    let mut lx = Lex::new(&block);
                    let mut used = 0usize;
                    while done < count {
                        if full && block.len() - lx.i < 64 {
                            break;
                        }
                        let start = lx.i;
                        let (Tok::Int(offset), Tok::Int(_), Tok::Word(kind)) =
                            (lx.next(), lx.next(), lx.next())
                        else {
                            return damaged(if pos + (start as u64) + 20 > d.len {
                                "cut short: the file ends inside its index".to_string()
                            } else {
                                format!("its index table is damaged at byte {}", pos + start as u64)
                            });
                        };
                        let number = first.saturating_add(done) as u64;
                        d.item()?;
                        if kind == b"n" && offset > 0 {
                            enter(d, index, number, Loc::At(offset as u64))?;
                        } else if kind != b"n" && kind != b"f" {
                            return damaged(format!(
                                "its index table is damaged at byte {}",
                                pos + start as u64
                            ));
                        }
                        done += 1;
                        used = lx.i;
                    }
                    if used == 0 && done < count {
                        return damaged("its index table is damaged");
                    }
                    pos += used as u64;
                }
            }
            Tok::End => return damaged("cut short: the file ends inside its index"),
            _ => return damaged(format!("its index table is damaged at byte {pos}")),
        }
    }
}

/// The most columns a predictor row may have.
const MAX_COLUMNS: usize = 64;

/// Undoes a PNG predictor on rows of `columns` bytes, each led by its filter type; what it
/// makes is charged to the check's memory before it is made and left charged. Ok(None)
/// for rows that do not fit.
fn unpredict(d: &mut Data, data: &[u8], columns: usize) -> Res<Option<Vec<u8>>> {
    let row = columns + 1;
    if columns == 0 || columns > MAX_COLUMNS || !data.len().is_multiple_of(row) {
        return Ok(None);
    }
    let made = data.len() / row * columns;
    let mut out = d.room(made)?;
    let unmade = |d: &mut Data| {
        d.free(made as u64);
        Ok(None)
    };
    let mut prior = [0u8; MAX_COLUMNS];
    for line in data.chunks_exact(row) {
        let (kind, raw) = (line[0], &line[1..]);
        let mut cur = [0u8; MAX_COLUMNS];
        for i in 0..columns {
            let left = if i > 0 { cur[i - 1] } else { 0 };
            let up = prior[i];
            let corner = if i > 0 { prior[i - 1] } else { 0 };
            cur[i] = raw[i].wrapping_add(match kind {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => {
                    let p = i16::from(left) + i16::from(up) - i16::from(corner);
                    let (pa, pb, pc) = (
                        (p - i16::from(left)).abs(),
                        (p - i16::from(up)).abs(),
                        (p - i16::from(corner)).abs(),
                    );
                    if pa <= pb && pa <= pc {
                        left
                    } else if pb <= pc {
                        up
                    } else {
                        corner
                    }
                }
                _ => return unmade(d),
            });
        }
        out.extend_from_slice(&cur[..columns]);
        prior = cur;
    }
    Ok(Some(out))
}

/// A cross-reference stream: its entries decoded from the stream's data.
fn xref_stream(d: &mut Data, at: u64, index: &mut Index) -> Res<Vec<u64>> {
    let head = window(d, at, true)?;
    let Some(obj) = object(&head, at) else {
        return damaged(format!("its index stream at byte {at} is damaged"));
    };
    let (Some(dict), Some(start)) = (obj.dict.as_ref(), obj.stream) else {
        return damaged(format!("its index stream at byte {at} is damaged"));
    };
    if key(dict, b"Type") != Some(&V::Name(b"XRef")) {
        return damaged(format!(
            "byte {at}, where its index should be, holds something else"
        ));
    }
    let Some(V::Arr(w)) = key(dict, b"W") else {
        return damaged("its index stream is damaged (no field widths)");
    };
    let widths: Vec<usize> = w
        .iter()
        .map(|v| {
            int(Some(v))
                .filter(|n| (0..=8).contains(n))
                .map(|n| n as usize)
        })
        .collect::<Option<_>>()
        .ok_or_else(|| Fault::Damaged("its index stream is damaged (bad field widths)".into()))?;
    if widths.len() != 3 || widths.iter().sum::<usize>() == 0 {
        return damaged("its index stream is damaged (bad field widths)");
    }
    let Some(length) = int(key(dict, b"Length")).filter(|n| *n >= 0) else {
        return damaged("its index stream has no length");
    };
    let mut raw = Vec::new();
    if flate_only(key(dict, b"Filter")) {
        d.inflate(
            start,
            length as u64,
            true,
            64 << 20,
            Some((&mut raw, 64 << 20)),
        )
        .map_err(|f| match f {
            Fault::Damaged(why) => Fault::Damaged(format!("its index stream is damaged: {why}")),
            other => other,
        })?;
    } else if key(dict, b"Filter").is_none() {
        if length > 64 << 20 {
            return unsupported("its index is larger than this check reads");
        }
        raw = d.upto_held(start, length as usize)?;
        if (raw.len() as i64) < length {
            return damaged("cut short: the file ends inside its index stream");
        }
    } else {
        return unsupported("its index stream uses a compression this check does not read");
    }
    let row: usize = widths.iter().sum();
    let parms = match key(dict, b"DecodeParms") {
        Some(V::Dict(p)) => Some(p),
        Some(V::Arr(items)) => items.iter().find_map(|v| match v {
            V::Dict(p) => Some(p),
            _ => None,
        }),
        _ => None,
    };
    let predictor = parms.and_then(|p| int(key(p, b"Predictor"))).unwrap_or(1);
    if predictor >= 10 {
        let columns = parms
            .and_then(|p| int(key(p, b"Columns")))
            .unwrap_or(1)
            .clamp(1, MAX_COLUMNS as i64) as usize;
        let made = unpredict(d, &raw, columns)?
            .ok_or_else(|| Fault::Damaged("its index stream is damaged (bad rows)".into()))?;
        d.free(raw.len() as u64);
        raw = made;
    } else if predictor != 1 {
        return unsupported("its index stream uses an encoding this check does not read");
    }
    // What was unpacked (at most 64 MiB) is held while its entries are read; it was
    // charged as it was made.
    let held = raw.len() as u64;
    let size = int(key(dict, b"Size")).unwrap_or(0).max(0);
    let ranges: Vec<(i64, i64)> = match key(dict, b"Index") {
        Some(V::Arr(items)) => items
            .chunks(2)
            .filter_map(|p| Some((int(p.first())?, int(p.get(1))?)))
            .collect(),
        _ => vec![(0, size)],
    };
    let field = |r: &[u8], n: usize, skip: usize| -> u64 {
        r[skip..skip + n]
            .iter()
            .fold(0u64, |v, b| (v << 8) | u64::from(*b))
    };
    let mut at_row = 0usize;
    for (first, count) in ranges {
        if first < 0 || count < 0 {
            return damaged("its index stream is damaged");
        }
        if index.entries.len().saturating_add(count as usize) > MAX_ENTRIES {
            return unsupported("its index lists more objects than this check reads");
        }
        for k in 0..count {
            let Some(r) = raw.get(at_row * row..(at_row + 1) * row) else {
                return damaged("its index stream holds fewer entries than it says");
            };
            at_row += 1;
            d.item()?;
            let kind = if widths[0] == 0 {
                1
            } else {
                field(r, widths[0], 0)
            };
            let a = field(r, widths[1], widths[0]);
            let number = first.saturating_add(k) as u64;
            match kind {
                1 if a > 0 => enter(d, index, number, Loc::At(a))?,
                2 => enter(d, index, number, Loc::In(a))?,
                _ => {}
            }
        }
    }
    d.free(held);
    Ok(found_trailer(dict, index))
}

/// Checks one stream: it ends where its length says, and a Flate stream decompresses.
fn stream(d: &mut Data, number: i64, dict: &[(&[u8], V)], start: u64, index: &Index) -> Res<bool> {
    let length = match key(dict, b"Length") {
        Some(V::Int(n)) => Some(*n),
        Some(V::Ref(n)) => match index.entries.get(&(*n as u64)) {
            Some(Loc::At(at)) => {
                let at = at.saturating_add(index.shift);
                let w = window(d, at, false)?;
                object(&w, at).and_then(|o| o.int)
            }
            _ => None,
        },
        _ => None,
    };
    let Some(length) = length.filter(|n| *n >= 0).map(|n| n as u64) else {
        return Ok(false);
    };
    let end = start.saturating_add(length);
    if end > d.len {
        return damaged(format!(
            "cut short: the file ends inside the contents of object {number}"
        ));
    }
    let after = d.upto(end, 64)?;
    let skip = after.iter().take_while(|c| white(**c)).count();
    if !after[skip..].starts_with(b"endstream") {
        return damaged(format!(
            "the contents of object {number} do not end where their length says"
        ));
    }
    let filter = key(dict, b"Filter");
    if (index.encrypted || filter.is_some()) && !(flate_only(filter) && !index.encrypted) {
        // Compressed (JPEG and the like) or encrypted contents never hold a long run of
        // zeros; unfiltered contents, such as raw pixels, may.
        if let Some(at) = d.zero_run(start, end)? {
            return damaged(format!(
                "the contents of object {number} hold {}",
                super::media::zeros_at(at, "data").replace(" inside its data", "")
            ));
        }
    }
    if !index.encrypted && flate_only(filter) {
        d.inflate(start, length, true, u64::MAX, None)
            .map_err(|f| match f {
                Fault::Damaged(why) => Fault::Damaged(format!(
                    "the contents of object {number} are damaged: {why}"
                )),
                other => other,
            })?;
    }
    Ok(true)
}

pub(super) fn check(d: &mut Data) -> Res<Good> {
    let head = d.upto(0, 1024)?;
    let Some(header) = head.windows(5).position(|w| w == b"%PDF-") else {
        return damaged("it does not start with a PDF header");
    };
    let (pointer, eof_end) = start_xref(d)?;
    let mut index = Index {
        entries: HashMap::new(),
        root: None,
        encrypted: false,
        shift: 0,
    };
    // Offsets count from the file's start; a few writers count from the header instead.
    let first = if header > 0 && !window(d, pointer, false).is_ok_and(|w| starts_section(&w)) {
        index.shift = header as u64;
        pointer + index.shift
    } else {
        pointer
    };
    if first >= d.len {
        return damaged("cut short: its index lies past the end of the file");
    }
    let mut queue = vec![first];
    let mut seen = HashSet::new();
    while let Some(at) = queue.pop() {
        if !seen.insert(at) {
            continue;
        }
        if seen.len() > MAX_SECTIONS {
            return unsupported("its index has more sections than this check follows");
        }
        if at >= d.len {
            return damaged("cut short: part of its index lies past the end of the file");
        }
        let next = section(d, at, &mut index)?;
        queue.extend(next.into_iter().map(|n| n.saturating_add(index.shift)));
    }
    let Some(root) = index.root else {
        return damaged("its index does not name the document's catalog");
    };
    if !index.entries.contains_key(&(root as u64)) {
        return damaged("its catalog, the object every page hangs from, is missing");
    }
    // Objects in order of offset, so the file is read front to back.
    let mut places: Vec<(u64, u64)> = Vec::new();
    for (number, loc) in &index.entries {
        match loc {
            Loc::At(at) => {
                d.hold(PLACE_HELD)?;
                places.push((at.saturating_add(index.shift), *number));
            }
            Loc::In(holder) => {
                if !matches!(index.entries.get(holder), Some(Loc::At(_))) {
                    return damaged(format!(
                        "object {number} is said to be in object {holder}, which is missing"
                    ));
                }
            }
        }
    }
    places.sort_unstable();
    let mut streams = 0u64;
    for (at, number) in &places {
        d.item()?;
        if *at >= d.len {
            return damaged(format!(
                "cut short: object {number} lies past the end of the file"
            ));
        }
        let w = window(d, *at, false)?;
        let mut found = object(&w, *at);
        if found
            .as_ref()
            .is_some_and(|o| o.dict.is_none() && o.int.is_none())
        {
            // A dictionary larger than the small window: read more.
            let w = window(d, *at, true)?;
            if let Some(o) = object(&w, *at) {
                if o.number as u64 == *number {
                    if let (Some(dict), Some(start)) = (&o.dict, o.stream) {
                        streams += u64::from(stream(d, o.number, dict, start, &index)?);
                    }
                    continue;
                }
            }
            found = None;
        }
        match found {
            Some(o) if o.number >= 0 && o.number as u64 == *number => {
                if let (Some(dict), Some(start)) = (&o.dict, o.stream) {
                    streams += u64::from(stream(d, o.number, dict, start, &index)?);
                }
            }
            _ => {
                return damaged(format!(
                    "object {number} is not at byte {at}, where its index says"
                ))
            }
        }
    }
    let mut note = say::pdf(index.entries.len() as u64, streams);
    if index.encrypted {
        note.push_str("; it is encrypted, so the contents of its streams were not unpacked");
    }
    let tail = d.upto(eof_end, 4096)?;
    if tail.iter().any(|c| !white(*c)) {
        note.push_str(&say::more_follow(d.len - eof_end, "its end marker"));
    }
    good("PDF document", note)
}

fn starts_section(w: &[u8]) -> bool {
    w.starts_with(b"xref") || object(w, 0).is_some()
}
