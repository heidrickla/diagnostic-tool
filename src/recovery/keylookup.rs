//! Finding a BitLocker recovery key so the technician does not have to type it: on the
//! customer's Microsoft account page (personal, or work or school), which the GUI shows in a
//! sign-in window built on `webview2`, or in a "BitLocker Recovery Key <ID>.TXT" file that
//! Windows saved to a drive.
//!
//! A recovery key is a secret (recovery rule 7). It is held in a `SecretKey`, which zeroes
//! itself when dropped and never prints its digits. Page text and file text are zeroed once
//! they have been searched, and are never logged or stored.
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{compiler_fence, AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub mod webview2;

use crate::tools::crash_dumps::DumpExclusion;

// ---------------------------------------------------------------- secrets in memory

/// Overwrites `bytes` with zeros in a way the optimiser keeps.
pub fn scrub(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// `scrub` for numbers that held a key's groups.
pub fn scrub_words(words: &mut [u32]) {
    for word in words.iter_mut() {
        // SAFETY: `word` is a valid, exclusive reference.
        unsafe { std::ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Bytes that may hold a recovery key, as read from a key file: zeroed when dropped, the
/// spare capacity included, on every path (a panic's too), and left out of dumps of this
/// process while they live. Filled in place up to the capacity given, so they never move.
pub struct SecretBytes {
    /// Declared first: taken back after the bytes are zeroed and before they are freed.
    _shield: Option<DumpShield>,
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Reads `reader` to its end, or to `limit` bytes (`Err` beyond), into a buffer sized
    /// to `limit` up front.
    pub fn read_to_end(reader: &mut impl std::io::Read, limit: usize) -> std::io::Result<Self> {
        let bytes = vec![0u8; limit + 1];
        let shield = DumpShield::over(bytes.as_ptr(), bytes.capacity());
        let mut own = Self {
            _shield: shield,
            bytes,
        };
        let mut filled = 0;
        loop {
            if filled == own.bytes.len() {
                return Err(std::io::Error::other("larger than a key file"));
            }
            match reader.read(&mut own.bytes[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        // Within the capacity: nothing is moved, and Drop zeroes the whole capacity.
        own.bytes.truncate(filled);
        Ok(own)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let len = self.bytes.len();
        self.bytes.resize(self.bytes.capacity(), 0);
        scrub(&mut self.bytes);
        self.bytes.truncate(len);
    }
}

/// `scrub` for UTF-16 text.
pub fn scrub_wide(units: &mut [u16]) {
    for unit in units.iter_mut() {
        // SAFETY: `unit` is a valid, exclusive reference.
        unsafe { std::ptr::write_volatile(unit, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Asks Windows Error Reporting to leave a buffer that may hold a recovery key out of dumps
/// of this process, for as long as the value lives; dropping it takes the request back, so
/// drop it before the buffer is freed. `None` when Windows refused the request. Measured
/// on Windows 11 (DESIGN.md, crash dumps and the key): a LocalDumps dump still held a
/// registered block, so this backs up, and does not replace, this program's own LocalDumps
/// exclusion (`crash_dumps::keep_out_of_dumps`).
pub struct DumpShield(usize);

impl DumpShield {
    pub fn over(start: *const u8, len: usize) -> Option<Self> {
        use windows_sys::Win32::System::ErrorReporting::WerRegisterExcludedMemoryBlock;
        let len = u32::try_from(len).ok().filter(|len| *len > 0)?;
        if start.is_null() {
            return None;
        }
        // SAFETY: Windows only records the address and size; the owner keeps the block
        // allocated until this value is dropped.
        let result = unsafe { WerRegisterExcludedMemoryBlock(start.cast(), len) };
        (result >= 0).then_some(Self(start as usize))
    }
}

impl Drop for DumpShield {
    fn drop(&mut self) {
        use windows_sys::Win32::System::ErrorReporting::WerUnregisterExcludedMemoryBlock;
        // SAFETY: the address is one this value registered.
        unsafe { WerUnregisterExcludedMemoryBlock(self.0 as *const std::ffi::c_void) };
    }
}

/// A shield over a string's whole buffer, its spare capacity included.
fn shield_string(text: &String) -> Option<DumpShield> {
    DumpShield::over(text.as_ptr(), text.capacity())
}

/// Text that may hold a recovery key: zeroed when dropped, and left out of dumps of this
/// process while it lives (`DumpShield`). Build it with enough capacity up front
/// (`with_capacity`) so a growing buffer leaves no copy behind.
pub struct ScrubbedText {
    /// Declared first: it is taken back after the text is zeroed and before it is freed.
    shield: Option<DumpShield>,
    text: String,
}

impl ScrubbedText {
    pub fn with_capacity(capacity: usize) -> Self {
        let text = String::with_capacity(capacity);
        Self {
            shield: shield_string(&text),
            text,
        }
    }

    /// Adds a character; the caller reserved the room. Should the buffer move anyway, the
    /// shield moves with it.
    pub fn push(&mut self, c: char) {
        let (start, capacity) = (self.text.as_ptr(), self.text.capacity());
        self.text.push(c);
        if self.text.as_ptr() != start || self.text.capacity() != capacity {
            self.shield = None;
            self.shield = shield_string(&self.text);
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether Windows took the request to leave this text out of dumps.
    pub fn shielded(&self) -> bool {
        self.shield.is_some()
    }
}

impl Drop for ScrubbedText {
    fn drop(&mut self) {
        // SAFETY: the bytes are zeroed and the string is never read again; zeros are UTF-8.
        let bytes = unsafe { self.text.as_mut_vec() };
        let len = bytes.len();
        // The spare capacity can hold an earlier, longer text; zero all of it.
        bytes.resize(bytes.capacity(), 0);
        scrub(bytes);
        bytes.truncate(len);
    }
}

/// Characters in a recovery key as written: eight groups of six digits joined by hyphens.
const KEY_LEN: usize = 55;

/// A BitLocker recovery key (a 48-digit recovery password). It zeroes itself when dropped,
/// cannot be copied by accident (no Clone), and its Debug text hides the digits.
/// The digits live in their own heap block, written in place, so the block stays where it
/// is while the key moves and is left out of dumps of this process (`DumpShield`).
pub struct SecretKey {
    /// Declared first: it is taken back after the digits are zeroed and before they are
    /// freed.
    shield: Option<DumpShield>,
    text: Box<[u8; KEY_LEN]>,
    /// This program stays out of crash dumps while the key lives, wherever it is kept: in
    /// a search or sign-in result, or held by a caller after the lookup returned.
    dumps: Option<DumpExclusion>,
}

impl SecretKey {
    fn from_groups(groups: &[u32; 8]) -> Self {
        let mut text = Box::new([b'-'; KEY_LEN]);
        let shield = DumpShield::over(text.as_ptr(), KEY_LEN);
        for (index, group) in groups.iter().enumerate() {
            let mut value = *group;
            let start = index * 7;
            for place in (0..6).rev() {
                text[start + place] = b'0' + (value % 10) as u8;
                value /= 10;
            }
            // SAFETY: `value` is a valid local; the volatile write is kept.
            unsafe { std::ptr::write_volatile(&mut value, 0) };
        }
        Self {
            shield,
            text,
            dumps: crate::tools::crash_dumps::exclusion_share(),
        }
    }

    /// The share of the exclusion from crash dumps this key holds.
    pub fn exclusion(&self) -> Option<&DumpExclusion> {
        self.dumps.as_ref()
    }

    /// Whether Windows took the request to leave the digits out of dumps.
    pub fn shielded(&self) -> bool {
        self.shield.is_some()
    }

    /// The key as Windows wants it typed: "123456-123456-...". Pass it straight to the unlock
    /// call; do not keep a copy.
    pub fn as_str(&self) -> &str {
        // The text is only ever ASCII digits and hyphens.
        std::str::from_utf8(&self.text[..]).unwrap_or("")
    }

    /// Whether two keys have the same digits.
    pub fn same_as(&self, other: &SecretKey) -> bool {
        self.text == other.text
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        scrub(&mut self.text[..]);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(48 digits, hidden)")
    }
}

// ---------------------------------------------------------------- keys and key IDs in text

/// A recovery key group is a multiple of 11 below 65536 * 11 (each group carries 16 bits).
fn valid_group(value: u32) -> bool {
    value.is_multiple_of(11) && value / 11 <= 0xFFFF
}

/// Length of the separator at `i` between key groups: a hyphen (or a typographic hyphen,
/// dash or minus a page may use), a space or a no-break space.
fn separator_len(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'-' | b' ' => Some(1),
        0xC2 if b.get(i + 1) == Some(&0xA0) => Some(2),
        0xE2 => match (b.get(i + 1), b.get(i + 2)) {
            (Some(0x80), Some(0x90..=0x93)) | (Some(0x88), Some(0x92)) => Some(3),
            _ => None,
        },
        _ => None,
    }
}

/// Every recovery key in `text`, with where it starts, in order. A run of digit groups that
/// is not exactly eight groups of six, or with a group that is not a valid key group, is
/// skipped whole, so no key is ever read out of the middle of a longer number.
fn find_keys(text: &str) -> Vec<(usize, SecretKey)> {
    let b = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() || (i > 0 && b[i - 1].is_ascii_digit()) {
            i += 1;
            continue;
        }
        let start = i;
        let mut groups = [0u32; 8];
        let mut count = 0usize;
        let mut well_formed = true;
        // One run: digits, then (separator, digits) while a digit follows the separator.
        loop {
            let digits_start = i;
            let mut value = 0u32;
            while i < b.len() && b[i].is_ascii_digit() {
                value = value
                    .saturating_mul(10)
                    .saturating_add(u32::from(b[i] - b'0'));
                i += 1;
            }
            if i - digits_start != 6 || count == 8 {
                well_formed = false;
            } else {
                groups[count] = value;
            }
            // SAFETY: `value` is a valid local; the volatile write is kept.
            unsafe { std::ptr::write_volatile(&mut value, 0) };
            count += 1;
            match separator_len(b, i) {
                Some(len) if b.get(i + len).is_some_and(u8::is_ascii_digit) => i += len,
                _ => break,
            }
        }
        if well_formed && count == 8 && groups.iter().all(|g| valid_group(*g)) {
            found.push((start, SecretKey::from_groups(&groups)));
        }
        scrub_words(&mut groups);
    }
    found
}

/// A key ID: the first eight hex digits, and the whole GUID when the text gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyId {
    /// Upper case, eight characters.
    pub prefix: String,
    /// Upper case, 36 characters with hyphens, when known.
    pub full: Option<String>,
}

impl KeyId {
    /// Reads a key ID as a person or Windows writes it: eight hex digits (the recovery
    /// screen shows these) or a whole GUID, with or without braces. None for anything else.
    pub fn parse(text: &str) -> Option<KeyId> {
        let trimmed = text
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();
        let b = trimmed.as_bytes();
        if b.len() == 8 && b.iter().all(u8::is_ascii_hexdigit) {
            return Some(KeyId {
                prefix: trimmed.to_ascii_uppercase(),
                full: None,
            });
        }
        if guid_at(b, 0) == Some(36) && b.len() == 36 {
            let full = trimmed.to_ascii_uppercase();
            return Some(KeyId {
                prefix: full[..8].to_string(),
                full: Some(full),
            });
        }
        None
    }

    /// Same key: the prefixes agree, and the whole GUIDs too when both are known.
    pub fn matches(&self, other: &KeyId) -> bool {
        self.prefix == other.prefix
            && match (&self.full, &other.full) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }

    /// The ID as a person looks for it on a page: the first eight characters.
    pub fn shown(&self) -> &str {
        &self.prefix
    }
}

fn hex_run(b: &[u8], at: usize, len: usize) -> bool {
    b.len() >= at + len && b[at..at + len].iter().all(u8::is_ascii_hexdigit)
}

/// The length of a GUID (8-4-4-4-12 hex digits) starting at `at`, if one does.
fn guid_at(b: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    for (index, len) in [8usize, 4, 4, 4, 12].iter().enumerate() {
        if index > 0 {
            if b.get(i) != Some(&b'-') {
                return None;
            }
            i += 1;
        }
        if !hex_run(b, i, *len) {
            return None;
        }
        i += len;
    }
    Some(i - at)
}

/// Whether the token boundary before `at` is clean: not inside a word, and not the tail of
/// a hyphenated word such as a device name "DESKTOP-1A2B3C4D".
fn clean_before(b: &[u8], at: usize) -> bool {
    if at == 0 {
        return true;
    }
    let before = b[at - 1];
    if before.is_ascii_alphanumeric() || before == b'_' {
        return false;
    }
    !(before == b'-' && at >= 2 && b[at - 2].is_ascii_alphanumeric())
}

/// The same for the boundary after a token ending at `end`.
fn clean_after(b: &[u8], end: usize) -> bool {
    match b.get(end) {
        None => true,
        Some(c) if c.is_ascii_alphanumeric() || *c == b'_' => false,
        Some(b'-') => !b.get(end + 1).is_some_and(u8::is_ascii_alphanumeric),
        Some(_) => true,
    }
}

/// Every key ID in `text` (whole GUIDs, and eight hex digits standing alone), with where
/// each starts, in order.
fn find_key_ids(text: &str) -> Vec<(usize, KeyId)> {
    let b = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_hexdigit() || !clean_before(b, i) {
            i += 1;
            continue;
        }
        if let Some(len) = guid_at(b, i).filter(|len| clean_after(b, i + len)) {
            let full = text[i..i + len].to_ascii_uppercase();
            found.push((
                i,
                KeyId {
                    prefix: full[..8].to_string(),
                    full: Some(full),
                },
            ));
            i += len;
            continue;
        }
        if hex_run(b, i, 8) && clean_after(b, i + 8) {
            found.push((
                i,
                KeyId {
                    prefix: text[i..i + 8].to_ascii_uppercase(),
                    full: None,
                },
            ));
            i += 8;
            continue;
        }
        i += 1;
    }
    found
}

/// What reading a page (or a key file) for a set of key IDs found.
#[derive(Debug)]
pub enum PageRead {
    /// The key listed under one of the IDs asked for.
    Found(SecretKey),
    /// The page lists recovery keys, but none under the IDs asked for.
    NotListed { keys: usize },
    /// No recovery key was recognised, or the page could not be read with certainty (two
    /// different keys could belong to the ID). The technician copies the key by hand.
    NotUnderstood,
}

enum Item {
    Id(KeyId),
    Key(SecretKey),
}

/// Finds the recovery key listed under one of `key_ids` in a page's visible text.
///
/// Pages list each key next to its ID. Which comes first is read from the page itself: the
/// order (ID then key, or key then ID) seen most often between neighbours wins, and the key
/// next to a wanted ID in that order is the answer. When the orders tie, an ID with a key on
/// only one side still gives an answer. The wanted IDs are tried in order, and the first
/// with exactly one key beside it gives the answer (every protector of a drive unlocks it).
/// An ID with two different keys beside it is not an answer: the technician then picks by
/// hand.
pub fn read_page(text: &str, key_ids: &[String]) -> PageRead {
    let wanted: Vec<KeyId> = key_ids.iter().filter_map(|id| KeyId::parse(id)).collect();
    let mut items: Vec<(usize, Item)> = find_keys(text)
        .into_iter()
        .map(|(at, key)| (at, Item::Key(key)))
        .collect();
    let keys = items.len();
    if keys == 0 {
        return PageRead::NotUnderstood;
    }
    items.extend(
        find_key_ids(text)
            .into_iter()
            .map(|(at, id)| (at, Item::Id(id))),
    );
    items.sort_by_key(|(at, _)| *at);
    let (mut id_first, mut key_first) = (0usize, 0usize);
    for pair in items.windows(2) {
        match (&pair[0].1, &pair[1].1) {
            (Item::Id(_), Item::Key(_)) => id_first += 1,
            (Item::Key(_), Item::Id(_)) => key_first += 1,
            _ => {}
        }
    }
    let is_key = |index: usize| matches!(items.get(index), Some((_, Item::Key(_))));
    // For each wanted ID in turn, the distinct keys beside it.
    let mut unclear = false;
    for want in &wanted {
        let mut answers: Vec<usize> = Vec::new();
        for (index, (_, item)) in items.iter().enumerate() {
            let Item::Id(id) = item else { continue };
            if !want.matches(id) {
                continue;
            }
            let after = Some(index + 1).filter(|i| is_key(*i));
            let before = index.checked_sub(1).filter(|i| is_key(*i));
            let candidates: Vec<usize> = if id_first > key_first {
                after.into_iter().collect()
            } else if key_first > id_first {
                before.into_iter().collect()
            } else {
                before.into_iter().chain(after).collect()
            };
            for candidate in candidates {
                let same = |known: &usize| match (&items[*known].1, &items[candidate].1) {
                    (Item::Key(a), Item::Key(b)) => a.same_as(b),
                    _ => false,
                };
                if !answers.iter().any(same) {
                    answers.push(candidate);
                }
            }
        }
        match answers.as_slice() {
            [] => {}
            [only] => {
                let only = *only;
                return match items.swap_remove(only).1 {
                    Item::Key(key) => PageRead::Found(key),
                    Item::Id(_) => PageRead::NotUnderstood,
                };
            }
            _ => unclear = true,
        }
    }
    if unclear {
        PageRead::NotUnderstood
    } else {
        PageRead::NotListed { keys }
    }
}

// ---------------------------------------------------------------- script results

/// Decodes the JSON string WebView2 returns from a script (`"line\nline"`) into text that is
/// zeroed when dropped. None when the result is not a JSON string (a page with no body
/// returns `null`).
pub fn decode_script_string(json: &str) -> Option<ScrubbedText> {
    let inner = json.trim().strip_prefix('"')?.strip_suffix('"')?;
    let mut out = ScrubbedText::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let decoded = match chars.next()? {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let high = hex4(&mut chars)?;
                if (0xD800..0xDC00).contains(&high) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let low = hex4(&mut chars)?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return None;
                    }
                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))?
                } else {
                    char::from_u32(high).unwrap_or('\u{FFFD}')
                }
            }
            _ => return None,
        };
        out.push(decoded);
    }
    Some(out)
}

fn hex4(chars: &mut std::str::Chars<'_>) -> Option<u32> {
    let mut value = 0;
    for _ in 0..4 {
        value = value * 16 + chars.next()?.to_digit(16)?;
    }
    Some(value)
}

// ---------------------------------------------------------------- where the sign-in may go

/// Which kind of account holds the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Account {
    /// A personal Microsoft account (outlook.com, hotmail.com, live.com and others).
    Personal,
    /// A work or school account (Microsoft Entra ID), through the self-service My Account
    /// page, which needs no administrator consent.
    WorkOrSchool,
}

impl Account {
    /// Where the window starts; Microsoft sends the customer to sign in first.
    pub fn start_url(self) -> &'static str {
        match self {
            Account::Personal => "https://account.microsoft.com/devices/recoverykey",
            Account::WorkOrSchool => "https://myaccount.microsoft.com/device-list",
        }
    }

    /// Whether `uri` is the page that lists recovery keys, whose text is then read.
    pub fn is_key_page(self, uri: &str) -> bool {
        let Some((host, path)) = https_host_and_path(uri) else {
            return false;
        };
        let path = path.to_ascii_lowercase();
        match self {
            Account::Personal => {
                host == "account.microsoft.com" && path.starts_with("/devices/recoverykey")
            }
            // Keys show in a device's panel on the devices pages.
            Account::WorkOrSchool => {
                host == "myaccount.microsoft.com" && path.starts_with("/device")
            }
        }
    }
}

/// The hosts the sign-in window may show, in its main page or in a frame. Microsoft's sign-in
/// and account pages, and the hosts those pages were measured to navigate to on 2026-11-06.
/// Anything else is refused.
pub const ALLOWED_HOSTS: &[&str] = &[
    "login.live.com",
    "account.live.com",
    "account.microsoft.com",
    "login.microsoftonline.com",
    "login.microsoft.com",
    "myaccount.microsoft.com",
    "mysignins.microsoft.com",
];

/// The host of an https address, lower case, with its path; None for anything else (another
/// scheme, a user name in the address, a port other than 443).
fn https_host_and_path(uri: &str) -> Option<(String, &str)> {
    let scheme = uri.get(..8)?;
    if !scheme.eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &uri[8..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.contains(['@', '\\']) {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, "443")) => host,
        Some(_) => return None,
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some((host, path))
}

/// Whether the sign-in window may go to `uri`. Err carries what to tell the technician: the
/// host that was refused, or the kind of address (never the path, which can carry tokens).
pub fn navigation_allowed(uri: &str) -> Result<(), String> {
    if uri.eq_ignore_ascii_case("about:blank") {
        return Ok(());
    }
    match https_host_and_path(uri) {
        Some((host, _)) if ALLOWED_HOSTS.contains(&host.as_str()) => Ok(()),
        Some((host, _)) => Err(host),
        None => Err(match uri.split_once(':') {
            Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => {
                "an address with a user name or an unusual port".to_string()
            }
            Some((scheme, _))
                if !scheme.is_empty()
                    && scheme.len() < 16
                    && scheme.bytes().all(|c| c.is_ascii_alphanumeric()) =>
            {
                format!("an address starting {}:", scheme.to_ascii_lowercase())
            }
            _ => "an address that is not https".to_string(),
        }),
    }
}

/// The host of `uri`, for a status line or the probe's notes; never the path.
pub fn host_of(uri: &str) -> String {
    https_host_and_path(uri)
        .map(|(host, _)| host)
        .unwrap_or_else(|| uri.split(':').next().unwrap_or("").to_string())
}

// ---------------------------------------------------------------- the sign-in step

/// The only script the sign-in window runs in a page: its visible text.
pub const PAGE_TEXT_SCRIPT: &str = "document.body.innerText";
/// How long the key page may show with no key read before the technician is told to copy
/// the key by hand (the page fills in after it loads).
pub const READ_GRACE: Duration = Duration::from_secs(12);

/// What the window says while the customer signs in.
pub const SIGNING_IN: &str = "Opening Microsoft's sign-in page. The customer signs in there.";

/// What the sign-in step looks for. Plain data an agent can supply.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignInOptions {
    /// The locked drive's key IDs: the eight hex digits the recovery screen shows, or whole
    /// GUIDs. 1 to 16 entries; entries that are not key IDs are ignored, but at least one
    /// must be.
    pub key_ids: Vec<String>,
    /// Open straight to this kind of account's sign-in page. None (the default) lets the
    /// technician choose in the window.
    pub account: Option<Account>,
}

/// What the sign-in step reports as it goes. Hosts only, never addresses (they can carry
/// sign-in codes), never page text or a key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SignInEvent {
    AccountChosen {
        account: Account,
    },
    /// A page (or a frame in it) on an allowed host opened.
    Opened {
        host: String,
        frame: bool,
    },
    /// A page or frame outside the allowed hosts was refused; `host` is the host, or the
    /// kind of address.
    Refused {
        host: String,
        frame: bool,
    },
    /// A page asked for a new window on an allowed host; it opened in the same view.
    NewWindowOpenedHere {
        host: String,
    },
    NewWindowRefused {
        host: String,
    },
    /// The page that lists recovery keys is showing and is being read.
    KeyPageShown,
    /// The key for a wanted ID was read; the window closes.
    KeyRead,
    /// The account lists keys, none for the wanted IDs.
    NoMatch {
        keys_listed: usize,
    },
    /// The key page could not be read with certainty; the technician was told to copy the
    /// key by hand.
    NotUnderstood,
    DownloadCancelled,
    BrowserFailed,
    /// The browser did not take this window's refusal of `what` (a page, a new window or
    /// a download), so the sign-in ended without reading a key.
    CouldNotRefuse {
        what: String,
    },
}

/// How the sign-in step ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignInOutcome {
    /// The key was read; it is in `SignInResult::key` for the unlock step, never here.
    KeyRead,
    /// The account lists keys but none for the wanted IDs. Manual entry follows.
    NoMatch { keys_listed: usize },
    /// The key page showed but could not be read with certainty. Manual entry follows.
    NotUnderstood,
    /// The window was closed (or cancelled) before a key page was read.
    Cancelled,
    /// The window could not work on this PC; `reason` says why. Manual entry follows.
    Unavailable { reason: String },
}

/// What the sign-in step gives back. The serialized form carries no key: `key` is for the
/// unlock step only and is skipped by serde.
#[derive(Debug, Serialize)]
pub struct SignInResult {
    pub outcome: SignInOutcome,
    pub account: Option<Account>,
    /// Hosts the window opened, in order, each once.
    pub hosts_opened: Vec<String>,
    /// Hosts (or kinds of address) the window refused, in order, each once.
    pub hosts_refused: Vec<String>,
    /// Whether the browser's data folder (cookies, the signed-in session) was removed when
    /// the window closed. When false it is removed the next time the window opens.
    pub folder_removed: bool,
    /// Sign-in folders an earlier window left (they can hold a signed-in session) that
    /// could not be removed this time either, with why.
    pub old_folders_left: Vec<(PathBuf, String)>,
    #[serde(skip)]
    pub key: Option<SecretKey>,
}

impl SignInResult {
    pub fn unavailable(reason: String) -> Self {
        Self {
            outcome: SignInOutcome::Unavailable { reason },
            account: None,
            hosts_opened: Vec::new(),
            hosts_refused: Vec::new(),
            folder_removed: true,
            old_folders_left: Vec::new(),
            key: None,
        }
    }
}

/// What the window does next after the key page's text was read.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadStep {
    /// Nothing to show yet; read again at the next tick.
    Wait,
    /// The key was read: close the window.
    Done,
    /// Show this to the technician (once) and keep the page open.
    Tell(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LastRead {
    NoMatch(usize),
    NotUnderstood,
}

/// The sign-in step's state and every decision in it: which addresses may open, when the
/// key page is read, what the page's text gives, what the technician is told, and the
/// result. The window feeds it what the browser does and shows what it says.
pub struct SignIn {
    ids: Vec<String>,
    shown: String,
    account: Option<Account>,
    on_key_page: Option<Instant>,
    last: Option<LastRead>,
    told: bool,
    key: Option<SecretKey>,
    opened: Vec<String>,
    refused: Vec<String>,
    events: Vec<SignInEvent>,
    /// Set when a refusal did not take: the sign-in ends and no key is read.
    broken: Option<String>,
}

fn push_once(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

impl SignIn {
    /// Err with the reason when the options are out of bounds.
    pub fn new(options: &SignInOptions) -> Result<SignIn, String> {
        crate::recovery::bitlocker::mark_key_held();
        let wanted = wanted_ids(&options.key_ids)?;
        let mut shown: Vec<&str> = Vec::new();
        for id in &wanted {
            if !shown.contains(&id.shown()) {
                shown.push(id.shown());
            }
        }
        Ok(SignIn {
            ids: options.key_ids.clone(),
            shown: shown.join(" or "),
            account: None,
            on_key_page: None,
            last: None,
            told: false,
            key: None,
            opened: Vec::new(),
            refused: Vec::new(),
            events: Vec::new(),
            broken: None,
        })
    }

    /// The IDs as a person looks for them: "1A2B3C4D" or "1A2B3C4D or 5E6F7A8B".
    pub fn shown_ids(&self) -> &str {
        &self.shown
    }

    pub fn account(&self) -> Option<Account> {
        self.account
    }

    /// The technician (or the options) chose an account: where to go.
    pub fn choose(&mut self, account: Account) -> &'static str {
        self.account = Some(account);
        self.on_key_page = None;
        self.told = false;
        self.events.push(SignInEvent::AccountChosen { account });
        account.start_url()
    }

    fn refused_text(&self, host: &str) -> String {
        let mut text = format!(
            "Only Microsoft's sign-in and account pages open here, so {host} was not opened."
        );
        if self.account == Some(Account::WorkOrSchool) {
            text.push_str(
                " A work or school account that signs in through its own company page cannot \
                 be used here; find the key on another device instead.",
            );
        }
        text
    }

    /// A navigation is starting: Ok to let it, Err with what to tell the technician (for a
    /// page; a refused frame is only recorded).
    pub fn navigation(&mut self, uri: &str, frame: bool) -> Result<(), String> {
        match navigation_allowed(uri) {
            Ok(()) => {
                let host = host_of(uri);
                push_once(&mut self.opened, host.clone());
                self.events.push(SignInEvent::Opened { host, frame });
                Ok(())
            }
            Err(host) => {
                push_once(&mut self.refused, host.clone());
                self.events.push(SignInEvent::Refused {
                    host: host.clone(),
                    frame,
                });
                Err(self.refused_text(&host))
            }
        }
    }

    /// A page asked for a new window: Ok to open the address in the same view instead, Err
    /// with what to tell the technician.
    pub fn new_window(&mut self, uri: &str) -> Result<(), String> {
        match navigation_allowed(uri) {
            Ok(()) => {
                self.events
                    .push(SignInEvent::NewWindowOpenedHere { host: host_of(uri) });
                Ok(())
            }
            Err(host) => {
                push_once(&mut self.refused, host.clone());
                self.events
                    .push(SignInEvent::NewWindowRefused { host: host.clone() });
                Err(self.refused_text(&host))
            }
        }
    }

    pub fn download_cancelled(&mut self) -> &'static str {
        self.events.push(SignInEvent::DownloadCancelled);
        "Downloads are turned off in this window."
    }

    /// The browser did not take a refusal of `what` ("a page outside Microsoft's sign-in",
    /// "a new window", "a download"): the sign-in ends here, no key is read from it, and the
    /// window closes. What to tell the technician.
    pub fn could_not_refuse(&mut self, what: &str) -> String {
        self.events
            .push(SignInEvent::CouldNotRefuse { what: what.into() });
        let reason = format!(
            "The sign-in window could not refuse {what}, so it was closed without reading a key."
        );
        self.broken = Some(reason.clone());
        self.key = None;
        format!("{reason} Type the key in instead.")
    }

    /// Whether the sign-in ended because a refusal did not take.
    pub fn broken(&self) -> bool {
        self.broken.is_some()
    }

    pub fn browser_failed(&mut self) -> &'static str {
        self.events.push(SignInEvent::BrowserFailed);
        "The sign-in page stopped working. Close this window and type the key in."
    }

    /// Whether the page at `uri` is the key page and should be read now. `Some` carries what
    /// to tell the technician when the key page first shows, or when the window leaves it
    /// (Microsoft first sends the key page on to sign in).
    pub fn should_read(&mut self, uri: &str) -> (bool, Option<&'static str>) {
        if self.broken.is_some() {
            return (false, None);
        }
        let on_page = self.account.is_some_and(|a| a.is_key_page(uri));
        if !on_page {
            // Microsoft sends the window from the key page to sign in first.
            let left = self.on_key_page.take().is_some() && !self.told;
            return (false, left.then_some(SIGNING_IN));
        }
        if self.on_key_page.is_none() {
            self.on_key_page = Some(Instant::now());
            self.events.push(SignInEvent::KeyPageShown);
            return (true, Some("Reading the recovery key page."));
        }
        (true, None)
    }

    /// The key page's visible text was read (None when the script gave no text). The grace
    /// before telling the technician to type the key in by hand counts from when the key page
    /// first showed.
    pub fn page_text(&mut self, text: Option<&str>) -> ReadStep {
        let waited = self
            .on_key_page
            .map_or(Duration::ZERO, |since| since.elapsed());
        self.page_text_after(text, waited)
    }

    fn page_text_after(&mut self, text: Option<&str>, waited: Duration) -> ReadStep {
        if self.broken.is_some() {
            return ReadStep::Done;
        }
        let read = text.map_or(PageRead::NotUnderstood, |text| read_page(text, &self.ids));
        match read {
            PageRead::Found(key) => {
                self.key = Some(key);
                self.events.push(SignInEvent::KeyRead);
                ReadStep::Done
            }
            PageRead::NotListed { keys } => {
                self.last = Some(LastRead::NoMatch(keys));
                if self.told {
                    return ReadStep::Wait;
                }
                self.told = true;
                self.events.push(SignInEvent::NoMatch { keys_listed: keys });
                let listed = if keys == 1 {
                    "one recovery key".to_string()
                } else {
                    format!("{keys} recovery keys")
                };
                ReadStep::Tell(format!(
                    "This account lists {listed}, none with key ID {}. The key may be in \
                     another account: choose again to sign in with it. Or close this window \
                     and type the key in.",
                    self.shown
                ))
            }
            PageRead::NotUnderstood => {
                if waited < READ_GRACE {
                    return ReadStep::Wait;
                }
                self.last = Some(LastRead::NotUnderstood);
                if self.told {
                    return ReadStep::Wait;
                }
                self.told = true;
                self.events.push(SignInEvent::NotUnderstood);
                ReadStep::Tell(format!(
                    "The key could not be read from this page by itself. Find the key whose ID \
                     starts with {}, then close this window and type its 48 digits into the \
                     recovery key box.",
                    self.shown
                ))
            }
        }
    }

    pub fn key_read(&self) -> bool {
        self.key.is_some()
    }

    /// Events since the last call, for the caller's progress.
    pub fn take_events(&mut self) -> Vec<SignInEvent> {
        std::mem::take(&mut self.events)
    }

    /// The result once the window has closed and its folder was (or was not) removed.
    pub fn finish(mut self, folder_removed: bool) -> SignInResult {
        if let Some(reason) = self.broken.take() {
            return SignInResult {
                outcome: SignInOutcome::Unavailable { reason },
                account: self.account,
                hosts_opened: self.opened,
                hosts_refused: self.refused,
                folder_removed,
                old_folders_left: Vec::new(),
                key: None,
            };
        }
        let outcome = match (&self.key, self.last) {
            (Some(_), _) => SignInOutcome::KeyRead,
            (None, Some(LastRead::NoMatch(keys))) => SignInOutcome::NoMatch { keys_listed: keys },
            (None, Some(LastRead::NotUnderstood)) => SignInOutcome::NotUnderstood,
            (None, None) => SignInOutcome::Cancelled,
        };
        SignInResult {
            outcome,
            account: self.account,
            hosts_opened: self.opened,
            hosts_refused: self.refused,
            folder_removed,
            old_folders_left: Vec::new(),
            key: self.key,
        }
    }
}

// ---------------------------------------------------------------- the sign-in folder

/// The name every sign-in folder starts with, under %TEMP%.
const SIGN_IN_PREFIX: &str = "DiagnosticTool-signin-";

fn is_sign_in_folder_name(name: &str) -> bool {
    name.strip_prefix(SIGN_IN_PREFIX)
        .is_some_and(|tail| tail.len() == 16 && tail.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Makes a new, empty folder for one sign-in window's browser data under %TEMP%.
pub fn new_sign_in_folder() -> std::io::Result<PathBuf> {
    use rand::Rng;
    let tag: u64 = rand::rng().random();
    let path = std::env::temp_dir().join(format!("{SIGN_IN_PREFIX}{tag:016x}"));
    // create_dir, not create_dir_all: an existing folder of that name is an error.
    std::fs::create_dir(&path)?;
    Ok(path)
}

/// What a sweep of old sign-in folders did.
#[derive(Debug, Default)]
pub struct Sweep {
    pub removed: usize,
    /// Folders, or the temporary folder itself, that could not be read or removed, with
    /// why.
    pub left: Vec<(PathBuf, String)>,
}

/// Removes sign-in folders an earlier window could not remove (the browser had not let go of
/// them, or the program was ended), and says each it could not.
pub fn sweep_old_sign_in_folders(keep: Option<&Path>) -> Sweep {
    let mut sweep = Sweep::default();
    let temp = std::env::temp_dir();
    let entries = match std::fs::read_dir(&temp) {
        Ok(entries) => entries,
        Err(e) => {
            sweep.left.push((temp, format!("could not be read: {e}")));
            return sweep;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                sweep
                    .left
                    .push((std::env::temp_dir(), format!("could not be read: {e}")));
                continue;
            }
        };
        let name = entry.file_name();
        let path = entry.path();
        if !is_sign_in_folder_name(&name.to_string_lossy()) || Some(path.as_path()) == keep {
            continue;
        }
        match entry.file_type() {
            Ok(kind) if !kind.is_dir() => continue,
            Ok(_) => {}
            Err(e) => {
                sweep.left.push((path, format!("could not be read: {e}")));
                continue;
            }
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => sweep.removed += 1,
            Err(e) => sweep
                .left
                .push((path, format!("could not be removed: {e}"))),
        }
    }
    sweep
}

// ---------------------------------------------------------------- saved key files

/// A recovery key found in a "BitLocker Recovery Key <ID>.TXT" file.
pub struct SavedKey {
    pub path: PathBuf,
    /// The key ID from the file's name, upper case.
    pub key_id: String,
    pub key: SecretKey,
}

impl fmt::Debug for SavedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavedKey")
            .field("path", &self.path)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Key files are a few hundred bytes; anything far larger is not one.
const KEY_FILE_LIMIT: u64 = 64 * 1024;

/// The key ID in a key file's name: "BitLocker Recovery Key <GUID>.TXT", also with the
/// " (1)" Windows adds to a second copy. None for other names.
pub fn key_file_id(name: &str) -> Option<KeyId> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".txt")?;
    let rest = stem.strip_prefix("bitlocker recovery key ")?;
    let rest = rest.trim_start_matches('{');
    let b = rest.as_bytes();
    let len = guid_at(b, 0)?;
    let tail = rest[len..].trim_start_matches('}');
    let copy = tail.is_empty()
        || tail
            .strip_prefix(" (")
            .and_then(|t| t.strip_suffix(')'))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()));
    if !copy {
        return None;
    }
    KeyId::parse(&rest[..len])
}

/// Decodes a key file's bytes: UTF-16 (as Windows saves it, with or without a byte order
/// mark) or UTF-8. The result is zeroed when dropped.
fn decode_key_file(bytes: &[u8]) -> ScrubbedText {
    let utf16 = bytes.starts_with(&[0xFF, 0xFE])
        || (bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 && bytes[0] != 0);
    if utf16 {
        let body = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
        let mut out = ScrubbedText::with_capacity(body.len() * 2);
        let units = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair));
        for c in char::decode_utf16(units) {
            out.push(c.unwrap_or('\u{FFFD}'));
        }
        return out;
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let mut out = ScrubbedText::with_capacity(body.len() * 3);
    for chunk in body.utf8_chunks() {
        for c in chunk.valid().chars() {
            out.push(c);
        }
        if !chunk.invalid().is_empty() {
            out.push('\u{FFFD}');
        }
    }
    out
}

/// The key in one key file's contents, for the ID its name gives. The file states the ID
/// too ("Identifier:"); a file whose stated ID differs from its name is not trusted.
pub fn read_key_file(bytes: &[u8], id: &KeyId) -> Option<SecretKey> {
    let text = decode_key_file(bytes);
    let stated = find_key_ids(text.as_str());
    if stated.iter().any(|(_, found)| !found.matches(id)) {
        return None;
    }
    let wanted = [id.full.clone().unwrap_or_else(|| id.prefix.clone())];
    if stated.is_empty() {
        // An older file with no identifier line: one key and nothing else.
        let mut keys = find_keys(text.as_str());
        return (keys.len() == 1).then(|| keys.remove(0).1);
    }
    match read_page(text.as_str(), &wanted) {
        PageRead::Found(key) => Some(key),
        _ => None,
    }
}
/// Most unreadable folders and entries a search result lists by name.
pub const MAX_UNREADABLE: usize = 64;
/// Most key IDs one search or sign-in takes (a drive has a few protectors).
pub const MAX_KEY_IDS: usize = 16;
/// Most extra folders one search takes.
pub const MAX_FOLDERS: usize = 32;
/// Deepest search below a drive's root.
pub const MAX_DRIVE_DEPTH: usize = 2;
/// Deepest search below a folder passed in.
pub const MAX_FOLDER_DEPTH: usize = 8;
/// Longest time limit per drive or folder, in seconds.
pub const MAX_TIME_LIMIT_SECS: u64 = 120;

/// The key IDs of `ids` that parse, or Err when none does or there are too many.
fn wanted_ids(ids: &[String]) -> Result<Vec<KeyId>, String> {
    if ids.len() > MAX_KEY_IDS {
        return Err(format!(
            "At most {MAX_KEY_IDS} key IDs can be looked for at once."
        ));
    }
    let wanted: Vec<KeyId> = ids.iter().filter_map(|id| KeyId::parse(id)).collect();
    if wanted.is_empty() {
        return Err("No key ID was given in a form this program reads (eight hex digits, or the whole ID). Type the recovery key in instead.".to_string());
    }
    Ok(wanted)
}

/// What `search_key_files` looks for and where. Plain data an agent can supply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeyFileSearchOptions {
    /// The locked drive's key IDs: the eight hex digits the recovery screen shows, or whole
    /// GUIDs. 1 to 16 entries; entries that are not key IDs are ignored, but at least one
    /// must be.
    pub key_ids: Vec<String>,
    /// Folders to search as well, such as the output of a copy of the customer's files.
    /// 0 to 32 entries. Searched even on a network drive, since they were named.
    pub folders: Vec<PathBuf>,
    /// Search every mounted fixed and removable drive with a letter (never network, CD or
    /// DVD drives). Default true.
    pub search_drives: bool,
    /// Folder levels searched below each drive's root: 0 (the root only) to 2. Default 2.
    pub drive_depth: usize,
    /// Folder levels searched below each folder in `folders`: 0 to 8. Default 6, since a
    /// copied user profile nests deeper.
    pub folder_depth: usize,
    /// Seconds before the search of a drive or folder is given up, so a failing drive cannot
    /// stall it: 1 to 120. Default 20. What was found by then is kept.
    pub time_limit_secs: u64,
    /// Folders and files looked at per drive or folder before it is left: 1 to 1,000,000.
    /// Default 100,000.
    pub entry_limit: usize,
}

impl Default for KeyFileSearchOptions {
    fn default() -> Self {
        Self {
            key_ids: Vec::new(),
            folders: Vec::new(),
            search_drives: true,
            drive_depth: 2,
            folder_depth: 6,
            time_limit_secs: 20,
            entry_limit: 100_000,
        }
    }
}

impl KeyFileSearchOptions {
    /// Err with what is wrong when a field is out of its bounds.
    pub fn check(&self) -> Result<Vec<KeyId>, String> {
        let wanted = wanted_ids(&self.key_ids)?;
        if self.folders.len() > MAX_FOLDERS {
            return Err(format!(
                "At most {MAX_FOLDERS} folders can be searched at once."
            ));
        }
        if self.drive_depth > MAX_DRIVE_DEPTH {
            return Err(format!("The drive depth is 0 to {MAX_DRIVE_DEPTH}."));
        }
        if self.folder_depth > MAX_FOLDER_DEPTH {
            return Err(format!("The folder depth is 0 to {MAX_FOLDER_DEPTH}."));
        }
        if !(1..=MAX_TIME_LIMIT_SECS).contains(&self.time_limit_secs) {
            return Err(format!(
                "The time limit is 1 to {MAX_TIME_LIMIT_SECS} seconds."
            ));
        }
        if !(1..=1_000_000).contains(&self.entry_limit) {
            return Err("The entry limit is 1 to 1,000,000.".to_string());
        }
        if !self.search_drives && self.folders.is_empty() {
            return Err("Nothing to search: no drives and no folders.".to_string());
        }
        Ok(wanted)
    }
}

/// What `search_key_files` reports as it goes. Never carries a key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum KeyFileEvent {
    /// A drive or folder's search started.
    Searching { root: PathBuf },
    /// A key file for a wanted ID was found and its key checks out.
    Found { path: PathBuf, key_id: String },
    /// A file named for a wanted ID was not usable: too large, unreadable, or its key or
    /// stated ID did not check.
    Unusable { path: PathBuf, why: String },
    /// A drive or folder's search ended; `entries` were looked at.
    Searched {
        root: PathBuf,
        entries: usize,
        stopped_at_limit: bool,
    },
    /// A drive or folder did not finish within the time limit (it may be failing).
    GaveUp { root: PathBuf },
    /// A folder or entry could not be read, so a key file in it would not be found.
    Unreadable { path: PathBuf, why: String },
    /// A drive or folder's search could not be started, so it was not searched.
    NotSearched { root: PathBuf, why: String },
}

/// A key file found, as an agent may see it: where it is and its ID, never the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyFileFound {
    pub path: PathBuf,
    /// The key ID from the file's name, upper case.
    pub key_id: String,
}

/// Why a search ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStop {
    /// Every drive and folder was searched.
    Finished,
    /// One or more drives or folders were given up at the time limit.
    TimeLimit,
    /// The cancel flag was set.
    Cancelled,
}

/// What `search_key_files` found. The serialized form carries no key; `keys` holds them
/// for the unlock step and is skipped by serde.
#[derive(Debug, Serialize)]
pub struct KeyFileSearchResult {
    pub found: Vec<KeyFileFound>,
    pub unusable: Vec<(PathBuf, String)>,
    pub roots_searched: Vec<PathBuf>,
    pub roots_given_up: Vec<PathBuf>,
    /// Drives or folders whose search could not be started, with why: not searched.
    pub roots_not_searched: Vec<(PathBuf, String)>,
    /// Folders and entries that could not be read, the first `MAX_UNREADABLE` of them.
    pub unreadable: Vec<(PathBuf, String)>,
    /// How many could not be read in all.
    pub unreadable_count: usize,
    pub entries_seen: usize,
    pub stop: SearchStop,
    /// The keys, in the order of `found`. Hand one to the unlock step; never serialized.
    #[serde(skip)]
    pub keys: Vec<SavedKey>,
}

enum FileCheck {
    NotWanted,
    Found(SavedKey),
    Unusable(String),
}

/// Reads one key file if its name's ID is wanted.
fn try_key_file(path: &Path, wanted: &[KeyId]) -> FileCheck {
    let Some(id) = path
        .file_name()
        .and_then(|name| key_file_id(&name.to_string_lossy()))
    else {
        return FileCheck::NotWanted;
    };
    if !wanted.iter().any(|w| w.matches(&id)) {
        return FileCheck::NotWanted;
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > KEY_FILE_LIMIT => {
            return FileCheck::Unusable("too large to be a key file".to_string())
        }
        Ok(_) => {}
        Err(e) => return FileCheck::Unusable(format!("could not be read: {e}")),
    }
    let bytes = match std::fs::File::open(path)
        .and_then(|mut file| SecretBytes::read_to_end(&mut file, KEY_FILE_LIMIT as usize))
    {
        Ok(bytes) => bytes,
        Err(e) => return FileCheck::Unusable(format!("could not be read: {e}")),
    };
    let key = read_key_file(bytes.as_slice(), &id);
    drop(bytes);
    match key {
        Some(key) => FileCheck::Found(SavedKey {
            path: path.to_path_buf(),
            key_id: id.full.clone().unwrap_or(id.prefix.clone()),
            key,
        }),
        None => FileCheck::Unusable(
            "its recovery key or stated key ID does not check; it may be damaged".to_string(),
        ),
    }
}

/// What a search thread sends back.
enum Found {
    Key(SavedKey),
    Unusable(PathBuf, String),
    /// A folder or entry that could not be read, so was not searched.
    Unreadable(PathBuf, String),
    Done {
        root: PathBuf,
        entries: usize,
        stopped_at_limit: bool,
    },
}

/// Searches `root` and `depth` folder levels below it for key files, sending each find as
/// it comes (so a search given up on a stalled drive keeps what it had). Reparse points
/// (junctions, links) are not followed. Ends early when `stop` is set.
fn search_folder(
    root: &Path,
    depth: usize,
    limit: usize,
    wanted: &[KeyId],
    stop: &AtomicBool,
    send: &mpsc::Sender<Found>,
) {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    let mut stopped_at_limit = false;
    // A send fails only once the search was given up and nobody reads any more.
    let unread = |path: PathBuf, e: std::io::Error| {
        let _ = send.send(Found::Unreadable(path, e.to_string()));
    };
    'folders: while let Some((folder, level)) = queue.pop() {
        let entries = match std::fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(e) => {
                unread(folder, e);
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    unread(folder.clone(), e);
                    continue;
                }
            };
            if stop.load(Ordering::Relaxed) {
                break 'folders;
            }
            seen += 1;
            if seen > limit {
                stopped_at_limit = true;
                break 'folders;
            }
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(e) => {
                    unread(entry.path(), e);
                    continue;
                }
            };
            if meta.file_attributes() & REPARSE_POINT != 0 {
                continue;
            }
            if meta.is_dir() {
                if level < depth {
                    queue.push((entry.path(), level + 1));
                }
                continue;
            }
            let path = entry.path();
            let message = match try_key_file(&path, wanted) {
                FileCheck::NotWanted => continue,
                FileCheck::Found(saved) => Found::Key(saved),
                FileCheck::Unusable(why) => Found::Unusable(path, why),
            };
            let _ = send.send(message);
        }
    }
    let _ = send.send(Found::Done {
        root: root.to_path_buf(),
        entries: seen.min(limit),
        stopped_at_limit,
    });
}

/// The roots of every mounted fixed and removable drive with a letter (not network drives,
/// not CD or DVD drives).
fn local_drive_roots() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    // SAFETY: no arguments.
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| format!("{}:\\", char::from(b'A' + bit)))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
            // SAFETY: `wide` is a nul-terminated root path.
            let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
            kind == DRIVE_FIXED || kind == DRIVE_REMOVABLE
        })
        .map(PathBuf::from)
        .collect()
}

/// The key file search engine: finds "BitLocker Recovery Key <ID>.TXT" files for the
/// options' key IDs without any sign-in, in the root and first folder levels of every
/// mounted fixed and removable drive (never network drives) and in the folders passed in.
/// Each drive or folder is searched on its own thread and given up at the time limit, so a
/// failing drive cannot stall the search; what it found by then is kept. Each file's key is
/// checked as a recovery key, and its stated ID against its name, before it is returned.
///
/// `progress` gets every event on the calling thread. Setting `cancel` ends the search
/// within a tenth of a second with what was found. Err only for options out of bounds.
pub fn search_key_files(
    options: &KeyFileSearchOptions,
    progress: &mut dyn FnMut(&KeyFileEvent),
    cancel: &AtomicBool,
) -> Result<KeyFileSearchResult, String> {
    let wanted = Arc::new(options.check()?);
    // A key file read lands in this process: kept out of crash dumps while this runs, while
    // each search thread runs (it may outlive this past the time limit), and while each key
    // found lives (`SecretKey` holds a share).
    let dumps = crate::tools::crash_dumps::keep_out_of_dumps()?;
    let drives = if options.search_drives {
        local_drive_roots()
    } else {
        Vec::new()
    };
    let roots: Vec<(PathBuf, usize)> = drives
        .into_iter()
        .map(|root| (root, options.drive_depth))
        .chain(
            options
                .folders
                .iter()
                .map(|folder| (folder.clone(), options.folder_depth)),
        )
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let (send, receive) = mpsc::channel();
    let mut running: Vec<PathBuf> = Vec::new();
    let mut not_searched: Vec<(PathBuf, String)> = Vec::new();
    for (root, depth) in roots {
        let (wanted, stop, send) = (Arc::clone(&wanted), Arc::clone(&stop), send.clone());
        let limit = options.entry_limit;
        let name = root.clone();
        let share = dumps.clone();
        let spawned = std::thread::Builder::new()
            .name("key file search".into())
            .spawn(move || {
                search_folder(&root, depth, limit, &wanted, &stop, &send);
                drop(share);
            });
        match spawned {
            Ok(_) => {
                progress(&KeyFileEvent::Searching { root: name.clone() });
                running.push(name);
            }
            Err(e) => {
                let why = format!("its search could not be started: {e}");
                progress(&KeyFileEvent::NotSearched {
                    root: name.clone(),
                    why: why.clone(),
                });
                not_searched.push((name, why));
            }
        }
    }
    drop(send);
    let mut result = KeyFileSearchResult {
        found: Vec::new(),
        unusable: Vec::new(),
        roots_searched: Vec::new(),
        roots_given_up: Vec::new(),
        roots_not_searched: not_searched,
        unreadable: Vec::new(),
        unreadable_count: 0,
        entries_seen: 0,
        stop: SearchStop::Finished,
        keys: Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(options.time_limit_secs);
    while !running.is_empty() {
        if cancel.load(Ordering::Relaxed) {
            result.stop = SearchStop::Cancelled;
            break;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            result.stop = SearchStop::TimeLimit;
            break;
        }
        match receive.recv_timeout(left.min(Duration::from_millis(100))) {
            Ok(Found::Key(saved)) => {
                // The same file reached twice (a folder passed in that is also on a drive).
                let canonical = std::fs::canonicalize(&saved.path).unwrap_or(saved.path.clone());
                let known = result
                    .keys
                    .iter()
                    .any(|k| std::fs::canonicalize(&k.path).unwrap_or(k.path.clone()) == canonical);
                if !known {
                    let found = KeyFileFound {
                        path: saved.path.clone(),
                        key_id: saved.key_id.clone(),
                    };
                    progress(&KeyFileEvent::Found {
                        path: found.path.clone(),
                        key_id: found.key_id.clone(),
                    });
                    result.found.push(found);
                    result.keys.push(saved);
                }
            }
            Ok(Found::Unreadable(path, why)) => {
                progress(&KeyFileEvent::Unreadable {
                    path: path.clone(),
                    why: why.clone(),
                });
                result.unreadable_count += 1;
                if result.unreadable.len() < MAX_UNREADABLE {
                    result.unreadable.push((path, why));
                }
            }
            Ok(Found::Unusable(path, why)) => {
                progress(&KeyFileEvent::Unusable {
                    path: path.clone(),
                    why: why.clone(),
                });
                result.unusable.push((path, why));
            }
            Ok(Found::Done {
                root,
                entries,
                stopped_at_limit,
            }) => {
                running.retain(|r| *r != root);
                result.entries_seen += entries;
                progress(&KeyFileEvent::Searched {
                    root: root.clone(),
                    entries,
                    stopped_at_limit,
                });
                result.roots_searched.push(root);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // Searches still running are told to stop and left to end on their own threads.
    stop.store(true, Ordering::Relaxed);
    if result.stop == SearchStop::TimeLimit {
        for root in running {
            progress(&KeyFileEvent::GaveUp { root: root.clone() });
            result.roots_given_up.push(root);
        }
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests;
