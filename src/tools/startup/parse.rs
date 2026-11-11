//! The pure parts of the startup tool: command lines, path classes, flags, publisher
//! text, and readers for the task script's output, shortcut files and Task Manager's
//! startup approval values. Nothing here touches the PC.
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Section {
    RunKeys,
    StartupFolders,
    Tasks,
    Services,
    Drivers,
}

impl Section {
    pub const ALL: [Section; 5] = [
        Section::RunKeys,
        Section::StartupFolders,
        Section::Tasks,
        Section::Services,
        Section::Drivers,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Section::RunKeys => "Run keys",
            Section::StartupFolders => "Startup folders",
            Section::Tasks => "Scheduled tasks",
            Section::Services => "Services",
            Section::Drivers => "Drivers",
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// What an entry starts: the command's program, and the file whose signature stands for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The program the command names, environment variables expanded and searched for.
    pub exe: String,
    pub args: String,
    /// The file that is checked: the program, or the DLL that rundll32 or svchost loads.
    pub file: String,
    pub via_dll: bool,
}

impl Target {
    pub fn exe_name(&self) -> String {
        file_name(&self.exe).to_ascii_lowercase()
    }
}

/// Everything the builder needs from the PC, so tests can supply a made-up one.
pub struct Env<'a> {
    pub var: &'a dyn Fn(&str) -> Option<String>,
    pub exists: &'a dyn Fn(&str) -> bool,
    /// Directories searched for a program named without a folder.
    pub search: &'a [String],
}

const PROGRAM_EXTENSIONS: [&str; 12] = [
    "exe", "com", "dll", "sys", "bat", "cmd", "scr", "msi", "vbs", "js", "ps1", "cpl",
];

/// Replaces `%NAME%` with its value; an unknown name is left as written.
pub fn expand_env(text: &str, var: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('%') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('%') {
            Some(close) if close > 0 && !after[..close].contains(char::is_whitespace) => {
                match var(&after[..close]) {
                    Some(value) => out.push_str(&value),
                    None => out.push_str(&rest[open..open + close + 2]),
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn has_extension(path: &str) -> bool {
    file_name(path).contains('.')
}

fn extension(path: &str) -> String {
    file_name(path)
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Splits a command line into the program and its arguments. A quoted program is taken as
/// written; an unquoted one is the shortest start of the line that is a file, as
/// CreateProcess reads it, else the first start that ends in a program extension.
pub fn split_command(text: &str, exists: &dyn Fn(&str) -> bool) -> (String, String) {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => (rest[..end].to_string(), rest[end + 1..].trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
    }
    let mut ends = Vec::new();
    let mut in_word = false;
    for (index, c) in text.char_indices() {
        if c.is_whitespace() {
            if in_word {
                ends.push(index);
            }
            in_word = false;
        } else {
            in_word = true;
        }
    }
    if in_word {
        ends.push(text.len());
    }
    let Some(&first) = ends.first() else {
        return (String::new(), String::new());
    };
    let as_file = |candidate: &str| {
        if exists(candidate) {
            return Some(candidate.to_string());
        }
        (!has_extension(candidate) && exists(&format!("{candidate}.exe")))
            .then(|| format!("{candidate}.exe"))
    };
    for &end in &ends {
        if as_file(&text[..end]).is_some() {
            return (text[..end].to_string(), text[end..].trim().to_string());
        }
    }
    let end = ends
        .iter()
        .copied()
        .find(|&end| PROGRAM_EXTENSIONS.contains(&extension(&text[..end]).as_str()))
        .unwrap_or(first);
    (text[..end].to_string(), text[end..].trim().to_string())
}

/// The program as a full path where it can be found: a name with no folder is searched
/// for in `search`, and a name with no extension may be an .exe.
pub fn resolve_exe(exe: &str, search: &[String], exists: &dyn Fn(&str) -> bool) -> String {
    let found = |path: &str| {
        if exists(path) {
            Some(path.to_string())
        } else if !has_extension(path) && exists(&format!("{path}.exe")) {
            Some(format!("{path}.exe"))
        } else {
            None
        }
    };
    let bare = !exe.contains(['\\', '/', ':']);
    if bare {
        for dir in search {
            if let Some(path) = found(&format!("{dir}\\{exe}")) {
                return path;
            }
        }
        return exe.to_string();
    }
    found(exe).unwrap_or_else(|| exe.to_string())
}

/// The DLL named first in rundll32's arguments: `x.dll,Entry arg` or `"x y.dll",Entry`.
pub fn rundll_dll(args: &str) -> Option<String> {
    let mut rest = args.trim();
    while rest.starts_with('/') {
        rest = rest.split_once(char::is_whitespace)?.1.trim_start();
    }
    let dll = if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next()?
    } else {
        rest.split(char::is_whitespace).next()?.split(',').next()?
    };
    let dll = dll.trim();
    (!dll.is_empty()).then(|| dll.to_string())
}

/// Builds the target of a command line (a Run value, a shortcut's target and arguments).
pub fn target_of_command(command: &str, env: &Env) -> Target {
    let expanded = expand_env(command, env.var);
    let (exe, args) = split_command(&expanded, env.exists);
    target_of(&exe, &args, env)
}

/// Builds the target of a program and arguments already apart (a task action).
pub fn target_of(exe: &str, args: &str, env: &Env) -> Target {
    let exe = resolve_exe(
        expand_env(exe.trim().trim_matches('"'), env.var).trim(),
        env.search,
        env.exists,
    );
    let args = expand_env(args, env.var);
    let mut file = exe.clone();
    let mut via_dll = false;
    if file_name(&exe).eq_ignore_ascii_case("rundll32.exe") {
        if let Some(dll) = rundll_dll(&args) {
            file = resolve_exe(&dll, env.search, env.exists);
            via_dll = true;
        }
    }
    Target {
        exe,
        args,
        file,
        via_dll,
    }
}

/// A service or driver image path as the service manager reads it: `\??\C:\x.sys`,
/// `\SystemRoot\System32\drivers\x.sys`, `System32\drivers\x.sys`. An empty path for a
/// driver means its default place.
pub fn normalize_image_path(image: &str, name: &str, driver: bool) -> String {
    let image = image.trim();
    if image.is_empty() {
        return if driver {
            format!("%SystemRoot%\\System32\\drivers\\{name}.sys")
        } else {
            String::new()
        };
    }
    let lower = image.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("\\??\\") {
        return image[image.len() - rest.len()..].to_string();
    }
    if lower.starts_with("\\systemroot\\") {
        return format!("%SystemRoot%{}", &image["\\systemroot".len()..]);
    }
    if lower.starts_with("system32\\") {
        return format!("%SystemRoot%\\{image}");
    }
    image.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trust {
    Valid,
    Unsigned,
    Invalid(String),
    /// The file exists but could not be read for checking (access denied, in use).
    Unreadable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFacts {
    pub exists: bool,
    pub trust: Trust,
    pub signer: Option<String>,
    pub company: Option<String>,
    pub version: Option<String>,
    pub modified: Option<SystemTime>,
}

impl FileFacts {
    pub fn missing() -> Self {
        FileFacts {
            exists: false,
            trust: Trust::Unsigned,
            signer: None,
            company: None,
            version: None,
            modified: None,
        }
    }
}

/// Maps a WinVerifyTrust status to a trust reading. `None` means the file has no signature
/// of the kind that was asked about, so a catalog should be tried.
pub fn trust_from_status(status: u32) -> Option<Trust> {
    Some(match status {
        0 => Trust::Valid,
        0x800B_0100 | 0x800B_0003 | 0x800B_0001 => return None,
        0x8007_0005 => Trust::Unreadable("access denied".into()),
        0x8007_0020 | 0x8007_0021 => Trust::Unreadable("file in use".into()),
        0x8009_2003 => Trust::Unreadable("the file could not be read".into()),
        0x8009_6010 => Trust::Invalid("the file was changed after it was signed".into()),
        0x800B_0101 => Trust::Invalid("the signing certificate has expired".into()),
        0x800B_0109 => Trust::Invalid("the certificate chain ends at an untrusted root".into()),
        0x800B_010A => Trust::Invalid("the certificate chain could not be built".into()),
        0x800B_010C => Trust::Invalid("the signing certificate was revoked".into()),
        0x800B_0110 => Trust::Invalid("the certificate is not valid for code signing".into()),
        0x800B_0111 => Trust::Invalid("the certificate is explicitly distrusted".into()),
        0x8009_6004 => Trust::Invalid("the signature does not verify".into()),
        0x8009_2026 => Trust::Invalid("blocked by a security setting".into()),
        other => Trust::Invalid(format!("verification failed (0x{other:08X})")),
    })
}

const MICROSOFT_SIGNERS: [&str; 4] = [
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft windows hardware abstraction layer publisher",
];

/// Publishers that sign other companies' drivers after testing them.
const TESTING_SIGNERS: [&str; 2] = [
    "microsoft windows hardware compatibility publisher",
    "microsoft windows early launch anti-malware publisher",
];

fn is_testing_signer(signer: &str) -> bool {
    TESTING_SIGNERS.contains(&signer.to_ascii_lowercase().as_str())
}

/// Microsoft-signed means a valid signature by a Microsoft publisher, or by the Windows
/// hardware testing publisher on a file whose company is Microsoft.
pub fn is_microsoft(facts: &FileFacts) -> bool {
    if facts.trust != Trust::Valid {
        return false;
    }
    let Some(signer) = facts.signer.as_deref() else {
        return false;
    };
    let lower = signer.to_ascii_lowercase();
    MICROSOFT_SIGNERS.contains(&lower.as_str())
        || (is_testing_signer(signer)
            && facts
                .company
                .as_deref()
                .is_some_and(|c| c.to_ascii_lowercase().starts_with("microsoft")))
}

/// The publisher part of an entry's line.
pub fn publisher_text(facts: Option<&FileFacts>) -> String {
    let Some(facts) = facts else {
        return "signature not checked".into();
    };
    if !facts.exists {
        return "file not found".into();
    }
    match (&facts.trust, facts.signer.as_deref()) {
        (Trust::Valid, Some(signer)) if is_testing_signer(signer) && !is_microsoft(facts) => {
            match facts.company.as_deref() {
                Some(company) => {
                    format!("company {company}, driver tested and signed by Microsoft")
                }
                None => format!("signed by {signer}"),
            }
        }
        (Trust::Valid, Some(signer)) => format!("signed by {signer}"),
        (Trust::Valid, None) => "signed, signer name unreadable".into(),
        (Trust::Unsigned, _) => match facts.company.as_deref() {
            Some(company) => format!("not signed, company {company}"),
            None => "not signed".into(),
        },
        (Trust::Invalid(reason), signer) => match signer {
            Some(signer) => format!("signature invalid ({reason}), signer {signer}"),
            None => format!("signature invalid ({reason})"),
        },
        (Trust::Unreadable(reason), _) => format!("signature not checked ({reason})"),
    }
}

const SCRIPT_HOSTS: [&str; 6] = [
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Flag {
    Missing,
    Unsigned,
    BadSignature(String),
    UserWritable(&'static str),
    ScriptHost(String),
}

impl Flag {
    pub fn text(&self) -> String {
        match self {
            Flag::Missing => "file is missing".into(),
            Flag::Unsigned => "unsigned".into(),
            Flag::BadSignature(reason) => format!("invalid signature: {reason}"),
            Flag::UserWritable(place) => format!("runs from {place}"),
            Flag::ScriptHost(host) => format!("script host {host}"),
        }
    }
}

/// AppData, Temp or Downloads in a path, whichever applies. Other places a user can write
/// (ProgramData, the profile itself) are a judgement call and are not flagged.
pub fn user_writable_place(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split(['\\', '/']).collect();
    let has = |names: &[&str]| segments.iter().any(|s| names.contains(s));
    if has(&["appdata", "%appdata%", "%localappdata%"]) {
        Some("AppData")
    } else if has(&["temp", "%temp%", "%tmp%"]) {
        Some("Temp")
    } else if has(&["downloads"]) {
        Some("Downloads")
    } else {
        None
    }
}

/// The flags for an entry. With no target (nothing to start that can be named) there are
/// none; with no facts the file was not checked, so only the command itself is judged.
pub fn flags(target: Option<&Target>, facts: Option<&FileFacts>) -> Vec<Flag> {
    let Some(target) = target else {
        return Vec::new();
    };
    let mut flags = Vec::new();
    if let Some(facts) = facts {
        if !facts.exists {
            flags.push(Flag::Missing);
        } else {
            match &facts.trust {
                Trust::Unsigned => flags.push(Flag::Unsigned),
                Trust::Invalid(reason) => flags.push(Flag::BadSignature(reason.clone())),
                Trust::Valid | Trust::Unreadable(_) => {}
            }
        }
    }
    if let Some(place) = user_writable_place(&target.file) {
        flags.push(Flag::UserWritable(place));
    }
    let name = target.exe_name();
    if SCRIPT_HOSTS.contains(&name.as_str()) {
        flags.push(Flag::ScriptHost(name));
    } else if name == "rundll32.exe" && user_writable_place(&target.file) == Some("AppData") {
        flags.push(Flag::ScriptHost(
            "rundll32.exe loading a DLL from AppData".into(),
        ));
    }
    flags
}

/// One scheduled task outside \Microsoft\, as the task script reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRow {
    pub path: String,
    pub name: String,
    pub state: String,
    pub action: String,
    pub execute: String,
    pub arguments: String,
    pub triggers: Vec<String>,
}

pub const TASK_HEADER: &str = "STARTUP-TASKS-V1";

/// Reads the task script's output strictly: a header line, tab-separated rows beginning
/// `T`, and an `END <count>` line that must match. Anything else is an error.
pub fn parse_tasks(output: &str) -> Result<Vec<TaskRow>, String> {
    let mut lines = output.lines().map(|line| line.trim_end_matches('\r'));
    if lines.next() != Some(TASK_HEADER) {
        return Err("the task listing did not start as expected".into());
    }
    let mut rows = Vec::new();
    for line in lines.by_ref() {
        if let Some(count) = line.strip_prefix("END ") {
            let count: usize = count
                .trim()
                .parse()
                .map_err(|_| "the task listing ended with an unreadable count".to_string())?;
            if lines.next().is_some() {
                return Err("the task listing had lines after its end".into());
            }
            if count != rows.len() {
                return Err(format!(
                    "the task listing announced {count} tasks and held {}",
                    rows.len()
                ));
            }
            return Ok(rows);
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 8 || fields[0] != "T" {
            return Err("the task listing held a line in an unexpected form".into());
        }
        rows.push(TaskRow {
            path: fields[1].to_string(),
            name: fields[2].to_string(),
            state: fields[3].to_string(),
            action: fields[4].to_string(),
            execute: fields[5].to_string(),
            arguments: fields[6].to_string(),
            triggers: unique_triggers(fields[7]),
        });
    }
    Err("the task listing was cut short".into())
}

/// What a shortcut points at, read from its file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Shortcut {
    pub target: Option<String>,
    pub arguments: Option<String>,
    pub relative: Option<String>,
}

/// Little-endian UTF-16 units of a byte string; an odd last byte is ignored.
pub fn utf16_le(bytes: &[u8]) -> Vec<u16> {
    (0..bytes.len() / 2)
        .map(|i| u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]))
        .collect()
}

fn u16_at(data: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn u32_at(data: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?) as usize)
}

fn c_string(data: &[u8], at: usize) -> Option<String> {
    let tail = data.get(at..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    Some(tail[..end].iter().map(|&b| b as char).collect())
}

fn wide_c_string(data: &[u8], at: usize) -> Option<String> {
    let tail = data.get(at..)?;
    let units: Vec<u16> = utf16_le(tail).into_iter().take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Reads the target path, arguments and relative path of a .lnk file (MS-SHLLINK). The
/// target is only given when the shortcut holds a local path; one that points through an
/// item list alone (an installed Store app) has none.
pub fn parse_shortcut(data: &[u8]) -> Result<Shortcut, String> {
    let bad = || "not a readable shortcut".to_string();
    if u32_at(data, 0).ok_or_else(bad)? != 0x4C {
        return Err(bad());
    }
    let flags = u32_at(data, 0x14).ok_or_else(bad)?;
    let mut at = 0x4C;
    if flags & 1 != 0 {
        at += 2 + u16_at(data, at).ok_or_else(bad)?;
    }
    let mut shortcut = Shortcut::default();
    if flags & 2 != 0 {
        let size = u32_at(data, at).ok_or_else(bad)?;
        let header = u32_at(data, at + 4).ok_or_else(bad)?;
        let info_flags = u32_at(data, at + 8).ok_or_else(bad)?;
        if info_flags & 1 != 0 {
            let base_offset = u32_at(data, at + 16).ok_or_else(bad)?;
            let suffix_offset = u32_at(data, at + 24).ok_or_else(bad)?;
            let (base, suffix) = if header >= 0x24 {
                let base_unicode = u32_at(data, at + 28).ok_or_else(bad)?;
                let suffix_unicode = u32_at(data, at + 32).ok_or_else(bad)?;
                (
                    wide_c_string(data, at + base_unicode),
                    wide_c_string(data, at + suffix_unicode),
                )
            } else {
                (
                    c_string(data, at + base_offset),
                    c_string(data, at + suffix_offset),
                )
            };
            if let Some(base) = base {
                shortcut.target = Some(format!("{base}{}", suffix.unwrap_or_default()));
            }
        }
        at += size;
    }
    let unicode = flags & 0x80 != 0;
    let mut strings = Vec::new();
    for bit in [0x04, 0x08, 0x10, 0x20, 0x40] {
        if flags & bit == 0 {
            strings.push(None);
            continue;
        }
        let count = u16_at(data, at).ok_or_else(bad)?;
        at += 2;
        let (text, width) = if unicode {
            let bytes = data.get(at..at + count * 2).ok_or_else(bad)?;
            (String::from_utf16_lossy(&utf16_le(bytes)), count * 2)
        } else {
            let bytes = data.get(at..at + count).ok_or_else(bad)?;
            (bytes.iter().map(|&b| b as char).collect(), count)
        };
        at += width;
        strings.push(Some(text));
    }
    shortcut.relative = strings[1].clone();
    shortcut.arguments = strings[3].clone();
    Ok(shortcut)
}

/// Task Manager's startup approval value: the first byte is odd when the item is disabled.
pub fn startup_approved(data: &[u8]) -> bool {
    data.first().is_none_or(|first| first & 1 == 0)
}

fn unique_triggers(text: &str) -> Vec<String> {
    let mut kinds: Vec<String> = Vec::new();
    for kind in text.split(',').filter(|t| !t.is_empty()) {
        if !kinds.iter().any(|seen| seen == kind) {
            kinds.push(kind.to_string());
        }
    }
    kinds
}

/// Replaces account SIDs (`S-1-5-21-...`) wherever they sit, even glued to other text as
/// in task names that end with the user's SID.
pub fn mask_sids(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("S-1-") {
        let after = &rest[at + 4..];
        let len = after
            .find(|c: char| !(c.is_ascii_digit() || c == '-'))
            .unwrap_or(after.len());
        if len >= 5 && after[..len].contains(|c: char| c.is_ascii_digit()) {
            out.push_str(&rest[..at]);
            out.push_str("[account]");
            rest = &after[len..];
        } else {
            out.push_str(&rest[..at + 4]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Strips the `!` (delete after a failure) and `*` (run in Safe Mode) marks of RunOnce names.
pub fn run_once_name(name: &str) -> &str {
    name.trim_start_matches(['!', '*'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn files(list: &[&str]) -> HashSet<String> {
        list.iter().map(|f| f.to_ascii_lowercase()).collect()
    }

    fn env_of<'a>(
        var: &'a dyn Fn(&str) -> Option<String>,
        exists: &'a dyn Fn(&str) -> bool,
        search: &'a [String],
    ) -> Env<'a> {
        Env {
            var,
            exists,
            search,
        }
    }

    fn var(name: &str) -> Option<String> {
        match name.to_ascii_lowercase().as_str() {
            "systemroot" | "windir" => Some(r"C:\Windows".into()),
            "programfiles" => Some(r"C:\Program Files".into()),
            "localappdata" => Some(r"C:\Users\Pat\AppData\Local".into()),
            _ => None,
        }
    }

    #[test]
    fn environment_variables_expand_and_unknown_ones_stay() {
        assert_eq!(
            expand_env(r"%SystemRoot%\System32\a.exe", &var),
            r"C:\Windows\System32\a.exe"
        );
        assert_eq!(
            expand_env(r"%ProgramFiles%\X\x.exe /a 50%", &var),
            r"C:\Program Files\X\x.exe /a 50%"
        );
        assert_eq!(expand_env(r"%NOPE%\x.exe", &var), r"%NOPE%\x.exe");
        assert_eq!(expand_env("100% sure %", &var), "100% sure %");
    }

    #[test]
    fn a_quoted_program_is_taken_as_written() {
        let exists = |_: &str| false;
        assert_eq!(
            split_command(r#""C:\Program Files\App\app.exe" -silent --x"#, &exists),
            (r"C:\Program Files\App\app.exe".into(), "-silent --x".into())
        );
        assert_eq!(
            split_command(r#""C:\a\b.exe""#, &exists),
            (r"C:\a\b.exe".into(), String::new())
        );
        assert_eq!(
            split_command(r#""C:\a b\unclosed.exe -x"#, &exists),
            (r"C:\a b\unclosed.exe -x".into(), String::new())
        );
    }

    #[test]
    fn an_unquoted_program_with_spaces_is_found_by_trying_longer_starts() {
        let present = files(&[r"C:\Program Files\App\app.exe"]);
        let exists = |p: &str| present.contains(&p.to_ascii_lowercase());
        assert_eq!(
            split_command(r"C:\Program Files\App\app.exe /background", &exists),
            (r"C:\Program Files\App\app.exe".into(), "/background".into())
        );
        // With nothing on disk the first start ending in an extension is the program.
        let none = |_: &str| false;
        assert_eq!(
            split_command(r"C:\Program Files\App\app.exe /background", &none),
            (r"C:\Program Files\App\app.exe".into(), "/background".into())
        );
        assert_eq!(
            split_command("tool --flag value", &none),
            ("tool".into(), "--flag value".into())
        );
    }

    #[test]
    fn a_name_without_a_folder_is_searched_for() {
        let present = files(&[r"C:\Windows\System32\cmd.exe", r"C:\Windows\notepad.exe"]);
        let exists = |p: &str| present.contains(&p.to_ascii_lowercase());
        let search = vec![
            r"C:\Windows\System32".to_string(),
            r"C:\Windows".to_string(),
        ];
        assert_eq!(
            resolve_exe("cmd", &search, &exists),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(
            resolve_exe("notepad.exe", &search, &exists),
            r"C:\Windows\notepad.exe"
        );
        assert_eq!(resolve_exe("ghost.exe", &search, &exists), "ghost.exe");
    }

    #[test]
    fn rundll32_is_judged_by_the_dll_it_loads() {
        let present = files(&[r"C:\Windows\System32\rundll32.exe"]);
        let exists = |p: &str| present.contains(&p.to_ascii_lowercase());
        let search = vec![r"C:\Windows\System32".to_string()];
        let env = env_of(&var, &exists, &search);
        let target = target_of_command(
            r"%SystemRoot%\System32\rundll32.exe %LOCALAPPDATA%\Odd\odd.dll,Start /s",
            &env,
        );
        assert_eq!(target.exe, r"C:\Windows\System32\rundll32.exe");
        assert_eq!(target.file, r"C:\Users\Pat\AppData\Local\Odd\odd.dll");
        assert!(target.via_dll);
        let found = flags(Some(&target), None);
        assert!(found.contains(&Flag::UserWritable("AppData")));
        assert!(found
            .iter()
            .any(|f| matches!(f, Flag::ScriptHost(h) if h.contains("rundll32"))));
        assert_eq!(
            rundll_dll(r#""C:\a b\x.dll",Entry arg"#),
            Some(r"C:\a b\x.dll".into())
        );
        assert_eq!(
            rundll_dll("/d shell32.dll,Control_RunDLL"),
            Some("shell32.dll".into())
        );
        assert_eq!(rundll_dll(""), None);
        // A system DLL through rundll32 is not flagged.
        let system = target_of_command("rundll32 shell32.dll,Control_RunDLL", &env);
        assert!(flags(Some(&system), None).is_empty());
    }

    #[test]
    fn service_image_paths_are_normalised() {
        assert_eq!(
            normalize_image_path(r"\SystemRoot\System32\drivers\a.sys", "a", true),
            r"%SystemRoot%\System32\drivers\a.sys"
        );
        assert_eq!(
            normalize_image_path(r"\??\C:\Windows\x.sys", "x", true),
            r"C:\Windows\x.sys"
        );
        assert_eq!(
            normalize_image_path(r"System32\DRIVERS\b.sys", "b", true),
            r"%SystemRoot%\System32\DRIVERS\b.sys"
        );
        assert_eq!(
            normalize_image_path("", "c", true),
            r"%SystemRoot%\System32\drivers\c.sys"
        );
        assert_eq!(normalize_image_path("", "c", false), "");
        assert_eq!(
            normalize_image_path(r#""C:\x y\svc.exe" -k"#, "s", false),
            r#""C:\x y\svc.exe" -k"#
        );
    }

    #[test]
    fn paths_are_classified_by_user_writable_place() {
        assert_eq!(
            user_writable_place(r"C:\Users\Pat\AppData\Roaming\x\y.exe"),
            Some("AppData")
        );
        assert_eq!(user_writable_place(r"C:\Windows\Temp\x.exe"), Some("Temp"));
        assert_eq!(
            user_writable_place(r"C:\Users\Pat\Downloads\setup.exe"),
            Some("Downloads")
        );
        assert_eq!(
            user_writable_place(r"%LOCALAPPDATA%\x\y.exe"),
            Some("AppData")
        );
        assert_eq!(user_writable_place(r"C:\ProgramData\Vendor\x.exe"), None);
        assert_eq!(user_writable_place(r"C:\Program Files\App\x.exe"), None);
        assert_eq!(user_writable_place(r"C:\Users\Pat\tool.exe"), None);
        assert_eq!(
            user_writable_place(r"C:\Program Files\Temporary\x.exe"),
            None
        );
    }

    fn facts(trust: Trust, signer: Option<&str>, company: Option<&str>) -> FileFacts {
        FileFacts {
            exists: true,
            trust,
            signer: signer.map(str::to_string),
            company: company.map(str::to_string),
            version: None,
            modified: None,
        }
    }

    fn target(file: &str) -> Target {
        Target {
            exe: file.into(),
            args: String::new(),
            file: file.into(),
            via_dll: false,
        }
    }

    #[test]
    fn flags_cover_missing_unsigned_invalid_and_user_places() {
        let t = target(r"C:\Program Files\App\app.exe");
        assert!(flags(Some(&t), Some(&facts(Trust::Valid, Some("Vendor"), None))).is_empty());
        assert_eq!(
            flags(Some(&t), Some(&facts(Trust::Unsigned, None, None))),
            vec![Flag::Unsigned]
        );
        assert_eq!(
            flags(Some(&t), Some(&FileFacts::missing())),
            vec![Flag::Missing]
        );
        let bad = facts(Trust::Invalid("changed".into()), Some("Vendor"), None);
        assert_eq!(
            flags(Some(&t), Some(&bad)),
            vec![Flag::BadSignature("changed".into())]
        );
        let user = target(r"C:\Users\Pat\AppData\Local\Temp\x.exe");
        assert_eq!(
            flags(Some(&user), Some(&facts(Trust::Valid, Some("V"), None))),
            vec![Flag::UserWritable("AppData")]
        );
        // Unreadable files are not flagged as unsigned.
        let locked = facts(Trust::Unreadable("access denied".into()), None, None);
        assert!(flags(Some(&t), Some(&locked)).is_empty());
        assert!(flags(None, None).is_empty());
        // Not checked: only the command is judged.
        assert!(flags(Some(&t), None).is_empty());
    }

    #[test]
    fn script_hosts_are_flagged_even_when_they_are_microsoft_files() {
        for host in [
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "cmd.exe",
        ] {
            let t = target(&format!(r"C:\Windows\System32\{host}"));
            let found = flags(
                Some(&t),
                Some(&facts(Trust::Valid, Some("Microsoft Windows"), None)),
            );
            assert_eq!(found, vec![Flag::ScriptHost(host.into())], "{host}");
        }
        let notepad = target(r"C:\Windows\System32\notepad.exe");
        assert!(flags(Some(&notepad), None).is_empty());
    }

    #[test]
    fn microsoft_signed_follows_the_signer_and_the_company() {
        assert!(is_microsoft(&facts(
            Trust::Valid,
            Some("Microsoft Windows"),
            None
        )));
        assert!(is_microsoft(&facts(
            Trust::Valid,
            Some("Microsoft Corporation"),
            None
        )));
        assert!(!is_microsoft(&facts(
            Trust::Valid,
            Some("Contoso Ltd"),
            None
        )));
        assert!(!is_microsoft(&facts(
            Trust::Unsigned,
            Some("Microsoft Corporation"),
            None
        )));
        let tested = "Microsoft Windows Hardware Compatibility Publisher";
        assert!(is_microsoft(&facts(
            Trust::Valid,
            Some(tested),
            Some("Microsoft Corporation")
        )));
        assert!(!is_microsoft(&facts(
            Trust::Valid,
            Some(tested),
            Some("NVIDIA Corporation")
        )));
        assert!(!is_microsoft(&facts(Trust::Valid, Some(tested), None)));
    }

    #[test]
    fn publisher_text_says_what_is_known() {
        assert_eq!(publisher_text(None), "signature not checked");
        assert_eq!(
            publisher_text(Some(&FileFacts::missing())),
            "file not found"
        );
        assert_eq!(
            publisher_text(Some(&facts(Trust::Valid, Some("Contoso Ltd"), None))),
            "signed by Contoso Ltd"
        );
        assert_eq!(
            publisher_text(Some(&facts(Trust::Unsigned, None, Some("Odd Co")))),
            "not signed, company Odd Co"
        );
        let tested = "Microsoft Windows Hardware Compatibility Publisher";
        assert_eq!(
            publisher_text(Some(&facts(
                Trust::Valid,
                Some(tested),
                Some("NVIDIA Corporation")
            ))),
            "company NVIDIA Corporation, driver tested and signed by Microsoft"
        );
        assert!(publisher_text(Some(&facts(
            Trust::Invalid("changed".into()),
            Some("Contoso Ltd"),
            None
        )))
        .contains("signature invalid (changed)"));
        assert!(publisher_text(Some(&facts(
            Trust::Unreadable("access denied".into()),
            None,
            None
        )))
        .contains("not checked (access denied)"));
    }

    #[test]
    fn verification_statuses_map_to_readings() {
        assert_eq!(trust_from_status(0), Some(Trust::Valid));
        assert_eq!(trust_from_status(0x800B_0100), None);
        assert!(matches!(
            trust_from_status(0x8009_6010),
            Some(Trust::Invalid(_))
        ));
        assert!(matches!(
            trust_from_status(0x8007_0005),
            Some(Trust::Unreadable(_))
        ));
        let Some(Trust::Invalid(text)) = trust_from_status(0x1234_5678) else {
            panic!("an unknown status is an invalid reading");
        };
        assert!(text.contains("0x12345678"));
    }

    const TASKS: &str = "STARTUP-TASKS-V1\r\n\
T\t\\\tUpdater\tReady\tExec\tC:\\Program Files\\Up\\up.exe\t--check\tLogon,Daily\r\n\
T\t\\Vendor\\\tSync\tRunning\tComHandler\t\t\tBoot\r\n\
END 2\r\n";

    #[test]
    fn the_task_listing_is_read_strictly() {
        let rows = parse_tasks(TASKS).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Updater");
        assert_eq!(rows[0].execute, r"C:\Program Files\Up\up.exe");
        assert_eq!(rows[0].triggers, ["Logon", "Daily"]);
        assert_eq!(rows[1].action, "ComHandler");
        assert_eq!(rows[1].execute, "");
        assert_eq!(parse_tasks("STARTUP-TASKS-V1\nEND 0\n").unwrap(), vec![]);
    }

    #[test]
    fn a_malformed_task_listing_is_an_error() {
        assert!(parse_tasks("").is_err());
        assert!(parse_tasks("hello\nEND 0\n").is_err());
        assert!(parse_tasks("STARTUP-TASKS-V1\nT\ta\tb\nEND 1\n").is_err());
        assert!(parse_tasks("STARTUP-TASKS-V1\nEND 3\n").is_err());
        assert!(parse_tasks("STARTUP-TASKS-V1\nEND x\n").is_err());
        assert!(parse_tasks("STARTUP-TASKS-V1\nWARNING something\nEND 0\n").is_err());
        let cut = TASKS.split("END").next().unwrap();
        assert!(parse_tasks(cut).is_err());
        assert!(parse_tasks(&format!("{TASKS}extra\n")).is_err());
    }

    /// A shortcut with a local path, unicode strings and arguments.
    fn shortcut_bytes(base: &str, suffix: &str, args: &str, unicode_info: bool) -> Vec<u8> {
        let mut data = vec![0u8; 0x4C];
        data[0] = 0x4C;
        let flags: u32 = 0x02 | 0x08 | 0x20 | 0x80;
        data[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
        let header: u32 = if unicode_info { 0x24 } else { 0x1C };
        let base_a = format!("{base}\0");
        let suffix_a = format!("{suffix}\0");
        let base_offset = header;
        let suffix_offset = base_offset + base_a.len() as u32;
        let mut tail = Vec::new();
        tail.extend_from_slice(base_a.as_bytes());
        tail.extend_from_slice(suffix_a.as_bytes());
        let (mut base_u, mut suffix_u) = (0u32, 0u32);
        if unicode_info {
            base_u = header + tail.len() as u32;
            for unit in format!("{base}\0").encode_utf16() {
                tail.extend_from_slice(&unit.to_le_bytes());
            }
            suffix_u = header + tail.len() as u32;
            for unit in format!("{suffix}\0").encode_utf16() {
                tail.extend_from_slice(&unit.to_le_bytes());
            }
        }
        let size = header + tail.len() as u32;
        let mut info = Vec::new();
        info.extend_from_slice(&size.to_le_bytes());
        info.extend_from_slice(&header.to_le_bytes());
        info.extend_from_slice(&1u32.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&base_offset.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&suffix_offset.to_le_bytes());
        if unicode_info {
            info.extend_from_slice(&base_u.to_le_bytes());
            info.extend_from_slice(&suffix_u.to_le_bytes());
        }
        info.extend_from_slice(&tail);
        data.extend_from_slice(&info);
        for text in [r"..\rel.exe", args] {
            data.extend_from_slice(&(text.encode_utf16().count() as u16).to_le_bytes());
            for unit in text.encode_utf16() {
                data.extend_from_slice(&unit.to_le_bytes());
            }
        }
        data
    }

    #[test]
    fn a_shortcut_gives_its_target_and_arguments() {
        for unicode_info in [false, true] {
            let data = shortcut_bytes(r"C:\Program Files\App", r"\app.exe", "-tray", unicode_info);
            let shortcut = parse_shortcut(&data).unwrap();
            assert_eq!(
                shortcut.target.as_deref(),
                Some(r"C:\Program Files\App\app.exe")
            );
            assert_eq!(shortcut.arguments.as_deref(), Some("-tray"));
            assert_eq!(shortcut.relative.as_deref(), Some(r"..\rel.exe"));
        }
    }

    #[test]
    fn a_malformed_shortcut_is_an_error() {
        assert!(parse_shortcut(&[]).is_err());
        assert!(parse_shortcut(&[1, 2, 3, 4]).is_err());
        let data = shortcut_bytes(r"C:\a", r"\b.exe", "x", false);
        assert!(parse_shortcut(&data[..data.len() - 5]).is_err());
        assert!(parse_shortcut(&data[..0x50]).is_err());
    }

    #[test]
    fn account_ids_are_masked_even_inside_a_name() {
        assert_eq!(
            mask_sids("BraveUpdateTaskUserS-1-5-21-111-222-333-1001Core{AB}"),
            "BraveUpdateTaskUser[account]Core{AB}"
        );
        assert_eq!(
            mask_sids(r"\SoftLanding\S-1-5-21-1-2-3-1004\Task"),
            r"\SoftLanding\[account]\Task"
        );
        assert_eq!(mask_sids("S-1-x and S-1-5 stay"), "S-1-x and S-1-5 stay");
        assert_eq!(mask_sids("plain text"), "plain text");
    }

    #[test]
    fn repeated_trigger_kinds_are_listed_once() {
        let rows = parse_tasks(
            "STARTUP-TASKS-V1\nT\t\\\tA\tReady\tExec\tx.exe\t\ttime,time,Logon,time\nEND 1\n",
        )
        .unwrap();
        assert_eq!(rows[0].triggers, ["time", "Logon"]);
    }

    #[test]
    fn task_manager_approval_values_read_enabled_and_disabled() {
        assert!(startup_approved(&[0x02, 0, 0, 0]));
        assert!(startup_approved(&[0x06, 0, 0, 0]));
        assert!(!startup_approved(&[0x03, 0, 0, 0]));
        assert!(!startup_approved(&[0x07, 0, 0, 0]));
        assert!(startup_approved(&[]));
        assert_eq!(run_once_name("!*Cleanup"), "Cleanup");
        assert_eq!(run_once_name("Plain"), "Plain");
    }
}
