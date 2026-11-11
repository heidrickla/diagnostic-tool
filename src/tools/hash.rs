//! The hash of one file, its size and times, and its Authenticode signature (embedded or
//! through a catalog). The file's bytes are read to hash and check them, never printed.
pub(crate) mod sys;

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use self::sys::RawSignature;
use super::{Args, Output, Tool};
use crate::clock;
use crate::events::{local_names, redact};

pub const TOOL: Tool = Tool {
    name: "hash",
    summary: "SHA-256 or SHA-1 of one file, its times and its Authenticode signature",
    usage: "\
Usage: toolkit hash --path PATH [--algorithm NAME]
  --path PATH         the file to read
  --algorithm NAME    sha256 (default) or sha1

Prints the file's hash, size, created, modified and accessed times, and whether it is
signed (embedded signature or Windows catalog), by whom, and whether the signature is
valid or why not. Refuses files over 4 GiB and stops hashing after 20 seconds. The
user's folder name in the path is left out of the output.",
    run,
};

/// Files larger than this are refused.
pub const SIZE_LIMIT: u64 = 4 << 30;
/// Hashing stops here; the signature check needs the rest of the 30 seconds.
const HASH_TIME: Duration = Duration::from_secs(20);
const SIGNATURE_START_LIMIT: Duration = Duration::from_secs(24);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha1,
}

impl Algorithm {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.to_ascii_lowercase().replace('-', "").as_str() {
            "sha256" => Ok(Self::Sha256),
            "sha1" => Ok(Self::Sha1),
            _ => Err(format!(
                "not an algorithm this tool offers: {text} (sha256 or sha1)"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha1 => "SHA-1",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Embedded,
    Catalog,
}

impl Method {
    fn word(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Catalog => "catalog",
        }
    }
}

/// What the signature checks add up to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Signed {
        signer: Option<String>,
        method: Method,
    },
    Unsigned,
    Invalid {
        signer: Option<String>,
        reason: String,
    },
    Unavailable(String),
}

/// One WinVerifyTrust status judged.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Valid,
    /// The file carries no signature of this kind.
    Absent,
    Invalid(String),
    Unreadable(String),
}

fn judge_status(status: u32) -> Status {
    let invalid = |why: &str| Status::Invalid(format!("{why} (0x{status:08X})"));
    match status {
        0 => Status::Valid,
        0x800B_0100 | 0x800B_0003 | 0x800B_0001 => Status::Absent,
        0x8007_0005 => Status::Unreadable("access denied".into()),
        0x8007_0020 | 0x8007_0021 => Status::Unreadable("the file is in use".into()),
        0x8009_2003 => Status::Unreadable("the file could not be read".into()),
        0x8009_6010 => invalid("the file was changed after it was signed"),
        0x800B_0101 => invalid("the signing certificate has expired"),
        0x800B_0109 => invalid("the certificate chain ends at an untrusted root"),
        0x800B_010A => invalid("the certificate chain could not be built"),
        0x800B_010C => invalid("the signing certificate was revoked"),
        0x800B_0110 => invalid("the certificate is not valid for code signing"),
        0x800B_0111 => invalid("the certificate is explicitly distrusted"),
        0x8009_6004 => invalid("the signature does not verify"),
        0x8009_2026 => invalid("blocked by a security setting"),
        _ => invalid("verification failed"),
    }
}
/// One embedded-signature status as a pass or the plain reason it is not one.
pub fn interpret_status(status: u32) -> Result<(), String> {
    match judge_status(status) {
        Status::Valid => Ok(()),
        Status::Absent => Err("no signature".into()),
        Status::Invalid(reason) | Status::Unreadable(reason) => Err(reason),
    }
}

/// Combines the embedded and the catalog check: any valid one signs the file, an invalid
/// signature outranks an absent one, and a file that could not be read says so.
pub fn interpret_signature(raw: &RawSignature) -> Signature {
    let embedded = raw
        .embedded
        .as_ref()
        .map(|c| (judge_status(c.status), c.signer.clone()));
    let catalog = raw
        .catalog
        .as_ref()
        .map(|c| (judge_status(c.status), c.signer.clone()));
    if let Some((Status::Valid, signer)) = &embedded {
        return Signature::Signed {
            signer: signer.clone(),
            method: Method::Embedded,
        };
    }
    if let Some((Status::Valid, signer)) = &catalog {
        return Signature::Signed {
            signer: signer.clone(),
            method: Method::Catalog,
        };
    }
    for (status, signer) in [&embedded, &catalog].into_iter().flatten() {
        if let Status::Invalid(reason) = status {
            return Signature::Invalid {
                signer: signer.clone(),
                reason: reason.clone(),
            };
        }
    }
    for (status, _) in [&embedded, &catalog].into_iter().flatten() {
        if let Status::Unreadable(reason) = status {
            return Signature::Unavailable(reason.clone());
        }
    }
    if embedded.is_none() && catalog.is_none() {
        return Signature::Unavailable("the signature check did not run".into());
    }
    Signature::Unsigned
}

/// Everything read about one file.
#[derive(Clone, Debug, PartialEq)]
pub struct Facts {
    /// The path as the operator gave it, with the profile folder name removed.
    pub path: String,
    pub algorithm: Algorithm,
    pub size: u64,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    /// The hash in lower-case hex, or why there is none.
    pub digest: Result<String, String>,
    pub signature: Signature,
}

fn run(args: &Args) -> Result<Output, String> {
    let algorithm = match args.value("--algorithm") {
        Some(text) => Algorithm::parse(text)?,
        None => Algorithm::Sha256,
    };
    let path = args
        .value("--path")
        .ok_or("give the file with --path PATH")?;
    let facts = gather(Path::new(path), algorithm, Instant::now())?;
    Ok(Output {
        text: render(&facts),
        data: to_json(&facts),
    })
}

pub fn shown_path(path: &str) -> String {
    let path = super::space::redact_profile(path);
    redact(&path, &local_names())
}

fn gather(path: &Path, algorithm: Algorithm, start: Instant) -> Result<Facts, String> {
    let shown = shown_path(&path.to_string_lossy());
    let metadata = std::fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => format!("no such file: {shown}"),
        std::io::ErrorKind::PermissionDenied => format!("access denied: {shown}"),
        _ => format!("cannot read {shown}: {error}"),
    })?;
    if !metadata.is_file() {
        return Err(format!("not a file: {shown}"));
    }
    let size = metadata.len();
    let mut facts = Facts {
        path: shown,
        algorithm,
        size,
        created: metadata.created().ok(),
        modified: metadata.modified().ok(),
        accessed: metadata.accessed().ok(),
        digest: Err(String::new()),
        signature: Signature::Unavailable(String::new()),
    };
    if size > SIZE_LIMIT {
        let reason = "the file is over 4 GiB, which this tool refuses".to_string();
        facts.digest = Err(reason.clone());
        facts.signature = Signature::Unavailable(reason);
        return Ok(facts);
    }
    facts.digest = sys::digest(path, algorithm, start + HASH_TIME);
    facts.signature = if start.elapsed() > SIGNATURE_START_LIMIT {
        Signature::Unavailable("the time limit was reached before the signature check".into())
    } else {
        interpret_signature(&sys::check_signature(path))
    };
    Ok(facts)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a time, in UTC.
pub fn rfc3339(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|e| -(e.duration().as_secs() as i64));
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil-from-days, after Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn time_json(time: Option<SystemTime>) -> Value {
    match time {
        Some(time) => json!(rfc3339(time)),
        None => json!({"unavailable": "the file system did not report it"}),
    }
}

fn time_line(label: &str, time: Option<SystemTime>) -> String {
    match time {
        Some(time) => format!("{label} {}", clock::local(time).long()),
        None => format!("{label} not reported"),
    }
}

pub fn render(facts: &Facts) -> String {
    let mut lines = vec![format!("File: {}", facts.path)];
    lines.push(match &facts.digest {
        Ok(hex) => format!("{}: {hex}", facts.algorithm.label()),
        Err(reason) => format!("{}: unavailable, {reason}", facts.algorithm.label()),
    });
    lines.push(format!(
        "Size: {} ({} bytes)",
        super::space::format_size(facts.size),
        facts.size
    ));
    lines.push(time_line("Created:", facts.created));
    lines.push(time_line("Modified:", facts.modified));
    lines.push(time_line("Accessed:", facts.accessed));
    lines.push(match &facts.signature {
        Signature::Signed { signer, method } => format!(
            "Signature: signed and valid, {} signature, signer {}",
            method.word(),
            signer.as_deref().unwrap_or("not readable")
        ),
        Signature::Unsigned => {
            "Signature: not signed (no embedded signature, not in a catalog)".into()
        }
        Signature::Invalid { signer, reason } => format!(
            "Signature: present but not valid, {reason}; signer {}",
            signer.as_deref().unwrap_or("not readable")
        ),
        Signature::Unavailable(reason) => format!("Signature: unavailable, {reason}"),
    });
    lines.join("\n")
}

pub fn to_json(facts: &Facts) -> Value {
    let digest = match &facts.digest {
        Ok(hex) => json!(hex),
        Err(reason) => json!({"unavailable": reason}),
    };
    let signature = match &facts.signature {
        Signature::Signed { signer, method } => json!({
            "status": "signed",
            "method": method.word(),
            "signer": signer,
            "valid": true,
        }),
        Signature::Unsigned => json!({"status": "unsigned", "valid": false}),
        Signature::Invalid { signer, reason } => json!({
            "status": "invalid",
            "signer": signer,
            "valid": false,
            "reason": reason,
        }),
        Signature::Unavailable(reason) => json!({"status": "unavailable", "unavailable": reason}),
    };
    json!({
        "path": facts.path,
        "algorithm": facts.algorithm.key(),
        "digest": digest,
        "size_bytes": facts.size,
        "created": time_json(facts.created),
        "modified": time_json(facts.modified),
        "accessed": time_json(facts.accessed),
        "signature": signature,
    })
}

#[cfg(test)]
mod tests {
    use super::sys::Check;
    use super::*;

    const SIGNATURE_CASES: &str = include_str!("../../tests/fixtures/hash/signature_cases.txt");
    const VECTORS: &str = include_str!("../../tests/fixtures/hash/vectors.txt");

    /// `-` is no check, otherwise a status in hex and an optional signer after a colon.
    fn check(text: &str) -> Result<Option<Check>, String> {
        if text == "-" {
            return Ok(None);
        }
        let (status, signer) = match text.split_once(':') {
            Some((status, signer)) => (status, Some(signer.to_string())),
            None => (text, None),
        };
        let status = u32::from_str_radix(status.trim_start_matches("0x"), 16)
            .map_err(|_| format!("not a status: {status}"))?;
        Ok(Some(Check { status, signer }))
    }

    fn describe(signature: &Signature) -> String {
        match signature {
            Signature::Signed { signer, method } => {
                format!(
                    "signed {} {}",
                    method.word(),
                    signer.as_deref().unwrap_or("-")
                )
            }
            Signature::Unsigned => "unsigned".into(),
            Signature::Invalid { signer, reason } => {
                format!("invalid {} {reason}", signer.as_deref().unwrap_or("-"))
            }
            Signature::Unavailable(reason) => format!("unavailable {reason}"),
        }
    }

    #[test]
    fn signature_cases_from_the_fixture() {
        let mut seen = 0;
        for line in SIGNATURE_CASES
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let (input, expected) = line.split_once(" => ").expect(line);
            let (embedded, catalog) = input.split_once(" / ").expect(line);
            let raw = RawSignature {
                embedded: check(embedded).expect(line),
                catalog: check(catalog).expect(line),
            };
            assert_eq!(describe(&interpret_signature(&raw)), expected, "{line}");
            seen += 1;
        }
        assert!(seen >= 10);
    }

    #[test]
    fn a_malformed_signature_case_is_rejected_not_guessed() {
        assert!(check("zzzz").is_err());
        assert!(check("0x:x").is_err());
    }

    #[test]
    fn hashes_match_the_known_vectors_and_the_chunked_reader_agrees() {
        let dir = std::env::temp_dir().join(format!("hash-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for line in VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let fields: Vec<&str> = line.split('|').collect();
            assert_eq!(fields.len(), 3, "{line}");
            let file = dir.join("v.bin");
            let bytes = if fields[1] == "million-a" {
                vec![b'a'; 1_000_000]
            } else {
                fields[1].as_bytes().to_vec()
            };
            std::fs::write(&file, bytes).unwrap();
            let algorithm = Algorithm::parse(fields[0]).unwrap();
            let got = sys::digest(&file, algorithm, Instant::now() + Duration::from_secs(10));
            assert_eq!(got, Ok(fields[2].to_string()), "{line}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_expired_deadline_stops_the_hash_and_says_so() {
        let dir = std::env::temp_dir().join(format!("hash-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("big.bin");
        std::fs::write(&file, vec![0u8; 3 << 20]).unwrap();
        let got = sys::digest(&file, Algorithm::Sha256, Instant::now());
        std::fs::remove_dir_all(&dir).unwrap();
        let reason = got.unwrap_err();
        assert!(reason.contains("time limit"), "{reason}");
    }

    #[test]
    fn algorithm_names_are_strict() {
        assert_eq!(Algorithm::parse("SHA-256"), Ok(Algorithm::Sha256));
        assert_eq!(Algorithm::parse("sha1"), Ok(Algorithm::Sha1));
        assert!(Algorithm::parse("md5").is_err());
        assert!(Algorithm::parse("").is_err());
    }

    #[test]
    fn rfc3339_times_are_utc() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_709_251_199)),
            "2024-02-29T23:59:59Z"
        );
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_794_000_000)),
            "2026-11-06T21:20:00Z"
        );
    }

    fn facts() -> Facts {
        Facts {
            path: r"C:\Users\[user]\Downloads\setup.exe".into(),
            algorithm: Algorithm::Sha256,
            size: 1_234_567,
            created: Some(UNIX_EPOCH + Duration::from_secs(1_794_000_000)),
            modified: None,
            accessed: Some(UNIX_EPOCH + Duration::from_secs(1_794_000_100)),
            digest: Ok("ab".repeat(32)),
            signature: Signature::Signed {
                signer: Some("Example Corp".into()),
                method: Method::Embedded,
            },
        }
    }

    #[test]
    fn the_report_says_what_was_read_and_what_was_not() {
        let text = render(&facts());
        assert!(text.contains("SHA-256: abab"));
        assert!(text.contains("Modified: not reported"));
        assert!(text.contains("signed and valid, embedded signature, signer Example Corp"));
        let mut partial = facts();
        partial.digest = Err("the time limit was reached after 2.0 GiB".into());
        partial.signature = Signature::Unavailable("access denied".into());
        let text = render(&partial);
        assert!(text.contains("SHA-256: unavailable, the time limit"));
        assert!(text.contains("Signature: unavailable, access denied"));
    }

    #[test]
    fn json_output_parses_and_names_unavailable_readings() {
        let mut partial = facts();
        partial.digest = Err("refused".into());
        let text = serde_json::to_string_pretty(&to_json(&partial)).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["digest"]["unavailable"], "refused");
        assert_eq!(
            back["modified"]["unavailable"],
            "the file system did not report it"
        );
        assert_eq!(back["signature"]["status"], "signed");
        assert_eq!(back["size_bytes"], 1_234_567);
    }

    #[test]
    fn the_path_hides_the_profile_folder() {
        let shown = shown_path(r"C:\Users\SomeoneElse\Desktop\a.exe");
        assert!(!shown.contains("SomeoneElse"), "{shown}");
        assert!(shown.contains("[user]"));
    }

    #[test]
    fn bad_input_is_refused_with_a_reason() {
        let missing = Path::new(r"C:\definitely\not\here.bin");
        assert!(gather(missing, Algorithm::Sha256, Instant::now())
            .unwrap_err()
            .contains("no such file"));
        let dir = std::env::temp_dir();
        assert!(gather(&dir, Algorithm::Sha256, Instant::now())
            .unwrap_err()
            .contains("not a file"));
    }

    #[test]
    fn the_tool_reads_this_pc() {
        let started = Instant::now();
        let exe = std::env::current_exe().unwrap();
        let facts = gather(&exe, Algorithm::Sha1, Instant::now()).unwrap();
        assert_eq!(facts.digest.as_ref().map(String::len), Ok(40));
        assert!(facts.size > 0);
        assert!(started.elapsed() < Duration::from_secs(15));
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let notepad = Path::new(&system).join("System32").join("notepad.exe");
        if notepad.is_file() {
            let facts = gather(&notepad, Algorithm::Sha256, Instant::now()).unwrap();
            assert!(
                matches!(facts.signature, Signature::Signed { .. }),
                "{:?}",
                facts.signature
            );
        }
    }
}
