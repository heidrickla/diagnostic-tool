//! Self-update from a signed release file at the build's update address. The release file holds a
//! manifest and an ECDSA P-256 signature made off the build machine; the program carries only the
//! public key. A release is installed only when its manifest verifies, names a newer
//! version, and the downloaded program matches the manifest's size and SHA-256.
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::Deserialize;

/// Where releases live and the key that signs them.
pub struct Source {
    /// `https://<host>/file/<bucket>/diagnostic-tool`, no trailing slash.
    pub base: &'static str,
    /// The signing key's public point, X then Y, 32 bytes each.
    pub public_key_xy: [u8; 64],
}

/// The release bucket and signing key from `site.toml`; `None` without them. The private
/// key is held off the build machine.
pub const SOURCE: Option<Source> = crate::site::UPDATE;

pub const PRODUCT: &str = "diagnostic-tool";
/// Largest release file read.
const ENVELOPE_CAP: usize = 16 * 1024;
/// Largest program downloaded.
pub const PROGRAM_CAP: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub file: String,
    pub size: usize,
    pub sha256: [u8; 32],
}

#[derive(Deserialize)]
struct Envelope {
    manifest: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    product: String,
    version: String,
    file: String,
    size: usize,
    sha256: String,
    published: String,
}

/// Checks the release file's signature, then reads the manifest it signs.
pub fn verify_envelope(bytes: &[u8], public_key_xy: &[u8; 64]) -> Result<Release, String> {
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| "the release file is not readable")?;
    let base64 = base64::engine::general_purpose::STANDARD;
    let manifest = base64
        .decode(envelope.manifest)
        .map_err(|_| "the release manifest is not readable")?;
    let signature = base64
        .decode(envelope.signature)
        .map_err(|_| "the release signature is not readable")?;
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend_from_slice(public_key_xy);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(&manifest, &signature)
        .map_err(|_| "the release signature does not match")?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest).map_err(|_| "the signed manifest is not readable")?;
    if manifest.product != PRODUCT {
        return Err("the signed manifest is for another product".into());
    }
    if parse_version(&manifest.version).is_none() {
        return Err("the signed manifest has no valid version".into());
    }
    if manifest.file != program_name(&manifest.version) {
        return Err("the signed manifest names an unexpected file".into());
    }
    if manifest.size == 0 || manifest.size > PROGRAM_CAP {
        return Err("the signed manifest gives an impossible size".into());
    }
    let sha256 = hex32(&manifest.sha256).ok_or("the signed manifest has no valid SHA-256")?;
    if manifest.published.is_empty() {
        return Err("the signed manifest has no publish time".into());
    }
    Ok(Release {
        version: manifest.version,
        file: manifest.file,
        size: manifest.size,
        sha256,
    })
}

pub fn program_name(version: &str) -> String {
    format!("DiagnosticTool-{version}.exe")
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `MAJOR.MINOR.PATCH` with an optional `-rc.N`; a release sorts after its candidates.
fn parse_version(text: &str) -> Option<(u32, u32, u32, u32)> {
    let (core, rc) = match text.split_once("-rc.") {
        Some((core, rc)) => (core, Some(rc)),
        None => (text, None),
    };
    let number = |part: &str| -> Option<u32> {
        (!part.is_empty() && part.len() <= 3 && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    let mut parts = core.split('.');
    let (major, minor, patch) = (
        number(parts.next()?)?,
        number(parts.next()?)?,
        number(parts.next()?)?,
    );
    if parts.next().is_some() {
        return None;
    }
    let rc = match rc {
        Some(rc) => number(rc)?,
        None => u32::MAX,
    };
    Some((major, minor, patch, rc))
}

/// True when `candidate` is a later version than `current`.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

/// Fetches and verifies the release file; `Ok(None)` when it names no newer version.
pub fn check(source: &Source, current: &str) -> Result<Option<Release>, String> {
    let bytes = http::get(&format!("{}/latest.json", source.base), ENVELOPE_CAP)?;
    let release = verify_envelope(&bytes, &source.public_key_xy)?;
    Ok(is_newer(&release.version, current).then_some(release))
}

/// Downloads the release's program and checks it against the signed manifest.
pub fn download(source: &Source, release: &Release) -> Result<Vec<u8>, String> {
    let bytes = http::get(&format!("{}/{}", source.base, release.file), PROGRAM_CAP)?;
    matches_release(&bytes, release)?;
    Ok(bytes)
}

pub fn matches_release(bytes: &[u8], release: &Release) -> Result<(), String> {
    if bytes.len() != release.size {
        return Err("the download is not the size the release names".into());
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    if digest.as_ref() != release.sha256 {
        return Err("the download does not match the release's SHA-256".into());
    }
    if !bytes.starts_with(b"MZ") {
        return Err("the download is not a Windows program".into());
    }
    Ok(())
}

fn old_path(program: &Path) -> PathBuf {
    let mut name = program.file_name().unwrap_or_default().to_os_string();
    name.push(".old");
    program.with_file_name(name)
}

/// Replaces `program` with the verified bytes. The running program is renamed aside,
/// which Windows allows, and put back if the new one cannot be moved into place.
pub fn install(program: &Path, bytes: &[u8], release: &Release) -> Result<(), String> {
    matches_release(bytes, release)?;
    let staged = program.with_file_name(format!("{}.download", release.file));
    let old = old_path(program);
    let written = std::fs::write(&staged, bytes).and_then(|()| {
        // Read back so a short write or a scanner's change is caught before the swap.
        let back = std::fs::read(&staged)?;
        Ok(back == bytes)
    });
    match written {
        Ok(true) => {}
        Ok(false) => {
            let _ = std::fs::remove_file(&staged);
            return Err("the downloaded program changed on disk before it was installed".into());
        }
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "the new program could not be saved next to this one ({error})"
            ));
        }
    }
    let left = |text: String| match std::fs::remove_file(&staged) {
        Ok(()) => text,
        Err(e) => format!("{text}; {} could not be removed ({e})", staged.display()),
    };
    if let Err(error) = remove_old_file(&old) {
        return Err(left(error));
    }
    // What is moved aside is known by its identity, so only that very file is put back.
    let moved = match file_identity(program) {
        Ok(Some(id)) => id,
        Ok(None) => return Err(left("this program's file was not found".into())),
        Err(why) => {
            return Err(left(format!(
                "this program's file could not be read ({why})"
            )))
        }
    };
    if let Err(error) = std::fs::rename(program, &old) {
        return Err(left(format!(
            "this program could not be moved aside ({error})"
        )));
    }
    if let Err(error) = std::fs::rename(&staged, program) {
        let failed = format!("the new program could not be put in place ({error})");
        let mut aside = MovedAside { old: &old, program };
        return Err(left(
            match crate::restore::put_back_if_still(&mut aside, &Some(moved), &None) {
                crate::restore::PutBack::PutBack => format!("{failed}; this program was put back"),
                crate::restore::PutBack::LeftChanged { .. } => format!(
                    "{failed}; {} is no longer the program moved aside, so it was left as it is: put this program back by hand",
                    old.display()
                ),
                crate::restore::PutBack::AlreadyBack => {
                    format!("{failed}; nothing is at {} to put back", old.display())
                }
                crate::restore::PutBack::Unknown { why } | crate::restore::PutBack::Failed { why } => {
                    format!(
                        "{failed}; this program could not be put back ({why}): it is {}, rename it to {} by hand",
                        old.display(),
                        program.display()
                    )
                }
            },
        ));
    }
    Ok(())
}

/// Removes a program an earlier update moved aside; Ok when there is none.
fn remove_old_file(old: &Path) -> Result<(), String> {
    match std::fs::remove_file(old) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "the program an earlier update moved aside, {}, could not be removed ({e})",
            old.display()
        )),
    }
}

/// A file's identity: its volume's serial number and its file index, read through one
/// handle; `None` when nothing is at `path`.
fn file_identity(path: &Path) -> Result<Option<(u32, u64)>, String> {
    match open_to_move(path) {
        Ok(Some(file)) => identity_of(&file).map(Some),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Opens `path` to read its identity and rename it, sharing it with every other user (the
/// running program has its own file open); `None` when nothing is there.
fn open_to_move(path: &Path) -> Result<Option<std::fs::File>, String> {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SHARE_ALL: u32 = 0x7;
    match std::fs::OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_ALL)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} could not be opened ({e})", path.display())),
    }
}

fn identity_of(file: &std::fs::File) -> Result<(u32, u64), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is the open file's; `info` is a valid out structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(format!(
            "its identity could not be read ({})",
            std::io::Error::last_os_error()
        ));
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// The program an update moved aside, at `old`, as the rollback compares it: its identity,
/// `None` when nothing is there. Putting it back to `None` renames the very file read, by
/// its handle, to `program`, never over a file already there.
struct MovedAside<'a> {
    old: &'a Path,
    program: &'a Path,
}

impl crate::restore::Place for MovedAside<'_> {
    type Value = Option<(u32, u64)>;
    fn read(&mut self) -> Result<Option<(u32, u64)>, String> {
        file_identity(self.old)
    }
    /// One handle: the identity is read through it and the file renamed through it, so the
    /// file renamed is the file compared, whatever is put at its name meanwhile.
    fn swap(
        &mut self,
        expect: &Option<(u32, u64)>,
        value: &Option<(u32, u64)>,
    ) -> Result<crate::restore::Swap<Option<(u32, u64)>>, String> {
        let (Some(expect), None) = (expect, value) else {
            return Err("a file is never moved aside by putting it back".into());
        };
        let Some(file) = open_to_move(self.old)? else {
            return Ok(crate::restore::Swap::Changed(None));
        };
        let now = identity_of(&file)?;
        if now != *expect {
            return Ok(crate::restore::Swap::Changed(Some(now)));
        }
        rename_open_file(&file, self.program)?;
        Ok(crate::restore::Swap::Done)
    }
}

/// Renames an open file to `to`, refusing when something is already there.
fn rename_open_file(file: &std::fs::File, to: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
    };
    let name: Vec<u16> = to.as_os_str().encode_wide().collect();
    let head = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = head + (name.len() + 1) * 2;
    // u64s, so the structure is aligned.
    let mut buffer = vec![0u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the buffer is zeroed, aligned and large enough for the structure and the
    // name with its terminating zero; the name is written within it.
    let ok = unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        let target = std::ptr::addr_of_mut!((*info).FileName).cast::<u16>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), target, name.len());
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            size as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "it could not be renamed to {} ({})",
            to.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Removes the program a previous update moved aside; it may still be closing.
pub fn remove_old(program: &Path) {
    let _ = std::fs::remove_file(old_path(program));
}

mod http {
    use windows_sys::Win32::Networking::WinHttp::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Handle(*mut core::ffi::c_void);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: a handle WinHTTP returned, closed once.
                unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }

    fn open(raw: *mut core::ffi::c_void, what: &str) -> Result<Handle, String> {
        if raw.is_null() {
            Err(format!("{what} failed (Windows error {})", last_error()))
        } else {
            Ok(Handle(raw))
        }
    }

    fn last_error() -> u32 {
        // SAFETY: reads the calling thread's last error.
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    }

    /// One HTTPS GET with no redirects, Windows' proxy settings and certificate store, and
    /// a cap on the body.
    pub fn get(url: &str, cap: usize) -> Result<Vec<u8>, String> {
        crate::live::reading("the network");
        let (host, path) = crate::site_rules::https_parts(url)?;
        let path = if path.is_empty() { "/" } else { path };
        // SAFETY: plain WinHTTP calls on handles owned by `Handle`; every pointer passed
        // lives for the call.
        unsafe {
            let session = open(
                WinHttpOpen(
                    wide("DiagnosticTool-Update").as_ptr(),
                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                ),
                "opening the connection",
            )?;
            WinHttpSetTimeouts(session.0, 10_000, 10_000, 15_000, 30_000);
            let connect = open(
                WinHttpConnect(session.0, wide(host).as_ptr(), 443, 0),
                "connecting",
            )?;
            let request = open(
                WinHttpOpenRequest(
                    connect.0,
                    wide("GET").as_ptr(),
                    wide(path).as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    WINHTTP_FLAG_SECURE,
                ),
                "preparing the request",
            )?;
            let never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_REDIRECT_POLICY,
                &never as *const u32 as *const _,
                4,
            );
            if WinHttpSendRequest(request.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) == 0
                || WinHttpReceiveResponse(request.0, std::ptr::null_mut()) == 0
            {
                return Err(format!(
                    "the update server could not be reached (Windows error {})",
                    last_error()
                ));
            }
            let mut status = 0u32;
            let mut length = 4u32;
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                std::ptr::null(),
                &mut status as *mut u32 as *mut _,
                &mut length,
                std::ptr::null_mut(),
            );
            if status != 200 {
                return Err(format!("the update server answered HTTP {status}"));
            }
            let mut body = Vec::new();
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let mut read = 0u32;
                if WinHttpReadData(
                    request.0,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut read,
                ) == 0
                {
                    return Err(format!(
                        "the download stopped (Windows error {})",
                        last_error()
                    ));
                }
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&buffer[..read as usize]);
                if body.len() > cap {
                    return Err("the update server sent more than expected".into());
                }
            }
            Ok(body)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn key() -> (EcdsaKeyPair, [u8; 64]) {
        let random = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                .unwrap();
        let mut xy = [0u8; 64];
        xy.copy_from_slice(&pair.public_key().as_ref()[1..]);
        (pair, xy)
    }

    fn manifest(version: &str, program: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, program);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        format!(
            r#"{{"product":"diagnostic-tool","version":"{version}","file":"DiagnosticTool-{version}.exe","size":{},"sha256":"{hex}","published":"2026-11-06T09:00:00Z"}}"#,
            program.len()
        )
    }

    fn envelope(pair: &EcdsaKeyPair, manifest: &str) -> Vec<u8> {
        let signature = pair
            .sign(&SystemRandom::new(), manifest.as_bytes())
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "manifest": b64.encode(manifest),
            "signature": b64.encode(signature.as_ref()),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_signed_release_verifies_and_a_changed_one_does_not() {
        let (pair, xy) = key();
        let program = b"MZ the new program".to_vec();
        let text = manifest("1.0.1", &program);
        let release = verify_envelope(&envelope(&pair, &text), &xy).unwrap();
        assert_eq!(release.version, "1.0.1");
        assert_eq!(release.file, "DiagnosticTool-1.0.1.exe");
        assert_eq!(release.size, program.len());
        assert_eq!(matches_release(&program, &release), Ok(()));

        // The manifest changed after signing: a bigger version, same signature.
        let signed = envelope(&pair, &text);
        let mut value: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        value["manifest"] = b64.encode(text.replace("1.0.1", "9.0.1")).into();
        let forged = value.to_string().into_bytes();
        assert_eq!(
            verify_envelope(&forged, &xy),
            Err("the release signature does not match".into())
        );

        // Signed by another key.
        let (other, _) = key();
        assert!(verify_envelope(&envelope(&other, &text), &xy).is_err());
    }

    #[test]
    fn a_download_must_match_the_signed_size_and_digest() {
        let (pair, xy) = key();
        let program = b"MZ the new program".to_vec();
        let release = verify_envelope(&envelope(&pair, &manifest("1.0.1", &program)), &xy).unwrap();
        let mut changed = program.clone();
        changed[3] ^= 1;
        assert!(matches_release(&changed, &release).is_err());
        assert!(matches_release(&program[..5], &release).is_err());
    }

    #[test]
    fn signed_manifests_with_odd_fields_are_refused() {
        let (pair, xy) = key();
        let program = b"MZ x".to_vec();
        let good = manifest("1.0.1", &program);
        for bad in [
            good.replace("diagnostic-tool\"", "other-tool\""),
            good.replace("DiagnosticTool-1.0.1.exe", "..\\\\evil.exe"),
            good.replace("\"1.0.1\"", "\"1.0\""),
            good.replace("\"published\"", "\"extra\":1,\"published\""),
        ] {
            assert!(
                verify_envelope(&envelope(&pair, &bad), &xy).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn versions_order_with_release_candidates_before_the_release() {
        assert!(is_newer("1.0.0", "1.0.0-rc.1"));
        assert!(is_newer("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(is_newer("1.0.1", "1.0.0"));
        assert!(is_newer("1.10.0", "1.9.9"));
        assert!(!is_newer("1.0.0-rc.1", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("1.0", "0.9.0"));
        assert!(!is_newer("2.0.0", "garbage"));
    }

    /// Needs the internet and an update address that holds a signed release.
    #[test]
    #[ignore]
    fn the_published_release_verifies_and_downloads() {
        let Some(source) = SOURCE.as_ref() else {
            eprintln!("skipped: this build has no update source in site.toml");
            return;
        };
        let release = check(source, "0.0.1")
            .expect("latest.json verifies")
            .expect("a release newer than 0.0.1");
        assert_eq!(release.file, program_name(&release.version));
        let bytes = download(source, &release).expect("the program matches its manifest");
        assert_eq!(bytes.len(), release.size);
        assert!(check(source, &release.version).unwrap().is_none());
    }

    /// Needs the internet: an unauthenticated API request answers 401.
    #[test]
    #[ignore]
    fn the_https_reader_reports_the_server_status() {
        assert_eq!(
            http::get("https://api.github.com/user", 4096),
            Err("the update server answered HTTP 401".into())
        );
        assert_eq!(
            http::get("http://example.com/", 4096),
            Err("the address must start with https://".into())
        );
    }

    #[test]
    fn install_swaps_the_program_and_keeps_the_old_one_aside() {
        let dir = std::env::temp_dir().join(format!("diagtool-update-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("DiagnosticTool.exe");
        std::fs::write(&program, b"MZ old").unwrap();
        let (pair, xy) = key();
        let new = b"MZ new program".to_vec();
        let release = verify_envelope(&envelope(&pair, &manifest("1.0.1", &new)), &xy).unwrap();
        install(&program, &new, &release).unwrap();
        assert_eq!(std::fs::read(&program).unwrap(), new);
        assert_eq!(std::fs::read(old_path(&program)).unwrap(), b"MZ old");
        assert!(!dir.join("DiagnosticTool-1.0.1.exe.download").exists());
        remove_old(&program);
        assert!(!old_path(&program).exists());
        assert!(install(&program, b"MZ tampered", &release).is_err());
        assert_eq!(std::fs::read(&program).unwrap(), new);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard: when the new program cannot be put in place, the program moved aside is
    /// renamed back only while the file at the moved-aside name is still that very file; a
    /// file put there since is left, and so is a file put at the program's own name.
    #[test]
    fn only_the_program_moved_aside_is_put_back() {
        let dir = std::env::temp_dir().join(format!("diagtool-rollback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("DiagnosticTool.exe");
        let old = old_path(&program);
        let put_back = |id| {
            crate::restore::put_back_if_still(
                &mut MovedAside {
                    old: &old,
                    program: &program,
                },
                &Some(id),
                &None,
            )
        };
        std::fs::write(&program, b"MZ running").unwrap();
        let id = file_identity(&program).unwrap().unwrap();
        std::fs::rename(&program, &old).unwrap();
        assert_eq!(put_back(id), crate::restore::PutBack::PutBack);
        assert_eq!(std::fs::read(&program).unwrap(), b"MZ running");

        // Another file at the moved-aside name: left, and nothing is renamed.
        std::fs::rename(&program, &old).unwrap();
        std::fs::remove_file(&old).unwrap();
        std::fs::write(&old, b"MZ someone else's").unwrap();
        assert!(matches!(
            put_back(id),
            crate::restore::PutBack::LeftChanged { .. }
        ));
        assert!(!program.exists());
        assert_eq!(std::fs::read(&old).unwrap(), b"MZ someone else's");

        // The very file, but something already at the program's name: not replaced.
        let other = file_identity(&old).unwrap().unwrap();
        std::fs::write(&program, b"MZ in the way").unwrap();
        assert!(matches!(
            put_back(other),
            crate::restore::PutBack::Failed { .. }
        ));
        assert_eq!(std::fs::read(&program).unwrap(), b"MZ in the way");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
