//! `dist` builds the release exe with builder paths remapped and checks it;
//! `repro` builds HEAD twice in different directories and compares the hashes.

use crate::{pe, repo_root, scan, Result};
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET: &str = "x86_64-pc-windows-msvc";
const BIN: &str = "DiagnosticTool";
const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x800;

pub struct DistOptions {
    pub allow_dirty: bool,
    /// Set by `repro` for a `git archive` export, which has no repository to ask.
    pub source_commit: Option<String>,
}

fn cargo() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd.output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{cmd:?} failed: {}", stderr.trim()).into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("{cmd:?} failed with {status}").into());
    }
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    output(Command::new("git").arg("-C").arg(root).args(args))
}

fn package_version(root: &Path) -> Result<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let package = manifest
        .split("\n[")
        .find(|section| section.starts_with("[package]") || section.starts_with("package]"))
        .ok_or("Cargo.toml has no [package] table")?;
    package
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_string)
        .ok_or_else(|| "no version in [package]".into())
}

fn home_subdir(var: &str, default: &str) -> Result<PathBuf> {
    if let Some(dir) = env::var_os(var) {
        return Ok(PathBuf::from(dir));
    }
    Ok(user_profile()?.join(default))
}

fn user_profile() -> Result<PathBuf> {
    env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .ok_or_else(|| "USERPROFILE is not set".into())
}

/// The builder-specific directories: remapped in the build, then searched for in the exe.
struct BuilderPaths {
    profile: PathBuf,
    cargo_home: PathBuf,
    rustup_home: PathBuf,
    sysroot: PathBuf,
    root: PathBuf,
}

impl BuilderPaths {
    fn discover(root: &Path) -> Result<Self> {
        let sysroot = output(
            Command::new("rustc")
                .args(["--print", "sysroot"])
                .current_dir(root),
        )?;
        Ok(BuilderPaths {
            profile: user_profile()?,
            cargo_home: home_subdir("CARGO_HOME", ".cargo")?,
            rustup_home: home_subdir("RUSTUP_HOME", ".rustup")?,
            sysroot: PathBuf::from(sysroot),
            root: root.to_path_buf(),
        })
    }

    // rustc applies the last matching prefix, so the most specific (the
    // repository, which may sit under the profile) goes last.
    fn remaps(&self) -> [(&Path, &str); 3] {
        [
            (&self.cargo_home, "/cargo"),
            (&self.sysroot, "/rustc-sysroot"),
            (&self.root, "/build"),
        ]
    }

    fn needles(&self) -> Vec<String> {
        [
            &self.profile,
            &self.cargo_home,
            &self.rustup_home,
            &self.sysroot,
            &self.root,
        ]
        .iter()
        .map(|p| p.display().to_string())
        .collect()
    }
}

/// `--config` value that adds to the rustflags in .cargo/config.toml. Cargo
/// merges config arrays, whereas RUSTFLAGS would replace them.
fn remap_config(paths: &BuilderPaths) -> Result<String> {
    let mut flags = Vec::new();
    for (from, to) in paths.remaps() {
        let from = from.display().to_string();
        // TOML literal strings keep backslashes but cannot hold a quote.
        if from.contains('\'') {
            return Err(format!("cannot pass a path containing a quote: {from}").into());
        }
        flags.push(format!("'--remap-path-prefix={from}={to}'"));
    }
    Ok(format!("target.{TARGET}.rustflags=[{}]", flags.join(", ")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every reason the exe is not fit to hand out; empty when it is.
fn release_problems(exe: &[u8], paths: &BuilderPaths) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for found in scan::find_paths(exe, &paths.needles()) {
        problems.push(format!(
            "contains builder path {} ({}) at offset {:#x}",
            found.needle, found.encoding, found.offset
        ));
    }
    let image = pe::Pe::parse(exe)?;
    for dll in image.imported_dlls()? {
        if pe::is_crt_dll(&dll) {
            problems.push(format!("imports C runtime DLL {dll}"));
        }
    }
    for (kind, name) in [
        (pe::RT_MANIFEST, "manifest"),
        (pe::RT_VERSION, "version"),
        (pe::RT_ICON_GROUP, "icon"),
    ] {
        if !image.has_resource(kind, 1)? {
            problems.push(format!("has no {name} resource with id 1"));
        }
    }
    match image.pdb_path()? {
        Some(pdb) if pdb.contains(['\\', '/', ':']) => {
            problems.push(format!("names its PDB with a directory: {pdb}"));
        }
        _ => {}
    }
    if !image
        .debug_entries()?
        .iter()
        .any(|e| e.kind == pe::DEBUG_TYPE_REPRO)
    {
        problems.push("was not linked with /Brepro".to_string());
    }
    if image.dependent_load_flags()? != Some(LOAD_LIBRARY_SEARCH_SYSTEM32) {
        problems.push("may load its imports from the application directory".to_string());
    }
    Ok(problems)
}

pub fn dist(options: &DistOptions) -> Result<()> {
    let root = repo_root();
    let (commit, dirty) = match &options.source_commit {
        Some(commit) => (commit.clone(), false),
        None => {
            let commit = git(&root, &["rev-parse", "HEAD"])?;
            let dirty = !git(&root, &["status", "--porcelain"])?.is_empty();
            if dirty && !options.allow_dirty {
                return Err(
                    "the working tree has changes; commit them or pass --allow-dirty".into(),
                );
            }
            (commit, dirty)
        }
    };
    let rustc = output(Command::new("rustc").arg("-vV").current_dir(&root))?;
    if !rustc.lines().any(|l| l == format!("host: {TARGET}")) {
        return Err(format!("dist builds on a {TARGET} host only").into());
    }
    let version = package_version(&root)?;
    let paths = BuilderPaths::discover(&root)?;
    let target_dir = root.join("target").join("dist");

    run(Command::new(cargo())
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "--locked",
            "--package",
            "diagnostic-tool",
        ])
        .args(["--bin", BIN])
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--config")
        .arg(remap_config(&paths)?)
        // Either variable would replace the crt-static and /Brepro flags.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS"))?;

    let built = target_dir.join("release").join(format!("{BIN}.exe"));
    let exe = fs::read(&built)?;
    let problems = release_problems(&exe, &paths)?;
    if !problems.is_empty() {
        return Err(format!(
            "{} is not releasable:\n  {}",
            built.display(),
            problems.join("\n  ")
        )
        .into());
    }

    let dist_dir = root.join("dist");
    fs::create_dir_all(&dist_dir)?;
    let name = format!("{BIN}-{version}.exe");
    let sha256 = sha256_hex(&exe);
    let out = dist_dir.join(&name);
    fs::write(&out, &exe)?;
    fs::write(dist_dir.join("SHA256SUMS"), format!("{sha256}  {name}\n"))?;
    let rustc_version = rustc.lines().next().unwrap_or_default();
    let cargo_version = output(Command::new(cargo()).arg("-V").current_dir(&root))?;
    fs::write(
        dist_dir.join("build-info.txt"),
        format!(
            "version: {version}\ncommit: {commit}\ndirty: {dirty}\nrustc: {rustc_version}\ncargo: {cargo_version}\ntarget: {TARGET}\nsha256: {sha256}\n"
        ),
    )?;
    println!("{sha256}  {}", out.display());
    Ok(())
}

/// Removes the scratch directory however `repro` ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            eprintln!("xtask: could not remove {}: {e}", self.0.display());
        }
    }
}

pub fn repro() -> Result<()> {
    let root = repo_root();
    let commit = git(&root, &["rev-parse", "HEAD"])?;
    let scratch =
        Scratch(env::temp_dir().join(format!("diagnostic-tool-repro-{}", std::process::id())));
    fs::create_dir_all(&scratch.0)?;
    let archive = scratch.0.join("source.tar");
    run(Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["archive", "--format=tar", "-o"])
        .arg(&archive)
        .arg(&commit))?;

    // Different names and depths, so any path that survives into the exe changes its hash.
    let trees = [scratch.0.join("a"), scratch.0.join("second-tree").join("b")];
    let mut hashes = Vec::new();
    for tree in &trees {
        fs::create_dir_all(tree)?;
        run(Command::new(system_tar()?)
            .arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(tree))?;
        run(Command::new(cargo())
            .current_dir(tree)
            .args(["run", "--locked", "--package", "xtask", "--", "dist"])
            .args(["--source-commit", &commit])
            .env_remove("CARGO_TARGET_DIR"))?;
        let sums = fs::read_to_string(tree.join("dist").join("SHA256SUMS"))?;
        let hash = sums
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        println!("{hash}  {}", tree.display());
        hashes.push(hash);
    }
    if hashes[0].is_empty() || hashes[0] != hashes[1] {
        return Err("the two builds differ".into());
    }
    println!(
        "reproducible: both builds of {commit} hash to {}",
        hashes[0]
    );
    Ok(())
}

// Git for Windows puts GNU tar first on PATH, which reads `C:` as a remote host.
fn system_tar() -> Result<PathBuf> {
    let root = env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
    Ok(PathBuf::from(root).join("System32").join("tar.exe"))
}
