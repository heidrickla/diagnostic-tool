//! Release tasks, run as `cargo xtask <command>`.

mod dist;
mod icon;
mod pe;
mod scan;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command>
  dist [--allow-dirty]    build dist/DiagnosticTool-<version>.exe, SHA256SUMS and build-info.txt
  repro                   build HEAD in two directories and compare the hashes
  icon [--preview <dir>]  render assets/app.ico
  screenshots [<dir>]     render the README screenshots into docs/screenshots or <dir>";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("dist") => dist_command(&args[1..]),
        Some("repro") if args.len() == 1 => dist::repro(),
        Some("icon") => icon_command(&args[1..]),
        Some("screenshots") => screenshots_command(&args[1..]),
        _ => Err(USAGE.into()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits inside the repository")
        .to_path_buf()
}

fn dist_command(args: &[String]) -> Result<()> {
    let mut options = dist::DistOptions {
        allow_dirty: false,
        source_commit: None,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--allow-dirty" => options.allow_dirty = true,
            "--source-commit" => {
                options.source_commit = Some(rest.next().ok_or(USAGE)?.clone());
            }
            _ => return Err(USAGE.into()),
        }
    }
    dist::dist(&options)
}

/// Writes assets/app.ico; `--preview <dir>` also writes each size as a PNG,
/// and the small sizes magnified to 256 px with square pixels for inspection.
fn icon_command(args: &[String]) -> Result<()> {
    let preview = match args {
        [] => None,
        [flag, dir] if flag == "--preview" => Some(PathBuf::from(dir)),
        _ => return Err(USAGE.into()),
    };
    let path = repo_root().join("assets").join("app.ico");
    let ico = icon::ico()?;
    std::fs::write(&path, &ico)?;
    println!("wrote {} ({} bytes)", path.display(), ico.len());
    if let Some(dir) = preview {
        std::fs::create_dir_all(&dir)?;
        for size in icon::BMP_SIZES.into_iter().chain([icon::PNG_SIZE]) {
            let file = dir.join(format!("icon-{size}.png"));
            let rgba = icon::render(size);
            std::fs::write(&file, icon::png(size, &rgba)?)?;
            let zoom = icon::PNG_SIZE / size;
            if zoom > 1 {
                let file = dir.join(format!("icon-{size}-zoom.png"));
                std::fs::write(&file, icon::png(size * zoom, &magnify(&rgba, size, zoom))?)?;
            }
        }
        println!("previews in {}", dir.display());
    }
    Ok(())
}

/// Builds the debug binary and runs its screenshot mode, which renders made-up readings
/// on a hidden desktop; the debug build is the only one that has the mode.
fn screenshots_command(args: &[String]) -> Result<()> {
    let root = repo_root();
    let dir = match args {
        [] => root.join("docs").join("screenshots"),
        [dir] => std::env::current_dir()?.join(dir),
        _ => return Err(USAGE.into()),
    };
    let status = std::process::Command::new(std::env::var_os("CARGO").unwrap_or("cargo".into()))
        .current_dir(&root)
        .args([
            "run",
            "--locked",
            "--quiet",
            "--bin",
            "DiagnosticTool",
            "--",
            "--screenshots",
        ])
        .arg(&dir)
        .status()?;
    if !status.success() {
        return Err(format!("the screenshot mode ended with {status}").into());
    }
    Ok(())
}

fn magnify(rgba: &[u8], size: u32, zoom: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgba.len() * (zoom * zoom) as usize);
    for y in 0..size * zoom {
        for x in 0..size * zoom {
            let i = (((y / zoom) * size + x / zoom) * 4) as usize;
            out.extend_from_slice(&rgba[i..i + 4]);
        }
    }
    out
}
