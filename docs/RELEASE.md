# Release

A release is one file, `DiagnosticTool-<version>.exe`, built on Windows from a committed tree and published with its SHA-256.

## Requirements

| Tool | Version | Used for |
|---|---|---|
| Rust | 1.98.1, `x86_64-pc-windows-msvc` | compiler, `rustfmt`, `clippy` |
| Visual Studio Build Tools | 2022, MSVC x64 | `link.exe` |
| Windows SDK | 10.0.22621 or later | `rc.exe` for the icon, manifest and version resources |
| Git | any | commit id, `git archive` for `repro` |

## Commands

| Command | Does |
|---|---|
| `cargo xtask dist` | Builds the release exe from a clean tree and writes `dist/` |
| `cargo xtask dist --allow-dirty` | The same from a tree with uncommitted changes; `build-info.txt` records `dirty: true` |
| `cargo xtask repro` | Extracts `HEAD` into two temporary directories, runs `dist` in each, prints both hashes and fails if they differ |
| `cargo xtask icon` | Renders `assets/app.ico` |
| `cargo xtask icon --preview <dir>` | Also writes each icon size as a PNG, small sizes magnified |

## Steps

| Step | Command |
|---|---|
| 1. Set the version | `version` in `Cargo.toml`; the VERSIONINFO resource, file name and build info follow it |
| 2. Run the gates | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` |
| 3. Commit | the tree must be clean for `dist` |
| 4. Build | `cargo xtask dist` |
| 5. Confirm reproducibility | `cargo xtask repro` prints the same hash as `dist/SHA256SUMS` |
| 6. Publish | `dist/DiagnosticTool-<version>.exe` with `dist/SHA256SUMS` |
| 7. Sign a manifest | only for builds with update settings; see Signing a release manifest |

## Signing a release manifest

A build with `update_base` and `update_public_key` in `site.toml` checks `<update_base>/latest.json` at start. The signing key is an ECDSA P-256 key pair; the private half is held off the build machine and signs on a machine that holds it, and the 128-hex-character public half (the uncompressed point without its leading `04` byte) is the `update_public_key` setting.

| Step | Content |
|---|---|
| 1. Write the manifest | JSON with `product`, `version`, `file` (`DiagnosticTool-<version>.exe`), `size` in bytes, `sha256` as 64 hex characters and `published` as a time; no other fields |
| 2. Sign it offline | ECDSA P-256 with SHA-256 over the manifest bytes exactly as written, the signature in fixed form (r then s, 64 bytes) |
| 3. Write `latest.json` | `{"manifest": "<base64 of the manifest bytes>", "signature": "<base64 of the signature>"}`, standard base64 |
| 4. Upload | the exe and `latest.json` under `update_base`, the exe under its own file name |

The program verifies the signature before it reads anything else from the file, then requires the signed size and SHA-256 to match the download.

## Outputs

| File | Content |
|---|---|
| `dist/DiagnosticTool-<version>.exe` | The application |
| `dist/SHA256SUMS` | `<sha256>  DiagnosticTool-<version>.exe`, the format `sha256sum -c` reads |
| `dist/build-info.txt` | version, git commit, dirty flag, rustc and cargo versions, target, SHA-256 |

## Checks `dist` makes before writing `dist/`

| Check | Fails when |
|---|---|
| Builder paths | The exe contains the user profile directory, `CARGO_HOME`, `RUSTUP_HOME`, the toolchain directory or the repository root, in UTF-8 or UTF-16LE, in any letter case, with either path separator |
| C runtime | The import table names `VCRUNTIME*`, `MSVCP*`, `ucrtbase*` or `api-ms-win-crt-*` |
| Resources | The manifest, version or icon resource with id 1 is absent |
| PDB path | The CodeView entry names the PDB with a directory |
| Deterministic link | The debug directory has no REPRO entry |
| DLL search | `DependentLoadFlags` is not `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800) |

`tests/release_binary.rs` checks the same properties on the exe that `cargo test` builds.

## Build settings

| Setting | Where | Effect |
|---|---|---|
| `target-feature=+crt-static` | `.cargo/config.toml` | The C runtime is linked in; no Visual C++ redistributable is needed |
| `/Brepro` | `.cargo/config.toml` | The PE timestamp is a hash of the content instead of the link time |
| `/PDBALTPATH:%_PDB%` | passed by rustc | The exe names its PDB without a directory |
| `/DEPENDENTLOADFLAG:0x800` | `build.rs`, DiagnosticTool only | The loader takes the exe's imports from System32, never from the folder it runs in |
| `lto = true`, `codegen-units = 1`, `incremental = false` | `[profile.release]` | One optimized, deterministic compilation unit |
| `panic = "unwind"` | `[profile.release]` | A panic in a worker thread unwinds that thread and leaves the GUI thread running |
| `--remap-path-prefix` | added by `dist` through `--config` | `CARGO_HOME` becomes `/cargo`, the toolchain `/rustc-sysroot`, the repository `/build` |
| `--locked` | `dist` | The build uses exactly `Cargo.lock` |
| `--target-dir target/dist` | `dist` | Release builds with remapping do not invalidate the ordinary `target/release` |

`dist` passes the remapping with `--config`, which cargo merges with the `rustflags` array in `.cargo/config.toml`. It clears `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` for the build, since either one replaces that array.

## Resources

| Resource | Id | Source |
|---|---|---|
| Icon group | 1 | `assets/app.ico`: 16, 20, 24, 32, 40, 48 and 64 px as 32-bit BMP, 256 px as PNG |
| Manifest | 1 | `assets/app.manifest`: `asInvoker`, PerMonitorV2 with `true/pm` fallback, Windows 10 and 11, Common Controls 6.0, UTF-8 code page, long paths |
| Version | 1 | `assets/app.rc` with `version.rh`, which `build.rs` writes from the package version |

| Version field | Value for `1.0.0` |
|---|---|
| FILEVERSION, PRODUCTVERSION | 1.0.0.0 |
| FileVersion, ProductVersion strings | 1.0.0 |
| FILEFLAGS | VS_FF_PRERELEASE when the version has a pre-release part |
| ProductName, FileDescription | Diagnostic Tool |
| CompanyName | Lewis Heidrick |
| LegalCopyright | Copyright 2026 Lewis Heidrick |
| OriginalFilename | DiagnosticTool.exe |

## Verifying a download

| Shell | Command | Compare with |
|---|---|---|
| PowerShell | `Get-FileHash .\DiagnosticTool-<version>.exe -Algorithm SHA256` | the hash in `SHA256SUMS` |
| Command Prompt | `certutil -hashfile DiagnosticTool-<version>.exe SHA256` | the hash in `SHA256SUMS` |
| Git Bash, WSL | `sha256sum -c SHA256SUMS` in the folder holding both files | prints `OK` |

## Reproducing a build

Anyone with the same toolchain can rebuild a published release and compare hashes:

| Step | Command |
|---|---|
| 1. Check out the release commit | `git checkout <commit from build-info.txt>` |
| 2. Build | `cargo xtask dist` |
| 3. Compare | `dist/SHA256SUMS` against the published `SHA256SUMS` |

The exe does not depend on the build directory, the user name or the time of the build, so the hash depends only on the source, `Cargo.lock` and the toolchain versions.
