# Diagnostic Tool

Diagnostic Tool is one portable Windows program for a technician helping someone whose PC has a problem, and for recovering data from a drive that is failing. It has no installer, no service, no startup entry and no listening port.

Diagnostics. The person being helped double-clicks the program and chooses Start; that one consent authorizes the checks. Actions that change the PC ask on their own: Windows asks for administrator approval before drive recovery or crash dump changes, Clean up confirms before it deletes, and writing an image to a replacement drive confirms the drive. Read-only checks run in the background across the whole system, a dated findings PDF is saved in the user's Documents folder, and the technician has the big picture before any repair. Every command and change goes in an activity record. There is no screen sharing or remote desktop.

Drive recovery. From a drive's health window the technician opens a recovery window that offers:

- Rescue image: the whole drive to an image file and a GNU ddrescue map on another drive, easy areas first, stoppable and resumable, with a map strip of rescued, bad and untried areas. The failing drive is only ever read.
- Rescue copy of files: chosen folders to another drive, with a log of damaged and skipped files.
- Recover deleted or lost files: NTFS, FAT and exFAT volumes, including lost partitions found by their boot sectors, recovered to another drive with a report. Find files by type recovers photos, documents, video, audio, archives and databases by their contents where the file system is gone.
- Working from an image: open it as a drive read-only, unlock a BitLocker volume, copy a person's files, check recovered files, and write the image to a replacement drive.

A condition strip keeps the drive's condition in view during a rescue, and a run that is stopped, paused by heat or interrupted by a drive that stopped answering resumes from its map. Every window has a "?" button that opens a help pane for what the window does and what to watch for.

## Requirements

| Item | Requirement |
|---|---|
| Operating system | Windows 10 or 11, x86-64 |
| Privileges | The checks run as the current user. Drive recovery and changing crash dump settings start a second copy of the program through one Windows administrator prompt |
| Installation | None; the executable is self-contained and needs no Visual C++ redistributable |

## Download and build

Build from source with Rust 1.98.1, the `x86_64-pc-windows-msvc` target, Visual Studio Build Tools 2022 and the Windows SDK:

| Command | Does |
|---|---|
| `cargo build --release --locked` | builds `target/release/DiagnosticTool.exe` |
| `cargo xtask dist` | builds the reproducible release exe with its checksums into `dist/`; see [docs/RELEASE.md](docs/RELEASE.md) |
| `cargo xtask repro` | builds the same commit twice in clean directories and compares the hashes |
| `cargo run --example sample_report` | writes a synthetic report to `output/pdf/` without reading this PC |
| `cargo fmt --all --check` | formatting gate |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | lint gate |
| `cargo test --locked --workspace` | tests |

A release is one file, `DiagnosticTool-<version>.exe`, published with its SHA-256. Verify a download with `Get-FileHash .\DiagnosticTool-<version>.exe -Algorithm SHA256` or `sha256sum -c SHA256SUMS` and compare it with the published `SHA256SUMS`.

## Usage

Run `DiagnosticTool.exe` and choose Start. The window lists each check with a progress bar and Pause, Stop and View hardware buttons; the user can keep working, because checks run one at a time at below-normal priority. When the checks finish, or the user stops them, the report is saved and the window offers Open report, Show in folder and Close.

Result rows end green when nothing was found, amber when something is worth a look and red for a serious fault. Rows with a tool open it when clicked:

| Check | Opens |
|---|---|
| Windows drive space | a map of the Windows drive by folder and file size, the largest files, and Clean up for temporary files and the Recycle Bin, removed only after confirmation |
| Recent system events, App crashes, Service failures, Hardware and driver events | an event viewer filtered by level, age and text |
| Restart and crash settings, Crash dump readiness | a window that says whether the next crash leaves a dump, with Set up and Put back for the settings |
| Drive health status, Drive wear and errors | the drive window: health, SMART and NVMe figures, a speed test, a read check and the Recovery button |
| CPU and memory | processor, memory and board details, and live CPU and memory graphs |

The checks are Windows version, hardware inventory (without serial numbers), Windows drive space, restart and crash settings, recent system events, app crashes, service failures, update history, CPU and memory, drive health status, hardware and driver events, drive wear and errors, and crash dump readiness. A check that cannot run is reported as unavailable with its reason, never as passed.

### Command line

| Command | Does |
|---|---|
| `DiagnosticTool.exe` | opens the diagnostic window |
| `DiagnosticTool.exe --recovery --disk N` | opens the recovery window for physical drive N; the drive window's Recovery button starts it through one administrator prompt |
| `DiagnosticTool.exe --recovery --image FILE` | opens the recovery window for a rescue image |
| `DiagnosticTool.exe --crash-dumps` | opens the crash dump settings window, elevated |
| `DiagnosticTool.exe --recover-files --image IMAGE --to FOLDER [options]` | recovers files from an image with no window |
| `DiagnosticTool.exe --help` | lists the options of `--recover-files` |
| `toolkit <tool>` | read-only console tools: events, timeline, crashes, drives, startup, network, perf, battery, space, hash, drivers, updates; `toolkit help` lists them, `toolkit <tool> --help` gives a tool's options, and `--json` gives the same readings as structured fields |

`--recover-files` options:

| Option | Does |
|---|---|
| `--volume N` | the volume to read, numbered from 1 as the run lists them; default the largest file-system volume |
| `--all` | recovers every file on the volume (default) |
| `--deleted-only` | recovers only deleted files |
| `--deleted-folder NAME` | puts deleted files under that folder of the destination |
| `--damaged-folder NAME` | puts files that end damaged under that folder |
| `--by-type` | one folder per kind of file instead of the source's folders |

The destination folder must exist, on another drive. Progress goes to standard output; exit 0 is complete, 1 is stopped or incomplete (run it again into the same folder to finish), 2 is a command line or image that could not be used. Ctrl+C stops cleanly.

## Site settings

A build can carry settings from an optional `site.toml` at the repository root: flat `key = "value"` lines read when the program is built. Without the file every key takes its default.

| Key | Meaning |
|---|---|
| `operator_name` | the technician's name shown to the person being helped, 1 to 12 characters with no space at either end; default "your technician" |
| `support_endpoint` and `support_operator_email` | both or neither; the remote support relay, an https address that is a bare host name with no port or path, used only by builds with the `live_support` feature and the activation marker |
| `update_base` and `update_public_key` | both or neither; an https base address (host name without a port, then a path with no trailing slash) where signed release manifests live, and the 128-hex-character P-256 public key that verifies them; without them the program does not update itself |

## Updates

When `update_base` and `update_public_key` are set, the window fetches a signed release manifest in the background at start. A newer version shows an Update button under Close once the report is saved; it downloads the program, checks it against the signed size and SHA-256, swaps it in and restarts. The check sends nothing about the PC. Release manifests are signed with a key held off the build machine.

## Remote support

The repository also holds an outbound support client, an HTTP relay and an MCP adapter for the technician's side. They are off in every ordinary build: the GUI's remote worker starts only in a build with the `live_support` feature and the activation marker, and the relay and adapter binaries exit disabled by default.

## Privacy

| What | Where it goes |
|---|---|
| Windows version, hardware inventory, event logs, drive and update state, crash settings, drive health data | read locally; the report holds hardware without serial numbers, and free text from the PC passes through redaction |
| The findings PDF and the activity record | saved on the PC, in Documents; nothing uploads them |
| Search the web in the event viewer | sends only the event's source and event id, and only when clicked |
| A BitLocker recovery key | held in memory only, kept out of crash dumps, and never shown |
| The update check | sends nothing about the PC, and happens only in a build with update settings |
| The network check | sends ping echoes to the default gateway, 1.1.1.1 and 8.8.8.8 and DNS lookups for two well-known names, and nothing about the PC |
| The BitLocker key lookup sign-in window | opens Microsoft's own sign-in pages, only when the user chooses it |

Nothing leaves the machine except remote support in a build configured for it once the user starts a session, the update check in a build with update settings, the event viewer's Search the web when clicked, the network check's pings and lookups, and the BitLocker key lookup's Microsoft sign-in window when chosen. Recovery never writes to the drive being rescued.

## Documents

| File | Content |
|---|---|
| [DESIGN.md](DESIGN.md) | architecture, consent model and how to add checks and repairs |
| [docs/RELEASE.md](docs/RELEASE.md) | release build, checks and reproduction |
| [CHANGELOG.md](CHANGELOG.md) | changes by version |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | dependency notices |

## License

MIT; see [LICENSE](LICENSE). Third-party components and their licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
