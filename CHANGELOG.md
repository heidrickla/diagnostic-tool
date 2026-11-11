# Changelog

## 1.0.0, 2026-11-11

### Data recovery

- A map with a block that runs past the largest byte a drive can have is refused when it is read, saying which line. The place Fill the gaps keeps is read and removed through the image's folder as the program opened and checked it, and removed only once the run's results are written and its event log is saved; every run that keeps a place ends through one step that saves the event log and then removes the place, a run with nothing to fill included (it saves its own event line first, so a place kept after a failed save stays until one is saved); a folder that cannot be opened, a log that cannot be saved and a place that cannot be removed are each said in the result.
- The drive health, drive space, processor and memory, crash dump, event viewer and inspector windows open help like the recovery windows: a "?" button shows what the window is for, steps for its controls, what to watch for and what needs judgment.
- The main window has a "?" button too: its help pane says what the app is, what each button and row opens, where to start, what to watch for and what needs judgment. The window widens by the pane while it is open.
- Every window, report, message and document is in American spelling.
- A recover asks which disk its destination is on once, when it opens the destination, in place of at every file and folder it makes; everything is still made through the handle of the folder it is in, never through a link or junction, which is refused where it is met. A test recovery of 4,000 small files from an image with a rescue map went from about 360 to about 600 files a second.
- `DiagnosticTool.exe --recover-files --image IMAGE --to FOLDER [--volume N] [--all | --deleted-only] [--deleted-folder NAME] [--damaged-folder NAME] [--by-type]` recovers files from an image with no window, for an agent: it opens the image read-only, lists the volume (the largest when none is named, and it says so), prints a progress line every 5 seconds with the time left, and writes the report and "Recovery log.txt" into FOLDER. It exits 0 when complete, 1 when stopped (Ctrl+C stops cleanly; a rerun into the same folder finishes the rest) or incomplete, 2 for a usage or open error, with the reason on standard error. A `--disk` source is refused: a live drive belongs in the rescue window. `--help` prints the options.
- The edge check reads again, from the drive, the rescued sectors within 8 sectors (set from 1 to 64) of every area the map does not hold as rescued, compares each with the image, and reports every sector that reads differently and every one that now fails to read: a sector beside a failing one can come back wrong without an error (manual step 42, two whole copies of a damaged photo differed from it in one such sector). It says before it starts how many sectors it reads and about how long, reads only those, each once, and writes nothing to the drive, the map or the image. Its findings go to a dated text file beside the image (sector, byte, the SHA-256 of the image's bytes and of the drive's, or the read error) and a line in the event log. A drop or Stop ends it with its place kept, and started again on the same map it carries on from there. Taking a sector the drive now returns alike on two reads in a row into the image is a step of its own, logged in the event log. The place a stopped check keeps is read and removed through the image's folder as the program opened and checked it, and removed, through the same ending step, only once the findings file and the event log line are written; a sector range that would run past the top of the address space is left out. The place is taken only by a check of the same map, distance and sector size, so one read in 4096-byte sectors starts afresh from a place kept in 512-byte sectors; a check with nothing to read, or whose image cannot be opened, ends through the same step, its event log line saved.
- A second launch with `--recovery --disk N` or `--recovery --image PATH` hands its arguments to the recovery copy that is running, which opens that source in a window of its own (the same source again only raises its window) and brings it forward, in place of only raising the window. The running copy ends when the last recovery window closes. A command line is taken whole: a second source, a repeated or unknown argument, or a change record that is not this program's is refused with the reason, in place of the rest being ignored. A flag's value is checked as a value of its kind: another flag or nothing in its place, a disk that is not a number and an empty image path are refused.
- Recover deleted or lost files writes each file's row to "Recovery log.txt" in the destination as the file ends, so a run cut short leaves a list of what it finished. A run into a folder that holds an earlier run of the same files keeps each file the earlier run left whole (named whole in its log, or the same as the item byte for byte), finishes a file its log names as cut short from where it ends, and writes no second copy named " (2)"; a file there that holds anything else is never written on. A picture cut short by Stop is no longer named "(partial)" or given a preview; that is for pictures written in full with parts missing.
- Recovered files are made durable on the destination together, every 2 seconds, 256 MB or 1,024 files and at the end, with one flush of the destination's volume where the program runs as administrator; a file is entered whole, in the log and the report, only after a flush that covers it.
- A recovery run again into a folder keeps a file an earlier run left only when it is byte for byte what this run writes for the item now, from the source read again with zeros where it cannot be read now, and only where this run puts the item: its folder as this run lays it out, with the deleted, damaged and by-type folders, under the item's name or "name (2)" and so on, or for a damaged picture "name (partial)", "name (2) (partial)" and so on. What an earlier log says could not be read plays no part; a kept file's condition and unreadable parts are this run's. A file shorter than the item is finished only when the earlier run's log names it as that item's copy cut short; one the log does not name may be anyone's and is never written on. The file is reached through the destination's checked folder handles, never by its path. A file that is anything else is left as it is and the item copied again. A damaged file moved into the damaged folder or renamed "(partial)" takes the item's own name there, numbered only when that is taken.
- A file is entered whole only when it holds its whole size and a flush covered the handle it was written through, and the report only after a flush of its own; a report whose flush fails is incomplete. A record whose data is shorter than its file is written to the file's size with the rest as zeros, and the file is damaged. A run that a damaged record places past where any source reaches is unreadable, never a read somewhere else.
- A damaged file that cannot be moved into the damaged folder, or a damaged picture that cannot be renamed "(partial)", stays where it is, and its row in the report and the log names that place and says why; a built-in preview found and not saved says why.
- A read of a range that ends at the top of the address space is aligned to the source's sectors and read without wrapping, on every read path; a range that runs past the top is not read whole. A read lists the bytes it could not read by their position in the bytes it returns, so bytes past the end of the source or past the top of the address space are listed too, never returned as zeros that look read. A file system's listing places only bytes inside the volume, and the rest of a stretch, however long, is missing and recovered as zeros with the file damaged. A place or length read from a file system's own records is added or multiplied only with a check, in the NTFS, FAT and exFAT readers, the search for volumes and the reader under them, never held at the top of the address space: one that would run past it is damage, its bytes unreadable, never a read that wraps, a short read taken as whole, or a place a later step brings back into range. An NTFS map whose cluster number overflows ends there, so the rest of the file is missing and nothing after it is read from the volume, and a boot sector whose volume size does not fit is no volume, never one cut to the whole source.
- A folder whose clusters run past the end of the source, or whose chain breaks, is listed with what could be read, and on FAT and exFAT alike the listing says how many folders could not be read in full. A folder is read in full only when every byte it declares was read and the walk of its chain read the chain's end-of-chain marker: one cut at the most this tool reads of a folder (2 MiB on FAT, 32 MiB on exFAT), an exFAT folder whose last cluster's table entry points onward or could not be read, an exFAT root whose chain ends on a table entry that could not be read, and a deleted FAT folder that ends before its entries' end marker are said not to be. A folder is read a cluster at a time, so on a drive a bad sector costs only its own cluster, and the entries of every cluster read are listed, also those after a cluster that could not be read or that lies outside the volume, in a deleted FAT folder too; a cluster not read is never taken for entries or their end. An exFAT file whose chain's last table entry is neither its end-of-chain marker nor a next cluster is damaged, as on FAT; on both, a file or folder in use whose chain breaks keeps the clusters its walk took, and only the rest is missing, never guessed to follow on. The free clusters a deleted FAT folder may run on into are counted against the scan's limits, as a chain is. An NTFS file table whose map puts part of it outside the volume, or whose attribute list or the records it names cannot be read, says the files described there are not listed; a file whose attribute list cannot be read in full, is longer than the 1 MiB read of it, or has a runlist that ends without its zero header, is damaged.
- Files are read in order of their first byte on the source, so the source is read forwards; the report lists them in the order chosen.
- Deleted files can go under a folder of their own, and files that end damaged under another with the built-in previews of damaged pictures, each keeping its folders, in place of "(partial)" beside the whole files; the recover window and the command line both offer it.
- The source's top-level `$RECYCLE.BIN` is written as "Recycle Bin (from the drive)", which Explorer shows, and files under its System Volume Information are left out, neither failures nor rows; the report counts them.
- The recovery measures its pace over the files written lately, fitted as time per file and time per byte, and gives the time left for the files and bytes that remain.

## 1.0.0-rc.7, 2026-11-10

### Data recovery

- A drive that drops leaves a hang zone around the place it hung: the damaged area the map shows there, failed blocks less than 16 MiB apart taken as one area, and in copying, which has nothing mapped ahead, also the first skip ahead of the read. Nothing doubles, so damaged areas apart from each other keep zones of their own. The rescue changes the status of nothing it did not read: only the read that dropped counts as failed, as any failed read does. Each phase reads everything outside the zones first, then each zone from the side away from where the drive hung, a stretch between two hangs from its middle outwards, and the places it hung last. A zone takes at most two hangs in a phase; what it is left with keeps its status, the end of the run says how much, and Fill the gaps reads it. Each new phase sizes the zones afresh to the damaged areas around the places the drive hung.
- Resume keeps the zones while the app stays open, and after the app is closed rebuilds them from the places the rescue's event log says the drive hung, around each the damaged area the map shows. A retry pass or Fill the gaps that drops goes on past the damaged area it dropped in, and past the first skip where it was reading untried bytes, in place of a skip that doubled.
- The rescue window shows the map as rows of equal blocks, each the color of what most of its part of the drive is, with the block being read marked, in place of the bar. The amounts above it use the legend's names and colors, each with its dot.

## 1.0.0-rc.6, 2026-11-09

### Data recovery

- A drive that drops is not read again where it hung in the same run. The read that dropped counts as a failed read of its length, as any failed read does: longer than a sector it goes to trimming, one sector is held as bad for a retry pass. Copying's last pass reads what drops left unread backwards from the far end of each area, and each phase hands a stretch it skipped for a drop on to the next.
- Resume keeps the drop skip, and copying's backward reading, of the map the run saved, while the app stays open; another map at the same path starts afresh.
- A drive back after a drop that does not yet give its own serial number is asked again for 20 seconds before the run stops for the technician, and every drive found has the whole 20 seconds; the message says which side lacks the serial number. Stop pressed while the drives are being looked through ends the wait.
- Wherever a map names the drive's own serial number, that serial decides: a drive with another one is refused, a changed size or sector size is refused first, and a drive that gives none now, or whose sector size is not known on both sides, is the technician's to confirm at Start. A drive serial is taken from the map only once the technician confirmed it.
- The block map strip shows what most of each part of the drive is: green rescued, orange rescued with some failed blocks, violet failed and still to be read again, red bad, gray not read yet, with a white mark where it is reading and a legend of colored dots.

## 1.0.0-rc.5, 2026-11-09

### Data recovery

- A rescue whose drive stops answering pauses with nothing marked: every failed or short read asks the drive whether it is still there before the area is called bad, and a drive that does not answer is waited for. The run saves its map, skips 1 GiB past the place (doubled within a zone, at most 5 % of the drive), looks for the drive every 3 s, and carries on with it under whatever disk number it comes back as. Only a drive with the same serial number of its own, size and sector size is carried on with by itself; one without its own serial number ends the run, and Resume asks the technician to confirm it. Fill the gaps does the same.
- The heat pause reads the drive's temperature once a minute and pauses the rescue at 38 C, carrying on by itself at 30 C or below or at once on Resume now; both temperatures are set in the window, and it can be turned off. The error pause stops a rescue when the drive's reallocated and pending sector counts grow by 1000 or more in 30 minutes, or suddenly faster; it can be set or turned off.
- A rescue writes an event log beside the image ("name.events.jsonl"): one JSON line for each start, pass, pause, resume, drop, return, health reading, read error, stop and end, and the progress every 30 s, with the run's state and figures on each line. It can be read while the rescue runs.
- The health log keeps asking a drive that stopped answering, writes a row for every reading that changes the run's state, and leaves out the heat pause's extra readings that change nothing.
- Another program reading the map (a virus scanner, an indexer) no longer ends a rescue: a save it refuses leaves the last saved map, the rescue carries on and saves again, and only a hold of 10 minutes ends the run, saying so.
- Fill the gaps counts a pass that was cut short in its result.
- The rescue window no longer flickers while it works.

## 1.0.0-rc.4, 2026-11-09

### Data recovery

- A drive behind a USB-to-SATA adapter has its SMART attributes read and its read limit set through the adapter's SCSI/ATA Translation (ATA PASS-THROUGH (16)), so a failing USB drive gives up on a bad sector as a SATA drive does instead of retrying until the adapter drops it. An adapter that refuses the 16-byte command block (ILLEGAL REQUEST, invalid operation code or field) or answers a read with zeros is sent ATA PASS-THROUGH (12), which some older adapters take instead; the form the drive answered through goes first after that, and the other is still tried when the adapter refuses it. An adapter that passes neither is named with both answers: "this USB adapter does not pass SMART commands (...)".
- A rescue image's map also names the drive's own model and serial number from IDENTIFY and the sector size, as comment lines GNU ddrescue ignores. An image started with the drive in its USB enclosure resumes once the drive is on a SATA port, and back, when the drive's own serial number and the size match; the image is found in the folder under the name it was given. A drive with another serial number of its own is refused, and so is the same drive reporting another size or sector size through the other connection, saying so. The map also says whether it is of the whole disk or of a volume at its byte offset, and the whole drive's size, and resumes only on that same part of the drive; an older map read for a volume asks the technician first. When the folder cannot be searched for the moved drive's image (more than 256 images with maps, or a map that cannot be read or understood), the rescue says so, names the folder and starts no new image. Maps without the new lines resume as before.
- Write image to a replacement drive also refuses the drive an image was made from by the drive's own serial number, read from each candidate with IDENTIFY, so the drive is refused on a SATA port or in another enclosure. A USB drive of the source drive's size (the whole drive's, for an image of a volume) whose own serial number cannot be read is refused too: it cannot be ruled out as the source behind another adapter, and the reason says to connect it through SATA or an adapter that passes ATA commands.
- Drive wear and errors counts a USB drive whose SMART data was read; one whose adapter does not pass it is listed and not counted as missing, as before.

## 1.0.0-rc.3, 2026-11-07

### Data recovery

- Rescue image reads photos first: the drive's file records are read through the rescue itself, then the areas of photo and video files, then the rest. It asks an ATA drive to give up on a bad sector after 1.5 s (10 s for retries), only once the drive at that disk number shows the serial number of the drive being read, and puts the drive's own setting back at the end, also after a command that got no answer in time. A failed sector is read again only in the retry passes chosen before Start (0 to 3, 1 by default): the first reads bad areas once more from their far end. It keeps a health log beside the image.
- Fill the gaps reads the areas a rescue image could not read again, in 1 to 5 passes the technician starts, each sector once per pass with a rest between passes, and stops when the drive's error counts rise.
- A recovered file whose record on the volume is damaged is reported damaged, never read in full, and an NTFS file whose map holds less than its size keeps that size with the rest written as zeros, in Recover deleted or lost files, Rescue copy of files and Copy the customer's files.
- A rescue image is read with the GNU ddrescue map beside it: a file over an area the map does not mark rescued is recovered as damaged with that area as zeros, not as whole. An image without a usable map says its unread areas are unknown.
- A picture recovered with parts missing is named "name (partial)" and its built-in preview (EXIF thumbnail, Multi-Picture preview, or a raw file's preview) is saved beside it as "name (preview).jpg"; the report says how much is missing and where.
- Save Explorer thumbnails writes the images in Windows Explorer's thumbnail caches on the volume, deleted caches included, to a "Thumbnails <date>" folder with a report.
- Open an image as a drive attaches a rescue image read-only so Explorer can browse its volumes, and detaches it when the window closes. Repair on a copy rebuilds a lost partition table or runs chkdsk on a differencing copy over the image, never on the image or the drive.
- Unlock a BitLocker drive unlocks a BitLocker volume on the drive or on an attached image with its 48-digit recovery key, and locks it again when the window closes. Find the key looks for a saved "BitLocker Recovery Key" file on this PC's drives, then offers to read the key from the customer's Microsoft account after the customer signs in; the key is used without being shown.
- Copy the customer's files finds Windows on the drive or image and copies each person's documents, photos, browser bookmarks and settings, Outlook files and Sticky Notes to another drive, with a handover report that gives the Windows product key and the saved Wi-Fi networks. Saved passwords are not copied, and the report says how the customer gets them back.
- Check recovered files sorts every file in a folder into good, damaged or not checked by its contents, with a reason for each and a report in the folder. Rescue copy of files, Recover deleted or lost files and Find files by type offer it on their output.
- Write image to a replacement drive writes a rescue image to a new drive after the technician types the last four characters of its serial number, refusing the drive the image came from and the disks holding the image, Windows, the program or a page file, and reads every chunk back after writing it.
- The recovery windows fit their content: lists get the room their rows need, a window grows and shrinks with what it shows until the technician resizes it, and no band is left empty. Rows that were cut short with an ellipsis (Write image's disks, Copy the customer's files' lines, crash dump items) wrap instead.
- A disabled button of every style is plainly dimmer than an enabled one, and each window uses one button style for its actions. Each empty list says in muted text what will appear in it. The BitLocker key field is labeled and gives the key's form.
- Check recovered files states each count in agreement with its number ("1 stream ends", "both files").
- A recovery window that ends while it has changed something (a drive's read limit, an attached image, a BitLocker lock) records the change before making it, and the next start puts back only what is still exactly as the tool left it and says the rest. Every blocking call that changes something has a time limit and keeps what it needs to undo the change until the call has ended.

### Other

- CPU and memory opens a processor and memory window. Processor, Memory and Board tabs give the processor's name, family, model and stepping, cores and threads (performance and efficient cores on a hybrid processor), caches, clocks and instruction sets, each memory module's slot, size, type, speeds, maker, part number, serial number, ranks and voltage with the channels in use, and the board and BIOS; Copy details puts them on the clipboard, and the report's hardware section carries them without serial numbers. CPU graph and Memory graph draw processor use (one graph or one per processor), the clock, memory in use and its split into in use, modified, standby and free, over 60 seconds, 5 or 30 minutes, with Pause and the value under the pointer.
- Restart and crash settings and Crash dump readiness open a crash dump window: whether the next crash leaves a dump, item by item, and with administrator rights Set up (Microsoft's default automatic memory dump, keeping the memory dump when space is low, and application dumps in `%ProgramData%\DiagnosticTool\CrashDumps`, or the technician's choices) and Put back, which restores exactly what was there. Every change is listed in the findings report.
- The hardware inventory may take 30 seconds, locally and over remote support, instead of the shared 12. On an older PC it timed out: it took 5.7 to 8.3 s on a 2014 Xeon VM, against 2.4 s on a current desktop, and went past 12 s under load.
- CI runs fmt, clippy and the tests on a Windows 11 runner.

## 1.0.0-rc.2, 2026-11-06

### Data recovery

- The drive window has a Recovery button. It opens a recovery window for the selected drive after one Windows administrator prompt, in a separate copy of the program; nothing else runs elevated. The drive being recovered is opened for reading only, and no output is accepted on it.
- Rescue image copies the whole drive to an image file on another drive, easy areas first, then the edges of failed areas, then what is left sector by sector, with optional retry passes. It keeps a GNU ddrescue mapfile that names the drive, can stop and resume at any point, flushes the image before each map save, shows a map strip of rescued, bad and untried areas, and pauses when the drive's error counts climb or it reaches its critical temperature.
- Rescue copy of files copies chosen folders to another drive, readable parts first, with unreadable parts as zeros or the damaged files left out, keeping folders and times, never following links, and writing a log that lists every file made and its state.
- Recover deleted or lost files reads NTFS, FAT and exFAT volumes and searches for lost partitions by their boot sectors, lists files in use and deleted with their folders, sizes, times and state (intact, partly overwritten, at risk, may be overwritten, overwritten, damaged by read errors), and recovers chosen files to another drive with a report.
- Find files by type searches the whole drive or image for JPEG, PNG, GIF, BMP, PDF, ZIP and Office documents, MP4 and MOV, AVI, WAV and WebP, SQLite, 7z and RAR files by their contents, and recovers chosen ones with a report.
- Every output is checked through its own handle and made relative to checked folder handles, so a junction or a changed mount point cannot carry a write to the drive being recovered. Reports and logs say on their last line that they are complete.

### Interface

- A button whose caption is too long for it loses the middle of the caption, so a long folder keeps its drive and its last folder.

## 1.0.0-rc.1, 2026-11-06

### Interface

- The four event rows open an event viewer with that row's events, filters by level, range and text, each event's full message with Copy details and Search the web, and a draggable bar between the list and the details.
- Drive health status and Drive wear and errors open a drive window: a drive list with grades, the selected drive's health verdict and figures, the full NVMe or SMART table, partitions, link, TRIM and self-test log, a speed test with sector-by-sector read-back, and a read check of every readable file.
- Result rows that have a tool open it when clicked, shown by a chevron and a hand pointer. Windows drive space opens a drive space window: the Windows drive's folders and files largest first with bars, folders opened by clicking, the drive's largest files (clicking one shows it in Explorer), Open in Explorer, Measure again, and Clean up, which removes temporary files unchanged for 7 days and empties the Recycle Bin after a confirmation that names both and their sizes.
- An Update button with a download arrow appears under Close when a newer signed release is published. It downloads the program, checks it against the signed manifest, replaces the running copy and restarts. Release manifests are signed with a key held off the build machine.
- Open report and Show in folder say why when they cannot work: the report was moved or deleted, no app opens PDF files, or Windows refused. Show in folder opens the folder when the report is gone. Before, both buttons did nothing.
- Hardware at a glance shows its values as selectable text, so a model number can be highlighted and copied, and a Copy all button puts the whole list on the clipboard.
- The user is no longer asked to approve repair batches: asking the technician for help and choosing Start authorize the work, the start screen is shorter with one Start button, the debug Repair preview is gone, and the report says "No repair was run in this session."

### Checks

- Rows have three results: green when nothing was found, amber for problems worth a look, and a red exclamation for serious faults. Recent system events no longer shows a green check beside errors: any known kind or any error flags it, and serious kinds turn it red. App crashes, Service failures and Hardware and driver events flag on any event in 7 days instead of only recent or repeated ones. One unclean restart is red in Crash dump readiness, and an unhealthy drive is red in Drive health status and Drive wear and errors. The report lists serious results first, each starting "Serious:".
- Recent system events reads 7 days of System and Application events through the Windows Event Log API instead of a 24-hour PowerShell sample. Events are grouped by source and event id, routine kinds such as DistributedCOM 10016 are hidden and counted, and the rest are ranked by known significance and recency. The row names the most significant known kind, and the report lists the top ten kinds with their meaning, count and first and last times.

- App crashes, Service failures and Hardware and driver events read 7 days through the event engine instead of 24-hour PowerShell samples, and their scripts are gone. App crashes counts crashes and hangs, names the most frequent faulting app with its module and exception code, and gives the newest and first times. Service failures counts events per service and names the most frequent. Hardware and driver events reads WHEA, drive, file system, graphics driver and driver load events one narrow query at a time. Each flags what happened in the past 24 hours or recurs 3 or more times in 7 days (any serious kind for hardware), and the report detail states the rule. The event engine gains `read_events_with_data`, `Drive removed` (disk 157) and `Driver failed to load` (Kernel-PnP 219) as known kinds.
- Windows drive space is read in-process and is flagged under 20 GiB or under 5 % free.
- Two new checks: Drive wear and errors (each drive's NVMe health log, SATA SMART where allowed, and Windows' failure prediction; the worst drive by endurance used, media errors, critical warnings or a failure prediction) and Crash dump readiness (30 days of stop events, unclean restarts and crash dump setup failures).

### Toolkit

- `toolkit <tool>` runs read-only tools for fixing from a console: `events` (the event engine by log, source, event id, level and time range, with one kind's newest message, redacted), `timeline` (changes and failures by day), `crashes` (stop codes and drivers from event 1001 and dump headers), `drives` (NVMe and SMART health), `startup` (what starts with Windows, with signers), `network` (adapters, gateway, DNS, proxy, hosts file, Wi-Fi), `perf` (a timed per-process sample), `battery` (wear) and `space` (largest folders and cleanup candidates).
- `toolkit hash --path PATH` gives a file's SHA-256 or SHA-1, size, times and Authenticode signature (embedded or catalog, the signer, and why a signature is not valid), refusing files over 4 GiB; `toolkit drivers [--all]` lists third-party driver packages with provider, class, version, date and signer, the present devices that report a problem code with its meaning, and the count of devices not present that still hold a driver; `toolkit updates [--days N]` reports when Windows Update last searched and installed, the updates installed and the failures in the range with their error codes explained, a pending restart, the Update and BITS services, and the client's events 20, 25, 31 and 34. Each has text and `--json` output.
- The event engine reads up to 365 days back.
- Every toolkit tool gives its readings as JSON with `--json`, built from the same interpretation as the text: snake_case fields, times as RFC 3339 UTC, sizes in bytes, unavailable readings with their reason, and any limit that cut a result short.
- `timeline --days` accepts up to 365.
- `startup` lists flagged entries and counts the rest per section; `--list` adds the other entries not signed by Microsoft and `--all` adds the Microsoft-signed ones.
- `network` counts the hosts file's names and prints only those under well-known domains or pointed at a public address.
- Redaction no longer fails on a word that ends in a non-ASCII character.

## 1.0.0-rc.1

The first release candidate, built from the prototype.

### Interface

- The consent dialog, status window and hardware view are redrawn in a dark zinc style with rounded cards, anti-aliased shapes and Segoe UI Variable.
- The status window shows each check with its state and result, a progress bar, the time left in the session, and Pause, Stop and View hardware.
- When the report is saved the window offers Open report, Show in folder and Close, and shows the file name and folder.
- The consent dialog says the tool finds problems so the technician can fix them, and that nothing changes until the user approves a fix.
- The window scales per monitor, follows Windows high-contrast colors, and shows focus rings once the keyboard is used.
- A second launch brings the running window forward.
- Closing the window stops the session and saves the report first.

### Checks

- Eleven read-only checks run from one ordered registry, each ending as found, unavailable with a reason, or not run.
- PowerShell is started by its absolute System32 path, suspended until it is inside the job, at below-normal priority.

### Report

- The PDF is dated in local time, names the version, leads with flagged results, lists checks that could not run and why, and says what the results cannot tell.
- Hardware collection time and memory modules read in plain words.
- The hardware inventory lists every physical display adapter with its video memory and driver, marks an adapter Windows knows but cannot see now as inactive, and never lists the Remote Desktop adapter.
- A new report never overwrites an earlier one.

### Reliability

- A panic or a native fault writes a crash note beside the reports and tells the user where it is.
- Empty text no longer crashes the window when a session finishes.

### Build

- The package is `diagnostic-tool` and the executable is `DiagnosticTool.exe`.
- The C runtime is linked statically and imports resolve from System32 only.
- The exe embeds a PerMonitorV2 manifest, a version resource and an icon.
- `cargo xtask dist` builds a release with checksums and refuses one that contains builder paths; `cargo xtask repro` checks that two builds match.
