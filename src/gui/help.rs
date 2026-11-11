//! Help for each window, as data: what the window does, the steps to use it, what to watch
//! for, what needs the technician's judgment, and what its colors mean. A page names its
//! topic with `Page::help_key`, and the tool window shows that topic in the pane its "?"
//! button opens: detailed information about the application and its functions, the steps for
//! the part of the app that is open, what to watch out for and what requires judgment.

/// One window's help. Every window's topic has all four of about, steps, watch and judgment.
pub struct Topic {
    pub title: &'static str,
    pub about: &'static str,
    pub steps: &'static [&'static str],
    pub watch: &'static [&'static str],
    pub judgment: &'static [&'static str],
    /// What the window's colors mean; empty when it has none of its own.
    pub colors: &'static [&'static str],
}

pub const HUB: &str = "hub";
pub const RECOVERY_DISK: &str = "recovery-disk";
pub const RECOVERY_IMAGE: &str = "recovery-image";
pub const RESCUE_IMAGE: &str = "rescue-image";
pub const RESCUE_COPY: &str = "rescue-copy";
pub const IMAGE_AS_DRIVE: &str = "image-as-drive";
pub const BITLOCKER: &str = "bitlocker";
pub const CUSTOMER_FILES: &str = "customer-files";
pub const RECOVER_FILES: &str = "recover-files";
pub const FILES_BY_TYPE: &str = "files-by-type";
pub const CHECK_FILES: &str = "check-files";
pub const WRITE_IMAGE: &str = "write-image";
pub const DRIVE_HEALTH: &str = "drive-health";
pub const DRIVE_SPACE: &str = "drive-space";
pub const CPU_MEMORY: &str = "cpu-memory";
pub const CRASH_DUMPS: &str = "crash-dumps";
pub const EVENTS: &str = "events";
pub const INSPECT: &str = "inspect";

/// What the condition strip's colors mean, in every window that shows it.
const STRIP_COLORS: &str = "In the drive's condition strip: green is fine, yellow needs watching, red is past the rescue's limits (at the heat pause, uncorrectable sectors, or error counts rising by the error pause's limit in 30 minutes), and gray is not known yet.";

const TOPICS: &[(&str, Topic)] = &[
    (
        HUB,
        Topic {
            title: "The Diagnostic Tool",
            about: "A tool for finding out what is wrong with a PC and fixing it. It opens by running a set of read-only checks for five minutes, one after another, and ends with a findings report saved in Documents. Each check is a row; a row that has a tool of its own opens it when clicked.",
            steps: &[
                "Leave the checks to run; the badge, the progress bar and the time left show where it is. Pause holds the next check until you press Resume, and Stop ends the session at once.",
                "Read each row: its color says whether the check found nothing, something to look at or something serious, and its words say what it found.",
                "Click a row with a tool behind it to dig in: drive space, recent events, drive health, crash dump readiness, or CPU and memory. The tool opens in its own window with its own help.",
                "View hardware lists what Windows reports for this PC, once the inventory check has finished.",
                "When the session ends the report saves itself. Open report and Show in folder find it; if it could not be saved, Save report as picks another folder.",
                "To work on a drive that is failing, open the drive health tool from its row and choose Recovery there.",
            ],
            watch: &[
                "The checks only read. Nothing on this PC is changed until a tool is used and its own prompt is accepted.",
                "Closing the window the first time stops the session and saves the report; the window closes once the report exists.",
                "A row that says Unavailable could not run; it is not the same as clear.",
                "The message under the list shows why a report did not open or save; read it before trying again.",
                "Update to a new version is offered only once the report is saved.",
            ],
            judgment: &[
                "Which finding to dig into first: serious rows before flagged ones, and a failing drive before anything that depends on it.",
                "Whether a flagged row matters: a full drive or an old crash may be known and harmless, while the same finding beside others may point to one cause.",
                "When the five minutes are enough: Stop is right once the rows that matter have finished, and a later session can run them again.",
            ],
            colors: &[
                "Green is fine, yellow is flagged, red is serious, and gray is waiting, not run or unavailable.",
            ],
        },
    ),
    (
        RECOVERY_DISK,
        Topic {
            title: "Data recovery",
            about: "The starting point for one drive: its health, the advice to image a failing drive first, and every recovery tool. Nothing here writes to this drive, and every copy goes to a different drive.",
            steps: &[
                "Read the health badge and the condition strip. A drive with reallocated, pending or uncorrectable sectors is failing.",
                "For a failing drive, start with Rescue image to copy it once into an image file on another drive.",
                "When only a few folders matter and the drive still mostly reads, Rescue copy of files is quicker.",
                "Once an image exists, choose it under File recovery reads from, so the recover tools read the image instead of the drive.",
                "Get the files out with Copy the customer's files, Recover deleted or lost files, or Find files by type, then Check recovered files.",
                "To give the customer a working drive, Write image to a replacement drive.",
            ],
            watch: &[
                "Every read wears a failing drive further. Read it once into an image and work from the image.",
                "The drive's figures in the strip come from the reading made when this window opened, and from a running rescue; the line under the strip says when.",
                "Rescue image and Write image need this window's administrator rights; without them they stay off.",
            ],
            judgment: &[
                "Rescue image or Rescue copy: imaging reads everything once and keeps every option open; a copy is quicker but reads the drive again for each later need.",
                "Whether the drive is worth reading at all: clicking, a drive that will not spin up, or counts rising fast all argue for imaging at once or stopping.",
            ],
            colors: &[STRIP_COLORS],
        },
    ),
    (
        RECOVERY_IMAGE,
        Topic {
            title: "Data recovery from an image",
            about: "The starting point for an image file made earlier: the failing drive is not touched, so its tools can run as often as needed.",
            steps: &[
                "Open the image as a drive to browse it in Explorer, unlock BitLocker on it, or repair a copy of it.",
                "Copy the customer's files, Recover deleted or lost files, or Find files by type from the image.",
                "Check recovered files on the folder they went to.",
                "Write image to a replacement drive to give the customer a drive that holds what the old one did.",
            ],
            watch: &[
                "Parts the rescue could not read are zeros in the image; files over them come out damaged.",
                "Copies always go to a folder on another drive than the one holding the image.",
            ],
            judgment: &[
                "Whether the image is complete enough: a rescue with purple left may still give more if the drive is read again; Fill the gaps does that from the Rescue image window.",
            ],
            colors: &[],
        },
    ),
    (
        RESCUE_IMAGE,
        Topic {
            title: "Rescue image",
            about: "Copies a failing drive into an image file on another drive, with a map beside it, so files are recovered from the image and the drive is read as little as possible. Stop keeps the map, and Start again resumes from it, here or with GNU ddrescue.",
            steps: &[
                "Choose where to save: a folder on a different, healthy drive with at least the failing drive's size free.",
                "Set the table: retry passes, Photos first, Fill the gaps' passes and rest, and the heat and error pauses. Click a value to change it; they are fixed while a run goes.",
                "Start. The first pass copies the easy areas and skips anything slow; Trim, Scrape and Retry return to the skipped areas a little at a time. The steps at the top right show where it is.",
                "When it says Done, start Fill the gaps for what is still purple. It reads purple first, splitting the longest run from its middle, and leaves red while purple remains.",
                "Click a square of the map to inspect it; from there Read this block or Continue scan from here points Fill the gaps at it.",
                "Check edges reads again the rescued sectors beside every area not rescued and reports any that now read differently. It writes nothing.",
                "Recover files from the image, not the drive.",
            ],
            watch: &[
                "Heat: at the heat pause's temperature (38 C unless changed) the rescue pauses itself and carries on at the resume temperature; Resume now carries on at once. A drive that will not cool needs air or a rest.",
                "Drops: the drive leaves USB and the rescue waits with the map saved. Unplug it and plug it back in; it carries on, under a new disk number if Windows gives it one.",
                "Reallocated climbing fast while little is recovered: the drive is wearing faster than it gives data back. The error pause stops the run at its limit in 30 minutes; Resume carries on.",
                "Clicking, or a drive that no longer spins up: stop and set the drive aside.",
            ],
            judgment: &[
                "When purple remains, read it before retrying red. Purple is usually the last readable data; red has already failed several times.",
                "Whether the wear is worth it: compare the reallocated count's climb with what each pass recovers. A climb is acceptable while the passes still bring data back.",
                "Hangs usually sit two or three blocks from the start or end of a large purple run. Splitting the runs from the middle clears them faster than skipping past.",
                "When to stop: once purple is gone and passes over red recover nothing, the image is as good as this drive will give.",
            ],
            colors: &[
                "Map: green rescued, orange rescued with some sectors failed, purple failed once and to be read again, red bad after every pass, gray not read yet.",
                "A ringed square is being read now; a cyan dot marks what this run recovered.",
                STRIP_COLORS,
            ],
        },
    ),
    (
        RESCUE_COPY,
        Topic {
            title: "Rescue copy of files",
            about: "Copies chosen folders from the failing drive to a folder on another drive, readable parts first, and lists damaged and skipped files as it goes.",
            steps: &[
                "Add the folders that matter, most important first.",
                "Choose where to copy to: a folder on another drive. The drive being copied is refused.",
                "Choose what happens to damaged files: copied with zeros where they could not be read, or skipped.",
                "Start. The first pass copies what reads easily; the second reads the failed parts again.",
                "Show log lists every damaged and skipped file; Check recovered files checks the copies.",
            ],
            watch: &[
                "Each copy reads the drive again. If more than a few folders are needed, a rescue image reads it once.",
                "The condition strip: heat, drops and rising counts mean the drive is getting worse while it is read.",
            ],
            judgment: &[
                "Damaged files with zeros keep what was readable, which is often most of a photo or document; skipping keeps the copy clean. Decide by what the customer needs.",
                "When to stop and image instead: a copy that slows to a crawl or fails file after file is wearing the drive for little.",
            ],
            colors: &[STRIP_COLORS],
        },
    ),
    (
        IMAGE_AS_DRIVE,
        Topic {
            title: "Open an image as a drive",
            about: "Attaches a rescue image read-only, so Windows gives its volumes drive letters and Explorer can open them. Repairs go to a copy that holds only the changes, never to the image or the drive.",
            steps: &[
                "Choose image, then Open as a drive. An image Windows cannot attach as it is may first need storing as a plain file; the window asks.",
                "Pick a volume and Open in Explorer, or Unlock a BitLocker drive on it.",
                "If a volume will not open, Repair on a copy makes the copy to work on.",
                "On the copy: Find lost partitions, Write the partitions found to the copy, or Fix file system errors on the copy.",
                "Keep the copy to go on with it later, or Discard the copy. Closing the window detaches everything it attached.",
            ],
            watch: &[
                "Parts the rescue could not read are zeros, so a volume may open with folders or files missing or damaged.",
                "A repair changes only the copy; the image stays as the rescue made it.",
            ],
            judgment: &[
                "Whether to repair at all: copying files out of a volume that opens is safer than fixing it. Repair only what will not open.",
                "Which partitions found to write: compare their sizes and positions with what the drive held before.",
            ],
            colors: &[],
        },
    ),
    (
        BITLOCKER,
        Topic {
            title: "Unlock a BitLocker drive",
            about: "Unlocks a BitLocker volume with its 48-digit recovery key, typed or looked up, and opens the recovery tools on the unlocked volume. Lock again, or closing the window, locks what this window unlocked.",
            steps: &[
                "Pick the locked volume. Its key ID is shown as Windows' recovery screen shows it.",
                "Type the recovery key, or Find the key: saved key files on this PC first, then the customer's Microsoft account.",
                "Unlock, then Open in Explorer, Recover deleted or lost files, or Find files by type.",
                "Lock again when done.",
            ],
            watch: &[
                "Unlocking puts the file system in use, and Windows can write to it. On a failing drive, image it first and unlock the image instead.",
                "The key never appears in the window, the logs or the report.",
            ],
            judgment: &[
                "Whether to unlock the drive itself or wait for an image: a drive that still reads well can be unlocked; one with rising counts or drops should be imaged first.",
            ],
            colors: &[STRIP_COLORS],
        },
    ),
    (
        CUSTOMER_FILES,
        Topic {
            title: "Copy the customer's files",
            about: "Copies each person's documents, photos, bookmarks, Outlook files and Sticky Notes from Windows on the drive or image to another drive, with a handover report.",
            steps: &[
                "Wait while the window finds Windows and the people on the drive; the list shows each person and their files.",
                "Choose where to copy to: a folder on another drive.",
                "Choose whether damaged files are copied with zeros or skipped.",
                "Start: the confirmation lists each person with their files and size, and where they go.",
                "Show report gives the handover report, with what did not carry over.",
            ],
            watch: &[
                "Saved passwords and Wi-Fi passwords are not copied; the report says what does not carry over.",
                "Reading a failing drive directly wears it; copying from its image does not.",
            ],
            judgment: &[
                "Which people and folders matter to the customer, and whether damaged files with zeros are worth handing over.",
            ],
            colors: &[STRIP_COLORS],
        },
    ),
    (
        RECOVER_FILES,
        Topic {
            title: "Recover deleted or lost files",
            about: "Finds files that were deleted or whose folders are lost, on the volumes of a drive or image, and copies the chosen ones to a folder on another drive. Nothing is written to what is read.",
            steps: &[
                "Pick a volume, or Search for lost partitions, or Search every sector when the volumes are gone.",
                "Narrow the list with Deleted only and the groups; select the files to keep.",
                "Recover selected, choosing a folder on another drive. Keep folders keeps their paths.",
                "Open folder to see them, and Check recovered files to find any damaged copy.",
                "Save Explorer thumbnails keeps the small pictures Windows made, which can stand in for a photo that is gone.",
            ],
            watch: &[
                "Deleted files can be overwritten. One marked overwritten or partly overwritten is wholly or partly another file's now; one marked intact may still be damaged.",
                "A file damaged by read errors has zeros where the drive could not be read.",
                "Do not recover to the drive being read, and do not use it in Windows meanwhile: every write can overwrite a deleted file.",
            ],
            judgment: &[
                "Damaged pictures may have good versions elsewhere on the volume: whole copies the same on every readable byte, near copies differing only beside a part never read, and other versions taken at the same moment by their capture time. The search for them sorts versions; it does not choose.",
                "A person should review the versions found before replacing anything: an edit or a smaller service copy may differ from the original, and only someone looking at them can say which the customer wants.",
            ],
            colors: &[
                "In the list: green intact, yellow partly overwritten or at risk, red overwritten or damaged by read errors, gray in use or not known.",
            ],
        },
    ),
    (
        FILES_BY_TYPE,
        Topic {
            title: "Find files by type",
            about: "Searches the raw data for photos, documents and other files by their own contents, so it works where the file system is gone; their names and folders are not known.",
            steps: &[
                "Pick the types to look for.",
                "Start. The search reads the whole drive or image from start to end.",
                "Select the files found, and Recover selected to a folder on another drive.",
                "Check recovered files to find the ones that came out damaged.",
            ],
            watch: &[
                "A file in pieces across the drive may come out mixed with another file's data.",
                "On a failing drive this reads everything again; search the image instead.",
            ],
            judgment: &[
                "Whether this is needed: Recover deleted or lost files keeps names and folders, so try it first.",
            ],
            colors: &[],
        },
    ),
    (
        CHECK_FILES,
        Topic {
            title: "Check recovered files",
            about: "Checks every file in a folder of recovered or copied files by its contents, sorts each into good, damaged or not checked, damaged first with the reason, and writes File check report.txt into the folder.",
            steps: &[
                "Choose the folder the files went to.",
                "Check.",
                "Open report, or Show file for one in the list.",
            ],
            watch: &[
                "Not checked means its type is not one the check reads, not that it is good.",
            ],
            judgment: &[
                "Which damaged files matter enough to look for elsewhere: in another copy, a backup, or the good versions of a picture.",
            ],
            colors: &[],
        },
    ),
    (
        WRITE_IMAGE,
        Topic {
            title: "Write image to a replacement drive",
            about: "Writes a rescue image to a new drive, erasing it first, so it holds what the failing drive held. The drive is read back and checked after writing.",
            steps: &[
                "Choose image.",
                "Pick the replacement drive from the list; Refresh list after plugging one in.",
                "Type the last four characters of its serial number to confirm it.",
                "Choose whether to grow the last partition to fill a larger drive.",
                "Write to this drive, and confirm. Show report opens the report saved beside the image.",
            ],
            watch: &[
                "Everything on the chosen drive is erased. This cannot be undone.",
                "Parts the rescue could not read are written as zeros and listed in the report.",
                "The drive the image came from, the drive holding the image, and the drives Windows and this program run from are never offered.",
            ],
            judgment: &[
                "Whether the image is complete enough to hand over as a working drive, or whether the customer is better served by their files copied to a fresh install.",
            ],
            colors: &[],
        },
    ),
    (
        DRIVE_HEALTH,
        Topic {
            title: "Drive health",
            about: "Each physical drive's identity, link, partitions, health verdict and figures, with the full health table, a speed test and a read check. It reads as the current user and changes nothing on the drive.",
            steps: &[
                "Pick the drive in the list at the top. The verdict and the figures under it follow the drive picked.",
                "On Details, read the verdict, then the figures and the health table. Copy details puts them on the clipboard.",
                "For a failing drive, Recovery opens the recovery window for that disk, with administrator rights for that window only.",
                "On Speed test, choose the volume and the test size, then Start speed test. It asks first, naming the file and the folder it will use.",
                "On Read check, choose the volume and Start read check. It reads every file the current user can open and lists the ones the drive could not read back.",
                "Stop ends a running test. Read again reads the drives afresh and keeps the same drive in view.",
            ],
            watch: &[
                "The speed test writes a file on the volume, twice, and deletes it; the volume needs the room it names, and other programs run slower meanwhile.",
                "The result is for the volume, not the disk, when the volume also lies on another disk; the confirmation says so.",
                "The read check reads without writing, but on a failing drive every read wears it further. Use Recovery and an image first.",
                "Files held online only by a cloud service are skipped, so nothing is downloaded; they are not checked.",
            ],
            judgment: &[
                "Whether a flagged or serious figure is a fault or an old, stable count: a rising count matters, a count that stays the same may not.",
                "Whether to run the read check at all on a drive that is already clicking or slow: image it instead.",
                "How to read a slow speed test: compare it with what that kind of drive should give, and run it again once other programs are idle.",
            ],
            colors: &[
                "Green is fine, yellow needs a look, red is serious, and gray is not known.",
            ],
        },
    ),
    (
        DRIVE_SPACE,
        Topic {
            title: "Drive space",
            about: "Which folders and files take the most room on the Windows drive, and a cleanup of week-old temporary files and the Recycle Bin.",
            steps: &[
                "Wait for the measuring to finish; the line under the bar counts folders as it goes. Folders and Largest files work once it is done.",
                "On Folders, double-click a folder to go in and Up to come back out. Each row shows its size and its share of the folder you are in.",
                "Largest files lists the biggest files on the whole drive with the folder each is in. Double-click one to show it in Explorer.",
                "Open in Explorer opens the folder you are in.",
                "Clean up looks for temporary files unchanged for 7 days or more and the Recycle Bin, and asks before removing anything.",
                "Measure again after a cleanup or any large change, as the figures are from the last measuring.",
            ],
            watch: &[
                "Cleanup removes for good; nothing it removes can be brought back, and the confirmation lists what and how much first.",
                "Files a program has open, read-only files and anything changed in the past week are left alone.",
                "Folders that need administrator rights are not counted, and the status line says how many; the sizes are then a minimum, as they are after a stop.",
            ],
            judgment: &[
                "Whether a large folder is safe to remove: this window only measures. Look in the folder first and ask the customer about anything personal.",
                "Whether a cleanup is wanted at all: on a drive being recovered it adds writes, and the Recycle Bin may hold what the customer has not yet looked for.",
            ],
            colors: &[],
        },
    ),
    (
        CPU_MEMORY,
        Topic {
            title: "Processor and memory",
            about: "The processor, memory and board details, read once and read again on request, and live graphs of processor use and memory in use that the window samples as it runs.",
            steps: &[
                "Processor, Memory and Board show the details read when the window opened. Copy details puts all three on the clipboard.",
                "Processor graph and Memory graph draw the live use, newest at the right. Point at the graph for the value at that moment.",
                "The range button steps the graph through the last 60 seconds, 5 minutes and 30 minutes.",
                "Per processor splits the processor graph into one trace for each logical processor; One graph puts them back together.",
                "Pause freezes the graph to look at a spike; Resume carries on. Sampling continues underneath.",
                "Read again reads the details afresh.",
            ],
            watch: &[
                "A figure shown as not read could not be read on this PC; it is not zero.",
                "The graph holds only what was sampled while the window was open, so a spike before it opened is not there.",
                "Memory graph's bar splits memory into in use, modified, standby and free. Standby is cache that is given up at once, so a small free share is not a shortage by itself.",
            ],
            judgment: &[
                "Whether use is high because of a fault or because of the work: watch for a minute with nothing running before deciding.",
                "Whether memory is short: committed close to its limit, with little available, is a shortage; a small free share alone is not.",
                "Whether a speed below the base speed is a fault: it can be power saving or heat, and needs another reading under load.",
            ],
            colors: &[],
        },
    ),
    (
        CRASH_DUMPS,
        Topic {
            title: "Crash dump readiness",
            about: "Whether Windows is set to leave a dump when it or a program crashes, item by item, and the settings to make it so, with Put back to restore what was there before. Changing settings needs administrator rights.",
            steps: &[
                "Read the items. Select one to see its values and why it reads as it does.",
                "Without administrator rights the window only reads; Change settings as administrator opens this window again with them.",
                "Choose which dumps to change (kernel, applications or both) and set each option; each button steps through its choices, and the folders open a picker.",
                "Set up lists every change it would make and what the present values are, and asks. Nothing changes until it is accepted.",
                "Restart Windows for kernel settings to take effect; this tool does not restart the PC.",
                "Put back returns each value to what it was before Set up first ran. It is off until there is something to put back.",
                "Check again reads the items afresh; Stop ends a check that is running. Copy puts the items and the last result on the clipboard.",
            ],
            watch: &[
                "A full memory dump can be as large as the PC's memory and is written to the memory dump file named in the options; make sure that drive has room.",
                "Set up saves the present values first. Do not delete that file, as Put back needs it.",
                "Put back removes only folders Set up made, and only when they are empty.",
                "A dump holds what was in memory at the crash, including documents and passwords. Treat it as the customer's private data.",
            ],
            judgment: &[
                "Kernel dumps only, application dumps only, or both: choose what the fault being chased needs; fewer changes are easier to put back.",
                "Mini or full application dumps: a full dump holds everything the program had and can be very large; start with mini unless the fault needs more.",
                "How many application dumps to keep, so a crash loop does not fill the drive.",
                "Whether to change a customer's PC at all: put it back once the dump is taken.",
            ],
            colors: &[
                "Green is ready, yellow needs a change, and gray could not be read.",
            ],
        },
    ),
    (
        EVENTS,
        Topic {
            title: "Event viewer",
            about: "The events behind one row of the main window, read again from the Windows event logs with their messages, filtered by level, time range and text. The row decides which logs and kinds of event are read: recent system events, app crashes, service failures, or hardware and driver events.",
            steps: &[
                "Wait for the reading to finish; the line under the title counts events as it goes.",
                "Switch the level buttons (critical, error, warning, information) to show or hide each level.",
                "Choose the time range: 24 hours, 7 days or 30 days.",
                "Type in the search box to narrow the list to events whose text matches.",
                "Select an event to see its level, time, source, event id, log and message below the list. Drag the bar between the list and the details to give either more room.",
                "Copy details copies the selected event. Search the web looks up its source and event id.",
            ],
            watch: &[
                "Recent system events hides kinds Windows logs routinely, as the main window's check does; the line under the title says so.",
                "Search the web sends only the source and the event id, and leaves the source out when it holds a computer or account name.",
                "A message is shortened and has names, addresses and email addresses replaced before it is shown.",
                "An event with no message is one whose source did not register its text on this PC; that is not an error in the event.",
            ],
            judgment: &[
                "Whether an event is the cause or a side effect: look at what came first in time. Many warnings are routine, and serious events are marked in the details.",
                "How far back to look: a fault that began a week ago needs the 7 days range, a crash this morning does not.",
                "Whether one repeated event matters: a count that grows with the problem does, a steady background one does not.",
            ],
            colors: &[],
        },
    ),
    (
        INSPECT,
        Topic {
            title: "Inspect the rescue map",
            about: "One square of the rescue window's map drawn as its own grid, in the same colors, and any square of that grid opened the same way, down to single sectors. It follows the rescue window's map as that window last had it, so it follows a run.",
            steps: &[
                "Point at a square to read its bytes and how much of it is rescued, to be read again, bad or not read yet.",
                "Click a square to look inside it. Back returns one level; the arrows at either side step to the neighboring block.",
                "Follow reading keeps the grid on the area the run is reading. Moving by hand turns it off.",
                "Right-click a square to pick it; right-click it again to let it go.",
                "Read this block reads the block shown, or the square picked, once more. Continue scan from here points Fill the gaps at it.",
            ],
            watch: &[
                "Read this block and Continue scan from here work only on a map that is not mid-run, or while Fill the gaps is running; otherwise they stay off.",
                "Each read of a failing drive wears it. Pick the smallest block that answers the question.",
                "The figures are the rescue window's map at the last refresh, not a fresh read of the drive.",
            ],
            judgment: &[
                "Whether a patch of bad squares is worth reading again: sectors beside rescued ones often still give, a long run of bad ones rarely does.",
                "How deep to look: a single sector's bytes tell which file or structure it falls in only with the recovery tools; use this window to aim reads, not to judge files.",
            ],
            colors: &[
                "Green rescued, orange rescued with some sectors failed, purple failed once and to be read again, red bad after every pass, gray not read yet.",
                "A ringed square is being read now; a cyan dot marks what this run recovered.",
            ],
        },
    ),
];

/// The topic of a window's key.
pub fn topic(key: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|(k, _)| *k == key).map(|(_, t)| t)
}

/// One paragraph of the help pane, in the order it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line {
    Title(&'static str),
    About(&'static str),
    Heading(&'static str),
    Step(usize, &'static str),
    Watch(&'static str),
    Judgment(&'static str),
    Color(&'static str),
}

impl Line {
    pub fn text(&self) -> String {
        match self {
            Line::Step(n, text) => format!("{n}. {text}"),
            Line::Title(t)
            | Line::About(t)
            | Line::Heading(t)
            | Line::Watch(t)
            | Line::Judgment(t)
            | Line::Color(t) => t.to_string(),
        }
    }
}

/// The topic as the pane shows it: title, what it does, then each section under its heading.
pub fn lines(topic: &Topic) -> Vec<Line> {
    let mut lines = vec![Line::Title(topic.title), Line::About(topic.about)];
    lines.push(Line::Heading("Steps"));
    lines.extend(
        topic
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| Line::Step(i + 1, s)),
    );
    lines.push(Line::Heading("Watch for"));
    lines.extend(topic.watch.iter().map(|s| Line::Watch(s)));
    lines.push(Line::Heading("Needs your judgment"));
    lines.extend(topic.judgment.iter().map(|s| Line::Judgment(s)));
    if !topic.colors.is_empty() {
        lines.push(Line::Heading("What the colors mean"));
        lines.extend(topic.colors.iter().map(|s| Line::Color(s)));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every window with help, by topic key.
    const WINDOWS: [&str; 18] = [
        HUB,
        RECOVERY_DISK,
        RECOVERY_IMAGE,
        RESCUE_IMAGE,
        RESCUE_COPY,
        IMAGE_AS_DRIVE,
        BITLOCKER,
        CUSTOMER_FILES,
        RECOVER_FILES,
        FILES_BY_TYPE,
        CHECK_FILES,
        WRITE_IMAGE,
        DRIVE_HEALTH,
        DRIVE_SPACE,
        CPU_MEMORY,
        CRASH_DUMPS,
        EVENTS,
        INSPECT,
    ];

    /// The guard: every window with help has a topic, and each says what the window does,
    /// how to use it, what to watch for and what needs judgment.
    #[test]
    fn every_window_has_its_help() {
        for key in WINDOWS {
            let topic = topic(key).unwrap_or_else(|| panic!("no help for {key}"));
            assert!(!topic.title.is_empty() && !topic.about.is_empty(), "{key}");
            assert!(!topic.steps.is_empty(), "{key} has no steps");
            assert!(!topic.watch.is_empty(), "{key} has no Watch for");
            assert!(!topic.judgment.is_empty(), "{key} has no judgment");
            for text in topic
                .steps
                .iter()
                .chain(topic.watch)
                .chain(topic.judgment)
                .chain(topic.colors)
            {
                assert!(!text.trim().is_empty(), "{key}");
            }
        }
        assert_eq!(TOPICS.len(), WINDOWS.len(), "a topic no window shows");
    }

    /// British forms that were in the app's text; none may come back.
    const BRITISH: [&str; 16] = [
        "colour",
        "behaviour",
        "centre",
        "centred",
        "grey",
        "licence",
        "organisation",
        "recognised",
        "judgement",
        "cancelled",
        "cancelling",
        "labelled",
        "normalised",
        "initialised",
        "optimised",
        "catalogued",
    ];

    /// The help and every string literal of the windows are in American spelling.
    #[test]
    fn the_help_and_the_windows_use_american_spelling() {
        for (key, topic) in TOPICS {
            for text in lines(topic).iter().map(Line::text) {
                for british in BRITISH {
                    assert!(!text.to_lowercase().contains(british), "{key}: {text}");
                }
            }
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gui");
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            // This file holds the list above.
            if path.extension().is_none_or(|e| e != "rs") || path.ends_with("help.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for line in source.lines().filter(|l| !l.trim_start().starts_with("//")) {
                // The odd pieces between quotes are the string literals.
                for text in line.split('"').skip(1).step_by(2) {
                    for british in BRITISH {
                        assert!(
                            !text.to_lowercase().contains(british),
                            "{}: {text}",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    /// The Rescue image's judgment carries the calls made on a failing drive: purple before
    /// red, wear against recovery, hangs at the runs' ends, when to stop.
    #[test]
    fn the_rescue_image_help_carries_the_judgment_calls() {
        let topic = topic(RESCUE_IMAGE).unwrap();
        let judgment = topic.judgment.join(" ");
        for said in [
            "read it before retrying red",
            "reallocated count's climb",
            "two or three blocks from the start or end",
            "Splitting the runs from the middle",
            "passes over red recover nothing",
        ] {
            assert!(judgment.contains(said), "{said}");
        }
        let lines = lines(topic);
        assert_eq!(lines[0], Line::Title("Rescue image"));
        assert!(matches!(lines[3], Line::Step(1, _)));
        assert!(lines.contains(&Line::Heading("What the colors mean")));
    }
}
