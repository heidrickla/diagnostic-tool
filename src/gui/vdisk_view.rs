//! The "Open an image as a drive" window. It drives the engines in `recovery::vdisk`
//! (`attach_image`) and `recovery::repair` (`start_repair`, `find_table`, `write_table`,
//! `chkdsk`, `end`): it builds their options, shows their events and renders their results.
//! Every guard is in the engines. Closing the window detaches everything it attached.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use diagnostics::recovery::repair::{
    self, ChkdskOptions, ChkdskResult, EndOptions, EndResult, FindOptions, NotEnded, Repair,
    RepairOptions, RepairStarted, Table, WriteTableOptions, WriteTableResult,
};
use diagnostics::recovery::vdisk::{
    self, AttachOptions, AttachResult, Attached, Event, VolumeInfo,
};
use diagnostics::tools::drives::bytes_text;
use diagnostics::ui_layout::{grid, scale};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{DT_END_ELLIPSIS, DT_LEFT, DT_SINGLELINE, DT_VCENTER, HDC};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

use crate::dialog::{Dialog, Item, Section};
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

const CHOOSE: usize = 10;
const ATTACH: usize = 11;
const EXPLORE: usize = 12;
const UNLOCK: usize = 13;
const REPAIR: usize = 14;
const FIND: usize = 15;
const WRITE_TABLE: usize = 16;
const CHKDSK: usize = 17;
const KEEP: usize = 18;
const DISCARD: usize = 19;
const CLOSE: usize = 20;
const STOP: usize = 21;
const VOLUMES: usize = 30;
const DO_PLAIN: usize = 40;
const DO_REPAIR: usize = 41;
const DO_WRITE: usize = 42;
const DO_CHKDSK: usize = 43;
const DO_DISCARD: usize = 44;
/// The most lines of chkdsk output the window shows.
const OUTPUT_LINES: usize = 2000;

/// Opens the window for `image`, or for an image chosen in it. `source_disk` is the disk
/// being recovered, which no copy may be written to.
pub fn open(owner: HWND, image: Option<PathBuf>, source_disk: Option<u32>) {
    toolwin::open(owner, "image-as-drive", move || {
        Box::new(DriveView::new(image, source_disk))
    });
}

/// What a background job hands back. Steps on the repair take it and give it back.
enum Done {
    Attached(Result<(Attached, AttachResult), String>),
    Started(Result<(Box<Repair>, RepairStarted), String>),
    Found(Result<Table, String>),
    Written(Box<Repair>, Result<WriteTableResult, String>),
    Checked(Box<Repair>, Result<ChkdskResult, String>),
    Ended(Result<EndResult, NotEnded>),
}

struct Job {
    done: mpsc::Receiver<Done>,
    events: mpsc::Receiver<Event>,
    cancel: Arc<AtomicBool>,
}

struct Controls {
    title: HWND,
    subtitle: HWND,
    about: HWND,
    choose: HWND,
    attach: HWND,
    volumes: HWND,
    explore: HWND,
    unlock: HWND,
    repair: HWND,
    repair_about: HWND,
    find: HWND,
    write_table: HWND,
    chkdsk: HWND,
    keep: HWND,
    discard: HWND,
    stop: HWND,
    output: HWND,
    notice: HWND,
    close: HWND,
}

pub struct DriveView {
    source_disk: Option<u32>,
    image: Option<PathBuf>,
    attached: Option<Attached>,
    /// The volumes of the attached image or of the copy, whichever is attached.
    volumes: Vec<VolumeInfo>,
    /// Offsets of volumes whose boot sector is BitLocker's.
    bitlocker: Vec<u64>,
    repair: Option<Repair>,
    /// The copy's disk number, kept while a step holds the repair.
    copy_disk: Option<u32>,
    table: Option<Table>,
    output: Vec<String>,
    job: Option<Job>,
    busy: String,
    notice: Option<(String, Tone)>,
    /// The folder chosen for the copy, between the question and the start.
    copy_folder: Option<PathBuf>,
    /// What the copy must not be written to, with what the person confirmed of its folder.
    copy_protected: diagnostics::recovery::dest::Protected,
    /// Confirmed in the dialog: store a sparse or compressed image plain.
    make_plain: bool,
    controls: Option<Controls>,
    area: (i32, i32, u32),
    /// The client height the content needs, from the last layout.
    natural: Option<i32>,
}

impl Drop for DriveView {
    fn drop(&mut self) {
        // A running step stops; a repair it holds is dropped with it, which keeps the copy
        // and detaches it.
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
        }
        drop(self.repair.take());
        drop(self.attached.take());
    }
}

impl DriveView {
    fn new(image: Option<PathBuf>, source_disk: Option<u32>) -> Self {
        Self {
            source_disk,
            image,
            attached: None,
            volumes: Vec::new(),
            bitlocker: Vec::new(),
            repair: None,
            copy_disk: None,
            table: None,
            output: Vec::new(),
            job: None,
            busy: String::new(),
            notice: None,
            copy_folder: None,
            copy_protected: Default::default(),
            make_plain: false,
            controls: None,
            area: (0, 0, 96),
            natural: None,
        }
    }

    fn start_job(
        &mut self,
        busy: &str,
        work: impl FnOnce(&dyn Fn(Event), &AtomicBool) -> Done + Send + 'static,
    ) {
        let (done_to, done) = mpsc::channel();
        let (event_to, events) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        thread::spawn(move || {
            let send = move |event: Event| {
                let _ = event_to.send(event);
            };
            let _ = done_to.send(work(&send, &stop));
        });
        self.job = Some(Job {
            done,
            events,
            cancel,
        });
        self.busy = busy.to_string();
        self.notice = None;
    }

    fn selected_volume(&self) -> Option<&VolumeInfo> {
        let c = self.controls.as_ref()?;
        self.volumes.get(toolwin::selected(c.volumes)?)
    }

    fn volume_rows(&self) -> Vec<String> {
        self.volumes
            .iter()
            .map(|v| {
                let locked = if self.bitlocker.contains(&v.offset) {
                    if v.file_system.is_empty() {
                        "  ·  BitLocker, locked"
                    } else {
                        "  ·  BitLocker, unlocked"
                    }
                } else {
                    ""
                };
                format!("{}{locked}", v.describe())
            })
            .collect()
    }

    fn render(&mut self) {
        let rows = self.volume_rows();
        let image_text = match &self.image {
            Some(path) => {
                let size = std::fs::metadata(path)
                    .map(|m| bytes_text(m.len()))
                    .unwrap_or_else(|_| "not readable".into());
                format!("{}, {size}", path.display())
            }
            None => "No image chosen yet.".into(),
        };
        let selected_letter = self.selected_volume().and_then(|v| v.letter());
        let selected_any = self.selected_volume().is_some();
        let busy = self.job.is_some();
        let in_repair = self.repair.is_some() || self.copy_disk.is_some();
        let Some(c) = &self.controls else {
            return;
        };
        ui::set_text(c.subtitle, &image_text);
        ui::set_text(
            c.attach,
            if self.attached.is_some() {
                "Close the drive"
            } else {
                "Open as a drive"
            },
        );
        toolwin::set_items(c.volumes, &rows, true);
        toolwin::set_empty(
            c.volumes,
            match (&self.attached, in_repair) {
                (_, true) => "The copy's volumes appear here once it is open.",
                (Some(_), false) => "Windows found no volumes on the image.",
                (None, false) => "The image's volumes appear here, with their drive letters, once it is open as a drive.",
            },
        );
        toolwin::set_empty(
            c.output,
            "What Find lost partitions and Fix file system errors report appears here.",
        );
        let ready = !busy && self.repair.is_some();
        ui::enable(c.choose, !busy && self.attached.is_none() && !in_repair);
        ui::enable(c.attach, !busy && !in_repair && self.image.is_some());
        ui::enable(c.explore, selected_letter.is_some());
        ui::enable(
            c.unlock,
            !self.bitlocker.is_empty() && (self.attached.is_some() || in_repair),
        );
        ui::enable(c.repair, !busy && !in_repair && self.image.is_some());
        ui::enable(c.find, ready);
        ui::enable(c.write_table, ready && self.table.is_some());
        ui::enable(c.chkdsk, ready && selected_any);
        ui::enable(c.keep, ready);
        ui::enable(c.discard, ready);
        ui::enable(c.stop, busy);
        ui::set_text(c.output, &self.output.join("\r\n"));
        let (notice, tone) = match (&self.notice, busy) {
            (_, true) => (self.busy.clone(), Tone::Neutral),
            (Some((text, tone)), _) => (text.clone(), *tone),
            (None, _) => (String::new(), Tone::Neutral),
        };
        ui::set_text(c.notice, &notice);
        ui::set_tone(c.notice, tone);
    }

    fn relayout(&mut self, hwnd: HWND) {
        let (w, h, dpi) = self.area;
        if w > 0 {
            self.layout(hwnd, w, h, dpi);
        }
    }

    /// Asks before storing the image plain; the engine refuses it without that answer.
    fn ask_attach(&mut self) -> Option<Ask> {
        let image = self.image.clone()?;
        if vdisk::is_differencing(&image) {
            self.attach(image);
            return None;
        }
        match vdisk::plain_needed(&image) {
            Ok(Some(needed)) if needed.fixable => Some(Ask {
                dialog: Dialog {
                    window_title: "Open as a drive".into(),
                    heading: "Store the image as a plain file?".into(),
                    intro: needed.text,
                    sections: vec![Section {
                        heading: None,
                        items: vec![
                            Item::Pair("Image".into(), image.display().to_string()),
                            Item::Pair("Takes more".into(), bytes_text(needed.more)),
                        ],
                    }],
                    accept: "Make it plain".into(),
                    decline: Some("Cancel".into()),
                    copy: None,
                },
                then: DO_PLAIN,
            }),
            _ => {
                self.attach(image);
                None
            }
        }
    }

    fn attach(&mut self, image: PathBuf) {
        let options = AttachOptions {
            image,
            make_plain: std::mem::take(&mut self.make_plain),
        };
        self.start_job("Attaching the image read-only…", move |events, cancel| {
            Done::Attached(vdisk::attach_image(&options, events, cancel))
        });
    }

    fn close_drive(&mut self) {
        self.volumes.clear();
        self.bitlocker.clear();
        if let Some(attached) = self.attached.take() {
            let image = attached.image().display().to_string();
            self.notice = Some(match attached.close() {
                Ok(()) => (
                    format!("{image} is detached and back to its own length."),
                    Tone::Neutral,
                ),
                Err(why) => (why, Tone::Warn),
            });
        }
    }

    fn ask_repair(&mut self, hwnd: HWND) -> Option<Ask> {
        let image = self.image.clone()?;
        let folder = toolwin::pick_folder(hwnd, "Choose a folder for the repaired copy")?;
        // The drive being recovered, and the drive the image was made from.
        let mut protected = self
            .source_disk
            .map(diagnostics::recovery::dest::Protected::disk)
            .unwrap_or_default()
            .join(diagnostics::recovery::output::source_disk(
                &diagnostics::recovery::SourceChoice::Image(image.clone()),
            ));
        if let Err(why) = toolwin::confirm_destination(hwnd, &folder, &mut protected) {
            self.notice = Some((format!("{why}."), Tone::Warn));
            return None;
        }
        self.copy_protected = protected;
        let copy = repair::copy_path(&image, &folder);
        self.copy_folder = Some(folder);
        Some(Ask {
            dialog: Dialog {
                window_title: "Repair on a copy".into(),
                heading: "Make a copy to repair?".into(),
                intro: "Repairs are never made on the drive or on its image. A copy is made that holds only the changes, over the image, which is only read. The copy is opened as a drive that can be written; the image's own drive closes first.".into(),
                sections: vec![Section {
                    heading: None,
                    items: vec![
                        Item::Pair("Image, only read".into(), image.display().to_string()),
                        Item::Pair("Copy".into(), copy.display().to_string()),
                    ],
                }],
                accept: "Make the copy".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_REPAIR,
        })
    }

    fn start_repair(&mut self) {
        let (Some(image), Some(folder)) = (self.image.clone(), self.copy_folder.take()) else {
            return;
        };
        self.close_drive();
        self.output.clear();
        self.table = None;
        // As checked when the folder was chosen; the repair asks the image again for the drive
        // it was made from.
        let source_disk = std::mem::take(&mut self.copy_protected);
        let options = RepairOptions {
            image,
            folder,
            source_disk,
        };
        self.start_job(
            "Making the copy and attaching it…",
            move |events, cancel| {
                Done::Started(
                    repair::start_repair(&options, events, cancel).map(|(r, s)| (Box::new(r), s)),
                )
            },
        );
    }

    fn find(&mut self) {
        let Some(image) = self.image.clone() else {
            return;
        };
        let options = FindOptions {
            image,
            every_sector: None,
        };
        self.start_job(
            "Searching the image for lost volumes…",
            move |events, cancel| Done::Found(repair::find_table(&options, events, cancel)),
        );
    }

    fn ask_write(&mut self) -> Option<Ask> {
        let table = self.table.as_ref()?;
        let disk = self.repair.as_ref()?.disk;
        let mut items: Vec<Item> = table
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| Item::Pair(format!("Partition {}", i + 1), e.describe()))
            .collect();
        items.push(Item::Pair(
            "Table".into(),
            match table.style {
                repair::Style::Mbr => "MBR".into(),
                repair::Style::Gpt => "GPT".into(),
            },
        ));
        items.push(Item::Pair(
            "Written to".into(),
            format!("Disk {disk}, the copy"),
        ));
        let mut sections = vec![Section {
            heading: None,
            items,
        }];
        if !table.left_out.is_empty() {
            sections.push(Section {
                heading: Some("Left out".into()),
                items: table.left_out.iter().cloned().map(Item::Para).collect(),
            });
        }
        Some(Ask {
            dialog: Dialog {
                window_title: "Repair on a copy".into(),
                heading: "Write this partition table to the copy?".into(),
                intro: "The copy's partition table is replaced with one built from the volumes the search found. Only the copy is written; the image and the drive stay as they are.".into(),
                sections,
                accept: "Write to the copy".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_WRITE,
        })
    }

    /// Runs a step that needs the repair on a worker thread and gives it back after.
    fn with_repair(
        &mut self,
        busy: &str,
        step: impl FnOnce(Repair, &dyn Fn(Event), &AtomicBool) -> Done + Send + 'static,
    ) {
        let Some(repair) = self.repair.take() else {
            return;
        };
        self.copy_disk = Some(repair.disk);
        self.start_job(busy, move |events, cancel| step(repair, events, cancel));
    }

    fn write_table(&mut self) {
        let (Some(table), Some(disk)) = (self.table.clone(), self.repair.as_ref().map(|r| r.disk))
        else {
            return;
        };
        // The disk the dialog showed is the confirmation the engine checks.
        let options = WriteTableOptions {
            table,
            confirm_disk: disk,
        };
        self.with_repair(
            "Writing the partition table to the copy…",
            move |repair, events, _| {
                let result = repair.write_table(&options, events);
                Done::Written(Box::new(repair), result)
            },
        );
    }

    fn ask_chkdsk(&mut self) -> Option<Ask> {
        let volume = self.selected_volume()?.clone();
        Some(Ask {
            dialog: Dialog {
                window_title: "Repair on a copy".into(),
                heading: "Check and fix this volume of the copy?".into(),
                intro: "Windows' disk check (chkdsk /f) checks the volume's file system and fixes the errors it finds, on the copy only. The volume is closed for the check, so close any window showing it.".into(),
                sections: vec![Section {
                    heading: None,
                    items: vec![Item::Pair("Volume".into(), volume.describe())],
                }],
                accept: "Fix the copy".into(),
                decline: Some("Cancel".into()),
                copy: None,
            },
            then: DO_CHKDSK,
        })
    }

    fn chkdsk(&mut self) {
        let Some(volume) = self.selected_volume().cloned() else {
            return;
        };
        self.output = vec![format!("chkdsk {} /f /x", volume.describe())];
        let options = ChkdskOptions {
            volume: volume.guid_path.clone(),
        };
        self.with_repair(
            "Windows' disk check is running on the copy…",
            move |repair, events, cancel| {
                let result = repair.chkdsk(&options, events, cancel);
                Done::Checked(Box::new(repair), result)
            },
        );
    }

    fn end_repair(&mut self, keep: bool) {
        let Some(repair) = self.repair.take() else {
            return;
        };
        self.volumes.clear();
        self.bitlocker.clear();
        self.table = None;
        self.copy_disk = None;
        let options = EndOptions { keep };
        self.start_job(
            if keep {
                "Keeping the copy and closing it…"
            } else {
                "Discarding the copy…"
            },
            move |_, _| Done::Ended(repair.end(&options)),
        );
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::Phase { text } | Event::Item { text } => self.busy = format!("{text}…"),
            Event::Progress { done, total } if total > 0 => {
                let phase = self.busy.split("  ·  ").next().unwrap_or("").to_string();
                self.busy = format!("{phase}  ·  {} of {}", bytes_text(done), bytes_text(total));
            }
            Event::Progress { .. } => {}
            Event::Line { text } | Event::Warning { text } => {
                if self.output.len() >= OUTPUT_LINES {
                    self.output.remove(1);
                }
                self.output.push(text);
            }
        }
    }

    fn picked(&mut self, done: Done) {
        match done {
            Done::Attached(Ok((attached, result))) => {
                self.notice = Some((
                    if result.letters.is_empty() {
                        "The image is attached read-only, but Windows gave none of its volumes a drive letter: it found no file system it reads. A damaged table can be rebuilt with Repair on a copy.".into()
                    } else {
                        format!(
                            "The image is attached read-only as Disk {}. Drive letters: {}. Nothing can be written to it.",
                            result.disk,
                            result.letters.join(", ")
                        )
                    },
                    Tone::Ok,
                ));
                self.attached = Some(attached);
                self.volumes = result.volumes;
                self.bitlocker = result.bitlocker;
            }
            Done::Attached(Err(why)) => self.notice = Some((why, Tone::Warn)),
            Done::Started(Ok((repair, started))) => {
                self.notice = Some((
                    format!(
                        "The copy {} is attached as Disk {}, and can be written. Next: Find lost partitions, or choose a volume and Fix file system errors on the copy.",
                        started.copy.display(),
                        started.disk
                    ),
                    Tone::Ok,
                ));
                // Volumes whose first sector could not be read are said, not taken for
                // volumes without BitLocker, after what was done.
                let done = self.notice.take().map(|(text, _)| text).unwrap_or_default();
                match diagnostics::recovery::bitlocker::boot_sectors(started.disk, &started.volumes)
                {
                    Ok(sorted) => {
                        self.bitlocker = sorted.bitlocker;
                        if sorted.unread.is_empty() {
                            self.notice = Some((done, Tone::Ok));
                        } else {
                            let unread: Vec<String> = sorted
                                .unread
                                .iter()
                                .map(|(at, why)| format!("the volume at byte {at}: {why}"))
                                .collect();
                            self.notice = Some((
                                format!(
                                    "{done} Whether these are BitLocker volumes is not known, as \
                                     their first sector could not be read: {}.",
                                    unread.join("; ")
                                ),
                                Tone::Warn,
                            ));
                        }
                    }
                    Err(why) => {
                        self.bitlocker = Vec::new();
                        self.notice = Some((
                            format!("{done} BitLocker volumes could not be looked for: {why}"),
                            Tone::Warn,
                        ));
                    }
                }
                self.copy_disk = Some(started.disk);
                self.repair = Some(*repair);
                self.volumes = started.volumes;
            }
            Done::Started(Err(why)) => self.notice = Some((why, Tone::Warn)),
            Done::Found(Ok(table)) => {
                let parts: Vec<String> = table.entries.iter().map(|e| e.describe()).collect();
                self.notice = Some((
                    format!(
                        "The search found {}: {}. Write the table to the copy to make them its volumes again.",
                        if parts.len() == 1 {
                            "1 volume".to_string()
                        } else {
                            format!("{} volumes", parts.len())
                        },
                        parts.join("; ")
                    ),
                    Tone::Ok,
                ));
                self.table = Some(table);
            }
            Done::Found(Err(why)) => self.notice = Some((why, Tone::Warn)),
            Done::Written(repair, result) => {
                match result {
                    Ok(written) => {
                        // The copy has no drive letters while it is repaired, so nothing
                        // indexes or writes to it; the kept copy opens read-only with them.
                        self.notice = Some((
                            format!(
                                "The copy has the rebuilt table: {} found. Fix file system errors checks one; to browse them, keep the copy and open it with Open an image as a drive.",
                                if written.volumes.len() == 1 {
                                    "1 volume".to_string()
                                } else {
                                    format!("{} volumes", written.volumes.len())
                                }
                            ),
                            Tone::Ok,
                        ));
                        self.volumes = written.volumes;
                    }
                    Err(why) => self.notice = Some((why, Tone::Warn)),
                }
                self.repair = Some(*repair);
            }
            Done::Checked(repair, result) => {
                match result {
                    Ok(checked) => {
                        let tone = if (0..=2).contains(&checked.exit_code) {
                            Tone::Ok
                        } else {
                            Tone::Warn
                        };
                        self.notice = Some((checked.meaning, tone));
                    }
                    Err(why) => self.notice = Some((why, Tone::Warn)),
                }
                self.volumes = repair.volumes();
                self.repair = Some(*repair);
            }
            Done::Ended(Ok(ended)) => self.notice = Some((ended.text, Tone::Ok)),
            Done::Ended(Err(not)) => {
                // Its volumes did not close: the copy is still attached, to be ended again.
                if let Some(repair) = not.repair {
                    self.copy_disk = Some(repair.disk);
                    self.volumes = repair.volumes();
                    self.repair = Some(*repair);
                }
                self.notice = Some((not.why, Tone::Warn));
            }
        }
    }
}

impl Page for DriveView {
    fn title(&self) -> String {
        "Open an image as a drive".into()
    }

    fn help_key(&self) -> Option<&'static str> {
        Some(crate::help::IMAGE_AS_DRIVE)
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((800, 720), (640, 600))
    }

    fn build(&mut self, hwnd: HWND) {
        let text = |kind, value: &str| ui::text(hwnd, kind, Tone::Neutral, false, value);
        let button = |id, kind, caption: &str| ui::button(hwnd, id, kind, caption);
        self.controls = Some(Controls {
            title: text(Kind::Title, "Open an image as a drive"),
            subtitle: text(Kind::Muted, ""),
            about: text(
                Kind::Body,
                &format!(
                    "Attaches a rescue image read-only, so Windows gives its volumes drive letters and Explorer can open them. Nothing can be written to the image while it is attached. Windows attaches an image this way up to {}.",
                    bytes_text(vdisk::MAX_VHD)
                ),
            ),
            choose: button(CHOOSE, Kind::Secondary, "Choose image…"),
            attach: button(ATTACH, Kind::Primary, "Open as a drive"),
            volumes: toolwin::list(hwnd, VOLUMES, grid::ROW_H),
            explore: button(EXPLORE, Kind::Secondary, "Open in Explorer"),
            unlock: button(UNLOCK, Kind::Secondary, "Unlock a BitLocker drive…"),
            repair: button(REPAIR, Kind::Secondary, "Repair on a copy…"),
            repair_about: text(Kind::Muted, "Repairs go to a copy that holds only the changes, never to the image or the drive."),
            find: button(FIND, Kind::Secondary, "Find lost partitions"),
            write_table: button(WRITE_TABLE, Kind::Secondary, "Write the partitions found to the copy…"),
            chkdsk: button(CHKDSK, Kind::Secondary, "Fix file system errors on the copy…"),
            keep: button(KEEP, Kind::Secondary, "Keep the copy"),
            discard: button(DISCARD, Kind::Secondary, "Discard the copy…"),
            stop: button(STOP, Kind::Secondary, "Stop"),
            output: ui::selectable_scrolling(hwnd, ""),
            notice: text(Kind::Body, ""),
            close: button(CLOSE, Kind::Ghost, "Close"),
        });
        self.render();
    }

    fn layout(&mut self, _hwnd: HWND, w: i32, h: i32, dpi: u32) {
        self.area = (w, h, dpi);
        let Some(c) = &self.controls else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        f.header(c.title, c.subtitle);
        f.text(c.about, 12);
        f.buttons(&[c.choose, c.attach], 12);
        let rows = toolwin::count(c.volumes).clamp(2, 4) as i32;
        f.block(c.volumes, f.s(grid::ROW_H) * rows + f.s(4));
        f.space(10);
        f.buttons(&[c.explore, c.unlock, c.repair], 10);
        f.text(c.repair_about, 6);
        f.buttons(&[c.find, c.write_table, c.chkdsk, c.keep, c.discard], 10);
        // The output takes what is left above the notice and the footer.
        ui::set_font(c.output, ui::fonts(dpi).caption);
        let notice_h = f.text_h(c.notice, f.w);
        let below = if notice_h > 0 { notice_h + f.s(8) } else { 0 } + toolwin::footer_h(dpi);
        let preferred = f.s(grid::BODY_H) * 6;
        self.natural = Some(f.y + preferred + below);
        f.block(c.output, (h - below - f.y).max(f.s(grid::BODY_H) * 2));
        f.space(8);
        f.text(c.notice, 0);
        toolwin::footer(w, h, dpi, &[], &[c.stop, c.close]);
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }

    fn command(&mut self, hwnd: HWND, id: usize, code: u16) -> Option<Ask> {
        let mut ask = None;
        match id {
            CHOOSE => {
                if let Some(path) = toolwin::pick_file(
                    hwnd,
                    "Choose a disk image, or a repaired copy",
                    "Disk images (*.img, *.dd, *.raw, *.bin, *.vhd)\0*.img;*.dd;*.raw;*.bin;*.vhd\0All files\0*.*\0",
                ) {
                    self.image = Some(path);
                    self.notice = None;
                }
            }
            ATTACH => {
                if self.attached.is_some() {
                    self.close_drive();
                } else {
                    ask = self.ask_attach();
                }
            }
            DO_PLAIN => {
                if let Some(image) = self.image.clone() {
                    self.make_plain = true;
                    self.attach(image);
                }
            }
            VOLUMES if code == toolwin::ACTIVATE => {
                if let Some(letter) = self.selected_volume().and_then(|v| v.letter()) {
                    toolwin::open_path(hwnd, std::path::Path::new(&format!("{letter}\\")));
                }
            }
            EXPLORE => {
                if let Some(letter) = self.selected_volume().and_then(|v| v.letter()) {
                    toolwin::open_path(hwnd, std::path::Path::new(&format!("{letter}\\")));
                }
            }
            UNLOCK => {
                let disk = self.attached.as_ref().map(|a| a.disk).or(self.copy_disk);
                if let Some(disk) = disk {
                    crate::bitlocker_view::open(hwnd, disk, self.source_disk);
                }
            }
            REPAIR => ask = self.ask_repair(hwnd),
            DO_REPAIR => self.start_repair(),
            FIND => self.find(),
            WRITE_TABLE => ask = self.ask_write(),
            DO_WRITE => self.write_table(),
            CHKDSK => ask = self.ask_chkdsk(),
            DO_CHKDSK => self.chkdsk(),
            KEEP => self.end_repair(true),
            DISCARD => {
                ask = Some(Ask {
                    dialog: Dialog {
                        window_title: "Repair on a copy".into(),
                        heading: "Discard the repaired copy?".into(),
                        intro: "The copy and every repair made to it are deleted. The image stays as it is.".into(),
                        sections: Vec::new(),
                        accept: "Discard".into(),
                        decline: Some("Keep it".into()),
                        copy: None,
                    },
                    then: DO_DISCARD,
                })
            }
            DO_DISCARD => self.end_repair(false),
            STOP => {
                if let Some(job) = &self.job {
                    job.cancel.store(true, Ordering::Relaxed);
                    self.busy = "Stopping…".into();
                }
            }
            // Posted, so the window closes after this call returns.
            CLOSE => unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            },
            _ => {}
        }
        self.render();
        self.relayout(hwnd);
        ask
    }

    fn tick(&mut self, hwnd: HWND) {
        let Some(job) = &self.job else {
            return;
        };
        let events: Vec<Event> = job.events.try_iter().collect();
        let done = match job.done.try_recv() {
            Ok(done) => Some(Some(done)),
            Err(mpsc::TryRecvError::Disconnected) => Some(None),
            Err(mpsc::TryRecvError::Empty) => None,
        };
        for event in events {
            self.event(event);
        }
        if let Some(done) = done {
            // Events sent just before the end.
            if let Some(job) = self.job.take() {
                for event in job.events.try_iter() {
                    self.event(event);
                }
            }
            match done {
                Some(done) => self.picked(done),
                None => {
                    self.notice = Some(("The work stopped without an answer.".into(), Tone::Warn))
                }
            }
            if self.repair.is_none() {
                self.copy_disk = None;
            }
        }
        self.render();
        self.relayout(hwnd);
    }

    fn draw_item(&self, _list: usize, index: usize, dc: HDC, rect: &RECT, state: ItemState) {
        draw_line(
            dc,
            rect,
            state,
            self.volume_rows().get(index).map(String::as_str),
        );
    }
}

/// One plain row of a list: its text, highlighted when chosen or under the pointer.
pub fn draw_line(dc: HDC, rect: &RECT, state: ItemState, text: Option<&str>) {
    let colors = ui::current();
    ui::fill_rect(dc, rect, colors.card);
    let Some(text) = text else {
        return;
    };
    let s = |x: i32| scale(state.dpi, x);
    if state.selected || state.hot {
        if let Some(canvas) = ui::Canvas::new(dc) {
            canvas.fill_round(
                (
                    rect.left as f32,
                    (rect.top + s(1)) as f32,
                    (rect.right - rect.left) as f32,
                    (rect.bottom - rect.top - s(2)) as f32,
                ),
                s(6) as f32,
                if state.selected {
                    colors.raised_hover
                } else {
                    colors.raised
                },
            );
        }
    }
    let line = RECT {
        left: rect.left + s(10),
        top: rect.top,
        right: rect.right - s(10),
        bottom: rect.bottom,
    };
    ui::draw_text(
        dc,
        text,
        &line,
        ui::fonts(state.dpi).body,
        colors.text,
        DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_LEFT,
    );
}
