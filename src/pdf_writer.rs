//! Renders the findings report as an A4 PDF with embedded Noto Sans. The content is
//! built as plain blocks first, so tests read what the report says without a PDF parser.
use std::io;

use printpdf::{
    Color, Line, LinePoint, Mm, Op, ParsedFont, PdfDocument, PdfFontHandle, PdfPage,
    PdfSaveOptions, Point, Pt, Rgb, TextItem,
};

use crate::checks::{Grade, Outcome};
use crate::clock;
use crate::inventory_view;
use crate::report::Report;
use crate::session::{CheckState, EndReason, Phase};

const NOTO_SANS: &[u8] = include_bytes!("../assets/NotoSans-Regular.ttf");

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Tone {
    Normal,
    Muted,
    Flag,
    Serious,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Block {
    Eyebrow(String),
    Title(String),
    Meta(String),
    Rule,
    Heading(String),
    Para(String, Tone),
    Bullet(String, Tone),
    Row(String, String, Tone),
    Page,
}

fn result_text(state: &CheckState) -> (String, Tone) {
    match state {
        CheckState::Done {
            outcome: Outcome::Found(finding),
            ..
        } => (
            finding.brief.clone(),
            match finding.grade {
                Grade::Serious => Tone::Serious,
                Grade::Flagged => Tone::Flag,
                Grade::Clear => Tone::Normal,
            },
        ),
        CheckState::Done {
            outcome: Outcome::Unavailable(reason),
            ..
        } => (format!("Unavailable: {reason}"), Tone::Flag),
        _ => ("Not run".into(), Tone::Muted),
    }
}

fn ending(phase: &Phase) -> &str {
    match phase {
        Phase::Ended(EndReason::Completed) => "all checks finished",
        Phase::Ended(EndReason::Stopped) => "stopped by the computer's owner",
        Phase::Ended(EndReason::Expired) => "the session time limit was reached",
        Phase::Ended(EndReason::ConnectionEnded(reason)) => reason,
        Phase::Running | Phase::Paused => "still open",
    }
}

fn list(labels: &[&str]) -> String {
    match labels {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

pub(crate) fn blocks(report: &Report<'_>) -> Vec<Block> {
    use Block::*;
    let session = report.session;
    let rows = session.rows();
    let started = clock::local(session.started_at());
    let mut out = vec![
        Eyebrow("DIAGNOSTIC TOOL".into()),
        Title("Computer check report".into()),
        Meta(format!("{}  |  Version {}", started.long(), report.version)),
        Rule,
        Para("This report lists what the read-only checks found on this computer. It stays here unless you choose to share it. It contains no personal files, passwords or screen images.".into(), Tone::Muted),
        Heading("At a glance".into()),
    ];
    let flagged: Vec<_> = rows
        .iter()
        .filter_map(|row| match &row.state {
            CheckState::Done {
                outcome: Outcome::Found(finding),
                ..
            } if finding.flagged() => {
                Some((finding.grade, format!("{}: {}", row.label, finding.brief)))
            }
            _ => None,
        })
        .collect();
    let unavailable: Vec<_> = rows
        .iter()
        .filter(|row| {
            matches!(
                row.state,
                CheckState::Done {
                    outcome: Outcome::Unavailable(_),
                    ..
                }
            )
        })
        .map(|row| row.label)
        .collect();
    let not_run: Vec<_> = rows
        .iter()
        .filter(|row| !matches!(row.state, CheckState::Done { .. }))
        .map(|row| row.label)
        .collect();
    if flagged.is_empty() && unavailable.is_empty() && not_run.is_empty() {
        out.push(Para("No check flagged anything to look at. That does not prove the computer is healthy; the limits are listed below.".into(), Tone::Normal));
    } else if flagged.is_empty() {
        out.push(Para(
            "None of the completed checks flagged anything, but not every check completed.".into(),
            Tone::Normal,
        ));
    } else {
        let noun = if flagged.len() == 1 {
            "result is"
        } else {
            "results are"
        };
        out.push(Para(
            format!("{} {noun} worth a closer look:", flagged.len()),
            Tone::Normal,
        ));
        let mut flagged = flagged;
        // Serious results lead, each marked in words as well as colour.
        flagged.sort_by_key(|(grade, _)| std::cmp::Reverse(*grade));
        out.extend(flagged.into_iter().map(|(grade, line)| match grade {
            Grade::Serious => Bullet(format!("Serious: {line}"), Tone::Serious),
            _ => Bullet(line, Tone::Flag),
        }));
    }
    if !unavailable.is_empty() {
        out.push(Para(
            format!(
                "Could not check: {}. Those parts of the computer were not examined.",
                list(&unavailable)
            ),
            Tone::Flag,
        ));
    }
    if !not_run.is_empty() {
        out.push(Para(
            format!(
                "Not run because the session ended ({}): {}.",
                ending(session.phase()),
                list(&not_run)
            ),
            Tone::Muted,
        ));
    }
    out.push(Heading("Checks".into()));
    for row in rows {
        let (text, tone) = result_text(&row.state);
        out.push(Row(row.label.into(), text, tone));
    }
    out.push(Heading("What these results cannot tell you".into()));
    for line in [
        "A check marked unavailable or not run is not a passing result.",
        "Recent system events, App crashes, Service failures and Hardware and driver events cover the past 7 days of the event logs, the last three with at most 1,000 events per query; Recent system events also hides kinds listed as routine. Crash dump readiness covers 30 days. No event check proves the hardware or software is healthy.",
        "The CPU and memory reading is one moment and may reflect whatever was running then.",
        "Drive health status comes from the Windows storage provider; it is not a full SMART test. Drive wear and errors reads each drive's own health data, and SATA drives need administrator rights for that, which this tool does not ask for, so they are reported as not read.",
        "Windows drive space gives the free space only; it does not say what fills the drive.",
        "A crash record shows which app failed, not why it failed.",
    ] {
        out.push(Bullet(line.into(), Tone::Normal));
    }
    out.push(Heading("Changes made".into()));
    out.push(Para(report.repair.into(), Tone::Normal));
    out.push(Heading("Next steps".into()));
    out.push(Para(
        format!(
            "If a problem continues, note what you were doing and when it happened. Review this report with {} before replacing parts: the hardware list identifies likely models but cannot prove a replacement fits.",
            crate::site::operator()
        ),
        Tone::Normal,
    ));

    out.extend([
        Page,
        Eyebrow("HARDWARE".into()),
        Title("Hardware at a glance".into()),
        Rule,
    ]);
    let inventory = session.inventory();
    if inventory.is_empty() {
        out.push(Para(
            "The hardware inventory was not collected.".into(),
            Tone::Flag,
        ));
    } else {
        for line in inventory_view::summary(inventory) {
            match line.split_once(": ") {
                Some((label, value)) => out.push(Row(label.into(), value.into(), Tone::Normal)),
                None => out.push(Para(line, Tone::Normal)),
            }
        }
        if inventory_view::summary(inventory)
            .iter()
            .any(|line| line.contains("capacity unavailable (Windows interface: USB)"))
        {
            out.push(Para("A removable USB drive reported 0 GiB to Windows. Its capacity is unknown here; this does not mean the drive is empty or faulty.".into(), Tone::Muted));
        }
        let mut parts: Vec<_> = inventory
            .iter()
            .filter(|(key, _)| key.starts_with("ram.") && key.ends_with(".part"))
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty())
            .collect();
        parts.sort_unstable();
        parts.dedup();
        if !parts.is_empty() {
            out.push(Row(
                "Memory part numbers".into(),
                parts.join(", "),
                Tone::Normal,
            ));
        }
    }
    if let Some(details) = report.details {
        let rows = crate::tools::cpu_memory::details::report_rows(details);
        if !rows.is_empty() {
            out.push(Heading("Processor and memory details".into()));
            for (label, value) in rows {
                out.push(Row(label, value, Tone::Normal));
            }
        }
    }
    out.push(Para("Source: Windows CIM and SMBIOS, read as the current user. Firmware fields can be missing or wrong. Serial numbers are not collected.".into(), Tone::Muted));
    out.push(Para("Before buying parts, check the power supply, case size, spare connectors, cooling clearance and board compatibility by hand.".into(), Tone::Muted));

    out.extend([
        Page,
        Eyebrow("DETAILS".into()),
        Title("Check details and session record".into()),
        Rule,
    ]);
    for row in rows {
        match &row.state {
            CheckState::Done {
                outcome: Outcome::Found(finding),
                ..
            } if row.id != "hardware.inventory" => {
                out.push(Heading(row.label.into()));
                out.push(Para(finding.detail.clone(), Tone::Normal));
            }
            CheckState::Done {
                outcome: Outcome::Unavailable(reason),
                ..
            } => {
                out.push(Heading(row.label.into()));
                out.push(Para(
                    format!("Unavailable: {reason}. No conclusion can be drawn."),
                    Tone::Flag,
                ));
            }
            _ => {}
        }
    }
    out.push(Heading("Session record".into()));
    out.push(Row("Started".into(), started.long(), Tone::Normal));
    let ended = session.ended_at().map_or("Still open".into(), |time| {
        format!("{}, {}", clock::local(time).long(), ending(session.phase()))
    });
    out.push(Row("Ended".into(), ended, Tone::Normal));
    out.push(Row(
        "Connection".into(),
        report.connection.into(),
        Tone::Normal,
    ));
    out.push(Row(
        "Version".into(),
        format!("Diagnostic Tool {}", report.version),
        Tone::Normal,
    ));
    for row in rows {
        let text = match &row.state {
            CheckState::Done {
                outcome,
                started,
                elapsed,
            } => format!(
                "{}, {:.1} s, {}",
                clock::local(*started).time(),
                elapsed.as_secs_f32(),
                match outcome {
                    Outcome::Found(_) => "completed",
                    Outcome::Unavailable(_) => "unavailable",
                    Outcome::Stopped => "stopped",
                }
            ),
            _ => "not run".into(),
        };
        out.push(Row(row.label.into(), text, Tone::Muted));
    }
    out
}

const LEFT: f32 = 18.0;
const RIGHT: f32 = 192.0;
const VALUE_X: f32 = 72.0;
const TOP: f32 = 277.0;
const BOTTOM: f32 = 24.0;

fn rgb(tone: Tone) -> (f32, f32, f32) {
    match tone {
        Tone::Normal => (0.094, 0.094, 0.106),
        Tone::Muted => (0.443, 0.443, 0.478),
        Tone::Flag => (0.706, 0.325, 0.035),
        Tone::Serious => (0.725, 0.110, 0.110),
    }
}

struct Layout {
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    y: f32,
    font: PdfFontHandle,
}

impl Layout {
    fn new(font: PdfFontHandle) -> Self {
        Self {
            pages: Vec::new(),
            ops: Vec::new(),
            y: TOP,
            font,
        }
    }

    fn ensure(&mut self, height: f32) {
        if self.y - height < BOTTOM {
            self.new_page();
        }
    }

    fn text(&mut self, text: &str, x: f32, y: f32, size: f32, color: (f32, f32, f32)) {
        self.ops.extend([
            Op::StartTextSection,
            Op::SetTextCursor {
                pos: Point::new(Mm(x), Mm(y)),
            },
            Op::SetFont {
                font: self.font.clone(),
                size: Pt(size),
            },
            Op::SetFillColor {
                col: Color::Rgb(Rgb {
                    r: color.0,
                    g: color.1,
                    b: color.2,
                    icc_profile: None,
                }),
            },
            Op::ShowText {
                items: vec![TextItem::Text(text.to_string())],
            },
            Op::EndTextSection,
        ]);
    }

    fn line(&mut self, y: f32, color: (f32, f32, f32), thickness: f32) {
        self.ops.extend([
            Op::SetOutlineColor {
                col: Color::Rgb(Rgb {
                    r: color.0,
                    g: color.1,
                    b: color.2,
                    icc_profile: None,
                }),
            },
            Op::SetOutlineThickness { pt: Pt(thickness) },
            Op::DrawLine {
                line: Line {
                    points: vec![
                        LinePoint {
                            p: Point::new(Mm(LEFT), Mm(y)),
                            bezier: false,
                        },
                        LinePoint {
                            p: Point::new(Mm(RIGHT), Mm(y)),
                            bezier: false,
                        },
                    ],
                    is_closed: false,
                },
            },
        ]);
    }

    fn lines(&mut self, text: &str, x: f32, units: usize, size: f32, tone: Tone, step: f32) {
        for part in text.split('\n') {
            for line in wrap(part, units) {
                self.ensure(step);
                self.text(&line, x, self.y, size, rgb(tone));
                self.y -= step;
            }
        }
    }

    fn block(&mut self, block: &Block) {
        match block {
            Block::Eyebrow(text) => {
                self.text(text, LEFT, self.y, 8.5, rgb(Tone::Muted));
                self.y -= 9.0;
            }
            Block::Title(text) => {
                self.text(text, LEFT, self.y, 20.0, rgb(Tone::Normal));
                self.y -= 8.0;
            }
            Block::Meta(text) => {
                self.text(text, LEFT, self.y, 9.5, rgb(Tone::Muted));
                self.y -= 5.0;
            }
            Block::Rule => {
                self.line(self.y, (0.831, 0.831, 0.847), 0.8);
                self.y -= 8.0;
            }
            Block::Heading(text) => {
                self.ensure(20.0);
                self.y -= 3.0;
                self.text(text, LEFT, self.y, 12.5, rgb(Tone::Normal));
                self.y -= 7.0;
            }
            Block::Para(text, tone) => {
                self.lines(text, LEFT, 92, 9.5, *tone, 5.2);
                self.y -= 2.0;
            }
            Block::Bullet(text, tone) => {
                let wrapped = wrap(text, 88);
                for (index, line) in wrapped.iter().enumerate() {
                    self.ensure(5.2);
                    if index == 0 {
                        self.text("\u{2022}", LEFT + 1.0, self.y, 9.5, rgb(*tone));
                    }
                    self.text(line, LEFT + 5.0, self.y, 9.5, rgb(*tone));
                    self.y -= 5.2;
                }
                self.y -= 0.8;
            }
            Block::Row(label, value, tone) => {
                let labels = wrap(label, 26);
                let values = wrap(value, 62);
                let count = labels.len().max(values.len());
                self.ensure(count as f32 * 5.0 + 3.0);
                for index in 0..count {
                    if let Some(text) = labels.get(index) {
                        self.text(text, LEFT, self.y, 9.5, rgb(Tone::Muted));
                    }
                    if let Some(text) = values.get(index) {
                        self.text(text, VALUE_X, self.y, 9.5, rgb(*tone));
                    }
                    self.y -= 5.0;
                }
                self.line(self.y + 2.6, (0.894, 0.894, 0.906), 0.4);
                self.y -= 1.4;
            }
            Block::Page => self.new_page(),
        }
    }

    fn new_page(&mut self) {
        let old = std::mem::take(&mut self.ops);
        self.pages.push(PdfPage::new(Mm(210.0), Mm(297.0), old));
        self.y = TOP;
    }

    fn finish(mut self, footer: &str) -> Vec<PdfPage> {
        self.new_page();
        let total = self.pages.len();
        for (index, page) in self.pages.iter_mut().enumerate() {
            page.ops.extend([
                Op::StartTextSection,
                Op::SetTextCursor {
                    pos: Point::new(Mm(LEFT), Mm(13.0)),
                },
                Op::SetFont {
                    font: self.font.clone(),
                    size: Pt(8.0),
                },
                Op::SetFillColor {
                    col: Color::Rgb(Rgb {
                        r: 0.443,
                        g: 0.443,
                        b: 0.478,
                        icc_profile: None,
                    }),
                },
                Op::ShowText {
                    items: vec![TextItem::Text(format!(
                        "{footer}  |  Page {} of {}",
                        index + 1,
                        total
                    ))],
                },
                Op::EndTextSection,
            ]);
        }
        self.pages
    }
}

fn width_units(ch: char) -> usize {
    if ch.is_ascii() {
        1
    } else if ch.len_utf8() >= 3 {
        2
    } else {
        1
    }
}

fn wrap(text: &str, max_units: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut units = 0;
    for word in text.split_whitespace() {
        let word_units: usize = word.chars().map(width_units).sum();
        if !current.is_empty() && units + word_units + 1 > max_units {
            lines.push(std::mem::take(&mut current));
            units = 0;
        }
        if !current.is_empty() {
            current.push(' ');
            units += 1;
        }
        for ch in word.chars() {
            let width = width_units(ch);
            if units + width > max_units && !current.is_empty() {
                lines.push(std::mem::take(&mut current));
                units = 0;
            }
            current.push(ch);
            units += width;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

pub(crate) fn render(report: &Report<'_>) -> io::Result<Vec<u8>> {
    let font = ParsedFont::from_bytes(NOTO_SANS, 0, &mut Vec::new())
        .ok_or_else(|| io::Error::other("embedded Noto Sans font could not be parsed"))?;
    if !font.has_source_bytes() {
        return Err(io::Error::other("embedded font bytes unavailable"));
    }
    let mut document = PdfDocument::new("Diagnostic Tool findings");
    let font_id = document.add_font(&font);
    let mut layout = Layout::new(PdfFontHandle::External(font_id));
    for block in blocks(report) {
        layout.block(&block);
    }
    let stamp = clock::local(report.session.started_at());
    let pages = layout.finish(&format!(
        "Diagnostic Tool {}  |  {}",
        report.version,
        stamp.long()
    ));
    let bytes = document
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut Vec::new());
    if bytes.len() < 500 || !bytes.starts_with(b"%PDF") {
        return Err(io::Error::other("PDF generation returned invalid bytes"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Finding, Grade};
    use crate::session::{EndReason, Session};
    use std::time::{Duration, Instant};

    fn report(session: &Session) -> Report<'_> {
        Report {
            session,
            version: "9.8.7-test",
            connection: "Local checks only.",
            repair: "No repair was run in this session.",
            details: None,
        }
    }

    fn first_page(blocks: &[Block]) -> &[Block] {
        let end = blocks.iter().position(|b| *b == Block::Page).unwrap();
        &blocks[..end]
    }

    #[test]
    fn wrapping_preserves_long_unicode_field() {
        let input = format!("Café {}", "字".repeat(400));
        let output = wrap(&input, 80);
        assert!(output.len() > 5);
        assert!(output
            .iter()
            .all(|line| line.chars().map(width_units).sum::<usize>() <= 80));
        assert_eq!(output.join(" ").replace(' ', ""), input.replace(' ', ""));
    }

    #[test]
    fn first_page_states_the_date_and_version() {
        let session = Session::new(Instant::now(), Duration::from_secs(300), false);
        let blocks = blocks(&report(&session));
        let today = clock::local(std::time::SystemTime::now());
        let meta = first_page(&blocks)
            .iter()
            .find_map(|b| match b {
                Block::Meta(text) => Some(text.clone()),
                _ => None,
            })
            .expect("no date line on page one");
        let date = today.long();
        let date = date.split(" at ").next().unwrap();
        assert!(meta.starts_with(date), "{meta}");
        assert!(meta.contains("Version 9.8.7-test"), "{meta}");
    }

    #[test]
    fn unavailable_and_unrun_checks_are_never_shown_as_passed() {
        let now = Instant::now();
        let mut session = Session::new(now, Duration::from_secs(300), false);
        let first = session.start_next(now).unwrap();
        session.finish(first, Outcome::Unavailable("timed out".into()), now);
        let second = session.start_next(now).unwrap();
        session.finish(second, Outcome::Found(Finding::new("ok", "ok", false)), now);
        session.end(EndReason::Stopped);
        let blocks = blocks(&report(&session));
        let page = first_page(&blocks);
        let rows: Vec<_> = page
            .iter()
            .filter_map(|b| match b {
                Block::Row(label, value, tone) => Some((label.as_str(), value.as_str(), *tone)),
                _ => None,
            })
            .collect();
        assert_eq!(rows.len(), crate::checks::CHECKS.len());
        assert_eq!(rows[0].1, "Unavailable: timed out");
        assert_eq!(rows[0].2, Tone::Flag);
        assert!(rows[2..].iter().all(|(_, value, _)| *value == "Not run"));
        let text = format!("{page:?}");
        assert!(text.contains("Could not check: Windows version"));
        assert!(text.contains("stopped by the computer's owner"));
        assert!(!text.contains("No check flagged anything"));
    }

    #[test]
    fn flagged_results_lead_the_summary() {
        let session = crate::report::tests::sample_session();
        let blocks = blocks(&report(&session));
        let text = format!("{:?}", first_page(&blocks));
        assert!(text.contains("App crashes: 2 in 24 hours, latest example.exe"));
        assert!(text.contains("1 result is worth a closer look"));
    }

    #[test]
    fn serious_results_lead_the_summary_in_red_and_in_words() {
        let now = Instant::now();
        let mut session = Session::new(now, Duration::from_secs(300), false);
        let grades = [Grade::Flagged, Grade::Serious, Grade::Clear];
        for (index, grade) in grades.into_iter().enumerate() {
            let id = session.start_next(now).unwrap();
            let brief = format!("brief {index}");
            session.finish(id, Outcome::Found(Finding::graded(brief, "d", grade)), now);
        }
        session.end(EndReason::Stopped);
        let blocks = blocks(&report(&session));
        let page = first_page(&blocks);
        let bullets: Vec<_> = page
            .iter()
            .filter_map(|b| match b {
                Block::Bullet(text, tone) if *tone != Tone::Normal => Some((text.as_str(), *tone)),
                _ => None,
            })
            .collect();
        assert_eq!(
            bullets,
            [
                ("Serious: Hardware inventory: brief 1", Tone::Serious),
                ("Windows version: brief 0", Tone::Flag),
            ]
        );
        let rows: Vec<_> = page
            .iter()
            .filter_map(|b| match b {
                Block::Row(_, _, tone) => Some(*tone),
                _ => None,
            })
            .collect();
        assert_eq!(rows[..3], [Tone::Flag, Tone::Serious, Tone::Normal]);
    }

    #[test]
    fn the_hardware_section_holds_the_details_without_serial_numbers() {
        use crate::tools::cpu_memory::{details, smbios};
        let decoded = smbios::decode(&smbios::parse_raw(&smbios::tests::sample()).unwrap());
        let found = details::Details {
            processor: None,
            memory: Some(details::Memory {
                installed_bytes: Some(32 << 30),
                usable_bytes: 31 << 30,
                available_bytes: 20 << 30,
                committed_bytes: 15 << 30,
                commit_limit_bytes: 40 << 30,
                channels: details::channels(&decoded.devices),
                arrays: decoded.arrays.clone(),
                modules: decoded.devices.clone(),
                mapped_bytes: None,
            }),
            board: Some(details::Board {
                baseboard: decoded.baseboard.clone(),
                bios: decoded.bios.clone(),
            }),
            smbios_version: Some(decoded.version.clone()),
            smbios_cut_short: None,
            unread: Vec::new(),
        };
        let session = crate::report::tests::sample_session();
        let mut with = report(&session);
        with.details = Some(&found);
        let blocks = blocks(&with);
        let hardware = blocks
            .iter()
            .position(|b| *b == Block::Title("Hardware at a glance".into()))
            .unwrap();
        let text = format!("{:?}", &blocks[hardware..]);
        assert!(text.contains("Processor and memory details"), "{text}");
        assert!(text.contains("Memory modules"), "{text}");
        assert!(text.contains("A, B"), "{text}");
        assert!(!text.contains("0x0A1B2C3D"), "{text}");
        // Without details the section is as before.
        let plain = format!("{:?}", blocks_of(&session));
        assert!(!plain.contains("Processor and memory details"));
    }

    fn blocks_of(session: &Session) -> Vec<Block> {
        blocks(&report(session))
    }

    #[test]
    fn renders_every_block_to_a_pdf() {
        let session = crate::report::tests::sample_session();
        let bytes = render(&report(&session)).unwrap();
        assert!(bytes.starts_with(b"%PDF"));
    }
}
