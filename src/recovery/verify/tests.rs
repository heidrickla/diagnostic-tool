use super::*;
use std::io::Write;

fn samples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recovery/samples")
}

fn sample(name: &str) -> Vec<u8> {
    std::fs::read(samples().join(name)).unwrap()
}

fn check_with(bytes: &[u8], name: &str, limits: &Limits) -> Checked {
    check(&mut Mem(bytes), name, &mut Budget::new(*limits, None))
}

fn check_bytes(bytes: &[u8], name: &str) -> Checked {
    check_with(bytes, name, &LIMITS)
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("diagtool-verify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A ZIP archive of `(name, data, deflated)` entries.
fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, deflated) in entries {
        let packed = if *deflated {
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        } else {
            data.to_vec()
        };
        let crc = crc32fast::hash(data);
        let method: u16 = if *deflated { 8 } else { 0 };
        let local = out.len() as u32;
        let mut header = Vec::new();
        header.extend_from_slice(b"PK\x03\x04");
        header.extend_from_slice(&20u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&[0; 4]);
        header.extend_from_slice(&crc.to_le_bytes());
        header.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&header[4..30]);
        // Comment length, disk, internal and external attributes.
        central.extend_from_slice(&[0; 10]);
        central.extend_from_slice(&local.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A PDF with a classic index; `stream` is a Flate content stream for the page.
fn pdf(stream: &[u8]) -> Vec<u8> {
    let packed = zlib(stream);
    let mut out = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>".to_vec(),
        [
            b"<< /Length 5 0 R /Filter /FlateDecode >>\nstream\n".to_vec(),
            packed.clone(),
            b"\nendstream".to_vec(),
        ]
        .concat(),
        format!("{}", packed.len()).into_bytes(),
    ];
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for at in offsets {
        out.extend_from_slice(format!("{at:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A PDF 1.5 whose index is a compressed cross-reference stream with a PNG predictor.
fn pdf_xref_stream() -> Vec<u8> {
    let mut out = b"%PDF-1.5\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [] /Count 0 >>",
    ]
    .iter()
    .enumerate()
    {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref_at = out.len();
    offsets.push(xref_at);
    // Rows of 1 + 4 + 1 bytes for objects 0..=3, predicted with "Up".
    let rows: Vec<[u8; 6]> = std::iter::once([0u8, 0, 0, 0, 0, 255])
        .chain(offsets.iter().map(|at| {
            let b = (*at as u32).to_be_bytes();
            [1, b[0], b[1], b[2], b[3], 0]
        }))
        .collect();
    let mut predicted = Vec::new();
    let mut prior = [0u8; 6];
    for row in &rows {
        predicted.push(2);
        for i in 0..6 {
            predicted.push(row[i].wrapping_sub(prior[i]));
        }
        prior = *row;
    }
    let packed = zlib(&predicted);
    out.extend_from_slice(
        format!(
            "3 0 obj\n<< /Type /XRef /Size 4 /W [1 4 1] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Columns 6 /Predictor 12 >> /Length {} >>\nstream\n",
            packed.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&packed);
    out.extend_from_slice(format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").as_bytes());
    out
}

/// An MP4 with a movie header, one track whose chunk table points into `mdat`.
fn mp4(media: &[u8]) -> Vec<u8> {
    fn boxed(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        [&((body.len() + 8) as u32).to_be_bytes()[..], kind, body].concat()
    }
    let ftyp = boxed(b"ftyp", b"isom\0\0\x02\0isomiso2mp41");
    let mdat_at = ftyp.len() as u32 + 8;
    let stsd = boxed(
        b"stsd",
        &[&[0u8; 4][..], &1u32.to_be_bytes(), &boxed(b"avc1", &[0; 8])].concat(),
    );
    let stco = boxed(
        b"stco",
        &[&[0u8; 4][..], &1u32.to_be_bytes(), &mdat_at.to_be_bytes()].concat(),
    );
    let stbl = boxed(b"stbl", &[stsd, stco].concat());
    let minf = boxed(b"minf", &stbl);
    let mdia = boxed(b"mdia", &[boxed(b"mdhd", &[0; 24]), minf].concat());
    let trak = boxed(b"trak", &[boxed(b"tkhd", &[0; 84]), mdia].concat());
    let moov = boxed(b"moov", &[boxed(b"mvhd", &[0; 100]), trak].concat());
    [ftyp, boxed(b"mdat", media), moov].concat()
}

/// An MP3 of `n` MPEG-1 layer III frames at 128 kbit/s, 44.1 kHz, after an ID3 tag.
fn mp3(n: usize) -> Vec<u8> {
    let mut out = b"ID3\x04\0\0\0\0\0\x0A".to_vec();
    out.extend_from_slice(&[0u8; 10]);
    for i in 0..n {
        out.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x64]);
        out.extend((0..413).map(|k| (k * 7 + i) as u8 | 1));
    }
    out
}

/// Bytes that vary, for compressed-looking data.
fn noise(n: usize) -> Vec<u8> {
    let mut x = 0x1234_5678u32;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x as u8) | 1
        })
        .collect()
}

const GOOD_SAMPLES: [&str; 18] = [
    "photo.jpg",
    "holiday.jpg",
    "image.png",
    "anim.gif",
    "picture.bmp",
    "still.webp",
    "clip.mp4",
    "clip.mov",
    "clip.avi",
    "tone.wav",
    "letter.pdf",
    "report.docx",
    "budget.xlsx",
    "minutes.odt",
    "bundle.zip",
    "notes.txt",
    "readme.txt",
    "archive.7z",
];

#[test]
fn each_sample_sorts_by_its_contents() {
    for name in GOOD_SAMPLES {
        let checked = check_bytes(&sample(name), name);
        let want = if name == "archive.7z" {
            Verdict::NotChecked
        } else {
            Verdict::Good
        };
        assert_eq!(checked.verdict, want, "{name}: {checked:?}");
    }
    assert_eq!(
        check_bytes(&sample("report.docx"), "report.docx").kind,
        "Word document"
    );
    assert_eq!(
        check_bytes(&sample("budget.xlsx"), "budget.xlsx").kind,
        "Excel workbook"
    );
    assert_eq!(
        check_bytes(&sample("minutes.odt"), "minutes.odt").kind,
        "OpenDocument text"
    );
    for name in ["archive.rar", "contacts.sqlite", "random.bin"] {
        let checked = check_bytes(&sample(name), name);
        assert_eq!(checked.verdict, Verdict::NotChecked, "{name}: {checked:?}");
    }
    let built = [
        ("built.pdf", pdf(b"BT /F1 12 Tf 72 712 Td (Hello) Tj ET")),
        ("stream.pdf", pdf_xref_stream()),
        ("built.mp4", mp4(&noise(20_000))),
        ("built.mp3", mp3(40)),
    ];
    for (name, bytes) in &built {
        let checked = check_bytes(bytes, name);
        assert_eq!(checked.verdict, Verdict::Good, "{name}: {checked:?}");
    }
}

/// The guard: a file cut short anywhere is never good. Text has no end to miss, so it is
/// left out; a PDF may lose its last line break and stay whole, so its cuts start earlier.
#[test]
fn a_file_cut_short_is_never_good() {
    let mut files: Vec<(String, Vec<u8>)> = GOOD_SAMPLES
        .iter()
        .filter(|n| !n.ends_with(".txt") && !n.ends_with(".7z"))
        .map(|n| (n.to_string(), sample(n)))
        .collect();
    files.push(("built.pdf".into(), pdf(b"BT ET")));
    files.push(("stream.pdf".into(), pdf_xref_stream()));
    files.push(("built.mp4".into(), mp4(&noise(20_000))));
    files.push(("built.mp3".into(), mp3(40)));
    for (name, bytes) in &files {
        let len = bytes.len();
        let mut cuts: Vec<usize> = (1..32).map(|k| len * k / 32).collect();
        let last = if name.ends_with(".pdf") {
            len - 2
        } else {
            len - 1
        };
        cuts.push(last);
        for cut in cuts {
            let checked = check_bytes(&bytes[..cut], name);
            assert_ne!(
                checked.verdict,
                Verdict::Good,
                "{name} cut to {cut} of {len}: {checked:?}"
            );
        }
    }
}

/// No flipped bit anywhere in any sample makes the check panic, and none in a PNG after its
/// signature passes, since every chunk has a checksum.
#[test]
fn flipped_bits_never_panic_and_checksums_catch_them() {
    let mut names: Vec<&str> = GOOD_SAMPLES.to_vec();
    names.extend(["archive.rar", "contacts.sqlite", "random.bin"]);
    let mut x = 0x9E37_79B9u32;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x as usize
    };
    for name in names {
        let bytes = sample(name);
        for _ in 0..300 {
            let mut flipped = bytes.clone();
            let at = next() % flipped.len();
            flipped[at] ^= 1 << (next() % 8);
            let checked = check_bytes(&flipped, name);
            if name == "image.png" && at >= 8 {
                assert_ne!(
                    checked.verdict,
                    Verdict::Good,
                    "{name} byte {at}: {checked:?}"
                );
            }
        }
    }
    let bundle = sample("bundle.zip");
    // Every byte of the compressed data is covered by the entry's checksum.
    for at in 35..60 {
        let mut flipped = bundle.clone();
        flipped[at] ^= 0x10;
        let checked = check_bytes(&flipped, "bundle.zip");
        assert_ne!(checked.verdict, Verdict::Good, "byte {at}: {checked:?}");
    }
}

/// Random bytes under every name the check reads, at many lengths, never panic.
#[test]
fn hostile_bytes_never_panic() {
    let names = [
        "a.jpg", "a.png", "a.gif", "a.bmp", "a.tif", "a.pdf", "a.zip", "a.docx", "a.mp4", "a.mp3",
        "a.wav", "a.rtf", "a.txt",
    ];
    let magics: [&[u8]; 13] = [
        b"\xFF\xD8\xFF",
        b"\x89PNG\r\n\x1a\n",
        b"GIF89a",
        b"BM\0\0\0\0\0\0\0\0\0\0\0\0\x28\0\0\0",
        b"II*\0",
        b"%PDF-1.7\n",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"\0\0\0\x18ftypisom",
        b"ID3\x04\0\0\0\0\0\0",
        b"RIFF\xff\xff\xff\x7fWAVE",
        b"{\\rtf1",
        b"MM\0*\0\0\0\x08",
    ];
    for (i, magic) in magics.iter().enumerate() {
        for len in [0usize, 1, 7, 64, 700, 5000] {
            let mut bytes = magic.to_vec();
            bytes.extend(noise(len + i).iter().map(|b| b.wrapping_mul(i as u8 + 3)));
            for name in names {
                let _ = check_bytes(&bytes, name);
            }
            // Zeros and 0xFF after the magic: lengths of zero and lengths of everything.
            for fill in [0u8, 0xFF] {
                let mut bytes = magic.to_vec();
                bytes.extend(std::iter::repeat_n(fill, len));
                for name in names {
                    let _ = check_bytes(&bytes, name);
                }
            }
        }
    }
}

/// The guard: a block of zeros where a recovery could not read, inside compressed data that
/// has no checksum, is damaged.
#[test]
fn a_zeroed_block_inside_compressed_data_is_damaged() {
    let photo = sample("holiday.jpg");
    let mut zeroed = photo.clone();
    let at = photo.len() / 2 / 512 * 512;
    zeroed[at..at + 4096].fill(0);
    let checked = check_bytes(&zeroed, "holiday.jpg");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
    let movie = mp4(&noise(20_000));
    let mut zeroed = movie.clone();
    zeroed[8192..8192 + 4096].fill(0);
    let checked = check_bytes(&zeroed, "built.mp4");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
    assert!(checked.reason.contains("zero bytes"), "{checked:?}");
    let text = sample("notes.txt");
    let mut zeroed = text.clone();
    zeroed[4096..4096 + 512].fill(0);
    let checked = check_bytes(&zeroed, "notes.txt");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
    let mut zeroed = mp3(40);
    zeroed[4096..4096 + 4096].fill(0);
    assert_eq!(check_bytes(&zeroed, "a.mp3").verdict, Verdict::Damaged);
    let pdf = pdf(&noise(9000));
    let mut zeroed = pdf.clone();
    zeroed[1024..1024 + 4096].fill(0);
    assert_eq!(check_bytes(&zeroed, "a.pdf").verdict, Verdict::Damaged);
}

/// The guard: an object that is not where the index says makes a PDF damaged.
#[test]
fn a_pdf_whose_offsets_do_not_resolve_is_damaged() {
    let good_pdf = pdf(b"BT ET");
    let find = |what: &[u8]| {
        good_pdf
            .windows(what.len())
            .rposition(|w| w == what)
            .unwrap()
    };
    let at = find(b"3 0 obj");
    let mut moved = good_pdf.clone();
    moved[at] = b'9';
    let checked = check_bytes(&moved, "a.pdf");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
    assert!(checked.reason.contains("object 3"), "{checked:?}");
    let mut pointer = good_pdf.clone();
    let p = find(b"startxref\n") + 10;
    pointer[p] = b'1';
    assert_eq!(check_bytes(&pointer, "a.pdf").verdict, Verdict::Damaged);
}

/// The guard: an Office file without its main part is damaged, and a part with a wrong
/// checksum is damaged.
#[test]
fn an_office_file_needs_its_main_part() {
    let types: &[u8] = b"<?xml version=\"1.0\"?><Types/>";
    let rels: &[u8] = b"<Relationships><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>";
    let whole = zip(&[
        ("[Content_Types].xml", types, true),
        ("_rels/.rels", rels, true),
        ("word/document.xml", b"<w:document/>", true),
    ]);
    assert_eq!(check_bytes(&whole, "a.docx").verdict, Verdict::Good);
    let without = zip(&[
        ("[Content_Types].xml", types, true),
        ("_rels/.rels", rels, false),
    ]);
    let checked = check_bytes(&without, "a.docx");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
    assert!(checked.reason.contains("word/document.xml"), "{checked:?}");
    let plain = zip(&[("a.txt", b"hello", false)]);
    assert_eq!(check_bytes(&plain, "a.docx").verdict, Verdict::Damaged);
    assert_eq!(check_bytes(&plain, "a.zip").verdict, Verdict::Good);
    let mut wrong = plain.clone();
    let at = wrong.windows(5).position(|w| w == b"hello").unwrap();
    wrong[at] = b'j';
    let checked = check_bytes(&wrong, "a.zip");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
}

/// A file's name never decides its type: a PNG named .jpg is checked as a PNG and says so,
/// and a .jpg that starts with zeros is damaged.
#[test]
fn the_contents_decide_the_type_and_a_mismatch_is_named() {
    let checked = check_bytes(&sample("image.png"), "photo.jpg");
    assert_eq!(checked.verdict, Verdict::Good);
    assert!(
        checked
            .reason
            .starts_with("named .jpg, but it holds a PNG image"),
        "{checked:?}"
    );
    let checked = check_bytes(&[0u8; 9000], "photo.jpg");
    assert_eq!(checked.verdict, Verdict::Damaged);
    assert!(checked.reason.contains("all zeros"), "{checked:?}");
    let checked = check_bytes(&[], "photo.jpg");
    assert_eq!(checked.verdict, Verdict::Damaged);
    assert_eq!(check_bytes(&[], "empty.txt").verdict, Verdict::NotChecked);
}

/// A file that would decompress past the cap, or take past the time limit, is not checked,
/// never good and never damaged for it.
#[test]
fn the_limits_end_a_check_as_not_checked() {
    let big = vec![b'a'; 4_000_000];
    let bomb = zip(&[("a.txt", &big, true)]);
    let small = Limits {
        bytes: 1_000_000,
        ..LIMITS
    };
    let checked = check_with(&bomb, "a.zip", &small);
    assert_eq!(checked.verdict, Verdict::NotChecked, "{checked:?}");
    assert!(checked.reason.contains("compressed data"), "{checked:?}");
    let none = Limits {
        time: Some(Duration::ZERO),
        ..LIMITS
    };
    let checked = check_with(&sample("holiday.jpg"), "a.jpg", &none);
    assert_eq!(checked.verdict, Verdict::NotChecked, "{checked:?}");
    assert!(checked.reason.contains("time limit"), "{checked:?}");
    assert_eq!(check_bytes(&bomb, "a.zip").verdict, Verdict::Good);
}

#[test]
fn a_folder_is_checked_damaged_first_and_the_report_ends_with_its_last_line() {
    let dir = temp("folder");
    std::fs::create_dir_all(dir.join("Pictures")).unwrap();
    std::fs::write(dir.join("Pictures/photo.jpg"), sample("photo.jpg")).unwrap();
    let cut = sample("holiday.jpg");
    std::fs::write(dir.join("Pictures/cut.jpg"), &cut[..cut.len() / 2]).unwrap();
    std::fs::write(dir.join("notes.txt"), sample("notes.txt")).unwrap();
    std::fs::write(dir.join("archive.7z"), sample("archive.7z")).unwrap();
    let cancel = AtomicBool::new(false);
    let mut events = Vec::new();
    let outcome = run(
        &Options::new(&dir),
        &mut |e| events.push(e.clone()),
        &cancel,
    )
    .unwrap();
    let order: Vec<(Verdict, String)> = outcome
        .rows
        .iter()
        .map(|r| (r.checked.verdict, r.path.display().to_string()))
        .collect();
    assert_eq!(
        order,
        vec![
            (Verdict::Damaged, "Pictures\\cut.jpg".to_string()),
            (Verdict::NotChecked, "archive.7z".to_string()),
            (Verdict::Good, "notes.txt".to_string()),
            (Verdict::Good, "Pictures\\photo.jpg".to_string()),
        ]
    );
    // An event before each file, one for the damaged file, one for the report.
    assert_eq!(events.len(), 6, "{events:?}");
    let damaged = events.iter().find(|e| e.warning.is_some()).unwrap();
    assert!(damaged
        .warning
        .as_ref()
        .unwrap()
        .starts_with("Pictures\\cut.jpg: cut short"));
    let last = events.last().unwrap();
    assert_eq!(last.phase, Some(Phase::Reporting));
    assert_eq!((last.files_done, last.files_total), (4, 4));
    assert_eq!((last.good, last.damaged, last.not_checked), (2, 1, 1));
    assert!(outcome.report_whole);
    let json = serde_json::to_string(&outcome).unwrap();
    assert!(json.contains("\"verdict\":\"Damaged\""), "{json}");
    let report = outcome.report.clone().unwrap();
    assert_eq!(report, dir.join(REPORT));
    let text = std::fs::read_to_string(&report).unwrap();
    assert!(text.ends_with(END), "{text}");
    assert!(text.find("Damaged (1)").unwrap() < text.find("Good (2)").unwrap());
    assert!(text.contains("4 files: 2 good, 1 damaged, 1 not checked."));
    assert!(outcome.ledger.outputs()[0].complete());
    // A second check does not check the first one's report, and makes its own.
    let again = run(&Options::new(&dir), &mut |_| {}, &cancel).unwrap();
    assert_eq!(again.rows.len(), 4);
    assert_eq!(again.report.unwrap(), dir.join("File check report (2).txt"));
    // Stopped before the first file: every file is listed, none checked, and the report
    // says it was stopped.
    let stop = AtomicBool::new(true);
    let options = Options {
        write_report: false,
        ..Options::new(&dir)
    };
    let stopped = run(&options, &mut |_| {}, &stop).unwrap();
    assert_eq!(stopped.ended, Ended::Stopped);
    assert_eq!(stopped.report, None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The guard: options out of their bounds are refused before anything is read.
#[test]
fn options_out_of_bounds_are_refused() {
    let cancel = AtomicBool::new(false);
    let good = Options::new(std::env::temp_dir());
    assert!(good.limits().is_ok());
    for bad in [
        Options::default(),
        Options {
            inflate_cap: 10,
            ..good.clone()
        },
        Options {
            seconds_per_file: 0,
            ..good.clone()
        },
        Options {
            max_files: 0,
            ..good.clone()
        },
    ] {
        let mut called = false;
        assert!(run(&bad, &mut |_| called = true, &cancel).is_err());
        assert!(!called);
    }
    let parsed: Options =
        serde_json::from_str(r#"{"folder":"D:\\x","seconds_per_file":5}"#).unwrap();
    assert_eq!(parsed.seconds_per_file, 5);
    assert_eq!(parsed.max_files, 200_000);
}

struct Fails(usize);

impl Write for Fails {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Err(io::Error::other("the disk is full"));
        }
        self.0 -= 1;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The guard: a report whose write fails is entered partial, and its last line is never
/// among what was written.
#[test]
fn a_report_cut_short_is_partial_in_the_ledger() {
    let rows = (0..3000)
        .map(|i| Row {
            path: PathBuf::from(format!("file{i}.jpg")),
            size: 1,
            checked: Checked {
                verdict: Verdict::Good,
                kind: "JPEG image",
                reason: "every part present up to its end marker".into(),
            },
        })
        .collect();
    let outcome = Outcome {
        folder: PathBuf::from("X:\\Recovered"),
        rows,
        ..Outcome::default()
    };
    let text = report_text(&outcome);
    assert!(text.len() > 64 * 1024);
    let mut ledger = Ledger::default();
    let id = ledger.made(
        0,
        "r.txt".into(),
        "X:".into(),
        String::new(),
        text.len() as u64,
    );
    let mut fails = Fails(1);
    let written = crate::recovery::ledger::write_counted(&mut fails, text.as_bytes(), &mut |n| {
        ledger.wrote(id, n)
    });
    assert!(written.is_err());
    ledger.partial(id, "the disk is full");
    let o = &ledger.outputs()[0];
    assert!(o.partial());
    assert_eq!(o.at, 64 * 1024);
    assert!(!text[..o.at as usize].contains(END));
}

#[test]
fn only_this_checks_own_reports_are_skipped() {
    for (name, own) in [
        ("File check report.txt", true),
        ("File check report (12).txt", true),
        ("File check report (x).txt", false),
        ("File check report.txt.jpg", false),
        ("Recovery report.txt", false),
    ] {
        assert_eq!(is_report(std::ffi::OsStr::new(name)), own, "{name}");
    }
}

/// Needs a folder named by DIAGTOOL_VERIFY_DIR (a corpus of real and damaged files): checks
/// it, writes its report there, and prints every row.
#[test]
#[ignore]
fn the_folder_named_by_the_environment() {
    let dir = PathBuf::from(std::env::var("DIAGTOOL_VERIFY_DIR").unwrap());
    let cancel = AtomicBool::new(false);
    let started = std::time::Instant::now();
    let outcome = run(&Options::new(&dir), &mut |_| {}, &cancel).unwrap();
    for row in &outcome.rows {
        println!(
            "ROW\t{}\t{}\t{}\t{}",
            row.checked.verdict.label(),
            row.path.display(),
            row.checked.kind,
            row.checked.reason
        );
    }
    println!(
        "DONE\t{} rows in {:.1} s; report {:?} {:?}",
        outcome.rows.len(),
        started.elapsed().as_secs_f64(),
        outcome.report,
        outcome.report_error
    );
}

/// Found on real files: an RTF ending in a NUL is not damage; a run of zeros is.
#[test]
fn a_stray_zero_byte_in_text_is_not_damage() {
    let mut rtf = b"{\\rtf1\\ansi Hello}".to_vec();
    rtf.push(0);
    assert_eq!(check_bytes(&rtf, "a.rtf").verdict, Verdict::Good);
}

/// Found on real files: an XML file cut short passed as text.
#[test]
fn an_xml_file_cut_short_is_damaged() {
    let xml = b"<?xml version=\"1.0\"?>\n<a><b>text</b></a>\n";
    assert_eq!(check_bytes(xml, "a.xml").verdict, Verdict::Good);
    assert_eq!(check_bytes(&xml[..30], "a.xml").verdict, Verdict::Damaged);
}

/// Found on real files: a constant-rate MP3 cut on a frame boundary passed; its VBR
/// header's frame count catches it.
#[test]
fn an_mp3_cut_on_a_frame_boundary_is_damaged_by_its_frame_count() {
    // 40 frames of 417 bytes, the first holding an Info header that counts 40.
    let mut audio = mp3(40);
    let first = 20;
    audio[first + 36..first + 40].copy_from_slice(b"Info");
    audio[first + 40..first + 44].copy_from_slice(&1u32.to_be_bytes());
    audio[first + 44..first + 48].copy_from_slice(&40u32.to_be_bytes());
    assert_eq!(check_bytes(&audio, "a.mp3").verdict, Verdict::Good);
    let cut = first + 20 * 417;
    let checked = check_bytes(&audio[..cut], "a.mp3");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
    assert!(
        checked.reason.contains("lists 40 audio frames"),
        "{checked:?}"
    );
}

/// Found on real files: zeros inside a PDF's JPEG stream passed, since only Flate streams
/// were unpacked.
#[test]
fn zeros_inside_a_pdf_jpeg_stream_are_damage() {
    let image = noise(20_000);
    let mut doc = b"%PDF-1.4\n".to_vec();
    let at1 = doc.len();
    doc.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    let at2 = doc.len();
    doc.extend_from_slice(
        format!(
            "2 0 obj\n<< /Filter /DCTDecode /Length {} >>\nstream\n",
            image.len()
        )
        .as_bytes(),
    );
    let data_at = doc.len();
    doc.extend_from_slice(&image);
    doc.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = doc.len();
    doc.extend_from_slice(
        format!(
            "xref\n0 3\n0000000000 65535 f \n{at1:010} 00000 n \n{at2:010} 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    assert_eq!(check_bytes(&doc, "a.pdf").verdict, Verdict::Good);
    let from = (data_at + 4096) / 512 * 512;
    doc[from..from + 8192].fill(0);
    let checked = check_bytes(&doc, "a.pdf");
    assert_eq!(checked.verdict, Verdict::Damaged, "{checked:?}");
}

/// A ZIP whose table of contents lists the same stored file `n` times.
fn overlapping_zip(n: usize, data: &[u8]) -> Vec<u8> {
    let one = zip(&[("a.txt", data, false)]);
    let central_at = 30 + 5 + data.len();
    let entry = one[central_at..central_at + 46 + 5].to_vec();
    let mut out = one[..central_at].to_vec();
    for _ in 0..n {
        out.extend_from_slice(&entry);
    }
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&((entry.len() * n) as u32).to_le_bytes());
    out.extend_from_slice(&(central_at as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Files built to make a check read, hold or count without end stop at a limit of its
/// budget, are not checked, and say which limit; never good and never damaged for it.
#[test]
fn a_hostile_file_stops_within_its_budget() {
    let started = std::time::Instant::now();
    // One stored file listed 60,000 times: its checksum would be read 60,000 times.
    let data = noise(64 << 10);
    assert_eq!(
        check_bytes(&overlapping_zip(2, &data), "a.zip").verdict,
        Verdict::Good
    );
    let small = Limits {
        bytes: 100 << 20,
        ..LIMITS
    };
    let mut budget = Budget::new(small, None);
    let checked = check(
        &mut Mem(&overlapping_zip(60_000, &data)),
        "a.zip",
        &mut budget,
    );
    assert_eq!(checked.verdict, Verdict::NotChecked, "{checked:?}");
    assert!(
        checked
            .reason
            .starts_with("it holds more than 104.9 MB of stored and compressed data"),
        "{checked:?}"
    );
    assert_eq!(budget.hit(), Some(Limit::Bytes));
    assert!(budget.spent().bytes <= 100 << 20);

    // Its entries and their names are held: a small memory limit stops it, and says so.
    let tight = Limits {
        memory: 64 << 10,
        ..LIMITS
    };
    let mut budget = Budget::new(tight, None);
    let checked = check(
        &mut Mem(&overlapping_zip(60_000, &data)),
        "a.zip",
        &mut budget,
    );
    assert_eq!(checked.verdict, Verdict::NotChecked, "{checked:?}");
    assert!(
        checked.reason.contains("more than 65.5 kB of memory"),
        "{checked:?}"
    );
    assert!(budget.spent().peak <= 64 << 10);

    // More parts than the budget counts.
    let few = Limits {
        count: 1000,
        ..LIMITS
    };
    let mut budget = Budget::new(few, None);
    let checked = check(
        &mut Mem(&overlapping_zip(60_000, &data)),
        "a.zip",
        &mut budget,
    );
    assert!(
        checked.reason.starts_with("it holds more than 1,000 parts"),
        "{checked:?}"
    );
    assert_eq!(budget.spent().count, 1000);

    // A PDF index held within the memory limit.
    let mut budget = Budget::new(
        Limits {
            memory: 40,
            ..LIMITS
        },
        None,
    );
    let checked = check(&mut Mem(&pdf_xref_stream()), "a.pdf", &mut budget);
    assert!(checked.reason.contains("of memory"), "{checked:?}");

    // Boxes nested past the depth the check follows: not checked, never good.
    fn boxed(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        [&((body.len() + 8) as u32).to_be_bytes()[..], kind, body].concat()
    }
    let mut deep = boxed(b"free", &[]);
    for _ in 0..=LIMITS.depth {
        deep = boxed(b"moov", &deep);
    }
    let file = [boxed(b"ftyp", b"isom\0\0\x02\0isomiso2mp41"), deep].concat();
    let checked = check_bytes(&file, "a.mp4");
    assert_eq!(checked.verdict, Verdict::NotChecked, "{checked:?}");
    assert_eq!(
        checked.reason,
        "its boxes are nested more than 16 deep, deeper than this check reads"
    );

    // Stopped.
    let stop = AtomicBool::new(true);
    let checked = check(
        &mut Mem(&overlapping_zip(2, &data)),
        "a.zip",
        &mut Budget::new(LIMITS, Some(&stop)),
    );
    assert_eq!(checked.verdict, Verdict::NotChecked);
    assert!(started.elapsed() < Duration::from_secs(60));
}

/// The listing of a folder stops at its count, leaves out folders past its depth, and says
/// both; the files it listed are still checked.
#[test]
fn the_listing_of_a_folder_stops_within_its_budget() {
    let dir = temp("listing");
    let mut deep = dir.clone();
    for d in 0..4 {
        deep = deep.join(format!("level {d}"));
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("notes.txt"), sample("notes.txt")).unwrap();
    }
    let shallow = Limits {
        depth: 2,
        ..LISTING
    };
    let mut budget = Budget::new(shallow, None);
    let listed = list(&dir, 100, &mut budget, &mut |_| {});
    assert_eq!(listed.found.len(), 2);
    assert_eq!(
        budget.said().unwrap(),
        "1 of its folders lay more than 2 deep and was not followed."
    );
    let mut budget = Budget::new(
        Limits {
            count: 3,
            ..LISTING
        },
        None,
    );
    let listed = list(&dir, 100, &mut budget, &mut |_| {});
    assert_eq!(budget.hit(), Some(Limit::Count));
    assert!(listed.found.len() < 4);
    assert_eq!(
        budget.said().unwrap(),
        "The listing of the folder stopped at its limit of 3 entries."
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
