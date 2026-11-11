//! Every reason that carries a count, in one place, so each agrees in number with its count
//! ("1 stream ends", "both files", "its only chunk"); `tests` renders each for 0, 1 and 2.

/// A count and its noun: "0 bytes", "1 byte", "2 bytes".
pub fn count(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", pick(n, one, many))
}

/// The word that agrees with a count: `one` for 1, `many` otherwise.
pub fn pick<'a>(n: u64, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 {
        one
    } else {
        many
    }
}

/// Every one of a count, as a sentence's subject: "no chunks", "its only chunk", "both
/// chunks", "all 3 chunks". Its verb agrees through `pick(n, ..)`.
pub fn every(n: u64, one: &str, many: &str) -> String {
    match n {
        0 => format!("no {many}"),
        1 => format!("its only {one}"),
        2 => format!("both {many}"),
        _ => format!("all {n} {many}"),
    }
}

/// "; 1 more byte follows its end marker".
pub fn more_follow(extra: u64, end: &str) -> String {
    format!(
        "; {} {} {end}",
        count(extra, "more byte", "more bytes"),
        pick(extra, "follows", "follow")
    )
}

/// A cut-off piece too short to be what it should be: "3 bytes at byte 40 are not a whole box".
pub fn not_whole(n: u64, pos: u64, what: &str) -> String {
    format!(
        "{} at byte {pos} {} not a whole {what}",
        count(n, "byte", "bytes"),
        pick(n, "is", "are")
    )
}

/// "cut short: its header says 40 bytes, the file holds 12".
pub fn header_says(stated: u64, holds: u64) -> String {
    format!(
        "cut short: its header says {}, the file holds {holds}",
        count(stated, "byte", "bytes")
    )
}

/// A file of nothing but zeros, as far as its first bytes were read.
pub fn all_zeros(zeros: u64, whole_file: bool) -> String {
    if whole_file {
        format!("it is all zeros ({})", count(zeros, "byte", "bytes"))
    } else {
        format!(
            "its first {} {}",
            count(zeros, "byte", "bytes"),
            pick(zeros, "is zero", "are all zeros")
        )
    }
}

pub fn png(w: u64, h: u64, chunks: u64) -> String {
    format!(
        "{w} by {h} pixels; {} {} {}",
        every(chunks, "chunk", "chunks"),
        pick(chunks, "passes", "pass"),
        pick(chunks, "its checksum", "their checksums")
    )
}

pub fn gif(w: u64, h: u64, frames: u64) -> String {
    format!(
        "{w} by {h} pixels, {}; every block present up to its end",
        count(frames, "frame", "frames")
    )
}

pub fn tiff(directories: u64, parts: u64) -> String {
    format!(
        "{}, {} of image data, {} inside the file",
        count(directories, "image directory", "image directories"),
        count(parts, "part", "parts"),
        pick(parts, "wholly", "all")
    )
}

pub fn mp4(tracks: u64) -> String {
    format!(
        "every box is whole to the end of the file; {} indexed",
        count(tracks, "track", "tracks")
    )
}

pub fn mp3(frames: u64) -> String {
    format!(
        "{} {} whole and {} to its end",
        every(frames, "audio frame", "audio frames"),
        pick(frames, "is", "are"),
        pick(frames, "runs", "run")
    )
}

pub fn mp3_short(stated: u64, frames: u64) -> String {
    format!(
        "cut short: its header lists {}, the file holds {frames}",
        count(stated, "audio frame", "audio frames")
    )
}

pub fn riff(chunks: u64) -> String {
    format!(
        "{} {} whole",
        every(chunks, "chunk", "chunks"),
        pick(chunks, "is", "are")
    )
}

pub fn stray_zeros(stray: u64) -> String {
    format!("; {}", count(stray, "stray zero byte", "stray zero bytes"))
}

pub fn pdf(objects: u64, streams: u64) -> String {
    let streams = match streams {
        0 => "it holds no streams".to_string(),
        n => format!(
            "{} {} where {} should",
            count(n, "stream", "streams"),
            pick(n, "ends", "end"),
            pick(n, "it", "they")
        ),
    };
    format!(
        "{} {} where its index says; {streams}",
        every(objects, "object", "objects"),
        pick(objects, "is", "are")
    )
}

/// A ZIP's entries, named "file" in an archive and "part" in a document built on ZIP.
pub fn zip(checked: u64, one: &str, many: &str) -> String {
    format!(
        "{} {} and {} {}",
        every(checked, one, many),
        pick(checked, "decompresses", "decompress"),
        pick(checked, "passes", "pass"),
        pick(checked, "its checksum", "their checksums")
    )
}

pub fn zip_locked(locked: u64, one: &str, many: &str) -> String {
    format!(
        "; {} password-protected {} could not be checked",
        locked,
        pick(locked, one, many)
    )
}

pub fn zip_unread(unread: u64, one: &str, many: &str) -> String {
    format!(
        "; {} {} a compression this check does not read",
        count(unread, one, many),
        pick(unread, "uses", "use")
    )
}

pub fn zip_size(shown: &str, out: u64, size: u64) -> String {
    format!(
        "{shown} is damaged: it decompresses to {}, not {size}",
        count(out, "byte", "bytes")
    )
}

pub fn zip_contents(n: u64, total: u64) -> String {
    format!(
        "its table of contents ends after {n} of its {}",
        count(total, "entry", "entries")
    )
}

/// The report's line when the folder held more than the check's limit.
pub fn more_than_checked(checked: u64) -> String {
    format!(
        "The folder holds more than the {} checked; the rest are not listed.",
        count(checked, "file", "files")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every counted reason for 0, 1 and 2, as a person reads it.
    #[test]
    fn every_counted_reason_agrees_with_its_count() {
        let cases: Vec<(&str, [String; 3])> = vec![
            ("more_follow", [0, 1, 2].map(|n| more_follow(n, "its end"))),
            ("not_whole", [0, 1, 2].map(|n| not_whole(n, 40, "box"))),
            ("header_says", [0, 1, 2].map(|n| header_says(n, 0))),
            ("all_zeros whole", [0, 1, 2].map(|n| all_zeros(n, true))),
            ("all_zeros head", [0, 1, 2].map(|n| all_zeros(n, false))),
            ("png", [0, 1, 2].map(|n| png(4, 3, n))),
            ("gif", [0, 1, 2].map(|n| gif(4, 3, n))),
            ("tiff dirs", [0, 1, 2].map(|n| tiff(n, 2))),
            ("tiff parts", [0, 1, 2].map(|n| tiff(2, n))),
            ("mp4", [0, 1, 2].map(mp4)),
            ("mp3", [0, 1, 2].map(mp3)),
            ("mp3_short", [0, 1, 2].map(|n| mp3_short(n, 0))),
            ("riff", [0, 1, 2].map(riff)),
            ("stray_zeros", [0, 1, 2].map(stray_zeros)),
            ("pdf objects", [0, 1, 2].map(|n| pdf(n, 2))),
            ("pdf streams", [0, 1, 2].map(|n| pdf(2, n))),
            ("zip", [0, 1, 2].map(|n| zip(n, "file", "files"))),
            (
                "zip_locked",
                [0, 1, 2].map(|n| zip_locked(n, "part", "parts")),
            ),
            (
                "zip_unread",
                [0, 1, 2].map(|n| zip_unread(n, "file", "files")),
            ),
            ("zip_size", [0, 1, 2].map(|n| zip_size("a.txt", n, 9))),
            ("zip_contents", [0, 1, 2].map(|n| zip_contents(0, n))),
            ("more_than_checked", [0, 1, 2].map(more_than_checked)),
        ];
        let expected: Vec<[&str; 3]> = vec![
            [
                "; 0 more bytes follow its end",
                "; 1 more byte follows its end",
                "; 2 more bytes follow its end",
            ],
            [
                "0 bytes at byte 40 are not a whole box",
                "1 byte at byte 40 is not a whole box",
                "2 bytes at byte 40 are not a whole box",
            ],
            [
                "cut short: its header says 0 bytes, the file holds 0",
                "cut short: its header says 1 byte, the file holds 0",
                "cut short: its header says 2 bytes, the file holds 0",
            ],
            [
                "it is all zeros (0 bytes)",
                "it is all zeros (1 byte)",
                "it is all zeros (2 bytes)",
            ],
            [
                "its first 0 bytes are all zeros",
                "its first 1 byte is zero",
                "its first 2 bytes are all zeros",
            ],
            [
                "4 by 3 pixels; no chunks pass their checksums",
                "4 by 3 pixels; its only chunk passes its checksum",
                "4 by 3 pixels; both chunks pass their checksums",
            ],
            [
                "4 by 3 pixels, 0 frames; every block present up to its end",
                "4 by 3 pixels, 1 frame; every block present up to its end",
                "4 by 3 pixels, 2 frames; every block present up to its end",
            ],
            [
                "0 image directories, 2 parts of image data, all inside the file",
                "1 image directory, 2 parts of image data, all inside the file",
                "2 image directories, 2 parts of image data, all inside the file",
            ],
            [
                "2 image directories, 0 parts of image data, all inside the file",
                "2 image directories, 1 part of image data, wholly inside the file",
                "2 image directories, 2 parts of image data, all inside the file",
            ],
            [
                "every box is whole to the end of the file; 0 tracks indexed",
                "every box is whole to the end of the file; 1 track indexed",
                "every box is whole to the end of the file; 2 tracks indexed",
            ],
            [
                "no audio frames are whole and run to its end",
                "its only audio frame is whole and runs to its end",
                "both audio frames are whole and run to its end",
            ],
            [
                "cut short: its header lists 0 audio frames, the file holds 0",
                "cut short: its header lists 1 audio frame, the file holds 0",
                "cut short: its header lists 2 audio frames, the file holds 0",
            ],
            [
                "no chunks are whole",
                "its only chunk is whole",
                "both chunks are whole",
            ],
            [
                "; 0 stray zero bytes",
                "; 1 stray zero byte",
                "; 2 stray zero bytes",
            ],
            [
                "no objects are where its index says; 2 streams end where they should",
                "its only object is where its index says; 2 streams end where they should",
                "both objects are where its index says; 2 streams end where they should",
            ],
            [
                "both objects are where its index says; it holds no streams",
                "both objects are where its index says; 1 stream ends where it should",
                "both objects are where its index says; 2 streams end where they should",
            ],
            [
                "no files decompress and pass their checksums",
                "its only file decompresses and passes its checksum",
                "both files decompress and pass their checksums",
            ],
            [
                "; 0 password-protected parts could not be checked",
                "; 1 password-protected part could not be checked",
                "; 2 password-protected parts could not be checked",
            ],
            [
                "; 0 files use a compression this check does not read",
                "; 1 file uses a compression this check does not read",
                "; 2 files use a compression this check does not read",
            ],
            [
                "a.txt is damaged: it decompresses to 0 bytes, not 9",
                "a.txt is damaged: it decompresses to 1 byte, not 9",
                "a.txt is damaged: it decompresses to 2 bytes, not 9",
            ],
            [
                "its table of contents ends after 0 of its 0 entries",
                "its table of contents ends after 0 of its 1 entry",
                "its table of contents ends after 0 of its 2 entries",
            ],
            [
                "The folder holds more than the 0 files checked; the rest are not listed.",
                "The folder holds more than the 1 file checked; the rest are not listed.",
                "The folder holds more than the 2 files checked; the rest are not listed.",
            ],
        ];
        assert_eq!(cases.len(), expected.len());
        for ((name, got), want) in cases.iter().zip(&expected) {
            for (g, w) in got.iter().zip(want) {
                assert_eq!(g, w, "{name}");
            }
        }
        // Three or more take "all", and no count of one is followed by a plural noun.
        assert_eq!(riff(3), "all 3 chunks are whole");
        for (name, got) in &cases {
            for bad in [
                "all 0 ",
                "all 1 ",
                "all 2 ",
                " 1 bytes",
                " 1 chunks",
                " 1 files",
            ] {
                assert!(!got[1].contains(bad), "{name}: {}", got[1]);
            }
        }
    }
}
