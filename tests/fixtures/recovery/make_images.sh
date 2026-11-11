#!/bin/bash
# Builds the file system images for the recovery tests from samples/, and manifest.txt,
# which lists every file the tests check. Run as root in WSL Debian with ntfs-3g,
# dosfstools and exfatprogs installed:  wsl -d Debian -u root -- bash make_images.sh
#
# Manifest lines: image|volume start|path|size|sha256|status, where status is live,
# deleted, or deleted-overwritten-by:<path> / deleted-partly when later files took its space.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
S=$HERE/samples
WORK=$(mktemp -d /tmp/recovery-fixtures.XXXXXX)
MNT=$WORK/mnt
mkdir -p "$MNT"
LOOPS=()
MANIFEST=$WORK/manifest.txt
: >"$MANIFEST"

cleanup() {
    if mountpoint -q "$MNT"; then umount "$MNT"; fi
    for l in "${LOOPS[@]+"${LOOPS[@]}"}"; do release "$l" || true; done
    rm -rf "$WORK"
}

# A FUSE file system lets go of its loop device a moment after unmounting.
release() {
    for _ in $(seq 50); do
        losetup -d "$1" 2>/dev/null && return 0
        sleep 0.2
    done
    echo "could not detach $1" >&2
    return 1
}
trap cleanup EXIT

# Deterministic bytes: gen <seed> <count>
gen() {
    python3 -c 'import random,sys; sys.stdout.buffer.write(random.Random(int(sys.argv[1])).randbytes(int(sys.argv[2])))' "$1" "$2"
}

# record <image> <volume start> <path in volume> <file> <status>
record() {
    echo "$1|$2|$3|$(stat -c %s "$4")|$(sha256sum <"$4" | cut -d' ' -f1)|$5" >>"$MANIFEST"
}

# attach <losetup options> <image>: sets L, and remembers the device for cleanup.
attach() {
    L=$(losetup -f --show "$@")
    LOOPS+=("$L")
}

detach() {
    release "$1"
    local keep=()
    for l in "${LOOPS[@]}"; do [ "$l" != "$1" ] && keep+=("$l"); done
    LOOPS=("${keep[@]+"${keep[@]}"}")
}

# put <image> <start> <source> <path in volume> <status>: copies a file in and records it.
put() {
    mkdir -p "$(dirname "$MNT/$4")"
    cp "$3" "$MNT/$4"
    sync
    record "$1" "$2" "/$4" "$3" "$5"
}

# Fills the volume so the next file can only go where a deleted one was.
fill() {
    dd if=/dev/zero of="$MNT/filler" bs=512 status=none 2>/dev/null || true
    sync
}

# prepare_overwrite <dir>: two files whose space later files will take. The later files
# exist, empty, before the volume fills, so writing them needs data space only.
prepare_overwrite() {
    gen 6 16384 >"$WORK/ow"
    gen 7 16384 >"$WORK/part"
    gen 8 16384 >"$WORK/new1"
    gen 9 8192 >"$WORK/new2"
    mkdir -p "$MNT/$1"
    cp "$WORK/ow" "$MNT/$1/overwritten.bin"
    cp "$WORK/part" "$MNT/$1/partly.bin"
    touch "$MNT/$1/new1.bin" "$MNT/$1/new2.bin"
    sync
}

# finish_overwrite <image> <start> <dir>, on a full volume: a new file takes all of one
# deleted file's space, a smaller one part of the other's.
finish_overwrite() {
    rm "$MNT/$3/overwritten.bin"
    sync
    cp "$WORK/new1" "$MNT/$3/new1.bin"
    sync
    rm "$MNT/$3/partly.bin"
    sync
    cp "$WORK/new2" "$MNT/$3/new2.bin"
    sync
    record "$1" "$2" "/$3/overwritten.bin" "$WORK/ow" "deleted-overwritten-by:/$3/new1.bin"
    record "$1" "$2" "/$3/partly.bin" "$WORK/part" "deleted-partly"
    record "$1" "$2" "/$3/new1.bin" "$WORK/new1" live
    record "$1" "$2" "/$3/new2.bin" "$WORK/new2" live
}

# spacers <dir> <seed>: four 8 KiB files; holes <dir> removes the first and third, so on a
# full volume the next 16 KiB file is split across two holes.
spacers() {
    mkdir -p "$MNT/$1"
    for i in 1 2 3 4; do
        gen $(($2 + i)) 8192 >"$MNT/$1/spacer$i.bin"
        sync
    done
}

holes() {
    rm "$MNT/$1/spacer1.bin" "$MNT/$1/spacer3.bin"
    sync
}

# ---- NTFS ----------------------------------------------------------------------------
img=$WORK/ntfs.img
truncate -s 3M "$img"
mkntfs -F -Q -c 1024 -L fixture "$img" >/dev/null
attach "$img"
ntfs-3g "$L" "$MNT"
put ntfs.img 0 "$S/readme.txt" readme.txt live
put ntfs.img 0 "$S/report.docx" Documents/report.docx live
put ntfs.img 0 "$S/notes.txt" Documents/notes.txt live
put ntfs.img 0 "$S/photo.jpg" Pictures/photo.jpg live
put ntfs.img 0 "$S/image.png" Pictures/Holiday/image.png live
put ntfs.img 0 "$S/tone.wav" Music/tone.wav live
put ntfs.img 0 "$S/anim.gif" Pictures/old.gif deleted
put ntfs.img 0 "$S/letter.pdf" Documents/Old/letter.pdf deleted
printf 'tiny deleted note\n' >"$WORK/tiny"
put ntfs.img 0 "$WORK/tiny" Documents/Old/tiny.txt deleted
spacers Documents 10
spacers Work 20
touch "$MNT/Documents/fragmented.bin" "$MNT/Work/fragmented-deleted.bin"
prepare_overwrite Scratch
fill
holes Documents
gen 31 16384 >"$WORK/frag"
put ntfs.img 0 "$WORK/frag" Documents/fragmented.bin live
holes Work
gen 30 16384 >"$WORK/fragdel"
put ntfs.img 0 "$WORK/fragdel" Work/fragmented-deleted.bin deleted
finish_overwrite ntfs.img 0 Scratch
rm "$MNT/Pictures/old.gif" "$MNT/Work/fragmented-deleted.bin"
rm -r "$MNT/Documents/Old"
sync
umount "$MNT"
detach "$L"
cp "$img" "$HERE/ntfs.img"

# ---- FAT32 ---------------------------------------------------------------------------
img=$WORK/fat32.img
truncate -s 3M "$img"
mkfs.vfat -F 32 -s 1 -S 512 -n FIXTURE "$img" >/dev/null 2>&1
attach "$img"
mount -t vfat "$L" "$MNT"
put fat32.img 0 "$S/holiday.jpg" "DCIM/Holiday photo.jpg" live
put fat32.img 0 "$S/photo.jpg" DCIM/IMG_0001.JPG live
put fat32.img 0 "$S/budget.xlsx" Docs/budget.xlsx live
put fat32.img 0 "$S/contacts.sqlite" Docs/contacts.sqlite live
put fat32.img 0 "$S/bundle.zip" Docs/bundle.zip live
put fat32.img 0 "$S/report.docx" "Docs/Quarterly report.docx" deleted
put fat32.img 0 "$S/anim.gif" DCIM/anim.gif deleted
put fat32.img 0 "$S/clip.mp4" Trip/clip.mp4 deleted
put fat32.img 0 "$S/clip.mov" "Trip/Beach clip.mov" deleted
prepare_overwrite Scratch
fill
finish_overwrite fat32.img 0 Scratch
rm "$MNT/Docs/Quarterly report.docx" "$MNT/DCIM/anim.gif"
rm -r "$MNT/Trip"
sync
umount "$MNT"
detach "$L"
cp "$img" "$HERE/fat32.img"

# ---- FAT16 ---------------------------------------------------------------------------
img=$WORK/fat16.img
truncate -s 3M "$img"
mkfs.vfat -F 16 -s 1 -S 512 -n FIXTURE16 "$img" >/dev/null 2>&1
attach "$img"
mount -t vfat "$L" "$MNT"
put fat16.img 0 "$S/notes.txt" notes.txt live
put fat16.img 0 "$S/photo.jpg" PHOTO.JPG live
put fat16.img 0 "$S/letter.pdf" "Old letter.pdf" deleted
put fat16.img 0 "$S/bundle.zip" Archive/bundle.zip live
put fat16.img 0 "$S/archive.7z" Archive/archive.7z deleted
put fat16.img 0 "$S/archive.rar" Archive/archive.rar live
rm "$MNT/Old letter.pdf" "$MNT/Archive/archive.7z"
sync
umount "$MNT"
detach "$L"
cp "$img" "$HERE/fat16.img"

# ---- exFAT: WSL's kernel has no exFAT driver, so exfat_fixture.py places the files on a
# volume mkfs.exfat made, and fsck.exfat checks the result.
img=$WORK/exfat.img
truncate -s 2M "$img"
mkfs.exfat -b 4K -c 4K -L fixture "$img" >/dev/null
python3 "$HERE/exfat_fixture.py" "$img" "$S" "$MANIFEST"
fsck.exfat -n "$img" >/dev/null
cp "$img" "$HERE/exfat.img"

# ---- MBR disk: a FAT12 partition, and an NTFS one whose entry was deleted and whose first
# boot sector is gone, so only its backup boot sector finds it.
img=$WORK/mbr.img
truncate -s 4M "$img"
printf 'label: dos\nstart=2048, size=2048, type=1\nstart=4096, size=4096, type=7\n' | sfdisk -q "$img"
attach -o $((2048 * 512)) --sizelimit $((2048 * 512)) "$img"
mkfs.vfat -F 12 -n PART1 "$L" >/dev/null
mount -t vfat "$L" "$MNT"
put mbr.img 1048576 "$S/notes.txt" notes.txt live
put mbr.img 1048576 "$S/image.png" image.png deleted
rm "$MNT/image.png"
sync
umount "$MNT"
detach "$L"
attach -o $((4096 * 512)) --sizelimit $((4096 * 512)) "$img"
mkntfs -F -Q -c 1024 -p 4096 -L lost "$L" >/dev/null
ntfs-3g "$L" "$MNT"
put mbr.img 2097152 "$S/report.docx" Documents/report.docx live
put mbr.img 2097152 "$S/letter.pdf" letter.pdf deleted
rm "$MNT/letter.pdf"
sync
umount "$MNT"
detach "$L"
sfdisk -q --delete "$img" 2
dd if=/dev/zero of="$img" bs=512 seek=4096 count=1 conv=notrunc status=none
cp "$img" "$HERE/mbr.img"

# ---- GPT disk: two FAT12 partitions, the second one's entry deleted.
img=$WORK/gpt.img
truncate -s 3M "$img"
printf 'label: gpt\nstart=2048, size=2048, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\nstart=4096, size=2014, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n' | sfdisk -q "$img"
attach -o $((2048 * 512)) --sizelimit $((2048 * 512)) "$img"
mkfs.vfat -F 12 -n GPT1 "$L" >/dev/null
mount -t vfat "$L" "$MNT"
put gpt.img 1048576 "$S/photo.jpg" photo.jpg live
umount "$MNT"
detach "$L"
attach -o $((4096 * 512)) --sizelimit $((2014 * 512)) "$img"
mkfs.vfat -F 12 -n LOST "$L" >/dev/null
mount -t vfat "$L" "$MNT"
put gpt.img 2097152 "$S/holiday.jpg" holiday.jpg live
put gpt.img 2097152 "$S/tone.wav" tone.wav deleted
rm "$MNT/tone.wav"
sync
umount "$MNT"
detach "$L"
sfdisk -q --delete "$img" 2
cp "$img" "$HERE/gpt.img"

cp "$MANIFEST" "$HERE/manifest.txt"
ls -l "$HERE"/*.img
