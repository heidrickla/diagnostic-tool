# Recovery fixtures

Small disk and volume images for the deleted and lost file recovery tests in `tests/recovery.rs`, and the sample files they hold.

## Making them

1. `python make_samples.py` (Windows, with ffmpeg on PATH and 7-Zip installed) writes `samples/`.
2. `wsl -d Debian -u root -- bash make_images.sh` (WSL Debian with `ntfs-3g`, `dosfstools` and `exfatprogs`) writes the images and `manifest.txt`. It loop-mounts each image as root, and unmounts and detaches every loop device it set up.

WSL's kernel has no exFAT driver, so `exfat_fixture.py` places the exFAT image's files itself on a volume `mkfs.exfat` made, deleting the way Windows does (entry set in-use bits and bitmap cleared, FAT chain left), and `fsck.exfat` checks the result. RAR has no free encoder, so `make_samples.py` writes a stored RAR5 archive to the format's specification.

`manifest.txt` lists every file the tests check, one per line: image, volume start in bytes, path, size, SHA-256 and status. The status is `live`, `deleted`, `deleted-overwritten-by:<path>` (a later file took all its space, so recovery returns that file's bytes) or `deleted-partly` (a later file took part of it).

## Images

| Image | Size | Holds |
|---|---|---|
| `ntfs.img` | 3 MiB | NTFS, 1 KiB clusters. In use: `readme.txt` (resident in its record), `Documents/report.docx`, `notes.txt`, `fragmented.bin` (split across two holes), `Pictures/photo.jpg`, `Pictures/Holiday/image.png`, `Music/tone.wav`. Deleted: `Pictures/old.gif`, the folder `Documents/Old` with `letter.pdf` and `tiny.txt` (resident), `Work/fragmented-deleted.bin` (split across two holes). `Scratch/overwritten.bin` and `partly.bin` deleted on a full volume and their space taken by `new1.bin` (all) and `new2.bin` (half). A zero-filled `filler` fills the rest. |
| `fat32.img` | 3 MiB | FAT32, 512-byte clusters. In use: `DCIM/Holiday photo.jpg` (long name), `DCIM/IMG_0001.JPG`, `Docs/budget.xlsx`, `contacts.sqlite`, `bundle.zip`. Deleted: `Docs/Quarterly report.docx` (long name), `DCIM/anim.gif`, the folder `Trip` with `clip.mp4` and `Beach clip.mov`. `Scratch` and `filler` as on NTFS. |
| `fat16.img` | 3 MiB | FAT16 with a fixed root folder. In use: `notes.txt`, `PHOTO.JPG`, `Archive/bundle.zip`, `archive.rar`. Deleted: `Old letter.pdf` in the root, `Archive/archive.7z`. |
| `exfat.img` | 2 MiB | exFAT, 4 KiB clusters. In use: `Videos/clip.avi`, `still.webp`, `Docs/minutes.odt`, `Docs/chained.bin` (FAT chain around a gap). Deleted: `Videos/clip.mp4` (NoFatChain), the folder `Old` with `report.docx`, `Work/chained-deleted.bin` (FAT chain kept). `Scratch` as on NTFS. |
| `mbr.img` | 4 MiB | MBR disk. Partition 1 at 1 MiB: FAT12 with `notes.txt`, deleted `image.png`. At 2 MiB an NTFS volume whose partition entry was deleted and whose first boot sector is zeroed, so only its backup boot sector finds it: `Documents/report.docx`, deleted `letter.pdf`. |
| `gpt.img` | 3 MiB | GPT disk. Partition 1 at 1 MiB: FAT12 with `photo.jpg`. At 2 MiB a FAT12 volume whose partition entry was deleted: `holiday.jpg`, deleted `tone.wav`. |

## Samples

`samples/` holds the files put in the images and laid end to end with junk for the carving tests: `photo.jpg`, `holiday.jpg`, `image.png`, `anim.gif` (three frames), `picture.bmp`, `still.webp`, `clip.mp4`, `clip.mov`, `clip.avi` (MJPEG), `tone.wav` (from ffmpeg's test sources); `letter.pdf`, `report.docx`, `budget.xlsx`, `minutes.odt`, `bundle.zip`, `contacts.sqlite` (200 rows), `archive.rar`, `notes.txt`, `readme.txt`, `random.bin` (written by `make_samples.py`); `archive.7z` (7-Zip, holding `letter.pdf` and `tone.wav`).
