"""Makes the sample files the recovery fixtures hold, into samples/.

Pictures, video and sound come from ffmpeg's test sources; the 7z archive from 7-Zip;
documents, archives and the database are written here with the standard library. RAR has
no free encoder, so a stored RAR5 archive is written by hand to the format's specification.
Run once with ffmpeg and 7z on PATH (or 7-Zip installed); the outputs are committed.
"""

import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "samples")


def ffmpeg(*args):
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", *args], check=True)


def media():
    src = ["-f", "lavfi", "-i"]
    ffmpeg(*src, "testsrc=size=160x120:rate=1", "-frames:v", "1", "-q:v", "5", p("photo.jpg"))
    ffmpeg(*src, "testsrc2=size=320x240:rate=1", "-frames:v", "1", "-q:v", "3", p("holiday.jpg"))
    ffmpeg(*src, "testsrc=size=64x48:rate=1", "-frames:v", "1", p("image.png"))
    ffmpeg(*src, "testsrc=size=32x24:rate=4", "-frames:v", "3", p("anim.gif"))
    ffmpeg(*src, "testsrc=size=32x24:rate=1", "-frames:v", "1", p("picture.bmp"))
    ffmpeg(*src, "testsrc=size=48x32:rate=1", "-frames:v", "1", p("still.webp"))
    ffmpeg(*src, "testsrc=size=64x48:rate=10", "-t", "0.5", "-pix_fmt", "yuv420p",
           "-c:v", "libx264", "-preset", "ultrafast", p("clip.mp4"))
    ffmpeg(*src, "testsrc=size=64x48:rate=10", "-t", "0.5", "-pix_fmt", "yuv420p",
           "-c:v", "libx264", "-preset", "ultrafast", p("clip.mov"))
    ffmpeg(*src, "testsrc=size=32x24:rate=5", "-t", "0.4", "-c:v", "mjpeg", p("clip.avi"))
    ffmpeg(*src, "sine=frequency=440:sample_rate=8000:duration=0.25", "-ac", "1",
           p("tone.wav"))


def p(name):
    return os.path.join(OUT, name)


def pdf():
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        None,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    text = b"BT /F1 12 Tf 20 50 Td (Recovered letter) Tj ET"
    objs[3] = b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream"
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    with open(p("letter.pdf"), "wb") as f:
        f.write(out)


CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/{part}" ContentType="{ctype}"/></Types>'
)
RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/officeDocument" Target="{part}"/></Relationships>'
)


def office(name, part, ctype, body):
    with zipfile.ZipFile(p(name), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES.format(part=part, ctype=ctype))
        z.writestr("_rels/.rels", RELS.format(part=part))
        z.writestr(part, body)


def documents():
    office(
        "report.docx",
        "word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly report</w:t></w:r>'
        "</w:p></w:body></w:document>",
    )
    office(
        "budget.xlsx",
        "xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main"><sheets/></workbook>',
    )
    with zipfile.ZipFile(p("minutes.odt"), "w") as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text", zipfile.ZIP_STORED)
        z.writestr("content.xml", "<office:document-content/>", zipfile.ZIP_DEFLATED)
        z.writestr("META-INF/manifest.xml", "<manifest:manifest/>", zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(p("bundle.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", "first file in the bundle\n" * 20)
        z.writestr("b/c.txt", "second file\n" * 50)
    db = p("contacts.sqlite")
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE contact (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)")
    con.executemany(
        "INSERT INTO contact (name, phone) VALUES (?, ?)",
        [("Person %d" % i, "555-%04d" % i) for i in range(200)],
    )
    con.commit()
    con.close()


def vint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def rar_block(body):
    head = vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(head)) + head


def rar():
    data = b"stored in a RAR5 archive\n" * 8
    name = b"inside.txt"
    main = rar_block(vint(1) + vint(0) + vint(0))
    file_body = (
        vint(2)  # file header
        + vint(0x0002)  # data area present
        + vint(len(data))
        + vint(0x0004)  # data CRC32 present
        + vint(len(data))  # unpacked size
        + vint(0x20)  # attributes
        + struct.pack("<I", zlib.crc32(data))
        + vint(0)  # stored, version 0
        + vint(0)  # host OS Windows
        + vint(len(name))
        + name
    )
    end = rar_block(vint(5) + vint(0) + vint(0))
    with open(p("archive.rar"), "wb") as f:
        f.write(b"Rar!\x1a\x07\x01\x00" + main + rar_block(file_body) + data + end)


def seven_zip():
    exe = shutil.which("7z") or r"C:\Program Files\7-Zip\7z.exe"
    target = p("archive.7z")
    if os.path.exists(target):
        os.remove(target)
    subprocess.run([exe, "a", "-bd", "-y", target, p("letter.pdf"), p("tone.wav")],
                   check=True, stdout=subprocess.DEVNULL)


def text():
    with open(p("notes.txt"), "wb") as f:
        f.write(b"".join(b"Line %04d of the notes file.\r\n" % i for i in range(300)))
    with open(p("readme.txt"), "wb") as f:
        f.write(b"A small file that NTFS keeps inside its file record.\r\n")
    # Pseudo-random so a wrong cluster can never look right.
    state, out = 12345, bytearray()
    for _ in range(40960):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(state >> 16 & 0xFF)
    with open(p("random.bin"), "wb") as f:
        f.write(out)


def main():
    os.makedirs(OUT, exist_ok=True)
    media()
    pdf()
    documents()
    rar()
    seven_zip()
    text()
    for name in sorted(os.listdir(OUT)):
        print(name, os.path.getsize(p(name)))


if __name__ == "__main__":
    sys.exit(main())
