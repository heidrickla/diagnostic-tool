"""Puts files into, and deletes files from, an exFAT image that mkfs.exfat made.

WSL's kernel has no exFAT driver, so this writes entry sets, the allocation bitmap and
the FAT itself, to the exFAT specification, and deletes the way Windows does: the entry
set's in-use bits and the bitmap are cleared, the FAT chain is left. fsck.exfat checks
the result. Usage: exfat_fixture.py <image> <samples dir> <manifest to append to>
"""

import hashlib
import os
import random
import struct
import sys

STAMP = (2026 - 1980) << 25 | 11 << 21 | 6 << 16 | 14 << 11 | 3 << 5  # 2026-11-06 14:03


class Volume:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.img = bytearray(f.read())
        b = self.img
        sector = 1 << b[0x6C]
        self.cluster = sector << b[0x6D]
        self.fat_at = struct.unpack_from("<I", b, 0x50)[0] * sector
        self.heap = struct.unpack_from("<I", b, 0x58)[0] * sector
        self.count = struct.unpack_from("<I", b, 0x5C)[0]
        self.root = struct.unpack_from("<I", b, 0x60)[0]
        # The bitmap's own entry in the root folder.
        root = self.read_cluster(self.root)
        for i in range(0, self.cluster, 32):
            if root[i] == 0x81:
                self.bitmap_cluster = struct.unpack_from("<I", root, i + 0x14)[0]
            if root[i] == 0x82:
                self.upcase_cluster = struct.unpack_from("<I", root, i + 0x14)[0]
        # Folders: path -> (first cluster); the root's entries live in its own cluster.
        self.dirs = {"": self.root}
        self.entries = {}  # path -> (dir cluster, entry offset, entry count, clusters)

    def at(self, n):
        return self.heap + (n - 2) * self.cluster

    def read_cluster(self, n):
        return self.img[self.at(n):self.at(n) + self.cluster]

    def bitmap_bit(self, n, value):
        byte = self.at(self.bitmap_cluster) + (n - 2) // 8
        if value:
            self.img[byte] |= 1 << ((n - 2) % 8)
        else:
            self.img[byte] &= ~(1 << ((n - 2) % 8)) & 0xFF

    def used(self, n):
        byte = self.at(self.bitmap_cluster) + (n - 2) // 8
        return self.img[byte] >> ((n - 2) % 8) & 1

    def fat(self, n, value):
        struct.pack_into("<I", self.img, self.fat_at + 4 * n, value)

    def free_run(self, need, start=2):
        n = start
        while n + need <= self.count + 2:
            if all(not self.used(c) for c in range(n, n + need)):
                return list(range(n, n + need))
            n += 1
        raise SystemExit("exFAT image is full")

    def take(self, clusters, chained):
        for c in clusters:
            self.bitmap_bit(c, 1)
        if chained:
            for a, b in zip(clusters, clusters[1:]):
                self.fat(a, b)
            self.fat(clusters[-1], 0xFFFFFFFF)

    def write_data(self, clusters, data):
        for i, c in enumerate(clusters):
            piece = data[i * self.cluster:(i + 1) * self.cluster]
            self.img[self.at(c):self.at(c) + len(piece)] = piece

    def name_hash(self, name):
        h = 0
        for ch in name.upper().encode("utf-16-le"):
            h = ((h << 15) | (h >> 1)) + ch & 0xFFFF
        return h

    def add_entry(self, parent, name, attr, first, length, contiguous):
        units = name.encode("utf-16-le")
        names = (len(name) + 14) // 15
        entries = bytearray(32 * (2 + names))
        entries[0] = 0x85
        entries[1] = 1 + names
        struct.pack_into("<H", entries, 4, attr)
        for off in (8, 12, 16):
            struct.pack_into("<I", entries, off, STAMP)
        s = entries[32:64]
        s[0] = 0xC0
        s[1] = 0x01 | (0x02 if contiguous else 0)
        s[3] = len(name)
        struct.pack_into("<H", s, 4, self.name_hash(name))
        struct.pack_into("<Q", s, 8, length)
        struct.pack_into("<I", s, 0x14, first)
        struct.pack_into("<Q", s, 0x18, length)
        entries[32:64] = s
        for i in range(names):
            e = 64 + 32 * i
            entries[e] = 0xC1
            chunk = units[30 * i:30 * (i + 1)]
            entries[e + 2:e + 2 + len(chunk)] = chunk
        checksum = 0
        for i, b in enumerate(entries):
            if i in (2, 3):
                continue
            checksum = (((checksum << 15) | (checksum >> 1)) + b) & 0xFFFF
        struct.pack_into("<H", entries, 2, checksum)
        # First free slot in the parent's one cluster.
        base = self.at(self.dirs[parent])
        slot = 0
        while self.img[base + slot] != 0:
            slot += 32
        if slot + len(entries) > self.cluster:
            raise SystemExit("folder is full")
        self.img[base + slot:base + slot + len(entries)] = entries
        return (self.dirs[parent], slot, len(entries) // 32)

    def mkdir(self, path):
        parent, name = os.path.split(path)
        clusters = self.free_run(1)
        self.take(clusters, chained=False)
        self.write_data(clusters, bytes(self.cluster))
        where = self.add_entry(parent, name, 0x10, clusters[0], self.cluster, True)
        self.dirs[path] = clusters[0]
        self.entries[path] = (where, clusters)

    def put(self, path, data, clusters=None):
        parent, name = os.path.split(path)
        need = max(1, -(-len(data) // self.cluster))
        if clusters is None:
            clusters = self.free_run(need)
        contiguous = clusters == list(range(clusters[0], clusters[0] + len(clusters)))
        self.take(clusters, chained=not contiguous)
        self.write_data(clusters, data)
        where = self.add_entry(parent, name, 0x20, clusters[0], len(data), contiguous)
        self.entries[path] = (where, clusters)
        return clusters

    def delete(self, path):
        for child in [p for p in self.entries if p.startswith(path + "/")]:
            self.delete(child)
        (cluster, slot, count), clusters = self.entries.pop(path)
        base = self.at(cluster) + slot
        for i in range(count):
            self.img[base + 32 * i] &= 0x7F
        for c in clusters:
            self.bitmap_bit(c, 0)

    def save(self):
        with open(self.path, "wb") as f:
            f.write(self.img)


def main():
    image, samples, manifest = sys.argv[1:4]
    v = Volume(image)
    lines = []
    name = os.path.basename(image)

    def record(path, data, status):
        lines.append("%s|0|/%s|%d|%s|%s" % (name, path, len(data), hashlib.sha256(data).hexdigest(), status))

    def sample(n):
        with open(os.path.join(samples, n), "rb") as f:
            return f.read()

    def gen(seed, n):
        return random.Random(seed).randbytes(n)

    for d in ["Videos", "Docs", "Old", "Work", "Scratch"]:
        v.mkdir(d)
    for path, src, status in [
        ("Videos/clip.avi", "clip.avi", "live"),
        ("still.webp", "still.webp", "live"),
        ("Docs/minutes.odt", "minutes.odt", "live"),
        ("Videos/clip.mp4", "clip.mp4", "deleted"),
        ("Old/report.docx", "report.docx", "deleted"),
    ]:
        data = sample(src)
        v.put(path, data)
        record(path, data, status)
    # Two files whose clusters are split around others, so their FAT chains matter.
    for path, data, status in [
        ("Docs/chained.bin", sample("random.bin"), "live"),
        ("Work/chained-deleted.bin", gen(60, 20480), "deleted"),
    ]:
        need = -(-len(data) // v.cluster)
        first = v.free_run(2)
        v.take(first[1:], chained=False)  # a one-cluster gap after the first cluster
        rest = v.free_run(need - 1)
        clusters = [first[0]] + rest
        v.put(path, data, clusters)
        for c in first[1:]:
            v.bitmap_bit(c, 0)
        record(path, data, status)
    ow, part, new1, new2 = gen(6, 16384), gen(7, 16384), gen(8, 16384), gen(9, 8192)
    ow_clusters = v.put("Scratch/overwritten.bin", ow)
    part_clusters = v.put("Scratch/partly.bin", part)
    v.delete("Scratch/overwritten.bin")
    v.put("Scratch/new1.bin", new1, ow_clusters)
    v.delete("Scratch/partly.bin")
    v.put("Scratch/new2.bin", new2, part_clusters[:2])
    record("Scratch/overwritten.bin", ow, "deleted-overwritten-by:/Scratch/new1.bin")
    record("Scratch/partly.bin", part, "deleted-partly")
    record("Scratch/new1.bin", new1, "live")
    record("Scratch/new2.bin", new2, "live")
    v.delete("Videos/clip.mp4")
    v.delete("Work/chained-deleted.bin")
    v.delete("Old")
    v.save()
    with open(manifest, "a", newline="\n") as f:
        f.write("".join(line + "\n" for line in lines))


if __name__ == "__main__":
    main()
