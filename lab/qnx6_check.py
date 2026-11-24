# Checks the qnx6 reader against two other sources for the same image:
#   1. the mkqnximage build lists, 2. a listing taken inside the running target (lab/target/list_files.sh).
# usage: qnx6_check.py DISK_IMAGE BUILD_DIR LIVE_LOG   (prints the report)
import hashlib
import os
import posixpath
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from qnxcbom import buildlist, qnx6  # noqa: E402

disk, build_dir, live_log = sys.argv[1:4]
NAMES = {0xB1: "boot", 0xB2: "system", 0xB3: "data"}
TABLE = []
for n in range(256):
    c = n << 24
    for _ in range(8):
        c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    TABLE.append(c)


def cksum(data):
    """POSIX cksum (what `cksum` prints on the target)."""
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ TABLE[(crc >> 24) ^ b]
    n = len(data)
    while n:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ TABLE[(crc >> 24) ^ (n & 0xFF)]
        n >>= 8
    return ~crc & 0xFFFFFFFF


cache = {}
on_disk = {}   # "/system/bin/sh" -> (size, crc)
print("== 1. what the reader finds in the disk image", os.path.basename(disk))
with open(disk, "rb") as handle:
    for kind, start, length in qnx6.partitions(handle, os.path.getsize(disk)):
        name = NAMES.get(kind, hex(kind))
        fs = qnx6.Qnx6(handle, start, length)
        items = list(fs.walk())
        print(f"partition {name} (type {kind:#x}): block size {fs.bs}, {fs.num_inodes} inodes, "
              + ", ".join(f"{k} {v}" for k, v in sorted(Counter(i[1] for i in items).items())))
        if name in ("system", "data"):
            for path, what, size, node in items:
                if what == "file":
                    data = fs.read(node, 64 * 1024 * 1024)
                    key = hashlib.sha1(data).digest()
                    if key not in cache:
                        cache[key] = cksum(data)
                    on_disk[f"/{name}/{path}"] = (len(data), cache[key])

print("\n== 2. disk image against the build lists (system.build, data.build)")
listed = {}
for part in ("system", "data"):
    with open(os.path.join(build_dir, part + ".build"), encoding="utf-8", errors="replace") as handle:
        for e in buildlist.parse(handle.read()):
            if e.kind in ("file", "inline", "hlink"):
                listed[f"/{part}/{e.dest}"] = e.kind
for part in ("system", "data"):
    disk_set = {p for p in on_disk if p.startswith(f"/{part}/")}
    list_set = {p for p in listed if p.startswith(f"/{part}/")}
    print(f"{part}: on disk {len(disk_set)}, named in the list {len(list_set)}, in both {len(disk_set & list_set)}")
    print(f"  in the list, not on disk: {len(list_set - disk_set)}", sorted(list_set - disk_set)[:12])
    extra = sorted(disk_set - list_set)
    print(f"  on disk, not in the list: {len(extra)}", extra[:12])
    print(f"  list entries of type hard link: {sum(1 for p in list_set if listed[p] == 'hlink')}")

print("\n== 3. disk image against a live listing inside the running QNX 8.0 target (cksum of every file)")
text = open(live_log, encoding="utf-8", errors="replace").read()
body = text.split("=== LIVE-BEGIN", 1)[1].split("=== LIVE-END", 1)[0] if "=== LIVE-BEGIN" in text else ""
live = {}
for line in body.splitlines():
    m = re.fullmatch(r"(\d+) (\d+) (/(?:system|data)/\S.*)", line.strip())
    if m:
        live[m.group(3)] = (int(m.group(2)), int(m.group(1)))
print(f"live files {len(live)}, disk files {len(on_disk)}, in both {len(set(live) & set(on_disk))}")
same = sum(1 for p in set(live) & set(on_disk) if live[p] == on_disk[p])
print(f"same size and checksum: {same} of {len(set(live) & set(on_disk))}")
diff = sorted(p for p in set(live) & set(on_disk) if live[p] != on_disk[p])
print("different content:", len(diff), diff[:12])
print("live only (made or moved while the target ran):", sorted(set(live) - set(on_disk))[:20])
print("disk only:", sorted(set(on_disk) - set(live))[:20])
