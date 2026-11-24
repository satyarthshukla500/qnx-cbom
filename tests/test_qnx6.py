# Tests for the qnx6 reader and --disk, using small images made with mkqnx6fsimg
# (needs the QNX SDP environment; without it these tests are skipped and say so).
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from fixtures import make_elf, make_image, tmpdir
from qnxcbom import qnx6
from test_product import run_cli, scan_args

HAVE_TOOL = shutil.which("mkqnx6fsimg") is not None
LONG = "etc/" + "long_name_" * 5 + "end.conf"      # longer than 27 characters: stored in the long-name file
BIG = random.Random(7).randbytes(3 * 1024 * 1024)  # more than the direct blocks hold: needs indirect blocks


def make_part(tmp, name, files, links=(), sectors=40960):
    """files: {path in image: bytes}. Returns the path of the qnx6 image."""
    lines = [f"[num_inodes=*200]", f"[num_sectors=*{sectors}]", "[uid=0 gid=0 perms=0755]"]
    for path, data in files.items():
        src = os.path.join(tmp, name + "-src", path)
        os.makedirs(os.path.dirname(src), exist_ok=True)
        with open(src, "wb") as handle:
            handle.write(data)
        lines.append(f"{path}={src}")
    for path, target in links:
        lines.append(f"[type=link] {path}={target}")
    listing, out = os.path.join(tmp, name + ".build"), os.path.join(tmp, name + ".img")
    with open(listing, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    subprocess.run(["mkqnx6fsimg", listing, out], check=True, capture_output=True, timeout=120)
    return out


def make_disk(tmp, parts):
    """MBR + partitions, the layout mkqnximage uses. parts: [(type, image path)]."""
    mbr, body, sector = bytearray(512), b"", 1
    for i, (kind, path) in enumerate(parts):
        data = open(path, "rb").read()
        data += bytes(-len(data) % 512)
        mbr[446 + 16 * i:462 + 16 * i] = bytes(4) + bytes([kind]) + bytes(3) + struct.pack("<II", sector, len(data) // 512)
        body += data
        sector += len(data) // 512
    mbr[510:512] = b"\x55\xaa"
    out = os.path.join(tmp, "disk.img")
    with open(out, "wb") as handle:
        handle.write(bytes(mbr) + body)
    return out


@unittest.skipUnless(HAVE_TOOL, "mkqnx6fsimg not found (source the QNX SDP environment)")
class Qnx6Tests(unittest.TestCase):
    def test_reads_files_names_links_and_big_files(self):
        with tmpdir() as tmp:
            files = {"bin/sshd": make_elf(["libcrypto.so.3"]), LONG: b"long name content\n", "a/b/c/deep.txt": b"deep\n",
                     "lib/big.bin": BIG, "empty": b""}
            part = make_part(tmp, "p", files, links=[("bin/ssh", "sshd")])
            with open(part, "rb") as handle:
                fs = qnx6.Qnx6(handle, 0, os.path.getsize(part))
                found = {path: (kind, node) for path, kind, size, node in fs.walk()}
                for path, data in files.items():
                    self.assertEqual(found[path][0], "file", path)
                    self.assertEqual(hashlib.sha1(fs.read(found[path][1], 1 << 30)).digest(), hashlib.sha1(data).digest(), path)
                self.assertEqual(found["bin/ssh"][0], "link")
                self.assertEqual({found[d][0] for d in ("a", "a/b", "etc")}, {"dir"})

    def test_hostile_images_fail_cleanly(self):
        with tmpdir() as tmp:
            part = make_part(tmp, "p", {"bin/sshd": make_elf(), LONG: b"x", "lib/big.bin": BIG})
            good = open(part, "rb").read()
            with self.assertRaises(qnx6.Qnx6Error):
                qnx6.Qnx6(io.BytesIO(bytes(len(good))), 0, len(good))   # no superblock
            with self.assertRaises(qnx6.Qnx6Error):
                qnx6.Qnx6(io.BytesIO(good[:0x1000]), 0, 0x1000)         # cut off before the superblock
            rng = random.Random(1)
            for _ in range(60):                                         # damaged copies: an error or a listing, never anything else
                bad = bytearray(good[:600_000])
                for _ in range(40):
                    bad[rng.randrange(0x2000, len(bad))] = rng.randrange(256)
                try:
                    fs = qnx6.Qnx6(io.BytesIO(bytes(bad)), 0, len(bad))
                    for _, _, _, node in fs.walk():
                        fs.read(node, 1 << 20)
                except qnx6.Qnx6Error:
                    pass

    def test_scan_reads_the_disk_and_falls_back_per_partition(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            sshd = make_elf(["libcrypto.so.3", "libc.so.6"], None, True, b"\0OpenSSH_10.4p1 mlkem768x25519-sha256\0")
            system = make_part(tmp, "sys", {"bin/sshd": sshd, "etc/pam/sshd": b"auth required pam_unix.so\n", "bin/extra": make_elf(["libc.so.6"])})
            data = make_part(tmp, "dat", {"var/note.txt": b"hello\n"})
            disk = make_disk(tmp, [(0xB2, system), (0xB3, data)])
            out = os.path.join(tmp, "a.json")
            code, _, err = run_cli(*scan_args(ifs, build, proj, "--disk", disk, "--json", out))
            scan = json.load(open(out))
            self.assertEqual(scan["image"]["sources"], {"data": "disk image", "system": "disk image"}, err)
            ids = {e["id"] for e in scan["elfs"]}
            self.assertIn("system:bin/extra", ids)                       # on the disk, not in the build list
            self.assertFalse([f for f in scan["findings"] if f["rule"] == "QCB-008"])   # the PAM file named sshd is not a program
            # a data partition that cannot be read: the build list is used for it and the report says so
            raw = bytearray(open(disk, "rb").read())
            at = len(raw) - os.path.getsize(data)
            raw[at + 0x2000:at + 0x2004] = bytes(4)
            with open(disk, "wb") as handle:
                handle.write(raw)
            code, _, err = run_cli(*scan_args(ifs, build, proj, "--disk", disk, "--json", out))
            scan = json.load(open(out))
            self.assertEqual(scan["image"]["sources"]["system"], "disk image")
            self.assertTrue(scan["image"]["sources"]["data"].startswith("build list"))
            self.assertTrue(any("data partition" in n for n in scan["notes"]))

    def test_disk_errors_are_one_line(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            junk = os.path.join(tmp, "junk")
            open(junk, "wb").write(b"not a disk" * 100)
            code, _, err = run_cli(*scan_args(ifs, build, proj, "--disk", junk))
            self.assertEqual(code, 2)
            self.assertTrue(err.startswith("qnx-cbom: error:") and err.count("\n") == 1, err)
            self.assertEqual(run_cli(*scan_args(ifs, build, proj, "--disk", os.path.join(tmp, "missing")))[0], 2)


if __name__ == "__main__":
    unittest.main()
