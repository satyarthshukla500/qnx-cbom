# Tests for the build-list parser, safe path resolver, ELF reader, version strings and config parsers.
import os
import tempfile
import unittest

from fixtures import make_elf, tmpdir
from qnxcbom import buildlist, configs, elf, libinfo, safepath


class BuildListTests(unittest.TestCase):
    def test_entries(self):
        text = ("# comment\n[uid=0 gid=0 perms=644]\n[+dupignore]\nbin/ls=usr/bin/ls\n[type=hlink] bin/cp=toybox\n"
                "[type=link] lib/a.so=a.so.1\n[type=dir] /etc\n/lib/x.so = lib/x.so\nlone/path\n")
        got = [(e.dest, e.src, e.kind) for e in buildlist.parse(text)]
        self.assertEqual(got, [("bin/ls", "usr/bin/ls", "file"), ("bin/cp", "toybox", "hlink"), ("lib/a.so", "a.so.1", "link"),
                               ("etc", "/etc", "dir"), ("lib/x.so", "lib/x.so", "file"), ("lone/path", "lone/path", "file")])

    def test_inline_block(self):
        entries = buildlist.parse("[perms=444] etc/ssh/sshd_config={\nA b\n# c\n}\nbin/x=bin/x\n")
        self.assertEqual(entries[0].kind, "inline")
        self.assertEqual(entries[0].text, "A b\n# c\n")
        self.assertEqual(entries[1].dest, "bin/x")

    def test_unclosed_block(self):
        with self.assertRaises(buildlist.BuildListError):
            buildlist.parse("etc/x={\nline\n")

    def test_garbage_does_not_crash(self):
        buildlist.parse("\x00\x01 = = =\n[[[ ]]]\n={\n}\n")


class SafePathTests(unittest.TestCase):
    def test_inside_outside_links(self):
        with tmpdir() as tmp:
            root = os.path.join(tmp, "root")
            outside = os.path.join(tmp, "outside.txt")
            os.makedirs(root)
            open(outside, "w").write("x")
            open(os.path.join(root, "ok.txt"), "w").write("x")
            os.symlink(outside, os.path.join(root, "link.txt"))
            os.symlink("/etc", os.path.join(root, "etc_link"))
            os.mkfifo(os.path.join(root, "fifo"))
            roots = safepath.Roots([root])
            self.assertEqual(roots.resolve("ok.txt")[0], os.path.realpath(os.path.join(root, "ok.txt")))
            self.assertEqual(roots.resolve("../outside.txt"), (None, "outside"))
            self.assertEqual(roots.resolve("link.txt"), (None, "outside"))
            self.assertEqual(roots.resolve("etc_link/passwd"), (None, "outside"))
            self.assertEqual(roots.resolve("/etc/passwd"), (None, "outside"))
            self.assertEqual(roots.resolve("fifo"), (None, "not-file"))
            self.assertEqual(roots.resolve("nothing"), (None, "missing"))
            self.assertEqual(roots.resolve("a\0b"), (None, "outside"))


class ElfTests(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryFile() as handle:
            handle.write(data)
            return elf.read_elf(handle, len(data))

    def test_needed_soname_interp(self):
        info = self.read(make_elf(["libcrypto.so.3", "libc.so.6"], "libx.so.1", False))
        self.assertEqual((info["needed"], info["soname"], info["has_interp"]), (["libcrypto.so.3", "libc.so.6"], "libx.so.1", False))
        self.assertTrue(self.read(make_elf(["libc.so.6"], None, True))["has_interp"])

    def test_not_elf(self):
        self.assertIsNone(self.read(b"hello world" * 20))

    def test_truncated_and_hostile(self):
        good = make_elf(["libcrypto.so.3"], None, True)
        for cut in (70, 100, 200, len(good) - 10):
            with self.assertRaises(elf.ElfError):
                self.read(good[:cut])
        bad = bytearray(good)
        bad[56:58] = (60000).to_bytes(2, "little")  # e_phnum far too big
        with self.assertRaises(elf.ElfError):
            self.read(bytes(bad))
        bad = bytearray(good)
        bad[32:40] = (2 ** 62).to_bytes(8, "little")  # program header offset outside the file
        with self.assertRaises(elf.ElfError):
            self.read(bytes(bad))
        with self.assertRaises(elf.ElfError):  # 32-bit class
            self.read(b"\x7fELF\x01\x01\x01" + bytes(100))


class LibInfoTests(unittest.TestCase):
    def test_strings(self):
        self.assertEqual(libinfo.openssl_version(b"x OpenSSL 3.5.9 29 Sep 2026 y"), ("3.5.9", "29 Sep 2026"))
        self.assertEqual(libinfo.openssl_version(b"OpenSSL 3.0 FIPS"), (None, None))
        self.assertTrue(libinfo.pq_capable(b"..ML-KEM-768.."))
        self.assertFalse(libinfo.pq_capable(b"nothing here"))
        self.assertEqual(libinfo.openssh_version(b"OpenSSH_10.4p1"), "10.4p1")
        self.assertEqual(libinfo.ssh_pq_kex(b"mlkem768x25519-sha256"), ["mlkem768x25519-sha256"])


class ConfigTests(unittest.TestCase):
    def test_qcrypto(self):
        got = configs.parse_qcrypto("# c\nopenssl-3 tags=a,b\nother tags=*  # tail\n\nbare\n")
        self.assertEqual(got, [{"plugin": "openssl-3", "tags": ["a", "b"]}, {"plugin": "other", "tags": ["*"]}, {"plugin": "bare", "tags": []}])

    def test_sshd(self):
        text = "kexalgorithms =+mlkem768x25519-sha256\nHostKey /a\nKexAlgorithms other\nCiphers a,b\nMatch User x\nMACs hidden\n"
        got = configs.parse_ssh_config(text, True)
        self.assertEqual(got["settings"]["KexAlgorithms"]["mode"], "add")  # first line wins
        self.assertEqual(got["settings"]["KexAlgorithms"]["items"], ["mlkem768x25519-sha256"])
        self.assertNotIn("MACs", got["settings"])
        self.assertEqual((got["host_keys"], got["match_blocks"]), (["/a"], 1))

    def test_ssh_client_host_blocks(self):
        got = configs.parse_ssh_config("Host *\nKexAlgorithms ^x\nHost other\nCiphers z\n", False)
        self.assertEqual(got["settings"]["KexAlgorithms"]["mode"], "prepend")
        self.assertNotIn("Ciphers", got["settings"])


if __name__ == "__main__":
    unittest.main()
