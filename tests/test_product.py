# End-to-end tests: keys, rules, outputs, command line, diff, hostile input.
import io
import json
import os
import re
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date

from fixtures import generate_keys, make_elf, make_image, tmpdir
from qnxcbom import cbom, cli, keys, report, rules, runtime, image, safepath

MARKER = "UNIQUE-SECRET-MARKER-12345"


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


def scan_args(ifs, build, proj, *extra):
    return ["scan", "--ifs-dir", ifs, "--build-dir", build, "--project-dir", proj, "--sdk-root", os.path.join(proj, "sdk"),
            "--date", "2026-11-23", *extra]


class KeyTests(unittest.TestCase):
    def test_real_keys(self):
        with tmpdir() as tmp:
            made = generate_keys(tmp)
            if not made:
                self.skipTest("openssl or ssh-keygen missing")
            def one(name):
                return keys.summarize(open(made[name], "rb").read())[0]
            self.assertEqual((one("rsa.key")["algorithm"], one("rsa.key")["size"], one("rsa.key")["kind"]), ("RSA", 2048, "private-key"))
            self.assertEqual((one("ec.key")["algorithm"], one("ec.key")["curve"]), ("EC", "P-256"))
            self.assertEqual(one("ed.key")["algorithm"], "Ed25519")
            cert = one("cert.pem")
            self.assertEqual((cert["kind"], cert["subject"], cert["algorithm"]), ("certificate", "test.example", "EC"))
            self.assertRegex(cert["not_after"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
            self.assertEqual(one("rsa.pub.pem")["size"], 2048)
            self.assertEqual(one("ssh_host_ed25519_key")["algorithm"], "Ed25519")
            self.assertEqual(one("ssh_host_rsa_key.pub")["size"], 2048)
            self.assertEqual((one("ssh_host_ecdsa_key.pub")["algorithm"], one("ssh_host_ecdsa_key.pub")["curve"]), ("EC", "P-384"))
            self.assertEqual(one("ssh_host_rsa_key")["size"], 2048)  # OpenSSH private format

    def test_garbage(self):
        for raw in (b"", b"-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
                    b"ssh-rsa AAAA x", os.urandom(5000)):
            keys.summarize(raw)  # must not raise


class RuleTests(unittest.TestCase):
    def model(self, **kw):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp, **kw)
            m = image.scan_image(ifs, build, safepath.Roots([proj, os.path.join(proj, "sdk")]), "t", "x86_64", "ifs")
        m.update({"scan_date": "2026-11-23", "runtime": None})
        return m

    def verdicts(self, m, today=date(2026, 11, 23)):
        rules.evaluate(m, today)
        return {(f["rule"], f["subject"]): f["severity"] for f in m["findings"]}

    def test_eol_depends_on_date(self):
        m = self.model()
        self.assertEqual(self.verdicts(m)[("QCB-001", "/proc/boot/libcrypto.so.3")], "UNSAFE")
        self.assertEqual(self.verdicts(m, date(2026, 9, 7))[("QCB-001", "/proc/boot/libcrypto.so.3")], "OK")
        m = self.model(openssl="OpenSSL 3.5.9 29 Sep 2026")
        self.assertEqual(self.verdicts(m)[("QCB-001", "/proc/boot/libcrypto.so.3")], "OK")

    def test_unknown_series_gives_note_not_finding(self):
        m = self.model(openssl="OpenSSL 9.9.9 1 Jan 2030")
        self.assertNotIn(("QCB-001", "/proc/boot/libcrypto.so.3"), self.verdicts(m))
        self.assertTrue(m["notes"])

    def test_sshd_modes(self):
        sev = lambda kex: self.verdicts(self.model(kex=kex)).get(("QCB-002", "/system/bin/sshd"))
        self.assertEqual(sev("KexAlgorithms curve25519-sha256@libssh.org"), "UNSAFE")
        self.assertEqual(sev("KexAlgorithms mlkem768x25519-sha256,curve25519-sha256@libssh.org"), "OK")
        self.assertEqual(sev("KexAlgorithms +mlkem768x25519-sha256"), "OK")
        self.assertEqual(sev("KexAlgorithms -mlkem*,sntrup*"), "UNSAFE")
        self.assertEqual(sev("KexAlgorithms -curve25519-sha256"), "OK")  # default (10.x) still has the PQ default
        self.assertEqual(sev("# no setting"), "OK")
        self.assertEqual(sev("KexAlgorithms mlkem*,curve25519-sha256"), "OK")  # wildcard in an explicit list
        m = self.model(ssh_pq=False)
        self.assertEqual(self.verdicts(m)[("QCB-002", "/system/bin/sshd")], "WARN")

    def test_other_rules_and_summary(self):
        m = self.model(kex="KexAlgorithms mlkem768x25519-sha256")
        m["keys"] = [{"id": "x", "image_path": "/a\x1b]0;PWN\x07.pem", "kind": "private-key", "algorithm": "RSA", "size": 2048, "curve": None,
                      "subject": None, "not_after": None, "quantum_safe": False},
                     {"id": "y", "image_path": "/b", "kind": "public-key", "algorithm": "ML-DSA-65", "size": None, "curve": None,
                      "subject": None, "not_after": None, "quantum_safe": True},
                     {"id": "z", "image_path": "/c", "kind": "private-key", "algorithm": "unreadable", "size": None, "curve": None,
                      "subject": None, "not_after": None, "quantum_safe": False}]
        v = self.verdicts(m)
        self.assertEqual(v[("QCB-003", "/system/bin/ssh")], "OK")
        self.assertEqual(v[("QCB-004", "/a\x1b]0;PWN\x07.pem")], "WARN")
        self.assertEqual(v[("QCB-004", "/b")], "OK")
        self.assertNotIn(("QCB-004", "/c"), v)  # undecidable: no finding, a note instead
        self.assertEqual(v[("QCB-005", "/proc/boot/qcrypto.conf")], "WARN")
        from qnxcbom import summary
        m.update({"tool": {"version": "0"}})
        text = summary.scan_text(m)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\x1b", text)

    def test_runtime_rules(self):
        m = self.model()
        probe = {"schema": "qnx-cbom-probe/1", "probe_version": "0", "target": {}, "scanned": 3, "errors": [],
                 "processes": [{"pid": 7, "name": "/system/bin/openssl", "libs": [
                     {"path": "/data/o35/libcrypto.so.3", "soname": "libcrypto.so.3", "version": "3.5.9", "released": "29 Sep 2026", "pq_capable": True}]},
                     {"pid": 8, "name": "/system/bin/sshd", "libs": [
                         {"path": "/proc/boot/libcrypto.so.3", "soname": "libcrypto.so.3", "version": "3.0.22", "released": None, "pq_capable": False}]}]}
        runtime.merge(m, runtime._check(probe))
        v = self.verdicts(m)
        self.assertEqual(v[("QCB-006", "/data/o35/libcrypto.so.3")], "WARN")
        self.assertEqual(v[("QCB-007", "/data/o35/libcrypto.so.3")], "OK")
        self.assertEqual(v[("QCB-007", "/proc/boot/libcrypto.so.3")], "UNSAFE")
        self.assertNotIn(("QCB-006", "/proc/boot/libcrypto.so.3"), v)

    def test_probe_input_checks(self):
        for bad in ({}, {"schema": "x"}, {"schema": "qnx-cbom-probe/1", "processes": "no"},
                    {"schema": "qnx-cbom-probe/1", "processes": [{"pid": "a", "libs": []}]},
                    {"schema": "qnx-cbom-probe/1", "processes": [{"pid": 1, "name": 5, "libs": []}]}):
            with self.assertRaises(runtime.ProbeFileError):
                runtime._check(bad)

    def test_console_capture(self):
        import zlib
        body = json.dumps({"schema": "qnx-cbom-probe/1", "processes": [], "scanned": 0})
        good = f"noise\r\nCBOM-BEGIN\r\n{body}\r\nCBOM-END len={len(body)} crc32={zlib.crc32(body.encode()):08x}\r\nprompt"
        with tmpdir() as tmp:
            path = os.path.join(tmp, "cap.txt")
            open(path, "w").write(good)
            self.assertEqual(runtime.load(path)["processes"], [])
            open(path, "w").write(good.replace('"scanned": 0', '"scanned": 1'))
            with self.assertRaises(runtime.ProbeFileError):
                runtime.load(path)


class CliTests(unittest.TestCase):
    def test_scan_outputs_and_exit_codes(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            out = lambda n: os.path.join(tmp, n)
            code, text, err = run_cli(*scan_args(ifs, build, proj, "--json", out("a.json"), "--cbom", out("a.cdx.json"), "--html", out("a.html"), "--text", out("a.txt")))
            self.assertEqual((code, err), (1, ""))
            self.assertIn("verdict: UNSAFE", open(out("a.txt")).read())
            scan = json.load(open(out("a.json")))
            self.assertEqual((scan["image"]["counts"]["crypto_elf"], scan["image"]["counts"]["crypto_executables"]), (3, 2))
            bom = json.load(open(out("a.cdx.json")))
            self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.6"))
            ifs2, build2, proj2 = make_image(os.path.join(tmp, "b") if os.makedirs(os.path.join(tmp, "b")) is None else tmp,
                                             openssl="OpenSSL 3.5.9 29 Sep 2026", kex="KexAlgorithms mlkem768x25519-sha256")
            code, _, _ = run_cli(*scan_args(ifs2, build2, proj2, "--json", out("b.json")))
            self.assertEqual(code, 0)
            code, text, _ = run_cli("diff", out("a.json"), out("b.json"))
            self.assertEqual(code, 0)
            self.assertIn("verdict: UNSAFE -> WARN", text)  # two classical-key and qcrypto warnings remain
            code, text, _ = run_cli("diff", out("b.json"), out("a.json"))
            self.assertEqual(code, 1)
            code, text, _ = run_cli("diff", out("a.json"), out("a.json"))
            self.assertEqual(code, 0)
            self.assertIn("new 0, gone 0, changed 0", text)
            self.assertEqual(run_cli("diff", out("a.json"), out("b.json"), "--html", out("d.html"))[0], 0)
            self.assertTrue(os.path.getsize(out("d.html")) > 500)

    def test_bad_input_gives_one_line(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            empty = os.path.join(tmp, "empty")
            os.makedirs(empty)
            text_file = os.path.join(tmp, "f.txt")
            open(text_file, "w").write("not json {")
            unreadable = os.path.join(tmp, "nope.json")
            cases = [[], ["scan"], ["scan", "--ifs-dir", ifs], ["scan", "--ifs-dir", "/nonexistent", "--build-dir", build],
                     ["scan", "--ifs-dir", ifs, "--build-dir", empty, "--sdk-root", proj],
                     ["scan", "--ifs", text_file, "--build-dir", build, "--sdk-root", proj],
                     ["scan", *scan_args(ifs, build, proj)[1:], "--runtime", text_file],
                     ["scan", *scan_args(ifs, build, proj)[1:], "--date", "tomorrow"],
                     ["scan", *scan_args(ifs, build, proj)[1:], "--html", "/nonexistent-dir/x.html"],
                     ["diff", text_file, text_file], ["diff", unreadable, unreadable], ["diff", "one"], ["bogus"]]
            for argv in cases:
                code, out, err = run_cli(*argv)
                self.assertEqual(code, 2, argv)
                self.assertRegex(err, r"^qnx-cbom: error: [^\n]+\n$", argv)
                self.assertNotIn("Traceback", err)

    def test_corrupt_scan_files(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            good = os.path.join(tmp, "g.json")
            run_cli(*scan_args(ifs, build, proj, "--json", good))
            scan = json.load(open(good))
            variants = {"schema": {**scan, "schema": "other"}, "findings": {**scan, "findings": "x"},
                        "finding-item": {**scan, "findings": [1]}, "verdict": {**scan, "summary": {}}, "list": [1, 2]}
            for name, data in variants.items():
                path = os.path.join(tmp, name + ".json")
                json.dump(data, open(path, "w"))
                code, _, err = run_cli("diff", good, path)
                self.assertEqual(code, 2, name)
                self.assertNotIn("Traceback", err)
            deep = os.path.join(tmp, "deep.json")
            open(deep, "w").write("[" * 100000)
            self.assertEqual(run_cli("diff", good, deep)[0], 2)


class HostileTests(unittest.TestCase):
    def test_no_quadratic_hangs(self):
        import time
        started = time.time()
        keys.summarize(b"\n" * 1_000_000)
        keys.summarize(b"-----BEGIN A-----\n" * 50_000)
        keys.summarize(b"-----BEGIN PRIVATE KEY-----\n" * 30_000)
        with tmpdir() as tmp:
            path = os.path.join(tmp, "cap.txt")
            open(path, "w").write("CBOM-BEGIN\n" * 600_000)
            with self.assertRaises(runtime.ProbeFileError):
                runtime.load(path)
            open(path, "w").write("CBOM-BEGIN\n{}\nCBOM-END len=" + "9" * 5000 + " crc32=00000000\n")
            with self.assertRaises(runtime.ProbeFileError):
                runtime.load(path)
        self.assertLess(time.time() - started, 10)

    def test_corrupt_crypto_file_fails_closed(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp, openssl="OpenSSL 3.5.9 29 Sep 2026")
            lib = os.path.join(ifs, "proc", "boot", "libcrypto.so.3")
            data = open(lib, "rb").read()
            open(lib, "wb").write(data[:100] + b"OpenSSL 3.0.22 25 Aug 2026")  # truncated ELF with a banner
            out = os.path.join(tmp, "o.json")
            code, text, _ = run_cli(*scan_args(ifs, build, proj, "--json", out, "--text", "-"))
            self.assertEqual(code, 1)
            self.assertIn("QCB-008", text)
            self.assertIn("not analysed", text)

    def test_config_parser_matches_openssh_line_rules(self):
        from qnxcbom import configs
        got = configs.parse_ssh_config("# note\x85KexAlgorithms curve25519-sha256\nKexAlgorithms mlkem768x25519-sha256\n", True)
        self.assertEqual(got["settings"]["KexAlgorithms"]["value"], "mlkem768x25519-sha256")
        got = configs.parse_ssh_config('KexAlgorithms "+mlkem768x25519-sha256"\n', True)
        self.assertEqual(got["settings"]["KexAlgorithms"]["mode"], "add")

    def test_swapped_in_link_is_refused(self):
        with tmpdir() as tmp:
            target = os.path.join(tmp, "outside")
            open(target, "w").write("secret")
            link = os.path.join(tmp, "f")
            os.symlink(target, link)
            with self.assertRaises(OSError):
                safepath.read_limited(link)
            fifo = os.path.join(tmp, "p")
            os.mkfifo(fifo)
            with self.assertRaises(OSError):
                safepath.read_limited(fifo)

    def test_unreadable_file_does_not_stop_scan(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp, extra_system="etc/custom_id=bin/ls\n")
            odd = os.path.join(ifs, "proc", "boot", "locked.bin")
            open(odd, "wb").write(make_elf(["libcrypto.so.3"], None, True))
            os.chmod(odd, 0)
            out = os.path.join(tmp, "o.json")
            code, _, err = run_cli(*scan_args(ifs, build, proj, "--json", out))
            os.chmod(odd, 0o600)
            self.assertEqual(err, "")
            if os.geteuid() != 0:
                c = json.load(open(out))["image"]["counts"]
                self.assertEqual(c["unreadable"] + c["bad_elf"], 1)  # counted, scan carries on


    def test_injection_and_secrets_and_paths(self):
        evil = '<script>alert(1)</script>"onmouseover="x'
        with tmpdir() as tmp:
            made = generate_keys(os.path.join(tmp, "k")) if os.makedirs(os.path.join(tmp, "k")) is None else {}
            extra_ifs = {}
            ifs, build, proj = make_image(tmp, kex=f"KexAlgorithms {evil}",
                                          extra_system=f"bin/{evil}=bin/ls\nbin/../../../../etc/passwd=../../../../../../etc/passwd\nbin/abs=/etc/passwd\n"
                                                       f"etc/{evil}.pem={{\n-----BEGIN PRIVATE KEY-----\n{MARKER}\n-----END PRIVATE KEY-----\n}}\n"
                                                       f"etc/qcrypto.conf={{\n{evil} tags=*\n}}\n")
            open(os.path.join(ifs, "proc", "boot", f"{evil}.sh".replace("/", "_")), "w").write("x")
            os.symlink("/etc/passwd", os.path.join(ifs, "proc", "boot", "evil_link"))
            os.symlink("/etc", os.path.join(ifs, "etc_dir_link"))
            if made:
                for name in ("rsa.key", "cert.pem"):
                    data = open(made[name]).read()
                    open(os.path.join(ifs, "proc", "boot", name), "w").write(data + "\n# " + MARKER)
            paths = {n: os.path.join(tmp, n) for n in ("j", "c", "h", "t")}
            code, out, err = run_cli(*scan_args(ifs, build, proj, "--json", paths["j"], "--cbom", paths["c"], "--html", paths["h"], "--text", paths["t"]))
            self.assertIn(code, (0, 1))
            self.assertEqual(err, "")
            blob = "".join(open(p).read() for p in paths.values())
            self.assertNotIn(MARKER, blob)
            html_text = open(paths["h"]).read()
            self.assertNotIn("<script>alert", html_text)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)
            self.assertEqual(len(re.findall(r"<script", html_text)), 1)  # only our own script
            self.assertIsNone(re.search(r"\son[a-z]+\s*=", html_text.split("<body>")[1]))
            self.assertIn("Content-Security-Policy", html_text)
            self.assertNotIn("unsafe-inline", html_text)
            self.assertNotIn("unsafe-eval", html_text)
            self.assertIsNone(re.search(r"(src|href)=\"(?!#|https://)", html_text))
            scan = json.load(open(paths["j"]))
            self.assertGreaterEqual(scan["image"]["counts"]["skipped_outside_roots"], 2)
            self.assertFalse(any("passwd" in e["image_path"] for e in scan["elfs"]))

    def test_cbom_schema(self):
        schema_dir = os.path.join(os.path.dirname(__file__), "..", "build", "schema")
        if not os.path.exists(os.path.join(schema_dir, "bom-1.6.schema.json")):
            self.skipTest("schema not fetched (make fetch-schema)")
        sys.path.insert(0, os.path.dirname(__file__))
        import validate_cbom
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            out = os.path.join(tmp, "x.cdx.json")
            run_cli(*scan_args(ifs, build, proj, "--cbom", out))
            self.assertEqual(validate_cbom.validate(out, schema_dir), [])

    def test_hostile_elf_in_image_does_not_stop_scan(self):
        with tmpdir() as tmp:
            good = make_elf(["libcrypto.so.3"], None, True)
            extra = {}
            ifs, build, proj = make_image(tmp)
            for i, data in enumerate((good[:100], good[:70] + b"\xff" * 400, b"\x7fELF" + b"\x02\x01\x01" + bytes(80))):
                open(os.path.join(ifs, "proc", "boot", f"bad{i}"), "wb").write(data)
            code, out, err = run_cli(*scan_args(ifs, build, proj, "--json", os.path.join(tmp, "o.json")))
            self.assertEqual(err, "")
            self.assertGreaterEqual(json.load(open(os.path.join(tmp, "o.json")))["image"]["counts"]["bad_elf"], 1)

    def test_report_with_many_findings_and_empty(self):
        with tmpdir() as tmp:
            ifs, build, proj = make_image(tmp)
            out = os.path.join(tmp, "s.json")
            run_cli(*scan_args(ifs, build, proj, "--json", out))
            scan = json.load(open(out))
            base = scan["findings"][0]
            scan["findings"] = [{**base, "subject": f"/x/{i}", "severity": ("UNSAFE", "WARN", "OK")[i % 3]} for i in range(600)]
            page = report.scan_page(scan)
            self.assertEqual(page.count('class="finding"'), 600)
            scan["findings"], scan["keys"], scan["libs"], scan["elfs"] = [], [], [], []
            scan["summary"] = {"unsafe": 0, "warn": 0, "ok": 0, "verdict": "OK"}
            self.assertIn("No findings.", report.scan_page(scan))


if __name__ == "__main__":
    unittest.main()
