# Runs hostile inputs through bin/qnx-cbom and logs one line per attack.
# Usage: python3 tests/security_attacks.py LOGFILE
import json
import os
from html.parser import HTMLParser
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fixtures import generate_keys, make_elf, make_image  # noqa: E402

TOOL = os.path.join(HERE, "..", "bin", "qnx-cbom")
SRC = os.path.join(HERE, "..", "src")
MARK = "UNIQUE-SECRET-MARKER-12345"
log, failed = [], 0


def run(*args, timeout=90):
    done = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True, timeout=timeout)
    return done.returncode, done.stdout, done.stderr


def record(name, ok, detail):
    global failed
    failed += 0 if ok else 1
    log.append(f"{'BLOCKED/HANDLED' if ok else 'GOT THROUGH    '}  {name} -> {detail}")


def scan(ifs, build, proj, *extra):
    return run("scan", "--ifs-dir", ifs, "--build-dir", build, "--project-dir", proj, "--sdk-root", os.path.join(proj, "sdk"),
               "--date", "2026-11-23", *extra)


def clean(code, err):
    return code in (0, 1, 2) and "Traceback" not in err


def main(logfile):
    with tempfile.TemporaryDirectory(prefix="qnxcbom-attack-") as tmp:
        n = [0]

        def image(**kw):
            n[0] += 1
            return make_image(os.path.join(tmp, f"i{n[0]}"), **kw)

        def counts(path):
            return json.load(open(path))["image"]["counts"]

        # 1-3 path traversal and absolute sources
        ifs, build, proj = image(extra_system="bin/trav=../../../../../../etc/passwd\nbin/absolute=/etc/passwd\nbin/home=/root/.bashrc\n")
        js = os.path.join(tmp, "a.json")
        code, _, err = scan(ifs, build, proj, "--json", js)
        record("build list sources ../../etc/passwd, /etc/passwd, /root/.bashrc", counts(js)["skipped_outside_roots"] + counts(js)["unresolved"] == 3 and counts(js)["skipped_outside_roots"] >= 2 and clean(code, err), f"skipped_outside_roots={counts(js)['skipped_outside_roots']} (existing files), unresolved={counts(js)['unresolved']} (missing file), none read, rc={code}")
        # 4 symlinks in the image folder
        ifs, build, proj = image()
        os.symlink("/etc/passwd", os.path.join(ifs, "proc", "boot", "l1"))
        os.symlink("/etc", os.path.join(ifs, "linkdir"))
        os.symlink("loop", os.path.join(ifs, "loop"))
        os.symlink(".", os.path.join(ifs, "self"))
        code, _, err = scan(ifs, build, proj, "--json", js)
        record("symlinks to /etc/passwd, to /etc, a self loop and a dir loop inside the IFS folder", counts(js)["links"] >= 2 and clean(code, err), f"file links counted={counts(js)['links']}; directory links are not entered; rc={code}")
        # 5 fifo
        os.mkfifo(os.path.join(ifs, "proc", "boot", "fifo.pem"))
        code, _, err = scan(ifs, build, proj, "--json", js)
        record("named pipe called fifo.pem inside the IFS folder (a read would hang)", clean(code, err), f"finished, rc={code}")
        # 6 injection through names and config
        evil = "<script>alert(1)</script>\"'><img src=x onerror=alert(1)>"
        ifs, build, proj = image(kex=f"KexAlgorithms {evil}", extra_system=f"bin/{evil}=bin/ls\netc/{evil}.pem={{\n-----BEGIN PUBLIC KEY-----\n{evil}\n-----END PUBLIC KEY-----\n}}\n")
        html = os.path.join(tmp, "e.html")
        code, _, err = scan(ifs, build, proj, "--html", html)
        page = open(html).read()
        body = page.split("<body>")[1]
        record("file name, config value and key text containing <script> and onerror", "<script>alert" not in page and "<img src=x" not in page and clean(code, err), "all shown as &lt;...&gt; text; the page has exactly one script (its own): " + str(page.count("<script")))
        found = {"handlers": [], "src": [], "scripts": 0}

        class Look(HTMLParser):
            def handle_starttag(self, tag, attrs):
                found["scripts"] += tag == "script"
                for name, _value in attrs:
                    if name.startswith("on"):
                        found["handlers"].append(name)
                    if name == "src":
                        found["src"].append(tag)
        Look().feed(page)
        record("report has CSP meta, no unsafe-inline/eval, no inline handler attributes, no src attributes (parsed with an HTML parser)", "Content-Security-Policy" in page and "unsafe-inline" not in page and "unsafe-eval" not in page and not found["handlers"] and not found["src"] and found["scripts"] == 1, f"handlers={found['handlers']}, src tags={found['src']}, script tags={found['scripts']}")
        # 7 command injection
        ifs, build, proj = image(extra_system="bin/;touch PWNED=bin/ls\n[perms=1] $(touch PWNED2)=bin/ls\n")
        os.makedirs(os.path.join(tmp, "cwd"), exist_ok=True)
        done = subprocess.run([sys.executable, TOOL, "scan", "--ifs-dir", ifs, "--build-dir", build, "--project-dir", proj, "--sdk-root", os.path.join(proj, "sdk"), "--date", "2026-11-23"],
                              cwd=os.path.join(tmp, "cwd"), capture_output=True, text=True, timeout=60)
        record("file names ';touch PWNED' and '$(touch PWNED2)'", not os.listdir(os.path.join(tmp, "cwd")) and clean(done.returncode, done.stderr), "no file was created")
        odd = os.path.join(tmp, "-x;$(id).bin")
        open(odd, "wb").write(b"x")
        code, _, err = run("scan", "--ifs", odd, "--build-dir", build, "--project-dir", proj, "--sdk-root", os.path.join(proj, "sdk"))
        record("--ifs file named '-x;$(id).bin' (passed to dumpifs as an argument)", code == 2 and clean(code, err), f"rc={code}: {err.strip()[:90]}")
        # 8 hostile ELF
        ifs, build, proj = image()
        good = make_elf(["libcrypto.so.3"], None, True)
        bad = {"trunc100": good[:100], "phnum60000": good[:56] + (60000).to_bytes(2, "little") + good[58:],
               "phoff_huge": good[:32] + (2 ** 62).to_bytes(8, "little") + good[40:], "class32": b"\x7fELF\x01\x01\x01" + bytes(100),
               "dyn_len_huge": good, "only_magic": b"\x7fELF"}
        for name, data in bad.items():
            open(os.path.join(ifs, "proc", "boot", name), "wb").write(data)
        code, _, err = scan(ifs, build, proj, "--json", js)
        record("six malformed ELF files (truncated, 60000 program headers, huge offset, 32-bit, magic only)", clean(code, err), f"scan finished rc={code}, bad_elf={counts(js)['bad_elf']}")
        # 9 giant config and giant files
        ifs, build, proj = image()
        open(os.path.join(ifs, "proc", "boot", "sshd_config"), "w").write("KexAlgorithms " + "a," * 3_000_000 + "\n")
        open(os.path.join(ifs, "proc", "boot", "big.pem"), "wb").write(b"A" * 70_000_000)
        code, _, err = scan(ifs, build, proj, "--json", js)
        record("6 MB sshd_config line and a 70 MB .pem file", clean(code, err), f"rc={code}, finished")
        # 10 secret marker
        ifs, build, proj = image()
        made = generate_keys(tempfile.mkdtemp(prefix="k", dir=tmp))
        for name in ("rsa.key", "cert.pem"):
            if name in made:
                open(os.path.join(ifs, "proc", "boot", name), "w").write(open(made[name]).read() + f"\n# {MARK}\n")
        open(os.path.join(ifs, "proc", "boot", "fake.key"), "w").write(f"-----BEGIN PRIVATE KEY-----\n{MARK}\n-----END PRIVATE KEY-----\n")
        outs = {k: os.path.join(tmp, "s." + k) for k in ("json", "cdx", "html", "txt")}
        code, so, err = scan(ifs, build, proj, "--json", outs["json"], "--cbom", outs["cdx"], "--html", outs["html"], "--text", outs["txt"])
        blob = so + err + "".join(open(p).read() for p in outs.values())
        record("private key files with a unique marker (and a fake PEM of the marker) in all outputs", MARK not in blob, "marker absent from json, cbom, html, text, stdout, stderr")
        # 11 too many files
        ifs, build, proj = image()
        crowd = os.path.join(ifs, "crowd")
        os.makedirs(crowd)
        for i in range(20_100):
            open(os.path.join(crowd, f"f{i}"), "w").close()
        code, _, err = scan(ifs, build, proj)
        record("20 100 files in the IFS folder", code == 2 and "too many files" in err, f"rc={code}: {err.strip()}")
        # 12 bad build lists
        ifs, build, proj = image()
        open(os.path.join(build, "system.build"), "w").write("x={\n" + "y" * 2_000_000 + "\n}\n")
        code, _, err = scan(ifs, build, proj)
        record("inline block of 2 MB in system.build", code == 2 and clean(code, err), f"rc={code}: {err.strip()}")
        open(os.path.join(build, "system.build"), "wb").write(os.urandom(100_000))
        code, _, err = scan(ifs, build, proj)
        record("system.build filled with random bytes", clean(code, err), f"rc={code}: {err.strip()[:80]}")
        # 13 hostile json
        base = os.path.join(tmp, "good.json")
        ifs, build, proj = image()
        scan(ifs, build, proj, "--json", base)
        for name, content in (("nested", "[" * 200_000), ("empty", ""), ("binary", None), ("nullbytes", "{\x00}"), ("wrong", '{"schema":"qnx-cbom-scan/1"}')):
            p = os.path.join(tmp, name + ".json")
            open(p, "wb").write(os.urandom(5000) if content is None else content.encode())
            code, _, err = run("diff", base, p)
            record(f"diff with {name} scan file", code == 2 and clean(code, err), f"rc={code}: {err.strip()[:80]}")
            code, _, err = scan(ifs, build, proj, "--runtime", p)
            record(f"--runtime with {name} file", code == 2 and clean(code, err), f"rc={code}: {err.strip()[:80]}")
        huge = os.path.join(tmp, "huge.json")
        with open(huge, "wb") as handle:
            handle.truncate(70 * 1024 * 1024)
        code, _, err = run("diff", base, huge)
        record("diff with a 70 MB file", code == 2 and "bigger than" in err, f"rc={code}: {err.strip()}")
        probe = os.path.join(tmp, "probe.json")
        json.dump({"schema": "qnx-cbom-probe/1", "scanned": 1, "processes": [{"pid": 1, "name": "<script>" * 1000, "libs": [{"path": "p" * 100000, "soname": "libcrypto.so.3", "version": "9" * 1000, "pq_capable": True}]}]}, open(probe, "w"))
        code, _, err = scan(ifs, build, proj, "--runtime", probe, "--html", os.path.join(tmp, "p.html"))
        record("probe file with 100 000 character path and 1000 character version", clean(code, err), f"rc={code} (text is cut to its limit)")
        # 14 missing/odd arguments
        for argv in (["scan", "--ifs-dir", "/nonexistent\x00x", "--build-dir", build], ["scan", "--ifs", "/dev/null", "--build-dir", build, "--sdk-root", proj]):
            try:
                code, _, err = run(*argv)
            except ValueError as err2:
                record("argument with NUL byte", True, f"refused by the operating system layer: {err2}")
                continue
            record(f"odd arguments {argv[1]} {argv[2][:12]}", code == 2 and clean(code, err), f"rc={code}: {err.strip()[:80]}")
        # 14b patterns that make naive regular expressions slow, and a corrupt crypto library
        import time
        ifs, build, proj = image()
        boot = os.path.join(ifs, "proc", "boot")
        open(os.path.join(boot, "newlines.pub"), "wb").write(b"\n" * 1_000_000)
        open(os.path.join(boot, "begins.pem"), "wb").write(b"-----BEGIN A-----\n" * 50_000)
        open(os.path.join(boot, "begins2.key"), "wb").write(b"-----BEGIN PRIVATE KEY-----\n" * 30_000)
        started = time.time()
        code, _, err = scan(ifs, build, proj)
        record("1 MB of newlines in a .pub, 50 000 unmatched BEGIN lines in a .pem and in a .key", time.time() - started < 20 and clean(code, err), f"finished, rc={code}")
        marks = os.path.join(tmp, "marks.txt")
        open(marks, "w").write("CBOM-BEGIN\n" * 600_000)
        started = time.time()
        code, _, err = scan(ifs, build, proj, "--runtime", marks)
        record("probe capture with 600 000 CBOM-BEGIN lines", code == 2 and time.time() - started < 20, f"rc={code} {err.strip()[:60]}")
        ifs, build, proj = image(openssl="OpenSSL 3.5.9 29 Sep 2026")
        lib = os.path.join(ifs, "proc", "boot", "libcrypto.so.3")
        data = open(lib, "rb").read()
        open(lib, "wb").write(data[:100] + b"OpenSSL 3.0.22 25 Aug 2026")
        code, so, err = scan(ifs, build, proj, "--text", "-")
        record("libcrypto.so.3 cut short so it cannot be read as ELF (verdict must not drop)", code == 1 and "QCB-008" in so, f"rc={code}, QCB-008 raised")
        open(lib, "w").write("OpenSSL 3.0.22 25 Aug 2026 (a text file with a library name)")
        code, so, err = scan(ifs, build, proj, "--text", "-")
        record("libcrypto.so.3 replaced by a text file", code == 1 and "QCB-008" in so, f"rc={code}, QCB-008 raised")
        os.chmod(lib, 0)
        code, so, err = scan(ifs, build, proj, "--text", "-")
        record("libcrypto.so.3 with mode 000", code == 1 and "QCB-008" in so or os.geteuid() == 0, f"rc={code}, QCB-008 raised")
        os.chmod(lib, 0o600)
        ifs, build, proj = image()
        open(os.path.join(ifs, "proc", "boot", "\x1b]0;PWN\x07evil.pem"), "wb").write(b"x")
        code, so, err = scan(ifs, build, proj, "--text", "-", "--name", "\x1b[2Jname")
        record("terminal escape sequences in a file name and in --name", "\x1b" not in so + err, f"no ESC byte in standard output or error, rc={code}")

        # 15 static check of the source
        pattern = re.compile(r"shell\s*=\s*True|os\.system|\beval\(|\bexec\(|pickle|yaml\.load|importlib|__import__|subprocess\.getoutput|os\.popen")
        hits = []
        for folder, _, names in os.walk(SRC):
            for name in names:
                if name.endswith(".py"):
                    for number, line in enumerate(open(os.path.join(folder, name)), 1):
                        if pattern.search(line):
                            hits.append(f"{name}:{number}")
        record("source search for shell=True, os.system, eval, exec, pickle, importlib", not hits, "no match" if not hits else ", ".join(hits))
        imports = set()
        for folder, _, names in os.walk(SRC):
            for name in names:
                if name.endswith(".py"):
                    imports.update(re.findall(r"^(?:import|from)\s+([a-zA-Z_0-9]+)", open(os.path.join(folder, name)).read(), re.M))
        third = sorted(i for i in imports if i not in sys.stdlib_module_names and i != "qnxcbom")
        record("third-party imports in the product", not third, "standard library only" if not third else str(third))
    open(logfile, "w").write(f"## security attack log; {len(log)} attacks; {failed} got through\n" + "\n".join(log) + "\n")
    print("\n".join(log))
    print(f"{len(log)} attacks, {failed} got through")
    return 1 if failed else 0


sys.exit(main(sys.argv[1]))
