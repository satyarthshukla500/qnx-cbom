# Writes the HTML reports the browser test needs and prints their paths as JSON.
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from fixtures import make_image  # noqa: E402
from qnxcbom import cli, report  # noqa: E402
import io
from contextlib import redirect_stderr, redirect_stdout


def main(tmp):
    ifs, build, proj = make_image(os.path.join(tmp, "img"), kex="KexAlgorithms <script>window.pwned=1</script>\"onmouseover=\"x")
    scan_json = os.path.join(tmp, "s.json")
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        cli.main(["scan", "--ifs-dir", ifs, "--build-dir", build, "--project-dir", proj, "--sdk-root", os.path.join(proj, "sdk"),
                  "--date", "2026-11-23", "--json", scan_json])
    scan = json.load(open(scan_json))
    out = {"small": os.path.join(tmp, "small.html"), "empty": os.path.join(tmp, "empty.html"),
           "large": os.path.join(tmp, "large.html"), "hostile": os.path.join(tmp, "hostile.html")}
    open(out["small"], "w").write(report.scan_page(scan))
    out["smallCount"] = len(scan["findings"])
    out["smallQuery"] = sum(1 for f in scan["findings"] if f["rule"] == "QCB-002")
    base = scan["findings"][0]
    big = dict(scan, findings=[{**base, "subject": f"/x/{i}", "severity": ("UNSAFE", "WARN", "OK")[i % 3], "rule": f"QCB-00{1 + i % 7}"}
                               for i in range(600)])
    open(out["large"], "w").write(report.scan_page(big))
    out["largeQuery"] = sum(1 for f in big["findings"] if "/x/7" in f["subject"].lower())
    empty = dict(scan, findings=[], keys=[], libs=[], elfs=[], summary={"unsafe": 0, "warn": 0, "ok": 0, "verdict": "OK"})
    open(out["empty"], "w").write(report.scan_page(empty))
    evil = '<script>window.pwned=1</script><img src=x onerror="window.pwned=1">'
    hostile = dict(scan, findings=[dict(scan["findings"][0], subject=evil, title=evil, evidence=[evil, '"><b onmouseover=x>'])])
    open(out["hostile"], "w").write(report.scan_page(hostile))
    print(json.dumps(out))


main(sys.argv[1])
