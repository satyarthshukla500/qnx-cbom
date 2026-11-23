# Compares two scan files: findings that are new, gone or changed, and library versions.
import json

from .rules import SEVERITY_ORDER

MAX_BYTES = 64 * 1024 * 1024


class ScanFileError(Exception):
    pass


def load_scan(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as err:
        raise ScanFileError(f"cannot read {path}: {err.strerror}")
    if len(raw) > MAX_BYTES:
        raise ScanFileError(f"{path} is bigger than 64 MiB")
    try:
        scan = json.loads(raw)
    except (ValueError, RecursionError):
        raise ScanFileError(f"{path} is not valid JSON")
    return check_scan(scan, path)


def check_scan(scan, path):
    if not isinstance(scan, dict) or scan.get("schema") != "qnx-cbom-scan/1":
        raise ScanFileError(f"{path} is not a qnx-cbom scan file (schema qnx-cbom-scan/1 expected)")
    for key, kind in (("findings", list), ("libs", list), ("summary", dict), ("image", dict)):
        if not isinstance(scan.get(key), kind):
            raise ScanFileError(f"{path} is damaged: field '{key}' is missing or has the wrong type")
    for finding in scan["findings"]:
        if not (isinstance(finding, dict) and isinstance(finding.get("rule"), str) and
                isinstance(finding.get("subject"), str) and isinstance(finding.get("title"), str) and
                isinstance(finding.get("evidence", []), list) and finding.get("severity") in SEVERITY_ORDER):
            raise ScanFileError(f"{path} is damaged: a finding is malformed")
    for lib in scan["libs"]:
        if not (isinstance(lib, dict) and isinstance(lib.get("image_path"), str)):
            raise ScanFileError(f"{path} is damaged: a library entry is malformed")
    if scan["summary"].get("verdict") not in tuple(SEVERITY_ORDER):
        raise ScanFileError(f"{path} is damaged: summary verdict is missing")
    return scan


def compare(a, b):
    fa = {(f["rule"], f["subject"]): f for f in a["findings"]}
    fb = {(f["rule"], f["subject"]): f for f in b["findings"]}
    new = [fb[k] for k in sorted(fb) if k not in fa]
    gone = [fa[k] for k in sorted(fa) if k not in fb]
    changed = [{"rule": k[0], "subject": k[1], "from": fa[k]["severity"], "to": fb[k]["severity"]}
               for k in sorted(fa) if k in fb and fa[k]["severity"] != fb[k]["severity"]]
    la = {l["image_path"]: l.get("version") for l in a["libs"]}
    lb = {l["image_path"]: l.get("version") for l in b["libs"]}
    libs = [{"path": p, "from": la.get(p), "to": lb.get(p)} for p in sorted(set(la) | set(lb)) if la.get(p) != lb.get(p)]
    regressed = any(f["severity"] != "OK" for f in new) or \
        any(SEVERITY_ORDER[c["to"]] > SEVERITY_ORDER[c["from"]] for c in changed)
    return {"verdict_a": a["summary"]["verdict"], "verdict_b": b["summary"]["verdict"], "name_a": a["image"].get("name", ""),
            "name_b": b["image"].get("name", ""), "new": new, "gone": gone, "changed": changed, "libs": libs,
            "regressed": regressed}
