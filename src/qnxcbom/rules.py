# Turns a scan model into findings using the rules table in rules.json.
# A rule that cannot be decided from the data produces no finding.
import fnmatch
import json
import os
from datetime import date

from .libinfo import SSH_PQ_KEX

with open(os.path.join(os.path.dirname(__file__), "rules.json"), encoding="utf-8") as _handle:
    _TABLE = json.load(_handle)
RULES = _TABLE["rules"]
SERIES = _TABLE["openssl_policy"]["series"]
PQ_KEX = SSH_PQ_KEX
SEVERITY_ORDER = {"OK": 0, "WARN": 1, "UNSAFE": 2}


def _finding(rule_id, severity, subject, evidence):
    rule = RULES[rule_id]
    return {"rule": rule_id, "severity": severity, "title": rule["title_ok"] if severity == "OK" else rule["title"], "subject": subject,
            "evidence": evidence, "fix": rule["fix"], "source_url": rule["source_url"],
            "source_date": rule["source_date"], "unverified": list(rule["unverified"])}


def _series_state(version, today):
    """Return (series, eol text, past) for an OpenSSL version, or None when the series is unknown."""
    series = ".".join(version.split(".")[:2])
    if series not in SERIES:
        return None
    eol = SERIES[series]["eol"]
    past = eol is None or today > date.fromisoformat(eol)
    return series, eol or "unsupported (date not read)", past


def _major(version):
    try:
        return int((version or "").split(".")[0])
    except ValueError:
        return 0


def _allows_pq(setting, openssh_version):
    """True / False, or None when the default list of this OpenSSH version is unknown."""
    default = True if _major(openssh_version) >= 10 else None
    if setting is None:
        return default
    items = setting["items"]
    listed = any(fnmatch.fnmatch(name, pat) for name in PQ_KEX for pat in items)
    if setting["mode"] in ("explicit",):
        return listed
    if setting["mode"] in ("add", "prepend"):
        return True if listed else default
    removed_all = all(any(fnmatch.fnmatch(name, pat) for pat in items) for name in PQ_KEX)
    return False if removed_all else default


def _ssh_findings(cfg, rule_id, bad_severity, model):
    if not cfg or not cfg["binary"]:
        return []
    if cfg.get("includes"):
        model["notes"].append(f"{cfg['path']} has Include lines; included files are not read, so {rule_id} may be incomplete.")
    binary = cfg["binary"]
    name = binary["path"]
    version = binary["openssh_version"]
    where = f"{binary['path']} (OpenSSH {version})" if version else binary["path"]
    if not binary["pq_kex"]:
        return [_finding(rule_id, "WARN", name, [f"{where} contains no post-quantum key exchange name."])]
    setting = cfg["settings"].get("KexAlgorithms")
    allowed = _allows_pq(setting, version)
    if allowed is None:
        return []
    names = ", ".join(binary["pq_kex"])
    if setting:
        line = f"{cfg['path']} line {setting['line']}: KexAlgorithms {setting['value']}"
        how = {"explicit": "explicit list", "add": "adds to the default", "remove": "removes from the default",
               "prepend": "goes before the default"}[setting["mode"]]
        config_text = f"{line} ({how})"
    else:
        config_text = "no KexAlgorithms line: the OpenSSH default list applies"
    if allowed:
        return [_finding(rule_id, "OK", name, [f"{where} contains: {names}.", config_text, "A post-quantum key exchange is allowed."])]
    return [_finding(rule_id, bad_severity, name, [f"{where} contains: {names}.", config_text,
                                                  "No post-quantum key exchange is in the allowed list."])]


def _eol_disk(model, today):
    users = {}
    for elf in model["elfs"]:
        for needed in elf["crypto_libs"]:
            users.setdefault(needed, []).append(elf)
    out = []
    for lib in model["libs"]:
        if lib["family"] != "openssl" or not lib["version"]:
            continue
        state = _series_state(lib["version"], today)
        if state is None:
            model["notes"].append(f"OpenSSL series of {lib['image_path']} ({lib['version']}) is not in the rules table.")
            continue
        series, eol, past = state
        linked = users.get(lib["soname"], [])
        evidence = [f"{lib['image_path']}: OpenSSL {lib['version']} {lib['released']}",
                    f"OpenSSL {series} upstream support: until {eol}; scan date {today.isoformat()}",
                    f"linked by {len(linked)} files, {sum(1 for e in linked if e['kind'] == 'executable')} of them programs"]
        out.append(_finding("QCB-001", "UNSAFE" if past else "OK", lib["image_path"], evidence))
    return out


def _keys(model):
    out = []
    for key in model["keys"]:
        if key["algorithm"] in ("unreadable", "unknown (encrypted)"):
            model["notes"].append(f"{key['image_path']}: key could not be classified ({key['algorithm']}).")
            continue
        size = f" {key['size']} bit" if key["size"] else ""
        curve = f" curve {key['curve']}" if key["curve"] else ""
        text = f"{key['algorithm']}{size}{curve} {key['kind']}"
        if key["subject"]:
            text += f", subject CN={key['subject']}"
        if key["not_after"]:
            text += f", valid until {key['not_after']}"
        state = "OK" if key["quantum_safe"] else "WARN"
        out.append(_finding("QCB-004", state, key["image_path"], [text]))
    return out


def _qcrypto(model):
    cfg = model["configs"]["qcrypto"]
    if not cfg:
        return []
    plugins = {lib["soname"]: lib for lib in model["libs"] if lib["family"] == "qcrypto"}
    out = []
    for entry in cfg["entries"]:
        plugin = plugins.get(f"qcrypto-{entry['plugin']}.so")
        if "*" not in entry["tags"] or plugin is None:
            continue
        evidence = [f"{cfg['path']}: {entry['plugin']} tags=*  (all algorithms go to this plug-in)",
                    f"{plugin['image_path']}: {'contains' if plugin['pq_capable'] else 'contains no'} ML-KEM/ML-DSA names"]
        out.append(_finding("QCB-005", "OK" if plugin["pq_capable"] else "WARN", cfg["path"], evidence))
    return out


def _runtime(model, today):
    runtime = model.get("runtime")
    if not runtime:
        return []
    seen, out = {}, []
    for proc in runtime["processes"]:
        for lib in proc["libs"]:
            seen.setdefault((lib["path"], lib["soname"], lib["version"], lib["disk_version"], lib["matches_disk"]), []).append(proc)
    for (path, soname, version, disk_version, matches), procs in sorted(seen.items(), key=lambda i: str(i[0])):
        names = ", ".join(sorted({f"{p['name']} (pid {p['pid']})" for p in procs})[:6])
        if version:
            state = _series_state(version, today)
            if state:
                series, eol, past = state
                out.append(_finding("QCB-007", "UNSAFE" if past else "OK", path,
                                    [f"mapped by {names}", f"{path}: OpenSSL {version}",
                                     f"OpenSSL {series} upstream support: until {eol}; scan date {today.isoformat()}"]))
        if matches is False:
            out.append(_finding("QCB-006", "WARN", path,
                                [f"mapped by {names}", f"loaded: {path} is OpenSSL {version}",
                                 f"image: {soname} is OpenSSL {disk_version}"]))
    return out


def _unverified(model):
    return [_finding("QCB-008", "UNSAFE", item["image_path"], [item["reason"]]) for item in model["unverified"]]


def evaluate(model, today: date):
    model["notes"] = []
    findings = _eol_disk(model, today)
    findings += _ssh_findings(model["configs"]["sshd"], "QCB-002", RULES["QCB-002"]["severity"], model)
    findings += _ssh_findings(model["configs"]["ssh"], "QCB-003", RULES["QCB-003"]["severity"], model)
    findings += _keys(model) + _qcrypto(model) + _runtime(model, today) + _unverified(model)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["rule"], f["subject"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    model["findings"] = findings
    verdict = "UNSAFE" if counts["UNSAFE"] else "WARN" if counts["WARN"] else "OK"
    model["summary"] = {"unsafe": counts["UNSAFE"], "warn": counts["WARN"], "ok": counts["OK"], "verdict": verdict}
