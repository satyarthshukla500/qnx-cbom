# Short plain-text summary of a scan, and of a diff between two scans.
# Text that came from the image is shown as plain ASCII (other characters escaped).


def _a(value):
    return ascii(str(value))[1:-1]


def scan_text(model):
    image, counts, summary = model["image"], model["image"]["counts"], model["summary"]
    lines = [f"qnx-cbom {model['tool']['version']}  image {_a(image['name'])} ({image['arch']})  scan date {model['scan_date']}",
             f"verdict: {summary['verdict']}   UNSAFE {summary['unsafe']}  WARN {summary['warn']}  OK {summary['ok']}",
             f"files {counts['files']}, ELF {counts['elf']}, crypto-linked ELF {counts['crypto_elf']} "
             f"({counts['crypto_executables']} programs)"]
    skipped = [(k, counts[k]) for k in ("bad_elf", "unreadable", "unresolved", "skipped_outside_roots", "skipped_too_big") if counts.get(k)]
    if skipped:
        lines.append("not analysed: " + ", ".join(f"{k} {v}" for k, v in skipped))
    runtime = model.get("runtime")
    if runtime:
        libs = sum(len(p["libs"]) for p in runtime["processes"])
        lines.append(f"runtime: {len(runtime['processes'])} processes map crypto libraries ({libs} mappings), "
                     f"{runtime['scanned']} processes read")
    for finding in model["findings"]:
        if finding["severity"] != "OK":
            lines.append(f"{finding['severity']:<6} {finding['rule']} {_a(finding['subject'])} - {finding['title']}")
    for note in model.get("notes", []):
        lines.append("note: " + _a(note))
    return "\n".join(lines) + "\n"


def diff_text(result):
    lines = [f"verdict: {result['verdict_a']} -> {result['verdict_b']}",
             f"new {len(result['new'])}, gone {len(result['gone'])}, changed {len(result['changed'])}, "
             f"library versions changed {len(result['libs'])}"]
    for f in result["new"]:
        lines.append(f"NEW      {f['severity']:<6} {f['rule']} {_a(f['subject'])}")
    for f in result["gone"]:
        lines.append(f"GONE     {f['severity']:<6} {f['rule']} {_a(f['subject'])}")
    for c in result["changed"]:
        lines.append(f"CHANGED  {c['rule']} {_a(c['subject'])}: {c['from']} -> {c['to']}")
    for lib in result["libs"]:
        lines.append(f"LIBRARY  {_a(lib['path'])}: {lib['from'] or 'unknown'} -> {lib['to'] or 'unknown'}")
    lines.append("result: " + ("worse" if result["regressed"] else "no new problems"))
    return "\n".join(lines) + "\n"
