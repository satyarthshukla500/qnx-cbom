# Builds the self-contained HTML report. Every value that came from the image is
# escaped when the page is written; the script only filters, sorts and copies.
import base64
import hashlib
import html
import unicodedata

from .report_assets import CSS, JS

SYMBOL = {"UNSAFE": "✖", "WARN": "▲", "OK": "✔"}
CELL_LIMIT = 300


def _clean(value, limit=CELL_LIMIT):
    """Text from the image: control characters replaced, long text cut."""
    text = "".join("�" if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp") else ch for ch in str(value))
    return text if len(text) <= limit else text[:limit] + "…"


def e(value, limit=CELL_LIMIT):
    return html.escape(_clean(value, limit), quote=True)


def _hash(text):
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()


def _page(title, body, with_script):
    policy = (f"default-src 'none'; style-src '{_hash(CSS)}'; "
              + (f"script-src '{_hash(JS)}'; " if with_script else "")
              + "img-src data:; base-uri 'none'; form-action 'none'")
    script = f"<script>{JS}</script>" if with_script else ""
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{html.escape(policy, quote=True)}\">"
            f"<title>{e(title)}</title><style>{CSS}</style></head>\n<body><div class=\"wrap\">{body}</div>{script}</body></html>\n")


def _sev(severity):
    return f"<span class=\"sev {severity}\">{SYMBOL[severity]} {severity}</span>"


def _table(headers, rows, label):
    if not rows:
        return ""
    head = "".join(f"<th scope=\"col\">{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return (f"<div class=\"scroll\" role=\"region\" aria-label=\"{html.escape(label, quote=True)}\" tabindex=\"0\">"
            f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>")


def _empty(text):
    return f"<p class=\"empty\">{html.escape(text)}</p>"


def _finding(f):
    searchable = " ".join([f["severity"], f["rule"], f["title"], f["subject"]] + f["evidence"]).lower()
    evidence = "".join(f"<li class=\"mono\">{e(line, 500)}</li>" for line in f["evidence"])
    unverified = "".join(f"<li>{e(line, 500)}</li>" for line in f["unverified"])
    notes = f"<p class=\"small\">Not verified:</p><ul class=\"small\">{unverified}</ul>" if unverified else ""
    return (f"<li class=\"finding\" data-sev=\"{f['severity']}\" data-rule=\"{e(f['rule'])}\" data-subject=\"{e(f['subject'])}\" "
            f"data-text=\"{e(searchable, 4000)}\"><details><summary>{_sev(f['severity'])} <code>{e(f['rule'])}</code> "
            f"<span>{e(f['title'])}</span> <code>{e(f['subject'])}</code></summary><div class=\"body\">"
            f"<p class=\"small\">Evidence</p><ul>{evidence}</ul>"
            f"<div class=\"fix\"><strong>Fix.</strong> {e(f['fix'], 1000)}</div>"
            f"<p><button type=\"button\" data-copy=\"{e(f['fix'], 1000)}\" data-label=\"Copy fix\">Copy fix</button></p>"
            f"<p class=\"small\">Source: <a href=\"{e(f['source_url'], 500)}\" rel=\"noopener noreferrer\">{e(f['source_url'], 500)}</a>"
            f" (read {e(f['source_date'])})</p>{notes}</div></details></li>")


def _findings_section(model):
    findings = model["findings"]
    total = {s: sum(1 for f in findings if f["severity"] == s) for s in ("UNSAFE", "WARN", "OK")}
    filters = "".join(f"<button type=\"button\" data-filter=\"{k}\" aria-pressed=\"{'true' if k == 'ALL' else 'false'}\">{label}</button>"
                      for k, label in (("ALL", f"All ({len(findings)})"), ("UNSAFE", f"UNSAFE ({total['UNSAFE']})"),
                                       ("WARN", f"WARN ({total['WARN']})"), ("OK", f"OK ({total['OK']})")))
    sorts = "".join(f"<button type=\"button\" data-sort=\"{k}\" aria-pressed=\"{'true' if k == 'severity' else 'false'}\">{k.capitalize()}</button>"
                    for k in ("severity", "rule", "subject"))
    controls = ("<div class=\"controls\"><div class=\"group\" role=\"group\" aria-label=\"Filter by severity\">" + filters + "</div>"
                "<label>Search <input type=\"search\" id=\"q\" placeholder=\"rule, path, text\"></label>"
                "<div class=\"group\" role=\"group\" aria-label=\"Sort by\">Sort: " + sorts + "</div>"
                "<div class=\"group\"><button type=\"button\" id=\"expand\">Expand all</button>"
                "<button type=\"button\" id=\"collapse\">Collapse all</button></div></div>")
    items = "".join(_finding(f) for f in findings)
    return ("<section id=\"findings\"><h2>Findings</h2>" + controls + "<p id=\"count\" class=\"small\" aria-live=\"polite\"></p>"
            + f"<ol id=\"list\">{items}</ol>"
            + "<p id=\"none\" class=\"empty\" hidden>No finding matches the filter.</p>"
            + ("" if findings else _empty("No findings.")) + "</section>")


def _programs(model):
    rows = [[f"<code>{e(x['image_path'])}</code>", x["kind"], f"<code>{e(', '.join(x['crypto_libs']))}</code>"]
            for x in model["elfs"] if x["crypto_libs"]]
    table = _table(["Path", "Kind", "Crypto libraries needed"], rows, "Crypto-linked programs and libraries")
    return "<section id=\"programs\"><h2>Crypto-linked programs and libraries</h2>" + (table or _empty("No ELF file links a crypto library.")) + "</section>"


def _libraries(model):
    rows = [[f"<code>{e(l['image_path'])}</code>", e(l["family"]), e(l["version"] or "no version string"),
             e(l["released"] or ""), "yes" if l["pq_capable"] else "no"] for l in model["libs"]]
    table = _table(["Path", "Family", "Version", "Released", "Post-quantum names present"], rows, "Crypto libraries")
    return "<section id=\"libraries\"><h2>Crypto libraries</h2>" + (table or _empty("No crypto library found.")) + "</section>"


def _keys(model):
    rows = [[f"<code>{e(k['image_path'])}</code>", e(k["kind"]), e(k["algorithm"]), e(k["size"] or ""), e(k["curve"] or ""),
             e(k["subject"] or ""), e(k["not_after"] or ""), "yes" if k["quantum_safe"] else "no"] for k in model["keys"]]
    table = _table(["Path", "Kind", "Algorithm", "Size (bits)", "Curve", "Subject", "Valid until", "Quantum-safe"], rows, "Keys and certificates")
    return ("<section id=\"keys\"><h2>Keys and certificates</h2><p class=\"small\">Only algorithm and size are read; key material is never kept.</p>"
            + (table or _empty("No keys or certificates found.")) + "</section>")


def _config(model):
    cfg = model["configs"]
    parts = []
    if cfg["qcrypto"]:
        rows = [[f"<code>{e(x['plugin'])}</code>", f"<code>{e(','.join(x['tags']))}</code>"] for x in cfg["qcrypto"]["entries"]]
        parts.append(f"<h3>qcrypto <code>{e(cfg['qcrypto']['path'])}</code></h3>" + (_table(["Plug-in", "Tags"], rows, "qcrypto entries") or _empty("Empty file.")))
    for name in ("sshd", "ssh"):
        c = cfg[name]
        if not c:
            continue
        binary = c["binary"]
        head = f"<h3>{name} <code>{e(c['path'] or 'no config file in the image')}</code></h3>"
        info = (f"<p class=\"small\">Binary <code>{e(binary['path'])}</code>, OpenSSH {e(binary['openssh_version'] or 'unknown')}, "
                f"post-quantum key exchange names in binary: {e(', '.join(binary['pq_kex']) or 'none')}</p>") if binary else ""
        rows = [[e(k), e(v["mode"]), f"<code>{e(v['value'], 600)}</code>", e(v["line"])] for k, v in sorted(c["settings"].items())]
        parts.append(head + info + (_table(["Setting", "Mode", "Value", "Line"], rows, name + " settings") or _empty("No algorithm settings in the file (defaults apply).")))
    return "<section id=\"config\"><h2>Configuration</h2>" + ("".join(parts) or _empty("No qcrypto, sshd or ssh configuration found.")) + "</section>"


def _runtime(model):
    runtime = model.get("runtime")
    if not runtime:
        return "<section id=\"runtime\"><h2>Runtime</h2>" + _empty("No runtime data (run the probe on the target and pass --runtime).") + "</section>"
    rows = []
    for proc in runtime["processes"]:
        for lib in proc["libs"]:
            match = {True: "yes", False: "NO", None: "unknown"}[lib["matches_disk"]]
            rows.append([f"<code>{e(proc['name'])}</code>", e(proc["pid"]), f"<code>{e(lib['path'])}</code>",
                         e(lib["version"] or "none"), e(lib["disk_version"] or "none"), match])
    target = runtime["target"]
    info = f"<p class=\"small\">Target {e(target['sysname'])} {e(target['release'])} {e(target['machine'])}; {e(runtime['scanned'])} processes read, {e(runtime['error_count'])} read errors.</p>"
    table = _table(["Process", "PID", "Mapped library", "Loaded version", "Image version", "Same as image"], rows, "Mapped crypto libraries")
    return "<section id=\"runtime\"><h2>Runtime</h2>" + info + (table or _empty("No process maps a crypto library.")) + "</section>"


def _method(model):
    c = model["image"]["counts"]
    notes = "".join(f"<li>{e(n, 500)}</li>" for n in model.get("notes", []))
    return ("<section id=\"method\"><h2>Method and limits</h2><ul>"
            f"<li>Read {c['files']} files: the boot image folder and the files named in {e(', '.join(model['image']['build_files']))}; "
            f"{c['elf']} are ELF, {c['crypto_elf']} link a crypto library ({c['crypto_executables']} are programs).</li>"
            "<li>The system and data partitions are not read from the disk image; their content comes from the build lists and the SDK files they name.</li>"
            f"<li>Not analysed: {c['skipped_outside_roots']} files outside the allowed folders, {c['skipped_too_big']} files that were too big, {c['unresolved']} files not found, {c['bad_elf']} ELF files that could not be read, {c['unreadable']} unreadable files.</li>"
            "<li>End-of-life dates come from the OpenSSL release policy page; each finding names its source and what was not verified.</li>"
            f"{notes}</ul></section>")


def scan_page(model):
    image, summary = model["image"], model["summary"]
    verdict = (f"<div class=\"verdict {summary['verdict']}\" role=\"status\"><span class=\"word\">{SYMBOL[summary['verdict']]} Verdict: {summary['verdict']}</span>"
               f"<span class=\"counts\">{_sev('UNSAFE')} {summary['unsafe']} {_sev('WARN')} {summary['warn']} {_sev('OK')} {summary['ok']}</span></div>")
    nav = ("<nav aria-label=\"Sections\"><ul>" + "".join(f"<li><a href=\"#{i}\">{t}</a></li>" for i, t in
           (("findings", "Findings"), ("programs", "Programs"), ("libraries", "Libraries"), ("keys", "Keys"),
            ("config", "Configuration"), ("runtime", "Runtime"), ("method", "Method"))) + "</ul></nav>")
    head = (f"<header><h1>qnx-cbom report</h1><p class=\"meta\">Image <strong>{e(image['name'])}</strong> &middot; {e(image['arch'])} &middot; "
            f"scan date {e(model['scan_date'])} &middot; qnx-cbom {e(model['tool']['version'])}</p></header>")
    legend = ("<p class=\"small\"><strong>UNSAFE</strong>: below the baseline (an OpenSSL series upstream still supports; post-quantum key exchange where the build has it). "
              "<strong>WARN</strong>: weaker than ideal or not confirmable. <strong>OK</strong>: meets the baseline for that check.</p>")
    body = head + verdict + legend + nav + _findings_section(model) + _programs(model) + _libraries(model) + _keys(model) + _config(model) + _runtime(model) + _method(model)
    return _page(f"qnx-cbom report - {image['name']}", body, True)


def diff_page(result):
    def rows(items, fields):
        return [[f(i) for f in fields] for i in items]
    sev_row = [lambda i: _sev(i["severity"]), lambda i: f"<code>{e(i['rule'])}</code>", lambda i: f"<code>{e(i['subject'])}</code>", lambda i: e(i["title"])]
    sections = []
    for title, items, label in (("New findings", result["new"], "new"), ("Findings that are gone", result["gone"], "gone")):
        sections.append(f"<section><h2>{title}</h2>" + (_table(["Severity", "Rule", "Subject", "Title"], rows(items, sev_row), title) or _empty("None.")) + "</section>")
    changed = rows(result["changed"], [lambda i: f"<code>{e(i['rule'])}</code>", lambda i: f"<code>{e(i['subject'])}</code>", lambda i: _sev(i["from"]), lambda i: _sev(i["to"])])
    sections.append("<section><h2>Changed severity</h2>" + (_table(["Rule", "Subject", "Before", "After"], changed, "Changed severity") or _empty("None.")) + "</section>")
    libs = rows(result["libs"], [lambda i: f"<code>{e(i['path'])}</code>", lambda i: e(i["from"] or "none"), lambda i: e(i["to"] or "none")])
    sections.append("<section><h2>Library versions</h2>" + (_table(["Path", "Before", "After"], libs, "Library versions") or _empty("No library version changed.")) + "</section>")
    verdict = (f"<div class=\"verdict {result['verdict_b']}\" role=\"status\"><span class=\"word\">{e(result['verdict_a'])} → {e(result['verdict_b'])}</span>"
               f"<span>{'Worse than before' if result['regressed'] else 'No new problems'}</span></div>")
    head = f"<header><h1>qnx-cbom diff</h1><p class=\"meta\">{e(result['name_a'])} → {e(result['name_b'])}</p></header>"
    return _page("qnx-cbom diff", head + verdict + "".join(sections), False)
