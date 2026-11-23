# Reads probe output (a JSON file or a saved console capture) and merges it into a scan.
import json
import re
import zlib

MAX_BYTES = 8 * 1024 * 1024
MAX_PROCESSES = 5000
MAX_LIBS = 256
LIB_ORDER = ("/proc/boot", "/system/lib", "/system/lib/dll")  # LD_LIBRARY_PATH set by the image profile
_TRAILER = re.compile(r"CBOM-END len=(\d{1,9}) crc32=([0-9a-fA-F]{8})")


def _marked_block(text):
    """(body, length, crc) between the first CBOM-BEGIN and the next CBOM-END line, or None."""
    begin = text.find("CBOM-BEGIN")
    end = text.find("CBOM-END", begin) if begin >= 0 else -1
    trailer = _TRAILER.match(text, end) if end >= 0 else None
    if not trailer:
        return None
    body = text[begin + len("CBOM-BEGIN"):end].strip("\r\n")
    return body, int(trailer.group(1)), int(trailer.group(2), 16)


class ProbeFileError(Exception):
    pass


def _text(value, limit):
    if not isinstance(value, str):
        raise ProbeFileError("probe output has a non-text field")
    return value[:limit]


def _check(probe):
    if not isinstance(probe, dict) or probe.get("schema") != "qnx-cbom-probe/1":
        raise ProbeFileError("not probe output (schema qnx-cbom-probe/1 expected)")
    procs = probe.get("processes")
    if not isinstance(procs, list) or len(procs) > MAX_PROCESSES:
        raise ProbeFileError("probe output has a bad process list")
    clean = []
    for proc in procs:
        if not isinstance(proc, dict) or type(proc.get("pid")) is not int or not isinstance(proc.get("libs"), list):
            raise ProbeFileError("probe output has a bad process entry")
        libs = []
        for lib in proc["libs"][:MAX_LIBS]:
            if not isinstance(lib, dict):
                raise ProbeFileError("probe output has a bad library entry")
            version = lib.get("version")
            libs.append({"path": _text(lib.get("path"), 512), "soname": _text(lib.get("soname"), 128),
                         "version": _text(version, 32) if version is not None else None,
                         "released": _text(lib["released"], 32) if lib.get("released") else None,
                         "pq_capable": lib.get("pq_capable") is True})
        clean.append({"pid": proc["pid"], "name": _text(proc.get("name"), 512), "libs": libs})
    target = probe.get("target") if isinstance(probe.get("target"), dict) else {}
    errors = probe.get("errors") if isinstance(probe.get("errors"), list) else []
    return {"schema": "qnx-cbom-probe/1", "probe_version": _text(probe.get("probe_version", ""), 32),
            "target": {k: _text(target.get(k, ""), 64) for k in ("sysname", "release", "machine")},
            "scanned": probe["scanned"] if type(probe.get("scanned")) is int else len(clean),
            "processes": clean, "error_count": len(errors)}


def load(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as err:
        raise ProbeFileError(f"cannot read {path}: {err.strerror}")
    if len(raw) > MAX_BYTES:
        raise ProbeFileError("probe file is bigger than 8 MiB")
    text = raw.decode("utf-8", "replace")
    marked = _marked_block(text)
    if marked:
        body, length, crc = marked
        if len(body.encode()) != length or zlib.crc32(body.encode()) != crc:
            raise ProbeFileError("console capture is damaged (length or crc32 does not match)")
        text = body
    try:
        return _check(json.loads(text))
    except (ValueError, RecursionError):
        raise ProbeFileError("probe file is not valid JSON")


def merge(model, probe):
    """Attach probe data to the scan and compare each mapped library with the image."""
    disk = {}
    for lib in model["libs"]:
        disk.setdefault(lib["soname"], []).append(lib)
    for proc in probe["processes"]:
        for lib in proc["libs"]:
            # the image file at the mapped path wins; otherwise the first one in loader search order
            candidates = sorted(disk.get(lib["soname"], []), key=lambda d: (d["image_path"] != lib["path"], _rank(d["image_path"])))
            lib["disk_version"] = candidates[0]["version"] if candidates else None
            if candidates and lib["version"] and lib["disk_version"]:
                lib["matches_disk"] = lib["version"] == lib["disk_version"]
            else:
                lib["matches_disk"] = None
    model["runtime"] = probe


def _rank(image_path):
    folder = image_path.rsplit("/", 1)[0]
    return LIB_ORDER.index(folder) if folder in LIB_ORDER else len(LIB_ORDER)
