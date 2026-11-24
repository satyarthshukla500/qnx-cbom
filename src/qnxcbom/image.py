# Builds the scan model: walks the extracted boot image and the build lists of
# the other partitions, reads each ELF and the crypto-related files.
import os
import posixpath
import re
import shutil
import stat
import struct
import subprocess
import tempfile

from . import buildlist, configs, elf, keys, libinfo, qnx6, safepath

MAX_FILES = 20_000
MAX_CONFIG_BYTES = 256 * 1024
MAX_DISK_BYTES = 1024 * 1024 * 1024
DISK_PARTS = {0xB2: "system", 0xB3: "data"}  # MBR types that mkqnximage gives its qnx6 partitions
MOUNTS = {"ifs": "/", "system": "/system/", "data": "/data/"}
CRYPTO_PREFIXES = ("libcrypto", "libssl", "libqcrypto")
KEY_SUFFIXES = (".pem", ".crt", ".cer", ".pub", ".key")
RELEVANT_NAMES = ("sshd", "ssh", "sshd_config", "ssh_config", "qcrypto.conf")


def _expect_elf(base):
    return base.startswith(CRYPTO_PREFIXES + ("qcrypto-",)) or base in ("sshd", "ssh")


def _relevant(base):
    """Files whose analysis decides a verdict; if one cannot be read the scan says so."""
    return base.startswith(CRYPTO_PREFIXES + ("qcrypto-",)) or base in RELEVANT_NAMES


class ScanError(Exception):
    pass


def extract_ifs(ifs_file: str, out_dir: str) -> None:
    """Run dumpifs -x for the user's image file; only the file path is passed."""
    tool = shutil.which("dumpifs")
    if tool is None and os.environ.get("QNX_HOST"):
        tool = os.path.join(os.environ["QNX_HOST"], "usr/bin/dumpifs")
    if tool is None or not os.path.isfile(tool):
        raise ScanError("dumpifs not found; source the QNX SDP environment file first")
    try:
        done = subprocess.run([tool, "-x", os.path.abspath(ifs_file)], cwd=out_dir, timeout=120,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        raise ScanError("dumpifs took longer than 120 s")
    if done.returncode != 0:
        raise ScanError("dumpifs failed on " + ifs_file)


def extract_disk(disk_file, out_dir, counts, unverified):
    """Read the system and data partitions of a disk image (qnx6) into out_dir/<part>/.
    Returns ({part: [records]}, {part: "disk image" or why the build list is used instead}).
    A partition that cannot be read completely is left out, so the build list is used for it."""
    found, sources, total = {}, {}, 0
    try:
        with open(disk_file, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            table = {DISK_PARTS[k]: (start, length) for k, start, length in qnx6.partitions(handle, size) if k in DISK_PARTS}
            for part in ("system", "data"):
                if part not in table:
                    sources[part] = "build list (no partition of that type in the disk image)"
                    continue
                try:
                    fs = qnx6.Qnx6(handle, *table[part])
                    entries = [item for item in fs.walk() if item[1] == "file"]
                    records = []
                    for path, _, length, node in entries:
                        base = posixpath.basename(path)
                        if length > safepath.MAX_FILE_BYTES:
                            counts["skipped_too_big"] += 1
                            if _relevant(base):
                                unverified.append({"id": part + ":" + path, "image_path": MOUNTS[part] + path, "reason": "file is bigger than 64 MiB"})
                            continue
                        total += length
                        if total > MAX_DISK_BYTES:
                            raise qnx6.Qnx6Error("more than 1 GiB of files")
                        real = os.path.join(out_dir, part, path)
                        os.makedirs(os.path.dirname(real), exist_ok=True)
                        with open(real, "wb") as out:
                            out.write(fs.read(node, safepath.MAX_FILE_BYTES))
                        records.append({"part": part, "path": path, "real": real, "text": None})
                except (qnx6.Qnx6Error, OSError, struct.error) as err:
                    sources[part] = "build list (the disk image part could not be read: " + str(err)[:120] + ")"
                    continue
                found[part] = records
                sources[part] = "disk image"
    except OSError as err:
        raise ScanError(f"cannot read {disk_file}: {err.strerror}")
    except qnx6.Qnx6Error as err:
        raise ScanError(f"{disk_file}: {err}")
    return found, sources


def _walk_ifs(ifs_dir, counts, unverified):
    """Yield (relative path, real path) for regular files; links are counted, not followed."""
    seen = 0
    for folder, dirs, names in os.walk(ifs_dir, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            path = os.path.join(folder, name)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                counts["links"] += 1
            elif stat.S_ISREG(mode):
                if os.lstat(path).st_size > safepath.MAX_FILE_BYTES:
                    counts["skipped_too_big"] += 1
                    if _relevant(name):
                        unverified.append({"id": "ifs:" + os.path.relpath(path, ifs_dir), "image_path": "/" + os.path.relpath(path, ifs_dir), "reason": "file is bigger than 64 MiB"})
                    continue
                seen += 1
                if seen > MAX_FILES:
                    raise ScanError("too many files in the boot image folder")
                yield os.path.relpath(path, ifs_dir).replace(os.sep, "/"), path


def _collect(ifs_dir, build_dir, roots, counts, unverified, disk_parts=None):
    disk_parts = disk_parts or {}
    """Return a list of file records: {id, part, path, image_path, real, text}."""
    records = []
    for rel, real in _walk_ifs(ifs_dir, counts, unverified):
        records.append({"part": "ifs", "path": rel, "real": real, "text": None})
    found_list = False
    for part in ("system", "data"):
        if part in disk_parts:
            records += disk_parts[part]
            continue
        list_file = os.path.join(build_dir, part + ".build")
        if not os.path.isfile(list_file):
            continue
        found_list = True
        try:
            with open(list_file, encoding="utf-8", errors="replace") as handle:
                entries = buildlist.parse(handle.read(safepath.MAX_FILE_BYTES))
        except (OSError, buildlist.BuildListError) as err:
            raise ScanError(f"cannot read {list_file}: {err}")
        for entry in entries:
            if entry.kind == "inline":
                records.append({"part": part, "path": entry.dest, "real": None, "text": entry.text})
            elif entry.kind == "file":
                real, reason = roots.resolve(entry.src)
                if real:
                    records.append({"part": part, "path": entry.dest, "real": real, "text": None})
                else:
                    counts[{"outside": "skipped_outside_roots", "too-big": "skipped_too_big"}.get(reason, "unresolved")] += 1
                    if _relevant(posixpath.basename(entry.dest)):
                        unverified.append({"id": part + ":" + entry.dest, "image_path": MOUNTS[part] + entry.dest,
                                           "reason": {"outside": "source is outside the allowed folders", "too-big": "file is bigger than 64 MiB"}.get(reason, "source file not found")})
            if len(records) > MAX_FILES:
                raise ScanError("too many files in the build lists")
    if not found_list and not disk_parts:
        raise ScanError("no system.build or data.build in " + build_dir)
    seen, unique = set(), []
    for rec in records:
        rec["id"] = rec["part"] + ":" + rec["path"]
        rec["image_path"] = MOUNTS[rec["part"]] + rec["path"]
        if rec["id"] not in seen:
            seen.add(rec["id"])
            unique.append(rec)
    return unique


def _family(base, soname):
    name = soname or base
    if name.startswith(("libcrypto", "libssl")):
        return "openssl"
    if name.startswith("libqcrypto") or re.match(r"qcrypto-.+\.so", name):
        return "qcrypto"
    return None


def _read(rec, limit=safepath.MAX_FILE_BYTES):
    if rec["text"] is not None:
        return rec["text"].encode("utf-8", "replace")
    return safepath.read_limited(rec["real"], limit)


def _analyse_elf(rec, base, model, counts):
    try:
        with safepath.open_regular(rec["real"]) as handle:
            info = elf.read_elf(handle, os.fstat(handle.fileno()).st_size)
    except (elf.ElfError, OSError) as err:
        counts["bad_elf"] += 1
        model["bad_elf"].append({"id": rec["id"], "reason": str(err)})
        if _relevant(base):
            model["unverified"].append({"id": rec["id"], "image_path": rec["image_path"], "reason": "not readable as ELF: " + str(err)})
        return None
    if info is None:
        return None
    crypto = [n for n in info["needed"] if n.startswith(CRYPTO_PREFIXES)]
    kind = "executable" if info["has_interp"] and not info["soname"] else "library"
    model["elfs"].append({"id": rec["id"], "part": rec["part"], "image_path": rec["image_path"], "kind": kind,
                          "soname": info["soname"], "needed": info["needed"], "crypto_libs": crypto})
    family = _family(base, info["soname"])
    if family:
        data = _read(rec)
        version, released = libinfo.openssl_version(data) if family == "openssl" else (None, None)
        model["libs"].append({"id": rec["id"], "image_path": rec["image_path"], "family": family,
                              "soname": info["soname"] or base, "version": version, "released": released,
                              "pq_capable": libinfo.pq_capable(data)})
    if kind == "executable" and base in ("sshd", "ssh"):
        data = _read(rec)
        model["ssh_binaries"][base] = {"path": rec["image_path"], "openssh_version": libinfo.openssh_version(data),
                                       "pq_kex": libinfo.ssh_pq_kex(data)}
    return info


def _text_config(rec, base):
    """A text file that only has the name of a program (for example the PAM file /system/etc/pam/sshd)."""
    if base not in ("sshd", "ssh"):
        return False
    head = _read(rec, 4096)
    return bool(head) and b"\0" not in head


def _analyse_text(rec, base, model):
    """Configuration files and keys; inline blocks and plain files alike."""
    text_names = {"qcrypto.conf": "qcrypto", "sshd_config": "sshd", "ssh_config": "ssh"}
    if base in text_names:
        text = _read(rec, MAX_CONFIG_BYTES).decode("utf-8", "replace")
        model["config_files"][text_names[base]] = {"path": rec["image_path"], "text": text,
                                                   "source": "inline" if rec["text"] is not None else "file"}
    elif base.endswith(KEY_SUFFIXES) or base.startswith("ssh_host_") or rec["image_path"] in model["host_key_paths"]:
        for item in keys.summarize(_read(rec, keys.MAX_BYTES)):
            item.update({"id": rec["id"], "image_path": rec["image_path"]})
            model["keys"].append(item)


def _host_key_paths(records):
    """Paths named by HostKey lines, so those files are read as keys whatever they are called."""
    paths = set()
    for rec in records:
        if posixpath.basename(rec["path"]) == "sshd_config":
            try:
                text = _read(rec, MAX_CONFIG_BYTES).decode("utf-8", "replace")
            except OSError:
                continue
            paths.update(configs.parse_ssh_config(text, True)["host_keys"])
    return paths


def _finish_configs(model):
    cfg = {"qcrypto": None, "sshd": None, "ssh": None}
    files = model.pop("config_files")
    if "qcrypto" in files:
        cfg["qcrypto"] = {"path": files["qcrypto"]["path"], "entries": configs.parse_qcrypto(files["qcrypto"]["text"])}
    for name, server in (("sshd", True), ("ssh", False)):
        binary = model["ssh_binaries"].get(name)
        if name not in files and not binary:
            continue
        parsed = configs.parse_ssh_config(files[name]["text"], server) if name in files else \
            {"settings": {}, "host_keys": [], "match_blocks": 0}
        cfg[name] = {"path": files[name]["path"] if name in files else None,
                     "source": files[name]["source"] if name in files else None,
                     "binary": binary, **parsed}
    model["configs"] = cfg
    del model["ssh_binaries"]
    del model["host_key_paths"]


def scan_image(ifs_dir, build_dir, roots, name, arch, ifs_label, disk_parts=None, sources=None):
    counts = {"links": 0, "skipped_outside_roots": 0, "skipped_too_big": 0, "unresolved": 0, "bad_elf": 0, "unreadable": 0}
    model = {"elfs": [], "libs": [], "keys": [], "bad_elf": [], "unverified": [], "config_files": {}, "ssh_binaries": {}}
    records = _collect(ifs_dir, build_dir, roots, counts, model["unverified"], disk_parts or {})
    model["host_key_paths"] = _host_key_paths(records)
    for rec in records:
        base = posixpath.basename(rec["path"])
        try:
            info = _analyse_elf(rec, base, model, counts) if rec["real"] else None
            if info is None and not any(u["id"] == rec["id"] for u in model["unverified"][-1:]):
                if rec["real"] and _expect_elf(base) and not _text_config(rec, base):
                    model["unverified"].append({"id": rec["id"], "image_path": rec["image_path"], "reason": "file is not an ELF file"})
                _analyse_text(rec, base, model)
        except OSError:
            counts["unreadable"] += 1
            if _relevant(base):
                model["unverified"].append({"id": rec["id"], "image_path": rec["image_path"], "reason": "file could not be read"})
    _finish_configs(model)
    for key in ("elfs", "libs", "keys"):
        model[key].sort(key=lambda item: (item["id"], item.get("algorithm", ""), item.get("size") or 0))
    crypto = [e for e in model["elfs"] if e["crypto_libs"]]
    counts.update({"files": len(records), "elf": len(model["elfs"]), "crypto_elf": len(crypto),
                   "crypto_executables": sum(1 for e in crypto if e["kind"] == "executable")})
    model["image"] = {"name": name, "arch": arch, "ifs": ifs_label,
                      "build_files": [p + ".build" for p in ("system", "data")
                                      if os.path.isfile(os.path.join(build_dir, p + ".build"))],
                      "counts": counts}
    if sources:
        model["image"]["sources"] = sources
        model["image"]["partition_notes"] = [f"{part} partition: files from the {how}" for part, how in sorted(sources.items())
                                             if how != "disk image"]
    return model


def scan_with_temp(ifs_file, ifs_dir, build_dir, roots, name, arch, disk=None):
    """Scan, extracting the boot image first when a file was given. With a disk image the
    system and data partitions are read from it (into a temporary folder) instead of the build lists."""
    with tempfile.TemporaryDirectory(prefix="qnxcbom-ifs-") as temp:
        disk_dir = os.path.join(temp, "disk")
        os.mkdir(disk_dir)
        extra = {"skipped_too_big": 0}
        unverified = []
        parts, sources = extract_disk(disk, disk_dir, extra, unverified) if disk else ({}, None)
        if ifs_dir:
            ifs_dir_used, label = ifs_dir, os.path.basename(os.path.abspath(ifs_dir))
        else:
            ifs_dir_used = os.path.join(temp, "ifs")
            os.mkdir(ifs_dir_used)
            extract_ifs(ifs_file, ifs_dir_used)
            label = os.path.basename(ifs_file)
        model = scan_image(ifs_dir_used, build_dir, roots, name, arch, label, parts, sources)
        model["image"]["counts"]["skipped_too_big"] += extra["skipped_too_big"]
        model["unverified"] += unverified
        return model
