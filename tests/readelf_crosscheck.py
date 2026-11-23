# Compares the project's ELF reader with the SDK readelf on every ELF file of a real image.
# Usage: readelf_crosscheck.py IFS_DIR BUILD_DIR  (SDK environment must be sourced)
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from qnxcbom import elf, image, safepath  # noqa: E402


def readelf_info(path):
    out = subprocess.run(["ntox86_64-readelf", "-d", path], capture_output=True, text=True, timeout=60).stdout
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[(.*?)\]", out)
    soname = re.findall(r"\(SONAME\)\s+Library soname: \[(.*?)\]", out)
    return needed, (soname[0] if soname else None)


def main(ifs_dir, build_dir):
    home = os.path.expanduser("~")
    roots = safepath.Roots([os.path.join(build_dir, "..", ".."), os.environ["QNX_TARGET"] + "/x86_64", os.environ["QNX_TARGET"]])
    counts = {"links": 0, "skipped_outside_roots": 0, "skipped_too_big": 0, "unresolved": 0, "bad_elf": 0}
    same = diff = 0
    for rec in image._collect(ifs_dir, build_dir, roots, counts, []):
        if not rec["real"]:
            continue
        with open(rec["real"], "rb") as handle:
            info = elf.read_elf(handle, os.fstat(handle.fileno()).st_size)
        if info is None:
            continue
        theirs = readelf_info(rec["real"])
        if (info["needed"], info["soname"]) == theirs:
            same += 1
        else:
            diff += 1
            print("DIFFERENT", rec["id"], info["needed"], info["soname"], theirs)
    print(f"ELF files compared with ntox86_64-readelf -d: {same + diff}; identical needed/soname: {same}; different: {diff}")
    return 1 if diff else 0


sys.exit(main(*sys.argv[1:3]))
