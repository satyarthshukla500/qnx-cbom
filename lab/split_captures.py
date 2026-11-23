# Cuts the CBOM-BEGIN ... CBOM-END blocks out of a console log into numbered files and
# writes the heading ("=== ...") that came before each block to OUT_PREFIX-labels.txt.
# usage: split_captures.py LOG OUT_PREFIX   -> OUT_PREFIX-1.txt, OUT_PREFIX-2.txt, ... and OUT_PREFIX-labels.txt
import re
import sys
import zlib
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
if not text.strip():
    sys.exit("split_captures: log is empty: " + sys.argv[1])
labels = []
pattern = re.compile(r"CBOM-BEGIN\n(.*?)\nCBOM-END len=(\d+) crc32=([0-9a-f]{8})\n", re.S)
for number, match in enumerate(pattern.finditer(text), 1):
    body = match.group(1)
    if len(body.encode()) != int(match.group(2)) or zlib.crc32(body.encode()) != int(match.group(3), 16):
        sys.exit(f"split_captures: capture {number} is damaged (length or crc32)")
    heading = [line for line in text[:match.start()].splitlines() if line.startswith("=== ")]
    labels.append(heading[-1] if heading else "")
    Path(f"{sys.argv[2]}-{number}.txt").write_text(match.group(0), encoding="utf-8")
Path(f"{sys.argv[2]}-labels.txt").write_text("".join(f"{i}\t{label}\n" for i, label in enumerate(labels, 1)), encoding="utf-8")
print(len(labels), "capture(s)")
