# Reads mkqnximage build lists (system.build, data.build).
# A line is "[attributes] dest = src" or an inline block "dest = {" ... "}".
# Only the text is parsed here; nothing from the list is run or opened.
import re
from dataclasses import dataclass

MAX_LINES = 200_000
MAX_INLINE_BYTES = 1_000_000

# entry types that are not regular files on the target
NOT_FILE_TYPES = {"dir", "link", "hlink", "fifo", "nod"}

_LINE = re.compile(r"^\s*((?:\[[^\]]*\]\s*)*)(.*?)\s*$")
_ATTR = re.compile(r"\[([^\]]*)\]")


@dataclass
class Entry:
    dest: str           # path on the target partition, no leading slash
    src: str | None     # source path as written in the list (None for inline)
    kind: str           # "file", "inline" or one of NOT_FILE_TYPES
    text: str | None    # inline content
    line: int


class BuildListError(Exception):
    pass


def _entry_type(attrs: str) -> str | None:
    for group in _ATTR.findall(attrs):
        for word in group.split():
            if word.startswith("type="):
                return word[5:]
    return None


def parse(text: str) -> list[Entry]:
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise BuildListError("build list has too many lines")
    entries: list[Entry] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        attrs, rest = _LINE.match(raw).groups()
        if not rest:
            continue  # attribute-only line: sets defaults we do not use
        etype = _entry_type(attrs)
        if "=" in rest:
            dest, _, src = (part.strip() for part in rest.partition("="))
        else:
            dest, src = rest, rest
        dest = dest.lstrip("/")
        if src == "{":
            # inline block: collect lines up to a lone "}"
            block, size = [], 0
            while i < len(lines) and lines[i].strip() != "}":
                size += len(lines[i]) + 1
                if size > MAX_INLINE_BYTES:
                    raise BuildListError(f"inline block for {dest} is too big")
                block.append(lines[i])
                i += 1
            if i >= len(lines):
                raise BuildListError(f"inline block for {dest} is not closed")
            i += 1
            entries.append(Entry(dest, None, "inline", "\n".join(block) + "\n", i))
        elif etype in NOT_FILE_TYPES:
            entries.append(Entry(dest, src, etype, None, i))
        elif dest:
            entries.append(Entry(dest, src, "file", None, i))
    return entries
