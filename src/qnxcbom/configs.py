# Parsers for qcrypto.conf, sshd_config and ssh_config. Text in, plain dicts out.
import re

MAX_LINE = 4096
LIST_SETTINGS = {"kexalgorithms": "KexAlgorithms", "hostkeyalgorithms": "HostKeyAlgorithms",
                 "ciphers": "Ciphers", "macs": "MACs"}


def parse_qcrypto(text: str) -> list[dict]:
    """Lines look like: <plugin> tags=a,b ; the last one is usually tags=*."""
    entries = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        tags = []
        for part in parts[1:]:
            if part.startswith("tags="):
                tags = [t for t in part[5:].split(",") if t]
        entries.append({"plugin": parts[0][:MAX_LINE], "tags": tags})
    return entries


def _mode_and_list(value: str):
    mode = {"+": "add", "-": "remove", "^": "prepend"}.get(value[:1], "explicit")
    body = value[1:] if mode != "explicit" else value
    return mode, [item.strip() for item in body.split(",") if item.strip()]


def parse_ssh_config(text: str, server: bool) -> dict:
    """First value of each setting wins, like OpenSSH. Reading stops at a Match
    line (and, for the client file, at a Host line other than 'Host *')."""
    settings, host_keys, match_blocks, includes = {}, [], 0, 0
    # OpenSSH ends a line only at a newline and splits words only at spaces and tabs
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip(" \t\r")[:MAX_LINE]
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[ \t]*=[ \t]*|[ \t]+", line, maxsplit=1)
        key = parts[0].lower()
        value = parts[1].strip(" \t").strip('"') if len(parts) > 1 else ""
        if key == "match" or (not server and key == "host" and value != "*"):
            match_blocks += 1
            break
        if key == "include":
            includes += 1
        if key == "hostkey" and server and value:
            host_keys.append(value)
        elif key in LIST_SETTINGS and value:
            name = LIST_SETTINGS[key]
            if name not in settings:
                mode, items = _mode_and_list(value)
                settings[name] = {"value": value, "mode": mode, "items": items, "line": number}
    return {"settings": settings, "host_keys": host_keys, "match_blocks": match_blocks, "includes": includes}
