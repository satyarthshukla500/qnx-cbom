# Summarises public keys, private keys and certificates: algorithm, size, curve,
# certificate subject name and end date. Key material is parsed only far enough
# to read these fields and is never stored or printed.
import base64
import binascii
import re
import struct

MAX_BYTES = 1_000_000
MAX_BLOCKS = 16
MAX_CHILDREN = 256

OIDS = {
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.2.840.10040.4.1": "DSA",
    "1.3.101.110": "X25519", "1.3.101.111": "X448", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512", "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}
CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384),
          "1.3.132.0.35": ("P-521", 521), "1.3.132.0.10": ("secp256k1", 256)}
FIXED_SIZE = {"Ed25519": 256, "Ed448": 456, "X25519": 256, "X448": 448}
SSH_CURVES = {"nistp256": ("P-256", 256), "nistp384": ("P-384", 384), "nistp521": ("P-521", 521)}
_SSH_PUB = re.compile(r"((?:sk-)?(?:ssh|ecdsa)-[a-z0-9@.-]+)[ \t]+([A-Za-z0-9+/=]+)")
MAX_LINES = 5000
MAX_LINE = 8192


def _pem_blocks(text):
    """(label, body) pairs found with plain searches, so a hostile file cannot make the work grow with its square."""
    found, pos, misses = [], 0, 0
    while len(found) < MAX_BLOCKS and misses < MAX_BLOCKS:
        begin = text.find("-----BEGIN ", pos)
        if begin < 0:
            break
        close = text.find("-----", begin + 11, begin + 70)
        label = text[begin + 11:close] if close > 0 else ""
        if not re.fullmatch(r"[A-Z0-9 ]{1,40}", label):
            pos = begin + 11
            continue
        marker = f"-----END {label}-----"
        end = text.find(marker, close + 5)
        if end < 0:
            misses += 1
            pos = close + 5
            continue
        found.append((label, text[close + 5:end]))
        pos = end + len(marker)
    return found


class KeyParseError(Exception):
    pass


# ---- DER ---------------------------------------------------------------

def _tlv(data, pos, end):
    """Return (tag, value_start, value_end) of the element at pos."""
    if pos + 2 > end:
        raise KeyParseError("short DER")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > end:
            raise KeyParseError("bad DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > end:
        raise KeyParseError("DER element too long")
    return tag, pos, pos + length


def _children(data, start, end):
    out, pos = [], start
    while pos < end:
        tag, vstart, vend = _tlv(data, pos, end)
        out.append((tag, vstart, vend))
        pos = vend
        if len(out) > MAX_CHILDREN:
            raise KeyParseError("too many DER elements")
    return out


def _oid(data, vstart, vend):
    raw = data[vstart:vend]
    if not raw:
        raise KeyParseError("empty OID")
    parts, value = [str(min(raw[0] // 40, 2)), str(raw[0] - 40 * min(raw[0] // 40, 2))], 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _int_bits(data, vstart, vend):
    return int.from_bytes(data[vstart:vend], "big").bit_length()


def _inner_bits(data, start, end):
    """Modulus size when the range holds one SEQUENCE (a wrapped RSA key)."""
    _tag, inner_start, inner_end = _tlv(data, start, end)
    return _rsa_bits(data, inner_start, inner_end)


def _rsa_bits(data, start, end):
    """Modulus size from an RSAPublicKey or RSAPrivateKey sequence."""
    kids = _children(data, start, end)
    index = 1 if len(kids) > 2 else 0  # private keys start with a version number
    return _int_bits(data, kids[index][1], kids[index][2])


def _algorithm(oid, params_oid):
    """Return (algorithm name, curve name or None, fixed size or None)."""
    name = OIDS.get(oid)
    if name is None and oid.startswith("2.16.840.1.101.3.4.3.") and 20 <= int(oid.rsplit(".", 1)[1]) <= 31:
        name = "SLH-DSA"
    if name == "EC" and params_oid in CURVES:
        return "EC", CURVES[params_oid][0], CURVES[params_oid][1]
    if name is None:
        return "OID " + oid, None, None
    return name, None, FIXED_SIZE.get(name)


def _alg_id(data, start, end):
    kids = _children(data, start, end)
    oid = _oid(data, kids[0][1], kids[0][2])
    params = None
    if len(kids) > 1 and kids[1][0] == 0x06:
        params = _oid(data, kids[1][1], kids[1][2])
    return oid, params


def _from_spki(data, start, end):
    kids = _children(data, start, end)
    oid, params = _alg_id(data, kids[0][1], kids[0][2])
    name, curve, size = _algorithm(oid, params)
    if name == "RSA":
        size = _inner_bits(data, kids[1][1] + 1, kids[1][2])
    return {"algorithm": name, "size": size, "curve": curve}


def _from_pkcs8(data, start, end):
    kids = _children(data, start, end)
    oid, params = _alg_id(data, kids[1][1], kids[1][2])
    name, curve, size = _algorithm(oid, params)
    if name == "RSA":
        size = _inner_bits(data, kids[2][1], kids[2][2])
    return {"algorithm": name, "size": size, "curve": curve}


def _from_certificate(data, start, end):
    tbs = _children(data, *_tlv(data, start, end)[1:])
    kids = _children(data, tbs[0][1], tbs[0][2])
    pos = 1 if kids[0][0] == 0xA0 else 0  # optional explicit version
    validity = _children(data, kids[pos + 3][1], kids[pos + 3][2])
    info = _from_spki(data, kids[pos + 5][1], kids[pos + 5][2])
    info["subject"] = _common_name(data, kids[pos + 4])
    info["not_after"] = _date(data, validity[1])
    return info


def _common_name(data, name):
    for rdn in _children(data, name[1], name[2]):
        for pair in _children(data, rdn[1], rdn[2]):
            kids = _children(data, pair[1], pair[2])
            if len(kids) == 2 and _oid(data, kids[0][1], kids[0][2]) == "2.5.4.3":
                raw = data[kids[1][1]:kids[1][2]][:128]
                return raw.decode("utf-16-be" if kids[1][0] == 0x1E else "utf-8", "replace")
    return None


def _date(data, element):
    """Certificate end time as an ISO timestamp, or None when it cannot be read."""
    tag, start, end = element
    text = data[start:end].decode("ascii", "replace")
    pattern = r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z" if tag == 0x17 else r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z"
    parts = re.fullmatch(pattern, text)
    if not parts:
        return None
    year = parts.group(1) if tag == 0x18 else ("20" if int(parts.group(1)) < 50 else "19") + parts.group(1)
    return f"{year}-{parts.group(2)}-{parts.group(3)}T{parts.group(4)}:{parts.group(5)}:{parts.group(6)}Z"


# ---- OpenSSH public key blobs -----------------------------------------

def _ssh_string(blob, pos):
    if pos + 4 > len(blob):
        raise KeyParseError("short ssh blob")
    length, = struct.unpack_from(">I", blob, pos)
    if pos + 4 + length > len(blob):
        raise KeyParseError("bad ssh string")
    return blob[pos + 4:pos + 4 + length], pos + 4 + length


def _from_ssh_blob(blob):
    kind, pos = _ssh_string(blob, 0)
    kind = kind.decode("ascii", "replace")
    if kind == "ssh-rsa":
        _e, pos = _ssh_string(blob, pos)
        modulus, _ = _ssh_string(blob, pos)
        return {"algorithm": "RSA", "size": int.from_bytes(modulus, "big").bit_length(), "curve": None}
    if kind.startswith("ecdsa-sha2-") or kind.startswith("sk-ecdsa-sha2-"):
        curve, _ = _ssh_string(blob, pos)
        name, size = SSH_CURVES.get(curve.decode("ascii", "replace"), (curve.decode("ascii", "replace"), None))
        return {"algorithm": "EC", "size": size, "curve": name}
    if kind in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        return {"algorithm": "Ed25519", "size": 256, "curve": None}
    if kind == "ssh-dss":
        return {"algorithm": "DSA", "size": None, "curve": None}
    return {"algorithm": kind, "size": None, "curve": None}


def _from_openssh_private(raw):
    """Read only the public half stored in the clear at the start of the file."""
    magic = b"openssh-key-v1\0"
    if not raw.startswith(magic):
        raise KeyParseError("not an OpenSSH key")
    pos = len(magic)
    for _ in range(3):  # cipher name, kdf name, kdf options
        _, pos = _ssh_string(raw, pos)
    pos += 4            # number of keys
    blob, _ = _ssh_string(raw, pos)
    return _from_ssh_blob(blob)


# ---- entry point ---------------------------------------------------------

def _record(kind, info):
    info.setdefault("subject", None)
    info.setdefault("not_after", None)
    info["kind"] = kind
    info["quantum_safe"] = info["algorithm"].startswith(("ML-", "SLH-"))
    return info


def _pem_block(label, der):
    if label == "CERTIFICATE":
        return _record("certificate", _from_certificate(der, 0, len(der)))
    if label == "PUBLIC KEY":
        tag, start, end = _tlv(der, 0, len(der))
        return _record("public-key", _from_spki(der, start, end))
    if label == "RSA PUBLIC KEY":
        return _record("public-key", {"algorithm": "RSA", "size": _rsa_bits(der, *_tlv(der, 0, len(der))[1:]), "curve": None})
    if label == "PRIVATE KEY":
        tag, start, end = _tlv(der, 0, len(der))
        return _record("private-key", _from_pkcs8(der, start, end))
    if label == "RSA PRIVATE KEY":
        return _record("private-key", {"algorithm": "RSA", "size": _rsa_bits(der, *_tlv(der, 0, len(der))[1:]), "curve": None})
    if label == "EC PRIVATE KEY":
        tag, start, end = _tlv(der, 0, len(der))
        curve, size = None, None
        for ctag, cstart, cend in _children(der, start, end):
            if ctag == 0xA0:
                oid = _oid(der, *_tlv(der, cstart, cend)[1:])
                curve, size = CURVES.get(oid, ("OID " + oid, None))
        return _record("private-key", {"algorithm": "EC", "size": size, "curve": curve})
    if label == "OPENSSH PRIVATE KEY":
        return _record("private-key", _from_openssh_private(der))
    if label == "ENCRYPTED PRIVATE KEY":
        return _record("private-key", {"algorithm": "unknown (encrypted)", "size": None, "curve": None})
    return None


def summarize(raw: bytes) -> list[dict]:
    """Return one summary dict per key or certificate found in the file content."""
    raw = raw[:MAX_BYTES]
    text = raw.decode("latin-1")
    found = []
    for label, body in _pem_blocks(text):
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
            record = _pem_block(label, der)
        except (KeyParseError, binascii.Error, ValueError, IndexError, struct.error):
            record = _record("private-key" if "PRIVATE" in label else "public-key",
                             {"algorithm": "unreadable", "size": None, "curve": None})
        if record:
            found.append(record)
    if not found:
        lines = [line.strip(" \t\r")[:MAX_LINE] for line in text.split("\n", MAX_LINES)[:MAX_LINES]]
        matches = [m.groups() for m in (_SSH_PUB.match(line) for line in lines) if m][:MAX_BLOCKS]
        for kind, body in matches:
            try:
                found.append(_record("public-key", _from_ssh_blob(base64.b64decode(body, validate=True))))
            except (KeyParseError, binascii.Error, ValueError, struct.error):
                found.append(_record("public-key", {"algorithm": "unreadable", "size": None, "curve": None}))
    return found
