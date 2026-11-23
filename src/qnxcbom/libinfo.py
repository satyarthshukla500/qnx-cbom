# Looks inside library and program files for version strings and post-quantum names.
import re

_OPENSSL = re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) (\d{1,2} [A-Z][a-z]{2} \d{4})")
_PQ_NAMES = re.compile(rb"ML-KEM|MLKEM|ML-DSA|MLDSA|SLH-DSA")
_OPENSSH = re.compile(rb"OpenSSH_(\d+\.\d+p\d+)")
SSH_PQ_KEX = ("mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com")  # names a config may list


def openssl_version(data: bytes):
    """Return (version, release date text) of the first OpenSSL banner, or (None, None)."""
    found = _OPENSSL.search(data)
    if not found:
        return None, None
    return found.group(1).decode(), found.group(2).decode()


def pq_capable(data: bytes) -> bool:
    return _PQ_NAMES.search(data) is not None


def openssh_version(data: bytes):
    found = _OPENSSH.search(data)
    return found.group(1).decode() if found else None


def ssh_pq_kex(data: bytes) -> list[str]:
    """Post-quantum key exchange names that appear in an ssh or sshd binary."""
    return [name for name in SSH_PQ_KEX if name.encode() in data]
