# Builds small synthetic images for the tests. Nothing here comes from the SDK.
import os
import shutil
import struct
import subprocess
import tempfile


def make_elf(needed=(), soname=None, interp=True, extra=b""):
    """A minimal valid ELF64 (little endian) with PT_LOAD, PT_DYNAMIC and optionally PT_INTERP."""
    names = list(needed) + ([soname] if soname else [])
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n in names)
    offsets, pos = {}, 1
    for n in names:
        offsets[n] = pos
        pos += len(n) + 1
    phnum = 2 + (1 if interp else 0)
    interp_bytes = b"/usr/lib/ldqnx-64.so.2\0" if interp else b""
    interp_off = 64 + 56 * phnum
    str_off = interp_off + len(interp_bytes)
    dyn_off = (str_off + len(strtab) + 7) & ~7
    dyn = b"".join(struct.pack("<qQ", 1, offsets[n]) for n in needed)
    if soname:
        dyn += struct.pack("<qQ", 14, offsets[soname])
    dyn += struct.pack("<qQ", 5, str_off) + struct.pack("<qQ", 0, 0)
    total = dyn_off + len(dyn)
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 4096)
    phdrs += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, dyn_off, len(dyn), len(dyn), 8)
    if interp:
        phdrs += struct.pack("<IIQQQQQQ", 3, 4, interp_off, interp_off, interp_off, len(interp_bytes), len(interp_bytes), 1)
    body = header + phdrs + interp_bytes + strtab
    body += bytes(dyn_off - len(body)) + dyn
    return body + extra


SSHD_CONFIG = "Protocol 2\nHostKey /data/var/ssh/ssh_host_rsa_key\nCiphers aes256-ctr\n{kex}\nPermitRootLogin no\n"


def make_image(root, openssl="OpenSSL 3.0.22 25 Aug 2026", kex="KexAlgorithms curve25519-sha256@libssh.org",
               ssh_pq=True, extra_system="", extra_ifs=None):
    """Create <root>/ifs, <root>/proj/output/build and <root>/proj/sdk. Returns (ifs_dir, build_dir, project_dir)."""
    ifs = os.path.join(root, "ifs")
    proj = os.path.join(root, "proj")
    build = os.path.join(proj, "output", "build")
    sdk = os.path.join(proj, "sdk")
    for d in (os.path.join(ifs, "proc", "boot"), build, os.path.join(sdk, "bin"), os.path.join(sdk, "lib")):
        os.makedirs(d, exist_ok=True)
    pq = b" mlkem768x25519-sha256 sntrup761x25519-sha512" if ssh_pq else b""
    files = {
        os.path.join(ifs, "proc", "boot", "libcrypto.so.3"): make_elf(["libc.so.6"], "libcrypto.so.3", False, b"\0" + openssl.encode() + b"\0"),
        os.path.join(ifs, "proc", "boot", "qcrypto.conf"): b"openssl-3 tags=*\n",
        os.path.join(ifs, "proc", "boot", "qcrypto-openssl-3.so"): make_elf(["libcrypto.so.3"], "qcrypto-openssl-3.so", False),
        os.path.join(sdk, "bin", "sshd"): make_elf(["libcrypto.so.3", "libc.so.6"], None, True, b"\0OpenSSH_10.4p1" + pq + b"\0"),
        os.path.join(sdk, "bin", "ssh"): make_elf(["libcrypto.so.3"], None, True, b"\0OpenSSH_10.4p1" + pq + b"\0"),
        os.path.join(sdk, "bin", "ls"): make_elf(["libc.so.6"], None, True),
    }
    for path, data in {**files, **(extra_ifs or {})}.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    system = ("[+dupignore]\nbin/sshd=bin/sshd\nbin/ssh=bin/ssh\n[type=hlink] bin/ll=ls\nbin/ls=bin/ls\n[perms=444] etc/ssh/sshd_config={\n"
              + SSHD_CONFIG.format(kex=kex) + "}\n" + extra_system)
    with open(os.path.join(build, "system.build"), "w") as handle:
        handle.write(system)
    with open(os.path.join(build, "data.build"), "w") as handle:
        handle.write("[type=dir] var\n")
    return ifs, build, proj


def generate_keys(directory):
    """Real keys made with the host openssl/ssh-keygen. Returns {name: path}; empty dict if the tools are missing."""
    out = {}
    openssl = shutil.which("openssl", path="/usr/bin:/bin") or "openssl"  # the SDK copy has no config file
    try:
        def run(*args):
            subprocess.run(args, check=True, capture_output=True, timeout=60)
        run(openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", os.path.join(directory, "rsa.key"))
        run(openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", os.path.join(directory, "ec.key"))
        run(openssl, "genpkey", "-algorithm", "ED25519", "-out", os.path.join(directory, "ed.key"))
        run(openssl, "req", "-x509", "-new", "-key", os.path.join(directory, "ec.key"), "-subj", "/CN=test.example", "-days", "30", "-out", os.path.join(directory, "cert.pem"))
        run(openssl, "pkey", "-in", os.path.join(directory, "rsa.key"), "-pubout", "-out", os.path.join(directory, "rsa.pub.pem"))
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.path.join(directory, "ssh_host_ed25519_key"))
        run("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", os.path.join(directory, "ssh_host_rsa_key"))
        run("ssh-keygen", "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-f", os.path.join(directory, "ssh_host_ecdsa_key"))
    except (OSError, subprocess.SubprocessError):
        return {}
    return {name: os.path.join(directory, name) for name in os.listdir(directory)}


def tmpdir():
    return tempfile.TemporaryDirectory(prefix="qnxcbom-test-")
