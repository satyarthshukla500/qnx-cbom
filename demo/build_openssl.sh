#!/bin/bash
# Builds OpenSSL 3.5.9 for QNX x86_64 with qcc into build/openssl35/ (the SHA-256 file comes from the same host as the tarball, so it only detects a damaged download).
# Needs the QNX SDP environment, curl, perl and make. Skips the work when the library already exists.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/openssl35
[ -f "$out/b/libcrypto.so.3" ] && [ -f "$out/b/apps/openssl" ] && [ -f "$out/b/libssl.so.3" ] && { echo "OpenSSL 3.5.9 already built in $out/b"; exit 0; }
mkdir -p "$out/src"
cd "$out"
base=https://github.com/openssl/openssl/releases/download/openssl-3.5.9
curl -fsSL -o openssl-3.5.9.tar.gz "$base/openssl-3.5.9.tar.gz"
curl -fsSL -o openssl-3.5.9.tar.gz.sha256 "$base/openssl-3.5.9.tar.gz.sha256"
echo "$(cut -d' ' -f1 openssl-3.5.9.tar.gz.sha256)  openssl-3.5.9.tar.gz" | sha256sum -c -
tar -xzf openssl-3.5.9.tar.gz -C src
mkdir -p b
cd b
# own Configure target: plain unix 64-bit, no Linux-only parts (see demo/qnx-generic64.conf)
../src/openssl-3.5.9/Configure --config="$root/demo/qnx-generic64.conf" qnx-generic64 no-asm no-tests no-makedepend \
    AR=ntox86_64-ar RANLIB=ntox86_64-ranlib --prefix=/opt/ossl35 --openssldir=/opt/ossl35/ssl > ../configure.log 2>&1
make -j"$(nproc)" build_sw > ../make.log 2>&1
ls -l libcrypto.so.3 libssl.so.3 apps/openssl
