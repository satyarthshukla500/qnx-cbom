#!/bin/bash
# Builds the payload disk image (a qnx6 file system) for run_qemu.py.
# usage: make_payload.sh OUT.img OPENSSL_BUILD_DIR   (needs the QNX SDP environment)
set -eu
out=$1
ossl=$2
here=$(cd "$(dirname "$0")" && pwd)
probe=$here/../probe/build/x86_64/cbom_probe
for needed in "$probe" "$ossl/apps/openssl" "$ossl/apps/openssl.cnf" "$ossl/libcrypto.so.3" "$ossl/libssl.so.3"; do
    [ -f "$needed" ] || { echo "missing $needed" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/payload.build" <<LIST
[num_inodes=*200]
[num_sectors=*65536]
[uid=0 gid=0 perms=0755]
cbom_probe=$probe
o35/openssl=$ossl/apps/openssl
o35/libcrypto.so.3=$ossl/libcrypto.so.3
o35/libssl.so.3=$ossl/libssl.so.3
[perms=0644]
o35/openssl.cnf=$ossl/apps/openssl.cnf
LIST
for script in "$here"/target/*.sh; do
    echo "$(basename "$script")=$script" >> "$work/payload.build"
done
mkqnx6fsimg "$work/payload.build" "$out" > /dev/null
ls -l "$out"
