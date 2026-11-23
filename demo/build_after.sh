#!/bin/bash
# Builds the upgraded lab image in build/after/ from a COPY of the stock mkqnximage project:
#   - /proc/boot/libcrypto.so.3 and /system/lib/libssl.so.3 are the OpenSSL 3.5.9 files
#   - sshd_config lists mlkem768x25519-sha256 first
# The stock project is only read. Needs the QNX SDP environment and demo/build_openssl.sh done.
# usage: build_after.sh STOCK_PROJECT_DIR (default ~/qnximg)
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
stock=${1:-$HOME/qnximg}
ossl=$root/build/openssl35/b
after=$root/build/after/qnximg
[ -f "$ossl/libcrypto.so.3" ] || { echo "run demo/build_openssl.sh first" >&2; exit 1; }
mkdir -p "$root/build/after"
case $after in "$root"/build/after/*) ;; *) echo "unexpected path $after" >&2; exit 1;; esac
rm -rf "$after"   # only ever our own build/after folder (checked above)
cp -r "$stock" "$after"
cd "$after"
# the copy holds the stock disk image; remove it so a failed build cannot pass for the new one
rm -f output/disk-qemu output/disk-qemu.vmdk
disk_tool=$QNX_HOST/../../common/mkqnximage/rundiskimage
[ -f "$disk_tool" ] || { echo "rundiskimage not found at $disk_tool" >&2; exit 1; }
mkdir -p local/openssl35
cp "$ossl/libcrypto.so.3" "$ossl/libssl.so.3" local/openssl35/
sed -i 's|^usr/lib/libcrypto.so.3$|libcrypto.so.3=local/openssl35/libcrypto.so.3|' output/build/ifs.build
sed -i 's|^lib/libssl.so.3=usr/lib/libssl.so.3$|lib/libssl.so.3=local/openssl35/libssl.so.3|' output/build/system.build
sed -i 's|^KexAlgorithms curve25519-sha256@libssh.org,|KexAlgorithms mlkem768x25519-sha256,curve25519-sha256@libssh.org,|' output/build/system.build
grep -q "local/openssl35/libcrypto" output/build/ifs.build && grep -q "local/openssl35/libssl" output/build/system.build && grep -q "^KexAlgorithms mlkem768x25519-sha256" output/build/system.build
mkifs -o output output/build/ifs.build output/ifs.bin > /dev/null
mkqnx6fsimg output/build/system.build output/system.part > /dev/null
mkqnx6fsimg output/build/data.build output/data.part > /dev/null
# the new system partition is a little bigger than the stock slot (libssl 3.5 is bigger)
size=$(stat -c %s output/system.part)
sed -i "s/^SYS_SECTORS=.*/SYS_SECTORS=$((size / 512))/" output/di.params
IMAGE_TYPE=qemu bash "$disk_tool" > output/rundiskimage.log 2>&1 || true   # its last step (a .vmdk descriptor) may fail; the raw disk is what QEMU uses
[ -f output/disk-qemu ] && [ output/disk-qemu -nt output/system.part ] || { echo "disk image was not created:" >&2; cat output/rundiskimage.log >&2; exit 1; }
ls -l output/ifs.bin output/disk-qemu
