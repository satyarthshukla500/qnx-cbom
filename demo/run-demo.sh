#!/bin/bash
# Regenerates the whole before/after demo with one command:
#   probe build -> OpenSSL 3.5.9 build -> upgraded lab image -> two QEMU boots -> scans -> diff
# Needs: QNX SDP 8.0.6 environment (source qnxsdp-env.sh), a mkqnximage x86_64 QEMU project (default ~/qnximg),
# qemu-system-x86_64, curl, perl, make. Nothing in the stock project is changed.
# Process ids and crc values differ from run to run; the verdicts do not. The scan date defaults to today
# (end-of-life checks depend on it); EVIDENCE=1 uses 2026-11-23 unless DEMO_DATE is set.
# usage: demo/run-demo.sh [STOCK_PROJECT_DIR]      EVIDENCE=1 also copies the results into evidence/; SKIP_BOOT=1 reuses the logs in build/demo
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
stock=${1:-$HOME/qnximg}
out=$root/build/demo
[ -n "${QNX_TARGET:-}" ] || { echo "source qnxsdp-env.sh first" >&2; exit 1; }
[ -f "$stock/output/ifs.bin" ] || { echo "no stock image in $stock/output" >&2; exit 1; }
mkdir -p "$out"
cd "$root"

echo "== 1/6 probe (qcc, x86_64 and aarch64le)"
make -s -C probe
echo "== 2/6 OpenSSL 3.5.9 for QNX"
demo/build_openssl.sh
echo "== 3/6 upgraded lab image"
demo/build_after.sh "$stock"
if [ "${SKIP_BOOT:-0}" = 1 ]; then
    echo "== 4-5/6 skipped (SKIP_BOOT=1): using the logs already in $out"
    [ -s "$out/stock.log" ] && [ -s "$out/after.log" ] || { echo "no logs in $out" >&2; exit 1; }
else
echo "== 4/6 payload disk"
lab/make_payload.sh "$out/payload.img" "$root/build/openssl35/b" > /dev/null
echo "== 5/6 two QEMU boots (stock and upgraded), this takes several minutes"
python3 lab/run_qemu.py "$out/payload.img" stock_all.sh "$out/stock.log" "$stock/output/ifs.bin" "$stock/output/disk-qemu.vmdk" > "$out/stock.status" 2>&1 &
stock_pid=$!
python3 lab/run_qemu.py "$out/payload.img" after_all.sh "$out/after.log" "$root/build/after/qnximg/output/ifs.bin" "$root/build/after/qnximg/output/disk-qemu" > "$out/after.status" 2>&1 &
after_pid=$!
wait $stock_pid $after_pid || { cat "$out/stock.status" "$out/after.status"; echo "a QEMU run did not finish" >&2; exit 1; }
fi
python3 lab/split_captures.py "$out/stock.log" "$out/stock-cap" > /dev/null
python3 lab/split_captures.py "$out/after.log" "$out/after-cap" > /dev/null
# pick each capture by the heading printed before it, not by its position
pick() { local n; n=$(grep -F "$2" "$out/$1-cap-labels.txt" | head -1 | cut -f1); [ -n "$n" ] || { echo "no capture '$2' in $1 log" >&2; exit 1; }; echo "$out/$1-cap-$n.txt"; }
cap_before=$(pick stock "probe 1: image library in use")
cap_override=$(pick stock "probe 2: both servers running")
cap_after=$(pick after "probe 2: both servers running")

echo "== 6/6 scans"
tool=bin/qnx-cbom
if [ "${EVIDENCE:-0}" = 1 ]; then date_arg=${DEMO_DATE:-2026-11-23}; else date_arg=${DEMO_DATE:-$(date -u +%F)}; fi
after=$root/build/after/qnximg
$tool scan --ifs "$stock/output/ifs.bin" --build-dir "$stock/output/build" --date "$date_arg" --name stock-image \
    --runtime "$cap_before" --json "$out/before.json" --cbom "$out/before.cdx.json" --html "$out/before.html" --text "$out/before.txt" || [ $? = 1 ]
$tool scan --ifs "$stock/output/ifs.bin" --build-dir "$stock/output/build" --date "$date_arg" --name stock-image-with-override \
    --runtime "$cap_override" --json "$out/override.json" --html "$out/override.html" --text "$out/override.txt" || [ $? = 1 ]
$tool scan --ifs "$after/output/ifs.bin" --build-dir "$after/output/build" --date "$date_arg" --name upgraded-image \
    --runtime "$cap_after" --json "$out/after.json" --cbom "$out/after.cdx.json" --html "$out/after.html" --text "$out/after.txt" && after_rc=0 || after_rc=$?
[ "$after_rc" -le 1 ] || { echo "scan of the upgraded image failed (exit $after_rc)" >&2; exit 1; }
$tool diff "$out/before.json" "$out/after.json" --html "$out/diff.html" --text "$out/diff.txt" || [ $? = 1 ]
for f in before override after diff; do echo "---- $f"; cat "$out/$f.txt"; done
echo "exit code of the scan of the upgraded image: $after_rc" | tee "$out/after-exit.txt"

if [ "${EVIDENCE:-0}" = 1 ]; then
    for f in before override after; do cp "$out/$f.json" "$out/$f.txt" "$out/$f.html" evidence/; done
    cp "$out/before.cdx.json" "$out/after.cdx.json" "$out/diff.txt" "$out/diff.html" "$out/after-exit.txt" evidence/
    cp "$out/stock.log" evidence/lab-stock-console.txt; cp "$out/after.log" evidence/lab-upgraded-console.txt
    cp "$cap_before" evidence/probe-stock.txt; cp "$cap_override" evidence/probe-stock-override.txt; cp "$cap_after" evidence/probe-upgraded.txt
fi
