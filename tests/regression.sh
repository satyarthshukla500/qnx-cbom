#!/bin/bash
# Runs every check and writes the logs into the folder given as $1 (default: evidence/).
# Needs the QNX SDP environment, the stock mkqnximage project (~/qnximg), and the test tools from the README.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/evidence}
stock=${STOCK:-$HOME/qnximg}
cd "$root"
mkdir -p "$out" build/schema
fails=0
step() { echo "== $1"; }

step "schema files"
[ -f build/schema/bom-1.6.schema.json ] || make -s fetch-schema

step "unit tests"
( cd tests && PYTHONPATH=../src python3 -W ignore -m unittest -v test_parsers test_product test_qnx6 ) > "$out/unit-test-log.txt" 2>&1 || fails=$((fails+1))
sed -i -E 's/^(Ran [0-9]+ tests?) in [0-9.]+s$/\1/' "$out/unit-test-log.txt"  # no timings in the evidence
tail -3 "$out/unit-test-log.txt"

step "scan of the real image"
{
  echo '$ bin/qnx-cbom scan --ifs ~/qnximg/output/ifs.bin --build-dir ~/qnximg/output/build --date 2026-11-23 --json scan-before.json --cbom scan-before.cdx.json --html scan-before.html --text -'
  bin/qnx-cbom scan --ifs "$stock/output/ifs.bin" --build-dir "$stock/output/build" --date 2026-11-23 \
      --json "$out/scan-before.json" --cbom "$out/scan-before.cdx.json" --html "$out/scan-before.html" --text -
  echo "exit code: $?"
} > "$out/scan-before-run.txt" 2>&1
python3 tests/validate_cbom.py "$out/scan-before.cdx.json" 2>&1 | sed "s|$root/||" > "$out/cbom-validation.txt"; [ "${PIPESTATUS[0]}" = 0 ] || fails=$((fails+1))
cat "$out/cbom-validation.txt"
python3 - "$out/scan-before.json" <<'PY' || fails=$((fails+1))
import json, sys
c = json.load(open(sys.argv[1]))["image"]["counts"]
print("T3 comparison (168 ELF, 19 crypto-linked, 15 programs):", c["elf"], c["crypto_elf"], c["crypto_executables"])
sys.exit(0 if (c["elf"], c["crypto_elf"], c["crypto_executables"]) == (168, 19, 15) else 1)
PY

step "readelf cross-check"
tmp=$(mktemp -d)
( cd "$tmp" && dumpifs -x "$stock/output/ifs.bin" > /dev/null 2>&1 )
{ echo '$ python3 tests/readelf_crosscheck.py <extracted ifs> ~/qnximg/output/build'; python3 -I tests/readelf_crosscheck.py "$tmp" "$stock/output/build"; echo "exit=$?"; } > "$out/readelf-crosscheck.txt" 2>&1
grep -q "different: 0" "$out/readelf-crosscheck.txt" || fails=$((fails+1))
tail -2 "$out/readelf-crosscheck.txt"
rm -rf "$tmp"

step "report in the browser"
if [ -d tests/ui/node_modules ]; then
  UI_LOG="$out/ui-test-log.txt" UI_SHOTS="$root/build" node tests/ui/ui_test.js | tail -1 || fails=$((fails+1))
else echo "ui test skipped (Playwright not installed)"; fails=$((fails+1)); fi

step "attack list"
python3 tests/security_attacks.py "$out/security-test-log.txt" | tail -1
grep -q "GOT THROUGH" "$out/security-test-log.txt" && fails=$((fails+1))

echo "failed steps: $fails"
exit $fails
