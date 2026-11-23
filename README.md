# qnx-cbom

A crypto bill of materials (CBOM) and readiness checker for QNX 8.0 images and live targets.

It answers, with one command: which programs use crypto, which libcrypto version each one really loads, which keys, certificates, qcrypto and SSH settings exist, and whether any of it is out of upstream support or quantum-vulnerable, with a fix text for every finding. The exit code is 0 only when there is no UNSAFE finding, so it works in CI.

Category: Developer Tooling & Host Tools. Licence: MIT.

## What is in the repository

| path | what it is |
|---|---|
| `src/qnxcbom/` | host scanner, rules, CycloneDX 1.6 / HTML / text outputs, diff (Python 3.12, standard library only) |
| `probe/` | the probe: a C program built with `qcc` that runs on the QNX target (x86_64 and aarch64le). It reads the memory map of every process through `/proc/<pid>/as` and `devctl` (`DCMD_PROC_MAPINFO`, `DCMD_PROC_MAPDEBUG`, the calls `pidin` uses) and reports the crypto libraries each process has really mapped. `-s` serves the same JSON as a QNX resource manager at `/dev/cbom`. |
| `lab/`, `demo/` | scripts that boot throwaway QEMU copies of a QNX image and regenerate the before/after demo |
| `tests/` | unit tests, browser test of the report, attack script, ELF cross-check |
| `evidence/` | raw output of every run the claims below rest on |

## Requirements

- QNX Software Development Platform 8.0.6 (non-commercial licence), environment loaded with `source qnxsdp-env.sh`. Used: `qcc`, `dumpifs`, `mkifs`, `mkqnx6fsimg`, `diskimage`.
- Target for the probe and the demo: QEMU x86_64 (QEMU 8.2.2) running a QNX 8.0 image made with `mkqnximage`. The aarch64le probe is compiled but not run (no aarch64 QEMU here).
- Toolchain: `qcc -Vgcc_ntox86_64` and `qcc -Vgcc_ntoaarch64le`.
- Host: Linux (built and tested on Ubuntu 24.04 under WSL2), Python 3.12.
- Only for the demo: `curl`, `perl`, `make`, `qemu-system-x86_64`.
- Only for the tests: `openssl` and `ssh-keygen` on the host, `python3-jsonschema`, Node.js 18 with Playwright 1.49.1 (`cd tests/ui && npm install && npx playwright install chromium`).

## Build

```
source ~/qnx800/qnxsdp-env.sh
make -C probe              # build/x86_64/cbom_probe and build/aarch64le/cbom_probe
```
Flags: `-O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`. Build log: `evidence/probe-build.txt`.
The scanner needs no build: `bin/qnx-cbom` runs from the checkout (`python3 -m qnxcbom` with `PYTHONPATH=src` does the same).

## Use

### Scan an image
```
bin/qnx-cbom scan --ifs ~/qnximg/output/ifs.bin --build-dir ~/qnximg/output/build \
    --json scan.json --cbom scan.cdx.json --html report.html --text -
```
Inputs: the boot image (`--ifs`, or an already extracted folder with `--ifs-dir`) and the mkqnximage build lists `system.build` and `data.build` in `--build-dir`. The system and data partitions are qnx6 file systems that this tool does not read from the disk image; their content is taken from the build lists and the SDK files they name. Sources are only opened inside the project folder and the SDK folders (`$QNX_TARGET`, `--sdk-root`).

Real output for the stock image (`evidence/scan-before-run.txt`):
```
$ bin/qnx-cbom scan --ifs ~/qnximg/output/ifs.bin --build-dir ~/qnximg/output/build --date 2026-11-23 --json scan-before.json --cbom scan-before.cdx.json --html scan-before.html --text -
qnx-cbom 0.1.0  image qnximg (x86_64)  scan date 2026-11-23
verdict: UNSAFE   UNSAFE 2  WARN 4  OK 1
files 217, ELF 168, crypto-linked ELF 19 (15 programs)
not analysed: skipped_outside_roots 2
UNSAFE QCB-001 /proc/boot/libcrypto.so.3 - OpenSSL library is past upstream end of life
UNSAFE QCB-002 /system/bin/sshd - sshd does not allow post-quantum key exchange
WARN   QCB-004 /data/var/ssh/ssh_host_ed25519_key - Key or certificate uses a quantum-vulnerable algorithm
WARN   QCB-004 /data/var/ssh/ssh_host_rsa_key - Key or certificate uses a quantum-vulnerable algorithm
WARN   QCB-004 /proc/boot/qtd_public_key.pem - Key or certificate uses a quantum-vulnerable algorithm
WARN   QCB-005 /proc/boot/qcrypto.conf - qcrypto sends all algorithms to a plug-in without post-quantum algorithms
exit code: 1
```
Exit codes: `0` no UNSAFE finding, `1` at least one UNSAFE finding, `2` bad input (one line `qnx-cbom: error: ...`, never a traceback).

Outputs: `--json` scan file, `--cbom` CycloneDX 1.6 (checked against the official 1.6 JSON schema, `evidence/cbom-validation.txt`), `--html` a single self-contained report (no external files, works offline), `--text` short summary. `--date YYYY-MM-DD` fixes the date used for end-of-life checks.

### Add what really runs: the probe
Run `cbom_probe` on the target (copy it there, or put it in the image). It prints a JSON report between `CBOM-BEGIN` and `CBOM-END` lines. Save the console output to a file and pass it to the scan:
```
bin/qnx-cbom scan ... --runtime probe-output.txt --html report.html
```
`cbom_probe -p PID` looks at one process, `-o FILE` writes plain JSON, `-s` serves `/dev/cbom` (root-readable) for as long as it runs. Real run on QNX 8.0 under QEMU: `evidence/lab-stock-console.txt`, one capture: `evidence/probe-stock-override.txt`.

### Compare two scans
```
bin/qnx-cbom diff before.json after.json --html diff.html
```
Real output for the stock image against the upgraded lab image (`evidence/diff.txt`):
```
verdict: UNSAFE -> WARN
new 1, gone 0, changed 3, library versions changed 1
NEW      OK     QCB-007 /data/lab/o35/libcrypto.so.3
CHANGED  QCB-001 /proc/boot/libcrypto.so.3: UNSAFE -> OK
CHANGED  QCB-002 /system/bin/sshd: UNSAFE -> OK
CHANGED  QCB-007 /proc/boot/libcrypto.so.3: UNSAFE -> OK
LIBRARY  /proc/boot/libcrypto.so.3: 3.0.22 -> 3.5.9
result: no new problems
```
Exit code 1 means the second scan has a new problem or a worse severity.

## Findings (rules)

| id | what | UNSAFE / WARN when |
|---|---|---|
| QCB-001 | OpenSSL library in the image | its series is past upstream end of life (3.0: 2026-09-07) |
| QCB-002 | sshd key exchange | the sshd binary has `mlkem768x25519-sha256` but `sshd_config` does not allow it |
| QCB-003 | ssh client key exchange | same for `ssh` (WARN) |
| QCB-004 | keys and certificates | RSA, ECDSA, Ed25519, Ed448 (WARN); ML-DSA and SLH-DSA are OK |
| QCB-005 | qcrypto | all algorithms go to a plug-in without ML-KEM/ML-DSA names (WARN) |
| QCB-006 | runtime | a process maps a libcrypto/libssl whose version differs from the image file (WARN) |
| QCB-007 | runtime | a process maps an OpenSSL series past end of life |
| QCB-008 | scan | a file that decides a verdict (libcrypto, libssl, qcrypto, sshd, ssh) could not be analysed |

Each finding carries its evidence, a fix text, the source URL and the date the source was read, and a list of what could not be verified (for example whether QNX supplies fixes for OpenSSL 3.0 after its upstream end of life). The rules and the OpenSSL date table are data in `src/qnxcbom/rules.json`.

## The before/after demo

`demo/run-demo.sh` regenerates it (it includes two QEMU boots):
1. builds the probe, and OpenSSL 3.5.9 for QNX with `qcc` (`demo/build_openssl.sh`, own Configure target in `demo/qnx-generic64.conf`);
2. builds an upgraded lab image from a copy of the stock project (`demo/build_after.sh`): `libcrypto.so.3` and `libssl.so.3` replaced by the 3.5.9 files, and `KexAlgorithms mlkem768x25519-sha256,...` in `sshd_config`;
3. boots the stock image and the upgraded image in throwaway QEMU copies (`-snapshot`, no network), runs the probe and an SSH login on loopback;
4. scans both images with the probe output merged, and diffs the scans.

What the run showed (`evidence/`):
- stock image: verdict UNSAFE (`before.txt`); the image's `sshd` faults ("Memory fault") even for `sshd -t`; the same command succeeds when the OpenSSL 3.5.9 library is put first in `LD_LIBRARY_PATH` (`lab-stock-console.txt`);
- upgraded image: verdict WARN, exit code 0 (`after.txt`, `after-exit.txt`); `sshd` starts, and an SSH login on loopback negotiated `kex: algorithm: mlkem768x25519-sha256` (`lab-upgraded-console.txt`);
- a process started with `LD_LIBRARY_PATH` pointing at OpenSSL 3.5.9 on the stock image is reported by the probe with the 3.5.9 library while the image file is 3.0.22 (finding QCB-006, `override.txt`).

## Limits, stated plainly

- The upgraded image is a **lab build on QEMU**, not a shipped fix. QNX's own OpenSSL 3.5 port is the upgrade path to use: github.com/qnx-ports/openssl (branches `qnx-openssl-3.5.4`, `qnx-openssl-3.6.0`; their existence was checked, `evidence/P1-source-checks.txt`; their content was not built or tested here). In the upgraded image `/system/bin/openssl` is still the 3.0.22 program running on the 3.5.9 library; its banner shows both.
- The cause of the `sshd` fault was narrowed to "faults with the image's libcrypto 3.0.22" (see above); the faulting function was not identified.
- The partitions are not read from the disk image (no qnx6 reader on the host). A file that the build lists name but that cannot be read is reported, never silently skipped.
- End-of-life dates were read from the OpenSSL policy page (live copy and an earlier copy of the same page); the date for series 1.0 and 1.1 was not read.
- qcrypto: SDP 8.0.6 has no key-encapsulation type (reading of the SDK headers, `evidence/T2-qcrypto-plugin.txt`), so QCB-005 has no in-place fix.
- The aarch64le probe compiles; it has not been run.
- The resource manager is a read-only file at `/dev/cbom`; it was run on the QEMU target (`evidence/lab-stock-console.txt`).

## Tests

```
make fetch-schema   # once: official CycloneDX schema files into build/schema
make check          # unit tests + browser test of the report
python3 tests/security_attacks.py evidence/security-test-log.txt
```
Logs: `evidence/unit-test-log.txt`, `evidence/ui-test-log.txt`, `evidence/security-test-log.txt`, `evidence/readelf-crosscheck.txt` (own ELF reader against the SDK `readelf` on all 168 ELF files of the image: identical).

## QNX connection (files to look at)

- `probe/cbom_probe.c`, `probe/cbom_resmgr.h`: QNX procfs `devctl` calls and a resource manager (`resmgr_attach`, `iofunc`).
- `lab/`, `demo/`: QNX image tools (`mkifs`, `mkqnx6fsimg`, `diskimage`, `dumpifs`) and QEMU boots of QNX 8.0.
- `src/qnxcbom/buildlist.py`, `image.py`: mkqnximage build lists and boot image (`dumpifs -x`) parsing.
- `evidence/lab-stock-console.txt`, `evidence/lab-upgraded-console.txt`: the QNX 8.0 console output.
