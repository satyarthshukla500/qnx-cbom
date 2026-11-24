# qnx-cbom

**What it does.** It lists every cryptographic component of a QNX 8.0 image (the programs and libraries that use OpenSSL or qcrypto, the keys, certificates and SSH settings), asks the *running* system which of those libraries are really loaded, and tells you for each finding what is wrong and how to fix it. One command; the exit code makes it usable in CI.

## Claims and proof

Each row is one claim, the raw file that shows it, and the command that reproduces it. Commands marked (SDK) need QNX SDP 8.0.6 loaded and the stock `mkqnximage` project in `~/qnximg`; the others run with only Python 3.12.

| claim | evidence | reproduce |
|---|---|---|
| The stock image scans UNSAFE, exit code 1 (UNSAFE 2, WARN 4, OK 1) | `evidence/scan-before-run.txt` | `bin/qnx-cbom scan --ifs ~/qnximg/output/ifs.bin --build-dir ~/qnximg/output/build --date 2026-11-23 --text -; echo $?` (SDK) |
| The image has 168 ELF files, 19 of them crypto-linked (15 programs); the own ELF reader agrees with `readelf` on all 168 | `evidence/scan-before-run.txt`, `evidence/readelf-crosscheck.txt` | same scan as above; `tests/regression.sh /tmp/regression-logs` (SDK; step "readelf cross-check") |
| The probe ran on QNX 8.0 under QEMU and listed the crypto libraries mapped by running processes | `evidence/lab-stock-console.txt`, `evidence/probe-stock.txt` | `demo/run-demo.sh` (SDK, QEMU) |
| `/dev/cbom` serves the probe's JSON report as a file on the target (two reads, both complete JSON) | `evidence/lab-stock-console.txt` (section `ls -l /dev/cbom`) | `demo/run-demo.sh` (SDK, QEMU) |
| The lab image with OpenSSL 3.5.9 (my own build of the upstream release, no assembler code) scans WARN, exit code 0 (UNSAFE to WARN) | `evidence/after.txt`, `evidence/after-exit.txt` | `PYTHONPATH=src python3 -m qnxcbom diff evidence/before.json evidence/after.json` shows the flip (no SDK); the scan itself: `demo/run-demo.sh` |
| An SSH login on that image negotiated `mlkem768x25519-sha256`, on the default QEMU guest CPU (`-cpu max`, AVX2 present; this build has no assembler code) | `evidence/lab-upgraded-console.txt` (`debug1: kex: algorithm: mlkem768x25519-sha256`) | `demo/run-demo.sh` (SDK, QEMU) |
| The scanner reads the system and data partitions from the real qnx6 disk image (`--disk`). System: 225 files on disk, 225 named in the build list, 225 in both. Data: 26 on disk, 21 in the list, 21 in both, 5 only on disk (made when the image was run). Against a listing taken inside the running QNX 8.0 target, 249 of 251 files have the same size and checksum; the other 2 (`/data/var/dumper/sshd.core`, `/data/var/random/rnd-seed`) are rewritten at boot | `evidence/qnx6-image-check.txt`, `evidence/qnx6-live-listing.txt`, `evidence/scan-disk-run.txt` | `bin/qnx-cbom scan --ifs ~/qnximg/output/ifs.bin --build-dir ~/qnximg/output/build --disk ~/qnximg/output/disk-qemu --text -` (SDK); the comparison: `python3 -I lab/qnx6_check.py DISK BUILD_DIR LIVE_LOG` |
| The OpenSSL 3.5.4 port from `qnx-ports` (branch `qnx-openssl-3.5.4`, built with its own `make -C qnx/build`, not installed into the SDK) gives the same result on a lab image: UNSAFE to WARN, exit code 0, QCB-001, QCB-002 and QCB-007 become OK, library shown as 3.5.4. Its SONAME is `libcrypto.so.3.5`; for the lab the file was installed under the name `libcrypto.so.3`. The `mlkem768x25519-sha256` login worked only on a QEMU guest CPU without AVX2 (`CBOM_QEMU_CPU=max,-avx2`); on the default CPU `sshd` stops with "Memory fault" | `evidence/lab-qnxports-scan.txt`, `evidence/lab-qnxports-console-noavx2.txt`, `evidence/lab-qnxports-console-avx2.txt`, `evidence/lab-qnxports-build.txt` | `AFTER_DIR=after-qnxports CRYPTO_SRC=<port build>/libcrypto.so.3.5 SSL_SRC=none demo/build_after.sh`, then `CBOM_QEMU_CPU=max,-avx2 python3 lab/run_qemu.py PAYLOAD qnxports_all.sh LOG IFS DISK` (SDK, QEMU; not part of `demo/run-demo.sh`) |
| The demo reproduces the committed output | `evidence/final-regression.txt` (before, override, after and diff texts identical, 38 unit tests OK) | `demo/run-demo.sh`, then compare with `evidence/` |

## Known limits

- The qnx6 reader (`--disk`) was only tried on images made by `mkqnx6fsimg` / `mkqnximage` from SDP 8.0.6 (the stock image and small test images). It does not check the superblock checksums, does not use the second superblock, and ignores qnx6 features those tools do not produce (for example encrypted or snapshot volumes); an image it cannot follow makes that partition fall back to the build list, with a note in the report. The boot partition (type 0xb1, a copy of the boot image) is not scanned from the disk. Without `--disk` the partitions come from the build lists only.
- The aarch64le probe compiles but has not been run. A retry with `qemu-system-aarch64` installed failed at `mkqnximage --arch=aarch64le`: the SDK has no `startup-qemu-virt`, so no aarch64 image could be built.
- The upgraded image in the demo is a **lab build on QEMU** with my own OpenSSL 3.5.9, not a shipped fix. The QNX port (github.com/qnx-ports/openssl, branch `qnx-openssl-3.5.4`) was also built (`make -C qnx/build`, not installed into the SDK) and put into a lab image the same way (`evidence/lab-qnxports-*.txt`). Result: verdict UNSAFE to WARN, exit code 0, the same three findings change to OK, and OpenSSL 3.5.4 is shown as the library. The SSH login that negotiates `mlkem768x25519-sha256` worked only with a QEMU guest CPU without AVX2: with AVX2 (the default of `lab/run_qemu.py`) `sshd` stops with the same "Memory fault" as the stock image (see the `sshd` line below); this build is built with assembler code (`evidence/lab-qnxports-build.txt`). The port's libraries have the SONAME `libcrypto.so.3.5`, so `LD_LIBRARY_PATH` does not replace the image's `libcrypto.so.3` by itself; for the lab the file was installed under the name `libcrypto.so.3` and the port's `libssl` was left out. Not tested: the `qnx-openssl-3.6.0` branch, an aarch64 build, the port's own test suite. In the 3.5.9 lab image `/system/bin/openssl` is still the 3.0.22 program running on the 3.5.9 library; its banner shows both.
- No real-time or timing claim is made; nothing was measured.
- The stock `sshd` stops with "Memory fault" (exit 139) on `sshd -t` in QEMU (guest CPU `max`, no KVM). The core file shows a SIGSEGV in `sha512_block_data_order_avx2` (libcrypto 3.0.22), called from `sshkey_shield_private` in `sshd`, at the first byte after the 16384-byte buffer being hashed (`evidence/sshd-fault.txt`). With the guest CPU `max,-avx2` the same `sshd -t` with the same stock libcrypto exits 0. The qnx-ports 3.5.4 build stops the same way on the AVX2 guest CPU. This was not tried on real hardware or another QEMU version, and it is not claimed to be a fault of the library or of QNX: the cause (emulated CPU or code) is unverified. The 3.5.9 lab build has no assembler code, so it does not take that path.
- QNX did ship OpenSSL 3.0 after the upstream end-of-life date: the SDP 8.0.6 package in the SDK used here is OpenSSL 3.0.22 ("8.0 Build 12 - October 1, 2026", package metadata), newer than 3.0.15 and 3.0.20 ([8.0.4 security notes](https://www.qnx.com/developers/docs/relnotes8.0/com.qnx.doc.release_notes/topic/8.0.4_prod_release_notes/8.0.4_security.html), May 2026). The [SDP 8.0.6 release notes](https://www.qnx.com/developers/docs/relnotes8.0/com.qnx.doc.release_notes/topic/8.0.6_prod_release_notes/8.0.6_rn.html) (edition 12 Nov 2026) say QNX OS ships OpenSSL 3.5 as well as 3.0, with 3.0 the default; no 3.5 package is in this SDK. Still unverified: whether fixes after 2026-09-07 are backported, and any support commitment for 3.0 (the QNX Download Center needs a login and was not opened). The rules still decide on 3.0 by the upstream date and list this as unverified.
- End-of-life dates were read from the OpenSSL policy page (live copy and an earlier copy of the same page); the date for series 1.0 and 1.1 was not read.
- qcrypto: SDP 8.0.6 has no key-encapsulation type (reading of the SDK headers, `evidence/T2-qcrypto-plugin.txt`), so QCB-005 has no in-place fix.
- The resource manager is a read-only file at `/dev/cbom`; it was run on the QEMU target (`evidence/lab-stock-console.txt`).

**Why this is useful.** A QNX image is built once and then runs in the field for years, so what is inside it has to be known and checked: the OpenSSL 3.0 series left upstream support on 2026-09-07, OpenSSH 10 made a hybrid post-quantum key exchange its default, and RSA and elliptic-curve keys are the ones a quantum computer breaks. The stock QNX 8.0 image that this was tested on ships OpenSSL 3.0.22 and an `sshd_config` that allows only classical key exchange, although its `sshd` binary supports `mlkem768x25519-sha256`. A file-level scan cannot tell you whether a process really uses the library the image holds (a `LD_LIBRARY_PATH` setting can replace it), and an inventory that is wrong about that is worse than none.

**Who it is for.** Teams that build and ship QNX images for long-lived products (QNX is used in vehicles, medical devices, factory systems and robots) and have to answer customers or auditors about the cryptography inside them; and CI jobs that must stop a build when the image gets worse.

**What the probe does on a running system.** It is a separate small program that only reads: it opens `/proc/<pid>/as` read-only, asks for the memory map, and reads the library files it finds there. It changes no other process and needs no change to the kernel or to the programs it inspects. Its source is one C file (`probe/cbom_probe.c`) plus the optional resource manager header, so it can be reviewed in one sitting. No claim is made about its effect on timing; none was measured.

**Why it needs QNX knowledge.** It reads the QNX boot image and the `mkqnximage` build lists, and its probe runs on the target and uses QNX's own process interface (`/proc/<pid>/as` with `devctl`, the calls `pidin` uses) and a QNX resource manager.

Category: Developer Tooling & Host Tools. Licence: Apache License 2.0. Copyright 2026 Satyarth Shukla.

## Why this runs on QNX

- `/dev/cbom` is a QNX resource manager (`cbom_probe -s`, `probe/cbom_resmgr.h`). It uses `dispatch_create`, `resmgr_attach`, `iofunc_func_init`, `iofunc_attr_init` and a read handler (`iofunc_read_verify`, `dispatch_block`, `dispatch_handler`).
- It appears as a read-only file for root (`S_IFNAM | 0400`). A client just reads it: `cat /dev/cbom`. A read from offset 0 builds a fresh report of all processes; later reads continue in that report.
- The report itself comes from procfs: `/proc/<pid>/as` with `devctl` (`DCMD_PROC_INFO`, `DCMD_PROC_MAPINFO`, `DCMD_PROC_MAPDEBUG`), the same calls `pidin` uses.
- qcrypto: the scanner reads `qcrypto.conf` (plug-in and tags per line), counts `libqcrypto` as a crypto library, and raises QCB-005 when all algorithms go to a plug-in without post-quantum names.
- Image side: `dumpifs -x` unpacks the boot image, and the `mkqnximage` build lists (`system.build`, `data.build`, with their inline `sshd_config` and `qcrypto.conf` blocks) say what is in the partitions.

## Try it in one minute (no SDK needed)

The real results of the lab runs are in `evidence/`. With only Python 3.12:
```
PYTHONPATH=src python3 -m qnxcbom diff evidence/before.json evidence/after.json
```
Then open `evidence/before.html`, `evidence/after.html` and `evidence/diff.html` in a browser (they are single files, nothing is loaded from the network).

## How it works, in five steps

1. **Read the image.** The boot image is unpacked with `dumpifs -x`; the system and data partitions are read from the disk image with `--disk`, or else taken from the `mkqnximage` build lists (`system.build`, `data.build`) and the SDK files they name.
2. **Read every ELF file** with a small bounded reader: which libraries it needs, whether it is a program or a library.
3. **Read the crypto files:** the version banner inside `libcrypto`, key and certificate type and size (never the key material), `qcrypto.conf`, `sshd_config`, `ssh_config`.
4. **Ask the running system** (optional): the probe lists which crypto libraries each process has really mapped, and the scan compares them with the image files.
5. **Apply the rules** in `src/qnxcbom/rules.json` and write the outputs.

**Why not just check package versions?** The tested image has no package list; the OpenSSL version exists only inside the library file, and which library a program loads can differ from the file in the image (an `LD_LIBRARY_PATH` setting is enough). The probe measures that; a file or package check cannot.

**Terms.** *CBOM*: a bill of materials for cryptography (what algorithms, keys and libraries a system contains), here in the CycloneDX 1.6 format. *Post-quantum / ML-KEM*: key-agreement algorithms (NIST FIPS 203) meant to resist quantum computers; `mlkem768x25519-sha256` is the hybrid of ML-KEM-768 and X25519 that OpenSSH offers. *qcrypto*: QNX's own crypto API with plug-ins. *Resource manager*: a QNX server that appears as a file in the path space (here `/dev/cbom`). *IFS*: the boot image of a QNX system. *Probe*: the small program that runs on the target.

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
- Target for the probe and the demo: QEMU x86_64 (QEMU 8.2.2) running a QNX 8.0 image made with `mkqnximage`. The aarch64le probe is compiled but not run (see Known limits).
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
Inputs: the boot image (`--ifs`, or an already extracted folder with `--ifs-dir`) and the mkqnximage build lists `system.build` and `data.build` in `--build-dir`. The system and data partitions are qnx6 file systems. With `--disk FILE` (the `output/disk-qemu` image of `mkqnximage`) they are read from the real disk image by a read-only qnx6 reader written in Python (`src/qnxcbom/qnx6.py`, nothing is mounted); without it their content is taken from the build lists and the SDK files they name. If one partition cannot be read completely, the build list is used for that partition only and the report says so in its notes. On the stock image the disk read finds 315 files and 260 ELF files (the build lists name 217 and 168: the 91 `[type=hlink]` entries, which the list reader does not count as files, are separate names of one toybox program, 2 files whose list sources lie outside the allowed folders, and 5 files made while the image was run: `evidence/qnx6-image-check.txt`); the verdict and the 19 crypto-linked files are the same (`evidence/scan-disk-run.txt`). Sources are only opened inside the project folder and the SDK folders (`$QNX_TARGET`, `--sdk-root`).

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
The levels: **UNSAFE** means the item fails the stated baseline (an OpenSSL series that upstream still supports; hybrid post-quantum key exchange where the build has it); it is a finding to act on, not proof of an attack. **WARN** is weaker than ideal or cannot be confirmed. **OK** meets the baseline.

This first scan is static (image files only), so it has UNSAFE 2. With the probe's output merged in (`--runtime`, next section) the same image has UNSAFE 3, because the running `random` daemon is seen loading the end-of-life libcrypto (QCB-007); that run is `evidence/before.txt`.

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
new 0, gone 0, changed 3, library versions changed 1
CHANGED  QCB-001 /proc/boot/libcrypto.so.3: UNSAFE -> OK
CHANGED  QCB-002 /system/bin/sshd: UNSAFE -> OK
CHANGED  QCB-007 /proc/boot/libcrypto.so.3: UNSAFE -> OK
LIBRARY  /proc/boot/libcrypto.so.3: 3.0.22 -> 3.5.9
result: no new problems
```
Exit code 1 means the second scan has a new problem or a worse severity. A "NEW ... OK" line is a finding that is new but fine.

In CI:
```
bin/qnx-cbom scan --ifs ifs.bin --build-dir build --json new.json --runtime probe-output.txt   # exit 1 = UNSAFE found, 2 = bad input
bin/qnx-cbom diff baseline.json new.json                                                       # exit 1 = something got worse
```

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
- stock image: verdict UNSAFE (`before.txt`); the image's `sshd` faults ("Memory fault") even for `sshd -t`; the same command succeeds when the OpenSSL 3.5.9 library is put first in `LD_LIBRARY_PATH` (`lab-stock-console.txt`); on a guest CPU without AVX2 `sshd -t` also exits 0 with the stock library (`evidence/sshd-fault.txt`; see Known limits for what that does and does not show);
- upgraded image: verdict WARN, exit code 0 (`after.txt`, `after-exit.txt`); `sshd` starts, and an SSH login on loopback negotiated `kex: algorithm: mlkem768x25519-sha256` (`lab-upgraded-console.txt`);
- a process started with `LD_LIBRARY_PATH` pointing at OpenSSL 3.5.9 on the stock image is reported by the probe with the 3.5.9 library while the image file is 3.0.22 (finding QCB-006, `override.txt`).

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
