# Command line: scan an image, or compare two scans. Every failure ends as one
# plain line on standard error and exit code 2; no traceback reaches the user.
import argparse
import json
import os
import re
import sys
from datetime import date, datetime, timezone

from . import __version__, cbom, diff, image, report, rules, runtime, safepath, summary

ARCHES = ("x86_64", "aarch64le")


class UserError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UserError(message)


def _parser():
    parser = Parser(prog="qnx-cbom", description="Crypto bill of materials and readiness check for QNX 8.0 images.")
    parser.add_argument("--version", action="version", version="qnx-cbom " + __version__)
    sub = parser.add_subparsers(dest="command", parser_class=Parser)
    scan = sub.add_parser("scan", help="scan an image")
    where = scan.add_mutually_exclusive_group(required=True)
    where.add_argument("--ifs", metavar="FILE", help="boot image file (extracted with dumpifs -x)")
    where.add_argument("--ifs-dir", metavar="DIR", help="boot image already extracted with dumpifs -x")
    scan.add_argument("--build-dir", required=True, metavar="DIR", help="folder with system.build and data.build")
    scan.add_argument("--project-dir", metavar="DIR", help="mkqnximage project folder (default: two levels above --build-dir)")
    scan.add_argument("--sdk-root", action="append", default=[], metavar="DIR", help="extra folder for build-list sources")
    scan.add_argument("--arch", choices=ARCHES, default="x86_64")
    scan.add_argument("--runtime", metavar="FILE", help="probe output to merge")
    scan.add_argument("--name", help="label shown in reports")
    scan.add_argument("--date", metavar="YYYY-MM-DD", help="date used for end-of-life checks (default: today, UTC)")
    scan.add_argument("--json", metavar="FILE", help="write the scan file")
    scan.add_argument("--cbom", metavar="FILE", help="write CycloneDX 1.6 JSON")
    scan.add_argument("--html", metavar="FILE", help="write the HTML report")
    scan.add_argument("--text", metavar="FILE", help="write the text summary ('-' for standard output)")
    cmp_ = sub.add_parser("diff", help="compare two scan files")
    cmp_.add_argument("a", metavar="A.json")
    cmp_.add_argument("b", metavar="B.json")
    cmp_.add_argument("--html", metavar="FILE", help="write the HTML report")
    cmp_.add_argument("--text", metavar="FILE", help="write the text summary ('-' for standard output)")
    return parser


def _write(path, text):
    if path == "-":
        sys.stdout.write(text)
        return
    try:
        with open(path, "w", encoding="utf-8", errors="backslashreplace") as handle:
            handle.write(text)
    except OSError as err:
        raise UserError(f"cannot write {path}: {err.strerror}")


def _dir(path, what):
    if not os.path.isdir(path):
        raise UserError(f"{what} is not a folder: {path}")
    return path


def _roots(args):
    project = args.project_dir or os.path.join(args.build_dir, "..", "..")
    if len([p for p in os.path.realpath(project).split(os.sep) if p]) < 2:
        raise UserError("the default project folder is too high up; pass --project-dir")
    folders = [project] + args.sdk_root
    target = os.environ.get("QNX_TARGET")
    if not args.sdk_root and target:
        folders += [os.path.join(target, args.arch), target]
    roots = safepath.Roots(folders)
    if not roots.folders:
        raise UserError("none of the source folders exist")
    return roots


def _scan(args):
    if args.date is not None:
        try:
            if not re.fullmatch(r"\d{4}-\d\d-\d\d", args.date):
                raise ValueError
            today = date.fromisoformat(args.date)
        except ValueError:
            raise UserError("--date must look like 2026-11-23")
    else:
        today = datetime.now(timezone.utc).date()
    _dir(args.build_dir, "--build-dir")
    if args.ifs_dir:
        _dir(args.ifs_dir, "--ifs-dir")
    elif not os.path.isfile(args.ifs):
        raise UserError(f"--ifs is not a file: {args.ifs}")
    probe = runtime.load(args.runtime) if args.runtime else None
    roots = _roots(args)
    name = args.name or os.path.basename(os.path.realpath(args.project_dir or os.path.join(args.build_dir, "..", "..")))
    body = image.scan_with_temp(args.ifs, args.ifs_dir, args.build_dir, roots, name, args.arch)
    model = {"schema": "qnx-cbom-scan/1", "tool": {"name": "qnx-cbom", "version": __version__},
             "scan_date": today.isoformat(), **body, "runtime": None}
    if probe:
        runtime.merge(model, probe)
    rules.evaluate(model, today)
    if args.json:
        _write(args.json, json.dumps(model, indent=1, sort_keys=True) + "\n")
    if args.cbom:
        _write(args.cbom, json.dumps(cbom.build(model), indent=1) + "\n")
    if args.html:
        _write(args.html, report.scan_page(model))
    if args.text or not (args.json or args.cbom or args.html):
        _write(args.text or "-", summary.scan_text(model))
    return 1 if model["summary"]["unsafe"] else 0


def _diff(args):
    result = diff.compare(diff.load_scan(args.a), diff.load_scan(args.b))
    if args.html:
        _write(args.html, report.diff_page(result))
    if args.text or not args.html:
        _write(args.text or "-", summary.diff_text(result))
    return 1 if result["regressed"] else 0


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        if args.command is None:
            raise UserError("a command is needed: scan or diff (see --help)")
        return _scan(args) if args.command == "scan" else _diff(args)
    except UserError as err:
        message = str(err)
    except (image.ScanError, runtime.ProbeFileError, diff.ScanFileError) as err:
        message = str(err)
    except KeyboardInterrupt:
        message = "interrupted"
    except Exception as err:  # last resort so the user never sees a traceback
        if os.environ.get("QNXCBOM_DEBUG"):
            raise
        message = f"internal error ({type(err).__name__}); run again with QNXCBOM_DEBUG=1 for details"
    print("qnx-cbom: error: " + ascii(message)[1:-1], file=sys.stderr)
    return 2
