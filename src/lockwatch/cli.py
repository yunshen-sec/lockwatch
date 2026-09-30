"""Command line interface for lockwatch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .models import ScanResult, Severity
from .osv import OsvCache, scan_packages
from .output import filter_findings, render_json, render_sarif, render_text
from .parsers import ParseError, parse_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lockwatch", description="Audit dependency lockfiles without executing project code")
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="scan dependency files")
    scan.add_argument("paths", nargs="*", type=Path, help="package-lock.json, requirements.txt, or poetry.lock")
    scan.add_argument("--package-lock", dest="package_locks", action="append", type=Path, default=[])
    scan.add_argument("--requirements", dest="requirements", action="append", type=Path, default=[])
    scan.add_argument("--poetry-lock", dest="poetry_locks", action="append", type=Path, default=[])
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--pretty", action="store_true", help="indent JSON output")
    scan.add_argument("--severity-threshold", default="unknown", help="only output findings at or above this level")
    scan.add_argument("--fail-on", help="exit 1 when a finding reaches this level")
    scan.add_argument("--osv", action="store_true", help="query OSV.dev (network access is opt-in)")
    scan.add_argument("--offline", action="store_true", help="do not query OSV.dev (default)")
    scan.add_argument("--timeout", type=float, default=5.0, help="OSV request timeout in seconds")
    scan.add_argument("--cache", type=Path, help="JSON cache file for OSV responses")
    scan.add_argument("--cache-max-age", type=float, default=86400.0, help="maximum cache age in seconds")
    scan.add_argument("--osv-endpoint", default=None, help=argparse.SUPPRESS)
    scan.add_argument("-o", "--output", type=Path, help="write report to this file")
    return parser


def _paths_from_args(args: argparse.Namespace) -> List[Path]:
    paths = list(args.paths) + list(args.package_locks) + list(args.requirements) + list(args.poetry_locks)
    if paths:
        return paths
    discovered = [Path(name) for name in ("package-lock.json", "requirements.txt", "poetry.lock") if Path(name).is_file()]
    if not discovered:
        raise ParseError("no dependency files supplied; pass paths or use --package-lock/--requirements/--poetry-lock")
    return discovered


def run_scan(args: argparse.Namespace) -> int:
    try:
        threshold = Severity.parse(args.severity_threshold)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else None
        if args.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        packages = parse_files(_paths_from_args(args))
    except (ParseError, ValueError) as exc:
        print("lockwatch: error: %s" % exc, file=sys.stderr)
        return 2
    findings = []
    errors: List[str] = []
    if args.osv and not args.offline:
        cache = OsvCache(args.cache, args.cache_max_age) if args.cache else None
        findings, errors = scan_packages(packages, timeout=args.timeout, cache=cache, endpoint=args.osv_endpoint or "https://api.osv.dev/v1/query")
    result = ScanResult(packages=packages, findings=filter_findings(findings, threshold), errors=errors, metadata={"severity_threshold": threshold.name.lower(), "osv_queried": bool(args.osv and not args.offline)})
    if args.format == "json":
        rendered = render_json(result, pretty=args.pretty)
    elif args.format == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_text(result)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    if fail_on is not None and any(item.severity >= fail_on for item in findings):
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = list(argv) if argv is not None else sys.argv[1:]
    # ``lockwatch requirements.txt`` is a convenient shorthand for scan.
    if arguments and arguments[0] not in {"scan", "-h", "--help"}:
        arguments.insert(0, "scan")
    args = parser.parse_args(arguments)
    if args.command != "scan":
        parser.print_help()
        return 2
    return run_scan(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
