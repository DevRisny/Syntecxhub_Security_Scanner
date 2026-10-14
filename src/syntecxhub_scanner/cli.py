"""Command-line entry point: `secscan <url> [options]`."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from . import report
from .permission import PermissionDenied
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Passive web security scanner: checks responses for missing headers, "
        "insecure cookies, information disclosure and weak TLS. Sends no attack payloads.",
    )
    parser.add_argument("target", help="URL to scan, e.g. http://localhost:8080")
    parser.add_argument("--max-pages", type=int, default=25, help="crawl limit (default 25)")
    parser.add_argument("--workers", type=int, default=4, help="concurrent requests (default 4)")
    parser.add_argument("--rate", type=float, default=5.0, help="max requests/second (default 5)")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds")
    parser.add_argument("--ignore-robots", action="store_true", help="do not honor robots.txt")
    parser.add_argument("--allow-public", action="store_true", help="allow scanning a non-local host")
    parser.add_argument("-y", "--yes", action="store_true", help="skip the interactive confirmation")
    parser.add_argument("--no-tls-check", action="store_true", help="skip the certificate/TLS check")
    parser.add_argument("--json", metavar="FILE", help="write a JSON report")
    parser.add_argument("--csv", metavar="FILE", help="write a CSV report")
    parser.add_argument("--html", metavar="FILE", help="write an HTML report")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        result = scan(
            args.target,
            max_pages=args.max_pages,
            max_workers=args.workers,
            requests_per_second=args.rate,
            timeout=args.timeout,
            respect_robots=not args.ignore_robots,
            allow_public=args.allow_public,
            assume_yes=args.yes,
            check_tls_cert=not args.no_tls_check,
        )
    except PermissionDenied as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return 130

    report.print_summary(result)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(report.to_json(result))
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as fh:
            fh.write(report.to_csv(result))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(result))

    highest = max((f.severity for f in result.findings), default=None)
    return 1 if highest is not None and highest >= 3 else 0  # non-zero exit on HIGH/CRITICAL


if __name__ == "__main__":
    raise SystemExit(main())
