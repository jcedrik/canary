"""Command-line entry point.

Usage:
    canary <path> [--format text|json|sarif] [--output FILE]
                  [--fail-on SEVERITY] [--min SEVERITY] [--baseline FILE]

Exit codes (so it slots into CI):
    0  no findings at or above --fail-on
    1  findings at or above --fail-on were present
    2  usage / runtime error
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .findings import Severity
from .report import render_json, render_sarif, render_terminal
from .scanner import Scanner

_SEVERITY_CHOICES = [s.name.lower() for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="canary",
        description="Static security scanner for LLM / AI-agent applications.",
    )
    p.add_argument("path", help="File or directory to scan.")
    p.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text). sarif = SARIF 2.1.0 for GitHub code scanning.",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write the report to this file instead of stdout.",
    )
    p.add_argument(
        "--baseline",
        default=None,
        help="Path to a previous JSON report. Findings already in it are "
        "treated as accepted and not reported (or counted for --fail-on).",
    )
    p.add_argument(
        "--include-tests",
        action="store_true",
        help="Also scan test directories and test files (skipped by default).",
    )
    p.add_argument("--version", action="version", version=f"canary {__version__}")
    p.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default="high",
        help="Exit non-zero if any finding is at or above this severity "
        "(default: high). Use for CI gating.",
    )
    p.add_argument(
        "--min",
        choices=_SEVERITY_CHOICES,
        default="info",
        help="Only report findings at or above this severity (default: info).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.exists(args.path):
        print(f"canary: path not found: {args.path}", file=sys.stderr)
        return 2

    min_sev = Severity.from_name(args.min)
    fail_sev = Severity.from_name(args.fail_on)

    result = Scanner(baseline=args.baseline, include_tests=args.include_tests).scan_path(args.path)
    # Apply the --min filter.
    result.findings = [f for f in result.findings if f.severity >= min_sev]

    if args.format == "json":
        out = render_json(result)
    elif args.format == "sarif":
        out = render_sarif(result, version=__version__)
    else:
        out = render_terminal(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        if args.format == "text":
            print(f"canary: report written to {args.output}", file=sys.stderr)
    else:
        print(out)

    worst = result.worst_severity()
    if worst is not None and worst >= fail_sev:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
