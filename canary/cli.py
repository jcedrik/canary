"""Command-line entry point.

Usage:
    canary <path> [--format text|json] [--fail-on SEVERITY] [--min SEVERITY]

Exit codes (so it slots into CI):
    0  no findings at or above --fail-on
    1  findings at or above --fail-on were present
    2  usage / runtime error
"""

from __future__ import annotations

import argparse
import os
import sys

from .findings import Severity
from .report import render_json, render_terminal
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
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
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

    result = Scanner().scan_path(args.path)
    # Apply the --min filter.
    result.findings = [f for f in result.findings if f.severity >= min_sev]

    if args.format == "json":
        print(render_json(result))
    else:
        print(render_terminal(result))

    worst = result.worst_severity()
    if worst is not None and worst >= fail_sev:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
