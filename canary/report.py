"""Output formatting: a readable terminal report and a JSON report.

The terminal reporter groups findings by severity (worst first) and uses
ANSI color only when stdout is a TTY, so piping to a file stays clean.
The JSON reporter is what you'd consume in CI.
"""

from __future__ import annotations

import json
import sys

from .findings import ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[95m",  # magenta
    Severity.HIGH: "\033[91m",      # red
    Severity.MEDIUM: "\033[93m",    # yellow
    Severity.LOW: "\033[94m",       # blue
    Severity.INFO: "\033[90m",      # grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color() -> bool:
    return sys.stdout.isatty()


def render_terminal(result: ScanResult) -> str:
    color = _use_color()
    lines: list[str] = []

    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    header = f"canary — scanned {result.files_scanned} file(s)"
    lines.append(c(header, _BOLD))

    if not result.findings:
        lines.append(c("No issues found.", _COLORS[Severity.LOW]))
        return "\n".join(lines)

    counts = result.count_by_severity()
    summary = "  ".join(f"{k}: {v}" for k, v in counts.items())
    lines.append(summary)
    lines.append("")

    # Worst first.
    for finding in sorted(
        result.findings, key=lambda f: f.severity, reverse=True
    ):
        sev = finding.severity
        tag = c(f"[{sev.label().upper()}]", _COLORS[sev])
        lines.append(f"{tag} {finding.title}  ({finding.rule_id})")
        lines.append(f"   {finding.file_path}:{finding.line}")
        if finding.snippet:
            lines.append(f"   > {finding.snippet}")
        lines.append(f"   why: {finding.explanation}")
        lines.append(f"   fix: {finding.remediation}")
        if finding.cwe:
            lines.append(f"   ref: {finding.cwe}")
        lines.append("")

    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
