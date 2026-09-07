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
    Severity.HIGH: "\033[91m",  # red
    Severity.MEDIUM: "\033[93m",  # yellow
    Severity.LOW: "\033[94m",  # blue
    Severity.INFO: "\033[90m",  # grey
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
    if result.suppressed:
        summary += f"  (suppressed: {result.suppressed})"
    lines.append(summary)
    owasp = "  ".join(f"{k}: {v}" for k, v in result.count_by_owasp().items())
    lines.append(f"OWASP LLM Top 10: {owasp}")
    lines.append("")

    # Worst first.
    for finding in sorted(result.findings, key=lambda f: f.severity, reverse=True):
        sev = finding.severity
        tag = c(f"[{sev.label().upper()}]", _COLORS[sev])
        lines.append(f"{tag} {finding.title}  ({finding.rule_id})")
        lines.append(f"   {finding.file_path}:{finding.line}")
        if finding.snippet:
            lines.append(f"   > {finding.snippet}")
        lines.append(f"   why: {finding.explanation}")
        lines.append(f"   fix: {finding.remediation}")
        refs = " / ".join(x for x in (finding.cwe, finding.owasp) if x)
        if refs:
            lines.append(f"   ref: {refs}")
        lines.append("")

    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


# ---- SARIF 2.1.0 ----
# GitHub code scanning, VS Code SARIF viewer, and most SAST aggregators read
# this. One run, one tool, one rule entry per distinct rule id.

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {  # GitHub's "security-severity" property, 0-10 scale
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(result: ScanResult, version: str = "0.2.0") -> str:
    from .findings import OWASP_LLM_TOP10

    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        if f.rule_id not in rules:
            tags = ["security"]
            if f.cwe:
                tags.append(f"external/cwe/{f.cwe.lower()}")
            if f.owasp:
                tags.append(f"external/owasp-llm/{f.owasp.lower()}")
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.explanation},
                "help": {
                    "text": f.remediation,
                    "markdown": (
                        f"**Fix:** {f.remediation}\n\n"
                        f"**OWASP LLM Top 10:** {f.owasp} "
                        f"{OWASP_LLM_TOP10.get(f.owasp or '', '')}\n\n"
                        f"**CWE:** {f.cwe or 'n/a'}"
                    ),
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "tags": tags,
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "category": f.category,
                },
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": max(f.line, 1), "snippet": {"text": f.snippet}},
                        }
                    }
                ],
                "partialFingerprints": {
                    "canary/v1": f"{f.rule_id}:{f.file_path}:{f.snippet}",
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "canary",
                        "version": version,
                        "informationUri": "https://github.com/jcedrik/canary",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "files_scanned": result.files_scanned,
                    "suppressed": result.suppressed,
                    "counts_by_owasp": result.count_by_owasp(),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)
