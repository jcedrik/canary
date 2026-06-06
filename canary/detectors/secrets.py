"""Hardcoded secrets detector.

Catches API keys and credentials committed into source. We focus on the
providers an LLM app actually uses (OpenAI, Anthropic, Google, AWS) plus a
generic high-entropy assignment fallback. Each pattern is anchored to a
recognizable prefix to keep false positives low.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..findings import Finding, Severity
from .base import Detector, register

# (rule_id, label, compiled pattern, severity)
_SECRET_PATTERNS = [
    (
        "CANARY-SEC-001",
        "OpenAI API key",
        re.compile(r"sk-(?!ant-)(proj-)?[A-Za-z0-9_\-]{20,}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-002",
        "Anthropic API key",
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-003",
        "Google / GCP API key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-004",
        "AWS access key id",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-005",
        "Generic bearer/secret assignment",
        re.compile(
            r"(api_?key|secret|token|password)\s*[:=]\s*"
            r"['\"][A-Za-z0-9_\-]{16,}['\"]",
            re.IGNORECASE,
        ),
        Severity.HIGH,
    ),
]

# Lines that are obviously placeholders, not real leaks.
_PLACEHOLDER = re.compile(
    r"(your[_\-]?(api[_\-]?)?key|xxx+|<.*>|example|placeholder|"
    r"changeme|here|dummy|fake|test[_\-]?key|\.\.\.)",
    re.IGNORECASE,
)


@register
class SecretsDetector(Detector):
    name = "secrets"
    category = "Exposed Secrets"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        for i, line in enumerate(content.splitlines(), start=1):
            if _PLACEHOLDER.search(line):
                continue  # skip obvious dummy values
            for rule_id, label, pattern, severity in _SECRET_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                yield Finding(
                    rule_id=rule_id,
                    title=f"{label} hardcoded in source",
                    severity=severity,
                    file_path=file_path,
                    line=i,
                    snippet=self._redact(line.strip(), m.group(0)),
                    explanation=(
                        "A credential appears to be committed directly in the "
                        "code. Anyone with repo access (or a leaked clone) can "
                        "use it, and it stays in git history even after removal."
                    ),
                    remediation=(
                        "Move the secret to an environment variable or a secret "
                        "manager, rotate the exposed key immediately, and purge "
                        "it from git history (git filter-repo / BFG)."
                    ),
                    category=self.category,
                    cwe="CWE-798",
                )
                # One finding per line: the most specific provider pattern
                # wins, so we stop rather than also firing the generic rule.
                break

    @staticmethod
    def _redact(line: str, secret: str) -> str:
        """Never echo the full secret back in the report."""
        if len(secret) <= 8:
            masked = "*" * len(secret)
        else:
            masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        return line.replace(secret, masked)
