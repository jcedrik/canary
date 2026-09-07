"""Hardcoded secrets detector.

Catches API keys and credentials committed into source. We focus on the
providers an LLM app actually uses (OpenAI, Anthropic, Google, AWS) plus a
generic high-entropy assignment fallback. Each pattern is anchored to a
recognizable prefix to keep false positives low.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..findings import Finding, Severity
from .base import Detector, register

# (rule_id, label, compiled pattern, severity)
_SECRET_PATTERNS = [
    (
        "CANARY-SEC-001",
        "OpenAI API key",
        re.compile(r"(?<![A-Za-z0-9_\-])sk-(?!ant-)(proj-)?[A-Za-z0-9_\-]{20,}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-002",
        "Anthropic API key",
        re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-003",
        "Google / GCP API key",
        re.compile(r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z_\-]{35}"),
        Severity.CRITICAL,
    ),
    (
        "CANARY-SEC-004",
        "AWS access key id",
        re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
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
    r"(your[_\-][a-z0-9_\-]*key|your[_\-]?(api[_\-]?)?key|xxx+|<.*>|example|placeholder|"
    r"changeme|here|dummy|fake|test[_\-]?key|\.\.\.|"
    r"gitleaks:allow|pragma:\s*allowlist\s*secret|noqa:\s*S105|"
    r"secret['\"]?\s*[:=]\s*['\"]?secret|"
    r"\$\{?[A-Z_]{4,}\}?)",  # shell/env interpolation like ${API_KEY}
    re.IGNORECASE,
)

# Keys that are public by design. A PostHog project token (phc_...) is a
# write-only analytics key meant to ship in client code; flagging it is noise.
_KNOWN_PUBLIC = re.compile(r"\bphc_[A-Za-z0-9]{30,}\b")

# A line this long is almost always data (base64 blobs, minified JS, cassette
# payloads), not a credential assignment.
_MAX_LINE = 400


@register
class SecretsDetector(Detector):
    name = "secrets"
    category = "Exposed Secrets"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        for i, line in enumerate(content.splitlines(), start=1):
            if len(line) > _MAX_LINE or _PLACEHOLDER.search(line) or _KNOWN_PUBLIC.search(line):
                continue  # skip data blobs and obvious dummy values
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
