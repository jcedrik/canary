"""Guardrails and PII-logging detectors.

Two checks that map directly to the kind of work hardening an LLM feature
requires:

* MissingGuardrailDetector: flags an LLM call whose output is returned to a
  user / written out with no moderation, schema validation, or filtering in
  between. This is heuristic by nature, so severity is MEDIUM.

* PiiLoggingDetector: flags logging calls whose arguments look like they
  carry personal data or raw model input/output. Logging raw user content is
  a common privacy slip (and a Law 25 / GDPR problem).
"""

from __future__ import annotations

import re
from typing import Iterable

from ..findings import Finding, Severity
from .base import Detector, register

# Common ways people call an LLM across SDKs. Anchored to method calls that
# actually invoke a model, not just any reference to the SDK module.
_LLM_CALL = re.compile(
    r"(chat\.completions\.create|messages\.create|generate_content|"
    r"\.invoke\(|\.predict\(|completions\.create|"
    r"(openai|anthropic|genai|client)\.[A-Za-z_]+\([^)]*model)",
    re.IGNORECASE,
)

# Signs that some safety step exists nearby.
_GUARDRAIL_HINT = re.compile(
    r"(moderat|validate|sanitize|guardrail|schema|pydantic|filter|"
    r"allowlist|denylist|refuse|safety)",
    re.IGNORECASE,
)

_LOG_CALL = re.compile(
    r"(logger?\.(info|debug|warning|error)|console\.(log|info|debug)|print)\s*\(",
    re.IGNORECASE,
)

_PII_ARG = re.compile(
    r"(email|phone|ssn|sin|address|password|user_?input|prompt|response|"
    r"message|content|api_?key|token)",
    re.IGNORECASE,
)


@register
class MissingGuardrailDetector(Detector):
    name = "missing-guardrails"
    category = "Missing Output Guardrails"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if not _LLM_CALL.search(line):
                continue
            # Look in a small window around the call for any safety step.
            window = "\n".join(lines[max(0, i - 4): i + 6])
            if _GUARDRAIL_HINT.search(window):
                continue  # something is in place, skip
            yield Finding(
                rule_id="CANARY-GR-001",
                title="LLM call with no visible output guardrail",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line=i + 1,
                snippet=line.strip(),
                explanation=(
                    "A model is invoked but there is no nearby moderation, "
                    "schema validation, or output filtering. Raw model output "
                    "can contain injected instructions, unsafe content, or "
                    "malformed data that downstream code trusts."
                ),
                remediation=(
                    "Validate the model's output before using it: enforce a "
                    "schema (e.g. Pydantic), run a moderation/safety check, and "
                    "constrain it to an allowlist of expected actions."
                ),
                category=self.category,
                cwe="CWE-20",
            )


@register
class PiiLoggingDetector(Detector):
    name = "pii-logging"
    category = "PII / Sensitive Data Logging"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        for i, line in enumerate(content.splitlines(), start=1):
            if not _LOG_CALL.search(line):
                continue
            if not _PII_ARG.search(line):
                continue
            yield Finding(
                rule_id="CANARY-PII-001",
                title="Possible sensitive data written to logs",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line=i,
                snippet=line.strip(),
                explanation=(
                    "A logging statement references what looks like personal "
                    "data or raw model input/output. Logs are often shipped to "
                    "third parties and retained long-term, so this can leak "
                    "PII and violate Law 25 / GDPR."
                ),
                remediation=(
                    "Redact or hash sensitive fields before logging. Log "
                    "identifiers and metadata, never raw user content, "
                    "credentials, or full prompts/responses."
                ),
                category=self.category,
                cwe="CWE-532",
            )
