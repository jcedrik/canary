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
from collections.abc import Iterable

from ..findings import Finding, Severity
from .base import Detector, register

# Common ways people call an LLM across SDKs. Anchored to method calls that
# actually invoke a model, not just any reference to the SDK module.
_LLM_CALL = re.compile(
    r"(chat\.completions\.create\(|messages\.create\(|responses\.create\(|"
    r"\.generate_content(_async|_stream)?\(|completions\.create\(|"
    r"(llm|model|chain|chat_model|agent)\.(invoke|ainvoke|predict|generate|run)\(|"
    r"\.converse\(|\.invoke_model\(|ChatCompletion\.create\()",
    re.IGNORECASE,
)

# Signs that some safety step exists nearby.
_GUARDRAIL_HINT = re.compile(
    r"(moderat|validate|sanitize|guardrail|schema|pydantic|filter|"
    r"allowlist|denylist|refuse|safety)",
    re.IGNORECASE,
)

_LOG_CALL = re.compile(
    r"\b(logger?\.(info|debug|warning|error)|logging\.(info|debug|warning|error)|"
    r"console\.(log|info|debug)|print)\s*\(",
    re.IGNORECASE,
)

# Strong PII / secret names only. The v0.1 list included "message",
# "content" and "response", which matched almost every log line in the
# benchmark. A log of `response.status` is not a leak; a log of `password`,
# `user_input` or `api_key` is.
_PII_ARG = re.compile(
    r"\b(email|e_mail|phone|ssn|sin\b|social_?security|date_?of_?birth|dob\b|"
    r"password|passwd|credit_?card|card_?number|iban|address|"
    r"user_?input|user_?message|user_?prompt|raw_?prompt|system_?prompt|"
    r"api_?key|secret|access_?token|refresh_?token|bearer|authorization)"
    r"(?!_?(configured|set|present|missing|fingerprint|fp|len|count|exists|required|name|id)\b)",
    re.IGNORECASE,
)

# The log line already redacts/hashes the value: not a leak.
_SAFE_LOG_HINT = re.compile(r"(scrub|redact|mask|hash|fingerprint|\*\*\*|len\()", re.IGNORECASE)

# Lines that are not code: comments, mocks, imports, docstrings.
_NOT_CODE = re.compile(
    r"^\s*(#|//|\*|/\*|>>>|\.\.\.|import\b|from\b|def\b|class\b)|"
    r"(mock|\.return_value|patch\(|assert\b|MagicMock|monkeypatch)",
    re.IGNORECASE,
)


def _keep_interpolations(literal: str) -> str:
    """Strip a string literal down to its interpolated expressions, so
    f"user={user_input}" keeps `user_input` but drops the prose."""
    parts = re.findall(r"\{([^}]+)\}|\$\{([^}]+)\}|%\((\w+)\)", literal)
    return " ".join(x for tup in parts for x in tup if x)


_LOOKS_LIKE_STATEMENT = re.compile(
    r"(=|\bawait\b|\breturn\b|\byield\b|^\s*[\w.]+\(|^\s*(for|async for)\b)"
)


def _inside_string(line: str, pos: int) -> bool:
    """True if `pos` sits inside a string literal on this line (odd number of
    unescaped quotes/backticks before it). Good enough for docstring prose."""
    before = line[:pos]
    for q in ("'", '"', "`"):
        if (before.count(q) - before.count("\\" + q)) % 2 == 1:
            return True
    return before.lstrip().startswith(("'", '"', "`"))


@register
class MissingGuardrailDetector(Detector):
    name = "missing-guardrails"
    category = "Missing Output Guardrails"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        if file_path.endswith((".json", ".yaml", ".yml", ".md", ".env")):
            return  # data and prose, never a model call
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = _LLM_CALL.search(line)
            if not m:
                continue
            if _NOT_CODE.search(line) or "(" not in line:
                continue  # comment, import, mock setup: not a real call
            if _inside_string(line, m.start()):
                continue  # docstring or message text mentioning the call
            if not _LOOKS_LIKE_STATEMENT.search(line):
                continue  # prose such as "response: the object from x.create()"
            # Look in a window around the call for any safety step. The
            # window is wider after the call than before, because output
            # handling happens after the model returns.
            window = "\n".join(lines[max(0, i - 4) : i + 12])
            if _GUARDRAIL_HINT.search(window):
                continue  # something is in place, skip
            yield Finding(
                rule_id="CANARY-GR-001",
                title="LLM call with no visible output guardrail",
                # LOW, not MEDIUM: on the v0.2 benchmark this heuristic was
                # right about one time in four. It is a prompt to go look,
                # not a verdict. See bench/RESULTS.md.
                severity=Severity.LOW,
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
        if file_path.endswith((".json", ".yaml", ".yml", ".md")):
            return  # data and prose
        for i, line in enumerate(content.splitlines(), start=1):
            if not _LOG_CALL.search(line):
                continue
            if _NOT_CODE.search(line) or _SAFE_LOG_HINT.search(line):
                continue
            # Only look at what is *inside* the log call, and only at
            # identifiers / interpolations, never at literal prose. A log
            # that says "please enter your password" leaks nothing.
            inner = line[line.find("(") + 1 :]
            inner_no_literals = re.sub(
                r"(['\"`])(?:(?!\1).)*\1", lambda m: _keep_interpolations(m.group(0)), inner
            )
            if not _PII_ARG.search(inner_no_literals):
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
