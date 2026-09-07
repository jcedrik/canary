"""Core data structures for scan findings.

Every detector emits Finding objects. Keeping this in one place means the
CLI, the JSON reporter, and the CI exit-code logic all agree on the shape
of the data.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered so we can compare and pick the worst finding in a scan."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.upper()]

    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    """A single security issue detected in the scanned code.

    Attributes:
        rule_id: Stable identifier, e.g. "CANARY-PI-001". Used so users can
            suppress a specific rule without silencing a whole category.
        title: Short human-readable summary.
        severity: How bad it is.
        file_path: Where it was found.
        line: 1-indexed line number (0 if not line-specific).
        snippet: The offending line(s), trimmed.
        explanation: Why this is a problem.
        remediation: Concrete fix the developer can apply.
        category: Grouping for the report, e.g. "Prompt Injection".
    """

    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line: int
    snippet: str
    explanation: str
    remediation: str
    category: str
    cwe: Optional[str] = None  # e.g. "CWE-798" for hardcoded credentials
    owasp: Optional[str] = None  # OWASP LLM Top 10 (2025) id, e.g. "LLM01"

    def __post_init__(self) -> None:
        # Every rule family maps to one OWASP LLM Top 10 category. Filling it
        # here means detectors never forget, and reports always carry it.
        if self.owasp is None:
            self.owasp = OWASP_BY_RULE.get(self.rule_id.rsplit("-", 1)[0])

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label()
        d["owasp_title"] = OWASP_LLM_TOP10.get(self.owasp or "", None)
        return d


# OWASP Top 10 for LLM Applications (2025 edition).
OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# Rule family (rule id without the trailing -NNN) to OWASP category.
OWASP_BY_RULE = {
    "CANARY-PI": "LLM01",
    "CANARY-SEC": "LLM02",
    "CANARY-PII": "LLM02",
    "CANARY-GR": "LLM05",
    "CANARY-EA": "LLM06",
}


@dataclass
class ScanResult:
    """Aggregate of everything one scan run produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    suppressed: int = 0  # findings dropped by inline ignores or a baseline

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def count_by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
        return dict(sorted(counts.items()))

    def count_by_owasp(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.owasp or "unmapped"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    def count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.label()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "suppressed": self.suppressed,
            "counts_by_severity": self.count_by_severity(),
            "counts_by_rule": self.count_by_rule(),
            "counts_by_owasp": self.count_by_owasp(),
            "findings": [f.to_dict() for f in self.findings],
        }
