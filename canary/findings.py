"""Core data structures for scan findings.

Every detector emits Finding objects. Keeping this in one place means the
CLI, the JSON reporter, and the CI exit-code logic all agree on the shape
of the data.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered so we can compare and pick the worst finding in a scan."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label()
        return d


@dataclass
class ScanResult:
    """Aggregate of everything one scan run produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

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
            "counts_by_severity": self.count_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
