"""The scanner: walk a path, run every detector on every eligible file.

Kept deliberately simple. Binary files, vendored dependencies, and version
control directories are skipped. Each file is read once and handed to all
detectors, so adding a detector costs nothing here.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

# Importing the detectors package triggers registration of each detector.
from . import detectors  # noqa: F401  (side-effect import)
from .detectors import base
from .findings import ScanResult

# Extensions worth scanning. LLM apps live mostly in these.
_SCANNABLE_EXT = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".rb",
    ".go",
}

# Directories we never descend into.
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "vendor",
    ".mypy_cache",
    ".tox",
    ".ruff_cache",
}

# Skipped unless --include-tests: test code legitimately contains fake keys,
# mocked model calls and logged fixtures. The v0.1 benchmark showed most
# false positives came from here.
_TEST_DIRS = {
    "tests",
    "test",
    "__tests__",
    "testing",
    "fixtures",
    "cassettes",
    "snapshots",
    "__snapshots__",
    "docs",
    "doc",
    ".github",
}
_TEST_FILE = re.compile(
    r"(^|[/\\])(test_[^/\\]*|[^/\\]*_test\.py|[^/\\]*\.(test|spec)\.[jt]sx?|conftest\.py)$"
)

_MAX_BYTES = 1_000_000  # skip files larger than ~1MB (likely data, not code)

# Inline suppression: `# canary: ignore CANARY-PI-001` or `# canary: ignore`
# (bare form silences every rule on that line). Works with // and # comments.
_SUPPRESS = re.compile(r"(?:#|//)\s*canary:\s*ignore(?:\s+([A-Z0-9\-, ]+))?", re.IGNORECASE)


class Scanner:
    def __init__(self, baseline: Optional[str] = None, include_tests: bool = False) -> None:
        self.detectors = base.all_detectors()
        self.include_tests = include_tests
        # A baseline is a previous JSON report; findings already in it are
        # considered accepted and are dropped from new results.
        self._baseline: set[tuple[str, str, str]] = set()
        if baseline:
            self._baseline = self._load_baseline(baseline)

    @staticmethod
    def _load_baseline(path: str) -> set[tuple[str, str, str]]:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return set()
        keys = set()
        for f in data.get("findings", []):
            keys.add((f.get("rule_id", ""), f.get("file_path", ""), f.get("snippet", "")))
        return keys

    def _is_baselined(self, finding) -> bool:
        if not self._baseline:
            return False
        # Keyed on snippet rather than line number so a baseline survives
        # unrelated edits above the finding.
        return (finding.rule_id, finding.file_path, finding.snippet) in self._baseline

    def scan_path(self, path: str) -> ScanResult:
        result = ScanResult()
        if os.path.isfile(path):
            self._scan_one(path, result)
            return result
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            if not self.include_tests:
                dirs[:] = [d for d in dirs if d not in _TEST_DIRS]
            for name in files:
                fpath = os.path.join(root, name)
                self._scan_one(fpath, result)
        return result

    def _scan_one(self, fpath: str, result: ScanResult) -> None:
        if not self.include_tests and _TEST_FILE.search(fpath):
            return
        ext = os.path.splitext(fpath)[1].lower()
        # .env has no "real" extension match above except by name
        if ext not in _SCANNABLE_EXT and not fpath.endswith(".env"):
            return
        try:
            if os.path.getsize(fpath) > _MAX_BYTES:
                return
            with open(fpath, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, UnicodeError):
            return
        result.files_scanned += 1
        lines = content.splitlines()
        for detector in self.detectors:
            try:
                for finding in detector.scan_file(fpath, content):
                    if self._suppressed(finding, lines):
                        result.suppressed += 1
                        continue
                    if self._is_baselined(finding):
                        result.suppressed += 1
                        continue
                    result.add(finding)
            except Exception:
                # A buggy detector must never abort the whole scan.
                continue

    @staticmethod
    def _suppressed(finding, lines: list[str]) -> bool:
        if finding.line <= 0 or finding.line > len(lines):
            return False
        m = _SUPPRESS.search(lines[finding.line - 1])
        if not m:
            return False
        rules = m.group(1)
        if not rules:
            return True
        wanted = {r.strip().upper() for r in rules.replace(",", " ").split()}
        return finding.rule_id.upper() in wanted
