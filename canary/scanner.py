"""The scanner: walk a path, run every detector on every eligible file.

Kept deliberately simple. Binary files, vendored dependencies, and version
control directories are skipped. Each file is read once and handed to all
detectors, so adding a detector costs nothing here.
"""

from __future__ import annotations

import os
from typing import Iterable

from .detectors import base
# Importing the detectors package triggers registration of each detector.
from . import detectors  # noqa: F401  (side-effect import)
from .findings import ScanResult

# Extensions worth scanning. LLM apps live mostly in these.
_SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".env",
    ".yaml", ".yml", ".json", ".rb", ".go",
}

# Directories we never descend into.
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", "vendor", ".mypy_cache",
}

_MAX_BYTES = 1_000_000  # skip files larger than ~1MB (likely data, not code)


class Scanner:
    def __init__(self) -> None:
        self.detectors = base.all_detectors()

    def scan_path(self, path: str) -> ScanResult:
        result = ScanResult()
        if os.path.isfile(path):
            self._scan_one(path, result)
            return result
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                fpath = os.path.join(root, name)
                self._scan_one(fpath, result)
        return result

    def _scan_one(self, fpath: str, result: ScanResult) -> None:
        ext = os.path.splitext(fpath)[1].lower()
        # .env has no "real" extension match above except by name
        if ext not in _SCANNABLE_EXT and not fpath.endswith(".env"):
            return
        try:
            if os.path.getsize(fpath) > _MAX_BYTES:
                return
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, UnicodeError):
            return
        result.files_scanned += 1
        for detector in self.detectors:
            try:
                for finding in detector.scan_file(fpath, content):
                    result.add(finding)
            except Exception:
                # A buggy detector must never abort the whole scan.
                continue
