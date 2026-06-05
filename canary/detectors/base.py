"""Detector base class and registry.

A detector inspects one file's content and yields Findings. New detectors
register themselves with @register so the scanner picks them up without any
central list to keep in sync.
"""

from __future__ import annotations

import abc
from typing import Iterable, Type

from ..findings import Finding

_REGISTRY: list[Type["Detector"]] = []


def register(cls: Type["Detector"]) -> Type["Detector"]:
    """Class decorator. Adds a detector to the global registry."""
    _REGISTRY.append(cls)
    return cls


def all_detectors() -> list["Detector"]:
    """Instantiate every registered detector."""
    return [cls() for cls in _REGISTRY]


class Detector(abc.ABC):
    """Base class for all detectors.

    Subclasses set `name` and `category` and implement `scan_file`.
    """

    name: str = "unnamed"
    category: str = "uncategorized"

    @abc.abstractmethod
    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        """Yield Findings for a single file. Must not raise on bad input."""
        raise NotImplementedError
