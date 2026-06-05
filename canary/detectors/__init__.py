"""Detector package.

Importing this package imports every detector module, which runs the
@register decorators and populates the registry. The scanner relies on this
side effect.
"""

from . import prompt_injection  # noqa: F401
from . import secrets  # noqa: F401
from . import guardrails  # noqa: F401

__all__ = ["prompt_injection", "secrets", "guardrails"]
