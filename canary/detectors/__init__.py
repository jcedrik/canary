"""Detector package.

Importing this package imports every detector module, which runs the
@register decorators and populates the registry. The scanner relies on this
side effect.
"""

from . import (
    excessive_agency,
    guardrails,
    prompt_injection,
    secrets,
)

__all__ = ["excessive_agency", "guardrails", "prompt_injection", "secrets"]
