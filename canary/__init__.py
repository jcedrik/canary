"""canary — a static security scanner for LLM and AI-agent applications.

Catches the failure modes that traditional linters miss: prompt injection,
leaked API keys, missing output guardrails, and sensitive data in logs.
"""

from .scanner import Scanner
from .findings import Finding, ScanResult, Severity

__version__ = "0.1.0"
__all__ = ["Scanner", "Finding", "ScanResult", "Severity", "__version__"]
