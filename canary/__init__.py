"""canary — a static security scanner for LLM and AI-agent applications.

Catches the failure modes that traditional linters miss: prompt injection,
leaked API keys, missing output guardrails, and sensitive data in logs.
"""

from .findings import Finding, ScanResult, Severity
from .scanner import Scanner

__version__ = "0.2.0"
__all__ = ["Finding", "ScanResult", "Scanner", "Severity", "__version__"]
