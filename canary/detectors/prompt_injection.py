"""Prompt injection detector.

The core LLM-app risk: untrusted user input flowing straight into a prompt
string with no separation. We do two things:

1. A lightweight AST pass over Python files to catch f-strings / concatenation
   that build a prompt out of variables, when those variables trace back to
   common request-input sources (request.json, input(), argv, etc.).
2. A regex fallback for non-Python files (JS/TS) where we can't cheaply parse,
   looking for template literals that interpolate into a prompt-ish variable.

This is intentionally conservative: it flags patterns, explains the risk, and
points at parameterization. False positives are tuned down by requiring the
sink to look prompt-related (variable/key named prompt, message, system, etc.).
"""

from __future__ import annotations

import ast
import re
from typing import Iterable

from ..findings import Finding, Severity
from .base import Detector, register

# Names that suggest a value is destined for an LLM prompt.
_PROMPT_HINTS = re.compile(
    r"(prompt|message|messages|system_?prompt|user_?input|query|instruction)",
    re.IGNORECASE,
)

# Calls/attributes that commonly carry untrusted input.
_TAINT_SOURCES = re.compile(
    r"(request\.(json|form|args|data|values)|input\s*\(|sys\.argv|"
    r"req\.body|req\.query|os\.environ\.get\(\s*['\"](?!.*KEY).*['\"]\))",
    re.IGNORECASE,
)


@register
class PromptInjectionDetector(Detector):
    name = "prompt-injection"
    category = "Prompt Injection"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        if file_path.endswith(".py"):
            yield from self._scan_python(file_path, content)
        elif file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            yield from self._scan_js_like(file_path, content)

    # ---- Python: AST-based ----
    def _scan_python(self, file_path: str, content: str) -> Iterable[Finding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return  # don't crash on a file we can't parse
        lines = content.splitlines()

        for node in ast.walk(tree):
            # Assignment where target name looks prompt-related and value
            # mixes a literal with a variable (f-string or + concatenation).
            if isinstance(node, ast.Assign):
                target_names = [
                    t.id for t in node.targets if isinstance(t, ast.Name)
                ]
                if not any(_PROMPT_HINTS.search(n) for n in target_names):
                    continue
                if self._value_mixes_input(node.value):
                    line = node.lineno
                    snippet = lines[line - 1].strip() if line - 1 < len(lines) else ""
                    yield Finding(
                        rule_id="CANARY-PI-001",
                        title="User input concatenated directly into a prompt",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line=line,
                        snippet=snippet,
                        explanation=(
                            "A prompt is built by interpolating a variable into "
                            "a template. If that variable contains untrusted "
                            "user input, an attacker can override your "
                            "instructions (prompt injection)."
                        ),
                        remediation=(
                            "Keep the system instruction in a separate message "
                            "from user content. Pass user text as its own "
                            "'user' role message rather than splicing it into "
                            "the system prompt, and validate/escape it first."
                        ),
                        category=self.category,
                        cwe="CWE-94",
                    )

    def _value_mixes_input(self, value: ast.AST) -> bool:
        """True if value is an f-string with interpolation or a + concat
        that includes a non-constant (i.e. a variable)."""
        if isinstance(value, ast.JoinedStr):  # f-string
            return any(
                isinstance(v, ast.FormattedValue) for v in value.values
            )
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            return self._contains_name(value)
        return False

    def _contains_name(self, node: ast.AST) -> bool:
        return any(isinstance(n, ast.Name) for n in ast.walk(node))

    # ---- JS/TS: regex-based ----
    def _scan_js_like(self, file_path: str, content: str) -> Iterable[Finding]:
        for i, line in enumerate(content.splitlines(), start=1):
            if not _PROMPT_HINTS.search(line):
                continue
            # template literal with interpolation: `...${...}...`
            if re.search(r"`[^`]*\$\{[^}]+\}[^`]*`", line):
                yield Finding(
                    rule_id="CANARY-PI-002",
                    title="Template literal interpolated into a prompt",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line=i,
                    snippet=line.strip(),
                    explanation=(
                        "A prompt-related string uses template interpolation. "
                        "If the interpolated value is user-controlled, this is "
                        "a prompt injection vector."
                    ),
                    remediation=(
                        "Separate system instructions from user content using "
                        "the messages array (role-based). Never build a single "
                        "prompt string from untrusted input."
                    ),
                    category=self.category,
                    cwe="CWE-94",
                )
