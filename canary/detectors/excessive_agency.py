"""Excessive agency detector (OWASP LLM06).

Agents act through tools. A tool is a plain function the model is allowed to
call, so whatever that function can do, a prompt-injected model can do too.
The dangerous pattern is a tool that reaches straight into the OS (shell,
eval, filesystem writes, raw SQL) with no validation between the model's
arguments and the side effect.

This detector is AST-based for Python. It looks for functions that are
exposed as tools (decorators such as @tool, @function_tool, @mcp.tool(),
or passed into a `tools=[...]` list / FunctionTool(...) wrapper) and flags
the ones whose body calls a dangerous sink.

Rules:
    CANARY-EA-001  tool function runs a shell / eval / exec sink   (HIGH)
    CANARY-EA-002  tool function writes files or executes raw SQL   (MEDIUM)

It stays quiet when the function body shows a validation step (allowlist,
schema, confirm, sanitize ...), mirroring the guardrail detector's logic.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from ..findings import Finding, Severity
from .base import Detector, register

# Decorator names that mark a function as an agent / MCP tool.
_TOOL_DECORATORS = re.compile(
    r"^(tool|function_tool|mcp\.tool|server\.tool|app\.tool|agent\.tool|"
    r"langchain\.tools\.tool|FunctionTool|tool_plain|kernel_function|"
    r"register_tool|action)$"
)

# Dangerous sinks, grouped by rule. Matched against the dotted call name.
_SHELL_SINKS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
    "eval",
    "exec",
    "os.exec",
    "os.execv",
    "os.execvp",
    "os.spawn",
    "pty.spawn",
    "commands.getoutput",
}
_WRITE_SINKS = {
    "shutil.rmtree",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.rename",
    "shutil.move",
    "shutil.copy",
    "pathlib.Path.write_text",
    "cursor.execute",
    "conn.execute",
    "connection.execute",
    "db.execute",
    "session.execute",
    "engine.execute",
}

_VALIDATION_HINT = re.compile(
    r"(allowlist|whitelist|validate|sanitize|schema|pydantic|confirm|"
    r"approve|shlex\.quote|is_safe|check_path|resolve\(\)|relative_to)",
    re.IGNORECASE,
)


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for a call target: os.system, eval, ..."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _decorator_name(dec: ast.AST) -> str:
    if isinstance(dec, ast.Call):
        return _dotted(dec.func)
    return _dotted(dec)


@register
class ExcessiveAgencyDetector(Detector):
    name = "excessive-agency"
    category = "Excessive Agency (agent tools)"

    def scan_file(self, file_path: str, content: str) -> Iterable[Finding]:
        if not file_path.endswith(".py"):
            return
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
        lines = content.splitlines()

        tool_names = self._names_registered_as_tools(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorated = any(_TOOL_DECORATORS.match(_decorator_name(d)) for d in node.decorator_list)
            if not decorated and node.name not in tool_names:
                continue

            body_src = "\n".join(lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)])
            if _VALIDATION_HINT.search(body_src):
                continue  # some validation exists, stay quiet

            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                name = _dotted(call.func)
                shell_true = any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in call.keywords
                )
                if name in _SHELL_SINKS or shell_true:
                    yield self._finding(
                        "CANARY-EA-001",
                        "Agent tool executes shell or eval with model-controlled input",
                        Severity.HIGH,
                        file_path,
                        call.lineno,
                        lines,
                        node.name,
                        name,
                        "The model can call this tool with arbitrary arguments. "
                        "A prompt-injected model therefore gets arbitrary code "
                        "or command execution on the host.",
                        "Never pass model output to a shell. Use an allowlist of "
                        "commands with fixed argument shapes, validate every "
                        "argument against a schema, and require human "
                        "confirmation for destructive actions.",
                        "CWE-78",
                    )
                elif name in _WRITE_SINKS or (name == "open" and self._opens_for_write(call)):
                    yield self._finding(
                        "CANARY-EA-002",
                        "Agent tool writes files or runs raw SQL without validation",
                        Severity.MEDIUM,
                        file_path,
                        call.lineno,
                        lines,
                        node.name,
                        name,
                        "This tool performs a side effect (filesystem write, "
                        "delete, or database statement) on arguments the model "
                        "controls. Path traversal and SQL injection become "
                        "reachable through the prompt.",
                        "Constrain paths to a sandbox directory (resolve and "
                        "check relative_to), use parameterized queries, and "
                        "scope the tool to the minimum capability it needs.",
                        "CWE-22",
                    )

    @staticmethod
    def _opens_for_write(call: ast.Call) -> bool:
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            return any(ch in str(call.args[1].value) for ch in "wa+")
        for kw in call.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                return any(ch in str(kw.value.value) for ch in "wa+")
        return False

    @staticmethod
    def _names_registered_as_tools(tree: ast.AST) -> set[str]:
        """Functions passed by name into tools=[...] or FunctionTool(...)."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "tools":
                for elt in ast.walk(node.value):
                    if isinstance(elt, ast.Name):
                        names.add(elt.id)
            if isinstance(node, ast.Call) and _dotted(node.func) in {
                "FunctionTool",
                "Tool",
                "StructuredTool.from_function",
                "tool",
                "function_tool",
            }:
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        names.add(arg.id)
                for kw in node.keywords:
                    if kw.arg in {"func", "fn", "function"} and isinstance(kw.value, ast.Name):
                        names.add(kw.value.id)
        return names

    def _finding(
        self,
        rule_id,
        title,
        severity,
        file_path,
        line,
        lines,
        func_name,
        sink,
        explanation,
        remediation,
        cwe,
    ) -> Finding:
        snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            file_path=file_path,
            line=line,
            snippet=snippet,
            explanation=f"Tool `{func_name}` calls `{sink}`. " + explanation,
            remediation=remediation,
            category=self.category,
            cwe=cwe,
        )
