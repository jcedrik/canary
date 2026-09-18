"""Tests for canary detectors.

We test each detector against a positive case (should flag) and a negative
case (should stay quiet), plus the scanner's file-walking and the CLI exit
codes. Negative cases matter as much as positive ones: a scanner that cries
wolf gets uninstalled.
"""

from canary.detectors.guardrails import (
    MissingGuardrailDetector,
    PiiLoggingDetector,
)
from canary.detectors.prompt_injection import PromptInjectionDetector
from canary.detectors.secrets import SecretsDetector
from canary.findings import Severity
from canary.scanner import Scanner


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# ---- Prompt injection ----
def test_prompt_injection_flags_fstring():
    code = 'prompt = f"Answer this: {user_input}"\n'
    findings = list(PromptInjectionDetector().scan_file("a.py", code))
    assert "CANARY-PI-001" in _rule_ids(findings)


def test_prompt_injection_ignores_static_prompt():
    code = 'prompt = "You are a helpful assistant."\n'
    findings = list(PromptInjectionDetector().scan_file("a.py", code))
    assert findings == []


def test_prompt_injection_ignores_non_prompt_fstring():
    code = 'greeting = f"Hello {name}"\n'
    findings = list(PromptInjectionDetector().scan_file("a.py", code))
    assert findings == []


def test_prompt_injection_js_template_literal():
    code = "const prompt = `Answer: ${userInput}`;\n"
    findings = list(PromptInjectionDetector().scan_file("a.ts", code))
    assert "CANARY-PI-002" in _rule_ids(findings)


# ---- Secrets ----
def test_secrets_flags_anthropic_key():
    code = 'KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"\n'
    findings = list(SecretsDetector().scan_file("a.py", code))
    assert "CANARY-SEC-002" in _rule_ids(findings)


def test_secrets_redacts_value():
    secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"
    code = f'KEY = "{secret}"\n'
    findings = list(SecretsDetector().scan_file("a.py", code))
    assert secret not in findings[0].snippet
    assert "*" in findings[0].snippet


def test_secrets_ignores_placeholder():
    code = 'api_key = "your-api-key-here"\n'
    findings = list(SecretsDetector().scan_file("a.py", code))
    assert findings == []


# ---- Guardrails ----
def test_missing_guardrail_flags_bare_call():
    code = (
        "resp = openai.chat.completions.create(model='gpt-4', messages=m)\n"
        "return resp.choices[0].message.content\n"
    )
    findings = list(MissingGuardrailDetector().scan_file("a.py", code))
    assert "CANARY-GR-001" in _rule_ids(findings)


def test_missing_guardrail_quiet_when_validation_present():
    code = (
        "resp = openai.chat.completions.create(model='gpt-4', messages=m)\n"
        "validated = MySchema.model_validate_json(resp.content)\n"
    )
    findings = list(MissingGuardrailDetector().scan_file("a.py", code))
    assert findings == []


# ---- PII logging ----
def test_pii_logging_flags_raw_input():
    code = 'logger.info("user_input=%s", user_input)\n'
    findings = list(PiiLoggingDetector().scan_file("a.py", code))
    assert "CANARY-PII-001" in _rule_ids(findings)


def test_pii_logging_quiet_on_safe_log():
    code = 'logger.info("request completed in %dms", duration)\n'
    findings = list(PiiLoggingDetector().scan_file("a.py", code))
    assert findings == []


# ---- Scanner integration ----
def test_scanner_finds_multiple_in_example(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(
        'openai.api_key = "sk-proj-1a2b3c4d5e6f7g8h9i0jKLMNOPqrstuvwxyz12"\n'
        "prompt = f\"Answer: {request.args.get('q')}\"\n"
    )
    result = Scanner().scan_path(str(tmp_path))
    assert result.files_scanned == 1
    assert result.worst_severity() == Severity.CRITICAL
    ids = _rule_ids(result.findings)
    assert "CANARY-SEC-001" in ids or "CANARY-SEC-005" in ids


def test_scanner_skips_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    bad = tmp_path / "node_modules" / "x.py"
    bad.write_text('key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"\n')
    result = Scanner().scan_path(str(tmp_path))
    assert result.files_scanned == 0


# ---- Excessive agency (agent tools) ----
import json

from canary.detectors.excessive_agency import ExcessiveAgencyDetector
from canary.report import render_sarif


def test_agency_flags_decorated_tool_with_shell():
    code = (
        "import subprocess\n@tool\ndef run(cmd: str):\n    return subprocess.run(cmd, shell=True)\n"
    )
    findings = list(ExcessiveAgencyDetector().scan_file("a.py", code))
    assert "CANARY-EA-001" in _rule_ids(findings)
    assert findings[0].owasp == "LLM06"


def test_agency_flags_mcp_tool_file_write():
    code = (
        "@mcp.tool()\n"
        "def save(path: str, data: str):\n"
        "    with open(path, 'w') as fh:\n"
        "        fh.write(data)\n"
    )
    findings = list(ExcessiveAgencyDetector().scan_file("a.py", code))
    assert "CANARY-EA-002" in _rule_ids(findings)


def test_agency_flags_function_passed_in_tools_list():
    code = "import os\ndef shell(cmd):\n    return os.system(cmd)\nagent = Agent(tools=[shell])\n"
    findings = list(ExcessiveAgencyDetector().scan_file("a.py", code))
    assert "CANARY-EA-001" in _rule_ids(findings)


def test_agency_quiet_with_allowlist():
    code = (
        "import subprocess\n"
        "ALLOWLIST = {'ls', 'pwd'}\n"
        "@tool\n"
        "def run(cmd: str):\n"
        "    if cmd not in ALLOWLIST: raise ValueError\n"
        "    return subprocess.run([cmd])\n"
    )
    findings = list(ExcessiveAgencyDetector().scan_file("a.py", code))
    assert findings == []


def test_agency_quiet_for_plain_function():
    code = "import os\ndef helper(cmd):\n    return os.system(cmd)\n"
    findings = list(ExcessiveAgencyDetector().scan_file("a.py", code))
    assert findings == []


# ---- OWASP mapping, suppression, baseline, SARIF ----
def test_every_finding_has_owasp_category(tmp_path):
    (tmp_path / "app.py").write_text(
        'KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"\nprompt = f"Answer: {user_input}"\n'
    )
    result = Scanner().scan_path(str(tmp_path))
    assert result.findings
    assert all(f.owasp for f in result.findings)
    assert "LLM01" in result.count_by_owasp()


def test_inline_suppression_specific_rule(tmp_path):
    (tmp_path / "app.py").write_text(
        'prompt = f"Answer: {user_input}"  # canary: ignore CANARY-PI-001\n'
    )
    result = Scanner().scan_path(str(tmp_path))
    assert result.findings == []
    assert result.suppressed == 1


def test_inline_suppression_does_not_silence_other_rules(tmp_path):
    (tmp_path / "app.py").write_text(
        'prompt = f"Answer: {user_input}"  # canary: ignore CANARY-SEC-001\n'
    )
    result = Scanner().scan_path(str(tmp_path))
    assert "CANARY-PI-001" in _rule_ids(result.findings)


def test_baseline_drops_known_findings(tmp_path):
    src = tmp_path / "app.py"
    src.write_text('prompt = f"Answer: {user_input}"\n')
    first = Scanner().scan_path(str(tmp_path))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(first.to_dict()))
    second = Scanner(baseline=str(baseline)).scan_path(str(tmp_path))
    assert second.findings == []
    assert second.suppressed == 1


def test_sarif_is_valid_shape(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"\n')
    result = Scanner().scan_path(str(tmp_path))
    sarif = json.loads(render_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "canary"
    assert run["results"][0]["ruleId"] == "CANARY-SEC-002"
    assert run["results"][0]["level"] == "error"
    rule = run["tool"]["driver"]["rules"][0]
    assert "external/owasp-llm/llm02" in rule["properties"]["tags"]
    assert "security-severity" in rule["properties"]


def test_cli_sarif_output_file(tmp_path):
    from canary.cli import main

    (tmp_path / "app.py").write_text('prompt = f"Answer: {user_input}"\n')
    out = tmp_path / "canary.sarif"
    code = main([str(tmp_path), "--format", "sarif", "-o", str(out), "--fail-on", "high"])
    assert code == 1
    assert json.loads(out.read_text())["runs"][0]["results"]


def test_cli_exit_zero_when_below_threshold(tmp_path):
    from canary.cli import main

    (tmp_path / "app.py").write_text('prompt = f"Answer: {user_input}"\n')
    assert main([str(tmp_path), "--fail-on", "critical", "--format", "json"]) == 0


def test_prompt_injection_flags_prompt_variable_but_not_constant():
    flagged = 'system_prompt = f"{SYSTEM_PROMPT} The user says: {prompt}"\n'
    assert "CANARY-PI-001" in _rule_ids(PromptInjectionDetector().scan_file("a.py", flagged))
    quiet = 'system_prompt = f"{SYSTEM_PROMPT} Today is {TODAY}"\n'
    assert (
        PromptInjectionDetector().scan_file("a.py", quiet) == []
        or list(PromptInjectionDetector().scan_file("a.py", quiet)) == []
    )
