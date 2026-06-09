"""Tests for canary detectors.

We test each detector against a positive case (should flag) and a negative
case (should stay quiet), plus the scanner's file-walking and the CLI exit
codes. Negative cases matter as much as positive ones: a scanner that cries
wolf gets uninstalled.
"""

from canary.scanner import Scanner
from canary.findings import Severity
from canary.detectors.prompt_injection import PromptInjectionDetector
from canary.detectors.secrets import SecretsDetector
from canary.detectors.guardrails import (
    MissingGuardrailDetector,
    PiiLoggingDetector,
)


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
        'prompt = f"Answer: {request.args.get(\'q\')}"\n'
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
