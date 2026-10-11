# Changelog

## 0.2.0 (2026-10)

**Release and validation chronology.** Development changes were committed with
September 2026 author dates. The benchmark artifacts in this release were
produced using repository snapshots obtained on October 10, 2026; they are
October validation evidence, not evidence of a September benchmark run.
GitHub Actions first ran on October 11, 2026, after the commits were pushed.
The PyPI publication is also an October 2026 release event; consult the
PyPI release history for its exact timestamp. These are distinct milestones:
development, validation, CI execution, and distribution.

The first release that was measured before it was shipped. `bench/` scans ten
public LLM application repositories (adk-samples, openai-agents-python,
anthropic-cookbook, vanna, crewAI-examples, chat-langchain, Chainlit cookbook,
pydantic-ai, mem0, open_deep_research) and every finding was reviewed in
context. See `bench/RESULTS.md`.

What the benchmark changed:

- 0.1.0 produced **2,231 findings** on those repos. 0.2.0 produces **222**, a
  10x reduction, with the true positives kept (31/33 on the prompt-injection
  rule).
- Test directories, fixtures, cassettes and docs are skipped by default
  (`--include-tests` restores them). They were the source of most noise.
- `CANARY-PI-001` now requires both a prompt-like target *and* an input-like
  interpolated value. `message = f"Deleted {name}"` is no longer injection.
- `CANARY-PII-001` dropped `message`, `content` and `response` from its PII
  list and only looks at identifiers inside the log call, not at prose.
- `CANARY-GR-001` ignores comments, docstrings, mocks, imports and data files,
  and is now **LOW** severity: measured precision is ~24 %, so it is a prompt
  to look, not a verdict.
- Secret patterns are word-boundary anchored (`task-...` is not an OpenAI key),
  skip 400+ character data lines, honour `gitleaks:allow` / `noqa: S105`, and
  treat PostHog `phc_` project tokens as public by design.

New:

- **`CANARY-EA-001` / `EA-002`, excessive agency (OWASP LLM06).** AST-based:
  functions exposed as agent or MCP tools (`@tool`, `@mcp.tool()`,
  `tools=[...]`, `FunctionTool(...)`) whose body reaches `subprocess`,
  `os.system`, `eval`/`exec`, file writes or raw SQL with no validation step.
- **OWASP LLM Top 10 (2025) mapping** on every finding, in text, JSON and SARIF.
- **SARIF 2.1.0 output** (`--format sarif`) with `security-severity`, CWE and
  OWASP tags, so findings appear in GitHub code scanning and PR annotations.
- **Reusable GitHub Action** (`uses: jcedrik/canary@v0.2`) that scans, uploads
  the SARIF and gates the build.
- **Inline suppression**: `# canary: ignore CANARY-PI-001` (or bare
  `# canary: ignore`), `//` works too.
- **`--baseline report.json`** to accept existing findings and fail only on new
  ones.
- `-o/--output`, `--include-tests`, `--version`.
- Package renamed to **`canary-sast`** on PyPI. The previous README pointed to
  `canary-scan`, which is an unrelated package owned by someone else.
- CI: ruff lint + format, Python 3.9 to 3.13, self-scan uploaded to code
  scanning, trusted publishing to PyPI on `v*` tags.

## 0.1.0 (2026-06)

Initial release: four detectors (prompt injection, exposed secrets, missing
guardrails, PII logging), text and JSON output, exit-code gating.
