"""DELIBERATELY VULNERABLE example app — used to demonstrate canary.

Do not copy these patterns. Each one trips a different detector.
"""

import logging

from flask import Flask, request
import openai

app = Flask(__name__)
logger = logging.getLogger(__name__)

# CANARY-SEC-001 / SEC-005: hardcoded key (fake value, but matches the shape)
openai.api_key = "sk-proj-1a2b3c4d5e6f7g8h9i0jKLMNOPqrstuvwxyz123456"


@app.route("/ask")
def ask():
    user_input = request.args.get("q")

    # CANARY-PI-001: user input spliced straight into the prompt
    system_prompt = f"You are a helpful assistant. Answer this: {user_input}"

    # CANARY-GR-001: raw model output is trusted as-is
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "system", "content": system_prompt}],
    )

    answer = response.choices[0].message.content

    # CANARY-PII-001: logging raw user input and model output
    logger.info("user_input=%s response=%s", user_input, answer)

    return answer


if __name__ == "__main__":
    app.run()


# ---- agent tool, CANARY-EA-001 ----
# A tool the model is allowed to call. Whatever the model passes in `cmd`
# runs on the host. This is the OWASP LLM06 "excessive agency" pattern.
from langchain.tools import tool
import subprocess


@tool
def run_command(cmd: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.check_output(cmd, shell=True).decode()
