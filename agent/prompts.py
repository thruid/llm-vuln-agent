"""Prompt templates for the LLM decision engine.

The LLM is a decision-maker, not a scanner: it reasons over observations and
returns a JSON decision, either a tool call or a final verdict. It never emits
shell commands.
"""

from __future__ import annotations

import json
from typing import Any

from agent.state import AgentState

SYSTEM_PROMPT = """You are the analysis and decision engine of an authorized vulnerability \
verification system. You do NOT scan, you do NOT execute shell commands, and you do NOT \
guess. You reason over observations, query the vulnerability knowledge base, decide which \
predefined tools to call, and interpret their results.

Rules:
1. Base every claim on evidence. If information is missing or a result is ambiguous, \
conclude UNCERTAIN rather than guessing.
2. Never conclude a vulnerability is present unless a verification tool returns evidence.
3. Only call tools from the provided list, with JSON arguments matching their schema.

Respond with a single JSON object in exactly one of these shapes:

Tool call:
{"type": "tool_call", "tool": "<tool name>", "arguments": { ... }, "reasoning": "..."}

Final verdict:
{"type": "final", "reasoning": "...", "report": {"entries": [{"target": "...", "service": "...", \
"version": "...", "cve": "...", "description": "...", "verification_method": "...", \
"verification_result": "...", "evidence": "...", "confidence": 0.0, "final_status": \
"CONFIRMED|NOT_VULNERABLE|UNCERTAIN"}]}}

Available tools:
{tools}
"""


def build_system_prompt(tools: list[dict[str, Any]]) -> str:
    rendered = []
    for t in tools:
        rendered.append(
            f"- {t['name']}: {t['description']}\n  input_schema: {json.dumps(t.get('input_schema', {}))}"
        )
    return SYSTEM_PROMPT.format(tools="\n".join(rendered))


def build_user_prompt(state: AgentState) -> str:
    asset = state.asset
    candidates = state.candidates
    results = state.verification_results
    return json.dumps(
        {
            "task": "analyze the following asset and determine, with evidence, whether any \
known vulnerability applies",
            "asset": asset.to_dict(),
            "candidates": candidates,
            "verification_results": results,
            "step": state.step,
            "instructions": "Decide the next action. If there are unverified candidates with a \
product match and a version that is not definitively 'no_match', verify the most promising one \
next. Otherwise produce the final verdict.",
        },
        ensure_ascii=False,
    )
