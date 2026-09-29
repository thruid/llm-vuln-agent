"""LLM clients behind a single ``decide`` interface.

- :class:`MockLLM` — deterministic, offline. Uses the reference planner so the
  whole pipeline runs without an API key.
- :class:`OpenAICompatibleLLM` — a real LLM that reasons over the prompt and
  tool schemas and returns a structured JSON decision.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Protocol, runtime_checkable

from agent import planner
from agent.prompts import build_system_prompt, build_user_prompt
from agent.state import AgentState
from models.result import Report, ReportEntry

logger = logging.getLogger(__name__)


@runtime_checkable
class LLMClient(Protocol):
    def decide(self, state: AgentState, tools: list[dict[str, Any]]) -> planner.Decision: ...


class MockLLM:
    """Deterministic planner-backed LLM for offline demos and tests."""

    name = "mock"

    def decide(self, state: AgentState, tools: list[dict[str, Any]]) -> planner.Decision:
        return planner.plan_next(state)


class OpenAICompatibleLLM:
    """Real LLM provider (OpenAI-compatible chat completions)."""

    name = "openai"

    def __init__(
        self,
        model: str,
        base_url: str = "",
        api_key: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2000,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens

    def _client(self):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("openai package is required for the OpenAI LLM provider") from exc
        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def decide(self, state: AgentState, tools: list[dict[str, Any]]) -> planner.Decision:
        client = self._client()
        messages = [
            {"role": "system", "content": build_system_prompt(tools)},
            {"role": "user", "content": build_user_prompt(state)},
        ]
        resp = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        content = resp.choices[0].message.content or ""
        return self._parse(content)

    @staticmethod
    def _parse(content: str) -> planner.Decision:
        # Strip markdown fences the model may add.
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip())
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            return planner.Decision(type="final", reasoning=f"could not parse LLM output: {exc}", report=None)

        if data.get("type") == "tool_call":
            return planner.Decision(
                type="tool_call",
                tool=str(data.get("tool", "")),
                arguments=data.get("arguments") or {},
                reasoning=data.get("reasoning", ""),
            )
        # Final decision.
        report_data = data.get("report") or {}
        entries = [
            ReportEntry.from_dict(e) for e in report_data.get("entries", []) if isinstance(e, dict)
        ]
        report = Report(target=report_data.get("target", ""), entries=entries)
        return planner.Decision(type="final", reasoning=data.get("reasoning", ""), report=report)


def build_llm(config: dict[str, Any]) -> LLMClient:
    provider = config.get("provider", "mock")
    if provider == "openai":
        import os

        api_key_env = config.get("api_key_env", "LLM_API_KEY")
        api_key = os.environ.get(api_key_env)
        return OpenAICompatibleLLM(
            model=config.get("model", "gpt-4o-mini"),
            base_url=config.get("base_url", ""),
            api_key=api_key,
            temperature=float(config.get("temperature", 0.0)),
            max_tokens=int(config.get("max_tokens", 2000)),
        )
    return MockLLM()
