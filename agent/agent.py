"""The agent loop: Observe -> Analyze -> Retrieve -> Plan -> Tool call -> ...

The loop is deliberately a small, explicit ``while`` loop rather than a large
framework, per the requirements. Each iteration asks the LLM for one decision
and either executes a tool or terminates with a final report.
"""

from __future__ import annotations

import logging
from typing import Any

from agent import planner
from agent.llm import LLMClient
from agent.state import AgentState
from models.result import Report
from tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class Agent:
    def __init__(self, llm: LLMClient, registry: ToolRegistry, state: AgentState) -> None:
        self.llm = llm
        self.registry = registry
        self.state = state

    def run(self) -> Report:
        state = self.state
        while not state.finished and state.step < state.max_steps:
            state.step += 1
            try:
                decision = self.llm.decide(state, self.registry.schemas())
            except Exception as exc:  # noqa: BLE001 - LLM boundary
                logger.exception("LLM decision failed")
                state.error = str(exc)
                state.finished = True
                break

            if decision.type == "tool_call":
                self._execute(decision)
            elif decision.type == "final":
                state.final_report = decision.report or planner.build_report(
                    state.asset, state.candidates, state.verification_results
                )
                state.finished = True
            else:
                state.error = f"unknown decision type {decision.type!r}"
                state.finished = True

        if not state.finished:
            logger.warning("agent hit max_steps (%d); emitting final report", state.max_steps)
            state.final_report = planner.build_report(state.asset, state.candidates, state.verification_results)
            state.finished = True
        return state.final_report

    def _execute(self, decision: planner.Decision) -> None:
        state = self.state
        result = self.registry.call(decision.tool, decision.arguments)
        state.observe("tool_call", tool=decision.tool, success=result["success"], reasoning=decision.reasoning)

        if decision.tool == "vulnerability_search":
            state.search_attempted = True
            if result["success"] and isinstance(result["output"], dict):
                state.candidates = result["output"].get("candidates", [])
                state.observe("retrieve", count=len(state.candidates))
            else:
                state.candidates = []
                state.observe("retrieve", count=0, error=result["error"])

        elif decision.tool == "vulnerability_verify":
            cve = str(decision.arguments.get("cve", ""))
            verification_id = str(decision.arguments.get("verification_id", ""))
            if result["success"] and isinstance(result["output"], dict):
                output = dict(result["output"])
                output.setdefault("verification_id", verification_id)
                state.verification_results[cve] = output
            else:
                state.verification_results[cve] = {
                    "status": "error",
                    "result": "uncertain",
                    "evidence": "",
                    "raw_output": "",
                    "confidence": 0.0,
                    "verification_id": verification_id,
                    "error": result["error"],
                }
            state.observe("verify", cve=cve, result=state.verification_results[cve].get("result"))

        elif decision.tool == "service_detect" and result["success"]:
            out = result["output"]
            if out.get("service"):
                state.asset.service = out["service"]
            if out.get("product"):
                state.asset.product = out["product"]

        elif decision.tool == "version_detect" and result["success"]:
            out = result["output"]
            if out.get("found") and out.get("version"):
                state.asset.version = out["version"]
