"""Planning: deterministic next-action selection and final report building.

These functions power the offline ``MockLLM`` and serve as the reference
logic the real LLM is asked to replicate. Keeping them separate makes the
decision policy testable without an API call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent.state import AgentState
from models.asset import Asset
from models.result import FinalStatus, Report, ReportEntry

_VERSION_NO_MATCH = "no_match"


@dataclass
class Decision:
    type: str  # "tool_call" | "final"
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    report: Report | None = None


def _is_pending(candidate: dict[str, Any], state: AgentState) -> bool:
    if not candidate.get("product_match"):
        return False
    if candidate.get("version_match") == _VERSION_NO_MATCH:
        return False
    if candidate.get("cve_id") in state.verification_results:
        return False
    return True


def plan_next(state: AgentState) -> Decision:
    """Choose the next action given the current state."""
    asset = state.asset
    if not (asset.product or asset.service or asset.version or asset.banner):
        # Nothing to search on: insufficient information.
        return build_final(state)
    if not state.candidates:
        if state.search_attempted:
            return build_final(state)
        return Decision(
            type="tool_call",
            tool="vulnerability_search",
            arguments={
                "product": state.asset.product or state.asset.service or "",
                "vendor": state.asset.vendor or "",
                "version": state.asset.version or "",
                "service": state.asset.service or "",
            },
            reasoning="No candidates yet; query the knowledge base for matching vulnerabilities.",
        )

    pending = sorted([c for c in state.candidates if _is_pending(c, state)], key=lambda c: -c.get("score", 0.0))
    if pending:
        best = pending[0]
        return Decision(
            type="tool_call",
            tool="vulnerability_verify",
            arguments={
                "ip": state.asset.ip,
                "port": state.asset.port,
                "cve": best["cve_id"],
                "verification_id": best.get("verification_id") or "mock",
                "version": state.asset.version,
            },
            reasoning=f"Verify the highest-scoring unverified candidate {best['cve_id']} "
            f"(version_match={best.get('version_match')}).",
        )
    return build_final(state)


def _normalize_status(value: str) -> str:
    return (value or "uncertain").upper()


def build_report(asset: Asset, candidates: list[dict[str, Any]], results: dict[str, dict[str, Any]]) -> Report:
    """Assemble the structured report from candidates and verification outcomes."""
    entries: list[ReportEntry] = []

    # Only candidates whose product actually matches the asset are relevant.
    relevant = [c for c in candidates if c.get("product_match")]

    for c in relevant:
        cve = c.get("cve_id", "")
        res = results.get(cve)
        if res is not None:
            status = _normalize_status(str(res.get("result", "uncertain")))
            entries.append(
                ReportEntry(
                    target=asset.target,
                    service=asset.service or "",
                    version=asset.version or "",
                    cve=cve,
                    description=c.get("description", ""),
                    verification_method=res.get("verification_id", ""),
                    verification_result=res.get("result", ""),
                    evidence=res.get("evidence", ""),
                    confidence=float(res.get("confidence", 0.0)),
                    final_status=status,
                )
            )
        elif c.get("version_match") == _VERSION_NO_MATCH:
            entries.append(
                ReportEntry(
                    target=asset.target,
                    service=asset.service or "",
                    version=asset.version or "",
                    cve=cve,
                    description=c.get("description", ""),
                    verification_method="version_match",
                    verification_result="no_match",
                    evidence=f"asset version {asset.version or '?'} outside affected range",
                    confidence=0.8,
                    final_status=FinalStatus.NOT_VULNERABLE.value,
                )
            )
        else:
            entries.append(
                ReportEntry(
                    target=asset.target,
                    service=asset.service or "",
                    version=asset.version or "",
                    cve=cve,
                    description=c.get("description", ""),
                    verification_method="",
                    verification_result="unverified",
                    evidence="insufficient information to reach a conclusion",
                    confidence=0.3,
                    final_status=FinalStatus.UNCERTAIN.value,
                )
            )

    if not entries:
        entries.append(
            ReportEntry(
                target=asset.target,
                service=asset.service or "",
                version=asset.version or "",
                cve="",
                description="no matching vulnerability found or insufficient asset information",
                verification_method="",
                verification_result="",
                evidence="",
                confidence=0.3,
                final_status=FinalStatus.UNCERTAIN.value,
            )
        )

    return Report(
        target=asset.target,
        entries=entries,
        meta={
            "candidates": len(candidates),
            "verified": len(results),
            "service": asset.service or "",
            "version": asset.version or "",
        },
    )


def build_final(state: AgentState) -> Decision:
    report = build_report(state.asset, state.candidates, state.verification_results)
    return Decision(type="final", report=report, reasoning="Analysis complete; producing final report.")
