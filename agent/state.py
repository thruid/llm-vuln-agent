"""Agent state: the mutable working context for one analysis run."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from models.asset import Asset
from models.result import Report


@dataclass
class AgentState:
    asset: Asset
    # Candidate vulnerabilities from the knowledge base (list of dicts).
    candidates: list[dict[str, Any]] = field(default_factory=list)
    # Verification outcomes keyed by CVE id.
    verification_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Step-by-step observation log for explainability.
    observations: list[dict[str, Any]] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    step: int = 0
    max_steps: int = 12
    search_attempted: bool = False
    finished: bool = False
    final_report: Report | None = None
    error: str = ""

    def observe(self, kind: str, **data: Any) -> None:
        self.observations.append({"step": self.step, "kind": kind, **data})

    def summary(self) -> dict[str, Any]:
        return {
            "asset": self.asset.to_dict(),
            "step": self.step,
            "candidates": len(self.candidates),
            "verified": list(self.verification_results),
            "search_attempted": self.search_attempted,
        }
