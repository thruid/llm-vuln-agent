"""End-to-end workflow: asset in, structured report out."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from agent.agent import Agent
from agent.state import AgentState
from models.asset import Asset
from models.result import Report
from pipeline.factory import System

logger = logging.getLogger(__name__)


def run_workflow(asset: Asset, system: System, max_steps: int | None = None) -> Report:
    """Run the full Observe -> ... -> Verify -> Report loop for one asset."""
    state = AgentState(asset=asset)
    if max_steps is not None:
        state.max_steps = max_steps
    agent = Agent(system.llm, system.registry, state)
    report = agent.run()
    if not report.generated_at:
        report.generated_at = datetime.now(timezone.utc).isoformat()
    logger.info("workflow finished: %d entries", len(report.entries))
    return report
